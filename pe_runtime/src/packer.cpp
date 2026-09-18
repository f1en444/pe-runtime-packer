#include "packer.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <random>
#include <stdexcept>
#include <vector>

namespace pe {

namespace {

constexpr std::uint32_t AlignUp(std::uint32_t v, std::uint32_t a)
{
    return (v + a - 1) & ~(a - 1);
}

// The stub: 45 bytes of position-independent x86-64 that:
//   1. reads its own module base from the PEB
//   2. runs a single-byte XOR over `[base + text_rva, base + text_rva + size)`
//   3. jumps to the original entry point.
//
// Four fields patched at pack time:
//   PATCH_TEXT_RVA         u32 at offset 0x10  — displacement in `lea rsi, [rax+disp32]`
//   PATCH_TEXT_SIZE        u32 at offset 0x15  — immediate in  `mov ecx, imm32`
//   PATCH_KEY_BYTE         u8  at offset 0x1A  — immediate in  `mov bl, imm8`
//   PATCH_ORIG_ENTRY_RVA   u32 at offset 0x27  — displacement in `lea rcx, [rax+disp32]`
constexpr std::array<std::uint8_t, 45> kStubTemplate = {
    // 0x00: mov rax, gs:[0x60]    ; PEB
    0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,
    // 0x09: mov rax, [rax + 0x10] ; ImageBaseAddress
    0x48, 0x8B, 0x40, 0x10,
    // 0x0D: lea rsi, [rax + TEXT_RVA]
    0x48, 0x8D, 0xB0, 0x00, 0x00, 0x00, 0x00,
    // 0x14: mov ecx, TEXT_SIZE
    0xB9, 0x00, 0x00, 0x00, 0x00,
    // 0x19: mov bl, KEY
    0xB3, 0x00,
    // 0x1B: xor [rsi], bl
    0x30, 0x1E,
    // 0x1D: inc rsi
    0x48, 0xFF, 0xC6,
    // 0x20: dec ecx
    0xFF, 0xC9,
    // 0x22: jnz -9  (back to xor [rsi], bl)
    0x75, 0xF7,
    // 0x24: lea rcx, [rax + ORIG_ENTRY]
    0x48, 0x8D, 0x88, 0x00, 0x00, 0x00, 0x00,
    // 0x2B: jmp rcx
    0xFF, 0xE1,
};

constexpr std::size_t kPatchTextRva      = 0x10;
constexpr std::size_t kPatchTextSize     = 0x15;
constexpr std::size_t kPatchKeyByte      = 0x1A;
constexpr std::size_t kPatchOrigEntryRva = 0x27;

// Helpers so we don't scatter memcpys everywhere.
template <typename T>
T& AtRef(std::vector<std::uint8_t>& bytes, std::size_t off)
{
    return *reinterpret_cast<T*>(bytes.data() + off);
}
template <typename T>
const T& AtRefC(const std::vector<std::uint8_t>& bytes, std::size_t off)
{
    return *reinterpret_cast<const T*>(bytes.data() + off);
}

std::uint8_t PickRandomKey()
{
    std::random_device rd;
    std::uniform_int_distribution<int> dist(1, 255); // avoid 0 which would be a no-op XOR
    return static_cast<std::uint8_t>(dist(rd));
}

} // namespace

PackReport Pack(const std::filesystem::path& in,
                const std::filesystem::path& out,
                const PackOptions& opts)
{
    // Parse (validates PE64, MZ/PE signatures, etc.). Then clone the raw bytes
    // so we can freely mutate — Image itself is a read-only view.
    Image image = Image::FromFile(in);
    std::vector<std::uint8_t> bytes = image.buffer();

    auto& dos = AtRef<IMAGE_DOS_HEADER>(bytes, 0);
    auto& nt  = AtRef<IMAGE_NT_HEADERS64>(bytes, dos.e_lfanew);

    // ---- locate target section ----
    const std::size_t sectionTableOff =
        dos.e_lfanew + offsetof(IMAGE_NT_HEADERS64, OptionalHeader)
        + nt.FileHeader.SizeOfOptionalHeader;

    auto* firstSection = reinterpret_cast<IMAGE_SECTION_HEADER*>(
        bytes.data() + sectionTableOff);
    IMAGE_SECTION_HEADER* text = nullptr;
    IMAGE_SECTION_HEADER* lastByRva = firstSection;
    IMAGE_SECTION_HEADER* lastByRaw = firstSection;

    for (WORD i = 0; i < nt.FileHeader.NumberOfSections; ++i)
    {
        auto& s = firstSection[i];
        char name[9]{};
        std::memcpy(name, s.Name, 8);
        if (opts.sectionName == name) text = &s;
        if (s.VirtualAddress   > lastByRva->VirtualAddress)   lastByRva = &s;
        if (s.PointerToRawData > lastByRaw->PointerToRawData) lastByRaw = &s;
    }
    if (!text)
        throw std::runtime_error("section not found: " + opts.sectionName);

    // ---- check the header region has room for one more IMAGE_SECTION_HEADER ----
    const std::size_t sectionHdrSize = sizeof(IMAGE_SECTION_HEADER);
    const std::size_t nextHeaderSlot = sectionTableOff
        + nt.FileHeader.NumberOfSections * sectionHdrSize;
    const std::size_t firstRawOff    = firstSection[0].PointerToRawData;
    if (nextHeaderSlot + sectionHdrSize > firstRawOff)
        throw std::runtime_error("no room in header region for another section — recompile "
                                 "with a larger /HEADERSIZE or use fewer sections");

    // ---- choose XOR key ----
    const std::uint8_t key = opts.xorKey ? opts.xorKey : PickRandomKey();

    // ---- encrypt the section's on-disk bytes ----
    const std::uint32_t encRva  = text->VirtualAddress;
    const std::uint32_t encSize = std::min(text->Misc.VirtualSize, text->SizeOfRawData);
    if (encSize == 0)
        throw std::runtime_error("target section has zero size");
    if (text->PointerToRawData + encSize > bytes.size())
        throw std::runtime_error("target section extends past end of file");
    for (std::uint32_t i = 0; i < encSize; ++i)
        bytes[text->PointerToRawData + i] ^= key;

    // Mark the section RWX so the stub can decrypt in place without calling
    // VirtualProtect. Cleaner packers would issue that VirtualProtect from
    // the stub — see README for the trade-off.
    text->Characteristics |=
        IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;

    // ---- build the stub bytes ----
    std::vector<std::uint8_t> stub(kStubTemplate.begin(), kStubTemplate.end());
    const std::uint32_t oldEntry = nt.OptionalHeader.AddressOfEntryPoint;

    std::memcpy(stub.data() + kPatchTextRva,      &encRva,  sizeof(encRva));
    std::memcpy(stub.data() + kPatchTextSize,     &encSize, sizeof(encSize));
    stub[kPatchKeyByte] = key;
    std::memcpy(stub.data() + kPatchOrigEntryRva, &oldEntry, sizeof(oldEntry));

    // ---- pick location for the new .stub section ----
    const std::uint32_t sectionAlign = nt.OptionalHeader.SectionAlignment;
    const std::uint32_t fileAlign    = nt.OptionalHeader.FileAlignment;

    const std::uint32_t newVa       = AlignUp(
        lastByRva->VirtualAddress + std::max(lastByRva->Misc.VirtualSize,
                                             lastByRva->SizeOfRawData),
        sectionAlign);
    const std::uint32_t newRawStart = AlignUp(
        lastByRaw->PointerToRawData + lastByRaw->SizeOfRawData, fileAlign);
    const std::uint32_t newRawSize  = AlignUp(
        static_cast<std::uint32_t>(stub.size()), fileAlign);

    // ---- append the new section header ----
    IMAGE_SECTION_HEADER newHdr{};
    std::memcpy(newHdr.Name, opts.stubSectionName.c_str(),
                std::min<std::size_t>(8, opts.stubSectionName.size()));
    newHdr.Misc.VirtualSize   = static_cast<DWORD>(stub.size());
    newHdr.VirtualAddress     = newVa;
    newHdr.SizeOfRawData      = newRawSize;
    newHdr.PointerToRawData   = newRawStart;
    newHdr.Characteristics =
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

    std::memcpy(bytes.data() + nextHeaderSlot, &newHdr, sectionHdrSize);
    nt.FileHeader.NumberOfSections += 1;

    // ---- rewrite entry point + image size ----
    nt.OptionalHeader.AddressOfEntryPoint = newVa;
    nt.OptionalHeader.SizeOfImage = AlignUp(newVa + newHdr.Misc.VirtualSize, sectionAlign);

    // ---- append the raw stub bytes to the file ----
    if (bytes.size() < newRawStart)
        bytes.resize(newRawStart, 0);
    bytes.resize(newRawStart + newRawSize, 0);
    std::memcpy(bytes.data() + newRawStart, stub.data(), stub.size());

    // ---- write the output ----
    std::ofstream fout(out, std::ios::binary | std::ios::trunc);
    if (!fout) throw std::runtime_error("failed to open output: " + out.string());
    fout.write(reinterpret_cast<const char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
    if (!fout) throw std::runtime_error("short write on output");

    return PackReport{
        key,
        encRva,
        encSize,
        newVa,
        static_cast<std::uint32_t>(stub.size()),
        oldEntry,
        newVa,
    };
}

} // namespace pe
