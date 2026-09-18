#include "pe_image.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace pe {

namespace {

// Slurp a file completely into memory. Fine for typical PE sizes (KB–MB).
std::vector<std::uint8_t> ReadFileBytes(const std::filesystem::path& path)
{
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) throw std::runtime_error("failed to open: " + path.string());
    auto size = in.tellg();
    if (size <= 0) throw std::runtime_error("empty or unreadable: " + path.string());
    in.seekg(0);
    std::vector<std::uint8_t> buf(static_cast<std::size_t>(size));
    if (!in.read(reinterpret_cast<char*>(buf.data()), size))
        throw std::runtime_error("short read on: " + path.string());
    return buf;
}

} // namespace

template <typename T>
const T* Image::at(std::size_t offset) const
{
    if (offset + sizeof(T) > bytes_.size()) return nullptr;
    return reinterpret_cast<const T*>(bytes_.data() + offset);
}

Image Image::FromFile(const std::filesystem::path& path)
{
    return FromBuffer(ReadFileBytes(path), /*mapped=*/false);
}

Image Image::FromBuffer(std::vector<std::uint8_t> bytes, bool mapped)
{
    Image img;
    img.bytes_  = std::move(bytes);
    img.mapped_ = mapped;

    if (img.bytes_.size() < sizeof(IMAGE_DOS_HEADER))
        throw std::runtime_error("buffer too small for DOS header");
    auto* dos = img.at<IMAGE_DOS_HEADER>(0);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE)
        throw std::runtime_error("missing MZ signature");
    auto* nt = img.at<IMAGE_NT_HEADERS64>(dos->e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE)
        throw std::runtime_error("missing PE signature");
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        throw std::runtime_error("only 64-bit PE files are supported");
    return img;
}

const IMAGE_NT_HEADERS64& Image::ntHeaders64() const
{
    auto* dos = at<IMAGE_DOS_HEADER>(0);
    auto* nt  = at<IMAGE_NT_HEADERS64>(dos->e_lfanew);
    return *nt;
}

bool           Image::is64()               const noexcept { return true; } // guarded in FromBuffer
std::uintptr_t Image::preferredBase()      const noexcept { return static_cast<std::uintptr_t>(ntHeaders64().OptionalHeader.ImageBase); }
std::size_t    Image::sizeOfImage()        const noexcept { return ntHeaders64().OptionalHeader.SizeOfImage; }
std::uint32_t  Image::entryPointRva()      const noexcept { return ntHeaders64().OptionalHeader.AddressOfEntryPoint; }
std::uint16_t  Image::characteristics()    const noexcept { return ntHeaders64().FileHeader.Characteristics; }
std::uint16_t  Image::dllCharacteristics() const noexcept { return ntHeaders64().OptionalHeader.DllCharacteristics; }
std::uint32_t  Image::timestamp()          const noexcept { return ntHeaders64().FileHeader.TimeDateStamp; }

std::vector<SectionInfo> Image::sections() const
{
    std::vector<SectionInfo> out;
    const auto& nt = ntHeaders64();
    auto* dos = at<IMAGE_DOS_HEADER>(0);
    const std::size_t first =
        dos->e_lfanew + offsetof(IMAGE_NT_HEADERS64, OptionalHeader)
        + nt.FileHeader.SizeOfOptionalHeader;
    for (WORD i = 0; i < nt.FileHeader.NumberOfSections; ++i)
    {
        auto* s = at<IMAGE_SECTION_HEADER>(first + i * sizeof(IMAGE_SECTION_HEADER));
        if (!s) break;
        char name[9]{};
        std::memcpy(name, s->Name, 8);
        out.push_back({
            std::string(name),
            s->Misc.VirtualSize,
            s->VirtualAddress,
            s->SizeOfRawData,
            s->PointerToRawData,
            s->Characteristics,
        });
    }
    return out;
}

const IMAGE_DATA_DIRECTORY* Image::dataDirectory(int index) const noexcept
{
    if (index < 0 || index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return nullptr;
    return &ntHeaders64().OptionalHeader.DataDirectory[index];
}

std::optional<std::size_t> Image::rvaToFileOffset(std::uint32_t rva) const
{
    if (mapped_) return rva; // already at VA offsets
    for (auto& s : sections())
    {
        if (rva >= s.virtualAddress && rva < s.virtualAddress + std::max(s.virtualSize, s.rawSize))
            return s.rawOffset + (rva - s.virtualAddress);
    }
    return std::nullopt;
}

std::string Image::readCString(std::uint32_t rva) const
{
    auto off = rvaToFileOffset(rva);
    if (!off) return {};
    std::string s;
    for (std::size_t i = *off; i < bytes_.size() && bytes_[i]; ++i)
        s.push_back(static_cast<char>(bytes_[i]));
    return s;
}

std::vector<ImportModule> Image::imports() const
{
    std::vector<ImportModule> mods;
    auto* dir = dataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (!dir || !dir->VirtualAddress) return mods;

    auto off = rvaToFileOffset(dir->VirtualAddress);
    if (!off) return mods;

    for (std::size_t p = *off; p + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= bytes_.size();
         p += sizeof(IMAGE_IMPORT_DESCRIPTOR))
    {
        auto* imp = at<IMAGE_IMPORT_DESCRIPTOR>(p);
        if (!imp || (imp->Name == 0 && imp->OriginalFirstThunk == 0)) break;

        ImportModule mod;
        mod.dllName = readCString(imp->Name);

        // Prefer OFT (name-preserving lookup table); fall back to IAT.
        std::uint32_t lookupRva = imp->OriginalFirstThunk ? imp->OriginalFirstThunk
                                                          : imp->FirstThunk;
        std::uint32_t iatRva    = imp->FirstThunk;
        auto lookupOff = rvaToFileOffset(lookupRva);
        if (!lookupOff) continue;

        for (std::size_t i = 0;; ++i)
        {
            auto* thunk = at<std::uint64_t>(*lookupOff + i * sizeof(std::uint64_t));
            if (!thunk || !*thunk) break;
            ImportEntry e{};
            e.iatRva = iatRva + static_cast<std::uint32_t>(i * sizeof(std::uint64_t));
            if (*thunk & 0x8000000000000000ULL)
            {
                e.byOrdinal = true;
                e.ordinal   = static_cast<std::uint16_t>(*thunk & 0xFFFF);
            }
            else
            {
                auto nameOff = rvaToFileOffset(static_cast<std::uint32_t>(*thunk & 0x7FFFFFFF));
                if (nameOff && *nameOff + 2 < bytes_.size())
                {
                    // IMAGE_IMPORT_BY_NAME { WORD Hint; CHAR Name[]; }
                    e.symbol = std::string(reinterpret_cast<const char*>(bytes_.data() + *nameOff + 2));
                }
            }
            mod.entries.push_back(std::move(e));
        }
        mods.push_back(std::move(mod));
    }
    return mods;
}

std::vector<ExportEntry> Image::exports() const
{
    std::vector<ExportEntry> out;
    auto* dir = dataDirectory(IMAGE_DIRECTORY_ENTRY_EXPORT);
    if (!dir || !dir->VirtualAddress) return out;
    auto off = rvaToFileOffset(dir->VirtualAddress);
    if (!off) return out;
    auto* ed = at<IMAGE_EXPORT_DIRECTORY>(*off);
    if (!ed) return out;

    const std::uint32_t dirStart = dir->VirtualAddress;
    const std::uint32_t dirEnd   = dirStart + dir->Size;

    auto funcsOff = rvaToFileOffset(ed->AddressOfFunctions);
    auto namesOff = rvaToFileOffset(ed->AddressOfNames);
    auto ordsOff  = rvaToFileOffset(ed->AddressOfNameOrdinals);
    if (!funcsOff) return out;

    std::vector<std::pair<std::uint16_t, std::string>> namedByOrdinal;
    if (namesOff && ordsOff)
    {
        for (DWORD i = 0; i < ed->NumberOfNames; ++i)
        {
            auto* nameRva = at<std::uint32_t>(*namesOff + i * sizeof(std::uint32_t));
            auto* ordIdx  = at<std::uint16_t>(*ordsOff  + i * sizeof(std::uint16_t));
            if (!nameRva || !ordIdx) continue;
            namedByOrdinal.emplace_back(*ordIdx, readCString(*nameRva));
        }
    }

    out.reserve(ed->NumberOfFunctions);
    for (DWORD i = 0; i < ed->NumberOfFunctions; ++i)
    {
        auto* rvaSlot = at<std::uint32_t>(*funcsOff + i * sizeof(std::uint32_t));
        if (!rvaSlot || !*rvaSlot) continue;
        ExportEntry e{};
        e.ordinal = static_cast<std::uint16_t>(ed->Base + i);
        e.rva     = *rvaSlot;
        for (auto& [ord, name] : namedByOrdinal)
            if (ord == i) { e.name = name; break; }
        if (e.rva >= dirStart && e.rva < dirEnd)
            e.forwarder = readCString(e.rva);
        out.push_back(std::move(e));
    }
    return out;
}

// ---------- pretty-printers ----------

namespace pretty {

std::string SectionCharacteristics(std::uint32_t c)
{
    std::string s;
    auto tag = [&](std::uint32_t bit, const char* label) {
        if (c & bit) { if (!s.empty()) s += '|'; s += label; }
    };
    tag(IMAGE_SCN_MEM_EXECUTE, "X");
    tag(IMAGE_SCN_MEM_READ,    "R");
    tag(IMAGE_SCN_MEM_WRITE,   "W");
    tag(IMAGE_SCN_CNT_CODE,               "CODE");
    tag(IMAGE_SCN_CNT_INITIALIZED_DATA,   "DATA");
    tag(IMAGE_SCN_CNT_UNINITIALIZED_DATA, "BSS");
    tag(IMAGE_SCN_MEM_DISCARDABLE,        "DISCARD");
    tag(IMAGE_SCN_MEM_SHARED,             "SHARED");
    return s;
}

std::string DllCharacteristics(std::uint16_t c)
{
    std::string s;
    auto tag = [&](std::uint16_t bit, const char* label) {
        if (c & bit) { if (!s.empty()) s += '|'; s += label; }
    };
    tag(IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA, "HIGH_ENTROPY_VA");
    tag(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,    "DYNAMIC_BASE");
    tag(IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY, "FORCE_INTEGRITY");
    tag(IMAGE_DLLCHARACTERISTICS_NX_COMPAT,       "NX_COMPAT");
    tag(IMAGE_DLLCHARACTERISTICS_NO_ISOLATION,    "NO_ISOLATION");
    tag(IMAGE_DLLCHARACTERISTICS_NO_SEH,          "NO_SEH");
    tag(IMAGE_DLLCHARACTERISTICS_NO_BIND,         "NO_BIND");
    tag(IMAGE_DLLCHARACTERISTICS_APPCONTAINER,    "APPCONTAINER");
    tag(IMAGE_DLLCHARACTERISTICS_WDM_DRIVER,      "WDM_DRIVER");
    tag(IMAGE_DLLCHARACTERISTICS_GUARD_CF,        "GUARD_CF");
    tag(IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE, "TS_AWARE");
    return s;
}

std::string Machine(std::uint16_t m)
{
    switch (m)
    {
        case IMAGE_FILE_MACHINE_AMD64: return "AMD64";
        case IMAGE_FILE_MACHINE_I386:  return "I386";
        case IMAGE_FILE_MACHINE_ARM64: return "ARM64";
        case IMAGE_FILE_MACHINE_ARM:   return "ARM";
        default: {
            std::ostringstream os;
            os << "0x" << std::hex << m;
            return os.str();
        }
    }
}

} // namespace pretty

} // namespace pe
