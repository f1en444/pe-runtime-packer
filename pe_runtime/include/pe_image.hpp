// pe_image.hpp — read-only PE parser. Owns a memory buffer holding either the
// raw file bytes (as read from disk) or an already-mapped image, and exposes
// typed views into its headers, section table, import descriptors, exports,
// relocations, TLS directory, and exception (.pdata) directory. Nothing here
// mutates a process's address space; that's the loader's job.
#pragma once

#include <windows.h>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace pe {

// Small POD views to keep the interface hpp-only where cheap.
struct SectionInfo
{
    std::string   name;         // trimmed to first null of the 8-char field
    std::uint32_t virtualSize;
    std::uint32_t virtualAddress;
    std::uint32_t rawSize;
    std::uint32_t rawOffset;
    std::uint32_t characteristics;
};

struct ImportEntry
{
    std::string   symbol;       // empty when imported by ordinal
    std::uint16_t ordinal;      // 0 when imported by name
    bool          byOrdinal;
    std::uint32_t iatRva;       // rva of the IAT slot to overwrite
};

struct ImportModule
{
    std::string              dllName;
    std::vector<ImportEntry> entries;
};

struct ExportEntry
{
    std::string   name;         // empty when exported by ordinal only
    std::uint16_t ordinal;
    std::uint32_t rva;          // 0 if forwarded
    std::string   forwarder;    // "kernel32.CreateFileA" style; empty if not forwarded
};

// Represents an on-disk PE image. Cheap to construct from a file path; heavy
// data (imports/exports) is decoded lazily by the accessor methods below.
class Image
{
public:
    // Loads the whole file into memory. Throws std::runtime_error on I/O or
    // header failure so callers can just try/catch at the CLI boundary.
    static Image FromFile(const std::filesystem::path& path);

    // Constructs from an existing raw-file byte buffer. `mapped` = true if the
    // buffer already looks like a mapped image (sections at VA offsets, not
    // file offsets) — used by the loader to re-parse after it has copied
    // headers into the target image region.
    static Image FromBuffer(std::vector<std::uint8_t> bytes, bool mapped);

    bool                    is64() const noexcept;
    std::uintptr_t          preferredBase() const noexcept;
    std::size_t             sizeOfImage() const noexcept;
    std::uint32_t           entryPointRva() const noexcept;
    std::uint16_t           characteristics() const noexcept;
    std::uint16_t           dllCharacteristics() const noexcept;
    std::uint32_t           timestamp() const noexcept;
    const IMAGE_NT_HEADERS64& ntHeaders64() const;

    std::span<const std::uint8_t> raw() const noexcept { return { bytes_.data(), bytes_.size() }; }

    // Section table.
    std::vector<SectionInfo> sections() const;

    // Data directory helpers.
    const IMAGE_DATA_DIRECTORY* dataDirectory(int index) const noexcept;

    // Decoded imports / exports.
    std::vector<ImportModule> imports() const;
    std::vector<ExportEntry>  exports() const;

    // RVA <-> file offset conversion. Returns nullopt when the RVA falls
    // outside every section (e.g. in the header region or a hole).
    std::optional<std::size_t> rvaToFileOffset(std::uint32_t rva) const;

    // Snapshot of the buffer (used by the loader to seed the mapped image).
    const std::vector<std::uint8_t>& buffer() const noexcept { return bytes_; }

private:
    Image() = default;

    // Reads a null-terminated ASCII string starting at `rva`.
    std::string readCString(std::uint32_t rva) const;

    template <typename T>
    const T* at(std::size_t offset) const;

    std::vector<std::uint8_t> bytes_;
    bool mapped_ = false;
};

// Pretty-print helpers used by the CLI `info` command.
namespace pretty {
    std::string SectionCharacteristics(std::uint32_t chars);
    std::string DllCharacteristics(std::uint16_t chars);
    std::string Machine(std::uint16_t machine);
}

} // namespace pe
