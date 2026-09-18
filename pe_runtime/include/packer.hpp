// packer.hpp — takes an unpacked 64-bit Windows PE, encrypts its code section
// with a rolling XOR, appends a tiny stub as a new section, and rewrites the
// entry point to run the stub first. At load time the stub decrypts the code
// in-place and jumps to the original entry point. Result: `.text` in the
// packed file is opaque bytes to any static-only tool (IDA / Ghidra / strings
// / diffing tools) — it only becomes real code once the process is live.
//
// This is a v1 / educational packer. It intentionally does the minimum work:
//   - single-byte XOR (fine for hiding, not for cryptographic secrecy)
//   - marks .text as RWX so the stub can write to it without VirtualProtect
//   - preserves all other sections + imports + resource directory verbatim
//
// The stub itself is visible in the output (~50 bytes in a new section) — a
// determined reverse engineer will unpack it manually in about a minute. For
// stronger protection you extend from here: add compression, multiple layers,
// anti-debug, code virtualization, etc.
#pragma once

#include "pe_image.hpp"

#include <cstdint>
#include <filesystem>

namespace pe {

struct PackOptions
{
    // Which section to encrypt. Default is ".text". Case-sensitive, up to 8
    // chars (PE section-name limit).
    std::string sectionName = ".text";

    // Explicit XOR key, or 0 to pick a random one at pack time.
    std::uint8_t xorKey = 0;

    // Name for the new stub section. Any 8-char string works.
    std::string stubSectionName = ".stub";
};

struct PackReport
{
    std::uint8_t  keyUsed;
    std::uint32_t encryptedRva;
    std::uint32_t encryptedSize;
    std::uint32_t stubRva;
    std::uint32_t stubSize;
    std::uint32_t oldEntryRva;
    std::uint32_t newEntryRva;
};

// Reads `in`, produces the packed image at `out`. Throws std::runtime_error
// on failure (missing section, no room to append a section header, etc.).
PackReport Pack(
    const std::filesystem::path& in,
    const std::filesystem::path& out,
    const PackOptions& opts = {});

} // namespace pe
