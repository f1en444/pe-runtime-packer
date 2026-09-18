#include "pe_image.hpp"
#include "packer.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <string>
#include <string_view>

namespace {

void Usage()
{
    std::puts("usage:");
    std::puts("  pe_runtime info FILE");
    std::puts("  pe_runtime pack IN OUT [--key 0xNN] [--section NAME] [--stub NAME]");
}

int RunInfo(const std::filesystem::path& file)
{
    try
    {
        auto img = pe::Image::FromFile(file);
        const auto& nt = img.ntHeaders64();

        std::printf("machine           : %s\n",
            pe::pretty::Machine(nt.FileHeader.Machine).c_str());
        std::printf("timestamp         : 0x%08X\n", img.timestamp());
        std::printf("preferred base    : 0x%016llX\n",
            (unsigned long long)img.preferredBase());
        std::printf("size of image     : 0x%zX\n", img.sizeOfImage());
        std::printf("entry point RVA   : 0x%08X\n", img.entryPointRva());
        std::printf("characteristics   : 0x%04X\n", img.characteristics());
        std::printf("dll characteristi : %s\n",
            pe::pretty::DllCharacteristics(img.dllCharacteristics()).c_str());

        std::puts("\nsections:");
        std::printf("  %-9s  %-8s  %-8s  %-8s  %-8s  %s\n",
                    "name", "vsize", "vaddr", "rsize", "raw", "flags");
        for (auto& s : img.sections())
            std::printf("  %-9s  %08X  %08X  %08X  %08X  %s\n",
                s.name.c_str(), s.virtualSize, s.virtualAddress,
                s.rawSize, s.rawOffset,
                pe::pretty::SectionCharacteristics(s.characteristics).c_str());

        auto imports = img.imports();
        if (!imports.empty())
        {
            std::puts("\nimports:");
            for (auto& mod : imports)
            {
                std::printf("  %s\n", mod.dllName.c_str());
                for (auto& e : mod.entries)
                {
                    if (e.byOrdinal)
                        std::printf("    #%u\n", e.ordinal);
                    else
                        std::printf("    %s\n", e.symbol.c_str());
                }
            }
        }

        auto exports = img.exports();
        if (!exports.empty())
        {
            std::puts("\nexports:");
            for (auto& e : exports)
            {
                if (!e.forwarder.empty())
                    std::printf("  #%u  %-40s -> %s\n",
                        e.ordinal, e.name.c_str(), e.forwarder.c_str());
                else
                    std::printf("  #%u  RVA 0x%08X  %s\n",
                        e.ordinal, e.rva, e.name.c_str());
            }
        }
        return 0;
    }
    catch (const std::exception& ex)
    {
        std::fprintf(stderr, "info failed: %s\n", ex.what());
        return 1;
    }
}

int RunPack(const std::filesystem::path& in,
            const std::filesystem::path& out,
            const pe::PackOptions& opts)
{
    try
    {
        auto rpt = pe::Pack(in, out, opts);
        std::printf("packed OK\n");
        std::printf("  key used         : 0x%02X\n", rpt.keyUsed);
        std::printf("  encrypted region : RVA 0x%08X  size 0x%X\n",
                    rpt.encryptedRva, rpt.encryptedSize);
        std::printf("  stub section     : RVA 0x%08X  size %u B\n",
                    rpt.stubRva, rpt.stubSize);
        std::printf("  entry point      : 0x%08X  ->  0x%08X\n",
                    rpt.oldEntryRva, rpt.newEntryRva);
        std::printf("  wrote            : %s\n", out.string().c_str());
        return 0;
    }
    catch (const std::exception& ex)
    {
        std::fprintf(stderr, "pack failed: %s\n", ex.what());
        return 1;
    }
}

} // namespace

int main(int argc, char** argv)
{
    if (argc < 2) { Usage(); return 1; }
    std::string_view cmd = argv[1];

    if (cmd == "info")
    {
        if (argc < 3) { Usage(); return 1; }
        return RunInfo(argv[2]);
    }

    if (cmd == "pack")
    {
        if (argc < 4) { Usage(); return 1; }
        std::filesystem::path in  = argv[2];
        std::filesystem::path out = argv[3];
        pe::PackOptions opts;
        for (int i = 4; i < argc; ++i)
        {
            std::string_view a = argv[i];
            auto need = [&](const char* name) -> const char* {
                if (i + 1 >= argc) {
                    std::fprintf(stderr, "%s needs an argument\n", name);
                    std::exit(1);
                }
                return argv[++i];
            };
            if      (a == "--key")     opts.xorKey = static_cast<std::uint8_t>(
                                            std::strtoul(need("--key"), nullptr, 0));
            else if (a == "--section") opts.sectionName = need("--section");
            else if (a == "--stub")    opts.stubSectionName = need("--stub");
            else {
                std::fprintf(stderr, "unrecognised: %.*s\n",
                             static_cast<int>(a.size()), a.data());
                return 1;
            }
        }
        return RunPack(in, out, opts);
    }

    Usage();
    return 1;
}
