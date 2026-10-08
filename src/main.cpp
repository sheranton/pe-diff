// pe-diff — compare two PE files and report structural differences.
//
// Walks both files' DOS/NT headers, section tables, import directories,
// and export directories, then prints a diff of what changed between
// them. Useful for comparing versions of the same binary, verifying a
// patch, or spot-checking what differs between two builds.
//
// Exit codes:
//   0 — files are structurally identical (ignoring timestamp changes)
//   1 — differences found
//   2 — input error (missing file, malformed PE)
//
// Build: CMake 3.15+, MSVC or MinGW-w64 (C++17). Handles 32- and 64-bit PE.

#include <windows.h>

#include <algorithm>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <optional>
#include <set>
#include <string>
#include <unordered_set>
#include <vector>

namespace {

std::vector<unsigned char> read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::fprintf(stderr, "error: cannot open '%s'\n", path.c_str());
        std::exit(2);
    }
    in.seekg(0, std::ios::end);
    const auto size = static_cast<std::size_t>(in.tellg());
    in.seekg(0, std::ios::beg);
    std::vector<unsigned char> bytes(size);
    in.read(reinterpret_cast<char*>(bytes.data()), size);
    return bytes;
}

struct ImportedFn {
    std::string dll;
    std::string name;  // empty for ordinal imports
    std::uint16_t ordinal{0};
};

struct PEInfo {
    std::string path;
    WORD        machine{0};
    DWORD       timestamp{0};
    WORD        characteristics{0};
    WORD        subsystem{0};
    bool        is_64{false};
    std::uint64_t image_base{0};
    DWORD       size_of_image{0};
    DWORD       entry_point{0};

    struct Section {
        std::string  name;
        DWORD        virtual_size{0};
        DWORD        virtual_address{0};
        DWORD        raw_size{0};
        DWORD        characteristics{0};
    };
    std::vector<Section> sections;

    std::vector<std::string> imported_dlls;
    std::vector<ImportedFn>  imported_fns;
    std::vector<std::string> exports;
};

const char* machine_name(WORD machine) {
    switch (machine) {
        case IMAGE_FILE_MACHINE_I386:  return "x86";
        case IMAGE_FILE_MACHINE_AMD64: return "x64";
        case IMAGE_FILE_MACHINE_ARM64: return "ARM64";
        default:                       return "unknown";
    }
}

std::optional<std::size_t> rva_to_offset(
    const PEInfo& info, const std::vector<unsigned char>& image, DWORD rva) {
    for (const auto& s : info.sections) {
        if (rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size) {
            const auto off = (rva - s.virtual_address);
            // Find raw offset for this section by locating the matching section
            // header in the raw bytes. We stored virtual_address but not raw
            // offset; re-parse quickly.
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.data());
            const auto nt_off = dos->e_lfanew + sizeof(DWORD);
            const auto* fh = reinterpret_cast<const IMAGE_FILE_HEADER*>(
                image.data() + nt_off);
            const auto sec_off = nt_off + sizeof(IMAGE_FILE_HEADER) + fh->SizeOfOptionalHeader;
            const auto* raw_sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
                image.data() + sec_off);
            for (WORD i = 0; i < fh->NumberOfSections; ++i) {
                if (raw_sections[i].VirtualAddress == s.virtual_address) {
                    return raw_sections[i].PointerToRawData + off;
                }
            }
        }
    }
    return std::nullopt;
}

PEInfo parse_pe(const std::string& path) {
    const auto image = read_file(path);
    PEInfo info;
    info.path = path;

    if (image.size() < sizeof(IMAGE_DOS_HEADER)) {
        std::fprintf(stderr, "error: '%s' too small\n", path.c_str());
        std::exit(2);
    }
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        std::fprintf(stderr, "error: '%s' not a PE file\n", path.c_str());
        std::exit(2);
    }

    const auto nt_off = dos->e_lfanew;
    const auto* sig = reinterpret_cast<const DWORD*>(image.data() + nt_off);
    if (*sig != IMAGE_NT_SIGNATURE) {
        std::fprintf(stderr, "error: '%s' missing PE signature\n", path.c_str());
        std::exit(2);
    }
    const auto* fh = reinterpret_cast<const IMAGE_FILE_HEADER*>(
        image.data() + nt_off + sizeof(DWORD));
    info.machine         = fh->Machine;
    info.timestamp       = fh->TimeDateStamp;
    info.characteristics = fh->Characteristics;

    const auto opt_off = nt_off + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    const auto* magic = reinterpret_cast<const WORD*>(image.data() + opt_off);
    info.is_64 = (*magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    DWORD import_rva = 0;
    DWORD export_rva = 0;

    if (info.is_64) {
        const auto* oh = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(
            image.data() + opt_off);
        info.subsystem     = oh->Subsystem;
        info.image_base    = oh->ImageBase;
        info.size_of_image = oh->SizeOfImage;
        info.entry_point   = oh->AddressOfEntryPoint;
        import_rva = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        export_rva = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    } else {
        const auto* oh = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(
            image.data() + opt_off);
        info.subsystem     = oh->Subsystem;
        info.image_base    = oh->ImageBase;
        info.size_of_image = oh->SizeOfImage;
        info.entry_point   = oh->AddressOfEntryPoint;
        import_rva = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        export_rva = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    }

    const auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        image.data() + opt_off + fh->SizeOfOptionalHeader);
    for (WORD i = 0; i < fh->NumberOfSections; ++i) {
        PEInfo::Section s;
        char name[9] = {};
        std::memcpy(name, sections[i].Name, 8);
        s.name            = name;
        s.virtual_size    = sections[i].Misc.VirtualSize;
        s.virtual_address = sections[i].VirtualAddress;
        s.raw_size        = sections[i].SizeOfRawData;
        s.characteristics = sections[i].Characteristics;
        info.sections.push_back(std::move(s));
    }

    // Imports
    if (import_rva) {
        if (const auto off = rva_to_offset(info, image, import_rva)) {
            const auto* desc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
                image.data() + *off);
            for (std::size_t i = 0; desc[i].Name; ++i) {
                const auto name_off = rva_to_offset(info, image, desc[i].Name);
                if (!name_off) continue;
                const char* dll_name = reinterpret_cast<const char*>(image.data() + *name_off);
                info.imported_dlls.emplace_back(dll_name);

                const auto thunk_rva = desc[i].OriginalFirstThunk ? desc[i].OriginalFirstThunk
                                                                  : desc[i].FirstThunk;
                const auto thunk_off = rva_to_offset(info, image, thunk_rva);
                if (!thunk_off) continue;

                if (info.is_64) {
                    const auto* thunks = reinterpret_cast<const ULONGLONG*>(
                        image.data() + *thunk_off);
                    for (std::size_t j = 0; thunks[j]; ++j) {
                        ImportedFn fn;
                        fn.dll = dll_name;
                        if (thunks[j] & 0x8000000000000000ULL) {
                            fn.ordinal = static_cast<std::uint16_t>(thunks[j] & 0xffff);
                        } else {
                            const auto hint_off = rva_to_offset(
                                info, image, static_cast<DWORD>(thunks[j]));
                            if (hint_off && *hint_off + 2 < image.size()) {
                                fn.name = reinterpret_cast<const char*>(
                                    image.data() + *hint_off + 2);
                            }
                        }
                        info.imported_fns.push_back(std::move(fn));
                    }
                } else {
                    const auto* thunks = reinterpret_cast<const DWORD*>(
                        image.data() + *thunk_off);
                    for (std::size_t j = 0; thunks[j]; ++j) {
                        ImportedFn fn;
                        fn.dll = dll_name;
                        if (thunks[j] & 0x80000000U) {
                            fn.ordinal = static_cast<std::uint16_t>(thunks[j] & 0xffff);
                        } else {
                            const auto hint_off = rva_to_offset(info, image, thunks[j]);
                            if (hint_off && *hint_off + 2 < image.size()) {
                                fn.name = reinterpret_cast<const char*>(
                                    image.data() + *hint_off + 2);
                            }
                        }
                        info.imported_fns.push_back(std::move(fn));
                    }
                }
            }
        }
    }

    // Exports
    if (export_rva) {
        if (const auto off = rva_to_offset(info, image, export_rva)) {
            const auto* dir = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
                image.data() + *off);
            const auto name_table_off = rva_to_offset(info, image, dir->AddressOfNames);
            if (name_table_off) {
                const auto* name_rvas = reinterpret_cast<const DWORD*>(
                    image.data() + *name_table_off);
                for (DWORD i = 0; i < dir->NumberOfNames; ++i) {
                    const auto n_off = rva_to_offset(info, image, name_rvas[i]);
                    if (!n_off) continue;
                    info.exports.emplace_back(reinterpret_cast<const char*>(image.data() + *n_off));
                }
            }
        }
    }

    std::sort(info.imported_dlls.begin(), info.imported_dlls.end());
    std::sort(info.exports.begin(), info.exports.end());
    return info;
}

struct DiffCounters {
    int header_diffs = 0;
    int section_diffs = 0;
    int import_diffs = 0;
    int export_diffs = 0;

    int total() const { return header_diffs + section_diffs + import_diffs + export_diffs; }
};

void diff_headers(const PEInfo& a, const PEInfo& b, DiffCounters& c, bool ignore_ts) {
    std::printf("== Headers ==\n");
    bool any = false;
    if (a.machine != b.machine) {
        std::printf("  machine:         %s -> %s\n", machine_name(a.machine), machine_name(b.machine));
        ++c.header_diffs; any = true;
    }
    if (!ignore_ts && a.timestamp != b.timestamp) {
        std::printf("  timestamp:       0x%08lx -> 0x%08lx\n",
                    static_cast<unsigned long>(a.timestamp),
                    static_cast<unsigned long>(b.timestamp));
        ++c.header_diffs; any = true;
    }
    if (a.characteristics != b.characteristics) {
        std::printf("  characteristics: 0x%04x -> 0x%04x\n", a.characteristics, b.characteristics);
        ++c.header_diffs; any = true;
    }
    if (a.subsystem != b.subsystem) {
        std::printf("  subsystem:       %u -> %u\n", a.subsystem, b.subsystem);
        ++c.header_diffs; any = true;
    }
    if (a.image_base != b.image_base) {
        std::printf("  image_base:      0x%016" PRIx64 " -> 0x%016" PRIx64 "\n",
                    a.image_base, b.image_base);
        ++c.header_diffs; any = true;
    }
    if (a.size_of_image != b.size_of_image) {
        std::printf("  size_of_image:   0x%08lx -> 0x%08lx\n",
                    static_cast<unsigned long>(a.size_of_image),
                    static_cast<unsigned long>(b.size_of_image));
        ++c.header_diffs; any = true;
    }
    if (a.entry_point != b.entry_point) {
        std::printf("  entry_point:     0x%08lx -> 0x%08lx\n",
                    static_cast<unsigned long>(a.entry_point),
                    static_cast<unsigned long>(b.entry_point));
        ++c.header_diffs; any = true;
    }
    if (!any) std::printf("  (no changes)\n");
}

void diff_sections(const PEInfo& a, const PEInfo& b, DiffCounters& c) {
    std::printf("\n== Sections ==\n");
    std::set<std::string> all_names;
    for (const auto& s : a.sections) all_names.insert(s.name);
    for (const auto& s : b.sections) all_names.insert(s.name);

    bool any = false;
    for (const auto& n : all_names) {
        auto a_it = std::find_if(a.sections.begin(), a.sections.end(),
                                 [&](const auto& s) { return s.name == n; });
        auto b_it = std::find_if(b.sections.begin(), b.sections.end(),
                                 [&](const auto& s) { return s.name == n; });
        if (a_it == a.sections.end()) {
            std::printf("  + %-9s (added, virt_size 0x%lx)\n",
                        n.c_str(), static_cast<unsigned long>(b_it->virtual_size));
            ++c.section_diffs; any = true;
        } else if (b_it == b.sections.end()) {
            std::printf("  - %-9s (removed, virt_size 0x%lx)\n",
                        n.c_str(), static_cast<unsigned long>(a_it->virtual_size));
            ++c.section_diffs; any = true;
        } else if (a_it->virtual_size != b_it->virtual_size ||
                   a_it->characteristics != b_it->characteristics) {
            std::printf("  ~ %-9s virt_size 0x%lx -> 0x%lx  chars 0x%08lx -> 0x%08lx\n",
                        n.c_str(),
                        static_cast<unsigned long>(a_it->virtual_size),
                        static_cast<unsigned long>(b_it->virtual_size),
                        static_cast<unsigned long>(a_it->characteristics),
                        static_cast<unsigned long>(b_it->characteristics));
            ++c.section_diffs; any = true;
        }
    }
    if (!any) std::printf("  (no changes)\n");
}

void diff_imports(const PEInfo& a, const PEInfo& b, DiffCounters& c) {
    std::printf("\n== Imports ==\n");
    std::set<std::string> a_dlls(a.imported_dlls.begin(), a.imported_dlls.end());
    std::set<std::string> b_dlls(b.imported_dlls.begin(), b.imported_dlls.end());

    bool any = false;
    for (const auto& d : a_dlls) {
        if (!b_dlls.count(d)) {
            std::printf("  - %s (DLL removed)\n", d.c_str());
            ++c.import_diffs; any = true;
        }
    }
    for (const auto& d : b_dlls) {
        if (!a_dlls.count(d)) {
            std::printf("  + %s (DLL added)\n", d.c_str());
            ++c.import_diffs; any = true;
        }
    }

    auto key = [](const ImportedFn& f) {
        return f.dll + "::" + (f.name.empty() ? ("#" + std::to_string(f.ordinal)) : f.name);
    };
    std::unordered_set<std::string> a_keys, b_keys;
    for (const auto& f : a.imported_fns) a_keys.insert(key(f));
    for (const auto& f : b.imported_fns) b_keys.insert(key(f));

    std::vector<std::string> removed, added;
    for (const auto& k : a_keys) if (!b_keys.count(k)) removed.push_back(k);
    for (const auto& k : b_keys) if (!a_keys.count(k)) added.push_back(k);
    std::sort(removed.begin(), removed.end());
    std::sort(added.begin(), added.end());

    for (const auto& k : removed) {
        std::printf("    - %s\n", k.c_str());
        ++c.import_diffs; any = true;
    }
    for (const auto& k : added) {
        std::printf("    + %s\n", k.c_str());
        ++c.import_diffs; any = true;
    }
    if (!any) std::printf("  (no changes)\n");
}

void diff_exports(const PEInfo& a, const PEInfo& b, DiffCounters& c) {
    std::printf("\n== Exports ==\n");
    std::set<std::string> a_set(a.exports.begin(), a.exports.end());
    std::set<std::string> b_set(b.exports.begin(), b.exports.end());

    bool any = false;
    for (const auto& e : a_set) {
        if (!b_set.count(e)) { std::printf("  - %s\n", e.c_str()); ++c.export_diffs; any = true; }
    }
    for (const auto& e : b_set) {
        if (!a_set.count(e)) { std::printf("  + %s\n", e.c_str()); ++c.export_diffs; any = true; }
    }
    if (!any) std::printf("  (no changes)\n");
}

}  // namespace

int main(int argc, char** argv) {
    bool ignore_timestamp = false;
    const char* path_a = nullptr;
    const char* path_b = nullptr;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--ignore-timestamp") == 0 ||
            std::strcmp(argv[i], "-T") == 0) {
            ignore_timestamp = true;
        } else if (!path_a) {
            path_a = argv[i];
        } else if (!path_b) {
            path_b = argv[i];
        }
    }

    if (!path_a || !path_b) {
        std::fprintf(stderr,
                     "usage: %s [--ignore-timestamp|-T] <file-a.exe> <file-b.exe>\n",
                     argc ? argv[0] : "pe-diff");
        return 2;
    }

    const auto a = parse_pe(path_a);
    const auto b = parse_pe(path_b);

    std::printf("pe-diff\n  A: %s\n  B: %s\n\n", path_a, path_b);

    DiffCounters c;
    diff_headers(a, b, c, ignore_timestamp);
    diff_sections(a, b, c);
    diff_imports(a, b, c);
    diff_exports(a, b, c);

    std::printf("\n== Summary ==\n");
    std::printf("  %d header, %d section, %d import, %d export change(s)\n",
                c.header_diffs, c.section_diffs, c.import_diffs, c.export_diffs);

    return c.total() == 0 ? 0 : 1;
}
