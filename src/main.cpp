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
// Build: CMake 3.15+, C++17 (MSVC, MinGW-w64, GCC or Clang). Handles 32- and
// 64-bit PE files on any host OS.

#include "pe_format.hpp"
#include "term.hpp"

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

// Returns `count` consecutive T at `offset`, or exits with the input-error
// status if any of them would lie outside the file.
template <typename T>
const T* at(const std::vector<unsigned char>& image, std::size_t offset,
            std::size_t count = 1) {
    if (offset > image.size() || count > (image.size() - offset) / sizeof(T)) {
        std::fprintf(stderr, "error: offset 0x%zx exceeds file size (malformed PE?)\n", offset);
        std::exit(2);
    }
    return reinterpret_cast<const T*>(image.data() + offset);
}

// NUL-terminated string at `offset`, cut off at the end of the file if the
// terminator is missing.
std::string cstr_at(const std::vector<unsigned char>& image, std::size_t offset) {
    std::string out;
    for (std::size_t i = offset; i < image.size() && image[i] != 0; ++i) {
        out.push_back(static_cast<char>(image[i]));
    }
    return out;
}

struct RawSection {
    DWORD virtual_address;
    DWORD virtual_size;
    DWORD raw_offset;
};

std::optional<std::size_t> rva_to_offset(const std::vector<RawSection>& sections, DWORD rva) {
    for (const auto& s : sections) {
        if (rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size) {
            return static_cast<std::size_t>(s.raw_offset) + (rva - s.virtual_address);
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
    const auto* dos = at<IMAGE_DOS_HEADER>(image, 0);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        std::fprintf(stderr, "error: '%s' not a PE file\n", path.c_str());
        std::exit(2);
    }

    const auto nt_off = static_cast<std::size_t>(static_cast<DWORD>(dos->e_lfanew));
    if (*at<DWORD>(image, nt_off) != IMAGE_NT_SIGNATURE) {
        std::fprintf(stderr, "error: '%s' missing PE signature\n", path.c_str());
        std::exit(2);
    }
    const auto* fh = at<IMAGE_FILE_HEADER>(image, nt_off + sizeof(DWORD));
    info.machine         = fh->Machine;
    info.timestamp       = fh->TimeDateStamp;
    info.characteristics = fh->Characteristics;

    const auto opt_off = nt_off + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    info.is_64 = (*at<WORD>(image, opt_off) == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    DWORD import_rva = 0;
    DWORD export_rva = 0;

    if (info.is_64) {
        const auto* oh = at<IMAGE_OPTIONAL_HEADER64>(image, opt_off);
        info.subsystem     = oh->Subsystem;
        info.image_base    = oh->ImageBase;
        info.size_of_image = oh->SizeOfImage;
        info.entry_point   = oh->AddressOfEntryPoint;
        import_rva = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        export_rva = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    } else {
        const auto* oh = at<IMAGE_OPTIONAL_HEADER32>(image, opt_off);
        info.subsystem     = oh->Subsystem;
        info.image_base    = oh->ImageBase;
        info.size_of_image = oh->SizeOfImage;
        info.entry_point   = oh->AddressOfEntryPoint;
        import_rva = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        export_rva = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    }

    const auto* sections = at<IMAGE_SECTION_HEADER>(
        image, opt_off + fh->SizeOfOptionalHeader, fh->NumberOfSections);
    std::vector<RawSection> raw;
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
        raw.push_back({sections[i].VirtualAddress, sections[i].Misc.VirtualSize,
                       sections[i].PointerToRawData});
    }

    // Imports
    if (import_rva) {
        if (const auto off = rva_to_offset(raw, import_rva)) {
            for (std::size_t i = 0;; ++i) {
                const auto& desc = *at<IMAGE_IMPORT_DESCRIPTOR>(
                    image, *off + i * sizeof(IMAGE_IMPORT_DESCRIPTOR));
                if (!desc.Name) break;
                const auto name_off = rva_to_offset(raw, desc.Name);
                if (!name_off) continue;
                const auto dll_name = cstr_at(image, *name_off);
                info.imported_dlls.push_back(dll_name);

                const auto thunk_rva = desc.OriginalFirstThunk ? desc.OriginalFirstThunk
                                                               : desc.FirstThunk;
                const auto thunk_off = rva_to_offset(raw, thunk_rva);
                if (!thunk_off) continue;

                const std::size_t thunk_size = info.is_64 ? sizeof(ULONGLONG) : sizeof(DWORD);
                const ULONGLONG ordinal_flag = info.is_64 ? 0x8000000000000000ULL : 0x80000000ULL;
                for (std::size_t j = 0;; ++j) {
                    const auto thunk_pos = *thunk_off + j * thunk_size;
                    const ULONGLONG thunk = info.is_64 ? *at<ULONGLONG>(image, thunk_pos)
                                                       : *at<DWORD>(image, thunk_pos);
                    if (!thunk) break;
                    ImportedFn fn;
                    fn.dll = dll_name;
                    if (thunk & ordinal_flag) {
                        fn.ordinal = static_cast<std::uint16_t>(thunk & 0xffff);
                    } else {
                        const auto hint_off = rva_to_offset(raw, static_cast<DWORD>(thunk));
                        if (hint_off && *hint_off + 2 < image.size()) {
                            fn.name = cstr_at(image, *hint_off + 2);
                        }
                    }
                    info.imported_fns.push_back(std::move(fn));
                }
            }
        }
    }

    // Exports
    if (export_rva) {
        if (const auto off = rva_to_offset(raw, export_rva)) {
            const auto* dir = at<IMAGE_EXPORT_DIRECTORY>(image, *off);
            const auto name_table_off = rva_to_offset(raw, dir->AddressOfNames);
            if (name_table_off) {
                const auto* name_rvas = at<DWORD>(image, *name_table_off, dir->NumberOfNames);
                for (DWORD i = 0; i < dir->NumberOfNames; ++i) {
                    const auto n_off = rva_to_offset(raw, name_rvas[i]);
                    if (!n_off) continue;
                    info.exports.push_back(cstr_at(image, *n_off));
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

void heading(const char* text) {
    std::printf("%s%s%s\n", term::bold(), text, term::reset());
}

std::string hex(std::uint64_t value, int width) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%0*" PRIx64, width, value);
    return buf;
}

void diff_headers(const PEInfo& a, const PEInfo& b, DiffCounters& c, bool ignore_ts) {
    heading("== Headers ==");
    const int before = c.header_diffs;
    // "  label:   old -> new", with the old value red and the new one green.
    const auto field = [&](bool differs, const char* label, const std::string& x,
                           const std::string& y) {
        if (!differs) return;
        std::printf("  %-17s%s%s%s -> %s%s%s\n", label, term::red(), x.c_str(), term::reset(),
                    term::green(), y.c_str(), term::reset());
        ++c.header_diffs;
    };
    field(a.machine != b.machine, "machine:", machine_name(a.machine), machine_name(b.machine));
    field(!ignore_ts && a.timestamp != b.timestamp, "timestamp:", hex(a.timestamp, 8),
          hex(b.timestamp, 8));
    field(a.characteristics != b.characteristics, "characteristics:", hex(a.characteristics, 4),
          hex(b.characteristics, 4));
    field(a.subsystem != b.subsystem, "subsystem:", std::to_string(a.subsystem),
          std::to_string(b.subsystem));
    field(a.image_base != b.image_base, "image_base:", hex(a.image_base, 16), hex(b.image_base, 16));
    field(a.size_of_image != b.size_of_image, "size_of_image:", hex(a.size_of_image, 8),
          hex(b.size_of_image, 8));
    field(a.entry_point != b.entry_point, "entry_point:", hex(a.entry_point, 8),
          hex(b.entry_point, 8));
    if (c.header_diffs == before) std::printf("  %s(no changes)%s\n", term::dim(), term::reset());
}

void diff_sections(const PEInfo& a, const PEInfo& b, DiffCounters& c) {
    std::printf("\n");
    heading("== Sections ==");
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
            std::printf("%s  + %-9s (added, virt_size 0x%lx)%s\n", term::green(),
                        n.c_str(), static_cast<unsigned long>(b_it->virtual_size), term::reset());
            ++c.section_diffs; any = true;
        } else if (b_it == b.sections.end()) {
            std::printf("%s  - %-9s (removed, virt_size 0x%lx)%s\n", term::red(),
                        n.c_str(), static_cast<unsigned long>(a_it->virtual_size), term::reset());
            ++c.section_diffs; any = true;
        } else if (a_it->virtual_size != b_it->virtual_size ||
                   a_it->characteristics != b_it->characteristics) {
            std::printf("%s  ~ %-9s virt_size 0x%lx -> 0x%lx  chars 0x%08lx -> 0x%08lx%s\n",
                        term::yellow(), n.c_str(),
                        static_cast<unsigned long>(a_it->virtual_size),
                        static_cast<unsigned long>(b_it->virtual_size),
                        static_cast<unsigned long>(a_it->characteristics),
                        static_cast<unsigned long>(b_it->characteristics), term::reset());
            ++c.section_diffs; any = true;
        }
    }
    if (!any) std::printf("  %s(no changes)%s\n", term::dim(), term::reset());
}

void diff_imports(const PEInfo& a, const PEInfo& b, DiffCounters& c) {
    std::printf("\n");
    heading("== Imports ==");
    std::set<std::string> a_dlls(a.imported_dlls.begin(), a.imported_dlls.end());
    std::set<std::string> b_dlls(b.imported_dlls.begin(), b.imported_dlls.end());

    bool any = false;
    for (const auto& d : a_dlls) {
        if (!b_dlls.count(d)) {
            std::printf("%s  - %s (DLL removed)%s\n", term::red(), d.c_str(), term::reset());
            ++c.import_diffs; any = true;
        }
    }
    for (const auto& d : b_dlls) {
        if (!a_dlls.count(d)) {
            std::printf("%s  + %s (DLL added)%s\n", term::green(), d.c_str(), term::reset());
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
        std::printf("%s    - %s%s\n", term::red(), k.c_str(), term::reset());
        ++c.import_diffs; any = true;
    }
    for (const auto& k : added) {
        std::printf("%s    + %s%s\n", term::green(), k.c_str(), term::reset());
        ++c.import_diffs; any = true;
    }
    if (!any) std::printf("  %s(no changes)%s\n", term::dim(), term::reset());
}

void diff_exports(const PEInfo& a, const PEInfo& b, DiffCounters& c) {
    std::printf("\n");
    heading("== Exports ==");
    std::set<std::string> a_set(a.exports.begin(), a.exports.end());
    std::set<std::string> b_set(b.exports.begin(), b.exports.end());

    bool any = false;
    for (const auto& e : a_set) {
        if (!b_set.count(e)) {
            std::printf("%s  - %s%s\n", term::red(), e.c_str(), term::reset());
            ++c.export_diffs;
            any = true;
        }
    }
    for (const auto& e : b_set) {
        if (!a_set.count(e)) {
            std::printf("%s  + %s%s\n", term::green(), e.c_str(), term::reset());
            ++c.export_diffs;
            any = true;
        }
    }
    if (!any) std::printf("  %s(no changes)%s\n", term::dim(), term::reset());
}

}  // namespace

int main(int argc, char** argv) {
    bool ignore_timestamp = false;
    bool bad_flag = false;
    term::Mode color = term::Mode::Auto;
    const char* path_a = nullptr;
    const char* path_b = nullptr;

    for (int i = 1; i < argc; ++i) {
        const int cf = term::parse_flag(argc, argv, i, color);
        if (cf != 0) {
            bad_flag |= cf < 0;
        } else if (std::strcmp(argv[i], "--ignore-timestamp") == 0 ||
                   std::strcmp(argv[i], "-T") == 0) {
            ignore_timestamp = true;
        } else if (!path_a) {
            path_a = argv[i];
        } else if (!path_b) {
            path_b = argv[i];
        }
    }

    if (!path_a || !path_b || bad_flag) {
        std::fprintf(stderr,
                     "usage: %s [--ignore-timestamp|-T] [--color auto|always|never] <file-a.exe> <file-b.exe>\n",
                     argc ? argv[0] : "pe-diff");
        return 2;
    }
    term::init(color);

    const auto a = parse_pe(path_a);
    const auto b = parse_pe(path_b);

    std::printf("%spe-diff%s\n  A: %s%s%s\n  B: %s%s%s\n\n", term::bold(), term::reset(),
                term::red(), path_a, term::reset(), term::green(), path_b, term::reset());

    DiffCounters c;
    diff_headers(a, b, c, ignore_timestamp);
    diff_sections(a, b, c);
    diff_imports(a, b, c);
    diff_exports(a, b, c);

    std::printf("\n");
    heading("== Summary ==");
    std::printf("  %s%d header, %d section, %d import, %d export change(s)%s\n", term::bold(),
                c.header_diffs, c.section_diffs, c.import_diffs, c.export_diffs, term::reset());

    return c.total() == 0 ? 0 : 1;
}
