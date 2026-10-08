# pe-diff

A structural diff tool for Portable Executable files. Takes two `.exe`
or `.dll` paths and prints what changed between them at the header,
section, import, and export level.

Natural companion to [pe-walker](https://github.com/td185721/pe-walker)
— that tool inspects a single binary; this one tells you what moved
between two of them.

## Use cases

- Check what changed between two versions of the same binary (patch
  diff).
- Verify a build is byte-structurally identical to a reference.
- Spot added or removed library dependencies without reading full
  dumpbin output.
- CI check: fail the pipeline if a release build gains an unexpected
  import.

## Build

Requires CMake 3.15+ and either MSVC or MinGW-w64 with C++17.

```powershell
cmake -S . -B build
cmake --build build --config Release
```

Produces `build/Release/pe-diff.exe` (MSVC) or `build/pe-diff.exe`
(MinGW).

## Usage

```powershell
pe-diff.exe old.dll new.dll
pe-diff.exe --ignore-timestamp old.dll new.dll
```

### Flags

| flag | effect |
|------|--------|
| `--ignore-timestamp`, `-T` | skip the TimeDateStamp field in the header diff. Useful when both builds are legitimate but produced at different times (which is almost always the case for a patch comparison). |

### Exit codes

| code | meaning |
|------|---------|
| 0 | files are structurally identical |
| 1 | one or more differences found |
| 2 | input error (missing file, malformed PE) |

The non-zero-on-difference exit is suitable for use in a shell pipeline
or CI check.

## What it compares

**Headers**
- Machine (x86 / x64 / ARM64)
- TimeDateStamp (unless `-T`)
- File characteristics
- Subsystem
- Image base
- Size of image
- Entry point RVA

**Sections**
- Added / removed sections (by name)
- Virtual size changes
- Characteristics flag changes

**Imports**
- Added / removed DLL dependencies
- Added / removed function imports (by `DLL::name` or `DLL::#ordinal`)

**Exports**
- Added / removed exported function names

## What it doesn't compare (yet)

- Byte-for-byte content inside each section (treats them as opaque)
- Resource directory tree (`.rsrc`)
- Relocations (`.reloc`)
- TLS callbacks
- Debug directory contents
- Digital signature contents

For byte-level section diffing, pair the output with a hex diff tool
(`fc /b`, `cmp`, `diffoscope`) on specific sections identified here.

## Example output

```
pe-diff
  A: C:\Windows\System32\notepad.exe
  B: C:\Windows\SysWOW64\notepad.exe

== Headers ==
  machine:         x64 -> x86
  timestamp:       0x112f10a4 -> 0x1a2e3c7f
  image_base:      0x0000000140000000 -> 0x0000000001000000
  size_of_image:   0x0005a000 -> 0x00047000
  entry_point:     0x000019c0 -> 0x00005f30

== Sections ==
  ~ .text     virt_size 0x267e2 -> 0x1f1a4  chars 0x60000020 -> 0x60000020
  ~ .rdata    virt_size 0xa6c8 -> 0x8bc0    chars 0x40000040 -> 0x40000040
  ...

== Imports ==
    - KERNEL32.dll::SetFilePointerEx
    + KERNEL32.dll::SetFilePointer

== Exports ==
  (no changes)

== Summary ==
  5 header, 7 section, 2 import, 0 export change(s)
```

## License

MIT — see [LICENSE](LICENSE).
