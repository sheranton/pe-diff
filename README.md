<p align="center">
  <img src="docs/banner.svg" width="100%" alt="pe-diff: what changed between two builds, at the level the loader sees it">
</p>

<p align="center">
  <a href="https://github.com/td185721/pe-diff/actions/workflows/ci.yml"><img src="https://github.com/td185721/pe-diff/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/td185721/pe-diff/releases/latest"><img src="https://img.shields.io/github/v/release/td185721/pe-diff?color=ff7b72" alt="Latest release"></a>
  <img src="https://img.shields.io/badge/C%2B%2B-17-00599C?logo=cplusplus&logoColor=white" alt="C++17">
  <img src="https://img.shields.io/badge/runs%20on-Windows%20%7C%20Linux%20%7C%20macOS-30363d" alt="Runs on Windows, Linux and macOS">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT license"></a>
</p>

<p align="center">
  <sub><b>Toolkit:</b> <a href="https://github.com/td185721/pe-walker">pe-walker</a> · <b>pe-diff</b> · <a href="https://github.com/td185721/rtti-dump">rtti-dump</a> · <a href="https://github.com/td185721/vtable-dump">vtable-dump</a> · <a href="https://github.com/td185721/pattern-scan">pattern-scan</a> · <a href="https://github.com/td185721/unwind-map">unwind-map</a></sub>
</p>

`pe-diff` compares two Portable Executable files and reports what changed in their structure: headers, sections, imported DLLs and functions, and exports. Byte-level diffs drown in noise from addresses that shift with every rebuild; `pe-diff` shows the changes the loader and the linker care about. It exits non-zero when anything differs, so it can gate a CI pipeline.

<p align="center">
  <img src="docs/demo.svg" width="640" alt="Animated terminal demo: pe-diff comparing the two fixture DLLs in color, exit status 1">
</p>

## Use cases

- **Patch analysis:** see what an update changed in a binary before reversing the code.
- **Dependency drift:** catch a release build that gains an unexpected DLL or API import.
- **Reproducibility:** confirm two builds are structurally identical.
- **Supply-chain checks:** fail a pipeline when an artifact's exports or imports change unexpectedly.

## Example

Real output comparing the two test fixtures in [`tests/fixtures`](tests/fixtures). The v2 build adds one exported function, `sample_ticks`, which calls `GetTickCount`:

```console
$ pe-diff -T sample64.dll sample64-v2.dll
pe-diff
  A: sample64.dll
  B: sample64-v2.dll

== Headers ==
  entry_point:     0x0000177c -> 0x0000178c

== Sections ==
  ~ .rdata    virt_size 0x183c -> 0x186c  chars 0x40000040 -> 0x40000040
  ~ .text     virt_size 0x1358 -> 0x1368  chars 0x60000020 -> 0x60000020

== Imports ==
    + KERNEL32.dll::GetTickCount

== Exports ==
  + sample_ticks

== Summary ==
  1 header, 2 section, 1 import, 1 export change(s)
$ echo $?
1
```

## Why these five changes

<p align="center">
  <img src="docs/how-it-works.svg" width="100%" alt="One added function in the source leads to an added export, an added import, larger .text and .rdata sections and a moved entry point">
</p>

The v2 fixture differs from v1 by one function. pe-diff reports its direct effects (a new export and a new import) and its side effects (two sections grow and the entry point moves), each as one line.

## Install

Download a prebuilt binary for Windows x64, Linux x64 (statically linked) or macOS arm64 from the [latest release](https://github.com/td185721/pe-diff/releases/latest), or build from source with CMake 3.15+ and any C++17 compiler:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release      # optional: run the test suite
```

## Usage

```text
pe-diff [--ignore-timestamp|-T] [--color auto|always|never] <old.exe|old.dll> <new.exe|new.dll>
```

| Flag | Effect |
|---|---|
| `--ignore-timestamp`, `-T` | Skip `TimeDateStamp` in the header comparison. Two legitimate builds almost always differ there. |
| `--color WHEN` | `auto` (default) colors added lines green, removed lines red and changed lines yellow, only on a terminal; `always` and `never` force it. Setting `NO_COLOR` turns colors off. |

| Exit status | Meaning |
|---|---|
| `0` | The files are structurally identical. |
| `1` | At least one difference was found. |
| `2` | Input error: missing file, or a malformed or truncated PE. |

Use it as a gate in a CI pipeline:

```sh
pe-diff -T baseline/app.exe build/app.exe || echo "structure changed, review the diff above"
```

## What it compares

| Area | Compared |
|---|---|
| Headers | machine, timestamp (unless `-T`), characteristics, subsystem, image base, size of image, entry point |
| Sections | added and removed sections, virtual size, characteristics |
| Imports | added and removed DLLs, and functions as `DLL::name` or `DLL::#ordinal` |
| Exports | added and removed names |

It does not diff section contents byte by byte, or compare resources, relocations, TLS callbacks, the debug directory or signatures. For byte-level changes inside a section, pair it with a hex or binary diff tool.

## Robustness

Both inputs are parsed with bounds-checked reads; a malformed file is reported with exit status `2` instead of crashing. When that parser was hardened, the old and new builds were run on 300 deliberately corrupted DLLs. The old build crashed on 92 of them and the new one on none. On 230 comparisons of real `System32` and `SysWOW64` binaries, the output stayed byte-for-byte identical.

## Testing

`ctest` runs golden-file tests on the fixture DLLs: identical inputs, the v1 to v2 change with and without `-T`, colored output, a missing file and usage errors, checking both output and exit status. CI runs them on Windows (MSVC), Linux (GCC) and macOS (Clang), and cross-builds with MinGW-w64.

## See also

- [pe-walker](https://github.com/td185721/pe-walker) shows the full structure of a single binary.

## License

MIT, see [LICENSE](LICENSE).
