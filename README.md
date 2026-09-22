# SymCheck

[![License: MIT](docs/badges/license.svg)](LICENSE)
[![Platform](docs/badges/platform.svg)](#)
[![C++](docs/badges/cxx.svg)](#)
[![Build](docs/badges/build.svg)](#build)

SymCheck is a Windows CLI for investigating C/C++ symbol and linker problems in `.obj`, `.lib`, `.dll`, and `.exe` files.

It parses PE/COFF itself (no dumpbin / LLVM / LIEF). Optional PDB via dbghelp, ELF64 symbols, and DWARF `.debug_line`.

## Build

```bat
build.bat
```

Finds Visual Studio with `vswhere`, runs CMake + NMake, runs unit tests. Output: `build\symcheck.exe`. Wrapper: `symcheck.bat`.

## Usage

```bat
symcheck.bat why "Namespace::fn(int)" --root out
symcheck.bat why "Namespace::fn(int)" --root out --verbose
symcheck.bat explain link.log --root out
symcheck.bat find "Namespace::fn" --root out
symcheck.bat inspect foo.lib
symcheck.bat help
```

PowerShell: use `.\symcheck.bat` from the current directory.

## Demo

Broken-link sample under `tests/calculator` (see [DEMO.md](tests/calculator/DEMO.md)):

```bat
cd tests\calculator
build.bat
diagnose.bat
```

## Commands

`inspect` `symbol` `find` `why` `explain` `trace` `abi` `snapshot` `ci` `security` `symbolize` `exports` `imports` `deps` `duplicates` `matrix` `compare`

## Layout

```
include/symcheck/   public headers
src/                implementation
tests/unit/         unit tests
tests/calculator/   intentional linker-failure demo
docs/               architecture notes
ide/                VS Code task examples
```

## Docs

[ARCHITECTURE](docs/ARCHITECTURE.md) · [ROADMAP](docs/ROADMAP.md) · [LICENSE](LICENSE)

Not a compiler, debugger, decompiler, or auto-fixer.
