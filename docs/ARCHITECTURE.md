# Architecture

SymCheck turns compiled Windows (and some ELF) artifacts into a shared symbol model, then answers questions about that model.

```
PE/COFF / ELF / PDB loaders
        |
   BinaryImage IR
        |
   project scan + cache
        |
   matcher (exact / closest)
        |
   diagnostics (why, explain, abi, security, ...)
        |
   CLI renderer (--json / --verbose / SARIF for ci)
```

## Why this shape

**Own parsers, shared IR.** Commands never talk to PE/COFF/ELF directly. Everything goes through `BinaryImage` / `Symbol` so `find`, `why`, `matrix`, and `ci` share one inventory.

**No LLVM/LIEF/dumpbin.** Keeps the binary small and the dependency story honest for a Windows MSVC shop. Tradeoff: less format coverage; ELF/DWARF are best-effort.

**Demangle at load (MSVC dbghelp).** Matching prefers demangled/core names because linker logs and humans rarely paste full mangling. Exact mangled match still ranks first when available.

**Archive members tracked.** A `.lib` hit reports `calc.lib -> divide.obj` so duplicate and mismatch reports point at the real object, not only the archive.

**`why` is ranked evidence, not a proof.** Default CLI output is compact (requested / closest / difference / diagnosis / likely causes / fix). Confidence fields and search inventory stay behind `--verbose` because most users want the next action, not the internal scorecard.

**Build discovery is optional (`--discover`).** Default roots stay simple (`.`, `build`, `lib`, `bin`, `third_party`). CMake/Ninja/`compile_commands.json`/MSBuild markers only expand roots when asked.

## Load order

1. COFF archive (`!<arch>`)
2. PE (`MZ` + `PE\0\0`) — also reads CodeView RSDS PDB path, section flags, DLL characteristics
3. ELF64 symbols (+ `.debug_line` when present)
4. PDB via dbghelp
5. COFF object

## Match ranks

1. Exact mangled / equivalent demangled
2. Same base name, different parameters
3. C vs C++ linkage
4. Architecture mismatch
5. Present but not exported
6. Not found

## Safety notes

Parsers bound table sizes from headers, reject truncated input, and avoid recursion. Failures return `Result`. The tool does not modify user files.

## Platform

Primary host is Windows + MSVC tooling. ELF64 objects can be inspected when present.
