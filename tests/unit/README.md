# Unit tests

`symcheck_tests` builds with the main CMake project and runs via `ctest`.

Files:

- `fixtures.hpp` - tiny synthetic PE/COFF bytes for parser tests
- `test_*.cpp` - one area per file
- `test_main.cpp` - runs every suite

These test SymCheck itself. For a sample app that *uses* SymCheck, see `../calculator/DEMO.md`.
