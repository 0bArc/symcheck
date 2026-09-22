cmake_minimum_required(VERSION 3.20)
project(SymCheck VERSION 0.5.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
  add_compile_options(/W4 /WX /permissive- /EHsc)
else()
  add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

add_library(symcheck_util STATIC
  src/util/error.cpp
  src/util/mapped_file.cpp
  src/util/byte_reader.cpp
  src/util/json_escape.cpp
)
target_include_directories(symcheck_util PUBLIC include)
if(WIN32)
  target_compile_definitions(symcheck_util PUBLIC SYMCHECK_WINDOWS=1)
endif()

add_library(symcheck_ir STATIC
  src/ir/types.cpp
  src/ir/binary.cpp
  src/ir/cache.cpp
)
target_include_directories(symcheck_ir PUBLIC include)
target_link_libraries(symcheck_ir PUBLIC symcheck_util)

add_library(symcheck_demangle STATIC
  src/demangle/msvc_demangle.cpp
)
target_include_directories(symcheck_demangle PUBLIC include)
target_link_libraries(symcheck_demangle PUBLIC symcheck_util)
if(WIN32)
  target_link_libraries(symcheck_demangle PUBLIC dbghelp)
endif()

add_library(symcheck_coff STATIC
  src/coff/coff_parser.cpp
  src/lib/archive.cpp
)
target_include_directories(symcheck_coff PUBLIC include)
target_link_libraries(symcheck_coff PUBLIC symcheck_ir)

add_library(symcheck_pe STATIC
  src/pe/pe_parser.cpp
)
target_include_directories(symcheck_pe PUBLIC include)
target_link_libraries(symcheck_pe PUBLIC symcheck_ir)

add_library(symcheck_elf STATIC
  src/elf/elf_parser.cpp
  src/elf/dwarf_line.cpp
)
target_include_directories(symcheck_elf PUBLIC include)
target_link_libraries(symcheck_elf PUBLIC symcheck_ir)

add_library(symcheck_pdb STATIC
  src/debug/pdb.cpp
)
target_include_directories(symcheck_pdb PUBLIC include)
target_link_libraries(symcheck_pdb PUBLIC symcheck_ir)
if(WIN32)
  target_link_libraries(symcheck_pdb PUBLIC dbghelp)
endif()

add_library(symcheck_scan STATIC
  src/scan/scanner.cpp
)
target_include_directories(symcheck_scan PUBLIC include)
target_link_libraries(symcheck_scan PUBLIC symcheck_util)

add_library(symcheck_build STATIC
  src/build/discover.cpp
)
target_include_directories(symcheck_build PUBLIC include)
target_link_libraries(symcheck_build PUBLIC symcheck_scan)

add_library(symcheck_load STATIC
  src/load/loader.cpp
)
target_include_directories(symcheck_load PUBLIC include)
target_link_libraries(symcheck_load PUBLIC
  symcheck_coff symcheck_pe symcheck_elf symcheck_pdb symcheck_demangle)

add_library(symcheck_diag STATIC
  src/diagnose/match.cpp
  src/diagnose/explain.cpp
  src/diagnose/signature_diff.cpp
  src/diagnose/project_find.cpp
  src/diagnose/why.cpp
  src/diagnose/project_tools.cpp
  src/diagnose/abi.cpp
  src/diagnose/snapshot.cpp
  src/diagnose/trace.cpp
  src/diagnose/security.cpp
  src/diagnose/symbolize.cpp
  src/graph/import_graph.cpp
)
target_include_directories(symcheck_diag PUBLIC include)
target_link_libraries(symcheck_diag PUBLIC
  symcheck_ir symcheck_demangle symcheck_coff symcheck_pe symcheck_elf
  symcheck_pdb symcheck_scan symcheck_load)

add_executable(symcheck
  src/cli/main.cpp
  src/cli/args.cpp
  src/cli/format.cpp
  src/cli/sarif.cpp
  src/cli/cmd_inspect.cpp
  src/cli/cmd_symbol.cpp
  src/cli/cmd_exports.cpp
  src/cli/cmd_imports.cpp
  src/cli/cmd_compare.cpp
  src/cli/cmd_explain.cpp
  src/cli/cmd_graph.cpp
  src/cli/cmd_find.cpp
  src/cli/cmd_why.cpp
  src/cli/cmd_deps.cpp
  src/cli/cmd_duplicates.cpp
  src/cli/cmd_matrix.cpp
  src/cli/cmd_trace.cpp
  src/cli/cmd_abi.cpp
  src/cli/cmd_snapshot.cpp
  src/cli/cmd_ci.cpp
  src/cli/cmd_security.cpp
  src/cli/cmd_symbolize.cpp
)
target_link_libraries(symcheck PRIVATE symcheck_diag symcheck_build)

enable_testing()
add_executable(symcheck_tests
  tests/unit/test_byte_reader.cpp
  tests/unit/test_coff.cpp
  tests/unit/test_archive.cpp
  tests/unit/test_pe.cpp
  tests/unit/test_match.cpp
  tests/unit/test_explain_parse.cpp
  tests/unit/test_signature_diff.cpp
  tests/unit/test_abi.cpp
  tests/unit/test_elf.cpp
  tests/unit/test_snapshot.cpp
  tests/unit/test_phase5.cpp
  tests/unit/test_main.cpp
)
target_link_libraries(symcheck_tests PRIVATE symcheck_diag symcheck_build)
add_test(NAME symcheck_tests COMMAND symcheck_tests)

install(TARGETS symcheck RUNTIME DESTINATION bin)
