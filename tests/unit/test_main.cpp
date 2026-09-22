#include <cstdio>

void run_byte_reader_tests();
void run_coff_tests();
void run_archive_tests();
void run_pe_tests();
void run_match_tests();
void run_explain_parse_tests();
void run_signature_diff_tests();
void run_abi_tests();
void run_elf_tests();
void run_snapshot_tests();
void run_security_tests();
void run_symbolize_parse_tests();
void run_dwarf_line_tests();

int main() {
  run_byte_reader_tests();
  run_coff_tests();
  run_archive_tests();
  run_pe_tests();
  run_match_tests();
  run_explain_parse_tests();
  run_signature_diff_tests();
  run_abi_tests();
  run_elf_tests();
  run_snapshot_tests();
  run_security_tests();
  run_symbolize_parse_tests();
  run_dwarf_line_tests();
  std::puts("all tests passed");
  return 0;
}
