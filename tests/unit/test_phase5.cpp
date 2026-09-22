#include "symcheck/diagnose/security.hpp"
#include "symcheck/diagnose/symbolize.hpp"
#include "symcheck/elf/dwarf_line.hpp"
#include "symcheck/ir/binary.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

void run_security_tests() {
  using namespace symcheck;
  BinaryImage image;
  image.path = "t.exe";
  image.format = BinaryFormat::PeExe;
  image.aslr = false;
  image.nx_compat = false;
  image.cfg = false;
  SectionInfo rwx;
  rwx.name = ".evil";
  rwx.executable = true;
  rwx.writable = true;
  rwx.characteristics = 0xE0000000u;
  image.sections.push_back(rwx);
  ImportEntry imp;
  imp.dll = "KERNEL32.dll";
  imp.symbol = "VirtualProtect";
  image.imports.push_back(imp);

  const SecurityReport r = analyze_security(image);
  assert(!r.rwx_sections.empty());
  assert(!r.sensitive_imports.empty());
  assert(!r.findings.empty());
  std::puts("security ok");
}

void run_symbolize_parse_tests() {
  using namespace symcheck;
  auto a = parse_address_list({"0x140001000", "ff00"});
  assert(a);
  assert(a.value().size() == 2);
  assert(a.value()[0] == 0x140001000ull);
  assert(a.value()[1] == 0xff00ull);

  auto b = parse_addresses_from_text("fault at 0x401000 then 401010\n");
  assert(b);
  assert(b.value().size() >= 2);

  BinaryImage image;
  image.path = "m.dll";
  image.image_base = 0x180000000ull;
  ExportEntry e;
  e.name = "foo";
  e.rva = 0x1000;
  image.exports.push_back(e);
  LineEntry line;
  line.address = 0x1000;
  line.file = "foo.cpp";
  line.line = 42;
  image.lines.push_back(line);

  const auto report =
      symbolize_addresses(image, {0x180001000ull, 0x18000ffffull});
  assert(report.frames.size() == 2);
  assert(report.frames[0].resolved);
  assert(report.frames[0].symbol == "foo");
  assert(report.frames[0].file == "foo.cpp");
  assert(report.frames[0].line == 42);
  std::puts("symbolize ok");
}

void run_dwarf_line_tests() {
  using namespace symcheck;
  // Minimal DWARF2 line program unit.
  // unit_length(4) version(2) header_length(4) min_inst maxops? no for v2
  // default_is_stmt line_base line_range opcode_base
  // opcode lengths (opcode_base-1)
  // include dirs: empty
  // files: "a.c\0" dir=0 mod=0 len=0 then empty
  // program: set_address + copy + end_sequence

  std::vector<std::uint8_t> raw;
  auto push_u8 = [&](std::uint8_t v) { raw.push_back(v); };
  auto push_u16 = [&](std::uint16_t v) {
    raw.push_back(static_cast<std::uint8_t>(v & 0xff));
    raw.push_back(static_cast<std::uint8_t>((v >> 8) & 0xff));
  };
  auto push_u32 = [&](std::uint32_t v) {
    for (int i = 0; i < 4; ++i) {
      raw.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xff));
    }
  };
  auto push_u64 = [&](std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
      raw.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xff));
    }
  };

  // Placeholder length; fill later.
  const std::size_t len_pos = 0;
  push_u32(0);
  push_u16(2);  // version
  const std::size_t hdr_len_pos = raw.size();
  push_u32(0);  // header_length placeholder
  const std::size_t hdr_start = raw.size();
  push_u8(1);   // min_inst
  push_u8(1);   // default_is_stmt
  push_u8(static_cast<std::uint8_t>(-5));  // line_base
  push_u8(14);  // line_range
  push_u8(13);  // opcode_base
  for (int i = 1; i < 13; ++i) {
    // standard opcode lengths
    static const std::uint8_t lens[] = {0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1};
    push_u8(lens[i - 1]);
  }
  push_u8(0);  // end include dirs
  // file a.c
  const char* fname = "a.c";
  for (const char* p = fname; *p; ++p) {
    push_u8(static_cast<std::uint8_t>(*p));
  }
  push_u8(0);
  push_u8(0);  // dir
  push_u8(0);  // time
  push_u8(0);  // size
  push_u8(0);  // end files
  const std::size_t hdr_end = raw.size();
  const std::uint32_t header_length =
      static_cast<std::uint32_t>(hdr_end - hdr_start);
  raw[hdr_len_pos] = static_cast<std::uint8_t>(header_length & 0xff);
  raw[hdr_len_pos + 1] =
      static_cast<std::uint8_t>((header_length >> 8) & 0xff);
  raw[hdr_len_pos + 2] =
      static_cast<std::uint8_t>((header_length >> 16) & 0xff);
  raw[hdr_len_pos + 3] =
      static_cast<std::uint8_t>((header_length >> 24) & 0xff);

  // extended set_address 0x1000 (32-bit)
  push_u8(0);
  push_u8(5);  // length: ext op + 4 addr
  push_u8(2);  // set_address
  push_u32(0x1000);
  push_u8(1);  // copy
  push_u8(0);
  push_u8(1);  // end_sequence length
  push_u8(1);  // end_sequence

  const std::uint32_t unit_len =
      static_cast<std::uint32_t>(raw.size() - 4);
  raw[len_pos] = static_cast<std::uint8_t>(unit_len & 0xff);
  raw[len_pos + 1] = static_cast<std::uint8_t>((unit_len >> 8) & 0xff);
  raw[len_pos + 2] = static_cast<std::uint8_t>((unit_len >> 16) & 0xff);
  raw[len_pos + 3] = static_cast<std::uint8_t>((unit_len >> 24) & 0xff);

  std::vector<std::byte> bytes(raw.size());
  for (std::size_t i = 0; i < raw.size(); ++i) {
    bytes[i] = static_cast<std::byte>(raw[i]);
  }
  BinaryImage image;
  auto ok = parse_dwarf_debug_line(bytes, image);
  assert(ok);
  assert(!image.lines.empty());
  assert(image.lines[0].address == 0x1000);
  assert(image.lines[0].file.find("a.c") != std::string::npos);
  (void)push_u64;
  std::puts("dwarf ok");
}
