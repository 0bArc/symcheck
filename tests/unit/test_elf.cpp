#include "symcheck/elf/elf_parser.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

namespace {

#pragma pack(push, 1)
struct Ehdr {
  unsigned char e_ident[16];
  std::uint16_t e_type;
  std::uint16_t e_machine;
  std::uint32_t e_version;
  std::uint64_t e_entry;
  std::uint64_t e_phoff;
  std::uint64_t e_shoff;
  std::uint32_t e_flags;
  std::uint16_t e_ehsize;
  std::uint16_t e_phentsize;
  std::uint16_t e_phnum;
  std::uint16_t e_shentsize;
  std::uint16_t e_shnum;
  std::uint16_t e_shstrndx;
};

struct Shdr {
  std::uint32_t sh_name;
  std::uint32_t sh_type;
  std::uint64_t sh_flags;
  std::uint64_t sh_addr;
  std::uint64_t sh_offset;
  std::uint64_t sh_size;
  std::uint32_t sh_link;
  std::uint32_t sh_info;
  std::uint64_t sh_addralign;
  std::uint64_t sh_entsize;
};

struct Sym {
  std::uint32_t st_name;
  unsigned char st_info;
  unsigned char st_other;
  std::uint16_t st_shndx;
  std::uint64_t st_value;
  std::uint64_t st_size;
};
#pragma pack(pop)

void append_bytes(std::vector<std::byte>& buf, const void* p, std::size_t n) {
  const auto* b = static_cast<const std::byte*>(p);
  for (std::size_t i = 0; i < n; ++i) {
    buf.push_back(b[i]);
  }
}

}  // namespace

void run_elf_tests() {
  using namespace symcheck;

  // Minimal ELF64: null + symtab + strtab + shstrtab
  // Layout:
  // [ehdr]
  // [shdr0 null][shdr1 symtab][shdr2 strtab][shdr3 shstrtab]
  // [sym0][sym1]
  // [strtab: \0 hello \0]
  // [shstrtab: \0 .symtab \0 .strtab \0 .shstrtab \0]

  std::vector<std::byte> buf;
  Ehdr eh{};
  eh.e_ident[0] = 0x7f;
  eh.e_ident[1] = 'E';
  eh.e_ident[2] = 'L';
  eh.e_ident[3] = 'F';
  eh.e_ident[4] = 2;
  eh.e_ident[5] = 1;
  eh.e_ident[6] = 1;
  eh.e_type = 1;       // ET_REL
  eh.e_machine = 62;   // x86_64
  eh.e_version = 1;
  eh.e_ehsize = sizeof(Ehdr);
  eh.e_shentsize = sizeof(Shdr);
  eh.e_shnum = 4;
  eh.e_shstrndx = 3;
  eh.e_shoff = sizeof(Ehdr);
  append_bytes(buf, &eh, sizeof(eh));

  const std::size_t shoff = buf.size();
  (void)shoff;
  Shdr null_sh{};
  append_bytes(buf, &null_sh, sizeof(null_sh));

  const char strtab_data[] = "\0hello";
  const char shstr[] = "\0.symtab\0.strtab\0.shstrtab";

  Sym syms[2]{};
  syms[1].st_name = 1;  // "hello"
  syms[1].st_info = (1 << 4) | 2;  // GLOBAL FUNC
  syms[1].st_shndx = 1;

  const std::size_t sym_off = sizeof(Ehdr) + 4 * sizeof(Shdr);
  const std::size_t str_off = sym_off + sizeof(syms);
  const std::size_t shstr_off = str_off + sizeof(strtab_data);

  Shdr symtab{};
  symtab.sh_name = 1;  // .symtab
  symtab.sh_type = 2;
  symtab.sh_offset = sym_off;
  symtab.sh_size = sizeof(syms);
  symtab.sh_link = 2;
  symtab.sh_entsize = sizeof(Sym);
  append_bytes(buf, &symtab, sizeof(symtab));

  Shdr strtab{};
  strtab.sh_name = 9;  // .strtab
  strtab.sh_type = 3;
  strtab.sh_offset = str_off;
  strtab.sh_size = sizeof(strtab_data);
  append_bytes(buf, &strtab, sizeof(strtab));

  Shdr shstrtab{};
  shstrtab.sh_name = 17;  // .shstrtab
  shstrtab.sh_type = 3;
  shstrtab.sh_offset = shstr_off;
  shstrtab.sh_size = sizeof(shstr);
  append_bytes(buf, &shstrtab, sizeof(shstrtab));

  append_bytes(buf, syms, sizeof(syms));
  append_bytes(buf, strtab_data, sizeof(strtab_data));
  append_bytes(buf, shstr, sizeof(shstr));

  assert(looks_like_elf(buf));
  auto image = parse_elf(buf, "test.o");
  assert(image);
  assert(image.value().architecture == Architecture::X64);
  assert(image.value().format == BinaryFormat::ElfObj);
  bool found = false;
  for (const auto& s : image.value().symbols) {
    if (s.mangled == "hello" && s.defined) {
      found = true;
    }
  }
  assert(found);
  std::puts("elf ok");
}
