#include "symcheck/elf/elf_parser.hpp"

#include "symcheck/elf/dwarf_line.hpp"
#include "symcheck/util/byte_reader.hpp"

#include <cassert>
#include <cstring>
#include <string>
#include <vector>

namespace symcheck {
namespace {

constexpr std::uint8_t kElfmagn0 = 0x7f;
constexpr unsigned char kElfClass64 = 2;
constexpr unsigned char kElfData2Lsb = 1;
constexpr std::uint16_t kEtRel = 1;
constexpr std::uint16_t kEtExec = 2;
constexpr std::uint16_t kEtDyn = 3;
constexpr std::uint32_t kShtSymtab = 2;
constexpr std::uint32_t kShtDynsym = 11;
constexpr unsigned char kStbLocal = 0;
constexpr unsigned char kSttFunc = 2;
constexpr unsigned char kSttObject = 1;
constexpr std::size_t kMaxSections = 512;
constexpr std::size_t kMaxSymbols = 500'000;

#pragma pack(push, 1)
struct Elf64Ehdr {
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

struct Elf64Shdr {
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

struct Elf64Sym {
  std::uint32_t st_name;
  unsigned char st_info;
  unsigned char st_other;
  std::uint16_t st_shndx;
  std::uint64_t st_value;
  std::uint64_t st_size;
};
#pragma pack(pop)

Architecture arch_from_elf_machine(std::uint16_t machine) {
  switch (machine) {
    case 3:  // EM_386
      return Architecture::X86;
    case 62:  // EM_X86_64
      return Architecture::X64;
    case 40:  // EM_ARM
      return Architecture::Arm;
    case 183:  // EM_AARCH64
      return Architecture::Arm64;
    default:
      return Architecture::Unknown;
  }
}

Result<void> parse_symtab(std::span<const std::byte> data,
                          const Elf64Shdr& symtab, const Elf64Shdr& strtab,
                          BinaryImage& image) {
  if (symtab.sh_entsize == 0 || symtab.sh_entsize != sizeof(Elf64Sym)) {
    return Result<void>::Fail("Unexpected ELF symbol entry size");
  }
  if (symtab.sh_offset + symtab.sh_size > data.size()) {
    return Result<void>::Fail("ELF symtab truncated");
  }
  if (strtab.sh_offset + strtab.sh_size > data.size()) {
    return Result<void>::Fail("ELF strtab truncated");
  }
  const std::size_t count = static_cast<std::size_t>(symtab.sh_size /
                                                     symtab.sh_entsize);
  const std::size_t n = count < kMaxSymbols ? count : kMaxSymbols;
  image.symbols.reserve(image.symbols.size() + n);
  for (std::size_t i = 0; i < n; ++i) {
    assert(i < kMaxSymbols);
    const std::size_t off =
        static_cast<std::size_t>(symtab.sh_offset) + i * sizeof(Elf64Sym);
    ByteReader r(data.subspan(off));
    auto sym_res = r.read<Elf64Sym>();
    if (!sym_res) {
      return Result<void>::Fail(sym_res.error());
    }
    const Elf64Sym es = sym_res.take_value();
    if (es.st_name == 0) {
      continue;
    }
    const std::size_t name_off =
        static_cast<std::size_t>(strtab.sh_offset) + es.st_name;
    auto name = ByteReader(data).read_c_string(name_off, 2048);
    if (!name) {
      continue;
    }
    Symbol sym;
    sym.mangled = name.take_value();
    const unsigned char bind = static_cast<unsigned char>(es.st_info >> 4);
    const unsigned char type = static_cast<unsigned char>(es.st_info & 0x0f);
    sym.binding = (bind == kStbLocal) ? SymbolBinding::Local
                                      : SymbolBinding::Global;
    if (type == kSttFunc) {
      sym.kind = SymbolKind::Function;
    } else if (type == kSttObject) {
      sym.kind = SymbolKind::Data;
    }
    sym.defined = es.st_shndx != 0;
    sym.exported = sym.defined && bind != kStbLocal;
    sym.architecture = image.architecture;
    if (sym.mangled.rfind("_Z", 0) == 0) {
      sym.linkage = Linkage::Cpp;
    } else {
      sym.linkage = Linkage::C;
    }
    image.symbols.push_back(std::move(sym));
  }
  return Result<void>::Ok();
}

}  // namespace

bool looks_like_elf(std::span<const std::byte> data) {
  if (data.size() < 16) {
    return false;
  }
  const auto* p = reinterpret_cast<const unsigned char*>(data.data());
  return p[0] == kElfmagn0 && p[1] == 'E' && p[2] == 'L' && p[3] == 'F';
}

Result<BinaryImage> parse_elf(std::span<const std::byte> data,
                              const std::string& path) {
  if (!looks_like_elf(data)) {
    return Result<BinaryImage>::Fail("Not ELF: " + path);
  }
  if (data.size() < sizeof(Elf64Ehdr)) {
    return Result<BinaryImage>::Fail("ELF header truncated");
  }
  const auto* ident =
      reinterpret_cast<const unsigned char*>(data.data());
  if (ident[4] != kElfClass64) {
    return Result<BinaryImage>::Fail("Only ELF64 supported");
  }
  if (ident[5] != kElfData2Lsb) {
    return Result<BinaryImage>::Fail("Only little-endian ELF supported");
  }

  ByteReader reader(data);
  auto ehdr_res = reader.read<Elf64Ehdr>();
  if (!ehdr_res) {
    return Result<BinaryImage>::Fail(ehdr_res.error());
  }
  const Elf64Ehdr ehdr = ehdr_res.take_value();
  if (ehdr.e_shnum == 0 || ehdr.e_shnum > kMaxSections) {
    return Result<BinaryImage>::Fail("ELF section count invalid");
  }
  if (ehdr.e_shentsize != sizeof(Elf64Shdr)) {
    return Result<BinaryImage>::Fail("Unexpected ELF section header size");
  }
  if (ehdr.e_shoff + static_cast<std::uint64_t>(ehdr.e_shnum) *
                         ehdr.e_shentsize >
      data.size()) {
    return Result<BinaryImage>::Fail("ELF section table truncated");
  }

  BinaryImage image;
  image.path = path;
  image.architecture = arch_from_elf_machine(ehdr.e_machine);
  image.file_size = data.size();
  if (ehdr.e_type == kEtRel) {
    image.format = BinaryFormat::ElfObj;
  } else if (ehdr.e_type == kEtDyn) {
    image.format = BinaryFormat::ElfShared;
  } else if (ehdr.e_type == kEtExec) {
    image.format = BinaryFormat::ElfExe;
  } else {
    image.format = BinaryFormat::ElfObj;
  }

  std::vector<Elf64Shdr> sections;
  sections.reserve(ehdr.e_shnum);
  ByteReader sh_reader(data);
  sh_reader.seek(static_cast<std::size_t>(ehdr.e_shoff));
  for (std::uint16_t i = 0; i < ehdr.e_shnum; ++i) {
    auto sh = sh_reader.read<Elf64Shdr>();
    if (!sh) {
      return Result<BinaryImage>::Fail(sh.error());
    }
    sections.push_back(sh.take_value());
  }

  for (std::size_t i = 0; i < sections.size(); ++i) {
    const Elf64Shdr& sh = sections[i];
    if (sh.sh_type != kShtSymtab && sh.sh_type != kShtDynsym) {
      continue;
    }
    if (sh.sh_link >= sections.size()) {
      return Result<BinaryImage>::Fail("ELF symtab link out of range");
    }
    auto parsed = parse_symtab(data, sh, sections[sh.sh_link], image);
    if (!parsed) {
      return Result<BinaryImage>::Fail(parsed.error());
    }
  }

  // DWARF .debug_line mapping when present.
  for (std::size_t i = 0; i < sections.size(); ++i) {
    if (ehdr.e_shstrndx >= sections.size()) {
      break;
    }
    const Elf64Shdr& shstr = sections[ehdr.e_shstrndx];
    const std::size_t name_off =
        static_cast<std::size_t>(shstr.sh_offset + sections[i].sh_name);
    auto name = ByteReader(data).read_c_string(name_off, 64);
    if (!name) {
      continue;
    }
    const std::string n = name.take_value();
    if (n == ".debug_line") {
      if (sections[i].sh_offset + sections[i].sh_size <= data.size()) {
        auto line_sec = data.subspan(
            static_cast<std::size_t>(sections[i].sh_offset),
            static_cast<std::size_t>(sections[i].sh_size));
        (void)parse_dwarf_debug_line(line_sec, image);
      }
    } else if (n == ".debug_info") {
      image.source_files.push_back(n);
    }
  }
  return Result<BinaryImage>::Ok(std::move(image));
}

}  // namespace symcheck
