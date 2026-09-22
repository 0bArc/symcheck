#include "symcheck/coff/coff_parser.hpp"

#include "symcheck/util/byte_reader.hpp"

#include <cassert>
#include <cstring>

namespace symcheck {
namespace {

constexpr std::size_t kCoffHeaderSize = 20;
constexpr std::size_t kSectionHeaderSize = 40;
constexpr std::size_t kSymbolSize = 18;
constexpr std::size_t kMaxSections = 96;
constexpr std::size_t kMaxSymbols = 2'000'000;

#pragma pack(push, 1)
struct CoffFileHeader {
  std::uint16_t machine;
  std::uint16_t number_of_sections;
  std::uint32_t time_date_stamp;
  std::uint32_t pointer_to_symbol_table;
  std::uint32_t number_of_symbols;
  std::uint16_t size_of_optional_header;
  std::uint16_t characteristics;
};

struct CoffSymbol {
  char name[8];
  std::uint32_t value;
  std::int16_t section_number;
  std::uint16_t type;
  std::uint8_t storage_class;
  std::uint8_t number_of_aux_symbols;
};
#pragma pack(pop)

static_assert(sizeof(CoffFileHeader) == kCoffHeaderSize);
static_assert(sizeof(CoffSymbol) == kSymbolSize);

Result<std::string> symbol_name(const CoffSymbol& sym,
                                std::span<const std::byte> string_table) {
  const bool zeros =
      sym.name[0] == 0 && sym.name[1] == 0 && sym.name[2] == 0 &&
      sym.name[3] == 0;
  if (!zeros) {
    char buf[9] = {};
    for (std::size_t i = 0; i < 8; ++i) {
      buf[i] = sym.name[i];
      if (buf[i] == '\0') {
        break;
      }
    }
    return Result<std::string>::Ok(std::string(buf));
  }

  std::uint32_t offset = 0;
  for (std::size_t i = 0; i < 4; ++i) {
    offset |= static_cast<std::uint32_t>(static_cast<unsigned char>(sym.name[4 + i]))
              << (8 * static_cast<unsigned>(i));
  }
  if (offset >= string_table.size()) {
    return Result<std::string>::Fail("COFF symbol string offset out of range");
  }
  ByteReader reader(string_table);
  return reader.read_c_string(offset, 4096);
}

SymbolKind kind_from_coff(const CoffSymbol& sym) {
  if (sym.storage_class == 103) {
    return SymbolKind::File;
  }
  if (sym.storage_class == 105) {
    return SymbolKind::WeakExternal;
  }
  const std::uint16_t dtype = static_cast<std::uint16_t>((sym.type >> 4) & 0x0f);
  if (dtype == 2) {
    return SymbolKind::Function;
  }
  if (sym.storage_class == 3 && sym.section_number > 0) {
    return SymbolKind::Section;
  }
  return SymbolKind::Data;
}

SymbolBinding binding_from_coff(std::uint8_t storage_class) {
  if (storage_class == 3 || storage_class == 6) {
    return SymbolBinding::Local;
  }
  if (storage_class == 105) {
    return SymbolBinding::Weak;
  }
  return SymbolBinding::Global;
}

}  // namespace

Result<BinaryImage> parse_coff_object(std::span<const std::byte> data,
                                      const std::string& path,
                                      const std::string& member_name) {
  if (data.size() < kCoffHeaderSize) {
    return Result<BinaryImage>::Fail("COFF object too small: " + path);
  }

  ByteReader reader(data);
  auto header_res = reader.read<CoffFileHeader>();
  if (!header_res) {
    return Result<BinaryImage>::Fail(header_res.error());
  }
  const CoffFileHeader header = header_res.take_value();

  if (header.number_of_sections > kMaxSections) {
    return Result<BinaryImage>::Fail("COFF section count exceeds bound");
  }
  if (header.number_of_symbols > kMaxSymbols) {
    return Result<BinaryImage>::Fail("COFF symbol count exceeds bound");
  }

  const std::size_t section_bytes =
      static_cast<std::size_t>(header.number_of_sections) * kSectionHeaderSize;
  const std::size_t after_optional =
      kCoffHeaderSize + header.size_of_optional_header;
  if (after_optional + section_bytes > data.size()) {
    return Result<BinaryImage>::Fail("COFF section table truncated");
  }

  BinaryImage image;
  image.path = path;
  image.format = BinaryFormat::CoffObj;
  image.architecture = architecture_from_machine(header.machine);
  image.file_size = data.size();

  if (header.pointer_to_symbol_table == 0 || header.number_of_symbols == 0) {
    return Result<BinaryImage>::Ok(std::move(image));
  }

  const std::size_t sym_off = header.pointer_to_symbol_table;
  const std::size_t sym_bytes =
      static_cast<std::size_t>(header.number_of_symbols) * kSymbolSize;
  if (sym_off > data.size() || sym_bytes > data.size() - sym_off) {
    return Result<BinaryImage>::Fail("COFF symbol table truncated");
  }

  const std::size_t string_table_off = sym_off + sym_bytes;
  if (string_table_off + 4 > data.size()) {
    return Result<BinaryImage>::Fail("COFF string table truncated");
  }

  ByteReader size_reader(data.subspan(string_table_off));
  auto str_size_res = size_reader.read<std::uint32_t>();
  if (!str_size_res) {
    return Result<BinaryImage>::Fail(str_size_res.error());
  }
  const std::uint32_t string_table_size = str_size_res.take_value();
  if (string_table_size < 4) {
    return Result<BinaryImage>::Fail("COFF string table size invalid");
  }
  if (string_table_size > data.size() - string_table_off) {
    return Result<BinaryImage>::Fail("COFF string table exceeds file");
  }
  const auto string_table = data.subspan(string_table_off, string_table_size);

  image.symbols.reserve(header.number_of_symbols);
  std::size_t index = 0;
  while (index < header.number_of_symbols) {
    assert(index < kMaxSymbols);
    const std::size_t entry_off = sym_off + index * kSymbolSize;
    ByteReader sym_reader(data.subspan(entry_off, kSymbolSize));
    auto sym_res = sym_reader.read<CoffSymbol>();
    if (!sym_res) {
      return Result<BinaryImage>::Fail(sym_res.error());
    }
    const CoffSymbol raw = sym_res.take_value();

    auto name_res = symbol_name(raw, string_table);
    if (!name_res) {
      return Result<BinaryImage>::Fail(name_res.error());
    }

    Symbol sym;
    sym.mangled = name_res.take_value();
    sym.kind = kind_from_coff(raw);
    sym.binding = binding_from_coff(raw.storage_class);
    sym.architecture = image.architecture;
    sym.defined = raw.section_number > 0;
    sym.object_member = member_name;
    if (raw.storage_class == 2 || raw.storage_class == 105) {
      image.symbols.push_back(std::move(sym));
    }

    const std::size_t skip =
        1 + static_cast<std::size_t>(raw.number_of_aux_symbols);
    if (skip == 0 || index + skip > header.number_of_symbols) {
      return Result<BinaryImage>::Fail("COFF aux symbol count invalid");
    }
    index += skip;
  }

  return Result<BinaryImage>::Ok(std::move(image));
}

}  // namespace symcheck
