#include "symcheck/pe/pe_parser.hpp"

#include "symcheck/util/byte_reader.hpp"

#include <algorithm>
#include <cassert>
#include <cstring>

namespace symcheck {
namespace {

constexpr std::uint16_t kDosMagic = 0x5A4D;
constexpr std::uint32_t kPeMagic = 0x00004550;
constexpr std::uint16_t kPe32 = 0x10b;
constexpr std::uint16_t kPe32Plus = 0x20b;
constexpr std::size_t kMaxSections = 96;
constexpr std::size_t kMaxExports = 1'000'000;
constexpr std::size_t kMaxImports = 1'000'000;

#pragma pack(push, 1)
struct DosHeader {
  std::uint16_t e_magic;
  std::uint16_t e_cblp;
  std::uint16_t e_cp;
  std::uint16_t e_crlc;
  std::uint16_t e_cparhdr;
  std::uint16_t e_minalloc;
  std::uint16_t e_maxalloc;
  std::uint16_t e_ss;
  std::uint16_t e_sp;
  std::uint16_t e_csum;
  std::uint16_t e_ip;
  std::uint16_t e_cs;
  std::uint16_t e_lfarlc;
  std::uint16_t e_ovno;
  std::uint16_t e_res[4];
  std::uint16_t e_oemid;
  std::uint16_t e_oeminfo;
  std::uint16_t e_res2[10];
  std::int32_t e_lfanew;
};

struct FileHeader {
  std::uint16_t machine;
  std::uint16_t number_of_sections;
  std::uint32_t time_date_stamp;
  std::uint32_t pointer_to_symbol_table;
  std::uint32_t number_of_symbols;
  std::uint16_t size_of_optional_header;
  std::uint16_t characteristics;
};

struct DataDirectory {
  std::uint32_t virtual_address;
  std::uint32_t size;
};

struct SectionHeader {
  char name[8];
  std::uint32_t virtual_size;
  std::uint32_t virtual_address;
  std::uint32_t size_of_raw_data;
  std::uint32_t pointer_to_raw_data;
  std::uint32_t pointer_to_relocations;
  std::uint32_t pointer_to_linenumbers;
  std::uint16_t number_of_relocations;
  std::uint16_t number_of_linenumbers;
  std::uint32_t characteristics;
};

struct ExportDirectory {
  std::uint32_t characteristics;
  std::uint32_t time_date_stamp;
  std::uint16_t major_version;
  std::uint16_t minor_version;
  std::uint32_t name;
  std::uint32_t base;
  std::uint32_t number_of_functions;
  std::uint32_t number_of_names;
  std::uint32_t address_of_functions;
  std::uint32_t address_of_names;
  std::uint32_t address_of_name_ordinals;
};

struct ImportDescriptor {
  std::uint32_t original_first_thunk;
  std::uint32_t time_date_stamp;
  std::uint32_t forwarder_chain;
  std::uint32_t name;
  std::uint32_t first_thunk;
};
#pragma pack(pop)

Result<std::size_t> rva_to_offset(std::uint32_t rva,
                                  std::span<const SectionHeader> sections) {
  const std::size_t n =
      sections.size() < kMaxSections ? sections.size() : kMaxSections;
  for (std::size_t i = 0; i < n; ++i) {
    const auto& sec = sections[i];
    const std::uint32_t start = sec.virtual_address;
    const std::uint32_t span_size =
        sec.virtual_size > sec.size_of_raw_data ? sec.virtual_size
                                                : sec.size_of_raw_data;
    if (rva >= start && rva < start + span_size) {
      const std::uint32_t delta = rva - start;
      return Result<std::size_t>::Ok(sec.pointer_to_raw_data + delta);
    }
  }
  return Result<std::size_t>::Fail("RVA not in any section");
}

Result<void> parse_exports(std::span<const std::byte> data,
                           std::span<const SectionHeader> sections,
                           std::uint32_t export_rva, std::uint32_t export_size,
                           BinaryImage& image) {
  if (export_rva == 0 || export_size == 0) {
    return Result<void>::Ok();
  }
  auto off_res = rva_to_offset(export_rva, sections);
  if (!off_res) {
    return Result<void>::Fail(off_res.error());
  }
  const std::size_t off = off_res.take_value();
  if (off + sizeof(ExportDirectory) > data.size()) {
    return Result<void>::Fail("Export directory truncated");
  }
  ByteReader reader(data.subspan(off));
  auto dir_res = reader.read<ExportDirectory>();
  if (!dir_res) {
    return Result<void>::Fail(dir_res.error());
  }
  const ExportDirectory dir = dir_res.take_value();
  if (dir.number_of_names > kMaxExports) {
    return Result<void>::Fail("Export name count exceeds bound");
  }

  auto names_off = rva_to_offset(dir.address_of_names, sections);
  auto ords_off = rva_to_offset(dir.address_of_name_ordinals, sections);
  auto funcs_off = rva_to_offset(dir.address_of_functions, sections);
  if (!names_off || !ords_off || !funcs_off) {
    return Result<void>::Fail("Export tables RVA invalid");
  }

  image.exports.reserve(dir.number_of_names);
  image.symbols.reserve(image.symbols.size() + dir.number_of_names);

  for (std::uint32_t i = 0; i < dir.number_of_names; ++i) {
    assert(i < kMaxExports);
    const std::size_t name_ptr_off = names_off.value() + i * 4;
    auto name_rva_res = ByteReader(data).peek_u32(name_ptr_off);
    if (!name_rva_res) {
      return Result<void>::Fail(name_rva_res.error());
    }
    auto name_file_off = rva_to_offset(name_rva_res.take_value(), sections);
    if (!name_file_off) {
      return Result<void>::Fail(name_file_off.error());
    }
    auto name_res =
        ByteReader(data).read_c_string(name_file_off.take_value(), 2048);
    if (!name_res) {
      return Result<void>::Fail(name_res.error());
    }

    const std::size_t ord_off = ords_off.value() + i * 2;
    auto ord_index_res = ByteReader(data).peek_u16(ord_off);
    if (!ord_index_res) {
      return Result<void>::Fail(ord_index_res.error());
    }
    const std::uint16_t ord_index = ord_index_res.take_value();
    if (ord_index >= dir.number_of_functions) {
      return Result<void>::Fail("Export ordinal index out of range");
    }

    const std::size_t func_off = funcs_off.value() + ord_index * 4;
    auto func_rva_res = ByteReader(data).peek_u32(func_off);
    if (!func_rva_res) {
      return Result<void>::Fail(func_rva_res.error());
    }
    const std::uint32_t func_rva = func_rva_res.take_value();

    ExportEntry entry;
    entry.name = name_res.take_value();
    entry.ordinal = dir.base + ord_index;
    entry.rva = func_rva;
    if (func_rva >= export_rva && func_rva < export_rva + export_size) {
      entry.is_forwarder = true;
      auto fwd_off = rva_to_offset(func_rva, sections);
      if (fwd_off) {
        auto fwd = ByteReader(data).read_c_string(fwd_off.take_value(), 2048);
        if (fwd) {
          entry.forwarder = fwd.take_value();
        }
      }
    }
    Symbol sym;
    sym.mangled = entry.name;
    sym.defined = true;
    sym.exported = true;
    sym.architecture = image.architecture;
    sym.kind = SymbolKind::Function;
    image.symbols.push_back(sym);
    image.exports.push_back(std::move(entry));
  }
  return Result<void>::Ok();
}

Result<void> parse_imports(std::span<const std::byte> data,
                           std::span<const SectionHeader> sections,
                           std::uint32_t import_rva, bool pe32_plus,
                           BinaryImage& image) {
  if (import_rva == 0) {
    return Result<void>::Ok();
  }
  auto desc_off_res = rva_to_offset(import_rva, sections);
  if (!desc_off_res) {
    return Result<void>::Fail(desc_off_res.error());
  }

  std::size_t desc_off = desc_off_res.take_value();
  constexpr std::size_t kMaxDlls = 10'000;
  for (std::size_t dll_i = 0; dll_i < kMaxDlls; ++dll_i) {
    if (desc_off + sizeof(ImportDescriptor) > data.size()) {
      return Result<void>::Fail("Import descriptor truncated");
    }
    ByteReader desc_reader(data.subspan(desc_off));
    auto desc_res = desc_reader.read<ImportDescriptor>();
    if (!desc_res) {
      return Result<void>::Fail(desc_res.error());
    }
    const ImportDescriptor desc = desc_res.take_value();
    if (desc.original_first_thunk == 0 && desc.first_thunk == 0 &&
        desc.name == 0) {
      break;
    }

    auto name_off_res = rva_to_offset(desc.name, sections);
    if (!name_off_res) {
      return Result<void>::Fail(name_off_res.error());
    }
    auto dll_name_res =
        ByteReader(data).read_c_string(name_off_res.take_value(), 512);
    if (!dll_name_res) {
      return Result<void>::Fail(dll_name_res.error());
    }
    const std::string dll = dll_name_res.take_value();
    image.imported_dlls.push_back(dll);

    const std::uint32_t thunk_rva =
        desc.original_first_thunk != 0 ? desc.original_first_thunk
                                       : desc.first_thunk;
    auto thunk_off_res = rva_to_offset(thunk_rva, sections);
    if (!thunk_off_res) {
      return Result<void>::Fail(thunk_off_res.error());
    }
    std::size_t thunk_off = thunk_off_res.take_value();
    const std::size_t thunk_size = pe32_plus ? 8 : 4;

    for (std::size_t n = 0; n < kMaxImports; ++n) {
      if (thunk_off + thunk_size > data.size()) {
        return Result<void>::Fail("Import thunk truncated");
      }
      std::uint64_t entry = 0;
      if (pe32_plus) {
        for (std::size_t b = 0; b < 8; ++b) {
          entry |= static_cast<std::uint64_t>(data[thunk_off + b]) << (8 * b);
        }
      } else {
        auto e = ByteReader(data).peek_u32(thunk_off);
        if (!e) {
          return Result<void>::Fail(e.error());
        }
        entry = e.take_value();
      }
      if (entry == 0) {
        break;
      }

      ImportEntry imp;
      imp.dll = dll;
      const bool ordinal_flag =
          pe32_plus ? ((entry & (1ull << 63)) != 0)
                    : ((entry & 0x80000000u) != 0);
      if (ordinal_flag) {
        imp.by_ordinal = true;
        imp.ordinal = static_cast<std::uint16_t>(entry & 0xffffu);
        imp.symbol = "#" + std::to_string(imp.ordinal);
      } else {
        const std::uint32_t hint_rva = static_cast<std::uint32_t>(entry & 0xffffffffu);
        auto hint_off = rva_to_offset(hint_rva, sections);
        if (!hint_off) {
          return Result<void>::Fail(hint_off.error());
        }
        if (hint_off.value() + 2 > data.size()) {
          return Result<void>::Fail("Import hint truncated");
        }
        auto sym = ByteReader(data).read_c_string(hint_off.value() + 2, 2048);
        if (!sym) {
          return Result<void>::Fail(sym.error());
        }
        imp.symbol = sym.take_value();
      }

      Symbol sym;
      sym.mangled = imp.symbol;
      sym.imported = true;
      sym.defined = false;
      sym.architecture = image.architecture;
      sym.kind = SymbolKind::Function;
      image.symbols.push_back(sym);
      image.imports.push_back(std::move(imp));
      thunk_off += thunk_size;
    }

    desc_off += sizeof(ImportDescriptor);
  }
  return Result<void>::Ok();
}

}  // namespace

bool looks_like_pe(std::span<const std::byte> data) {
  if (data.size() < sizeof(DosHeader)) {
    return false;
  }
  auto magic = ByteReader(data).peek_u16(0);
  if (!magic || magic.value() != kDosMagic) {
    return false;
  }
  ByteReader reader(data);
  auto dos = reader.read<DosHeader>();
  if (!dos) {
    return false;
  }
  const auto lfanew = static_cast<std::size_t>(dos.value().e_lfanew);
  if (lfanew + 4 > data.size()) {
    return false;
  }
  auto sig = ByteReader(data).peek_u32(lfanew);
  return sig && sig.value() == kPeMagic;
}

Result<BinaryImage> parse_pe(std::span<const std::byte> data,
                             const std::string& path) {
  if (!looks_like_pe(data)) {
    return Result<BinaryImage>::Fail("Not a PE image: " + path);
  }

  ByteReader reader(data);
  auto dos_res = reader.read<DosHeader>();
  if (!dos_res) {
    return Result<BinaryImage>::Fail(dos_res.error());
  }
  const DosHeader dos = dos_res.take_value();
  const std::size_t pe_off = static_cast<std::size_t>(dos.e_lfanew);
  reader.seek(pe_off);
  auto sig_res = reader.read<std::uint32_t>();
  if (!sig_res || sig_res.value() != kPeMagic) {
    return Result<BinaryImage>::Fail("PE signature missing");
  }

  auto fh_res = reader.read<FileHeader>();
  if (!fh_res) {
    return Result<BinaryImage>::Fail(fh_res.error());
  }
  const FileHeader fh = fh_res.take_value();
  if (fh.number_of_sections > kMaxSections) {
    return Result<BinaryImage>::Fail("PE section count exceeds bound");
  }

  BinaryImage image;
  image.path = path;
  image.architecture = architecture_from_machine(fh.machine);
  image.file_size = data.size();

  const bool is_dll = (fh.characteristics & 0x2000) != 0;
  image.format = is_dll ? BinaryFormat::PeDll : BinaryFormat::PeExe;

  if (fh.size_of_optional_header < 2) {
    return Result<BinaryImage>::Fail("PE optional header missing");
  }
  auto magic_res = reader.read<std::uint16_t>();
  if (!magic_res) {
    return Result<BinaryImage>::Fail(magic_res.error());
  }
  const std::uint16_t opt_magic = magic_res.take_value();
  const bool pe32_plus = opt_magic == kPe32Plus;
  if (opt_magic != kPe32 && opt_magic != kPe32Plus) {
    return Result<BinaryImage>::Fail("Unsupported PE optional magic");
  }

  // Skip to data directories: PE32 at +96 from magic start (after magic already read 2),
  // DataDirectory starts at optional+96 for PE32, optional+112 for PE32+.
  // We already consumed magic (2 bytes). Remaining optional = size - 2.
  const std::size_t optional_remaining =
      static_cast<std::size_t>(fh.size_of_optional_header) - 2;
  const std::size_t dd_from_magic = pe32_plus ? 112 : 96;
  if (dd_from_magic < 2 || (dd_from_magic - 2) + 16 > optional_remaining) {
    return Result<BinaryImage>::Fail("Optional header too small for directories");
  }
  reader.seek(reader.tell() + (dd_from_magic - 2));

  // Export = index 0, Import = index 1
  auto export_va = reader.read<std::uint32_t>();
  auto export_sz = reader.read<std::uint32_t>();
  auto import_va = reader.read<std::uint32_t>();
  auto import_sz = reader.read<std::uint32_t>();
  if (!export_va || !export_sz || !import_va || !import_sz) {
    return Result<BinaryImage>::Fail("Cannot read data directories");
  }

  // DllCharacteristics at optional header offset 70 (PE32 and PE32+).
  const std::size_t opt_start = pe_off + 4 + sizeof(FileHeader);
  auto dll_chars_res = ByteReader(data).peek_u16(opt_start + 70);
  if (dll_chars_res) {
    const std::uint16_t dll_chars = dll_chars_res.take_value();
    image.high_entropy_va = (dll_chars & 0x0020) != 0;
    image.aslr = (dll_chars & 0x0040) != 0;
    image.nx_compat = (dll_chars & 0x0100) != 0;
    image.cfg = (dll_chars & 0x4000) != 0;
  }
  if (pe32_plus) {
    auto base_res = ByteReader(data).peek_u32(opt_start + 24);
    auto base_hi = ByteReader(data).peek_u32(opt_start + 28);
    if (base_res && base_hi) {
      image.image_base = base_res.take_value() |
                         (static_cast<std::uint64_t>(base_hi.take_value()) << 32);
    }
  } else {
    auto base_res = ByteReader(data).peek_u32(opt_start + 28);
    if (base_res) {
      image.image_base = base_res.take_value();
    }
  }

  const std::size_t section_table_off =
      pe_off + 4 + sizeof(FileHeader) + fh.size_of_optional_header;
  if (section_table_off + fh.number_of_sections * sizeof(SectionHeader) >
      data.size()) {
    return Result<BinaryImage>::Fail("Section table truncated");
  }

  std::vector<SectionHeader> sections;
  sections.reserve(fh.number_of_sections);
  ByteReader sec_reader(data);
  sec_reader.seek(section_table_off);
  for (std::uint16_t i = 0; i < fh.number_of_sections; ++i) {
    auto sec = sec_reader.read<SectionHeader>();
    if (!sec) {
      return Result<BinaryImage>::Fail(sec.error());
    }
    sections.push_back(sec.take_value());
    const SectionHeader& sh = sections.back();
    SectionInfo info;
    info.name.assign(sh.name, strnlen(sh.name, 8));
    info.virtual_address = sh.virtual_address;
    info.virtual_size = sh.virtual_size;
    info.characteristics = sh.characteristics;
    info.readable = (sh.characteristics & 0x40000000u) != 0;
    info.writable = (sh.characteristics & 0x80000000u) != 0;
    info.executable = (sh.characteristics & 0x20000000u) != 0;
    image.sections.push_back(std::move(info));
  }

  auto exp = parse_exports(data, sections, export_va.take_value(),
                           export_sz.take_value(), image);
  if (!exp) {
    return Result<BinaryImage>::Fail(exp.error());
  }
  (void)import_sz;
  auto imp =
      parse_imports(data, sections, import_va.take_value(), pe32_plus, image);
  if (!imp) {
    return Result<BinaryImage>::Fail(imp.error());
  }

  std::sort(image.exports.begin(), image.exports.end(),
            [](const ExportEntry& a, const ExportEntry& b) {
              return a.name < b.name;
            });
  std::sort(image.imports.begin(), image.imports.end(),
            [](const ImportEntry& a, const ImportEntry& b) {
              if (a.dll != b.dll) {
                return a.dll < b.dll;
              }
              return a.symbol < b.symbol;
            });
  std::sort(image.imported_dlls.begin(), image.imported_dlls.end());
  image.imported_dlls.erase(
      std::unique(image.imported_dlls.begin(), image.imported_dlls.end()),
      image.imported_dlls.end());

  return Result<BinaryImage>::Ok(std::move(image));
}

}  // namespace symcheck
