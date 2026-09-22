#include "symcheck/debug/pdb.hpp"

#include "symcheck/util/byte_reader.hpp"

#include <cassert>
#include <cstdio>
#include <vector>

#if defined(SYMCHECK_WINDOWS)
#  define WIN32_LEAN_AND_MEAN
#  include <Windows.h>
#  include <DbgHelp.h>
#  pragma comment(lib, "dbghelp.lib")
#endif

namespace symcheck {
namespace {

#pragma pack(push, 1)
struct DebugDirectory {
  std::uint32_t characteristics;
  std::uint32_t time_date_stamp;
  std::uint16_t major_version;
  std::uint16_t minor_version;
  std::uint32_t type;
  std::uint32_t size_of_data;
  std::uint32_t address_of_raw_data;
  std::uint32_t pointer_to_raw_data;
};

struct DosHeaderMini {
  std::uint16_t e_magic;
  std::uint16_t pad[29];
  std::int32_t e_lfanew;
};

struct FileHeaderMini {
  std::uint16_t machine;
  std::uint16_t number_of_sections;
  std::uint32_t time_date_stamp;
  std::uint32_t pointer_to_symbol_table;
  std::uint32_t number_of_symbols;
  std::uint16_t size_of_optional_header;
  std::uint16_t characteristics;
};

struct SectionHeaderMini {
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
#pragma pack(pop)

constexpr std::uint32_t kImageDebugTypeCodeview = 2;
constexpr std::uint32_t kRsdsSig = 0x53445352;  // 'RSDS'
constexpr std::size_t kMaxDebugEntries = 64;
constexpr std::size_t kMaxSections = 96;
constexpr std::size_t kMaxPdbSymbols = 500'000;

Result<std::size_t> rva_to_off(std::uint32_t rva,
                               std::span<const SectionHeaderMini> sections) {
  const std::size_t n =
      sections.size() < kMaxSections ? sections.size() : kMaxSections;
  for (std::size_t i = 0; i < n; ++i) {
    const auto& sec = sections[i];
    const std::uint32_t start = sec.virtual_address;
    const std::uint32_t span_size =
        sec.virtual_size > sec.size_of_raw_data ? sec.virtual_size
                                                : sec.size_of_raw_data;
    if (rva >= start && rva < start + span_size) {
      return Result<std::size_t>::Ok(sec.pointer_to_raw_data + (rva - start));
    }
  }
  return Result<std::size_t>::Fail("Debug RVA not in section");
}

std::string guid_to_hex(const std::uint8_t* g) {
  char buf[40];
  const int n = std::snprintf(
      buf, sizeof(buf),
      "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X", g[3],
      g[2], g[1], g[0], g[5], g[4], g[7], g[6], g[8], g[9], g[10], g[11],
      g[12], g[13], g[14], g[15]);
  if (n <= 0) {
    return {};
  }
  return std::string(buf);
}

#if defined(SYMCHECK_WINDOWS)
struct EnumCtx {
  BinaryImage* image = nullptr;
  std::size_t count = 0;
};

BOOL CALLBACK enum_sym_cb(PSYMBOL_INFO info, ULONG /*size*/, PVOID user) {
  auto* ctx = static_cast<EnumCtx*>(user);
  if (ctx == nullptr || ctx->image == nullptr || info == nullptr) {
    return FALSE;
  }
  if (ctx->count >= kMaxPdbSymbols) {
    return FALSE;
  }
  if (info->NameLen == 0) {
    return TRUE;
  }
  Symbol sym;
  sym.mangled.assign(info->Name, info->NameLen);
  sym.defined = true;
  sym.exported = (info->Flags & SYMFLAG_EXPORT) != 0;
  sym.architecture = ctx->image->architecture;
  sym.kind = SymbolKind::Function;
  ctx->image->symbols.push_back(std::move(sym));
  ++ctx->count;
  return TRUE;
}
#endif

}  // namespace

bool looks_like_pdb(std::span<const std::byte> data) {
  if (data.size() < 32) {
    return false;
  }
  const char* p = reinterpret_cast<const char*>(data.data());
  return p[0] == 'M' && p[1] == 'i' && p[2] == 'c' && p[3] == 'r' &&
         p[4] == 'o' && p[5] == 's' && p[6] == 'o' && p[7] == 'f' &&
         p[8] == 't' && p[9] == ' ' && p[10] == 'C' && p[11] == '/' &&
         p[12] == 'C' && p[13] == '+' && p[14] == '+';
}

Result<PdbLinkInfo> extract_pdb_link(std::span<const std::byte> pe_bytes) {
  if (pe_bytes.size() < sizeof(DosHeaderMini)) {
    return Result<PdbLinkInfo>::Fail("PE too small for debug link");
  }
  ByteReader reader(pe_bytes);
  auto dos = reader.read<DosHeaderMini>();
  if (!dos || dos.value().e_magic != 0x5A4D) {
    return Result<PdbLinkInfo>::Fail("Not PE for debug link");
  }
  const std::size_t pe_off = static_cast<std::size_t>(dos.value().e_lfanew);
  reader.seek(pe_off);
  auto sig = reader.read<std::uint32_t>();
  if (!sig || sig.value() != 0x00004550u) {
    return Result<PdbLinkInfo>::Fail("PE signature missing");
  }
  auto fh = reader.read<FileHeaderMini>();
  if (!fh) {
    return Result<PdbLinkInfo>::Fail(fh.error());
  }
  if (fh.value().size_of_optional_header < 2) {
    return Result<PdbLinkInfo>::Fail("Optional header missing");
  }
  auto magic = reader.read<std::uint16_t>();
  if (!magic) {
    return Result<PdbLinkInfo>::Fail(magic.error());
  }
  const bool pe32_plus = magic.value() == 0x20b;
  const std::size_t dd_from_magic = pe32_plus ? 112 : 96;
  reader.seek(pe_off + 4 + sizeof(FileHeaderMini) + dd_from_magic);
  // Skip to debug directory index 6.
  reader.seek(reader.tell() + 6 * 8);
  auto dbg_va = reader.read<std::uint32_t>();
  auto dbg_sz = reader.read<std::uint32_t>();
  if (!dbg_va || !dbg_sz) {
    return Result<PdbLinkInfo>::Fail("Cannot read debug directory");
  }
  if (dbg_va.value() == 0 || dbg_sz.value() == 0) {
    return Result<PdbLinkInfo>::Fail("No debug directory");
  }

  const std::size_t section_table_off =
      pe_off + 4 + sizeof(FileHeaderMini) + fh.value().size_of_optional_header;
  if (fh.value().number_of_sections > kMaxSections) {
    return Result<PdbLinkInfo>::Fail("Section count exceeds bound");
  }
  std::vector<SectionHeaderMini> sections;
  sections.reserve(fh.value().number_of_sections);
  ByteReader sec_reader(pe_bytes);
  sec_reader.seek(section_table_off);
  for (std::uint16_t i = 0; i < fh.value().number_of_sections; ++i) {
    auto sec = sec_reader.read<SectionHeaderMini>();
    if (!sec) {
      return Result<PdbLinkInfo>::Fail(sec.error());
    }
    sections.push_back(sec.take_value());
  }

  auto dbg_off = rva_to_off(dbg_va.value(), sections);
  if (!dbg_off) {
    // Fallback: sometimes PointerToRawData is used directly in older layouts.
    return Result<PdbLinkInfo>::Fail(dbg_off.error());
  }

  const std::size_t entry_count =
      dbg_sz.value() / sizeof(DebugDirectory) < kMaxDebugEntries
          ? dbg_sz.value() / sizeof(DebugDirectory)
          : kMaxDebugEntries;
  for (std::size_t i = 0; i < entry_count; ++i) {
    assert(i < kMaxDebugEntries);
    const std::size_t entry_off =
        dbg_off.value() + i * sizeof(DebugDirectory);
    if (entry_off + sizeof(DebugDirectory) > pe_bytes.size()) {
      return Result<PdbLinkInfo>::Fail("Debug directory truncated");
    }
    ByteReader er(pe_bytes.subspan(entry_off));
    auto entry = er.read<DebugDirectory>();
    if (!entry) {
      return Result<PdbLinkInfo>::Fail(entry.error());
    }
    if (entry.value().type != kImageDebugTypeCodeview) {
      continue;
    }
    const std::size_t raw = entry.value().pointer_to_raw_data;
    if (raw + 24 > pe_bytes.size()) {
      return Result<PdbLinkInfo>::Fail("CodeView data truncated");
    }
    auto sig_cv = ByteReader(pe_bytes).peek_u32(raw);
    if (!sig_cv || sig_cv.value() != kRsdsSig) {
      continue;
    }
    const std::uint8_t* guid =
        reinterpret_cast<const std::uint8_t*>(pe_bytes.data() + raw + 4);
    auto age_res = ByteReader(pe_bytes).peek_u32(raw + 20);
    if (!age_res) {
      return Result<PdbLinkInfo>::Fail(age_res.error());
    }
    auto path_res = ByteReader(pe_bytes).read_c_string(raw + 24, 1024);
    if (!path_res) {
      return Result<PdbLinkInfo>::Fail(path_res.error());
    }
    PdbLinkInfo info;
    info.path = path_res.take_value();
    info.guid_hex = guid_to_hex(guid);
    info.age = age_res.take_value();
    return Result<PdbLinkInfo>::Ok(std::move(info));
  }
  return Result<PdbLinkInfo>::Fail("No CodeView RSDS entry");
}

Result<void> enrich_image_from_pdb(BinaryImage& image,
                                   const std::string& pdb_path) {
#if defined(SYMCHECK_WINDOWS)
  if (pdb_path.empty()) {
    return Result<void>::Fail("Empty PDB path");
  }
  HANDLE proc = GetCurrentProcess();
  SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
  if (!SymInitialize(proc, nullptr, FALSE)) {
    return Result<void>::Fail("SymInitialize failed");
  }
  const DWORD64 base =
      SymLoadModuleEx(proc, nullptr, pdb_path.c_str(), nullptr, 0x10000000,
                      0, nullptr, 0);
  if (base == 0) {
    SymCleanup(proc);
    return Result<void>::Fail("SymLoadModuleEx failed for " + pdb_path);
  }
  EnumCtx ctx;
  ctx.image = &image;
  const BOOL ok =
      SymEnumSymbols(proc, base, "*", enum_sym_cb, &ctx);
  SymUnloadModule64(proc, base);
  SymCleanup(proc);
  if (!ok && ctx.count == 0) {
    return Result<void>::Fail("SymEnumSymbols failed");
  }
  image.pdb_path = pdb_path;
  image.format = image.format == BinaryFormat::Unknown ? BinaryFormat::Pdb
                                                       : image.format;
  return Result<void>::Ok();
#else
  (void)image;
  (void)pdb_path;
  return Result<void>::Fail("PDB enrichment requires Windows dbghelp");
#endif
}

Result<BinaryImage> load_pdb_symbols(const std::string& pdb_path) {
  BinaryImage image;
  image.path = pdb_path;
  image.format = BinaryFormat::Pdb;
  auto enrich = enrich_image_from_pdb(image, pdb_path);
  if (!enrich) {
    return Result<BinaryImage>::Fail(enrich.error());
  }
  return Result<BinaryImage>::Ok(std::move(image));
}

}  // namespace symcheck
