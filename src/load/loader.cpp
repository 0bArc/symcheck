#include "symcheck/load/loader.hpp"

#include "symcheck/coff/coff_parser.hpp"
#include "symcheck/debug/pdb.hpp"
#include "symcheck/demangle/msvc_demangle.hpp"
#include "symcheck/elf/elf_parser.hpp"
#include "symcheck/lib/archive.hpp"
#include "symcheck/pe/pe_parser.hpp"
#include "symcheck/util/mapped_file.hpp"

#include <algorithm>
#include <cctype>

namespace symcheck {
namespace {

std::string to_lower(std::string s) {
  for (char& ch : s) {
    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  }
  return s;
}

bool ends_with_ci(const std::string& path, const char* ext) {
  const std::string p = to_lower(path);
  const std::string e = to_lower(ext);
  if (p.size() < e.size()) {
    return false;
  }
  return p.compare(p.size() - e.size(), e.size(), e) == 0;
}

}  // namespace

void enrich_demangle(BinaryImage& image) {
  constexpr std::size_t kMax = 10'000'000;
  const std::size_t n =
      image.symbols.size() < kMax ? image.symbols.size() : kMax;
  for (std::size_t i = 0; i < n; ++i) {
    Symbol& sym = image.symbols[i];
    if (sym.demangled.empty()) {
      sym.demangled = demangle_msvc(sym.mangled);
    }
    if (sym.linkage == Linkage::Unknown) {
      sym.linkage = guess_linkage(sym.mangled);
    }
  }
}

Result<BinaryImage> load_binary(const std::string& path) {
  auto mapped = MappedFile::open(path);
  if (!mapped) {
    return Result<BinaryImage>::Fail(mapped.error());
  }
  const auto bytes = mapped.value().bytes();
  if (bytes.empty()) {
    return Result<BinaryImage>::Fail("Empty file: " + path);
  }

  Result<BinaryImage> image = Result<BinaryImage>::Fail("Unrecognized format");
  if (looks_like_archive(bytes)) {
    image = parse_coff_library(bytes, path);
  } else if (looks_like_pe(bytes)) {
    image = parse_pe(bytes, path);
    if (image) {
      auto link = extract_pdb_link(bytes);
      if (link) {
        image.value().pdb_path = link.value().path;
        image.value().pdb_guid = link.value().guid_hex;
        image.value().pdb_age = link.value().age;
      }
    }
  } else if (looks_like_elf(bytes)) {
    image = parse_elf(bytes, path);
  } else if (looks_like_pdb(bytes) || ends_with_ci(path, ".pdb")) {
    image = load_pdb_symbols(path);
  } else {
    image = parse_coff_object(bytes, path);
  }
  if (!image) {
    return image;
  }
  image.value().file_size = mapped.value().size();
  image.value().mtime = mapped.value().mtime();
  enrich_demangle(image.value());
  return image;
}

Result<BinaryImage> load_binary_cached(BinaryCache& cache,
                                       const std::string& path) {
  return cache.get_or_load(path, &load_binary);
}

}  // namespace symcheck
