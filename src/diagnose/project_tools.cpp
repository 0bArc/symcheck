#include "symcheck/diagnose/project_tools.hpp"

#include "symcheck/ir/cache.hpp"
#include "symcheck/load/loader.hpp"
#include "symcheck/scan/scanner.hpp"

#include <algorithm>
#include <cctype>
#include <map>

namespace symcheck {
namespace {

std::string lower(std::string s) {
  for (char& ch : s) {
    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  }
  return s;
}

std::string file_basename(std::string path) {
  const auto slash = path.find_last_of("\\/");
  if (slash != std::string::npos && slash + 1 < path.size()) {
    path = path.substr(slash + 1);
  }
  return path;
}

std::string find_dll_on_roots(const std::string& dll_name,
                              const std::vector<std::string>& roots,
                              BinaryCache& cache) {
  const std::string want = lower(file_basename(dll_name));
  const auto paths = scan_binaries(roots);
  constexpr std::size_t kMax = 50'000;
  const std::size_t n = paths.size() < kMax ? paths.size() : kMax;
  for (std::size_t i = 0; i < n; ++i) {
    if (lower(file_basename(paths[i])) == want) {
      auto img = load_binary_cached(cache, paths[i]);
      if (img && (img.value().format == BinaryFormat::PeDll ||
                  img.value().format == BinaryFormat::PeExe)) {
        return paths[i];
      }
    }
  }
  return {};
}

bool is_system_dll(const std::string& dll_name) {
  const std::string n = lower(file_basename(dll_name));
  if (n.rfind("api-ms-win-", 0) == 0) {
    return true;
  }
  if (n.rfind("ext-ms-", 0) == 0) {
    return true;
  }
  return n == "kernel32.dll" || n == "kernelbase.dll" || n == "ntdll.dll" ||
         n == "user32.dll" || n == "gdi32.dll" || n == "advapi32.dll" ||
         n == "shell32.dll" || n == "ole32.dll" || n == "oleaut32.dll" ||
         n == "ws2_32.dll" || n == "dbghelp.dll" || n == "bcrypt.dll" ||
         n == "sechost.dll" || n == "rpcrt4.dll" || n == "ucrtbase.dll" ||
         n.find("vcruntime") != std::string::npos ||
         n.find("msvcp") != std::string::npos ||
         n.find("msvcr") != std::string::npos;
}

}  // namespace

const char* to_string(CrtKind crt) {
  switch (crt) {
    case CrtKind::DynamicRelease:
      return "/MD (dynamic)";
    case CrtKind::DynamicDebug:
      return "/MDd (dynamic debug)";
    case CrtKind::LikelyStatic:
      return "likely /MT";
    case CrtKind::Unknown:
    default:
      return "unknown";
  }
}

CrtKind detect_crt(const BinaryImage& image) {
  bool dynamic = false;
  bool debug = false;
  bool libcmt = false;
  for (const auto& dll : image.imported_dlls) {
    const std::string d = lower(dll);
    if (d.find("vcruntime") != std::string::npos ||
        d.find("msvcp") != std::string::npos ||
        d.find("ucrtbase") != std::string::npos ||
        d.find("msvcr") != std::string::npos) {
      dynamic = true;
      if (!d.empty() && d.back() == 'd' && d.find(".dll") != std::string::npos) {
        // e.g. msvcp140d.dll
        if (d.find("d.dll") != std::string::npos) {
          debug = true;
        }
      }
      if (d.find("140d") != std::string::npos ||
          d.find("120d") != std::string::npos ||
          d.find("ucrtbased") != std::string::npos) {
        debug = true;
      }
    }
  }
  for (const auto& sym : image.symbols) {
    const std::string m = lower(sym.mangled);
    if (m.find("libcmt") != std::string::npos) {
      libcmt = true;
    }
  }
  if (dynamic && debug) {
    return CrtKind::DynamicDebug;
  }
  if (dynamic) {
    return CrtKind::DynamicRelease;
  }
  if (libcmt) {
    return CrtKind::LikelyStatic;
  }
  if (image.format == BinaryFormat::PeExe ||
      image.format == BinaryFormat::PeDll) {
    return CrtKind::Unknown;
  }
  return CrtKind::Unknown;
}

std::vector<MatrixRow> build_matrix(const std::vector<BinaryImage>& images,
                                    const std::string& primary_path) {
  Architecture primary = Architecture::Unknown;
  for (const auto& img : images) {
    if (!primary_path.empty() && img.path == primary_path) {
      primary = img.architecture;
      break;
    }
  }
  if (primary == Architecture::Unknown) {
    for (const auto& img : images) {
      if (img.format == BinaryFormat::PeExe) {
        primary = img.architecture;
        break;
      }
    }
  }

  CrtKind primary_crt = CrtKind::Unknown;
  for (const auto& img : images) {
    if (img.format == BinaryFormat::PeExe) {
      primary_crt = detect_crt(img);
      break;
    }
  }

  std::vector<MatrixRow> rows;
  rows.reserve(images.size());
  constexpr std::size_t kMax = 50'000;
  const std::size_t n = images.size() < kMax ? images.size() : kMax;
  for (std::size_t i = 0; i < n; ++i) {
    MatrixRow row;
    row.path = images[i].path;
    row.arch = images[i].architecture;
    row.format = images[i].format;
    row.crt = detect_crt(images[i]);
    row.crt_note = to_string(row.crt);
    if (primary != Architecture::Unknown &&
        row.arch != Architecture::Unknown && row.arch != primary) {
      row.arch_mismatch = true;
    }
    if (primary_crt != CrtKind::Unknown && row.crt != CrtKind::Unknown &&
        row.crt != primary_crt &&
        (images[i].format == BinaryFormat::PeDll ||
         images[i].format == BinaryFormat::PeExe ||
         images[i].format == BinaryFormat::CoffLib)) {
      row.crt_warning = true;
    }
    rows.push_back(std::move(row));
  }
  return rows;
}

std::vector<DuplicateGroup> find_duplicates(
    const std::vector<BinaryImage>& images) {
  struct Acc {
    DuplicateGroup group;
    std::vector<std::string> units;
  };
  std::map<std::string, Acc> index;
  constexpr std::size_t kMaxImages = 50'000;
  const std::size_t n = images.size() < kMaxImages ? images.size() : kMaxImages;
  for (std::size_t i = 0; i < n; ++i) {
    const auto& img = images[i];
    constexpr std::size_t kMaxSym = 10'000'000;
    const std::size_t sn =
        img.symbols.size() < kMaxSym ? img.symbols.size() : kMaxSym;
    for (std::size_t s = 0; s < sn; ++s) {
      const Symbol& sym = img.symbols[s];
      if (!sym.defined && !sym.exported) {
        continue;
      }
      if (sym.mangled.empty() || sym.mangled[0] == '.') {
        continue;
      }

      // Same .obj seen both bare and inside .lib counts as one unit.
      std::string unit;
      if (!sym.object_member.empty()) {
        unit = lower(file_basename(sym.object_member));
      } else if (img.format == BinaryFormat::CoffObj) {
        unit = lower(file_basename(img.path));
      } else {
        unit = lower(img.path);
      }

      std::string loc = img.path;
      if (!sym.object_member.empty()) {
        loc += " -> " + file_basename(sym.object_member);
      }

      auto& acc = index[sym.mangled];
      acc.group.mangled = sym.mangled;
      if (acc.group.demangled.empty()) {
        acc.group.demangled = sym.demangled;
      }
      bool unit_seen = false;
      for (const auto& u : acc.units) {
        if (u == unit) {
          unit_seen = true;
          break;
        }
      }
      if (!unit_seen) {
        acc.units.push_back(unit);
        acc.group.locations.push_back(loc);
      }
    }
  }

  std::vector<DuplicateGroup> out;
  for (auto& kv : index) {
    if (kv.second.units.size() >= 2) {
      out.push_back(std::move(kv.second.group));
    }
  }
  std::sort(out.begin(), out.end(),
            [](const DuplicateGroup& a, const DuplicateGroup& b) {
              return a.mangled < b.mangled;
            });
  return out;
}

DepNode build_deps_tree(const BinaryImage& root,
                        const std::vector<std::string>& search_roots,
                        BinaryCache& cache) {
  DepNode node;
  node.name = root.path;
  node.found = true;

  constexpr std::size_t kMaxDll = 10'000;
  const std::size_t n =
      root.imported_dlls.size() < kMaxDll ? root.imported_dlls.size() : kMaxDll;
  for (std::size_t i = 0; i < n; ++i) {
    DepNode child;
    child.name = root.imported_dlls[i];
    if (is_system_dll(child.name)) {
      child.found = true;
    } else {
      const std::string found =
          find_dll_on_roots(child.name, search_roots, cache);
      child.found = !found.empty();
      if (!found.empty()) {
        auto img = load_binary_cached(cache, found);
        if (img) {
          const auto& kids = img.value().imported_dlls;
          const std::size_t kn = kids.size() < kMaxDll ? kids.size() : kMaxDll;
          for (std::size_t k = 0; k < kn; ++k) {
            DepNode gc;
            gc.name = kids[k];
            gc.found = is_system_dll(gc.name) ||
                       !find_dll_on_roots(gc.name, search_roots, cache).empty();
            child.children.push_back(std::move(gc));
          }
        }
      }
    }
    node.children.push_back(std::move(child));
  }
  return node;
}

}  // namespace symcheck
