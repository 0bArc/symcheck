#include "symcheck/diagnose/trace.hpp"

#include "symcheck/diagnose/match.hpp"
#include "symcheck/diagnose/project_find.hpp"

#include <cctype>
#include <string>

namespace symcheck {
namespace {

std::string to_lower(std::string s) {
  for (char& ch : s) {
    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  }
  return s;
}

std::string basename_of(const std::string& path) {
  const auto slash = path.find_last_of("/\\");
  if (slash == std::string::npos) {
    return path;
  }
  return path.substr(slash + 1);
}

bool looks_like_source(const std::string& query) {
  const std::string q = to_lower(query);
  const auto dot = q.find_last_of('.');
  if (dot == std::string::npos) {
    return false;
  }
  const std::string ext = q.substr(dot + 1);
  return ext == "c" || ext == "cc" || ext == "cpp" || ext == "cxx" ||
         ext == "h" || ext == "hpp" || ext == "hxx" || ext == "obj";
}

bool path_mentions(const std::string& hay, const std::string& needle_base) {
  const std::string h = to_lower(hay);
  const std::string n = to_lower(needle_base);
  return h.find(n) != std::string::npos;
}

}  // namespace

TraceReport project_trace(const std::string& query,
                          const std::vector<std::string>& roots,
                          BinaryCache& cache) {
  TraceReport report;
  report.query = query;
  report.query_looks_like_source = looks_like_source(query);

  auto images = load_project_binaries(roots, cache, &report.searched_paths);
  constexpr std::size_t kMaxImages = 50'000;
  const std::size_t n =
      images.size() < kMaxImages ? images.size() : kMaxImages;

  if (report.query_looks_like_source) {
    const std::string base = basename_of(query);
    for (std::size_t i = 0; i < n; ++i) {
      const BinaryImage& image = images[i];
      bool hit_file = path_mentions(image.path, base);
      if (!hit_file) {
        for (const auto& member : image.members) {
          if (path_mentions(member, base)) {
            hit_file = true;
            break;
          }
        }
      }
      if (!hit_file) {
        for (const auto& src : image.source_files) {
          if (path_mentions(src, base)) {
            hit_file = true;
            break;
          }
        }
      }
      if (!hit_file && path_mentions(image.pdb_path, base)) {
        hit_file = true;
      }
      if (!hit_file) {
        continue;
      }
      constexpr std::size_t kMaxSym = 10'000;
      const std::size_t sn =
          image.symbols.size() < kMaxSym ? image.symbols.size() : kMaxSym;
      for (std::size_t s = 0; s < sn; ++s) {
        const Symbol& sym = image.symbols[s];
        if (!sym.defined && !sym.exported) {
          continue;
        }
        TraceHit hit;
        hit.binary_path = image.path;
        hit.symbol_mangled = sym.mangled;
        hit.symbol_demangled = sym.demangled;
        hit.object_member = sym.object_member;
        hit.pdb_path = image.pdb_path;
        hit.rank = MatchRank::ExactMangled;
        report.hits.push_back(std::move(hit));
        if (report.hits.size() >= 200) {
          return report;
        }
      }
    }
    return report;
  }

  FindReport found = project_find(query, roots, cache);
  report.searched_paths = found.searched_paths;
  auto add_hits = [&](const std::vector<FindHit>& list) {
    for (const auto& fh : list) {
      TraceHit hit;
      hit.binary_path = fh.path;
      hit.symbol_mangled = fh.match.candidate.mangled;
      hit.symbol_demangled = fh.match.candidate.demangled;
      hit.object_member = fh.match.candidate.object_member;
      hit.pdb_path = fh.image.pdb_path;
      hit.rank = fh.match.rank;
      report.hits.push_back(std::move(hit));
    }
  };
  add_hits(found.exact);
  add_hits(found.closest);
  return report;
}

}  // namespace symcheck
