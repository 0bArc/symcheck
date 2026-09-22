#include "symcheck/diagnose/project_find.hpp"

#include "symcheck/load/loader.hpp"
#include "symcheck/scan/scanner.hpp"

#include <algorithm>

namespace symcheck {

std::vector<BinaryImage> load_project_binaries(
    const std::vector<std::string>& roots, BinaryCache& cache,
    std::vector<std::string>* searched_paths) {
  const auto paths = scan_binaries(roots);
  std::vector<BinaryImage> images;
  images.reserve(paths.size());
  constexpr std::size_t kMax = 50'000;
  const std::size_t n = paths.size() < kMax ? paths.size() : kMax;
  for (std::size_t i = 0; i < n; ++i) {
    if (searched_paths != nullptr) {
      searched_paths->push_back(paths[i]);
    }
    auto img = load_binary_cached(cache, paths[i]);
    if (img) {
      images.push_back(img.take_value());
    }
  }
  return images;
}

FindReport project_find(const std::string& query,
                        const std::vector<std::string>& roots,
                        BinaryCache& cache) {
  FindReport report;
  report.query = query;
  auto images = load_project_binaries(roots, cache, &report.searched_paths);

  constexpr std::size_t kMax = 50'000;
  const std::size_t n = images.size() < kMax ? images.size() : kMax;
  for (std::size_t i = 0; i < n; ++i) {
    FindHit hit;
    hit.path = images[i].path;
    hit.match = find_best_match(images[i], query);
    hit.image = std::move(images[i]);
    if (hit.match.rank == MatchRank::ExactMangled) {
      if (hit.match.candidate.defined || hit.match.candidate.exported) {
        report.exact.push_back(std::move(hit));
      }
    } else if (hit.match.rank != MatchRank::NotFound) {
      report.closest.push_back(std::move(hit));
    }
  }

  std::sort(report.closest.begin(), report.closest.end(),
            [](const FindHit& a, const FindHit& b) {
              return static_cast<int>(a.match.rank) <
                     static_cast<int>(b.match.rank);
            });

  constexpr std::size_t kMaxClosest = 20;
  if (report.closest.size() > kMaxClosest) {
    report.closest.resize(kMaxClosest);
  }
  return report;
}

}  // namespace symcheck
