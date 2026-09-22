#pragma once

#include "symcheck/diagnose/match.hpp"
#include "symcheck/ir/binary.hpp"
#include "symcheck/ir/cache.hpp"

#include <string>
#include <vector>

namespace symcheck {

struct FindHit {
  SymbolMatch match;
  BinaryImage image;
  std::string path;
};

struct FindReport {
  std::string query;
  std::vector<std::string> searched_paths;
  std::vector<FindHit> exact;
  std::vector<FindHit> closest;
};

[[nodiscard]] FindReport project_find(const std::string& query,
                                      const std::vector<std::string>& roots,
                                      BinaryCache& cache);

[[nodiscard]] std::vector<BinaryImage> load_project_binaries(
    const std::vector<std::string>& roots, BinaryCache& cache,
    std::vector<std::string>* searched_paths);

}  // namespace symcheck
