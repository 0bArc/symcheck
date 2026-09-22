#pragma once

#include "symcheck/ir/binary.hpp"

#include <string>
#include <vector>

namespace symcheck {

enum class MatchRank {
  ExactMangled = 1,
  SameBaseDifferentParams = 2,
  LinkageMismatch = 3,
  ArchMismatch = 4,
  MissingExport = 5,
  NotFound = 6,
};

struct SymbolMatch {
  MatchRank rank = MatchRank::NotFound;
  Symbol expected;
  Symbol candidate;
  std::string location;
  std::string reason;
};

[[nodiscard]] std::string base_name(const std::string& demangled);
[[nodiscard]] SymbolMatch find_best_match(const BinaryImage& image,
                                          const std::string& query);
[[nodiscard]] std::vector<SymbolMatch> find_matches_in(
    const std::vector<BinaryImage>& images, const std::string& query);

}  // namespace symcheck
