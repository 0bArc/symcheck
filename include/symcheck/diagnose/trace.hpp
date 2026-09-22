#pragma once

#include "symcheck/diagnose/match.hpp"
#include "symcheck/ir/binary.hpp"
#include "symcheck/ir/cache.hpp"

#include <string>
#include <vector>

namespace symcheck {

struct TraceHit {
  std::string binary_path;
  std::string symbol_mangled;
  std::string symbol_demangled;
  std::string object_member;
  std::string pdb_path;
  MatchRank rank = MatchRank::NotFound;
};

struct TraceReport {
  std::string query;
  bool query_looks_like_source = false;
  std::vector<std::string> searched_paths;
  std::vector<TraceHit> hits;
};

// Trace source basename or symbol name into scanned binaries (+ PDB link).
[[nodiscard]] TraceReport project_trace(const std::string& query,
                                        const std::vector<std::string>& roots,
                                        BinaryCache& cache);

}  // namespace symcheck
