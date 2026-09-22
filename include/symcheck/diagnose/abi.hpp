#pragma once

#include "symcheck/diagnose/project_tools.hpp"
#include "symcheck/ir/binary.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace symcheck {

struct AbiFingerprint {
  std::string path;
  Architecture arch = Architecture::Unknown;
  CrtKind crt = CrtKind::Unknown;
  std::uint64_t hash = 0;
  std::size_t defined_count = 0;
  std::size_t export_count = 0;
  std::size_t import_count = 0;
  std::vector<std::string> export_names;
};

struct AbiDiff {
  AbiFingerprint left;
  AbiFingerprint right;
  bool arch_mismatch = false;
  bool crt_mismatch = false;
  bool hash_mismatch = false;
  std::vector<std::string> only_left;
  std::vector<std::string> only_right;
};

[[nodiscard]] AbiFingerprint fingerprint_abi(const BinaryImage& image);
[[nodiscard]] AbiDiff compare_abi(const BinaryImage& a, const BinaryImage& b);

}  // namespace symcheck
