#pragma once

#include "symcheck/ir/binary.hpp"

#include <string>
#include <vector>

namespace symcheck {

struct SecurityFinding {
  std::string id;
  std::string severity;  // error | warning | note
  std::string message;
  std::string path;
};

struct SecurityReport {
  std::string path;
  bool aslr = false;
  bool nx_compat = false;
  bool cfg = false;
  bool high_entropy_va = false;
  std::vector<SectionInfo> rwx_sections;
  std::vector<std::string> sensitive_imports;
  std::vector<SecurityFinding> findings;
};

[[nodiscard]] SecurityReport analyze_security(const BinaryImage& image);

}  // namespace symcheck
