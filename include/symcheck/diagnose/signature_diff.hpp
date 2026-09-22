#pragma once

#include <string>
#include <vector>

namespace symcheck {

struct SignatureDiff {
  std::vector<std::string> differences;
  int expected_param_count = -1;
  int found_param_count = -1;
};

[[nodiscard]] SignatureDiff diff_signatures(const std::string& expected_demangled,
                                            const std::string& found_demangled);

}  // namespace symcheck
