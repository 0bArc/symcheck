#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace symcheck {

struct ScanLimits {
  std::size_t max_depth = 12;
  std::size_t max_files = 50'000;
};

[[nodiscard]] std::vector<std::string> default_search_roots();

[[nodiscard]] bool has_binary_extension(const std::string& path);

// Iterative directory walk. Skips missing roots. Bounded depth and file count.
[[nodiscard]] std::vector<std::string> scan_binaries(
    const std::vector<std::string>& roots, ScanLimits limits = {});

}  // namespace symcheck
