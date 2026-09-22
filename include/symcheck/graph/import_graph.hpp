#pragma once

#include "symcheck/ir/binary.hpp"

#include <string>
#include <vector>

namespace symcheck {

struct GraphNode {
  std::string name;
  std::vector<std::string> children;
};

[[nodiscard]] GraphNode build_import_graph(const BinaryImage& image);

}  // namespace symcheck
