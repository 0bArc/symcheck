#include "symcheck/graph/import_graph.hpp"

#include <algorithm>

namespace symcheck {

GraphNode build_import_graph(const BinaryImage& image) {
  GraphNode root;
  root.name = image.path;
  root.children = image.imported_dlls;
  std::sort(root.children.begin(), root.children.end());
  root.children.erase(
      std::unique(root.children.begin(), root.children.end()),
      root.children.end());
  return root;
}

}  // namespace symcheck
