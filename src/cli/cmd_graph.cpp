#include "symcheck/cli/commands.hpp"
#include "symcheck/cli/format.hpp"
#include "symcheck/diagnose/project_tools.hpp"
#include "symcheck/ir/cache.hpp"
#include "symcheck/load/loader.hpp"

#include <iostream>

namespace symcheck {

int cmd_graph(const CliArgs& args) {
  if (args.positional.size() != 1) {
    std::cerr << "graph requires exactly one path\n";
    return 2;
  }
  BinaryCache cache;
  auto image = load_binary_cached(cache, args.positional[0]);
  if (!image) {
    std::cerr << image.error().message() << '\n';
    return 1;
  }
  const auto tree =
      build_deps_tree(image.value(), resolve_roots(args), cache);
  print_deps(tree, args.json);
  return 0;
}

}  // namespace symcheck
