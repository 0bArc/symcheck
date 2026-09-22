#include "symcheck/cli/commands.hpp"
#include "symcheck/cli/format.hpp"
#include "symcheck/diagnose/project_find.hpp"
#include "symcheck/diagnose/project_tools.hpp"
#include "symcheck/ir/cache.hpp"

#include <iostream>

namespace symcheck {

int cmd_duplicates(const CliArgs& args) {
  std::vector<std::string> roots = resolve_roots(args);
  if (!args.positional.empty()) {
    roots = {args.positional[0]};
  }
  BinaryCache cache;
  auto images = load_project_binaries(roots, cache, nullptr);
  const auto groups = find_duplicates(images);
  print_duplicates(groups, args.json);
  return groups.empty() ? 0 : 1;
}

}  // namespace symcheck
