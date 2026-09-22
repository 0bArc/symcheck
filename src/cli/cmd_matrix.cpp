#include "symcheck/cli/commands.hpp"
#include "symcheck/cli/format.hpp"
#include "symcheck/diagnose/project_find.hpp"
#include "symcheck/diagnose/project_tools.hpp"
#include "symcheck/ir/cache.hpp"

#include <iostream>

namespace symcheck {

int cmd_matrix(const CliArgs& args) {
  std::vector<std::string> roots = resolve_roots(args);
  if (!args.positional.empty()) {
    roots = {args.positional[0]};
  }
  BinaryCache cache;
  auto images = load_project_binaries(roots, cache, nullptr);
  const auto rows = build_matrix(images, args.target);
  print_matrix(rows, args.json);
  bool bad = false;
  for (const auto& row : rows) {
    if (row.arch_mismatch) {
      bad = true;
    }
  }
  return bad ? 1 : 0;
}

}  // namespace symcheck
