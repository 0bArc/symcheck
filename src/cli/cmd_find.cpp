#include "symcheck/cli/commands.hpp"
#include "symcheck/cli/format.hpp"
#include "symcheck/diagnose/project_find.hpp"
#include "symcheck/ir/cache.hpp"

#include <iostream>

namespace symcheck {

int cmd_find(const CliArgs& args) {
  if (args.positional.size() != 1) {
    std::cerr << "find requires <name>\n";
    return 2;
  }
  BinaryCache cache;
  const auto report =
      project_find(args.positional[0], resolve_roots(args), cache);
  print_find(report, args.json);
  return report.exact.empty() ? 1 : 0;
}

}  // namespace symcheck
