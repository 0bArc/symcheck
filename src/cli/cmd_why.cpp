#include "symcheck/cli/commands.hpp"
#include "symcheck/cli/format.hpp"
#include "symcheck/diagnose/why.hpp"
#include "symcheck/ir/cache.hpp"

#include <iostream>

namespace symcheck {

int cmd_why(const CliArgs& args) {
  if (args.positional.empty() || args.positional.size() > 2) {
    std::cerr << "why requires <name> [target]\n";
    return 2;
  }
  const std::string target =
      args.positional.size() == 2 ? args.positional[1] : args.target;
  BinaryCache cache;
  const auto report =
      project_why(args.positional[0], target, resolve_roots(args), cache);
  print_why(report, args.json, args.verbose);
  return report.has_exact &&
                 (target.empty() || report.target_links_provider)
             ? 0
             : 1;
}

}  // namespace symcheck
