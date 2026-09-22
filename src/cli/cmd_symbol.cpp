#include "symcheck/cli/commands.hpp"
#include "symcheck/cli/format.hpp"
#include "symcheck/diagnose/match.hpp"
#include "symcheck/load/loader.hpp"

#include <iostream>

namespace symcheck {

int cmd_symbol(const CliArgs& args) {
  if (args.positional.size() != 2) {
    std::cerr << "symbol requires <path> <name>\n";
    return 2;
  }
  auto image = load_binary(args.positional[0]);
  if (!image) {
    std::cerr << image.error().message() << '\n';
    return 1;
  }
  const auto match = find_best_match(image.value(), args.positional[1]);
  print_symbol_lookup(image.value(), args.positional[1], match, args.json);
  return match.rank == MatchRank::ExactMangled ? 0 : 1;
}

}  // namespace symcheck
