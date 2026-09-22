#include "symcheck/cli/commands.hpp"
#include "symcheck/cli/format.hpp"
#include "symcheck/load/loader.hpp"

#include <iostream>

namespace symcheck {

int cmd_compare(const CliArgs& args) {
  if (args.positional.size() != 2) {
    std::cerr << "compare requires <a> <b>\n";
    return 2;
  }
  auto left = load_binary(args.positional[0]);
  if (!left) {
    std::cerr << left.error().message() << '\n';
    return 1;
  }
  auto right = load_binary(args.positional[1]);
  if (!right) {
    std::cerr << right.error().message() << '\n';
    return 1;
  }
  print_compare(left.value(), right.value(), args.json);
  return 0;
}

}  // namespace symcheck
