#include "symcheck/cli/commands.hpp"
#include "symcheck/cli/format.hpp"
#include "symcheck/load/loader.hpp"

#include <iostream>

namespace symcheck {

int cmd_exports(const CliArgs& args) {
  if (args.positional.size() != 1) {
    std::cerr << "exports requires exactly one path\n";
    return 2;
  }
  auto image = load_binary(args.positional[0]);
  if (!image) {
    std::cerr << image.error().message() << '\n';
    return 1;
  }
  print_exports(image.value(), args.json);
  return 0;
}

}  // namespace symcheck
