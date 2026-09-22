#include "symcheck/cli/commands.hpp"

#include <iostream>

int main(int argc, char** argv) {
  using symcheck::CliArgs;
  using symcheck::Command;
  using symcheck::parse_args;
  using symcheck::usage_text;

  const CliArgs args = parse_args(argc, argv);
  if (!args.error.empty()) {
    std::cerr << args.error << '\n' << usage_text();
    return 2;
  }
  if (args.help || args.command == Command::Help) {
    std::cout << usage_text();
    return 0;
  }

  switch (args.command) {
    case Command::Inspect:
      return symcheck::cmd_inspect(args);
    case Command::Symbol:
      return symcheck::cmd_symbol(args);
    case Command::Exports:
      return symcheck::cmd_exports(args);
    case Command::Imports:
      return symcheck::cmd_imports(args);
    case Command::Compare:
      return symcheck::cmd_compare(args);
    case Command::Explain:
      return symcheck::cmd_explain(args);
    case Command::Graph:
      return symcheck::cmd_graph(args);
    case Command::Find:
      return symcheck::cmd_find(args);
    case Command::Why:
      return symcheck::cmd_why(args);
    case Command::Deps:
      return symcheck::cmd_deps(args);
    case Command::Duplicates:
      return symcheck::cmd_duplicates(args);
    case Command::Matrix:
      return symcheck::cmd_matrix(args);
    case Command::Trace:
      return symcheck::cmd_trace(args);
    case Command::Abi:
      return symcheck::cmd_abi(args);
    case Command::Snapshot:
      return symcheck::cmd_snapshot(args);
    case Command::Ci:
      return symcheck::cmd_ci(args);
    case Command::Security:
      return symcheck::cmd_security(args);
    case Command::Symbolize:
      return symcheck::cmd_symbolize(args);
    case Command::Help:
      std::cout << usage_text();
      return 0;
    case Command::Unknown:
    default:
      std::cerr << usage_text();
      return 2;
  }
}
