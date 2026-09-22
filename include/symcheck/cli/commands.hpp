#pragma once

#include <string>
#include <vector>

namespace symcheck {

enum class Command {
  Help,
  Inspect,
  Symbol,
  Exports,
  Imports,
  Compare,
  Explain,
  Graph,
  Find,
  Why,
  Deps,
  Duplicates,
  Matrix,
  Trace,
  Abi,
  Snapshot,
  Ci,
  Security,
  Symbolize,
  Unknown,
};

struct CliArgs {
  Command command = Command::Help;
  std::vector<std::string> positional;
  std::vector<std::string> libs;
  std::vector<std::string> objs;
  std::vector<std::string> roots;
  std::string target;
  std::string out_path;
  std::string log_path;
  bool json = false;
  bool sarif = false;
  bool discover = false;
  bool verbose = false;
  bool help = false;
  std::string error;
};

[[nodiscard]] CliArgs parse_args(int argc, char** argv);
[[nodiscard]] const char* usage_text();
[[nodiscard]] std::vector<std::string> resolve_roots(const CliArgs& args);

int cmd_inspect(const CliArgs& args);
int cmd_symbol(const CliArgs& args);
int cmd_exports(const CliArgs& args);
int cmd_imports(const CliArgs& args);
int cmd_compare(const CliArgs& args);
int cmd_explain(const CliArgs& args);
int cmd_graph(const CliArgs& args);
int cmd_find(const CliArgs& args);
int cmd_why(const CliArgs& args);
int cmd_deps(const CliArgs& args);
int cmd_duplicates(const CliArgs& args);
int cmd_matrix(const CliArgs& args);
int cmd_trace(const CliArgs& args);
int cmd_abi(const CliArgs& args);
int cmd_snapshot(const CliArgs& args);
int cmd_ci(const CliArgs& args);
int cmd_security(const CliArgs& args);
int cmd_symbolize(const CliArgs& args);

}  // namespace symcheck
