#include "symcheck/cli/commands.hpp"
#include "symcheck/cli/format.hpp"
#include "symcheck/diagnose/explain.hpp"
#include "symcheck/diagnose/project_find.hpp"
#include "symcheck/ir/cache.hpp"
#include "symcheck/load/loader.hpp"

#include <fstream>
#include <iostream>
#include <sstream>

namespace symcheck {
namespace {

std::string read_all_stdin() {
  std::ostringstream oss;
  oss << std::cin.rdbuf();
  return oss.str();
}

std::string read_file(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return {};
  }
  std::ostringstream oss;
  oss << in.rdbuf();
  return oss.str();
}

}  // namespace

int cmd_explain(const CliArgs& args) {
  std::string text;
  if (args.positional.empty()) {
    text = read_all_stdin();
  } else {
    text = read_file(args.positional[0]);
    if (text.empty()) {
      std::cerr << "Cannot read log: " << args.positional[0] << '\n';
      return 1;
    }
  }

  const auto errors = parse_linker_errors(text);
  if (errors.empty()) {
    std::cerr << "No linker errors found in input\n";
    return 1;
  }

  BinaryCache cache;
  std::vector<BinaryImage> search;
  std::vector<std::string> paths;

  for (const auto& p : args.libs) {
    auto img = load_binary_cached(cache, p);
    if (!img) {
      std::cerr << img.error().message() << '\n';
      return 1;
    }
    paths.push_back(p);
    search.push_back(img.take_value());
  }
  for (const auto& p : args.objs) {
    auto img = load_binary_cached(cache, p);
    if (!img) {
      std::cerr << img.error().message() << '\n';
      return 1;
    }
    paths.push_back(p);
    search.push_back(img.take_value());
  }

  if (search.empty()) {
    search = load_project_binaries(resolve_roots(args), cache, &paths);
  }

  int exit_code = 0;
  constexpr std::size_t kMaxErrors = 100;
  const std::size_t n =
      errors.size() < kMaxErrors ? errors.size() : kMaxErrors;
  for (std::size_t i = 0; i < n; ++i) {
    const auto report = explain_unresolved(errors[i], search, paths);
    print_explain(report, args.json);
    if (report.match.rank != MatchRank::ExactMangled &&
        errors[i].kind == LinkerErrorKind::Unresolved) {
      exit_code = 1;
    }
    if (i + 1 < n) {
      std::cout << '\n';
    }
  }
  return exit_code;
}

}  // namespace symcheck
