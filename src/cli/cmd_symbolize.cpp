#include "symcheck/cli/commands.hpp"
#include "symcheck/diagnose/symbolize.hpp"
#include "symcheck/load/loader.hpp"
#include "symcheck/util/json_escape.hpp"
#include "symcheck/util/mapped_file.hpp"

#include <iostream>
#include <vector>

namespace symcheck {

int cmd_symbolize(const CliArgs& args) {
  if (args.positional.empty()) {
    std::cerr << "symbolize requires <module> <addr>... or --log <file>\n";
    return 2;
  }
  auto image = load_binary(args.positional[0]);
  if (!image) {
    std::cerr << image.error().message() << '\n';
    return 1;
  }

  std::vector<std::uint64_t> addrs;
  if (!args.log_path.empty()) {
    auto mapped = MappedFile::open(args.log_path);
    if (!mapped) {
      std::cerr << mapped.error().message() << '\n';
      return 1;
    }
    const auto bytes = mapped.value().bytes();
    const std::string text(reinterpret_cast<const char*>(bytes.data()),
                           bytes.size());
    auto parsed = parse_addresses_from_text(text);
    if (!parsed) {
      std::cerr << parsed.error().message() << '\n';
      return 1;
    }
    addrs = parsed.take_value();
  } else {
    if (args.positional.size() < 2) {
      std::cerr << "symbolize requires addresses or --log\n";
      return 2;
    }
    std::vector<std::string> toks(args.positional.begin() + 1,
                                  args.positional.end());
    auto parsed = parse_address_list(toks);
    if (!parsed) {
      std::cerr << parsed.error().message() << '\n';
      return 1;
    }
    addrs = parsed.take_value();
  }

  const SymbolizeReport report = symbolize_addresses(image.value(), addrs);
  if (args.json) {
    std::cout << "{\"module\":\"" << json_escape(report.module_path)
              << "\",\"frames\":[";
    for (std::size_t i = 0; i < report.frames.size(); ++i) {
      const auto& f = report.frames[i];
      if (i > 0) {
        std::cout << ',';
      }
      std::cout << "{\"address\":" << f.address
                << ",\"resolved\":" << (f.resolved ? "true" : "false")
                << ",\"symbol\":\"" << json_escape(f.symbol) << "\""
                << ",\"file\":\"" << json_escape(f.file) << "\""
                << ",\"line\":" << f.line << "}";
    }
    std::cout << "]}\n";
  } else {
    std::cout << "SymCheck symbolize\n  module: " << report.module_path
              << '\n';
    for (const auto& f : report.frames) {
      std::cout << "  0x" << std::hex << f.address << std::dec;
      if (f.resolved) {
        std::cout << "  "
                  << (f.demangled.empty() ? f.symbol : f.demangled);
        if (!f.file.empty()) {
          std::cout << "  at " << f.file << ":" << f.line;
        }
      } else {
        std::cout << "  (unresolved)";
      }
      std::cout << '\n';
    }
  }
  bool any = false;
  for (const auto& f : report.frames) {
    if (f.resolved) {
      any = true;
    }
  }
  return any ? 0 : 1;
}

}  // namespace symcheck
