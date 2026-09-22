#include "symcheck/cli/commands.hpp"
#include "symcheck/diagnose/trace.hpp"
#include "symcheck/ir/cache.hpp"
#include "symcheck/util/json_escape.hpp"

#include <iostream>

namespace symcheck {

int cmd_trace(const CliArgs& args) {
  if (args.positional.empty()) {
    std::cerr << "trace requires <source|symbol>\n";
    return 2;
  }
  BinaryCache cache;
  const auto report =
      project_trace(args.positional[0], resolve_roots(args), cache);

  if (args.json) {
    std::cout << "{\"query\":\"" << json_escape(report.query)
              << "\",\"source_query\":"
              << (report.query_looks_like_source ? "true" : "false")
              << ",\"hits\":" << report.hits.size() << "}\n";
  } else {
    std::cout << "SymCheck trace\n\nQUERY\n  " << report.query << '\n';
    if (report.hits.empty()) {
      std::cout << "\nHITS\n  (none)\n";
    } else {
      std::cout << "\nHITS\n";
      constexpr std::size_t kMax = 50;
      const std::size_t n =
          report.hits.size() < kMax ? report.hits.size() : kMax;
      for (std::size_t i = 0; i < n; ++i) {
        const auto& h = report.hits[i];
        std::cout << "  " << h.binary_path;
        if (!h.object_member.empty()) {
          std::cout << " -> " << h.object_member;
        }
        std::cout << '\n';
        if (!h.symbol_demangled.empty()) {
          std::cout << "    " << h.symbol_demangled << '\n';
        } else {
          std::cout << "    " << h.symbol_mangled << '\n';
        }
        if (!h.pdb_path.empty()) {
          std::cout << "    pdb: " << h.pdb_path << '\n';
        }
      }
    }
  }
  return report.hits.empty() ? 1 : 0;
}

}  // namespace symcheck
