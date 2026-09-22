#include "symcheck/cli/commands.hpp"
#include "symcheck/diagnose/security.hpp"
#include "symcheck/load/loader.hpp"
#include "symcheck/util/json_escape.hpp"

#include <iostream>

namespace symcheck {

int cmd_security(const CliArgs& args) {
  if (args.positional.size() != 1) {
    std::cerr << "security requires <path>\n";
    return 2;
  }
  auto image = load_binary(args.positional[0]);
  if (!image) {
    std::cerr << image.error().message() << '\n';
    return 1;
  }
  const SecurityReport report = analyze_security(image.value());
  if (args.json) {
    std::cout << "{\"path\":\"" << json_escape(report.path) << "\","
              << "\"aslr\":" << (report.aslr ? "true" : "false") << ","
              << "\"nx\":" << (report.nx_compat ? "true" : "false") << ","
              << "\"cfg\":" << (report.cfg ? "true" : "false") << ","
              << "\"rwx\":" << report.rwx_sections.size() << ","
              << "\"sensitive_imports\":" << report.sensitive_imports.size()
              << ",\"findings\":" << report.findings.size() << "}\n";
  } else {
    std::cout << "SymCheck security\n"
              << "  path: " << report.path << '\n'
              << "  ASLR: " << (report.aslr ? "yes" : "no") << '\n'
              << "  NX:   " << (report.nx_compat ? "yes" : "no") << '\n'
              << "  CFG:  " << (report.cfg ? "yes" : "no") << '\n'
              << "  HEVA: " << (report.high_entropy_va ? "yes" : "no") << '\n';
    if (!report.rwx_sections.empty()) {
      std::cout << "  RWX sections:\n";
      for (const auto& s : report.rwx_sections) {
        std::cout << "    " << s.name << '\n';
      }
    }
    if (!report.sensitive_imports.empty()) {
      std::cout << "  Sensitive imports:\n";
      constexpr std::size_t kMax = 40;
      const std::size_t n = report.sensitive_imports.size() < kMax
                                ? report.sensitive_imports.size()
                                : kMax;
      for (std::size_t i = 0; i < n; ++i) {
        std::cout << "    " << report.sensitive_imports[i] << '\n';
      }
    }
    std::cout << "  Findings: " << report.findings.size() << '\n';
    for (const auto& f : report.findings) {
      std::cout << "  [" << f.severity << "] " << f.id << ": " << f.message
                << '\n';
    }
  }
  bool bad = false;
  for (const auto& f : report.findings) {
    if (f.severity == "error" || f.severity == "warning") {
      bad = true;
    }
  }
  return bad ? 1 : 0;
}

}  // namespace symcheck
