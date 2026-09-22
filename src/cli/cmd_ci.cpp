#include "symcheck/cli/commands.hpp"
#include "symcheck/cli/sarif.hpp"
#include "symcheck/diagnose/explain.hpp"
#include "symcheck/diagnose/project_find.hpp"
#include "symcheck/diagnose/project_tools.hpp"
#include "symcheck/ir/cache.hpp"
#include "symcheck/util/json_escape.hpp"
#include "symcheck/util/mapped_file.hpp"

#include <iostream>
#include <vector>

namespace symcheck {

int cmd_ci(const CliArgs& args) {
  BinaryCache cache;
  const auto roots = resolve_roots(args);
  auto images = load_project_binaries(roots, cache, nullptr);
  const auto dups = find_duplicates(images);
  const auto rows = build_matrix(images, args.target);

  std::vector<ExplainReport> explains;
  if (!args.log_path.empty()) {
    auto mapped = MappedFile::open(args.log_path);
    if (!mapped) {
      std::cerr << mapped.error().message() << '\n';
      return 1;
    }
    const auto bytes = mapped.value().bytes();
    const std::string text(reinterpret_cast<const char*>(bytes.data()),
                           bytes.size());
    const auto errs = parse_linker_errors(text);
    explains.reserve(errs.size());
    std::vector<std::string> searched;
    for (const auto& img : images) {
      searched.push_back(img.path);
    }
    for (const auto& err : errs) {
      explains.push_back(explain_unresolved(err, images, searched));
    }
  }

  std::vector<SarifFinding> findings = findings_from_duplicates(dups);
  {
    auto more = findings_from_matrix(rows);
    findings.insert(findings.end(), more.begin(), more.end());
  }
  {
    auto more = findings_from_explain(explains);
    findings.insert(findings.end(), more.begin(), more.end());
  }

  const bool bad = !findings.empty();

  if (args.sarif) {
    print_sarif(findings);
  } else if (args.json) {
    std::cout << "{\"duplicates\":" << dups.size()
              << ",\"findings\":" << findings.size()
              << ",\"images\":" << images.size() << "}\n";
  } else {
    std::cout << "SymCheck ci\n"
              << "  images:     " << images.size() << '\n'
              << "  duplicates: " << dups.size() << '\n'
              << "  findings:   " << findings.size() << '\n';
    constexpr std::size_t kMax = 30;
    const std::size_t n =
        findings.size() < kMax ? findings.size() : kMax;
    for (std::size_t i = 0; i < n; ++i) {
      std::cout << "  [" << findings[i].level << "] " << findings[i].rule_id
                << ": " << findings[i].message << '\n';
    }
    std::cout << (bad ? "FAIL\n" : "PASS\n");
  }
  return bad ? 1 : 0;
}

}  // namespace symcheck
