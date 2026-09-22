#include "symcheck/cli/sarif.hpp"

#include "symcheck/util/json_escape.hpp"

#include <iostream>
#include <sstream>

namespace symcheck {

std::string build_sarif(const std::vector<SarifFinding>& findings) {
  std::ostringstream out;
  out << "{"
      << "\"$schema\":\"https://json.schemastore.org/sarif-2.1.0.json\","
      << "\"version\":\"2.1.0\","
      << "\"runs\":[{"
      << "\"tool\":{\"driver\":{"
      << "\"name\":\"SymCheck\","
      << "\"informationUri\":\"https://github.com/symcheck/symcheck\","
      << "\"rules\":["
      << "{\"id\":\"duplicate-symbol\",\"name\":\"DuplicateSymbol\","
      << "\"shortDescription\":{\"text\":\"Symbol defined in multiple "
         "binaries\"}},"
      << "{\"id\":\"arch-mismatch\",\"name\":\"ArchMismatch\","
      << "\"shortDescription\":{\"text\":\"Architecture mismatch across "
         "binaries\"}},"
      << "{\"id\":\"crt-warning\",\"name\":\"CrtWarning\","
      << "\"shortDescription\":{\"text\":\"CRT mix warning\"}},"
      << "{\"id\":\"unresolved-symbol\",\"name\":\"UnresolvedSymbol\","
      << "\"shortDescription\":{\"text\":\"Unresolved external symbol\"}}"
      << "]}},"
      << "\"results\":[";

  for (std::size_t i = 0; i < findings.size(); ++i) {
    const auto& f = findings[i];
    if (i > 0) {
      out << ',';
    }
    out << "{\"ruleId\":\"" << json_escape(f.rule_id) << "\","
        << "\"level\":\"" << json_escape(f.level) << "\","
        << "\"message\":{\"text\":\"" << json_escape(f.message) << "\"}";
    if (!f.path.empty()) {
      out << ",\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{"
          << "\"uri\":\"" << json_escape(f.path) << "\"}}}]";
    }
    out << '}';
  }
  out << "]}]}";
  return out.str();
}

void print_sarif(const std::vector<SarifFinding>& findings) {
  std::cout << build_sarif(findings) << '\n';
}

std::vector<SarifFinding> findings_from_duplicates(
    const std::vector<DuplicateGroup>& groups) {
  std::vector<SarifFinding> out;
  out.reserve(groups.size());
  for (const auto& g : groups) {
    SarifFinding f;
    f.rule_id = "duplicate-symbol";
    f.level = "error";
    f.message = "Duplicate symbol " +
                (g.demangled.empty() ? g.mangled : g.demangled);
    if (!g.locations.empty()) {
      f.path = g.locations[0];
    }
    out.push_back(std::move(f));
  }
  return out;
}

std::vector<SarifFinding> findings_from_matrix(
    const std::vector<MatrixRow>& rows) {
  std::vector<SarifFinding> out;
  for (const auto& row : rows) {
    if (row.arch_mismatch) {
      SarifFinding f;
      f.rule_id = "arch-mismatch";
      f.level = "error";
      f.path = row.path;
      f.message = "Architecture mismatch: " + row.path;
      out.push_back(std::move(f));
    }
    if (row.crt_warning) {
      SarifFinding f;
      f.rule_id = "crt-warning";
      f.level = "warning";
      f.path = row.path;
      f.message = row.crt_note.empty() ? "CRT compatibility warning"
                                       : row.crt_note;
      out.push_back(std::move(f));
    }
  }
  return out;
}

std::vector<SarifFinding> findings_from_explain(
    const std::vector<ExplainReport>& reports) {
  std::vector<SarifFinding> out;
  for (const auto& r : reports) {
    if (r.match.rank == MatchRank::ExactMangled) {
      continue;
    }
    SarifFinding f;
    f.rule_id = "unresolved-symbol";
    f.level = "error";
    f.message = r.error.demangled.empty() ? r.error.mangled : r.error.demangled;
    if (!r.match.location.empty()) {
      f.path = r.match.location;
      f.message += " (closest in " + r.match.location + ")";
    }
    out.push_back(std::move(f));
  }
  return out;
}

}  // namespace symcheck
