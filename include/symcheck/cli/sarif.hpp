#pragma once

#include "symcheck/diagnose/explain.hpp"
#include "symcheck/diagnose/project_tools.hpp"
#include "symcheck/diagnose/why.hpp"

#include <string>
#include <vector>

namespace symcheck {

struct SarifFinding {
  std::string rule_id;
  std::string message;
  std::string path;
  std::string level;  // error | warning | note
};

[[nodiscard]] std::string build_sarif(
    const std::vector<SarifFinding>& findings);

void print_sarif(const std::vector<SarifFinding>& findings);

[[nodiscard]] std::vector<SarifFinding> findings_from_duplicates(
    const std::vector<DuplicateGroup>& groups);
[[nodiscard]] std::vector<SarifFinding> findings_from_matrix(
    const std::vector<MatrixRow>& rows);
[[nodiscard]] std::vector<SarifFinding> findings_from_explain(
    const std::vector<ExplainReport>& reports);

}  // namespace symcheck
