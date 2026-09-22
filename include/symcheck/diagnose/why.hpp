#pragma once

#include "symcheck/diagnose/project_find.hpp"
#include "symcheck/diagnose/signature_diff.hpp"

#include <string>
#include <vector>

namespace symcheck {

enum class WhyStatus {
  Found,
  ClosestMismatch,
  NotFound,
};

enum class WhyConfidence {
  High,
  Medium,
  Low,
};

// Central taxonomy for the why engine. Not every class is fully diagnosed yet.
enum class WhyFailureClass {
  None,
  SignatureMismatch,
  MissingLibrary,
  LibraryNotLinked,
  ArchitectureMismatch,
  CallingConventionMismatch,
  LinkageMismatch,
  MissingExport,
  DuplicateSymbol,
  WrongLibraryVersion,
  DebugReleaseMismatch,
  RuntimeMismatch,
  IncompatibleSymbol,
  NotCompiled,
  Unknown,
};

struct WhyCheck {
  std::string question;
  std::string answer;
  std::string detail;
};

struct WhySearchSummary {
  std::string target;
  std::vector<std::string> roots;
  std::vector<std::string> libraries;
  std::vector<std::string> objects;
  std::vector<std::string> dlls;
  std::vector<std::string> executables;
  std::size_t binaries_scanned = 0;
};

struct WhyReport {
  std::string query;
  std::string target_path;
  FindReport find;
  SignatureDiff signature_diff;
  WhySearchSummary search;

  WhyStatus status = WhyStatus::NotFound;
  WhyConfidence confidence = WhyConfidence::Low;
  WhyConfidence diagnosis_confidence = WhyConfidence::Low;
  WhyConfidence root_cause_confidence = WhyConfidence::Low;
  WhyFailureClass failure_class = WhyFailureClass::Unknown;
  bool target_links_provider = false;
  bool has_exact = false;

  std::string expected_display;
  std::string closest_display;
  std::string location_display;
  std::string confidence_basis;

  std::vector<std::string> facts;
  std::vector<std::string> inferences;
  std::vector<WhyCheck> investigation;

  // Conservative one-line summary of what binaries prove / do not prove.
  std::string likely_cause;
  // Ranked hypotheses. Prefer these over treating CAUSE as the root cause.
  std::vector<std::string> likely_causes;
  std::string suggested_fix;
};

[[nodiscard]] const char* to_string(WhyStatus status);
[[nodiscard]] const char* to_string(WhyConfidence confidence);
[[nodiscard]] const char* to_string(WhyFailureClass failure_class);

[[nodiscard]] WhyReport project_why(const std::string& query,
                                    const std::string& target_path,
                                    const std::vector<std::string>& roots,
                                    BinaryCache& cache);

}  // namespace symcheck
