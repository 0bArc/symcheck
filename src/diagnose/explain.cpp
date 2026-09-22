#include "symcheck/diagnose/explain.hpp"

#include "symcheck/demangle/msvc_demangle.hpp"
#include "symcheck/diagnose/signature_diff.hpp"

#include <cctype>
#include <sstream>

namespace symcheck {
namespace {

std::string trim(std::string s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) {
    s.erase(s.begin());
  }
  while (!s.empty() &&
         (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) {
    s.pop_back();
  }
  return s;
}

std::string to_lower(std::string s) {
  for (char& ch : s) {
    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  }
  return s;
}

std::string extract_quoted(const std::string& line) {
  const auto first = line.find('"');
  if (first == std::string::npos) {
    return {};
  }
  const auto second = line.find('"', first + 1);
  if (second == std::string::npos || second <= first + 1) {
    return {};
  }
  return line.substr(first + 1, second - first - 1);
}

std::string extract_parenthesized_mangle(const std::string& line) {
  const auto first = line.find("(?");
  if (first == std::string::npos) {
    const auto alt = line.find("(_");
    if (alt == std::string::npos) {
      return {};
    }
    const auto end = line.find(')', alt);
    if (end == std::string::npos || end <= alt + 1) {
      return {};
    }
    return line.substr(alt + 1, end - alt - 1);
  }
  const auto end = line.find(')', first);
  if (end == std::string::npos || end <= first + 1) {
    return {};
  }
  return line.substr(first + 1, end - first - 1);
}

std::string extract_after(const std::string& lower, const std::string& line,
                          const char* marker) {
  const auto pos = lower.find(marker);
  if (pos == std::string::npos) {
    return {};
  }
  return trim(line.substr(pos + std::char_traits<char>::length(marker)));
}

std::string extract_backticks(const std::string& line) {
  const auto first = line.find('`');
  if (first == std::string::npos) {
    return {};
  }
  const auto second = line.find('\'', first + 1);
  if (second == std::string::npos || second <= first + 1) {
    return {};
  }
  return line.substr(first + 1, second - first - 1);
}

void fill_symbol_fields(LinkerError& err) {
  if (err.mangled.empty()) {
    return;
  }
  err.demangled = demangle_msvc(err.mangled);
}

}  // namespace

std::vector<LinkerError> parse_linker_errors(const std::string& text) {
  std::vector<LinkerError> out;
  std::istringstream in(text);
  std::string line;
  constexpr std::size_t kMaxLines = 100'000;
  for (std::size_t i = 0; i < kMaxLines && std::getline(in, line); ++i) {
    const std::string lower = to_lower(line);
    LinkerError err;
    err.raw_line = line;

    if (lower.find("lnk2019") != std::string::npos ||
        lower.find("lnk2001") != std::string::npos ||
        lower.find("unresolved external symbol") != std::string::npos) {
      err.kind = LinkerErrorKind::Unresolved;
      if (lower.find("lnk2019") != std::string::npos) {
        err.code = "LNK2019";
      } else if (lower.find("lnk2001") != std::string::npos) {
        err.code = "LNK2001";
      }
      err.mangled = extract_parenthesized_mangle(line);
      if (err.mangled.empty()) {
        err.mangled = extract_quoted(line);
      }
      fill_symbol_fields(err);
      if (!err.mangled.empty()) {
        out.push_back(std::move(err));
      }
      continue;
    }

    if (lower.find("lnk1120") != std::string::npos) {
      err.kind = LinkerErrorKind::Unresolved;
      err.code = "LNK1120";
      err.mangled = "unresolved count summary";
      err.demangled = trim(line);
      out.push_back(std::move(err));
      continue;
    }

    if (lower.find("lnk1107") != std::string::npos) {
      err.kind = LinkerErrorKind::InvalidOrCorrupt;
      err.code = "LNK1107";
      err.demangled = trim(line);
      err.mangled = "invalid_or_corrupt_file";
      out.push_back(std::move(err));
      continue;
    }

    if (lower.find("lnk4098") != std::string::npos ||
        (lower.find("defaultlib") != std::string::npos &&
         lower.find("conflict") != std::string::npos)) {
      err.kind = LinkerErrorKind::DefaultlibConflict;
      err.code = "LNK4098";
      err.demangled = trim(line);
      err.mangled = "defaultlib_conflict";
      out.push_back(std::move(err));
      continue;
    }

    if (lower.find("lnk4217") != std::string::npos ||
        lower.find("locally defined symbol") != std::string::npos) {
      err.kind = LinkerErrorKind::LocallyDefinedImported;
      err.code = "LNK4217";
      err.mangled = extract_quoted(line);
      if (err.mangled.empty()) {
        err.mangled = extract_parenthesized_mangle(line);
      }
      fill_symbol_fields(err);
      if (err.mangled.empty()) {
        err.mangled = "locally_defined_imported";
        err.demangled = trim(line);
      }
      out.push_back(std::move(err));
      continue;
    }

    if (lower.find("undefined reference to") != std::string::npos) {
      err.kind = LinkerErrorKind::Unresolved;
      err.code = "undefined_reference";
      err.mangled = extract_backticks(line);
      if (err.mangled.empty()) {
        err.mangled = extract_after(lower, line, "undefined reference to");
      }
      fill_symbol_fields(err);
      if (!err.mangled.empty()) {
        out.push_back(std::move(err));
      }
      continue;
    }

    if (lower.find("multiple definition of") != std::string::npos) {
      err.kind = LinkerErrorKind::MultipleDefinition;
      err.code = "multiple_definition";
      err.mangled = extract_backticks(line);
      if (err.mangled.empty()) {
        err.mangled = extract_after(lower, line, "multiple definition of");
      }
      fill_symbol_fields(err);
      if (!err.mangled.empty()) {
        out.push_back(std::move(err));
      }
      continue;
    }

    if (lower.find("cannot find -l") != std::string::npos ||
        lower.find("cannot find -l") != std::string::npos) {
      err.kind = LinkerErrorKind::CannotFindLib;
      err.code = "cannot_find_lib";
      const auto pos = lower.find("-l");
      if (pos != std::string::npos) {
        err.library_hint = trim(line.substr(pos + 2));
        err.mangled = err.library_hint;
      }
      err.demangled = trim(line);
      out.push_back(std::move(err));
      continue;
    }

    if (lower.find("dso missing from command line") != std::string::npos) {
      err.kind = LinkerErrorKind::DsoMissing;
      err.code = "dso_missing";
      err.mangled = extract_quoted(line);
      if (err.mangled.empty()) {
        err.mangled = "dso_missing";
      }
      err.demangled = trim(line);
      out.push_back(std::move(err));
      continue;
    }
  }
  return out;
}

ExplainReport explain_unresolved(const LinkerError& error,
                                 const std::vector<BinaryImage>& search_set,
                                 const std::vector<std::string>& searched_paths) {
  ExplainReport report;
  report.error = error;
  report.searched = searched_paths;

  if (error.kind == LinkerErrorKind::CannotFindLib) {
    report.match.rank = MatchRank::NotFound;
    report.match.reason = "Linker cannot find library -l" + error.library_hint;
    report.suggested_fix =
        "Install the library or add its directory to the linker search path";
    return report;
  }
  if (error.kind == LinkerErrorKind::DsoMissing) {
    report.match.rank = MatchRank::NotFound;
    report.match.reason = "Shared library needed on the link line (DSO missing)";
    report.suggested_fix =
        "Add the reported shared library to the link command";
    return report;
  }
  if (error.kind == LinkerErrorKind::InvalidOrCorrupt) {
    report.match.rank = MatchRank::NotFound;
    report.match.reason = "Input file is invalid or corrupt for the linker";
    report.suggested_fix =
        "Rebuild the object/library or check architecture of the input";
    return report;
  }
  if (error.kind == LinkerErrorKind::DefaultlibConflict) {
    report.match.rank = MatchRank::NotFound;
    report.match.reason = "Default library conflict (often /MD vs /MT)";
    report.suggested_fix =
        "Build all libraries with the same runtime library setting";
    return report;
  }
  if (error.kind == LinkerErrorKind::MultipleDefinition) {
    auto matches = find_matches_in(search_set, error.mangled);
    if (!matches.empty()) {
      report.match = matches.front();
    }
    report.match.reason = "Multiple definitions of the same symbol";
    report.suggested_fix =
        "Remove duplicate objects/libraries from the link, or make one definition inline/static";
    return report;
  }

  auto matches = find_matches_in(search_set, error.mangled);
  if (!matches.empty()) {
    report.match = matches.front();
  } else {
    report.match.rank = MatchRank::NotFound;
    report.match.reason = "No binaries to search";
  }

  if (report.match.rank == MatchRank::SameBaseDifferentParams ||
      report.match.rank == MatchRank::LinkageMismatch) {
    report.signature_diff = diff_signatures(error.demangled,
                                            report.match.candidate.demangled);
  }

  switch (report.match.rank) {
    case MatchRank::ExactMangled:
      report.suggested_fix =
          "Symbol exists in a dependency. Add that library or object to the link line.";
      break;
    case MatchRank::SameBaseDifferentParams:
      report.suggested_fix =
          "Make the declaration and definition use the same parameter types.";
      break;
    case MatchRank::LinkageMismatch:
      report.suggested_fix =
          "Align C and C++ linkage. Use extern \"C\" on both sides or on neither.";
      break;
    case MatchRank::ArchMismatch:
      report.suggested_fix =
          "Rebuild the library for the same architecture as the application.";
      break;
    case MatchRank::MissingExport:
      report.suggested_fix =
          "Export the symbol from the DLL (dllexport or module definition file).";
      break;
    case MatchRank::NotFound:
    default:
      report.suggested_fix =
          "Compile and link the translation unit that defines the symbol.";
      break;
  }
  return report;
}

}  // namespace symcheck
