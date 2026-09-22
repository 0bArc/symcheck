#pragma once

#include "symcheck/diagnose/match.hpp"
#include "symcheck/diagnose/signature_diff.hpp"
#include "symcheck/ir/binary.hpp"

#include <string>
#include <vector>

namespace symcheck {

enum class LinkerErrorKind {
  Unresolved,
  MultipleDefinition,
  CannotFindLib,
  DsoMissing,
  InvalidOrCorrupt,
  DefaultlibConflict,
  LocallyDefinedImported,
  Other,
};

struct LinkerError {
  LinkerErrorKind kind = LinkerErrorKind::Unresolved;
  std::string mangled;
  std::string demangled;
  std::string library_hint;
  std::string raw_line;
  std::string code;  // e.g. LNK2019
};

[[nodiscard]] std::vector<LinkerError> parse_linker_errors(
    const std::string& text);

struct ExplainReport {
  LinkerError error;
  SymbolMatch match;
  SignatureDiff signature_diff;
  std::vector<std::string> searched;
  std::string suggested_fix;
};

[[nodiscard]] ExplainReport explain_unresolved(
    const LinkerError& error, const std::vector<BinaryImage>& search_set,
    const std::vector<std::string>& searched_paths);

}  // namespace symcheck
