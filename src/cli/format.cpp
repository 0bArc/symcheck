#include "symcheck/cli/format.hpp"

#include "symcheck/diagnose/signature_diff.hpp"
#include "symcheck/ir/types.hpp"
#include "symcheck/util/json_escape.hpp"

#include <iostream>
#include <set>
#include <string>
#include <vector>

namespace symcheck {
namespace {

const char* rank_name(MatchRank rank) {
  switch (rank) {
    case MatchRank::ExactMangled:
      return "exact";
    case MatchRank::SameBaseDifferentParams:
      return "signature_mismatch";
    case MatchRank::LinkageMismatch:
      return "linkage_mismatch";
    case MatchRank::ArchMismatch:
      return "arch_mismatch";
    case MatchRank::MissingExport:
      return "missing_export";
    case MatchRank::NotFound:
    default:
      return "not_found";
  }
}

}  // namespace

void print_inspect(const BinaryImage& image, bool json) {
  if (json) {
    std::cout << "{"
              << "\"path\":\"" << json_escape(image.path) << "\","
              << "\"format\":\"" << to_string(image.format) << "\","
              << "\"architecture\":\"" << to_string(image.architecture) << "\","
              << "\"symbols\":" << image.symbols.size() << ","
              << "\"exports\":" << image.exports.size() << ","
              << "\"imports\":" << image.imports.size() << ","
              << "\"defined\":" << image.defined_count() << ","
              << "\"undefined\":" << image.undefined_count()
              << "}\n";
    return;
  }

  std::cout << "File: " << image.path << '\n'
            << "Format: " << to_string(image.format) << '\n'
            << "Architecture: " << to_string(image.architecture) << '\n';
  if (!image.pdb_path.empty()) {
    std::cout << "PDB: " << image.pdb_path << '\n';
  }
  std::cout << '\n'
            << "Symbols: " << image.symbols.size() << '\n'
            << "Defined: " << image.defined_count() << '\n'
            << "Undefined: " << image.undefined_count() << '\n'
            << "Exports: " << image.exports.size() << '\n'
            << "Imports: " << image.imports.size() << '\n';
  if (!image.members.empty()) {
    std::cout << "Objects: " << image.members.size() << '\n';
  }
  if (!image.imported_dlls.empty()) {
    std::cout << '\n' << "Imported DLLs:\n";
    for (const auto& dll : image.imported_dlls) {
      std::cout << "  " << dll << '\n';
    }
  }
}

void print_exports(const BinaryImage& image, bool json) {
  if (json) {
    std::cout << "{\"exports\":[";
    for (std::size_t i = 0; i < image.exports.size(); ++i) {
      if (i != 0) {
        std::cout << ',';
      }
      std::cout << "{\"name\":\"" << json_escape(image.exports[i].name) << "\"";
      if (image.exports[i].is_forwarder) {
        std::cout << ",\"forwarder\":\"" << json_escape(image.exports[i].forwarder)
                  << "\"";
      }
      std::cout << ",\"ordinal\":" << image.exports[i].ordinal << "}";
    }
    std::cout << "]}\n";
    return;
  }
  std::cout << "Exports: " << image.exports.size() << '\n';
  for (const auto& e : image.exports) {
    std::string label = e.name;
    for (const auto& sym : image.symbols) {
      if (sym.mangled == e.name && !sym.demangled.empty()) {
        label = sym.demangled;
        break;
      }
    }
    std::cout << label;
    if (e.is_forwarder) {
      std::cout << "  [forwarder -> " << e.forwarder << "]";
    }
    std::cout << '\n';
  }
}

void print_imports(const BinaryImage& image, bool json) {
  if (json) {
    std::cout << "{\"imports\":[";
    for (std::size_t i = 0; i < image.imports.size(); ++i) {
      if (i != 0) {
        std::cout << ',';
      }
      std::cout << "{\"dll\":\"" << json_escape(image.imports[i].dll)
                << "\",\"symbol\":\"" << json_escape(image.imports[i].symbol)
                << "\",\"by_ordinal\":"
                << (image.imports[i].by_ordinal ? "true" : "false") << "}";
    }
    std::cout << "]}\n";
    return;
  }

  std::cout << "Imports: " << image.imports.size() << '\n';
  constexpr std::size_t kMaxPerDll = 40;
  for (const auto& dll : image.imported_dlls) {
    std::vector<const ImportEntry*> entries;
    for (const auto& imp : image.imports) {
      if (imp.dll == dll) {
        entries.push_back(&imp);
      }
    }
    std::cout << '\n' << dll << '\n';
    const std::size_t show =
        entries.size() < kMaxPerDll ? entries.size() : kMaxPerDll;
    for (std::size_t i = 0; i < show; ++i) {
      const bool last = i + 1 == show && entries.size() <= kMaxPerDll;
      std::cout << (last ? " `-- " : " |-- ");
      if (entries[i]->by_ordinal) {
        std::cout << "ordinal #" << entries[i]->ordinal;
      } else {
        std::cout << entries[i]->symbol;
      }
      std::cout << '\n';
    }
    if (entries.size() > kMaxPerDll) {
      std::cout << " `-- ... " << (entries.size() - kMaxPerDll) << " more\n";
    }
  }
}

void print_symbol_lookup(const BinaryImage& image, const std::string& query,
                         const SymbolMatch& match, bool json) {
  if (json) {
    std::cout << "{"
              << "\"query\":\"" << json_escape(query) << "\","
              << "\"status\":\"" << rank_name(match.rank) << "\","
              << "\"path\":\"" << json_escape(image.path) << "\"";
    if (match.rank != MatchRank::NotFound) {
      std::cout << ",\"found_mangled\":\""
                << json_escape(match.candidate.mangled) << "\""
                << ",\"found_demangled\":\""
                << json_escape(match.candidate.demangled) << "\"";
    }
    std::cout << "}\n";
    return;
  }

  std::cout << "Symbol: " << query << '\n';
  if (match.rank == MatchRank::ExactMangled) {
    std::cout << "Status: FOUND\n"
              << "Mangled: " << match.candidate.mangled << '\n'
              << "Demangled: " << match.candidate.demangled << '\n'
              << "Location: " << match.location << '\n';
    return;
  }

  std::cout << "Status: NOT FOUND\n"
            << "Searched:\n  " << image.path << '\n';
  if (match.rank != MatchRank::NotFound) {
    std::cout << "\nPossible mismatch:\n"
              << "  Expected: " << match.expected.demangled << '\n'
              << "  Available: " << match.candidate.demangled << '\n'
              << "  At: " << match.location << '\n'
              << "  Reason: " << match.reason << '\n';
    const auto diff =
        diff_signatures(match.expected.demangled, match.candidate.demangled);
    if (!diff.differences.empty()) {
      std::cout << "  DIFFERENCES:\n";
      for (const auto& d : diff.differences) {
        std::cout << "    - " << d << '\n';
      }
    }
  }
}

void print_compare(const BinaryImage& a, const BinaryImage& b, bool json) {
  std::set<std::string> set_a;
  std::set<std::string> set_b;
  for (const auto& s : a.symbols) {
    if (s.defined || s.exported) {
      set_a.insert(s.mangled);
    }
  }
  for (const auto& s : b.symbols) {
    if (s.defined || s.exported) {
      set_b.insert(s.mangled);
    }
  }

  std::vector<std::string> added;
  std::vector<std::string> removed;
  std::size_t unchanged = 0;
  for (const auto& name : set_b) {
    if (set_a.count(name) == 0) {
      added.push_back(name);
    } else {
      ++unchanged;
    }
  }
  for (const auto& name : set_a) {
    if (set_b.count(name) == 0) {
      removed.push_back(name);
    }
  }

  if (json) {
    std::cout << "{"
              << "\"added\":" << added.size() << ","
              << "\"removed\":" << removed.size() << ","
              << "\"unchanged\":" << unchanged << "}\n";
    return;
  }

  std::cout << "Compare\n"
            << "  Left:  " << a.path << '\n'
            << "  Right: " << b.path << '\n'
            << '\n'
            << "Added:     " << added.size() << '\n'
            << "Removed:   " << removed.size() << '\n'
            << "Unchanged: " << unchanged << '\n';
  if (!added.empty()) {
    std::cout << "\nAdded symbols:\n";
    for (const auto& n : added) {
      std::cout << "  + " << n << '\n';
    }
  }
  if (!removed.empty()) {
    std::cout << "\nRemoved symbols:\n";
    for (const auto& n : removed) {
      std::cout << "  - " << n << '\n';
    }
  }
}

void print_explain(const ExplainReport& report, bool json) {
  if (json) {
    std::cout << "{"
              << "\"symbol\":\"" << json_escape(report.error.mangled) << "\","
              << "\"code\":\"" << json_escape(report.error.code) << "\","
              << "\"rank\":\"" << rank_name(report.match.rank) << "\","
              << "\"reason\":\"" << json_escape(report.match.reason) << "\","
              << "\"suggested_fix\":\""
              << json_escape(report.suggested_fix) << "\"}\n";
    return;
  }

  std::cout << "SymCheck explain\n"
            << "\nERROR\n";
  if (!report.error.code.empty()) {
    std::cout << "  " << report.error.code << '\n';
  }
  std::cout << "  " << report.error.demangled << '\n';
  if (!report.error.mangled.empty()) {
    std::cout << "  (" << report.error.mangled << ")\n";
  }

  if (!report.searched.empty()) {
    std::cout << "\nSEARCHED\n";
    constexpr std::size_t kMaxShow = 30;
    const std::size_t n =
        report.searched.size() < kMaxShow ? report.searched.size() : kMaxShow;
    for (std::size_t i = 0; i < n; ++i) {
      std::cout << "  " << report.searched[i] << '\n';
    }
    if (report.searched.size() > kMaxShow) {
      std::cout << "  ... " << (report.searched.size() - kMaxShow) << " more\n";
    }
  }

  if (report.match.rank == MatchRank::ExactMangled) {
    std::cout << "\nFOUND\n"
              << "  " << report.match.candidate.demangled << '\n'
              << "  at " << report.match.location << '\n';
  } else if (report.match.rank != MatchRank::NotFound) {
    std::cout << "\nCLOSEST\n"
              << "  Expected: " << report.error.demangled << '\n'
              << "  Available: " << report.match.candidate.demangled << '\n'
              << "  at " << report.match.location << '\n';
    if (!report.signature_diff.differences.empty()) {
      std::cout << "\nDIFFERENCES\n";
      for (const auto& d : report.signature_diff.differences) {
        std::cout << "  - " << d << '\n';
      }
    } else {
      std::cout << "\nDIFFERENCE\n"
                << "  " << report.match.reason << '\n';
    }
  } else {
    std::cout << "\nFOUND\n"
              << "  (none)\n";
  }

  std::cout << "\nLIKELY CAUSE\n"
            << "  " << report.match.reason << '\n'
            << "\nSuggested action:\n"
            << "  " << report.suggested_fix << '\n';
}

void print_graph(const GraphNode& node) {
  std::cout << node.name << '\n';
  for (std::size_t i = 0; i < node.children.size(); ++i) {
    const bool last = i + 1 == node.children.size();
    std::cout << (last ? " `-- " : " |-- ") << node.children[i] << '\n';
  }
}

void print_find(const FindReport& report, bool json) {
  if (json) {
    std::cout << "{\"query\":\"" << json_escape(report.query) << "\","
              << "\"exact\":" << report.exact.size() << ","
              << "\"closest\":" << report.closest.size() << "}\n";
    return;
  }

  if (!report.exact.empty()) {
    std::cout << "FOUND  " << report.exact[0].match.candidate.demangled << '\n';
    std::set<std::string> seen;
    for (const auto& hit : report.exact) {
      if (seen.insert(hit.match.location).second) {
        std::cout << "  " << hit.match.location << '\n';
      }
    }
    return;
  }

  std::cout << "NOT FOUND  " << report.query << '\n';
  if (!report.closest.empty()) {
    std::cout << "Closest:\n";
    constexpr std::size_t kMax = 5;
    const std::size_t n =
        report.closest.size() < kMax ? report.closest.size() : kMax;
    for (std::size_t i = 0; i < n; ++i) {
      std::cout << "  " << report.closest[i].match.candidate.demangled << '\n'
                << "    " << report.closest[i].match.location << '\n';
    }
  }
}

void print_why(const WhyReport& report, bool json, bool verbose) {
  if (json) {
    std::cout << "{\"query\":\"" << json_escape(report.query) << "\","
              << "\"status\":\"" << to_string(report.status) << "\","
              << "\"failure_class\":\"" << to_string(report.failure_class)
              << "\","
              << "\"diagnosis_confidence\":\""
              << to_string(report.diagnosis_confidence) << "\","
              << "\"root_cause_confidence\":\""
              << to_string(report.root_cause_confidence) << "\","
              << "\"likely_cause\":\"" << json_escape(report.likely_cause)
              << "\"}\n";
    return;
  }

  // Compact default: what / where / why / next step.
  std::cout << to_string(report.status) << '\n';
  if (!report.target_path.empty()) {
    std::cout << '\n' << "Target\n  " << report.target_path << '\n';
  }

  std::cout << '\n' << "Requested\n  " << report.expected_display << '\n';

  if (report.status == WhyStatus::Found ||
      report.status == WhyStatus::ClosestMismatch) {
    std::cout << '\n'
              << (report.status == WhyStatus::Found ? "Match\n"
                                                    : "Closest match\n")
              << "  " << report.closest_display << '\n';
    if (!report.location_display.empty()) {
      std::cout << "  " << report.location_display << '\n';
    }
  }

  if (!report.signature_diff.differences.empty()) {
    std::cout << '\n' << "Difference\n";
    for (const auto& d : report.signature_diff.differences) {
      std::cout << "  " << d << '\n';
    }
  }

  if (report.failure_class != WhyFailureClass::None) {
    std::cout << '\n' << "Diagnosis\n  " << to_string(report.failure_class)
              << '\n';
  }

  if (!report.likely_causes.empty()) {
    std::cout << '\n' << "Likely causes\n";
    for (const auto& c : report.likely_causes) {
      std::cout << "  - " << c << '\n';
    }
  } else if (!report.likely_cause.empty()) {
    std::cout << '\n' << "Cause\n  " << report.likely_cause << '\n';
  }

  if (!report.suggested_fix.empty()) {
    std::cout << '\n' << "Fix\n  " << report.suggested_fix << '\n';
  }

  if (!verbose) {
    return;
  }

  // Verbose: search inventory and internal confidence fields.
  std::cout << "\n--- verbose ---\n";
  std::cout << "\nSearch\n";
  if (!report.search.roots.empty()) {
    std::cout << "  Roots\n";
    for (const auto& r : report.search.roots) {
      std::cout << "    " << r << '\n';
    }
  }
  if (!report.search.libraries.empty()) {
    std::cout << "  Libraries\n";
    for (const auto& p : report.search.libraries) {
      std::cout << "    " << p << '\n';
    }
  }
  if (!report.search.objects.empty()) {
    std::cout << "  Objects\n";
    for (const auto& p : report.search.objects) {
      std::cout << "    " << p << '\n';
    }
  }
  std::cout << "  Binaries scanned: " << report.search.binaries_scanned
            << '\n';

  if (!report.facts.empty()) {
    std::cout << "\nFact\n";
    for (const auto& f : report.facts) {
      std::cout << "  " << f << '\n';
    }
  }
  if (!report.inferences.empty()) {
    std::cout << "\nInference\n";
    for (const auto& i : report.inferences) {
      std::cout << "  " << i << '\n';
    }
  }
  if (!report.investigation.empty()) {
    std::cout << "\nInvestigation\n";
    for (std::size_t i = 0; i < report.investigation.size(); ++i) {
      const auto& c = report.investigation[i];
      std::cout << "  [" << (i + 1) << "] " << c.question << " "
                << c.answer << '\n';
      if (!c.detail.empty()) {
        std::cout << "      " << c.detail << '\n';
      }
    }
  }
  if (!report.likely_cause.empty()) {
    std::cout << "\nCause\n  " << report.likely_cause << '\n';
  }
  std::cout << "\nDiagnosis confidence\n  "
            << to_string(report.diagnosis_confidence)
            << "\nRoot cause confidence\n  "
            << to_string(report.root_cause_confidence) << '\n';
  if (!report.confidence_basis.empty()) {
    std::cout << "Confidence basis\n  " << report.confidence_basis << '\n';
  }
}

void print_deps(const DepNode& node, bool json) {
  if (json) {
    std::cout << "{\"root\":\"" << json_escape(node.name)
              << "\",\"imports\":" << node.children.size() << "}\n";
    return;
  }
  std::cout << node.name << '\n';
  for (std::size_t i = 0; i < node.children.size(); ++i) {
    const bool last = i + 1 == node.children.size();
    std::cout << (last ? " `-- " : " |-- ") << node.children[i].name;
    if (!node.children[i].found) {
      std::cout << "  [NOT FOUND on search path]";
    }
    std::cout << '\n';
    for (std::size_t j = 0; j < node.children[i].children.size(); ++j) {
      const bool glast = j + 1 == node.children[i].children.size();
      std::cout << (last ? "     " : " |   ") << (glast ? "`-- " : "|-- ")
                << node.children[i].children[j].name;
      if (!node.children[i].children[j].found) {
        std::cout << "  [NOT FOUND on search path]";
      }
      std::cout << '\n';
    }
  }
}

void print_duplicates(const std::vector<DuplicateGroup>& groups, bool json) {
  if (json) {
    std::cout << "{\"duplicates\":" << groups.size() << "}\n";
    return;
  }
  if (groups.empty()) {
    std::cout << "No duplicate defined symbols found.\n";
    return;
  }
  for (const auto& g : groups) {
    std::cout << "DUPLICATE SYMBOL\n"
              << "  " << (g.demangled.empty() ? g.mangled : g.demangled) << '\n'
              << "  (" << g.mangled << ")\n"
              << "Found in:\n";
    for (const auto& loc : g.locations) {
      std::cout << "  " << loc << '\n';
    }
    std::cout << "Possible causes:\n"
              << "  duplicate object\n"
              << "  duplicate library\n"
              << "  multiple definition / possible ODR violation\n\n";
  }
}

void print_matrix(const std::vector<MatrixRow>& rows, bool json) {
  if (json) {
    std::cout << "{\"rows\":" << rows.size() << "}\n";
    return;
  }
  std::cout << "TARGET                           ARCH     CRT\n"
            << "-------------------------------- -------- --------------------\n";
  for (const auto& row : rows) {
    std::string path = row.path;
    if (path.size() > 32) {
      path = "..." + path.substr(path.size() - 29);
    }
    while (path.size() < 32) {
      path.push_back(' ');
    }
    std::cout << path << ' ' << to_string(row.arch);
    const std::string arch = to_string(row.arch);
    for (std::size_t i = arch.size(); i < 8; ++i) {
      std::cout << ' ';
    }
    std::cout << ' ' << row.crt_note;
    if (row.arch_mismatch) {
      std::cout << "  <- MISMATCH";
    } else if (row.crt_warning) {
      std::cout << "  <- WARNING";
    }
    std::cout << '\n';
  }
}

}  // namespace symcheck
