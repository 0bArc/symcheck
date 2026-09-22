#include "symcheck/diagnose/why.hpp"

#include "symcheck/demangle/msvc_demangle.hpp"
#include "symcheck/diagnose/match.hpp"
#include "symcheck/ir/types.hpp"
#include "symcheck/load/loader.hpp"

#include <algorithm>
#include <cctype>
#include <set>

namespace symcheck {
namespace {

std::string basename_of(std::string path) {
  const auto slash = path.find_last_of("\\/");
  if (slash != std::string::npos && slash + 1 < path.size()) {
    path = path.substr(slash + 1);
  }
  return path;
}

std::string basename_lower(std::string path) {
  path = basename_of(std::move(path));
  for (char& ch : path) {
    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  }
  return path;
}

std::string short_location(const std::string& location) {
  const auto arrow = location.find(" -> ");
  if (arrow == std::string::npos) {
    return basename_of(location);
  }
  return basename_of(location.substr(0, arrow)) + " -> " +
         basename_of(location.substr(arrow + 4));
}

std::string compact_name(const std::string& demangled_or_query) {
  const std::string core = base_name(demangled_or_query);
  const auto open = demangled_or_query.find('(');
  if (open == std::string::npos) {
    return core.empty() ? demangled_or_query : core;
  }
  const auto close = demangled_or_query.find(')', open);
  if (close == std::string::npos) {
    return core;
  }
  return core + demangled_or_query.substr(open, close - open + 1);
}

bool target_references_provider(const BinaryImage& target,
                                const FindHit& hit) {
  const std::string provider = basename_lower(hit.path);
  for (const auto& dll : target.imported_dlls) {
    if (basename_lower(dll) == provider) {
      return true;
    }
  }
  for (const auto& imp : target.imports) {
    if (imp.symbol == hit.match.candidate.mangled) {
      return true;
    }
  }
  return false;
}

bool any_obj_hit(const FindReport& find) {
  for (const auto& hit : find.exact) {
    if (hit.image.format == BinaryFormat::CoffObj) {
      return true;
    }
  }
  for (const auto& hit : find.closest) {
    if (hit.image.format == BinaryFormat::CoffObj) {
      return true;
    }
  }
  return false;
}

bool any_lib_hit(const FindReport& find) {
  for (const auto& hit : find.exact) {
    if (hit.image.format == BinaryFormat::CoffLib) {
      return true;
    }
  }
  for (const auto& hit : find.closest) {
    if (hit.image.format == BinaryFormat::CoffLib) {
      return true;
    }
  }
  return false;
}

std::string display_expected(const std::string& query) {
  const std::string dem = demangle_msvc(query);
  if (!dem.empty() && dem != query) {
    return dem;
  }
  return query;
}

void fill_search(WhySearchSummary& search, const std::string& target_path,
                 const std::vector<std::string>& roots,
                 const FindReport& find) {
  search.target = target_path.empty() ? std::string() : basename_of(target_path);
  search.roots = roots;
  search.binaries_scanned = find.searched_paths.size();

  std::set<std::string> libs;
  std::set<std::string> objs;
  std::set<std::string> dlls;
  std::set<std::string> exes;
  constexpr std::size_t kMax = 50'000;
  const std::size_t n =
      find.searched_paths.size() < kMax ? find.searched_paths.size() : kMax;
  for (std::size_t i = 0; i < n; ++i) {
    const std::string base = basename_of(find.searched_paths[i]);
    const std::string low = basename_lower(find.searched_paths[i]);
    if (low.size() >= 4 && low.compare(low.size() - 4, 4, ".lib") == 0) {
      libs.insert(base);
    } else if (low.size() >= 4 && low.compare(low.size() - 4, 4, ".obj") == 0) {
      objs.insert(base);
    } else if (low.size() >= 4 && low.compare(low.size() - 4, 4, ".dll") == 0) {
      dlls.insert(base);
    } else if (low.size() >= 4 && low.compare(low.size() - 4, 4, ".exe") == 0) {
      exes.insert(base);
    }
  }
  search.libraries.assign(libs.begin(), libs.end());
  search.objects.assign(objs.begin(), objs.end());
  search.dlls.assign(dlls.begin(), dlls.end());
  search.executables.assign(exes.begin(), exes.end());
}

}  // namespace

const char* to_string(WhyStatus status) {
  switch (status) {
    case WhyStatus::Found:
      return "FOUND";
    case WhyStatus::ClosestMismatch:
      return "NOT FOUND (closest mismatch)";
    case WhyStatus::NotFound:
    default:
      return "NOT FOUND";
  }
}

const char* to_string(WhyConfidence confidence) {
  switch (confidence) {
    case WhyConfidence::High:
      return "HIGH";
    case WhyConfidence::Medium:
      return "MEDIUM";
    case WhyConfidence::Low:
    default:
      return "LOW";
  }
}

const char* to_string(WhyFailureClass failure_class) {
  switch (failure_class) {
    case WhyFailureClass::None:
      return "none";
    case WhyFailureClass::SignatureMismatch:
      return "signature_mismatch";
    case WhyFailureClass::MissingLibrary:
      return "missing_library";
    case WhyFailureClass::LibraryNotLinked:
      return "library_not_linked";
    case WhyFailureClass::ArchitectureMismatch:
      return "architecture_mismatch";
    case WhyFailureClass::CallingConventionMismatch:
      return "calling_convention_mismatch";
    case WhyFailureClass::LinkageMismatch:
      return "linkage_mismatch";
    case WhyFailureClass::MissingExport:
      return "missing_export";
    case WhyFailureClass::DuplicateSymbol:
      return "duplicate_symbol";
    case WhyFailureClass::WrongLibraryVersion:
      return "wrong_library_version";
    case WhyFailureClass::DebugReleaseMismatch:
      return "debug_release_mismatch";
    case WhyFailureClass::RuntimeMismatch:
      return "runtime_mismatch";
    case WhyFailureClass::IncompatibleSymbol:
      return "incompatible_symbol";
    case WhyFailureClass::NotCompiled:
      return "not_compiled";
    case WhyFailureClass::Unknown:
    default:
      return "unknown";
  }
}

WhyReport project_why(const std::string& query, const std::string& target_path,
                      const std::vector<std::string>& roots,
                      BinaryCache& cache) {
  WhyReport report;
  report.query = query;
  report.target_path = target_path;
  report.find = project_find(query, roots, cache);
  report.has_exact = !report.find.exact.empty();
  report.expected_display = display_expected(query);
  fill_search(report.search, target_path, roots, report.find);

  BinaryImage target;
  bool have_target = false;
  if (!target_path.empty()) {
    auto t = load_binary_cached(cache, target_path);
    if (t) {
      target = t.take_value();
      have_target = true;
    }
  }

  if (!report.find.closest.empty()) {
    report.signature_diff = diff_signatures(
        report.expected_display,
        report.find.closest[0].match.candidate.demangled);
  }

  if (have_target && report.has_exact) {
    for (const auto& hit : report.find.exact) {
      if (target_references_provider(target, hit)) {
        report.target_links_provider = true;
        break;
      }
    }
  }

  {
    WhyCheck src;
    src.question = "Symbol exists in source?";
    src.answer = "UNKNOWN";
    src.detail = "No PDB/source map in this phase";
    report.investigation.push_back(std::move(src));

    WhyCheck obj;
    obj.question = "Symbol exists in object files?";
    if (report.has_exact && any_obj_hit(report.find)) {
      obj.answer = "YES";
    } else if (!report.find.closest.empty() && any_obj_hit(report.find)) {
      obj.answer = "CLOSEST ONLY";
    } else {
      obj.answer = "NO";
    }
    report.investigation.push_back(std::move(obj));

    WhyCheck lib;
    lib.question = "Symbol exists in libraries?";
    if (report.has_exact && any_lib_hit(report.find)) {
      lib.answer = "YES";
    } else if (!report.find.closest.empty() && any_lib_hit(report.find)) {
      lib.answer = "CLOSEST ONLY";
    } else {
      lib.answer = "NO";
    }
    report.investigation.push_back(std::move(lib));

    WhyCheck arch;
    arch.question = "Architecture mismatch?";
    if (have_target) {
      bool mismatch = false;
      Architecture lib_arch = Architecture::Unknown;
      for (const auto& hit : report.find.exact) {
        if (hit.image.architecture != Architecture::Unknown &&
            target.architecture != Architecture::Unknown &&
            hit.image.architecture != target.architecture) {
          mismatch = true;
          lib_arch = hit.image.architecture;
        }
      }
      for (const auto& hit : report.find.closest) {
        if (hit.image.architecture != Architecture::Unknown &&
            target.architecture != Architecture::Unknown &&
            hit.image.architecture != target.architecture) {
          mismatch = true;
          lib_arch = hit.image.architecture;
        }
      }
      if (mismatch) {
        arch.answer = "YES";
        arch.detail = std::string("target: ") + to_string(target.architecture) +
                      ", library: " + to_string(lib_arch);
      } else {
        arch.answer = "NO";
        arch.detail = std::string("target: ") + to_string(target.architecture);
      }
    } else {
      arch.answer = "UNKNOWN";
      arch.detail = "No target binary given";
    }
    report.investigation.push_back(std::move(arch));

    WhyCheck linked;
    linked.question = "Provider referenced by target?";
    if (!have_target) {
      linked.answer = "UNKNOWN";
      linked.detail = "No target binary given";
    } else if (report.has_exact) {
      const auto& hit = report.find.exact[0];
      if (hit.image.format == BinaryFormat::PeDll) {
        linked.answer = report.target_links_provider ? "YES" : "NO";
      } else {
        linked.answer = "UNKNOWN";
        linked.detail = "Static .lib/.obj link not visible in PE imports";
      }
    } else {
      linked.answer = "N/A";
      linked.detail = "No exact provider to check";
    }
    report.investigation.push_back(std::move(linked));
  }

  if (report.has_exact) {
    report.status = WhyStatus::Found;
    report.failure_class = WhyFailureClass::None;
    report.closest_display = report.find.exact[0].match.candidate.demangled;
    report.location_display =
        short_location(report.find.exact[0].match.location);
    report.diagnosis_confidence = WhyConfidence::High;
    report.root_cause_confidence = WhyConfidence::Low;
    report.confidence = report.diagnosis_confidence;
    report.confidence_basis =
        "Exact mangled/demangled match found in searched binaries";

    report.facts.push_back("Requested: " +
                           compact_name(report.expected_display));
    report.facts.push_back("Available: " +
                           compact_name(report.closest_display));
    report.facts.push_back("Location: " + report.location_display);
    if (have_target) {
      report.facts.push_back("Target: " + basename_of(target_path));
    }

    const auto& hit = report.find.exact[0];
    if (have_target && hit.image.format == BinaryFormat::PeDll &&
        !report.target_links_provider) {
      report.failure_class = WhyFailureClass::LibraryNotLinked;
      report.diagnosis_confidence = WhyConfidence::High;
      report.root_cause_confidence = WhyConfidence::Medium;
      report.confidence = report.diagnosis_confidence;
      report.confidence_basis =
          "Exact DLL export exists; target PE imports do not reference it";
      report.inferences.push_back(
          "Exact export exists, but the target does not import that DLL/symbol");
      report.likely_cause = "Exact export exists, but target does not import it";
      report.likely_causes = {
          "Import library not on the link line",
          "Wrong DLL/import library version",
          "Stale target build",
      };
      report.suggested_fix =
          "Link the import library for " + basename_of(hit.path);
    } else if (have_target && (hit.image.format == BinaryFormat::CoffLib ||
                               hit.image.format == BinaryFormat::CoffObj)) {
      report.failure_class = WhyFailureClass::None;
      report.diagnosis_confidence = WhyConfidence::High;
      report.root_cause_confidence = WhyConfidence::Low;
      report.confidence = report.diagnosis_confidence;
      report.confidence_basis =
          "Exact symbol exists in static .lib/.obj; PE imports cannot prove link status";
      report.facts.push_back(
          "Static .lib/.obj link cannot be proven from PE imports alone");
      report.inferences.push_back(
          "Exact symbol exists in a static provider; target may already contain it");
      report.likely_cause =
          "Symbol is available via a static library/object under search roots";
      report.suggested_fix =
          "If the linker still fails, add " + basename_of(hit.path) +
          " to the link line";
    } else if (have_target && report.target_links_provider) {
      report.failure_class = WhyFailureClass::None;
      report.diagnosis_confidence = WhyConfidence::High;
      report.root_cause_confidence = WhyConfidence::Low;
      report.confidence = report.diagnosis_confidence;
      report.confidence_basis =
          "Exact provider is referenced by target imports; runtime path is not proven";
      report.inferences.push_back(
          "Target already imports a provider; failure may be runtime path related");
      report.likely_cause =
          "Link metadata already references a provider; runtime path may still fail";
      report.suggested_fix =
          "Ensure the DLL is beside the exe or on PATH";
    } else {
      report.failure_class = WhyFailureClass::None;
      report.diagnosis_confidence = WhyConfidence::High;
      report.root_cause_confidence = WhyConfidence::Low;
      report.confidence = report.diagnosis_confidence;
      report.confidence_basis =
          "Exact symbol exists under search roots";
      report.inferences.push_back(
          "Exact symbol is available under the searched binaries");
      report.likely_cause = "Symbol is available; ensure the failing target links it";
      report.suggested_fix =
          "Link the providing .lib/.obj/.dll into the failing target";
    }
  } else if (!report.find.closest.empty()) {
    report.status = WhyStatus::ClosestMismatch;
    const auto& hit = report.find.closest[0];
    report.closest_display = hit.match.candidate.demangled;
    report.location_display = short_location(hit.match.location);
    report.diagnosis_confidence = WhyConfidence::High;
    report.root_cause_confidence = WhyConfidence::Low;
    report.confidence = report.diagnosis_confidence;
    report.confidence_basis =
        "Exact symbol base name matched, but signature/encoding differs";

    report.facts.push_back("Requested: " +
                           compact_name(report.expected_display));
    report.facts.push_back("Available: " +
                           compact_name(report.closest_display));
    report.facts.push_back("Location: " + report.location_display);
    if (have_target) {
      report.facts.push_back("Target: " + basename_of(target_path));
    }

    bool has_cc = false;
    for (const auto& d : report.signature_diff.differences) {
      if (d.find("Calling convention") != std::string::npos) {
        has_cc = true;
      }
    }

    if (hit.match.rank == MatchRank::SameBaseDifferentParams || has_cc) {
      if (has_cc && report.signature_diff.expected_param_count ==
                        report.signature_diff.found_param_count) {
        report.failure_class = WhyFailureClass::CallingConventionMismatch;
        report.confidence_basis =
            "Same base name matched; calling convention tokens differ";
        report.inferences.push_back(
            "Same function base name, incompatible calling convention");
        report.likely_cause =
            "Requested calling convention is not present in the scanned artifacts";
        report.likely_causes = {
            "Calling convention mismatch on declaration vs definition",
            "Stale object or library",
            "Wrong build artifact being scanned",
        };
        report.suggested_fix =
            "Align calling conventions or rebuild the affected artifacts";
      } else {
        report.failure_class = WhyFailureClass::SignatureMismatch;
        if (report.signature_diff.expected_param_count >= 0 &&
            report.signature_diff.found_param_count >= 0 &&
            report.signature_diff.expected_param_count !=
                report.signature_diff.found_param_count) {
          report.confidence_basis =
              "Exact symbol base name matched, but parameter count differs (" +
              std::to_string(report.signature_diff.expected_param_count) +
              " vs " +
              std::to_string(report.signature_diff.found_param_count) + ")";
          report.inferences.push_back(
              "Same function base name, incompatible parameter count");
        } else {
          report.confidence_basis =
              "Exact symbol base name matched, but parameter types differ";
          report.inferences.push_back(
              "Same function base name, incompatible parameter types");
        }
        report.likely_cause =
            "Requested signature is not present in the scanned artifacts";
        report.likely_causes = {
            "Declaration/definition mismatch",
            "Stale object or library",
            "Different header or build configuration",
            "Overload mismatch",
            "Wrong library version",
        };
        report.suggested_fix =
            "Align signatures or rebuild the affected artifacts";
      }
    } else if (hit.match.rank == MatchRank::LinkageMismatch) {
      report.failure_class = WhyFailureClass::LinkageMismatch;
      report.confidence_basis =
          "Related name matched; C versus C++ linkage encoding differs";
      report.inferences.push_back(
          "Related name exists, but C versus C++ linkage encoding differs");
      report.likely_cause = "Available symbol has incompatible linkage";
      report.likely_causes = {
          "C/C++ linkage mismatch (extern \"C\")",
          "Stale object or library",
          "Wrong build artifact being scanned",
      };
      report.suggested_fix =
          "Use extern \"C\" on both sides or on neither, then rebuild";
    } else if (hit.match.rank == MatchRank::ArchMismatch) {
      report.failure_class = WhyFailureClass::ArchitectureMismatch;
      report.confidence_basis =
          "Related symbol found, but provider architecture differs from target";
      report.inferences.push_back(
          "A candidate exists, but architecture does not match the target");
      report.likely_cause = "Available symbol comes from a different architecture";
      report.likely_causes = {
          "Architecture mismatch (for example x86 vs x64)",
          "Wrong build artifact being scanned",
      };
      report.suggested_fix = "Rebuild for the same architecture";
    } else if (hit.match.rank == MatchRank::MissingExport) {
      report.failure_class = WhyFailureClass::MissingExport;
      report.diagnosis_confidence = WhyConfidence::Medium;
      report.root_cause_confidence = WhyConfidence::Low;
      report.confidence = report.diagnosis_confidence;
      report.confidence_basis =
          "Definition-like symbol seen without a clear DLL export match";
      report.inferences.push_back(
          "A definition appears present without a matching DLL export");
      report.likely_cause =
          "Symbol appears present but may not be exported from the DLL";
      report.likely_causes = {
          "Missing dllexport / module-definition export",
          "Stale DLL build",
          "Wrong DLL being scanned",
      };
      report.suggested_fix =
          "Export the symbol, rebuild the DLL, then re-run why";
    } else {
      report.failure_class = WhyFailureClass::IncompatibleSymbol;
      report.diagnosis_confidence = WhyConfidence::Medium;
      report.root_cause_confidence = WhyConfidence::Low;
      report.confidence = report.diagnosis_confidence;
      report.confidence_basis =
          "A related symbol was found, but it is not an exact match";
      report.inferences.push_back(
          "A related symbol exists but is not an exact match");
      report.likely_cause = "Available related symbol is incompatible";
      report.likely_causes = {
          "Incompatible related symbol",
          "Stale or wrong build artifact",
      };
      report.suggested_fix = "Inspect the closest match and align signatures";
    }
  } else {
    report.status = WhyStatus::NotFound;
    report.failure_class = WhyFailureClass::NotCompiled;
    report.diagnosis_confidence = WhyConfidence::High;
    report.root_cause_confidence = WhyConfidence::Low;
    report.confidence = report.diagnosis_confidence;
    report.confidence_basis =
        "No exact or close match among scanned binaries";
    report.facts.push_back("Requested: " +
                           compact_name(report.expected_display));
    report.facts.push_back("No exact or close match under search roots");
    if (have_target) {
      report.facts.push_back("Target: " + basename_of(target_path) + " (" +
                             to_string(target.architecture) + ")");
    }
    if (report.search.libraries.empty() && report.search.objects.empty()) {
      report.failure_class = WhyFailureClass::MissingLibrary;
      report.inferences.push_back(
          "Search roots contained no libraries/objects with a related symbol");
      report.likely_cause =
          "No related symbol found under the searched paths";
      report.likely_causes = {
          "Missing library",
          "Wrong search roots",
          "Symbol never compiled",
      };
      report.suggested_fix =
          "Pass --root to the directory that contains the built .lib/.obj files";
    } else {
      report.inferences.push_back(
          "Binaries were scanned, but the required symbol was not present");
      report.likely_cause =
          "Required symbol was not present in the searched binaries";
      report.likely_causes = {
          "Function not compiled into the library/object",
          "Wrong or stale build artifact",
          "Search roots do not include the real provider",
      };
      report.suggested_fix =
          "Compile the defining translation unit, or widen --root";
    }
  }

  return report;
}

}  // namespace symcheck
