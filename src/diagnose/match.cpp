#include "symcheck/diagnose/match.hpp"

#include "symcheck/demangle/msvc_demangle.hpp"

#include <algorithm>
#include <cctype>

namespace symcheck {
namespace {

std::string normalize(std::string s) {
  std::string out;
  out.reserve(s.size());
  for (char ch : s) {
    if (ch == ' ') {
      continue;
    }
    out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
  }
  return out;
}

bool names_equal(const std::string& a, const std::string& b) {
  return normalize(a) == normalize(b);
}

bool params_equal(const std::string& a, const std::string& b) {
  std::string na = normalize(a);
  std::string nb = normalize(b);
  if (na == "(void)") {
    na = "()";
  }
  if (nb == "(void)") {
    nb = "()";
  }
  return na == nb;
}

bool is_name_char(char ch) {
  return std::isalnum(static_cast<unsigned char>(ch)) != 0 || ch == '_' ||
         ch == ':' || ch == '~';
}

// Pulls `demo::Greeter::hello` out of MSVC text like
// `public: void __cdecl demo::Greeter::hello(void) __ptr64`.
std::string core_qualified_name(const std::string& demangled) {
  std::string head = demangled;
  const auto paren = head.find('(');
  if (paren != std::string::npos) {
    head = head.substr(0, paren);
  }

  const auto col = head.rfind("::");
  if (col != std::string::npos) {
    std::size_t start = col;
    while (start > 0 && is_name_char(head[start - 1])) {
      --start;
    }
    return head.substr(start);
  }

  std::size_t end = head.size();
  while (end > 0 && head[end - 1] == ' ') {
    --end;
  }
  std::size_t start = end;
  while (start > 0 && is_name_char(head[start - 1])) {
    --start;
  }
  if (start >= end) {
    return head;
  }
  return head.substr(start, end - start);
}

std::string param_list(const std::string& demangled) {
  const auto open = demangled.find('(');
  if (open == std::string::npos) {
    return {};
  }
  const auto close = demangled.find(')', open);
  if (close == std::string::npos || close < open) {
    return {};
  }
  return demangled.substr(open, close - open + 1);
}

}  // namespace

std::string base_name(const std::string& demangled) {
  return core_qualified_name(demangled);
}

SymbolMatch find_best_match(const BinaryImage& image,
                            const std::string& query) {
  SymbolMatch best;
  best.rank = MatchRank::NotFound;
  best.reason = "Symbol not found";
  best.expected.mangled = query;
  best.expected.demangled = demangle_msvc(query);

  const std::string query_demangled = demangle_msvc(query);
  best.expected.demangled = query_demangled;
  if (query_demangled == query && query.find('(') != std::string::npos) {
    best.expected.demangled = query;
  }
  const std::string query_base = core_qualified_name(best.expected.demangled);
  const std::string query_params = param_list(best.expected.demangled);
  const Linkage query_linkage = guess_linkage(query);

  constexpr std::size_t kMax = 10'000'000;
  const std::size_t n = image.symbols.size() < kMax ? image.symbols.size() : kMax;

  for (std::size_t i = 0; i < n; ++i) {
    const Symbol& sym = image.symbols[i];
    SymbolMatch cur;
    cur.candidate = sym;
    cur.expected = best.expected;
    cur.location = image.path;
    if (!sym.object_member.empty()) {
      std::string member = sym.object_member;
      const auto slash = member.find_last_of("\\/");
      if (slash != std::string::npos && slash + 1 < member.size()) {
        member = member.substr(slash + 1);
      }
      cur.location += " -> " + member;
    }

    const std::string cand_base = core_qualified_name(sym.demangled);
    const std::string cand_params = param_list(sym.demangled);
    const bool is_provider = sym.defined || sym.exported;
    // Name-only queries look like "calc::add", not mangled "?..." / "_Z...".
    const bool query_name_only =
        query.find('(') == std::string::npos && !query.empty() &&
        query[0] != '?' && query.rfind("_Z", 0) != 0;

    // Undefined COFF refs (common in .obj that call the symbol) are not providers.
    if (!is_provider) {
      continue;
    }

    if (sym.mangled == query || names_equal(sym.mangled, query) ||
        names_equal(sym.demangled, query) ||
        names_equal(sym.demangled, query_demangled) ||
        (!query_base.empty() && names_equal(cand_base, query_base) &&
         params_equal(cand_params, query_params) && !query_params.empty()) ||
        (query_name_only && !query_base.empty() &&
         names_equal(cand_base, query_base))) {
      cur.rank = MatchRank::ExactMangled;
      cur.reason = "Exact symbol match";
      return cur;
    }

    if (!query_base.empty() && names_equal(cand_base, query_base) &&
        !query_name_only && !params_equal(cand_params, query_params)) {
      cur.rank = MatchRank::SameBaseDifferentParams;
      cur.reason = "Same function base name, different signature";
      if (static_cast<int>(cur.rank) < static_cast<int>(best.rank) ||
          best.rank == MatchRank::NotFound) {
        best = cur;
      }
      continue;
    }

    if (query_linkage != Linkage::Unknown && sym.linkage != Linkage::Unknown &&
        query_linkage != sym.linkage &&
        names_equal(cand_base, query_base)) {
      cur.rank = MatchRank::LinkageMismatch;
      cur.reason = "C versus C++ linkage mismatch";
      if (best.rank == MatchRank::NotFound ||
          static_cast<int>(cur.rank) < static_cast<int>(best.rank)) {
        best = cur;
      }
      continue;
    }

    if (sym.architecture != Architecture::Unknown &&
        image.architecture != Architecture::Unknown &&
        names_equal(cand_base, query_base) &&
        sym.architecture != best.expected.architecture &&
        best.expected.architecture != Architecture::Unknown) {
      cur.rank = MatchRank::ArchMismatch;
      cur.reason = "Architecture mismatch";
      if (best.rank == MatchRank::NotFound ||
          static_cast<int>(cur.rank) < static_cast<int>(best.rank)) {
        best = cur;
      }
    }
  }

  if (best.rank == MatchRank::NotFound) {
    for (std::size_t i = 0; i < n; ++i) {
      const Symbol& sym = image.symbols[i];
      if (sym.defined && !sym.exported &&
          (names_equal(core_qualified_name(sym.demangled), query_base) ||
           names_equal(sym.mangled, query))) {
        best.rank = MatchRank::MissingExport;
        best.candidate = sym;
        best.location = image.path;
        if (!sym.object_member.empty()) {
          std::string member = sym.object_member;
          const auto slash = member.find_last_of("\\/");
          if (slash != std::string::npos && slash + 1 < member.size()) {
            member = member.substr(slash + 1);
          }
          best.location += " -> " + member;
        }
        best.reason = "Symbol present in object or library but not exported";
        break;
      }
    }
  }

  return best;
}

std::vector<SymbolMatch> find_matches_in(const std::vector<BinaryImage>& images,
                                         const std::string& query) {
  std::vector<SymbolMatch> out;
  out.reserve(images.size());
  constexpr std::size_t kMaxImages = 10'000;
  const std::size_t n = images.size() < kMaxImages ? images.size() : kMaxImages;
  for (std::size_t i = 0; i < n; ++i) {
    out.push_back(find_best_match(images[i], query));
  }
  std::sort(out.begin(), out.end(),
            [](const SymbolMatch& a, const SymbolMatch& b) {
              return static_cast<int>(a.rank) < static_cast<int>(b.rank);
            });
  return out;
}

}  // namespace symcheck
