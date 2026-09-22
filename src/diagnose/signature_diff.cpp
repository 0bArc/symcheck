#include "symcheck/diagnose/signature_diff.hpp"

#include "symcheck/diagnose/match.hpp"

#include <cctype>

namespace symcheck {
namespace {

std::string lower(std::string s) {
  for (char& ch : s) {
    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  }
  return s;
}

bool contains_token(const std::string& hay, const char* needle) {
  return lower(hay).find(needle) != std::string::npos;
}

int count_params(const std::string& demangled) {
  const auto open = demangled.find('(');
  if (open == std::string::npos) {
    return -1;
  }
  const auto close = demangled.find(')', open);
  if (close == std::string::npos || close <= open + 1) {
    return 0;
  }
  std::string inside = demangled.substr(open + 1, close - open - 1);
  const std::string low = lower(inside);
  if (inside.empty() || low == "void") {
    return 0;
  }
  int count = 1;
  int depth = 0;
  constexpr std::size_t kMax = 4096;
  const std::size_t n = inside.size() < kMax ? inside.size() : kMax;
  for (std::size_t i = 0; i < n; ++i) {
    const char ch = inside[i];
    if (ch == '<' || ch == '(') {
      ++depth;
    } else if (ch == '>' || ch == ')') {
      if (depth > 0) {
        --depth;
      }
    } else if (ch == ',' && depth == 0) {
      ++count;
    }
  }
  return count;
}

std::string after_paren_tail(const std::string& demangled) {
  const auto close = demangled.rfind(')');
  if (close == std::string::npos || close + 1 >= demangled.size()) {
    return {};
  }
  return demangled.substr(close + 1);
}

std::string calling_conv(const std::string& demangled) {
  const std::string low = lower(demangled);
  if (low.find("__vectorcall") != std::string::npos) {
    return "__vectorcall";
  }
  if (low.find("__fastcall") != std::string::npos) {
    return "__fastcall";
  }
  if (low.find("__stdcall") != std::string::npos) {
    return "__stdcall";
  }
  if (low.find("__cdecl") != std::string::npos) {
    return "__cdecl";
  }
  if (low.find("__thiscall") != std::string::npos) {
    return "__thiscall";
  }
  return {};
}

}  // namespace

SignatureDiff diff_signatures(const std::string& expected_demangled,
                              const std::string& found_demangled) {
  SignatureDiff diff;
  if (base_name(expected_demangled) != base_name(found_demangled) &&
      lower(base_name(expected_demangled)) !=
          lower(base_name(found_demangled))) {
    // Still compare if core names match ignoring case via normalize-ish
  }

  diff.expected_param_count = count_params(expected_demangled);
  diff.found_param_count = count_params(found_demangled);
  if (diff.expected_param_count >= 0 && diff.found_param_count >= 0 &&
      diff.expected_param_count != diff.found_param_count) {
    diff.differences.push_back(
        "Parameter count: expected " + std::to_string(diff.expected_param_count) +
        ", found " + std::to_string(diff.found_param_count));
  }

  const auto open_e = expected_demangled.find('(');
  const auto open_f = found_demangled.find('(');
  if (open_e != std::string::npos && open_f != std::string::npos) {
    const auto close_e = expected_demangled.find(')', open_e);
    const auto close_f = found_demangled.find(')', open_f);
    if (close_e != std::string::npos && close_f != std::string::npos) {
      const std::string pe =
          expected_demangled.substr(open_e, close_e - open_e + 1);
      const std::string pf =
          found_demangled.substr(open_f, close_f - open_f + 1);
      if (lower(pe) != lower(pf) &&
          diff.expected_param_count == diff.found_param_count) {
        diff.differences.push_back("Parameter types differ: " + pe + " vs " +
                                   pf);
      }
      const bool e_const = contains_token(pe, "const");
      const bool f_const = contains_token(pf, "const");
      if (e_const != f_const) {
        diff.differences.push_back("Parameter constness differs");
      }
      const bool e_ref = pe.find('&') != std::string::npos;
      const bool f_ref = pf.find('&') != std::string::npos;
      const bool e_ptr = pe.find('*') != std::string::npos;
      const bool f_ptr = pf.find('*') != std::string::npos;
      if (e_ref != f_ref || e_ptr != f_ptr) {
        diff.differences.push_back("Pointer versus reference differs");
      }
    }
  }

  const std::string te = after_paren_tail(expected_demangled);
  const std::string tf = after_paren_tail(found_demangled);
  const bool e_mconst = contains_token(te, "const") &&
                        !contains_token(te, "noexcept");
  // member const: ") const" pattern
  const bool e_mem_const = lower(te).find("const") != std::string::npos;
  const bool f_mem_const = lower(tf).find("const") != std::string::npos;
  const bool e_noexcept = contains_token(expected_demangled, "noexcept");
  const bool f_noexcept = contains_token(found_demangled, "noexcept");
  if (e_mem_const != f_mem_const) {
    diff.differences.push_back("Member constness differs");
  }
  if (e_noexcept != f_noexcept) {
    diff.differences.push_back("noexcept differs");
  }
  (void)e_mconst;

  const std::string ce = calling_conv(expected_demangled);
  const std::string cf = calling_conv(found_demangled);
  if (!ce.empty() && !cf.empty() && ce != cf) {
    diff.differences.push_back("Calling convention: expected " + ce +
                               ", found " + cf);
  }

  if (diff.differences.empty() &&
      lower(expected_demangled) != lower(found_demangled)) {
    diff.differences.push_back("Signatures differ");
  }
  return diff;
}

}  // namespace symcheck
