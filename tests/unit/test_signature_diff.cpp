#include "symcheck/diagnose/signature_diff.hpp"

#include <cassert>

namespace {

void test_param_count_diff() {
  const auto diff = symcheck::diff_signatures(
      "demo::Greeter::hello(int)",
      "public: void __cdecl demo::Greeter::hello(void) __ptr64");
  assert(!diff.differences.empty());
  assert(diff.expected_param_count == 1);
  assert(diff.found_param_count == 0);
}

}  // namespace

void run_signature_diff_tests() { test_param_count_diff(); }
