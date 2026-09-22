#include "symcheck/diagnose/explain.hpp"

#include <cassert>
#include <string>

namespace {

void test_lnk2001() {
  const char* log =
      "foo.obj : error LNK2001: unresolved external symbol "
      "\"public: void __cdecl demo::Greeter::hello(void)\" "
      "(?hello@Greeter@demo@@QEAAXXZ)\n";
  const auto errs = symcheck::parse_linker_errors(log);
  assert(!errs.empty());
  assert(errs[0].code == "LNK2001");
  assert(errs[0].mangled == "?hello@Greeter@demo@@QEAAXXZ");
}

void test_gcc_undefined() {
  const char* log =
      "main.cpp:(.text+0x20): undefined reference to `demo::Greeter::hello()'\n";
  const auto errs = symcheck::parse_linker_errors(log);
  assert(!errs.empty());
  assert(errs[0].code == "undefined_reference");
  assert(errs[0].mangled.find("hello") != std::string::npos);
}

void test_cannot_find_lib() {
  const char* log = "/usr/bin/ld: cannot find -lfoo\n";
  const auto errs = symcheck::parse_linker_errors(log);
  assert(!errs.empty());
  assert(errs[0].kind == symcheck::LinkerErrorKind::CannotFindLib);
}

}  // namespace

void run_explain_parse_tests() {
  test_lnk2001();
  test_gcc_undefined();
  test_cannot_find_lib();
}
