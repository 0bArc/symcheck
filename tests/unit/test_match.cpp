#include "symcheck/diagnose/explain.hpp"
#include "symcheck/diagnose/match.hpp"
#include "symcheck/ir/binary.hpp"

#include <cassert>

namespace {

void test_base_name() {
  assert(symcheck::base_name("Foo::bar(int)") == "Foo::bar");
  assert(symcheck::base_name("plain") == "plain");
  assert(symcheck::base_name(
             "public: int __cdecl demo::Greeter::add(int,int) __ptr64") ==
         "demo::Greeter::add");
}

void test_find_exact() {
  symcheck::BinaryImage image;
  image.path = "t.lib";
  symcheck::Symbol s;
  s.mangled = "?bar@Foo@@QEAAXXZ";
  s.demangled = "Foo::bar(void)";
  s.defined = true;
  image.symbols.push_back(s);

  const auto match =
      symcheck::find_best_match(image, "?bar@Foo@@QEAAXXZ");
  assert(match.rank == symcheck::MatchRank::ExactMangled);
}

void test_find_signature_mismatch() {
  symcheck::BinaryImage image;
  image.path = "t.lib";
  symcheck::Symbol s;
  s.mangled = "x";
  s.demangled = "Foo::bar(int)";
  s.defined = true;
  image.symbols.push_back(s);

  const auto match = symcheck::find_best_match(image, "Foo::bar()");
  assert(match.rank == symcheck::MatchRank::SameBaseDifferentParams);
}

void test_find_msvc_decorated_mismatch() {
  symcheck::BinaryImage image;
  image.path = "t.lib";
  symcheck::Symbol s;
  s.mangled = "?add@Greeter@demo@@QEAAHHH@Z";
  s.demangled = "public: int __cdecl demo::Greeter::add(int,int) __ptr64";
  s.defined = true;
  image.symbols.push_back(s);

  const auto match =
      symcheck::find_best_match(image, "demo::Greeter::add(long,long)");
  assert(match.rank == symcheck::MatchRank::SameBaseDifferentParams);
}

void test_parse_lnk2019() {
  const char* log =
      "main.obj : error LNK2019: unresolved external symbol "
      "\"public: void __cdecl Foo::bar(void)\" "
      "(?bar@Foo@@QEAAXXZ) referenced in function main\n";
  const auto errs = symcheck::parse_linker_errors(log);
  assert(!errs.empty());
  assert(errs[0].mangled == "?bar@Foo@@QEAAXXZ");
}

}  // namespace

void run_match_tests() {
  test_base_name();
  test_find_exact();
  test_find_signature_mismatch();
  test_find_msvc_decorated_mismatch();
  test_parse_lnk2019();
}
