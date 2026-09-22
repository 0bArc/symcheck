#include "fixtures.hpp"

#include "symcheck/pe/pe_parser.hpp"

#include <cassert>

namespace {

void test_looks_like_pe() {
  const auto pe = symcheck::test::make_minimal_pe(false);
  assert(symcheck::looks_like_pe(pe));
}

void test_parse_pe_exe() {
  const auto pe = symcheck::test::make_minimal_pe(false);
  auto image = symcheck::parse_pe(pe, "app.exe");
  assert(image);
  assert(image.value().format == symcheck::BinaryFormat::PeExe);
  assert(image.value().architecture == symcheck::Architecture::X64);
}

void test_parse_pe_dll() {
  const auto pe = symcheck::test::make_minimal_pe(true);
  auto image = symcheck::parse_pe(pe, "foo.dll");
  assert(image);
  assert(image.value().format == symcheck::BinaryFormat::PeDll);
}

}  // namespace

void run_pe_tests() {
  test_looks_like_pe();
  test_parse_pe_exe();
  test_parse_pe_dll();
}
