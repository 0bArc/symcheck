#include "fixtures.hpp"

#include "symcheck/coff/coff_parser.hpp"

#include <cassert>

namespace {

void test_parse_coff_symbol() {
  const auto bytes = symcheck::test::make_coff_obj("foo");
  auto image = symcheck::parse_coff_object(bytes, "foo.obj");
  assert(image);
  assert(image.value().format == symcheck::BinaryFormat::CoffObj);
  assert(image.value().architecture == symcheck::Architecture::X64);
  assert(image.value().symbols.size() == 1);
  assert(image.value().symbols[0].mangled == "foo");
  assert(image.value().symbols[0].defined);
}

void test_parse_coff_truncated() {
  std::vector<std::byte> bad = {std::byte{1}, std::byte{2}};
  auto image = symcheck::parse_coff_object(bad, "bad.obj");
  assert(!image);
}

}  // namespace

void run_coff_tests() {
  test_parse_coff_symbol();
  test_parse_coff_truncated();
}
