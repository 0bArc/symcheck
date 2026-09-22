#include "fixtures.hpp"

#include "symcheck/lib/archive.hpp"

#include <cassert>

namespace {

void test_parse_archive() {
  const auto obj = symcheck::test::make_coff_obj("bar");
  const auto lib = symcheck::test::make_archive_with_obj(obj, "bar.obj");
  assert(symcheck::looks_like_archive(lib));
  auto image = symcheck::parse_coff_library(lib, "bar.lib");
  assert(image);
  assert(image.value().format == symcheck::BinaryFormat::CoffLib);
  assert(image.value().symbols.size() == 1);
  assert(image.value().symbols[0].mangled == "bar");
  assert(image.value().symbols[0].object_member == "bar.obj");
}

}  // namespace

void run_archive_tests() { test_parse_archive(); }
