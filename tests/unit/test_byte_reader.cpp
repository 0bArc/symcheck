#include "symcheck/util/byte_reader.hpp"

#include <cassert>
#include <vector>

namespace {

void test_byte_reader_basic() {
  std::vector<std::byte> data = {std::byte{1}, std::byte{2}, std::byte{3},
                                 std::byte{4}};
  symcheck::ByteReader reader(data);
  auto u16 = reader.read<std::uint16_t>();
  assert(u16);
  assert(u16.value() == 0x0201);
  auto u16b = reader.read<std::uint16_t>();
  assert(u16b);
  assert(u16b.value() == 0x0403);
  auto fail = reader.read<std::uint16_t>();
  assert(!fail);
}

void test_byte_reader_cstring() {
  std::vector<std::byte> data = {std::byte{'h'}, std::byte{'i'}, std::byte{0},
                                 std::byte{'x'}};
  symcheck::ByteReader reader(data);
  auto s = reader.read_c_string(0, 8);
  assert(s);
  assert(s.value() == "hi");
}

}  // namespace

void run_byte_reader_tests() {
  test_byte_reader_basic();
  test_byte_reader_cstring();
}
