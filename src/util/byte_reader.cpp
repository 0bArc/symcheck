#include "symcheck/util/byte_reader.hpp"

#include <type_traits>

namespace symcheck {

Result<void> ByteReader::require(std::size_t nbytes) const {
  if (nbytes > remaining()) {
    return Result<void>::Fail("Truncated binary: need more bytes than remain");
  }
  return Result<void>::Ok();
}

Result<std::span<const std::byte>> ByteReader::slice(std::size_t offset,
                                                     std::size_t length) const {
  if (offset > data_.size()) {
    return Result<std::span<const std::byte>>::Fail("Slice offset out of range");
  }
  if (length > data_.size() - offset) {
    return Result<std::span<const std::byte>>::Fail("Slice length out of range");
  }
  return Result<std::span<const std::byte>>::Ok(data_.subspan(offset, length));
}

Result<std::string> ByteReader::read_c_string(std::size_t offset,
                                              std::size_t max_len) const {
  if (offset >= data_.size()) {
    return Result<std::string>::Fail("String offset out of range");
  }
  const std::size_t limit =
      max_len < (data_.size() - offset) ? max_len : (data_.size() - offset);
  std::string out;
  out.reserve(limit);
  for (std::size_t i = 0; i < limit; ++i) {
    const char ch = static_cast<char>(data_[offset + i]);
    if (ch == '\0') {
      return Result<std::string>::Ok(std::move(out));
    }
    out.push_back(ch);
  }
  return Result<std::string>::Fail("String not null-terminated within bound");
}

Result<std::uint16_t> ByteReader::peek_u16(std::size_t offset) const {
  if (offset + sizeof(std::uint16_t) > data_.size()) {
    return Result<std::uint16_t>::Fail("peek_u16 out of range");
  }
  const auto b0 = static_cast<std::uint16_t>(data_[offset]);
  const auto b1 = static_cast<std::uint16_t>(data_[offset + 1]);
  return Result<std::uint16_t>::Ok(static_cast<std::uint16_t>(b0 | (b1 << 8)));
}

Result<std::uint32_t> ByteReader::peek_u32(std::size_t offset) const {
  if (offset + sizeof(std::uint32_t) > data_.size()) {
    return Result<std::uint32_t>::Fail("peek_u32 out of range");
  }
  const auto b0 = static_cast<std::uint32_t>(data_[offset]);
  const auto b1 = static_cast<std::uint32_t>(data_[offset + 1]);
  const auto b2 = static_cast<std::uint32_t>(data_[offset + 2]);
  const auto b3 = static_cast<std::uint32_t>(data_[offset + 3]);
  return Result<std::uint32_t>::Ok(b0 | (b1 << 8) | (b2 << 16) | (b3 << 24));
}

}  // namespace symcheck
