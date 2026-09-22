#pragma once

#include "symcheck/util/error.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <type_traits>

namespace symcheck {

class ByteReader {
 public:
  explicit ByteReader(std::span<const std::byte> data) : data_(data) {}

  [[nodiscard]] std::size_t size() const { return data_.size(); }
  [[nodiscard]] std::size_t tell() const { return offset_; }
  [[nodiscard]] std::size_t remaining() const {
    return offset_ <= data_.size() ? data_.size() - offset_ : 0;
  }

  void seek(std::size_t offset) { offset_ = offset; }

  [[nodiscard]] Result<void> require(std::size_t nbytes) const;

  template <typename T>
  Result<T> read() {
    static_assert(std::is_trivially_copyable_v<T>);
    const auto check = require(sizeof(T));
    if (!check) {
      return Result<T>::Fail(check.error());
    }
    T value{};
    const auto* src = reinterpret_cast<const std::byte*>(data_.data() + offset_);
    auto* dst = reinterpret_cast<std::byte*>(&value);
    for (std::size_t i = 0; i < sizeof(T); ++i) {
      dst[i] = src[i];
    }
    offset_ += sizeof(T);
    return Result<T>::Ok(value);
  }

  Result<std::span<const std::byte>> slice(std::size_t offset, std::size_t length) const;
  Result<std::string> read_c_string(std::size_t offset, std::size_t max_len) const;
  Result<std::uint16_t> peek_u16(std::size_t offset) const;
  Result<std::uint32_t> peek_u32(std::size_t offset) const;

 private:
  std::span<const std::byte> data_;
  std::size_t offset_ = 0;
};

}  // namespace symcheck
