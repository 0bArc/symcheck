#pragma once

#include "symcheck/util/error.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace symcheck {

class MappedFile {
 public:
  MappedFile() = default;
  ~MappedFile();

  MappedFile(const MappedFile&) = delete;
  MappedFile& operator=(const MappedFile&) = delete;

  MappedFile(MappedFile&& other) noexcept;
  MappedFile& operator=(MappedFile&& other) noexcept;

  static Result<MappedFile> open(const std::string& path);

  [[nodiscard]] std::span<const std::byte> bytes() const;
  [[nodiscard]] const std::string& path() const { return path_; }
  [[nodiscard]] std::uint64_t size() const { return size_; }
  [[nodiscard]] std::uint64_t mtime() const { return mtime_; }

 private:
  void close();

  std::string path_;
  std::uint64_t size_ = 0;
  std::uint64_t mtime_ = 0;
  void* file_handle_ = nullptr;
  void* map_handle_ = nullptr;
  void* view_ = nullptr;
};

}  // namespace symcheck
