#pragma once

#include "symcheck/ir/binary.hpp"
#include "symcheck/util/error.hpp"

#include <string>
#include <unordered_map>

namespace symcheck {

class BinaryCache {
 public:
  Result<BinaryImage> get_or_load(
      const std::string& path,
      Result<BinaryImage> (*loader)(const std::string&));

  void clear();
  [[nodiscard]] std::size_t size() const { return entries_.size(); }

 private:
  struct Entry {
    std::uint64_t size = 0;
    std::uint64_t mtime = 0;
    BinaryImage image;
  };

  std::unordered_map<std::string, Entry> entries_;
};

}  // namespace symcheck
