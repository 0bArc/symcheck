#include "symcheck/ir/binary.hpp"

namespace symcheck {

std::size_t BinaryImage::defined_count() const {
  std::size_t n = 0;
  constexpr std::size_t kMax = 10'000'000;
  const std::size_t limit = symbols.size() < kMax ? symbols.size() : kMax;
  for (std::size_t i = 0; i < limit; ++i) {
    if (symbols[i].defined) {
      ++n;
    }
  }
  return n;
}

std::size_t BinaryImage::undefined_count() const {
  std::size_t n = 0;
  constexpr std::size_t kMax = 10'000'000;
  const std::size_t limit = symbols.size() < kMax ? symbols.size() : kMax;
  for (std::size_t i = 0; i < limit; ++i) {
    if (!symbols[i].defined && !symbols[i].imported) {
      ++n;
    }
  }
  return n;
}

std::size_t BinaryImage::exported_count() const {
  return exports.size();
}

std::size_t BinaryImage::imported_count() const {
  return imports.size();
}

}  // namespace symcheck
