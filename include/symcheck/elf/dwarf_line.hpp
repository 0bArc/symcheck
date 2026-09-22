#pragma once

#include "symcheck/ir/binary.hpp"
#include "symcheck/util/error.hpp"

#include <span>

namespace symcheck {

// Parse DWARF .debug_line into image.lines / image.source_files. Bounded.
[[nodiscard]] Result<void> parse_dwarf_debug_line(
    std::span<const std::byte> section, BinaryImage& image);

}  // namespace symcheck
