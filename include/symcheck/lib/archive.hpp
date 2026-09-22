#pragma once

#include "symcheck/ir/binary.hpp"
#include "symcheck/util/error.hpp"

#include <span>
#include <string>

namespace symcheck {

Result<BinaryImage> parse_coff_library(std::span<const std::byte> data,
                                       const std::string& path);

[[nodiscard]] bool looks_like_archive(std::span<const std::byte> data);

}  // namespace symcheck
