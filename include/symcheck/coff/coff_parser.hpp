#pragma once

#include "symcheck/ir/binary.hpp"
#include "symcheck/util/error.hpp"

#include <span>

namespace symcheck {

Result<BinaryImage> parse_coff_object(std::span<const std::byte> data,
                                      const std::string& path,
                                      const std::string& member_name = {});

}  // namespace symcheck
