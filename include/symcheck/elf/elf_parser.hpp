#pragma once

#include "symcheck/ir/binary.hpp"
#include "symcheck/util/error.hpp"

#include <span>
#include <string>

namespace symcheck {

[[nodiscard]] bool looks_like_elf(std::span<const std::byte> data);

// ELF + symbol table (.symtab / .dynsym). DWARF line programs not required.
Result<BinaryImage> parse_elf(std::span<const std::byte> data,
                              const std::string& path);

}  // namespace symcheck
