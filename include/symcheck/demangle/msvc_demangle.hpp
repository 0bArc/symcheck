#pragma once

#include "symcheck/ir/types.hpp"

#include <string>

namespace symcheck {

[[nodiscard]] std::string demangle_msvc(const std::string& mangled);
[[nodiscard]] Linkage guess_linkage(const std::string& mangled);

}  // namespace symcheck
