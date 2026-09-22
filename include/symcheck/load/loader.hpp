#pragma once

#include "symcheck/ir/binary.hpp"
#include "symcheck/ir/cache.hpp"
#include "symcheck/util/error.hpp"

#include <string>

namespace symcheck {

Result<BinaryImage> load_binary(const std::string& path);
Result<BinaryImage> load_binary_cached(BinaryCache& cache,
                                       const std::string& path);

void enrich_demangle(BinaryImage& image);

}  // namespace symcheck
