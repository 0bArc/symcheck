#pragma once

#include <string>
#include <vector>

namespace symcheck {

struct BuildDiscovery {
  std::vector<std::string> binary_roots;
  std::vector<std::string> compile_commands;
  std::vector<std::string> cmake_caches;
  std::vector<std::string> ninja_files;
  std::vector<std::string> msbuild_projects;
  std::vector<std::string> notes;
};

// Walk start dirs for compile_commands.json, CMakeCache.txt, build.ninja, *.vcxproj.
[[nodiscard]] BuildDiscovery discover_build_system(
    const std::vector<std::string>& start_roots);

// Merge discovered binary roots with explicit roots (deduped).
[[nodiscard]] std::vector<std::string> merge_roots_with_discovery(
    const std::vector<std::string>& explicit_roots);

}  // namespace symcheck
