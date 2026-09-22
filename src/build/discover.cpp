#include "symcheck/build/discover.hpp"

#include "symcheck/scan/scanner.hpp"

#if defined(SYMCHECK_WINDOWS)
#  define WIN32_LEAN_AND_MEAN
#  include <Windows.h>
#endif

#include <algorithm>
#include <cctype>
#include <fstream>
#include <queue>
#include <set>
#include <string>

namespace symcheck {
namespace {

std::string to_lower(std::string s) {
  for (char& ch : s) {
    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  }
  return s;
}

std::string join_path(const std::string& dir, const std::string& name) {
  if (dir.empty()) {
    return name;
  }
  const char last = dir.back();
  if (last == '\\' || last == '/') {
    return dir + name;
  }
  return dir + '\\' + name;
}

bool directory_exists(const std::string& path) {
#if defined(SYMCHECK_WINDOWS)
  const DWORD attrs = GetFileAttributesA(path.c_str());
  if (attrs == INVALID_FILE_ATTRIBUTES) {
    return false;
  }
  return (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
#else
  (void)path;
  return false;
#endif
}

bool file_exists(const std::string& path) {
#if defined(SYMCHECK_WINDOWS)
  const DWORD attrs = GetFileAttributesA(path.c_str());
  return attrs != INVALID_FILE_ATTRIBUTES &&
         (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
#else
  std::ifstream in(path);
  return static_cast<bool>(in);
#endif
}

std::string basename_lower(const std::string& path) {
  const auto slash = path.find_last_of("/\\");
  std::string base =
      slash == std::string::npos ? path : path.substr(slash + 1);
  return to_lower(base);
}

bool ends_with_ci(const std::string& path, const std::string& suffix) {
  const std::string p = to_lower(path);
  const std::string s = to_lower(suffix);
  if (p.size() < s.size()) {
    return false;
  }
  return p.compare(p.size() - s.size(), s.size(), s) == 0;
}

void add_unique(std::vector<std::string>& list, std::set<std::string>& seen,
                const std::string& path) {
  if (path.empty()) {
    return;
  }
  if (!seen.insert(to_lower(path)).second) {
    return;
  }
  list.push_back(path);
}

}  // namespace

BuildDiscovery discover_build_system(
    const std::vector<std::string>& start_roots) {
  BuildDiscovery disc;
  std::set<std::string> seen_roots;
  std::set<std::string> seen_cc;
  std::set<std::string> seen_cmake;
  std::set<std::string> seen_ninja;
  std::set<std::string> seen_msbuild;

  struct Node {
    std::string path;
    std::size_t depth = 0;
  };
  std::queue<Node> q;
  constexpr std::size_t kMaxRoots = 64;
  constexpr std::size_t kMaxDepth = 8;
  constexpr std::size_t kMaxNodes = 20'000;

  const std::size_t root_n =
      start_roots.size() < kMaxRoots ? start_roots.size() : kMaxRoots;
  for (std::size_t i = 0; i < root_n; ++i) {
    if (!start_roots[i].empty()) {
      q.push(Node{start_roots[i], 0});
    }
  }

  std::size_t visited = 0;
  while (!q.empty() && visited < kMaxNodes) {
    Node cur = q.front();
    q.pop();
    ++visited;
    if (!directory_exists(cur.path) && !file_exists(cur.path)) {
      continue;
    }

    const std::string cc = join_path(cur.path, "compile_commands.json");
    if (file_exists(cc)) {
      add_unique(disc.compile_commands, seen_cc, cc);
      add_unique(disc.binary_roots, seen_roots, cur.path);
      disc.notes.push_back("found compile_commands.json in " + cur.path);
    }
    const std::string cmake = join_path(cur.path, "CMakeCache.txt");
    if (file_exists(cmake)) {
      add_unique(disc.cmake_caches, seen_cmake, cmake);
      add_unique(disc.binary_roots, seen_roots, cur.path);
      disc.notes.push_back("found CMakeCache.txt in " + cur.path);
    }
    const std::string ninja = join_path(cur.path, "build.ninja");
    if (file_exists(ninja)) {
      add_unique(disc.ninja_files, seen_ninja, ninja);
      add_unique(disc.binary_roots, seen_roots, cur.path);
      disc.notes.push_back("found build.ninja in " + cur.path);
    }

#if defined(SYMCHECK_WINDOWS)
    if (directory_exists(cur.path) && cur.depth < kMaxDepth) {
      const std::string pattern = join_path(cur.path, "*");
      WIN32_FIND_DATAA fd{};
      HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
      if (h != INVALID_HANDLE_VALUE) {
        constexpr std::size_t kMaxChildren = 10'000;
        for (std::size_t c = 0; c < kMaxChildren; ++c) {
          const std::string name = fd.cFileName;
          if (name != "." && name != "..") {
            const std::string child = join_path(cur.path, name);
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
              q.push(Node{child, cur.depth + 1});
            } else if (ends_with_ci(name, ".vcxproj") ||
                       ends_with_ci(name, ".sln")) {
              add_unique(disc.msbuild_projects, seen_msbuild, child);
              add_unique(disc.binary_roots, seen_roots, cur.path);
            }
          }
          if (!FindNextFileA(h, &fd)) {
            break;
          }
        }
        FindClose(h);
      }
    }
#else
    (void)kMaxDepth;
#endif
  }

  if (disc.binary_roots.empty()) {
    disc.notes.push_back("no build-system markers found");
  }
  return disc;
}

std::vector<std::string> merge_roots_with_discovery(
    const std::vector<std::string>& explicit_roots) {
  std::vector<std::string> start = explicit_roots;
  if (start.empty()) {
    start = default_search_roots();
  }
  BuildDiscovery disc = discover_build_system(start);
  std::vector<std::string> out = start;
  std::set<std::string> seen;
  for (const auto& r : out) {
    seen.insert(to_lower(r));
  }
  for (const auto& r : disc.binary_roots) {
    if (seen.insert(to_lower(r)).second) {
      out.push_back(r);
    }
  }
  return out;
}

}  // namespace symcheck
