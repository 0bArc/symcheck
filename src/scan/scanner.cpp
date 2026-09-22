#include "symcheck/scan/scanner.hpp"

#if defined(SYMCHECK_WINDOWS)
#  define WIN32_LEAN_AND_MEAN
#  include <Windows.h>
#endif

#include <cctype>
#include <queue>

namespace symcheck {
namespace {

std::string to_lower_ext(std::string s) {
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

}  // namespace

std::vector<std::string> default_search_roots() {
  return {".", "build", "lib", "bin", "third_party"};
}

bool has_binary_extension(const std::string& path) {
  const auto dot = path.find_last_of('.');
  if (dot == std::string::npos || dot + 1 >= path.size()) {
    return false;
  }
  const std::string ext = to_lower_ext(path.substr(dot + 1));
  return ext == "obj" || ext == "lib" || ext == "dll" || ext == "exe" ||
         ext == "pdb" || ext == "o" || ext == "so" || ext == "a";
}

std::vector<std::string> scan_binaries(const std::vector<std::string>& roots,
                                      ScanLimits limits) {
  std::vector<std::string> out;
  out.reserve(256);

  struct Node {
    std::string path;
    std::size_t depth = 0;
  };
  std::queue<Node> q;

  constexpr std::size_t kMaxRoots = 256;
  const std::size_t root_n =
      roots.size() < kMaxRoots ? roots.size() : kMaxRoots;
  for (std::size_t i = 0; i < root_n; ++i) {
    const std::string& root = roots[i];
    if (root.empty()) {
      continue;
    }
    // Single file root
    if (has_binary_extension(root)) {
      out.push_back(root);
      continue;
    }
    if (directory_exists(root)) {
      q.push(Node{root, 0});
    }
  }

#if defined(SYMCHECK_WINDOWS)
  while (!q.empty() && out.size() < limits.max_files) {
    const Node cur = q.front();
    q.pop();
    if (cur.depth > limits.max_depth) {
      continue;
    }

    const std::string pattern = join_path(cur.path, "*");
    WIN32_FIND_DATAA fd{};
    const HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) {
      continue;
    }

    constexpr std::size_t kMaxEntriesPerDir = 100'000;
    for (std::size_t n = 0; n < kMaxEntriesPerDir; ++n) {
      const std::string name = fd.cFileName;
      if (name != "." && name != "..") {
        const std::string full = join_path(cur.path, name);
        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
          if (cur.depth + 1 <= limits.max_depth) {
            q.push(Node{full, cur.depth + 1});
          }
        } else if (has_binary_extension(full)) {
          out.push_back(full);
          if (out.size() >= limits.max_files) {
            FindClose(h);
            return out;
          }
        }
      }
      if (FindNextFileA(h, &fd) == 0) {
        break;
      }
    }
    FindClose(h);
  }
#else
  (void)limits;
#endif

  return out;
}

}  // namespace symcheck
