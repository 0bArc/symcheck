#pragma once

#include "symcheck/ir/binary.hpp"
#include "symcheck/ir/cache.hpp"

#include <string>
#include <vector>

namespace symcheck {

enum class CrtKind {
  Unknown,
  DynamicRelease,
  DynamicDebug,
  LikelyStatic,
};

struct MatrixRow {
  std::string path;
  Architecture arch = Architecture::Unknown;
  BinaryFormat format = BinaryFormat::Unknown;
  CrtKind crt = CrtKind::Unknown;
  bool arch_mismatch = false;
  bool crt_warning = false;
  std::string crt_note;
};

[[nodiscard]] CrtKind detect_crt(const BinaryImage& image);
[[nodiscard]] const char* to_string(CrtKind crt);

[[nodiscard]] std::vector<MatrixRow> build_matrix(
    const std::vector<BinaryImage>& images, const std::string& primary_path);

struct DuplicateGroup {
  std::string mangled;
  std::string demangled;
  std::vector<std::string> locations;
};

[[nodiscard]] std::vector<DuplicateGroup> find_duplicates(
    const std::vector<BinaryImage>& images);

struct DepNode {
  std::string name;
  bool found = true;
  std::vector<DepNode> children;
};

[[nodiscard]] DepNode build_deps_tree(const BinaryImage& root,
                                      const std::vector<std::string>& search_roots,
                                      BinaryCache& cache);

}  // namespace symcheck
