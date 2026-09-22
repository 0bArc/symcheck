#pragma once

#include "symcheck/diagnose/abi.hpp"
#include "symcheck/ir/binary.hpp"
#include "symcheck/util/error.hpp"

#include <string>
#include <vector>

namespace symcheck {

struct SnapshotEntry {
  std::string path;
  std::string format;
  std::string arch;
  std::string crt;
  std::uint64_t hash = 0;
  std::size_t defined_count = 0;
  std::size_t export_count = 0;
  std::vector<std::string> exports;
};

struct Snapshot {
  std::string version = "1";
  std::vector<SnapshotEntry> entries;
};

struct SnapshotDiff {
  std::vector<std::string> added;
  std::vector<std::string> removed;
  std::vector<std::string> changed;
};

[[nodiscard]] Snapshot build_snapshot(const std::vector<BinaryImage>& images);
[[nodiscard]] Result<void> write_snapshot(const Snapshot& snap,
                                          const std::string& path);
[[nodiscard]] Result<Snapshot> read_snapshot(const std::string& path);
[[nodiscard]] SnapshotDiff diff_snapshots(const Snapshot& a,
                                          const Snapshot& b);

}  // namespace symcheck
