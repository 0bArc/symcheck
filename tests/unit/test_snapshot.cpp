#include "symcheck/diagnose/snapshot.hpp"
#include "symcheck/ir/binary.hpp"

#include <cassert>
#include <cstdio>
#include <filesystem>
#include <string>

void run_snapshot_tests() {
  using namespace symcheck;
  BinaryImage a;
  a.path = "a.obj";
  a.architecture = Architecture::X64;
  a.format = BinaryFormat::CoffObj;
  Symbol s;
  s.mangled = "foo";
  s.defined = true;
  a.symbols.push_back(s);

  Snapshot snap = build_snapshot({a});
  assert(snap.entries.size() == 1);

  const std::string path = "symcheck_snapshot_test.json";
  auto wr = write_snapshot(snap, path);
  assert(wr);

  auto rd = read_snapshot(path);
  assert(rd);
  assert(rd.value().entries.size() == 1);
  assert(rd.value().entries[0].path == "a.obj");

  Snapshot other = snap;
  other.entries[0].hash ^= 1ull;
  const SnapshotDiff d = diff_snapshots(snap, other);
  assert(d.changed.size() == 1);

  std::filesystem::remove(path);
  std::puts("snapshot ok");
}
