#include "symcheck/cli/commands.hpp"
#include "symcheck/diagnose/project_find.hpp"
#include "symcheck/diagnose/snapshot.hpp"
#include "symcheck/ir/cache.hpp"
#include "symcheck/util/json_escape.hpp"

#include <iostream>

namespace symcheck {

int cmd_snapshot(const CliArgs& args) {
  if (args.positional.empty()) {
    std::cerr << "snapshot requires: save <file> | diff <old> <new>\n";
    return 2;
  }
  const std::string sub = args.positional[0];
  if (sub == "save") {
    if (args.positional.size() < 2) {
      std::cerr << "snapshot save requires <file>\n";
      return 2;
    }
    BinaryCache cache;
    auto images = load_project_binaries(resolve_roots(args), cache, nullptr);
    Snapshot snap = build_snapshot(images);
    auto wr = write_snapshot(snap, args.positional[1]);
    if (!wr) {
      std::cerr << wr.error().message() << '\n';
      return 1;
    }
    std::cout << "Wrote snapshot " << args.positional[1] << " ("
              << snap.entries.size() << " entries)\n";
    return 0;
  }
  if (sub == "diff") {
    if (args.positional.size() < 3) {
      std::cerr << "snapshot diff requires <old> <new>\n";
      return 2;
    }
    auto a = read_snapshot(args.positional[1]);
    auto b = read_snapshot(args.positional[2]);
    if (!a) {
      std::cerr << a.error().message() << '\n';
      return 1;
    }
    if (!b) {
      std::cerr << b.error().message() << '\n';
      return 1;
    }
    const SnapshotDiff d = diff_snapshots(a.value(), b.value());
    if (args.json) {
      std::cout << "{\"added\":" << d.added.size()
                << ",\"removed\":" << d.removed.size()
                << ",\"changed\":" << d.changed.size() << "}\n";
    } else {
      std::cout << "Snapshot diff\n"
                << "  added:   " << d.added.size() << '\n'
                << "  removed: " << d.removed.size() << '\n'
                << "  changed: " << d.changed.size() << '\n';
      constexpr std::size_t kMax = 20;
      for (std::size_t i = 0; i < d.changed.size() && i < kMax; ++i) {
        std::cout << "  ~ " << d.changed[i] << '\n';
      }
      for (std::size_t i = 0; i < d.added.size() && i < kMax; ++i) {
        std::cout << "  + " << d.added[i] << '\n';
      }
      for (std::size_t i = 0; i < d.removed.size() && i < kMax; ++i) {
        std::cout << "  - " << d.removed[i] << '\n';
      }
    }
    return (d.added.empty() && d.removed.empty() && d.changed.empty()) ? 0
                                                                       : 1;
  }
  std::cerr << "Unknown snapshot subcommand: " << sub << '\n';
  return 2;
}

}  // namespace symcheck
