#include "symcheck/cli/commands.hpp"

#include "symcheck/build/discover.hpp"
#include "symcheck/scan/scanner.hpp"

namespace symcheck {

const char* usage_text() {
  return
      "SymCheck - C/C++ symbol diagnostics\n"
      "\n"
      "Usage:\n"
      "  symcheck inspect <path> [--json]\n"
      "  symcheck symbol <path> <name> [--json]\n"
      "  symcheck find <name> [--root DIR]... [--json]\n"
      "  symcheck why <name> [target] [--root DIR]... [--verbose] [--json]\n"
      "  symcheck trace <source|symbol> [--root DIR]... [--json]\n"
      "  symcheck abi <a> [b] [--json]\n"
      "  symcheck snapshot save <file> [--root DIR]...\n"
      "  symcheck snapshot diff <old> <new> [--json]\n"
      "  symcheck ci [--root DIR]... [--log link.log] [--sarif] [--discover]\n"
      "  symcheck security <path> [--json]\n"
      "  symcheck symbolize <module> <addr>... [--log file] [--json]\n"
      "  symcheck exports <path> [--json]\n"
      "  symcheck imports <path> [--json]\n"
      "  symcheck deps <exe|dll> [--root DIR]... [--json]\n"
      "  symcheck duplicates [DIR] [--root DIR]... [--json]\n"
      "  symcheck matrix [DIR] [--root DIR]... [--target path] [--json]\n"
      "  symcheck compare <a> <b> [--json]\n"
      "  symcheck explain [log] [--lib path]... [--obj path]... [--root DIR]...\n"
      "  symcheck graph <exe>   (alias of deps)\n"
      "  symcheck help\n"
      "\n"
      "Formats: PE/COFF, PDB (dbghelp), ELF64 symbols. "
      "Default roots: . build lib bin third_party\n"
      "Exit codes: 0 ok, 1 findings/errors, 2 usage\n";
}

std::vector<std::string> resolve_roots(const CliArgs& args) {
  if (args.discover) {
    return merge_roots_with_discovery(args.roots);
  }
  if (!args.roots.empty()) {
    return args.roots;
  }
  return default_search_roots();
}

CliArgs parse_args(int argc, char** argv) {
  CliArgs args;
  if (argc < 2) {
    args.command = Command::Help;
    args.help = true;
    return args;
  }

  const std::string cmd = argv[1];
  if (cmd == "help" || cmd == "--help" || cmd == "-h") {
    args.command = Command::Help;
    args.help = true;
    return args;
  }
  if (cmd == "inspect") {
    args.command = Command::Inspect;
  } else if (cmd == "symbol") {
    args.command = Command::Symbol;
  } else if (cmd == "exports") {
    args.command = Command::Exports;
  } else if (cmd == "imports") {
    args.command = Command::Imports;
  } else if (cmd == "compare") {
    args.command = Command::Compare;
  } else if (cmd == "explain") {
    args.command = Command::Explain;
  } else if (cmd == "graph") {
    args.command = Command::Graph;
  } else if (cmd == "find") {
    args.command = Command::Find;
  } else if (cmd == "why") {
    args.command = Command::Why;
  } else if (cmd == "deps") {
    args.command = Command::Deps;
  } else if (cmd == "duplicates") {
    args.command = Command::Duplicates;
  } else if (cmd == "matrix") {
    args.command = Command::Matrix;
  } else if (cmd == "trace") {
    args.command = Command::Trace;
  } else if (cmd == "abi") {
    args.command = Command::Abi;
  } else if (cmd == "snapshot") {
    args.command = Command::Snapshot;
  } else if (cmd == "ci") {
    args.command = Command::Ci;
  } else if (cmd == "security") {
    args.command = Command::Security;
  } else if (cmd == "symbolize") {
    args.command = Command::Symbolize;
  } else {
    args.command = Command::Unknown;
    args.error = "Unknown command: " + cmd;
    return args;
  }

  for (int i = 2; i < argc; ++i) {
    const std::string a = argv[i];
    if (a == "--json") {
      args.json = true;
    } else if (a == "--verbose" || a == "-v") {
      args.verbose = true;
    } else if (a == "--sarif") {
      args.sarif = true;
    } else if (a == "--discover") {
      args.discover = true;
    } else if (a == "--lib") {
      if (i + 1 >= argc) {
        args.error = "--lib requires a path";
        return args;
      }
      ++i;
      args.libs.push_back(argv[i]);
    } else if (a == "--obj") {
      if (i + 1 >= argc) {
        args.error = "--obj requires a path";
        return args;
      }
      ++i;
      args.objs.push_back(argv[i]);
    } else if (a == "--root") {
      if (i + 1 >= argc) {
        args.error = "--root requires a path";
        return args;
      }
      ++i;
      args.roots.push_back(argv[i]);
    } else if (a == "--target") {
      if (i + 1 >= argc) {
        args.error = "--target requires a path";
        return args;
      }
      ++i;
      args.target = argv[i];
    } else if (a == "--out") {
      if (i + 1 >= argc) {
        args.error = "--out requires a path";
        return args;
      }
      ++i;
      args.out_path = argv[i];
    } else if (a == "--log") {
      if (i + 1 >= argc) {
        args.error = "--log requires a path";
        return args;
      }
      ++i;
      args.log_path = argv[i];
    } else if (a == "--help" || a == "-h") {
      args.help = true;
    } else if (!a.empty() && a[0] == '-') {
      args.error = "Unknown option: " + a;
      return args;
    } else {
      args.positional.push_back(a);
    }
  }
  return args;
}

}  // namespace symcheck
