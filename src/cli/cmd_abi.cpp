#include "symcheck/cli/commands.hpp"
#include "symcheck/diagnose/abi.hpp"
#include "symcheck/load/loader.hpp"
#include "symcheck/util/json_escape.hpp"

#include <iostream>

namespace symcheck {

int cmd_abi(const CliArgs& args) {
  if (args.positional.empty() || args.positional.size() > 2) {
    std::cerr << "abi requires <a> [b]\n";
    return 2;
  }
  auto left = load_binary(args.positional[0]);
  if (!left) {
    std::cerr << left.error().message() << '\n';
    return 1;
  }

  if (args.positional.size() == 1) {
    const AbiFingerprint fp = fingerprint_abi(left.value());
    if (args.json) {
      std::cout << "{\"path\":\"" << json_escape(fp.path) << "\","
                << "\"arch\":\"" << to_string(fp.arch) << "\","
                << "\"crt\":\"" << to_string(fp.crt) << "\","
                << "\"hash\":" << fp.hash << ","
                << "\"defined\":" << fp.defined_count << ","
                << "\"exports\":" << fp.export_count << "}\n";
    } else {
      std::cout << "ABI fingerprint\n"
                << "  path: " << fp.path << '\n'
                << "  arch: " << to_string(fp.arch) << '\n'
                << "  crt:  " << to_string(fp.crt) << '\n'
                << "  hash: " << fp.hash << '\n'
                << "  defined/exports/imports: " << fp.defined_count << '/'
                << fp.export_count << '/' << fp.import_count << '\n';
    }
    return 0;
  }

  auto right = load_binary(args.positional[1]);
  if (!right) {
    std::cerr << right.error().message() << '\n';
    return 1;
  }
  const AbiDiff diff = compare_abi(left.value(), right.value());
  if (args.json) {
    std::cout << "{\"arch_mismatch\":"
              << (diff.arch_mismatch ? "true" : "false")
              << ",\"crt_mismatch\":" << (diff.crt_mismatch ? "true" : "false")
              << ",\"hash_mismatch\":"
              << (diff.hash_mismatch ? "true" : "false")
              << ",\"only_left\":" << diff.only_left.size()
              << ",\"only_right\":" << diff.only_right.size() << "}\n";
  } else {
    std::cout << "ABI compare\n"
              << "  " << diff.left.path << "  hash=" << diff.left.hash << '\n'
              << "  " << diff.right.path << "  hash=" << diff.right.hash
              << '\n';
    if (diff.arch_mismatch) {
      std::cout << "  ARCH mismatch\n";
    }
    if (diff.crt_mismatch) {
      std::cout << "  CRT mismatch\n";
    }
    if (!diff.only_left.empty()) {
      std::cout << "  Only in left: " << diff.only_left.size() << '\n';
    }
    if (!diff.only_right.empty()) {
      std::cout << "  Only in right: " << diff.only_right.size() << '\n';
    }
    if (!diff.hash_mismatch && !diff.arch_mismatch && !diff.crt_mismatch) {
      std::cout << "  Compatible fingerprint\n";
    }
  }
  return (diff.arch_mismatch || diff.hash_mismatch) ? 1 : 0;
}

}  // namespace symcheck
