#include "symcheck/diagnose/abi.hpp"

#include <algorithm>
#include <set>

namespace symcheck {
namespace {

std::uint64_t fnv1a64(const std::string& s, std::uint64_t h) {
  constexpr std::uint64_t kPrime = 1099511628211ull;
  for (unsigned char c : s) {
    h ^= c;
    h *= kPrime;
  }
  return h;
}

}  // namespace

AbiFingerprint fingerprint_abi(const BinaryImage& image) {
  AbiFingerprint fp;
  fp.path = image.path;
  fp.arch = image.architecture;
  fp.crt = detect_crt(image);
  fp.defined_count = image.defined_count();
  fp.export_count = image.exports.size();
  fp.import_count = image.imports.size();
  fp.export_names.reserve(image.exports.size());
  for (const auto& e : image.exports) {
    fp.export_names.push_back(e.name);
  }
  if (fp.export_names.empty()) {
    constexpr std::size_t kMax = 100'000;
    const std::size_t n =
        image.symbols.size() < kMax ? image.symbols.size() : kMax;
    for (std::size_t i = 0; i < n; ++i) {
      const Symbol& s = image.symbols[i];
      if (s.defined && s.binding != SymbolBinding::Local) {
        fp.export_names.push_back(s.mangled);
      }
    }
  }
  std::sort(fp.export_names.begin(), fp.export_names.end());
  fp.export_names.erase(
      std::unique(fp.export_names.begin(), fp.export_names.end()),
      fp.export_names.end());

  std::uint64_t h = 14695981039346656037ull;
  h = fnv1a64(to_string(fp.arch), h);
  h = fnv1a64(to_string(fp.crt), h);
  for (const auto& name : fp.export_names) {
    h = fnv1a64(name, h);
  }
  fp.hash = h;
  return fp;
}

AbiDiff compare_abi(const BinaryImage& a, const BinaryImage& b) {
  AbiDiff diff;
  diff.left = fingerprint_abi(a);
  diff.right = fingerprint_abi(b);
  diff.arch_mismatch = diff.left.arch != diff.right.arch;
  diff.crt_mismatch = diff.left.crt != diff.right.crt &&
                      diff.left.crt != CrtKind::Unknown &&
                      diff.right.crt != CrtKind::Unknown;
  diff.hash_mismatch = diff.left.hash != diff.right.hash;

  std::set<std::string> left_set(diff.left.export_names.begin(),
                                 diff.left.export_names.end());
  std::set<std::string> right_set(diff.right.export_names.begin(),
                                  diff.right.export_names.end());
  for (const auto& n : left_set) {
    if (right_set.find(n) == right_set.end()) {
      diff.only_left.push_back(n);
    }
  }
  for (const auto& n : right_set) {
    if (left_set.find(n) == left_set.end()) {
      diff.only_right.push_back(n);
    }
  }
  return diff;
}

}  // namespace symcheck
