#include "symcheck/diagnose/abi.hpp"
#include "symcheck/ir/binary.hpp"

#include <cassert>
#include <cstdio>

void run_abi_tests() {
  using namespace symcheck;
  BinaryImage a;
  a.path = "a.dll";
  a.architecture = Architecture::X64;
  a.format = BinaryFormat::PeDll;
  ExportEntry e1;
  e1.name = "foo";
  a.exports.push_back(e1);
  Symbol s1;
  s1.mangled = "foo";
  s1.defined = true;
  s1.exported = true;
  a.symbols.push_back(s1);

  BinaryImage b = a;
  b.path = "b.dll";

  const AbiFingerprint fa = fingerprint_abi(a);
  const AbiFingerprint fb = fingerprint_abi(b);
  assert(fa.hash == fb.hash);

  ExportEntry e2;
  e2.name = "bar";
  b.exports.push_back(e2);
  const AbiDiff diff = compare_abi(a, b);
  assert(diff.hash_mismatch);
  assert(diff.only_right.size() == 1);
  assert(diff.only_right[0] == "bar");
  std::puts("abi ok");
}
