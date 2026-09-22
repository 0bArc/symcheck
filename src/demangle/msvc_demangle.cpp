#include "symcheck/demangle/msvc_demangle.hpp"

#include "symcheck/ir/types.hpp"

#if defined(SYMCHECK_WINDOWS)
#  define WIN32_LEAN_AND_MEAN
#  include <Windows.h>
#  include <dbghelp.h>
#endif

namespace symcheck {

std::string demangle_msvc(const std::string& mangled) {
  if (mangled.empty()) {
    return mangled;
  }
#if defined(SYMCHECK_WINDOWS)
  char buffer[4096];
  const DWORD flags = UNDNAME_COMPLETE;
  const DWORD n = UnDecorateSymbolName(mangled.c_str(), buffer,
                                       static_cast<DWORD>(sizeof(buffer)), flags);
  if (n == 0 || buffer[0] == '\0') {
    return mangled;
  }
  return std::string(buffer);
#else
  return mangled;
#endif
}

Linkage guess_linkage(const std::string& mangled) {
  if (mangled.empty()) {
    return Linkage::Unknown;
  }
  if (mangled[0] == '?' || mangled.rfind("_Z", 0) == 0) {
    return Linkage::Cpp;
  }
  return Linkage::C;
}

}  // namespace symcheck
