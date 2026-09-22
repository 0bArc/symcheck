#include "symcheck/diagnose/security.hpp"

#include <cctype>
#include <cstring>

namespace symcheck {
namespace {

constexpr std::uint32_t kScnMemExecute = 0x20000000u;
constexpr std::uint32_t kScnMemRead = 0x40000000u;
constexpr std::uint32_t kScnMemWrite = 0x80000000u;

bool name_eq_ci(const std::string& a, const char* b) {
  std::size_t i = 0;
  for (; i < a.size() && b[i] != '\0'; ++i) {
    const char ca =
        static_cast<char>(std::tolower(static_cast<unsigned char>(a[i])));
    const char cb =
        static_cast<char>(std::tolower(static_cast<unsigned char>(b[i])));
    if (ca != cb) {
      return false;
    }
  }
  return i == a.size() && b[i] == '\0';
}

bool is_sensitive_import(const std::string& name) {
  static const char* kList[] = {
      "VirtualAlloc",       "VirtualProtect",     "VirtualAllocEx",
      "WriteProcessMemory", "ReadProcessMemory",  "CreateRemoteThread",
      "NtMapViewOfSection", "LoadLibraryA",       "LoadLibraryW",
      "LoadLibraryExA",     "LoadLibraryExW",     "GetProcAddress",
      "OpenProcess",        "NtCreateThreadEx",   "QueueUserAPC",
  };
  constexpr std::size_t kCount = sizeof(kList) / sizeof(kList[0]);
  for (std::size_t i = 0; i < kCount; ++i) {
    if (name_eq_ci(name, kList[i])) {
      return true;
    }
  }
  return false;
}

}  // namespace

SecurityReport analyze_security(const BinaryImage& image) {
  SecurityReport report;
  report.path = image.path;
  report.aslr = image.aslr;
  report.nx_compat = image.nx_compat;
  report.cfg = image.cfg;
  report.high_entropy_va = image.high_entropy_va;

  constexpr std::size_t kMaxSec = 96;
  const std::size_t sn =
      image.sections.size() < kMaxSec ? image.sections.size() : kMaxSec;
  for (std::size_t i = 0; i < sn; ++i) {
    const SectionInfo& s = image.sections[i];
    const bool exec = s.executable ||
                      (s.characteristics & kScnMemExecute) != 0;
    const bool write =
        s.writable || (s.characteristics & kScnMemWrite) != 0;
    if (exec && write) {
      report.rwx_sections.push_back(s);
      SecurityFinding f;
      f.id = "rwx-section";
      f.severity = "warning";
      f.path = image.path;
      f.message = "RWX section " + s.name;
      report.findings.push_back(std::move(f));
    }
    (void)kScnMemRead;
  }

  if (!image.aslr && (image.format == BinaryFormat::PeExe ||
                      image.format == BinaryFormat::PeDll)) {
    SecurityFinding f;
    f.id = "no-aslr";
    f.severity = "warning";
    f.path = image.path;
    f.message = "ASLR (DYNAMIC_BASE) not set";
    report.findings.push_back(std::move(f));
  }
  if (!image.nx_compat && (image.format == BinaryFormat::PeExe ||
                           image.format == BinaryFormat::PeDll)) {
    SecurityFinding f;
    f.id = "no-nx";
    f.severity = "warning";
    f.path = image.path;
    f.message = "NXCOMPAT not set";
    report.findings.push_back(std::move(f));
  }
  if (!image.cfg && (image.format == BinaryFormat::PeExe ||
                     image.format == BinaryFormat::PeDll)) {
    SecurityFinding f;
    f.id = "no-cfg";
    f.severity = "note";
    f.path = image.path;
    f.message = "Control Flow Guard not set";
    report.findings.push_back(std::move(f));
  }

  constexpr std::size_t kMaxImp = 100'000;
  const std::size_t in =
      image.imports.size() < kMaxImp ? image.imports.size() : kMaxImp;
  for (std::size_t i = 0; i < in; ++i) {
    if (is_sensitive_import(image.imports[i].symbol)) {
      report.sensitive_imports.push_back(image.imports[i].dll + "!" +
                                         image.imports[i].symbol);
      SecurityFinding f;
      f.id = "sensitive-import";
      f.severity = "note";
      f.path = image.path;
      f.message = "Sensitive import " + image.imports[i].dll + "!" +
                  image.imports[i].symbol;
      report.findings.push_back(std::move(f));
    }
  }
  return report;
}

}  // namespace symcheck
