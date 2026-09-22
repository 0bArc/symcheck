#pragma once

#include <cstdint>
#include <string>

namespace symcheck {

enum class BinaryFormat {
  Unknown,
  CoffObj,
  CoffLib,
  PeExe,
  PeDll,
  Pdb,
  ElfObj,
  ElfShared,
  ElfExe,
};

enum class Architecture {
  Unknown,
  X86,
  X64,
  Arm,
  Arm64,
  Arm64Ec,
};

enum class SymbolKind {
  Unknown,
  Function,
  Data,
  Section,
  File,
  WeakExternal,
};

enum class Linkage {
  Unknown,
  C,
  Cpp,
};

enum class SymbolBinding {
  Local,
  Global,
  Weak,
};

[[nodiscard]] const char* to_string(BinaryFormat format);
[[nodiscard]] const char* to_string(Architecture arch);
[[nodiscard]] const char* to_string(SymbolKind kind);
[[nodiscard]] const char* to_string(Linkage linkage);

[[nodiscard]] Architecture architecture_from_machine(std::uint16_t machine);

struct Symbol {
  std::string mangled;
  std::string demangled;
  SymbolKind kind = SymbolKind::Unknown;
  Linkage linkage = Linkage::Unknown;
  SymbolBinding binding = SymbolBinding::Global;
  Architecture architecture = Architecture::Unknown;
  bool defined = false;
  bool exported = false;
  bool imported = false;
  std::string object_member;
};

struct ImportEntry {
  std::string dll;
  std::string symbol;
  std::uint16_t ordinal = 0;
  bool by_ordinal = false;
};

struct ExportEntry {
  std::string name;
  std::uint32_t ordinal = 0;
  std::uint32_t rva = 0;
  bool is_forwarder = false;
  std::string forwarder;
};

struct SectionInfo {
  std::string name;
  std::uint32_t virtual_address = 0;
  std::uint32_t virtual_size = 0;
  std::uint32_t characteristics = 0;
  bool readable = false;
  bool writable = false;
  bool executable = false;
};

struct LineEntry {
  std::uint64_t address = 0;
  std::string file;
  std::uint32_t line = 0;
  std::uint32_t column = 0;
};

}  // namespace symcheck
