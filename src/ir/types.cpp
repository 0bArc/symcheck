#include "symcheck/ir/types.hpp"

namespace symcheck {

const char* to_string(BinaryFormat format) {
  switch (format) {
    case BinaryFormat::CoffObj:
      return "COFF";
    case BinaryFormat::CoffLib:
      return "COFF library";
    case BinaryFormat::PeExe:
      return "PE executable";
    case BinaryFormat::PeDll:
      return "PE DLL";
    case BinaryFormat::Pdb:
      return "PDB";
    case BinaryFormat::ElfObj:
      return "ELF object";
    case BinaryFormat::ElfShared:
      return "ELF shared";
    case BinaryFormat::ElfExe:
      return "ELF executable";
    case BinaryFormat::Unknown:
    default:
      return "unknown";
  }
}

const char* to_string(Architecture arch) {
  switch (arch) {
    case Architecture::X86:
      return "x86";
    case Architecture::X64:
      return "x64";
    case Architecture::Arm:
      return "ARM";
    case Architecture::Arm64:
      return "ARM64";
    case Architecture::Arm64Ec:
      return "ARM64EC";
    case Architecture::Unknown:
    default:
      return "unknown";
  }
}

const char* to_string(SymbolKind kind) {
  switch (kind) {
    case SymbolKind::Function:
      return "function";
    case SymbolKind::Data:
      return "data";
    case SymbolKind::Section:
      return "section";
    case SymbolKind::File:
      return "file";
    case SymbolKind::WeakExternal:
      return "weak";
    case SymbolKind::Unknown:
    default:
      return "unknown";
  }
}

const char* to_string(Linkage linkage) {
  switch (linkage) {
    case Linkage::C:
      return "C";
    case Linkage::Cpp:
      return "C++";
    case Linkage::Unknown:
    default:
      return "unknown";
  }
}

Architecture architecture_from_machine(std::uint16_t machine) {
  switch (machine) {
    case 0x014c:
      return Architecture::X86;
    case 0x8664:
      return Architecture::X64;
    case 0x01c0:
    case 0x01c4:
      return Architecture::Arm;
    case 0xaa64:
      return Architecture::Arm64;
    case 0xa641:
      return Architecture::Arm64Ec;
    default:
      return Architecture::Unknown;
  }
}

}  // namespace symcheck
