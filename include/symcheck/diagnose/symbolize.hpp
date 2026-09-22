#pragma once

#include "symcheck/ir/binary.hpp"
#include "symcheck/util/error.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace symcheck {

struct SymbolizeFrame {
  std::uint64_t address = 0;
  std::string module;
  std::string symbol;
  std::string demangled;
  std::string file;
  std::uint32_t line = 0;
  bool resolved = false;
};

struct SymbolizeReport {
  std::string module_path;
  std::vector<SymbolizeFrame> frames;
};

// Resolve absolute or RVA addresses against a loaded module (+ PDB when present).
[[nodiscard]] SymbolizeReport symbolize_addresses(
    const BinaryImage& image, const std::vector<std::uint64_t>& addresses);

[[nodiscard]] Result<std::vector<std::uint64_t>> parse_address_list(
    const std::vector<std::string>& tokens);

[[nodiscard]] Result<std::vector<std::uint64_t>> parse_addresses_from_text(
    const std::string& text);

}  // namespace symcheck
