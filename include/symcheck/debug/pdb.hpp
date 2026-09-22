#pragma once

#include "symcheck/ir/binary.hpp"
#include "symcheck/util/error.hpp"

#include <span>
#include <string>

namespace symcheck {

struct PdbLinkInfo {
  std::string path;
  std::string guid_hex;
  std::uint32_t age = 0;
};

// Read CodeView RSDS from PE debug directory (no PDB file open).
[[nodiscard]] Result<PdbLinkInfo> extract_pdb_link(
    std::span<const std::byte> pe_bytes);

// Load public symbols from a .pdb via dbghelp into image.symbols.
[[nodiscard]] Result<void> enrich_image_from_pdb(BinaryImage& image,
                                                 const std::string& pdb_path);

[[nodiscard]] bool looks_like_pdb(std::span<const std::byte> data);

// Standalone .pdb: open via dbghelp and fill a BinaryImage shell.
[[nodiscard]] Result<BinaryImage> load_pdb_symbols(const std::string& pdb_path);

}  // namespace symcheck
