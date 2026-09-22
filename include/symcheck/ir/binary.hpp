#pragma once

#include "symcheck/ir/types.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace symcheck {

struct BinaryImage {
  std::string path;
  BinaryFormat format = BinaryFormat::Unknown;
  Architecture architecture = Architecture::Unknown;
  std::uint64_t file_size = 0;
  std::uint64_t mtime = 0;

  std::vector<Symbol> symbols;
  std::vector<ImportEntry> imports;
  std::vector<ExportEntry> exports;
  std::vector<std::string> imported_dlls;
  std::vector<std::string> members;
  std::vector<SectionInfo> sections;
  std::vector<LineEntry> lines;

  // Debug link (PE CodeView RSDS) and optional source basenames from PDB/ELF.
  std::string pdb_path;
  std::string pdb_guid;
  std::uint32_t pdb_age = 0;
  std::vector<std::string> source_files;

  std::uint64_t image_base = 0;
  bool aslr = false;
  bool nx_compat = false;
  bool cfg = false;
  bool high_entropy_va = false;

  [[nodiscard]] std::size_t defined_count() const;
  [[nodiscard]] std::size_t undefined_count() const;
  [[nodiscard]] std::size_t exported_count() const;
  [[nodiscard]] std::size_t imported_count() const;
};

}  // namespace symcheck
