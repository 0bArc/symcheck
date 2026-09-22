#include "symcheck/elf/dwarf_line.hpp"

#include "symcheck/util/byte_reader.hpp"

#include <cassert>
#include <string>
#include <vector>

namespace symcheck {
namespace {

constexpr std::size_t kMaxUnits = 256;
constexpr std::size_t kMaxFiles = 4096;
constexpr std::size_t kMaxDirs = 1024;
constexpr std::size_t kMaxOps = 2'000'000;
constexpr std::size_t kMaxLinesOut = 200'000;

struct LineMachine {
  std::uint64_t address = 0;
  std::uint32_t file = 1;
  std::uint32_t line = 1;
  std::uint32_t column = 0;
  bool is_stmt = true;
  bool basic_block = false;
  bool end_sequence = false;
  bool prologue_end = false;
  bool epilogue_begin = false;
};

Result<std::uint64_t> read_uleb(ByteReader& r) {
  std::uint64_t result = 0;
  unsigned shift = 0;
  for (int i = 0; i < 10; ++i) {
    auto b = r.read<std::uint8_t>();
    if (!b) {
      return Result<std::uint64_t>::Fail(b.error());
    }
    result |= (static_cast<std::uint64_t>(b.value() & 0x7f) << shift);
    if ((b.value() & 0x80) == 0) {
      return Result<std::uint64_t>::Ok(result);
    }
    shift += 7;
  }
  return Result<std::uint64_t>::Fail("ULEB128 too long");
}

Result<std::int64_t> read_sleb(ByteReader& r) {
  std::uint64_t result = 0;
  unsigned shift = 0;
  std::uint8_t byte = 0;
  for (int i = 0; i < 10; ++i) {
    auto b = r.read<std::uint8_t>();
    if (!b) {
      return Result<std::int64_t>::Fail(b.error());
    }
    byte = b.value();
    result |= (static_cast<std::uint64_t>(byte & 0x7f) << shift);
    shift += 7;
    if ((byte & 0x80) == 0) {
      break;
    }
  }
  if (shift < 64 && (byte & 0x40) != 0) {
    result |= (~0ull << shift);
  }
  return Result<std::int64_t>::Ok(static_cast<std::int64_t>(result));
}

void emit_row(const LineMachine& m, const std::vector<std::string>& files,
              BinaryImage& image) {
  if (image.lines.size() >= kMaxLinesOut) {
    return;
  }
  LineEntry e;
  e.address = m.address;
  e.line = m.line;
  e.column = m.column;
  if (m.file >= 1 && m.file <= files.size()) {
    e.file = files[m.file - 1];
  }
  image.lines.push_back(std::move(e));
}

Result<void> parse_one_unit(std::span<const std::byte> unit, BinaryImage& image) {
  ByteReader r(unit);
  auto unit_len = r.read<std::uint32_t>();
  if (!unit_len) {
    return Result<void>::Fail(unit_len.error());
  }
  std::size_t header_after_len = r.tell();
  bool dwarf64 = false;
  std::uint64_t length = unit_len.value();
  if (unit_len.value() == 0xffffffffu) {
    auto len64 = r.read<std::uint64_t>();
    if (!len64) {
      return Result<void>::Fail(len64.error());
    }
    length = len64.value();
    dwarf64 = true;
    header_after_len = r.tell();
  }
  if (header_after_len + length > unit.size()) {
    return Result<void>::Fail("debug_line unit length overrun");
  }

  auto version = r.read<std::uint16_t>();
  if (!version) {
    return Result<void>::Fail(version.error());
  }
  if (version.value() < 2 || version.value() > 5) {
    return Result<void>::Fail("Unsupported DWARF line version");
  }

  if (version.value() >= 5) {
    auto addr_size = r.read<std::uint8_t>();
    auto seg_size = r.read<std::uint8_t>();
    if (!addr_size || !seg_size) {
      return Result<void>::Fail("DWARF5 line header truncated");
    }
  }

  std::uint64_t header_length = 0;
  if (dwarf64) {
    auto hl = r.read<std::uint64_t>();
    if (!hl) {
      return Result<void>::Fail(hl.error());
    }
    header_length = hl.value();
  } else {
    auto hl = r.read<std::uint32_t>();
    if (!hl) {
      return Result<void>::Fail(hl.error());
    }
    header_length = hl.value();
  }
  const std::size_t header_start = r.tell();
  (void)header_length;

  auto min_inst = r.read<std::uint8_t>();
  if (!min_inst) {
    return Result<void>::Fail(min_inst.error());
  }
  std::uint8_t max_ops = 1;
  if (version.value() >= 4) {
    auto mop = r.read<std::uint8_t>();
    if (!mop) {
      return Result<void>::Fail(mop.error());
    }
    max_ops = mop.value() == 0 ? 1 : mop.value();
  }
  auto default_is_stmt = r.read<std::uint8_t>();
  auto line_base_b = r.read<std::int8_t>();
  auto line_range = r.read<std::uint8_t>();
  auto opcode_base = r.read<std::uint8_t>();
  if (!default_is_stmt || !line_base_b || !line_range || !opcode_base) {
    return Result<void>::Fail("Line header fields truncated");
  }
  const std::int8_t line_base = line_base_b.value();
  const std::uint8_t line_range_v =
      line_range.value() == 0 ? 1 : line_range.value();
  const std::uint8_t opcode_base_v =
      opcode_base.value() == 0 ? 1 : opcode_base.value();
  const std::uint8_t min_inst_v =
      min_inst.value() == 0 ? 1 : min_inst.value();

  for (std::uint8_t i = 1; i < opcode_base_v; ++i) {
    auto skip = r.read<std::uint8_t>();
    if (!skip) {
      return Result<void>::Fail(skip.error());
    }
  }

  auto read_cstring_adv = [&](std::string& out) -> Result<void> {
    out.clear();
    constexpr std::size_t kMax = 1024;
    for (std::size_t i = 0; i < kMax; ++i) {
      auto b = r.read<std::uint8_t>();
      if (!b) {
        return Result<void>::Fail(b.error());
      }
      if (b.value() == 0) {
        return Result<void>::Ok();
      }
      out.push_back(static_cast<char>(b.value()));
    }
    return Result<void>::Fail("C string too long in debug_line");
  };

  std::vector<std::string> include_dirs;
  include_dirs.reserve(16);
  if (version.value() < 5) {
    for (std::size_t i = 0; i < kMaxDirs; ++i) {
      std::string dir;
      auto ok = read_cstring_adv(dir);
      if (!ok) {
        return ok;
      }
      if (dir.empty()) {
        break;
      }
      include_dirs.push_back(std::move(dir));
    }
  }

  std::vector<std::string> files;
  files.reserve(32);
  if (version.value() < 5) {
    for (std::size_t i = 0; i < kMaxFiles; ++i) {
      std::string name;
      auto ok = read_cstring_adv(name);
      if (!ok) {
        return ok;
      }
      if (name.empty()) {
        break;
      }
      auto dir_idx = read_uleb(r);
      auto mod = read_uleb(r);
      auto len = read_uleb(r);
      if (!dir_idx || !mod || !len) {
        return Result<void>::Fail("File entry truncated");
      }
      std::string full = name;
      if (dir_idx.value() >= 1 && dir_idx.value() <= include_dirs.size()) {
        full = include_dirs[static_cast<std::size_t>(dir_idx.value() - 1)] +
               "/" + name;
      }
      files.push_back(std::move(full));
      image.source_files.push_back(files.back());
    }
  } else {
    // DWARF5: skip directory/file entry formats; still try to run opcodes
    // if header_length points past tables. Best-effort: jump to program.
    r.seek(header_start + static_cast<std::size_t>(header_length));
  }

  if (version.value() < 5) {
    // Standard: program starts after header tables; header_length from
    // after header_length field covers remaining header.
    const std::size_t program_off =
        header_start + static_cast<std::size_t>(header_length);
    if (program_off > unit.size()) {
      return Result<void>::Fail("Line program offset past unit");
    }
    r.seek(program_off);
  }

  LineMachine m;
  m.is_stmt = default_is_stmt.value() != 0;
  const std::size_t end = header_after_len + static_cast<std::size_t>(length);

  for (std::size_t op_i = 0; op_i < kMaxOps && r.tell() < end; ++op_i) {
    assert(op_i < kMaxOps);
    auto op = r.read<std::uint8_t>();
    if (!op) {
      return Result<void>::Fail(op.error());
    }
    const std::uint8_t opcode = op.value();
    if (opcode == 0) {
      auto plen = read_uleb(r);
      if (!plen) {
        return Result<void>::Fail(plen.error());
      }
      auto ext = r.read<std::uint8_t>();
      if (!ext) {
        return Result<void>::Fail(ext.error());
      }
      if (ext.value() == 1) {  // end_sequence
        m.end_sequence = true;
        emit_row(m, files, image);
        m = LineMachine{};
        m.is_stmt = default_is_stmt.value() != 0;
      } else if (ext.value() == 2) {  // set_address
        if (plen.value() >= 9) {
          auto addr = r.read<std::uint64_t>();
          if (!addr) {
            return Result<void>::Fail(addr.error());
          }
          m.address = addr.value();
        } else if (plen.value() >= 5) {
          auto addr = r.read<std::uint32_t>();
          if (!addr) {
            return Result<void>::Fail(addr.error());
          }
          m.address = addr.value();
        }
      } else {
        // Skip remaining payload bytes of this extended op.
        const std::uint64_t skip =
            plen.value() > 1 ? plen.value() - 1 : 0;
        for (std::uint64_t s = 0; s < skip && s < 4096; ++s) {
          auto b = r.read<std::uint8_t>();
          if (!b) {
            return Result<void>::Fail(b.error());
          }
        }
      }
    } else if (opcode < opcode_base_v) {
      switch (opcode) {
        case 1:  // copy
          emit_row(m, files, image);
          m.basic_block = false;
          m.prologue_end = false;
          m.epilogue_begin = false;
          break;
        case 2: {  // advance_pc
          auto op_adv = read_uleb(r);
          if (!op_adv) {
            return Result<void>::Fail(op_adv.error());
          }
          m.address += op_adv.value() * min_inst_v;
          (void)max_ops;
          break;
        }
        case 3: {  // advance_line
          auto adv = read_sleb(r);
          if (!adv) {
            return Result<void>::Fail(adv.error());
          }
          m.line = static_cast<std::uint32_t>(
              static_cast<std::int64_t>(m.line) + adv.value());
          break;
        }
        case 4: {  // set_file
          auto f = read_uleb(r);
          if (!f) {
            return Result<void>::Fail(f.error());
          }
          m.file = static_cast<std::uint32_t>(f.value());
          break;
        }
        case 5: {  // set_column
          auto c = read_uleb(r);
          if (!c) {
            return Result<void>::Fail(c.error());
          }
          m.column = static_cast<std::uint32_t>(c.value());
          break;
        }
        case 6:  // negate_stmt
          m.is_stmt = !m.is_stmt;
          break;
        case 7:  // set_basic_block
          m.basic_block = true;
          break;
        case 8: {  // const_add_pc
          const std::uint8_t adjusted = 255 - opcode_base_v;
          m.address += (adjusted / line_range_v) * min_inst_v;
          break;
        }
        case 9: {  // fixed_advance_pc
          auto adv = r.read<std::uint16_t>();
          if (!adv) {
            return Result<void>::Fail(adv.error());
          }
          m.address += adv.value();
          break;
        }
        default: {
          // Skip standard opcode operands using opcode_lengths — already
          // consumed lengths array; unknown: stop unit safely.
          return Result<void>::Ok();
        }
      }
    } else {
      const std::uint8_t adjusted = opcode - opcode_base_v;
      const std::uint8_t addr_adv = adjusted / line_range_v;
      const std::int8_t line_adv =
          static_cast<std::int8_t>(line_base + (adjusted % line_range_v));
      m.address += static_cast<std::uint64_t>(addr_adv) * min_inst_v;
      m.line = static_cast<std::uint32_t>(
          static_cast<std::int32_t>(m.line) + line_adv);
      emit_row(m, files, image);
      m.basic_block = false;
      m.prologue_end = false;
      m.epilogue_begin = false;
    }
  }
  return Result<void>::Ok();
}

}  // namespace

Result<void> parse_dwarf_debug_line(std::span<const std::byte> section,
                                    BinaryImage& image) {
  if (section.empty()) {
    return Result<void>::Ok();
  }
  std::size_t off = 0;
  for (std::size_t u = 0; u < kMaxUnits && off + 4 <= section.size(); ++u) {
    ByteReader peek(section.subspan(off));
    auto len32 = peek.read<std::uint32_t>();
    if (!len32) {
      return Result<void>::Fail(len32.error());
    }
    std::size_t unit_size = 4;
    std::uint64_t length = len32.value();
    if (len32.value() == 0xffffffffu) {
      auto len64 = peek.read<std::uint64_t>();
      if (!len64) {
        return Result<void>::Fail(len64.error());
      }
      length = len64.value();
      unit_size = 12;
    }
    if (length == 0) {
      break;
    }
    if (off + unit_size + static_cast<std::size_t>(length) > section.size()) {
      return Result<void>::Fail("debug_line unit exceeds section");
    }
    auto unit = section.subspan(off, unit_size + static_cast<std::size_t>(length));
    auto parsed = parse_one_unit(unit, image);
    if (!parsed) {
      // Soft-fail one bad unit; keep prior lines.
      break;
    }
    off += unit_size + static_cast<std::size_t>(length);
  }
  return Result<void>::Ok();
}

}  // namespace symcheck
