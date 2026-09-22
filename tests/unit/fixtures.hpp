#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace symcheck::test {

inline void append_u16(std::vector<std::byte>& out, std::uint16_t v) {
  out.push_back(static_cast<std::byte>(v & 0xff));
  out.push_back(static_cast<std::byte>((v >> 8) & 0xff));
}

inline void append_u32(std::vector<std::byte>& out, std::uint32_t v) {
  out.push_back(static_cast<std::byte>(v & 0xff));
  out.push_back(static_cast<std::byte>((v >> 8) & 0xff));
  out.push_back(static_cast<std::byte>((v >> 16) & 0xff));
  out.push_back(static_cast<std::byte>((v >> 24) & 0xff));
}

inline void append_i16(std::vector<std::byte>& out, std::int16_t v) {
  append_u16(out, static_cast<std::uint16_t>(v));
}

inline void append_bytes(std::vector<std::byte>& out, const char* s,
                         std::size_t n) {
  for (std::size_t i = 0; i < n; ++i) {
    out.push_back(static_cast<std::byte>(s[i]));
  }
}

// Minimal x64 COFF object with one external defined symbol.
inline std::vector<std::byte> make_coff_obj(const char* symbol_name,
                                            bool defined = true) {
  std::vector<std::byte> out;
  out.reserve(128);

  // IMAGE_FILE_HEADER
  append_u16(out, 0x8664);  // machine
  append_u16(out, 0);       // sections
  append_u32(out, 0);       // timestamp
  append_u32(out, 20);      // pointer to symbol table
  append_u32(out, 1);       // number of symbols
  append_u16(out, 0);       // optional header size
  append_u16(out, 0);       // characteristics

  // Symbol
  char name[8] = {};
  const std::string sym = symbol_name;
  const std::size_t copy = sym.size() < 8 ? sym.size() : 8;
  for (std::size_t i = 0; i < copy; ++i) {
    name[i] = sym[i];
  }
  append_bytes(out, name, 8);
  append_u32(out, 0);  // value
  append_i16(out, defined ? static_cast<std::int16_t>(1)
                          : static_cast<std::int16_t>(0));
  append_u16(out, 0x20);  // function type
  out.push_back(static_cast<std::byte>(2));  // external
  out.push_back(static_cast<std::byte>(0));  // aux

  // String table size only
  append_u32(out, 4);
  return out;
}

inline std::vector<std::byte> make_archive_with_obj(
    const std::vector<std::byte>& obj, const char* member_name) {
  std::vector<std::byte> out;
  const char mag[] = "!<arch>\n";
  append_bytes(out, mag, 8);

  char hdr[60];
  for (int i = 0; i < 60; ++i) {
    hdr[i] = ' ';
  }
  const std::string name = std::string(member_name) + "/";
  for (std::size_t i = 0; i < name.size() && i < 16; ++i) {
    hdr[i] = name[i];
  }
  // date, uid, gid, mode left as spaces
  const std::string size = std::to_string(obj.size());
  for (std::size_t i = 0; i < size.size() && i < 10; ++i) {
    hdr[48 + i] = size[i];
  }
  hdr[58] = '`';
  hdr[59] = '\n';
  append_bytes(out, hdr, 60);
  out.insert(out.end(), obj.begin(), obj.end());
  return out;
}

inline std::vector<std::byte> make_minimal_pe(bool as_dll) {
  std::vector<std::byte> out(512, std::byte{0});

  // DOS header
  out[0] = std::byte{0x4d};
  out[1] = std::byte{0x5a};
  const std::uint32_t lfanew = 128;
  out[60] = static_cast<std::byte>(lfanew & 0xff);
  out[61] = static_cast<std::byte>((lfanew >> 8) & 0xff);

  // PE signature
  out[lfanew + 0] = std::byte{'P'};
  out[lfanew + 1] = std::byte{'E'};
  out[lfanew + 2] = std::byte{0};
  out[lfanew + 3] = std::byte{0};

  const std::size_t fh = lfanew + 4;
  // File header: machine x64
  out[fh + 0] = std::byte{0x64};
  out[fh + 1] = std::byte{0x86};
  out[fh + 2] = std::byte{1};  // one section
  out[fh + 3] = std::byte{0};
  // SizeOfOptionalHeader = 240 (PE32+)
  out[fh + 16] = std::byte{240};
  out[fh + 17] = std::byte{0};
  // Characteristics
  const std::uint16_t chars = as_dll ? 0x2002 : 0x0022;
  out[fh + 18] = static_cast<std::byte>(chars & 0xff);
  out[fh + 19] = static_cast<std::byte>((chars >> 8) & 0xff);

  const std::size_t opt = fh + 20;
  // PE32+ magic
  out[opt + 0] = std::byte{0x0b};
  out[opt + 1] = std::byte{0x02};
  // NumberOfRvaAndSizes at offset 108 from optional start for PE32+
  // Data directories at optional+112
  // Leave export/import RVA zero

  // Section header after optional
  const std::size_t sec = opt + 240;
  const char secname[] = ".text\0\0\0";
  for (int i = 0; i < 8; ++i) {
    out[sec + static_cast<std::size_t>(i)] =
        static_cast<std::byte>(secname[i]);
  }
  // VirtualSize / VA / SizeOfRawData / PointerToRawData
  out[sec + 8] = std::byte{0x10};
  out[sec + 12] = std::byte{0x00};
  out[sec + 13] = std::byte{0x10};  // VA 0x1000
  out[sec + 16] = std::byte{0x10};
  out[sec + 20] = std::byte{0x00};
  out[sec + 21] = std::byte{0x02};  // raw ptr 0x200

  return out;
}

}  // namespace symcheck::test
