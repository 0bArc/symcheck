#include "symcheck/lib/archive.hpp"

#include "symcheck/coff/coff_parser.hpp"
#include "symcheck/util/byte_reader.hpp"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <string_view>

namespace symcheck {
namespace {

constexpr char kArmag[] = "!<arch>\n";
constexpr std::size_t kArmagLen = 8;
constexpr std::size_t kHeaderSize = 60;
constexpr std::size_t kMaxMembers = 100'000;

struct ArchiveMember {
  std::string name;
  std::size_t offset = 0;
  std::size_t size = 0;
};

std::string trim_spaces(std::string s) {
  while (!s.empty() && (s.back() == ' ' || s.back() == '\n' || s.back() == '\r' ||
                        s.back() == '`')) {
    s.pop_back();
  }
  return s;
}

Result<std::uint64_t> parse_decimal(std::string_view text) {
  std::uint64_t value = 0;
  bool any = false;
  constexpr std::size_t kMaxDigits = 20;
  const std::size_t n = text.size() < kMaxDigits ? text.size() : kMaxDigits;
  for (std::size_t i = 0; i < n; ++i) {
    const char ch = text[i];
    if (ch == ' ') {
      break;
    }
    if (ch < '0' || ch > '9') {
      return Result<std::uint64_t>::Fail("Invalid archive size field");
    }
    any = true;
    const std::uint64_t digit = static_cast<std::uint64_t>(ch - '0');
    if (value > (UINT64_MAX - digit) / 10) {
      return Result<std::uint64_t>::Fail("Archive size overflow");
    }
    value = value * 10 + digit;
  }
  if (!any) {
    return Result<std::uint64_t>::Fail("Empty archive size field");
  }
  return Result<std::uint64_t>::Ok(value);
}

Result<ArchiveMember> read_member_header(std::span<const std::byte> data,
                                         std::size_t offset) {
  if (offset + kHeaderSize > data.size()) {
    return Result<ArchiveMember>::Fail("Archive member header truncated");
  }
  const auto hdr = data.subspan(offset, kHeaderSize);
  std::string name(reinterpret_cast<const char*>(hdr.data()), 16);
  name = trim_spaces(std::move(name));

  std::string size_field(reinterpret_cast<const char*>(hdr.data() + 48), 10);
  auto size_res = parse_decimal(size_field);
  if (!size_res) {
    return Result<ArchiveMember>::Fail(size_res.error());
  }

  if (static_cast<unsigned char>(hdr[58]) != 0x60 ||
      static_cast<unsigned char>(hdr[59]) != 0x0a) {
    return Result<ArchiveMember>::Fail("Archive member end marker missing");
  }

  ArchiveMember member;
  member.name = std::move(name);
  member.offset = offset + kHeaderSize;
  member.size = static_cast<std::size_t>(size_res.take_value());
  if (member.offset > data.size() || member.size > data.size() - member.offset) {
    return Result<ArchiveMember>::Fail("Archive member data truncated");
  }
  return Result<ArchiveMember>::Ok(std::move(member));
}

std::string resolve_longname(const std::string& name,
                             std::span<const std::byte> longnames) {
  if (name.empty() || name[0] != '/') {
    return name;
  }
  bool digits = true;
  for (std::size_t i = 1; i < name.size(); ++i) {
    if (name[i] < '0' || name[i] > '9') {
      digits = false;
      break;
    }
  }
  if (!digits || name.size() == 1) {
    return name;
  }
  std::size_t offset = 0;
  for (std::size_t i = 1; i < name.size(); ++i) {
    offset = offset * 10 + static_cast<std::size_t>(name[i] - '0');
  }
  if (offset >= longnames.size()) {
    return name;
  }
  ByteReader reader(longnames);
  auto s = reader.read_c_string(offset, 1024);
  if (!s) {
    return name;
  }
  return s.take_value();
}

}  // namespace

bool looks_like_archive(std::span<const std::byte> data) {
  if (data.size() < kArmagLen) {
    return false;
  }
  for (std::size_t i = 0; i < kArmagLen; ++i) {
    if (static_cast<char>(data[i]) != kArmag[i]) {
      return false;
    }
  }
  return true;
}

Result<BinaryImage> parse_coff_library(std::span<const std::byte> data,
                                       const std::string& path) {
  if (!looks_like_archive(data)) {
    return Result<BinaryImage>::Fail("Not a COFF library archive: " + path);
  }

  BinaryImage image;
  image.path = path;
  image.format = BinaryFormat::CoffLib;
  image.file_size = data.size();

  std::span<const std::byte> longnames;
  std::size_t offset = kArmagLen;
  std::size_t member_index = 0;

  while (offset + kHeaderSize <= data.size() && member_index < kMaxMembers) {
    if ((offset % 2) != 0) {
      ++offset;
      if (offset + kHeaderSize > data.size()) {
        break;
      }
    }

    auto member_res = read_member_header(data, offset);
    if (!member_res) {
      return Result<BinaryImage>::Fail(member_res.error());
    }
    ArchiveMember member = member_res.take_value();
    const std::size_t next = member.offset + member.size;
    if (next < member.offset) {
      return Result<BinaryImage>::Fail("Archive member size wrap");
    }

    const auto body = data.subspan(member.offset, member.size);

    if (member.name == "/" || member.name == "//") {
      if (member.name == "//") {
        longnames = body;
      }
      offset = next;
      ++member_index;
      continue;
    }

    std::string display = resolve_longname(member.name, longnames);
    if (!display.empty() && display.back() == '/') {
      display.pop_back();
    }

    if (body.size() >= 20) {
      auto obj = parse_coff_object(body, path, display);
      if (obj) {
        if (image.architecture == Architecture::Unknown) {
          image.architecture = obj.value().architecture;
        } else if (obj.value().architecture != Architecture::Unknown &&
                   obj.value().architecture != image.architecture) {
          return Result<BinaryImage>::Fail(
              "Mixed architectures inside library: " + path);
        }
        image.members.push_back(display);
        for (auto& sym : obj.value().symbols) {
          image.symbols.push_back(std::move(sym));
        }
      }
    }

    offset = next;
    ++member_index;
  }

  if (member_index >= kMaxMembers) {
    return Result<BinaryImage>::Fail("Archive member count exceeds bound");
  }

  std::sort(image.symbols.begin(), image.symbols.end(),
            [](const Symbol& a, const Symbol& b) {
              return a.mangled < b.mangled;
            });
  return Result<BinaryImage>::Ok(std::move(image));
}

}  // namespace symcheck
