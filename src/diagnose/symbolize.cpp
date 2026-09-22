#include "symcheck/diagnose/symbolize.hpp"

#include "symcheck/demangle/msvc_demangle.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>

#if defined(SYMCHECK_WINDOWS)
#  define WIN32_LEAN_AND_MEAN
#  include <Windows.h>
#  include <DbgHelp.h>
#endif

namespace symcheck {
namespace {

constexpr std::size_t kMaxFrames = 10'000;
constexpr std::size_t kMaxLines = 500'000;

bool parse_hex_u64(const std::string& tok, std::uint64_t& out) {
  std::string s = tok;
  if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
    s = s.substr(2);
  }
  if (s.empty()) {
    return false;
  }
  std::uint64_t v = 0;
  constexpr std::size_t kMaxDigits = 16;
  if (s.size() > kMaxDigits) {
    return false;
  }
  for (char ch : s) {
    v <<= 4;
    if (ch >= '0' && ch <= '9') {
      v |= static_cast<std::uint64_t>(ch - '0');
    } else if (ch >= 'a' && ch <= 'f') {
      v |= static_cast<std::uint64_t>(10 + ch - 'a');
    } else if (ch >= 'A' && ch <= 'F') {
      v |= static_cast<std::uint64_t>(10 + ch - 'A');
    } else {
      return false;
    }
  }
  out = v;
  return true;
}

const LineEntry* nearest_line(const BinaryImage& image, std::uint64_t addr) {
  const LineEntry* best = nullptr;
  const std::size_t n =
      image.lines.size() < kMaxLines ? image.lines.size() : kMaxLines;
  for (std::size_t i = 0; i < n; ++i) {
    if (image.lines[i].address <= addr) {
      if (best == nullptr || image.lines[i].address >= best->address) {
        best = &image.lines[i];
      }
    }
  }
  return best;
}

SymbolizeFrame resolve_from_exports(const BinaryImage& image,
                                    std::uint64_t addr) {
  SymbolizeFrame frame;
  frame.address = addr;
  frame.module = image.path;
  std::uint64_t rva = addr;
  if (image.image_base != 0 && addr >= image.image_base) {
    rva = addr - image.image_base;
  }
  const ExportEntry* best = nullptr;
  for (const auto& e : image.exports) {
    if (e.rva <= rva) {
      if (best == nullptr || e.rva >= best->rva) {
        best = &e;
      }
    }
  }
  if (best != nullptr) {
    frame.symbol = best->name;
    frame.demangled = demangle_msvc(best->name);
    frame.resolved = true;
  }
  if (const LineEntry* line = nearest_line(image, rva)) {
    frame.file = line->file;
    frame.line = line->line;
    if (!frame.resolved) {
      frame.resolved = true;
    }
  }
  return frame;
}

#if defined(SYMCHECK_WINDOWS)
SymbolizeFrame resolve_dbghelp(const BinaryImage& image, std::uint64_t addr) {
  SymbolizeFrame frame = resolve_from_exports(image, addr);
  if (image.pdb_path.empty() && image.format != BinaryFormat::Pdb) {
    return frame;
  }
  HANDLE proc = GetCurrentProcess();
  SymSetOptions(SYMOPT_UNDNAME | SYMOPT_LOAD_LINES | SYMOPT_DEFERRED_LOADS);
  if (!SymInitialize(proc, nullptr, FALSE)) {
    return frame;
  }
  const char* mod_path =
      image.format == BinaryFormat::Pdb ? image.path.c_str()
                                        : (image.pdb_path.empty()
                                               ? image.path.c_str()
                                               : image.pdb_path.c_str());
  const DWORD64 base = SymLoadModuleEx(proc, nullptr, mod_path, nullptr,
                                       image.image_base != 0 ? image.image_base
                                                             : 0x10000000,
                                       0, nullptr, 0);
  if (base == 0) {
    SymCleanup(proc);
    return frame;
  }
  char buffer[sizeof(SYMBOL_INFO) + 512]{};
  auto* info = reinterpret_cast<SYMBOL_INFO*>(buffer);
  info->SizeOfStruct = sizeof(SYMBOL_INFO);
  info->MaxNameLen = 511;
  DWORD64 displacement = 0;
  const DWORD64 query =
      image.image_base != 0 ? addr : (base + (addr & 0xffffffffull));
  if (SymFromAddr(proc, query, &displacement, info)) {
    frame.symbol.assign(info->Name, info->NameLen);
    frame.demangled = demangle_msvc(frame.symbol);
    frame.resolved = true;
  }
  IMAGEHLP_LINE64 line{};
  line.SizeOfStruct = sizeof(line);
  DWORD line_disp = 0;
  if (SymGetLineFromAddr64(proc, query, &line_disp, &line)) {
    frame.file = line.FileName ? line.FileName : "";
    frame.line = line.LineNumber;
    frame.resolved = true;
  }
  SymUnloadModule64(proc, base);
  SymCleanup(proc);
  return frame;
}
#endif

}  // namespace

Result<std::vector<std::uint64_t>> parse_address_list(
    const std::vector<std::string>& tokens) {
  std::vector<std::uint64_t> out;
  out.reserve(tokens.size());
  constexpr std::size_t kMax = kMaxFrames;
  const std::size_t n = tokens.size() < kMax ? tokens.size() : kMax;
  for (std::size_t i = 0; i < n; ++i) {
    std::uint64_t v = 0;
    if (!parse_hex_u64(tokens[i], v)) {
      return Result<std::vector<std::uint64_t>>::Fail("Bad address: " +
                                                      tokens[i]);
    }
    out.push_back(v);
  }
  return Result<std::vector<std::uint64_t>>::Ok(std::move(out));
}

Result<std::vector<std::uint64_t>> parse_addresses_from_text(
    const std::string& text) {
  std::vector<std::uint64_t> out;
  std::string tok;
  constexpr std::size_t kMaxChars = 2'000'000;
  const std::size_t n = text.size() < kMaxChars ? text.size() : kMaxChars;
  for (std::size_t i = 0; i < n; ++i) {
    const char ch = text[i];
    const bool hexish =
        (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') ||
        (ch >= 'A' && ch <= 'F') || ch == 'x' || ch == 'X';
    if (hexish) {
      tok.push_back(ch);
      if (tok.size() > 18) {
        tok.clear();
      }
      continue;
    }
    if (!tok.empty()) {
      std::uint64_t v = 0;
      if (parse_hex_u64(tok, v) && out.size() < kMaxFrames) {
        out.push_back(v);
      }
      tok.clear();
    }
  }
  if (!tok.empty()) {
    std::uint64_t v = 0;
    if (parse_hex_u64(tok, v) && out.size() < kMaxFrames) {
      out.push_back(v);
    }
  }
  return Result<std::vector<std::uint64_t>>::Ok(std::move(out));
}

SymbolizeReport symbolize_addresses(const BinaryImage& image,
                                    const std::vector<std::uint64_t>& addresses) {
  SymbolizeReport report;
  report.module_path = image.path;
  const std::size_t n =
      addresses.size() < kMaxFrames ? addresses.size() : kMaxFrames;
  report.frames.reserve(n);
  for (std::size_t i = 0; i < n; ++i) {
#if defined(SYMCHECK_WINDOWS)
    report.frames.push_back(resolve_dbghelp(image, addresses[i]));
#else
    report.frames.push_back(resolve_from_exports(image, addresses[i]));
#endif
  }
  return report;
}

}  // namespace symcheck
