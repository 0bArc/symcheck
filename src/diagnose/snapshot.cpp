#include "symcheck/diagnose/snapshot.hpp"

#include "symcheck/util/json_escape.hpp"
#include "symcheck/util/mapped_file.hpp"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <map>
#include <sstream>

namespace symcheck {
namespace {

std::string trim(std::string s) {
  while (!s.empty() && (s.back() == '\r' || s.back() == '\n' || s.back() == ' ')) {
    s.pop_back();
  }
  return s;
}

// Minimal field extractor: "key":"value" or "key":123
bool extract_string_field(const std::string& json, const std::string& key,
                          std::string& out) {
  const std::string needle = "\"" + key + "\":\"";
  const auto pos = json.find(needle);
  if (pos == std::string::npos) {
    return false;
  }
  std::size_t i = pos + needle.size();
  out.clear();
  constexpr std::size_t kMax = 4096;
  for (std::size_t n = 0; n < kMax && i < json.size(); ++n, ++i) {
    if (json[i] == '"') {
      return true;
    }
    if (json[i] == '\\' && i + 1 < json.size()) {
      ++i;
      out.push_back(json[i]);
      continue;
    }
    out.push_back(json[i]);
  }
  return false;
}

bool extract_u64_field(const std::string& json, const std::string& key,
                       std::uint64_t& out) {
  const std::string needle = "\"" + key + "\":";
  const auto pos = json.find(needle);
  if (pos == std::string::npos) {
    return false;
  }
  std::size_t i = pos + needle.size();
  while (i < json.size() && (json[i] == ' ' || json[i] == '\t')) {
    ++i;
  }
  std::uint64_t v = 0;
  bool any = false;
  constexpr std::size_t kMaxDigits = 20;
  for (std::size_t n = 0; n < kMaxDigits && i < json.size(); ++n, ++i) {
    if (json[i] < '0' || json[i] > '9') {
      break;
    }
    any = true;
    v = v * 10 + static_cast<std::uint64_t>(json[i] - '0');
  }
  if (!any) {
    return false;
  }
  out = v;
  return true;
}

}  // namespace

Snapshot build_snapshot(const std::vector<BinaryImage>& images) {
  Snapshot snap;
  snap.entries.reserve(images.size());
  for (const auto& image : images) {
    const AbiFingerprint fp = fingerprint_abi(image);
    SnapshotEntry e;
    e.path = image.path;
    e.format = to_string(image.format);
    e.arch = to_string(image.architecture);
    e.crt = to_string(fp.crt);
    e.hash = fp.hash;
    e.defined_count = fp.defined_count;
    e.export_count = fp.export_count;
    e.exports = fp.export_names;
    snap.entries.push_back(std::move(e));
  }
  std::sort(snap.entries.begin(), snap.entries.end(),
            [](const SnapshotEntry& a, const SnapshotEntry& b) {
              return a.path < b.path;
            });
  return snap;
}

Result<void> write_snapshot(const Snapshot& snap, const std::string& path) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    return Result<void>::Fail("Cannot write snapshot: " + path);
  }
  out << "{\"version\":\"" << json_escape(snap.version) << "\",\"entries\":[";
  for (std::size_t i = 0; i < snap.entries.size(); ++i) {
    const auto& e = snap.entries[i];
    if (i > 0) {
      out << ',';
    }
    out << "{\"path\":\"" << json_escape(e.path) << "\","
        << "\"format\":\"" << json_escape(e.format) << "\","
        << "\"arch\":\"" << json_escape(e.arch) << "\","
        << "\"crt\":\"" << json_escape(e.crt) << "\","
        << "\"hash\":" << e.hash << ","
        << "\"defined\":" << e.defined_count << ","
        << "\"exports\":" << e.export_count << ","
        << "\"export_names\":[";
    for (std::size_t j = 0; j < e.exports.size(); ++j) {
      if (j > 0) {
        out << ',';
      }
      out << '"' << json_escape(e.exports[j]) << '"';
    }
    out << "]}";
  }
  out << "]}\n";
  if (!out) {
    return Result<void>::Fail("Write failed: " + path);
  }
  return Result<void>::Ok();
}

Result<Snapshot> read_snapshot(const std::string& path) {
  auto mapped = MappedFile::open(path);
  if (!mapped) {
    // Fallback text read for tiny files
    std::ifstream in(path, std::ios::binary);
    if (!in) {
      return Result<Snapshot>::Fail("Cannot read snapshot: " + path);
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    const std::string text = ss.str();
    Snapshot snap;
    (void)extract_string_field(text, "version", snap.version);
    std::size_t pos = 0;
    constexpr std::size_t kMaxEntries = 50'000;
    for (std::size_t n = 0; n < kMaxEntries; ++n) {
      const auto obj = text.find("{\"path\":", pos);
      if (obj == std::string::npos) {
        break;
      }
      const auto end = text.find("}", obj + 1);
      if (end == std::string::npos) {
        break;
      }
      const std::string chunk = text.substr(obj, end - obj + 1);
      SnapshotEntry e;
      if (!extract_string_field(chunk, "path", e.path)) {
        pos = obj + 8;
        continue;
      }
      extract_string_field(chunk, "format", e.format);
      extract_string_field(chunk, "arch", e.arch);
      extract_string_field(chunk, "crt", e.crt);
      extract_u64_field(chunk, "hash", e.hash);
      std::uint64_t tmp = 0;
      if (extract_u64_field(chunk, "defined", tmp)) {
        e.defined_count = static_cast<std::size_t>(tmp);
      }
      if (extract_u64_field(chunk, "exports", tmp)) {
        e.export_count = static_cast<std::size_t>(tmp);
      }
      snap.entries.push_back(std::move(e));
      pos = end + 1;
    }
    return Result<Snapshot>::Ok(std::move(snap));
  }

  const auto bytes = mapped.value().bytes();
  std::string text(reinterpret_cast<const char*>(bytes.data()), bytes.size());
  text = trim(text);
  Snapshot snap;
  (void)extract_string_field(text, "version", snap.version);
  std::size_t pos = 0;
  constexpr std::size_t kMaxEntries = 50'000;
  for (std::size_t n = 0; n < kMaxEntries; ++n) {
    const auto obj = text.find("{\"path\":", pos);
    if (obj == std::string::npos) {
      break;
    }
    const auto end = text.find("}", obj + 1);
    if (end == std::string::npos) {
      break;
    }
    const std::string chunk = text.substr(obj, end - obj + 1);
    SnapshotEntry e;
    if (!extract_string_field(chunk, "path", e.path)) {
      pos = obj + 8;
      continue;
    }
    extract_string_field(chunk, "format", e.format);
    extract_string_field(chunk, "arch", e.arch);
    extract_string_field(chunk, "crt", e.crt);
    extract_u64_field(chunk, "hash", e.hash);
    std::uint64_t tmp = 0;
    if (extract_u64_field(chunk, "defined", tmp)) {
      e.defined_count = static_cast<std::size_t>(tmp);
    }
    if (extract_u64_field(chunk, "exports", tmp)) {
      e.export_count = static_cast<std::size_t>(tmp);
    }
    snap.entries.push_back(std::move(e));
    pos = end + 1;
  }
  return Result<Snapshot>::Ok(std::move(snap));
}

SnapshotDiff diff_snapshots(const Snapshot& a, const Snapshot& b) {
  SnapshotDiff d;
  std::map<std::string, const SnapshotEntry*> left;
  std::map<std::string, const SnapshotEntry*> right;
  for (const auto& e : a.entries) {
    left[e.path] = &e;
  }
  for (const auto& e : b.entries) {
    right[e.path] = &e;
  }
  for (const auto& kv : left) {
    auto it = right.find(kv.first);
    if (it == right.end()) {
      d.removed.push_back(kv.first);
    } else if (kv.second->hash != it->second->hash) {
      d.changed.push_back(kv.first);
    }
  }
  for (const auto& kv : right) {
    if (left.find(kv.first) == left.end()) {
      d.added.push_back(kv.first);
    }
  }
  return d;
}

}  // namespace symcheck
