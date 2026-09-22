#include "symcheck/ir/cache.hpp"

#include "symcheck/util/mapped_file.hpp"

namespace symcheck {

Result<BinaryImage> BinaryCache::get_or_load(
    const std::string& path, Result<BinaryImage> (*loader)(const std::string&)) {
  if (loader == nullptr) {
    return Result<BinaryImage>::Fail("BinaryCache loader is null");
  }

  auto mapped = MappedFile::open(path);
  if (!mapped) {
    return Result<BinaryImage>::Fail(mapped.error());
  }

  const auto it = entries_.find(path);
  if (it != entries_.end()) {
    if (it->second.size == mapped.value().size() &&
        it->second.mtime == mapped.value().mtime()) {
      return Result<BinaryImage>::Ok(it->second.image);
    }
  }

  auto loaded = loader(path);
  if (!loaded) {
    return loaded;
  }

  Entry entry;
  entry.size = mapped.value().size();
  entry.mtime = mapped.value().mtime();
  entry.image = loaded.value();
  entries_[path] = std::move(entry);
  return Result<BinaryImage>::Ok(entries_[path].image);
}

void BinaryCache::clear() { entries_.clear(); }

}  // namespace symcheck
