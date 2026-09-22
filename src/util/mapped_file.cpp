#include "symcheck/util/mapped_file.hpp"

#if defined(SYMCHECK_WINDOWS)
#  define WIN32_LEAN_AND_MEAN
#  include <Windows.h>
#endif

#include <utility>

namespace symcheck {

MappedFile::~MappedFile() { close(); }

MappedFile::MappedFile(MappedFile&& other) noexcept
    : path_(std::move(other.path_)),
      size_(other.size_),
      mtime_(other.mtime_),
      file_handle_(other.file_handle_),
      map_handle_(other.map_handle_),
      view_(other.view_) {
  other.size_ = 0;
  other.mtime_ = 0;
  other.file_handle_ = nullptr;
  other.map_handle_ = nullptr;
  other.view_ = nullptr;
}

MappedFile& MappedFile::operator=(MappedFile&& other) noexcept {
  if (this == &other) {
    return *this;
  }
  close();
  path_ = std::move(other.path_);
  size_ = other.size_;
  mtime_ = other.mtime_;
  file_handle_ = other.file_handle_;
  map_handle_ = other.map_handle_;
  view_ = other.view_;
  other.size_ = 0;
  other.mtime_ = 0;
  other.file_handle_ = nullptr;
  other.map_handle_ = nullptr;
  other.view_ = nullptr;
  return *this;
}

void MappedFile::close() {
#if defined(SYMCHECK_WINDOWS)
  if (view_ != nullptr) {
    UnmapViewOfFile(view_);
    view_ = nullptr;
  }
  if (map_handle_ != nullptr) {
    CloseHandle(static_cast<HANDLE>(map_handle_));
    map_handle_ = nullptr;
  }
  if (file_handle_ != nullptr) {
    CloseHandle(static_cast<HANDLE>(file_handle_));
    file_handle_ = nullptr;
  }
#endif
  size_ = 0;
  mtime_ = 0;
}

Result<MappedFile> MappedFile::open(const std::string& path) {
#if !defined(SYMCHECK_WINDOWS)
  return Result<MappedFile>::Fail("MappedFile requires Windows in MVP");
#else
  MappedFile file;
  file.path_ = path;

  const HANDLE hfile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                                   nullptr);
  if (hfile == INVALID_HANDLE_VALUE) {
    return Result<MappedFile>::Fail("Cannot open file: " + path);
  }
  file.file_handle_ = hfile;

  LARGE_INTEGER size_li{};
  if (GetFileSizeEx(hfile, &size_li) == 0) {
    file.close();
    return Result<MappedFile>::Fail("Cannot get file size: " + path);
  }
  if (size_li.QuadPart < 0) {
    file.close();
    return Result<MappedFile>::Fail("Negative file size: " + path);
  }
  file.size_ = static_cast<std::uint64_t>(size_li.QuadPart);

  FILETIME ft{};
  if (GetFileTime(hfile, nullptr, nullptr, &ft) != 0) {
    ULARGE_INTEGER uli{};
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    file.mtime_ = uli.QuadPart;
  }

  if (file.size_ == 0) {
    return Result<MappedFile>::Ok(std::move(file));
  }

  const HANDLE hmap =
      CreateFileMappingA(hfile, nullptr, PAGE_READONLY, 0, 0, nullptr);
  if (hmap == nullptr) {
    file.close();
    return Result<MappedFile>::Fail("Cannot map file: " + path);
  }
  file.map_handle_ = hmap;

  void* view = MapViewOfFile(hmap, FILE_MAP_READ, 0, 0, 0);
  if (view == nullptr) {
    file.close();
    return Result<MappedFile>::Fail("Cannot map view: " + path);
  }
  file.view_ = view;
  return Result<MappedFile>::Ok(std::move(file));
#endif
}

std::span<const std::byte> MappedFile::bytes() const {
  if (view_ == nullptr || size_ == 0) {
    return {};
  }
  return std::span<const std::byte>(static_cast<const std::byte*>(view_),
                                    static_cast<std::size_t>(size_));
}

}  // namespace symcheck
