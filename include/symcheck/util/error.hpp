#pragma once

#include <string>
#include <utility>

namespace symcheck {

class Error {
 public:
  Error() = default;
  explicit Error(std::string message) : message_(std::move(message)) {}

  [[nodiscard]] const std::string& message() const { return message_; }
  [[nodiscard]] bool empty() const { return message_.empty(); }

 private:
  std::string message_;
};

template <typename T>
class Result {
 public:
  static Result Ok(T value) {
    Result r;
    r.ok_ = true;
    r.value_ = std::move(value);
    return r;
  }

  static Result Fail(Error err) {
    Result r;
    r.ok_ = false;
    r.error_ = std::move(err);
    return r;
  }

  static Result Fail(std::string message) {
    return Fail(Error(std::move(message)));
  }

  [[nodiscard]] bool ok() const { return ok_; }
  [[nodiscard]] explicit operator bool() const { return ok_; }

  [[nodiscard]] T& value() { return value_; }
  [[nodiscard]] const T& value() const { return value_; }

  [[nodiscard]] const Error& error() const { return error_; }

  T take_value() { return std::move(value_); }

 private:
  bool ok_ = false;
  T value_{};
  Error error_{};
};

template <>
class Result<void> {
 public:
  static Result Ok() {
    Result r;
    r.ok_ = true;
    return r;
  }

  static Result Fail(Error err) {
    Result r;
    r.ok_ = false;
    r.error_ = std::move(err);
    return r;
  }

  static Result Fail(std::string message) {
    return Fail(Error(std::move(message)));
  }

  [[nodiscard]] bool ok() const { return ok_; }
  [[nodiscard]] explicit operator bool() const { return ok_; }
  [[nodiscard]] const Error& error() const { return error_; }

 private:
  bool ok_ = false;
  Error error_{};
};

}  // namespace symcheck
