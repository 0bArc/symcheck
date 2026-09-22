#include "calc.hpp"

#include <cstdio>

int main() {
  const int a = 10;
  const int b = 2;

  std::printf("add = %d\n", calc::add(a, b));
  std::printf("sub = %d\n", calc::sub(a, b));
  std::printf("mul = %d\n", calc::mul(a, b));
  std::printf("div = %f\n", calc::div(10.0, 2.0));
  std::printf("pow = %d\n", calc::power(2, 8));
  return 0;
}
