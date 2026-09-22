#include "calc.hpp"

namespace calc {

// Junior mistake: implemented with ints, header promised doubles.
double div(int a, int b) {
  if (b == 0) {
    return 0.0;
  }
  return static_cast<double>(a) / static_cast<double>(b);
}

}  // namespace calc
