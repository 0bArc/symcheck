#ifndef CALC_HPP
#define CALC_HPP

// Simple homework calculator helpers.
namespace calc {

int add(int a, int b);
int sub(int a, int b);
int mul(int a, int b);

// BUG: header says doubles, source defines ints.
double div(double a, double b);

// BUG: declared here, never implemented in any .cpp
int power(int base, int exp);

}  // namespace calc

#endif
