# Calculator demo

Small C++ homework project used to exercise SymCheck. Link is broken on purpose.

## Bugs

1. Header declares `calc::div(double, double)`; `divide.cpp` defines `calc::div(int, int)`.
2. `calc::power` is declared and called; no `.cpp` defines it.

Until those are fixed, `app.exe` is not produced.

## Run

From the SymCheck repo root:

```bat
build.bat
cd tests\calculator
build.bat
diagnose.bat
```

Manual checks (PowerShell: prefix with `.\`):

```bat
symcheck.bat why "calc::div(double,double)" --root out
symcheck.bat why "calc::power(int,int)" --root out
symcheck.bat explain out\link.log --root out
```

Expected: `div` → `signature_mismatch`; `power` → `not_compiled`.

This is a demo under SymCheck. The project README is at the [repository root](../../README.md).
