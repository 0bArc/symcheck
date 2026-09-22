@echo off
cd /d "%~dp0"
if not exist out\calc.lib call build.bat
echo ===== WHY DIV =====
call .\symcheck.bat why "calc::div(double,double)" --root out
echo.
echo ===== WHY POWER =====
call .\symcheck.bat why "calc::power(int,int)" --root out
echo.
echo ===== FIND ADD =====
call .\symcheck.bat find "calc::add" --root out
echo.
echo ===== EXPLAIN =====
call .\symcheck.bat explain out\link.log --root out
echo.
echo ===== SECURITY =====
call .\symcheck.bat security ..\..\build\symcheck.exe --json
echo.
echo ===== SYMBOLIZE =====
call .\symcheck.bat symbolize ..\..\build\symcheck.exe 0x140001000 --json
echo.
echo ===== CI =====
call .\symcheck.bat ci --root out --json
echo ALL_OK
