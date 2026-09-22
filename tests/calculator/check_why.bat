@echo off
cd /d "%~dp0"
if not exist out\calc.lib call build.bat
echo ===== default why =====
call .\symcheck.bat why "calc::div(double,double)" --root out
echo.
echo ===== verbose why =====
call .\symcheck.bat why "calc::div(double,double)" --root out --verbose
