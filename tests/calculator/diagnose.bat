@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "REPO=%~dp0..\.."
set "SC=%REPO%\symcheck.bat"
set "OUT=%cd%\out"

if not exist "%REPO%\build\symcheck.exe" (
  echo Build SymCheck first from repo root:
  echo   build.bat
  exit /b 1
)
if not exist "%OUT%\calc.lib" (
  call build.bat || exit /b 1
)

echo.
echo ========== inspect library ==========
call "%SC%" inspect "%OUT%\calc.lib"

echo.
echo ========== why: wrong divide signature ==========
call "%SC%" why "calc::div(double,double)" --root "%OUT%"

echo.
echo ========== why: missing power ==========
call "%SC%" why "calc::power(int,int)" --root "%OUT%"

echo.
echo ========== explain linker log ==========
call "%SC%" explain "%OUT%\link.log" --root "%OUT%"

echo.
echo ========== find add ==========
call "%SC%" find "calc::add" --root "%OUT%"

echo.
echo ========== security (tool binary; no app.exe until link fixed) ==========
call "%SC%" security "%REPO%\build\symcheck.exe"

echo.
echo Note: app.exe does not exist yet. Fix div/power, rebuild, then:
echo   symcheck.bat security out\app.exe
echo   symcheck.bat symbolize out\app.exe 0x140001000
endlocal
