@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "VCVARS="
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
  for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    if exist "%%i\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=%%i\VC\Auxiliary\Build\vcvars64.bat"
  )
)
if not defined VCVARS if exist "%ProgramFiles%\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" (
  set "VCVARS=%ProgramFiles%\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
)
if not defined VCVARS if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
  set "VCVARS=%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
)
if not defined VCVARS (
  echo Could not find vcvars64.bat. Install Visual Studio C++ tools.
  exit /b 1
)

call "%VCVARS%" || exit /b 1

if not exist build mkdir build
cmake -S . -B build -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release || exit /b 1
cmake --build build || exit /b 1
ctest --test-dir build --output-on-failure || exit /b 1

echo.
echo Built: build\symcheck.exe
echo Run:   symcheck.bat help
endlocal
