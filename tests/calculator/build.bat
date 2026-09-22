@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "OUT=%cd%\out"
if not exist "%OUT%" mkdir "%OUT%"

set "VCVARS="
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
  for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    if exist "%%i\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=%%i\VC\Auxiliary\Build\vcvars64.bat"
  )
)
if not defined VCVARS (
  echo Could not find Visual Studio C++ tools.
  exit /b 1
)
call "%VCVARS%" || exit /b 1

set "INC=/Iinclude"
set "FLAGS=/nologo /EHsc /std:c++20 /W3 %INC%"

echo Compiling calculator sources...
cl %FLAGS% /c /Fo"%OUT%\add.obj"      src\add.cpp      || exit /b 1
cl %FLAGS% /c /Fo"%OUT%\subtract.obj" src\subtract.cpp || exit /b 1
cl %FLAGS% /c /Fo"%OUT%\multiply.obj" src\multiply.cpp || exit /b 1
cl %FLAGS% /c /Fo"%OUT%\divide.obj"   src\divide.cpp   || exit /b 1
cl %FLAGS% /c /Fo"%OUT%\main.obj"     src\main.cpp     || exit /b 1

lib /nologo /OUT:"%OUT%\calc.lib" "%OUT%\add.obj" "%OUT%\subtract.obj" "%OUT%\multiply.obj" "%OUT%\divide.obj" || exit /b 1

echo Linking app.exe (expect linker errors)...
link /nologo /OUT:"%OUT%\app.exe" "%OUT%\main.obj" "%OUT%\calc.lib" > "%OUT%\link.log" 2>&1
set "LINK_ERR=%ERRORLEVEL%"
type "%OUT%\link.log"

echo.
echo Artifacts in out\
dir /b "%OUT%"
if not "%LINK_ERR%"=="0" (
  echo.
  echo Link failed as expected for this homework bug demo.
  echo Next: diagnose.bat
  exit /b 0
)
endlocal
