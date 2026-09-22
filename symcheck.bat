@echo off
setlocal
set "ROOT=%~dp0"
set "SC=%ROOT%build\symcheck.exe"
if not exist "%SC%" (
  echo symcheck.exe missing. From repo root run: build.bat
  exit /b 1
)
"%SC%" %*
endlocal
