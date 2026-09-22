@echo off
REM Local wrapper so `symcheck.bat` works from this folder.
call "%~dp0..\..\symcheck.bat" %*
