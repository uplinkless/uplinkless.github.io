@echo off
rem Builds hello_upx.exe (x64) reproducibly into the folder given as the first argument.
rem Run from an "x64 Native Tools Command Prompt for VS". /Brepro makes the output byte-identical
rem for the same source and compiler version.
setlocal
if "%~1"=="" (echo usage: build.cmd OUTPUT_FOLDER & exit /b 2)
set "OUT=%~f1"
if not exist "%OUT%" mkdir "%OUT%"
cl /nologo /O2 /MT /GS /W4 /Brepro "%~dp0hello_upx.c" /Fo"%OUT%\\" /Fe"%OUT%\hello_upx.exe" /link /Brepro /DYNAMICBASE user32.lib advapi32.lib || exit /b 1
del /q "%OUT%\hello_upx.obj" 2>nul
exit /b 0
