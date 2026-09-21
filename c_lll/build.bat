@echo off
echo Building LLL Dynamic Link Library (lll.dll) with MSVC...
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cl /LD /O2 /W4 /D_CRT_SECURE_NO_WARNINGS /I"%~dp0include" "%~dp0src\lll.c" /Fe"%~dp0bin\lll.dll" /link /DLL
echo Build completed.