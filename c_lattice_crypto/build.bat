@echo off
setlocal

echo Building educational LWE native library (lattice_crypto.dll) with MSVC...
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

if not exist "%~dp0bin" mkdir "%~dp0bin"

cl /nologo /LD /O2 /W4 /D_CRT_SECURE_NO_WARNINGS /D LATTICE_CRYPTO_BUILD /I"%~dp0include" "%~dp0src\lattice_crypto.c" /Fe"%~dp0bin\lattice_crypto.dll" /link /DLL

if errorlevel 1 (
    echo Build failed.
    exit /b 1
)

echo Build completed.
endlocal
