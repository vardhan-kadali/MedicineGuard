@echo off
setlocal enabledelayedexpansion

echo ====================================================================
echo  MedicineGuard Phase 1 - C Native Build Pipeline
echo ====================================================================

:: Find GCC in PATH or fallback to MSYS2 UCRT64
where gcc >nul 2>nul
if %ERRORLEVEL% equ 0 (
    set GCC_CMD=gcc
) else if exist "C:\msys64\ucrt64\bin\gcc.exe" (
    set GCC_CMD=C:\msys64\ucrt64\bin\gcc.exe
) else (
    echo [ERROR] GCC compiler not found in PATH or at C:\msys64\ucrt64\bin\gcc.exe
    echo Please ensure MinGW-w64 or MSYS2 is installed.
    exit /b 1
)

echo [INFO] Using Compiler: %GCC_CMD%
%GCC_CMD% --version | findstr /i "gcc"

:: Create build directory
if not exist "build" mkdir build

set CFLAGS=-std=c11 -Wall -Wextra -Werror -O3 -Icore-c/include

echo.
echo [1/4] Compiling core-c/src/sha256.c ...
%GCC_CMD% %CFLAGS% -c core-c/src/sha256.c -o build/sha256.o
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to compile sha256.c
    exit /b %ERRORLEVEL%
)

echo [2/4] Compiling core-c/src/merkle.c ...
%GCC_CMD% %CFLAGS% -c core-c/src/merkle.c -o build/merkle.o
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to compile merkle.c
    exit /b %ERRORLEVEL%
)

echo [3/4] Building test runners (test_sha256, test_merkle) ...
%GCC_CMD% %CFLAGS% build/sha256.o core-c/tests/test_sha256.c -o build/test_sha256.exe
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to link test_sha256.exe
    exit /b %ERRORLEVEL%
)

%GCC_CMD% %CFLAGS% build/sha256.o build/merkle.o core-c/tests/test_merkle.c -o build/test_merkle.exe
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to link test_merkle.exe
    exit /b %ERRORLEVEL%
)

echo [4/4] Building benchmark runner (benchmark.exe) ...
%GCC_CMD% %CFLAGS% build/sha256.o build/merkle.o core-c/benchmarks/benchmark.c -o build/benchmark.exe
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to link benchmark.exe
    exit /b %ERRORLEVEL%
)

echo.
echo ====================================================================
echo  BUILD SUCCESSFUL! Binaries created in build/
echo    - build/test_sha256.exe
echo    - build/test_merkle.exe
echo    - build/benchmark.exe
echo ====================================================================
exit /b 0

