@echo off
setlocal enabledelayedexpansion

echo ====================================================================
echo  MedicineGuard Phase 1 - DAA Empirical Benchmark Runner
echo ====================================================================

if not exist "build\benchmark.exe" (
    echo [INFO] benchmark.exe not found. Running build.bat first...
    call scripts\build.bat
    if %ERRORLEVEL% neq 0 (
        echo [ERROR] Build failed.
        exit /b %ERRORLEVEL%
    )
)

echo.
echo [BENCHMARK] Executing across batch sizes (100, 1,000, 10,000, 100,000)...
build\benchmark.exe
exit /b %ERRORLEVEL%

