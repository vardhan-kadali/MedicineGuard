@echo off
setlocal

echo ============================================================
echo   MedicineGuard - Running WebAssembly Engine Tests (Node.js)
echo ============================================================

where node >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Node.js not found in PATH.
    exit /b 1
)

node scripts\test_wasm.js
if %ERRORLEVEL% neq 0 (
    echo [ERROR] WebAssembly test suite failed with code %ERRORLEVEL%.
    exit /b %ERRORLEVEL%
)

echo.
echo [SUCCESS] All WebAssembly tests passed successfully!
exit /b 0

