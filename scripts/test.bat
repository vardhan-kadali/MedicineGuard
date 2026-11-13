@echo off
setlocal enabledelayedexpansion

echo ====================================================================
echo  MedicineGuard Phase 1 - Automated Test Suite Runner
echo ====================================================================

:: Ensure binaries are compiled
if not exist "build\test_sha256.exe" (
    echo [INFO] Binaries not found. Running build.bat first...
    call scripts\build.bat
    if %ERRORLEVEL% neq 0 (
        echo [ERROR] Build step failed. Aborting tests.
        exit /b %ERRORLEVEL%
    )
)

echo.
echo [TEST 1/2] Running SHA-256 NIST and Cryptographic Tests...
echo --------------------------------------------------------------------
build\test_sha256.exe
set SHA_EXIT=%ERRORLEVEL%
if %SHA_EXIT% neq 0 (
    echo [FAIL] test_sha256.exe exited with error code %SHA_EXIT%
    exit /b %SHA_EXIT%
)

echo.
echo [TEST 2/2] Running Merkle Tree, Proofs and Negative Security Tests...
echo --------------------------------------------------------------------
build\test_merkle.exe
set MERKLE_EXIT=%ERRORLEVEL%
if %MERKLE_EXIT% neq 0 (
    echo [FAIL] test_merkle.exe exited with error code %MERKLE_EXIT%
    exit /b %MERKLE_EXIT%
)

echo.
echo ====================================================================
echo  ALL PHASE 1 AUTOMATED TESTS PASSED CLEANLY (100%% SUCCESS)
echo ====================================================================
exit /b 0
