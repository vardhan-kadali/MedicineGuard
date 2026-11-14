@echo off
setlocal enabledelayedexpansion

echo ============================================================
echo   MedicineGuard - WebAssembly Engine Build Pipeline
echo ============================================================

:: 1. Check for emcc or activate EMSDK
where emcc >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [OK] emcc found in current PATH.
) else (
    if exist "D:\emsdk\emsdk_env.bat" (
        echo [*] Activating Emscripten environment from D:\emsdk...
        call "D:\emsdk\emsdk_env.bat" >nul 2>&1
    ) else if exist "%EMSDK%\emsdk_env.bat" (
        echo [*] Activating Emscripten environment from %EMSDK%...
        call "%EMSDK%\emsdk_env.bat" >nul 2>&1
    ) else (
        echo [ERROR] Emscripten compiler emcc was not found in PATH and emsdk_env.bat was not found.
        echo Please ensure Emscripten is installed or EMSDK environment variable is set.
        exit /b 1
    )
)

where emcc >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to locate emcc after activation attempt.
    exit /b 1
)

:: 2. Ensure output directory exists
if not exist "public\wasm" (
    echo [*] Creating output directory: public\wasm
    mkdir "public\wasm"
)

:: 3. Compile C sources to WebAssembly module
echo [*] Compiling C sources into WebAssembly module...
echo     Sources:  core-c/src/sha256.c
echo               core-c/src/merkle.c
echo               wasm/src/wasm_bridge.c
echo     Includes: core-c/include, wasm/include
echo     Output:   public/wasm/medicineguard.js, public/wasm/medicineguard.wasm

emcc core-c/src/sha256.c core-c/src/merkle.c wasm/src/wasm_bridge.c ^
    -Icore-c/include -Iwasm/include ^
    -std=c11 -O3 ^
    -s WASM=1 ^
    -s MODULARIZE=1 ^
    -s EXPORT_ES6=1 ^
    -s EXPORT_NAME=createMedicineGuardModule ^
    -s ALLOW_MEMORY_GROWTH=1 ^
    -s INITIAL_MEMORY=16777216 ^
    -s MAXIMUM_MEMORY=268435456 ^
    -s ENVIRONMENT=web,worker,node ^
    --no-entry ^
    -s EXPORTED_FUNCTIONS=[_malloc,_free,_mg_wasm_malloc,_mg_wasm_free,_mg_wasm_sha256,_mg_wasm_batch_create,_mg_wasm_batch_add_record,_mg_wasm_batch_build_tree,_mg_wasm_batch_get_root,_mg_wasm_batch_get_leaf_count,_mg_wasm_batch_get_height,_mg_wasm_batch_get_proof_size,_mg_wasm_batch_generate_proof,_mg_wasm_batch_destroy,_mg_wasm_verify_record,_mg_wasm_verify_leaf_hash,_mg_wasm_status_string,_mg_wasm_get_error_string] ^
    -s EXPORTED_RUNTIME_METHODS=[ccall,cwrap,getValue,setValue,UTF8ToString,stringToUTF8,HEAPU8] ^
    -o public/wasm/medicineguard.js

if %ERRORLEVEL% neq 0 (
    echo [ERROR] WebAssembly compilation failed with code %ERRORLEVEL%.
    exit /b %ERRORLEVEL%
)

echo.
echo ============================================================
echo   Build Successful! Artifacts generated in public/wasm/
echo ============================================================
for %%F in (public\wasm\medicineguard.js public\wasm\medicineguard.wasm) do (
    echo   %%~nxF: %%~zF bytes
)
echo ============================================================

exit /b 0
