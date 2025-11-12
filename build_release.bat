@echo off
setlocal

set "REPO_ROOT=%~dp0"

REM Stamp builds with the current git commit if available
set "UOW_COMMIT_HASH="
for /f %%i in ('git -C "%REPO_ROOT%" rev-parse --short HEAD 2^>nul') do set "UOW_COMMIT_HASH=%%i"
if not defined UOW_COMMIT_HASH set "UOW_COMMIT_HASH=unknown"
echo Build stamp: commit=%UOW_COMMIT_HASH%

REM Ensure we are in the repo root and switch to the build directory
pushd "%REPO_ROOT%UOWalkPatch\build-codex" || goto :eof

REM Clean stale CMake cache from previous paths/machines
if exist CMakeCache.txt del /f /q CMakeCache.txt
if exist CMakeFiles rmdir /s /q CMakeFiles

REM Configure the project (force 32-bit build via generator arg as well)
cmake -S .. -B . -A Win32 -DUOWALK_RELEASE_SYMBOLS=ON -DUOW_COMMIT_HASH=%UOW_COMMIT_HASH% || goto :eof

REM Build Release and clean first to ensure a fresh binary
cmake --build . --config Release --clean-first || goto :eof

popd
endlocal
