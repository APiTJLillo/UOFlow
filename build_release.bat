@echo off
setlocal

REM Ensure we are in the repo root and switch to the build directory
pushd "%~dp0UOWalkPatch\build-codex" || goto :eof

REM Clean stale CMake cache from previous paths/machines
if exist CMakeCache.txt del /f /q CMakeCache.txt
if exist CMakeFiles rmdir /s /q CMakeFiles

REM Configure the project (force 32-bit build via generator arg as well)
cmake -S .. -B . -A Win32 -DUOWALK_RELEASE_SYMBOLS=ON || goto :eof

REM Build Release and clean first to ensure a fresh binary
cmake --build . --config Release --clean-first || goto :eof

popd
endlocal
