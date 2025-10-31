@echo off
setlocal
pushd "%~dp0UOWalkPatch\build-codex" || goto :eof
cmake --build . --config Release
popd
endlocal
