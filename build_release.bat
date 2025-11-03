@echo off
setlocal
pushd "%~dp0UOWalkPatch\build-codex" || goto :eof
cmake -S .. -B . -DUOWALK_RELEASE_SYMBOLS=ON || goto :eof
cmake --build . --config Release --clean-first
popd
endlocal
