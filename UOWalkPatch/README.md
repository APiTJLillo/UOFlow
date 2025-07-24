# UOWalkPatch

This utility injects a helper stub into the running Ultima Online Enhanced Client. The stub registers additional Lua natives which expand the built in macro functionality. Signatures for client functions are defined in `signatures.json`.
`command_list.json` contains a reference list of skills and spells for use with the `processCommand` signature.

## Building

```
mkdir build && cd build
cmake ..
make
```

Run `UOInjector.exe` to start the Enhanced Client or inject into an existing
process. If `uosa.exe` is not running the injector launches it normally and
polls the new process until `kernel32.dll` appears before injecting
`UOWalkPatchDLL.dll`. The polling routine tolerates temporary failures while the
client is still spinning up so it no longer times out instantly on slower
systems.
The helper scans the client for the `RegisterLuaFunction` routine, reads the
`lua_State*` from `globalStateInfo + 0xC` and registers any natives described
in `signatures.json`.
Reloading the UI will trigger the hook again so the functions remain available.
During initialization the DLL scans UOSA.exe for the call to
`RegisterLuaFunction` by locating the nearby "GetBuildVersion" string.
Once found, it hooks that routine so the first Lua state pointer can be
captured and additional natives registered.
A debug console pops up showing pattern matches and other status messages.
Press **Enter** to exit the helper.

All debug output is also written to `uowalkpatch_debug.log`. The file is created
next to the DLL if possible, otherwise in `%WINDIR%\Temp`.

## Troubleshooting

If injection fails with a generic `LoadLibrary` error, ensure `signatures.json`
is present in the same directory as `UOWalkPatchDLL.dll`. The DLL refuses to
load when this file is missing.
