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
The helper scans the client for the `RegisterLuaFunction` routine and the
`globalStateInfo` structure. By reading the pointer at `globalStateInfo + 0xC`
the DLL obtains the current `lua_State*` and registers any natives described in
`signatures.json`.
Reloading the UI causes the Lua state address to change, so a background polling
thread monitors `globalStateInfo` and re-registers functions whenever the state
pointer updates. No code patches or hooks are required.
A debug console pops up showing pattern matches and other status messages.
Press **Enter** to exit the helper.

All debug output is also written to `uowalkpatch_debug.log`. The file is created
next to the DLL if possible, otherwise in `%WINDIR%\Temp`.

## Lua functions

The patch exposes a couple of helper calls to Lua. `DummyPrint` simply logs a
message and `walk` triggers the client's internal movement routine. For sending
arbitrary packets without Lua, the DLL exports a `SendRaw` function that
forwards a byte buffer through the client's network layer. Internally the DLL
hooks the Winsock send-family (`send`, `WSASend`, `WSASendTo`, `sendto`) to
surface the game's packet wrapper and capture the network manager pointer. The
Lua functions are registered automatically when the helper locates the client's
Lua state.

`UOW_StatusFlags` and `UOW_StatusFlagsEx` now publish shims that forward to
registry-stored implementations. The install path logs the active binding,
reasserts the shim during early heartbeats, and can optionally trace overwrites
by launching with `UOW_TRACE_OVERWRITES=1`, which briefly hooks `_G.__newindex`
to report any script attempting to replace these globals.

## Troubleshooting

If injection fails with a generic `LoadLibrary` error, ensure `signatures.json`
is present in the same directory as `UOWalkPatchDLL.dll`. The DLL refuses to
load when this file is missing.
