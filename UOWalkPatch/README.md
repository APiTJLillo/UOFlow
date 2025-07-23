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
process. If `uosa.exe` is not running the injector launches it in a suspended
state, injects `UOWalkPatch.dll` and then resumes execution so the hook is
installed before the client registers its Lua functions. The installed hook
captures the internal `lua_State*` and registers any natives described in
`signatures.json`.
Reloading the UI will trigger the hook again so the functions remain available.
A debug console pops up showing pattern matches and other status messages.
Press **Enter** to exit the helper.
