# UOWalkPatch

This utility injects a helper stub into the running Ultima Online Enhanced Client. The stub registers additional Lua natives which expand the built in macro functionality. Signatures for client functions are defined in `signatures.json`.
`command_list.json` contains a reference list of skills and spells for use with the `processCommand` signature.

## Building

```
mkdir build && cd build
cmake ..
make
```

Run `UOWalkPatch.exe` after the client is already running. The tool attaches to
`uosa.exe`, locates the hidden `RegisterLuaFunction` call used when the client
registers its own Lua functions and patches it. The installed hook captures the
internal `lua_State*` and registers any natives described in `signatures.json`.
Reloading the UI will trigger the hook again so the functions remain available.
A debug console pops up showing pattern matches and other status messages.
Press **Enter** to exit the helper.
