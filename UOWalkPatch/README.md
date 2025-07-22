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
`uosa.exe`, locates the hidden `RegisterLuaFunction` routine and the global
`lua_State` pointer, then registers any functions described in
`signatures.json`.  A small monitoring thread stays alive and watches for the
UI being reloaded (when the `lua_State` pointer changes) so the natives are
re-registered automatically.  A debug console pops up showing pattern matches
and other status messages. Press **Enter** to stop the helper.
