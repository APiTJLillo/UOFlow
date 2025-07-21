# UOWalkPatch

This utility injects a helper stub into the running Ultima Online Enhanced Client. The stub registers additional Lua natives which expand the built in macro functionality. Signatures for client functions are defined in `signatures.json`.
`command_list.json` contains a reference list of skills and spells for use with the `processCommand` signature.

## Building

```
mkdir build && cd build
cmake ..
make
```

The resulting `UOWalkPatch.exe` should be run after the client is started. It will search for `uosa.exe`, allocate memory for the stub and spawn a remote thread. A debug console pops up showing pattern matches and other status messages.
