# UOWalkPatch Refactor TODO

This file tracks the incremental refactor of the monolithic translation unit into a structured DLL project.

- [x] Extract logging utilities into `Core/Logging.hpp` and `Core/Logging.cpp`.
- [x] Move pattern scanning helpers to `Core/PatternScan.hpp` and `.cpp`.
- [x] Pull out portable helpers into `Core/Utils.hpp` and `.cpp`.
- [x] Isolate Winsock tracing into `Net/PacketTrace.*`.
- [x] Carve out SendBuilder hooks into `Net/SendBuilder.*`.
- [x] Export `GlobalStateInfo` and related logic into `Engine/GlobalState.*`.
 - [x] Migrate movement hooks into `Engine/Movement.*`.
 - [x] Relocate Lua bridge code into `Engine/LuaBridge.*`.
 - [x] Slim down `DllMain.cpp` to orchestrate subsystem init/shutdown.
- [x] Address build errors by adding missing standard headers.
- [x] Wrap MinHook initialization/teardown behind `Core/MinHookHelpers`.
