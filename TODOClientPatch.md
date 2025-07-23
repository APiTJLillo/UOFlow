# UOWalkPatch TODO

This file tracks remaining tasks for the **UOWalkPatch** helper.
The helper injects a DLL into *UOSA.exe* so new Lua functions can be
exposed to the custom UI. It hooks the game's `RegisterLuaFunction`
routine early in the loading sequence to capture the `lua_State` pointer
and then registers extra bridges defined in `signatures.json`.

- [x] Implement JSON-driven signature loader
- [x] Hook `RegisterLuaFunction` early during client startup to capture all `lua_State` instances
- [x] Unhook `RegisterLuaFunction` after the first state is captured
- [ ] Record captured state pointers (login, shard select, in-game) for later use
- [ ] Confirm DLL is built without a fixed base address so relocation works when injected
- [ ] Ensure `signatures.json` resides next to `UOWalkPatchDLL.dll`; fail gracefully if missing
- [ ] Add runtime check in the injector for `signatures.json` and output helpful errors
- [ ] Document troubleshooting steps in the README when injection fails
- [ ] Note location of `uowalkpatch_debug.log` and console output for debugging
- [ ] Modular stub build: emit bridges as symbols, auto-populate funcs[] (section .bridges in stub)
- [ ] Template bridge generator (Python)
- [ ] Spell-casting research - identify CastSpellRequest function and craft pattern + bridge
- [ ] Skill use research (UseSkillRequest)
- [ ] Console command list inside patch console – prints all registered Lua natives
- [ ] CLI flags (`--force-rescan`, `--add-func walk.json`, `--list-cache`)
- [ ] Graceful failure if any pattern not found – warn & skip that Lua native but continue others
- [ ] CI script (GitHub Actions) builds 32-bit EXE from stub + injector
- [x] Documentation updates for contributors (HOWTO add new native)
