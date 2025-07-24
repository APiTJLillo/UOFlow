# UOWalkPatch TODO

This file tracks remaining tasks for the **UOWalkPatch** helper.
The helper injects a DLL into *UOSA.exe* so new Lua functions can be
exposed to the custom UI. It hooks the game's `RegisterLuaFunction`
routine early in the loading sequence to capture the `lua_State` pointer
and then registers extra bridges defined in `signatures.json`.

- [x] Implement JSON-driven signature loader
- [x] Hook `RegisterLuaFunction` early during client startup to capture all `lua_State` instances
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

## Lua Function Injection — New Approach

Goal:

Eliminate trampoline injection. Use a signature to scan for `globalStateInfo`,
read `lua_State*` from offset `0xC`, and call `RegisterLuaFunction` safely to
register both internal and injected Lua functions.

### Step 1: Find globalStateInfo in the Target Process
- [x] Create a signature to find the instruction sequence:

  ```
  mov ecx, [globalStateInfo]   ; opcode: 8B 0D ?? ?? ?? ??
  mov eax, [ecx+0C]            ; opcode: 8B 41 0C
  ```

  Use:

  Pattern: `8B 0D ?? ?? ?? ?? 8B 41 0C`

  Mask: `xx????xxx`

- [x] Scan `.text` section of `UOSA.exe` after process launch (or while
      suspended).
- [x] Read the absolute 4-byte address at offset 2 → this is the address of
      `globalStateInfo`.

### Step 2: Extract and Monitor the Lua State
- [x] Add `0xC` to `globalStateInfo` → this gives you the memory location of the
      `lua_State*`.
- [x] Read the pointer at `[globalStateInfo + 0xC]` using `ReadProcessMemory`.
- [x] Optionally poll this memory location periodically in your helper. If it
      changes, re-register functions.

### Step 3: Scan for RegisterLuaFunction
- [x] Use the `GetBuildVersion` scanning technique or a static signature to find
      the real `RegisterLuaFunction`.
      - From push of `GetBuildVersion` → trace the next call.
      - OR create a byte pattern for the full function.
- [x] Confirm address is stable and matches expected calling convention
      (`cdecl`).

### Step 4: Register Your Lua Functions
- [x] Build a function in your helper:

  ```cpp
  bool RegisterFunction(
      HANDLE hProcess,
      uintptr_t registerLuaFunc,
      uintptr_t luaState,
      uintptr_t callbackPtr,
      const std::string& name
  );
  ```

- [ ] Allocate memory in target for the function name string with
      `VirtualAllocEx`.
- [ ] Build a stub to call `RegisterLuaFunction`:

  ```
  push offset name
  push offset callback
  push offset lua_State
  call registerLuaFunction
  add esp, 0xC
  ret
  ```

- [ ] Launch with `CreateRemoteThread` or `QueueUserAPC`.

### Step 5: Verify and Harden
- [x] Log successful registration and print `lua_State*` value.
- [ ] If registration fails, log the name, pointer and return code.
- [ ] Confirm the function appears in the Lua environment and executes.

### Optional: Clean Up Old Hook System
- [x] Remove trampoline logic.
- [x] Remove instruction patching code and RWX section manipulation.
- [ ] Replace it with pure scanning and remote-call logic.

### Optional Testing Steps
- [ ] Launch `UOSA` in debug mode.
- [ ] Watch `[globalStateInfo + 0xC]` in x32dbg and verify state transitions.
- [ ] Dump Lua global environment and confirm function is added.

### Bonus Features (for later)
- [ ] Allow dynamic re-registration on Lua state change.
- [ ] Add JSON-configured function list for runtime injection.
- [ ] Detect duplicate function names and overwrite safely.
