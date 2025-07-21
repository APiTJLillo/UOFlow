

> Everything here assumes the July 2025 retail Enhanced Client.
Replace pattern bytes / RVAs as you discover new builds.




---

0. Purpose

UOWalkPatch.exe attaches to a running uosa.exe, injects a stub that registers one or many extra Lua natives (today: walk(dir,run), tomorrow: cast(spellId), useSkill(id), etc.).
It never touches files on disk; all hooks are found at runtime by signature scan and cached.
During injection a small debug console is opened so you can see log messages from the helper. The injector logs pattern matches, process attachment and other progress information to this console.
The file `command_list.json` enumerates spells and skills that can be used with the `processCommand` signature.
See TODOClientPatch.md for roadmap tasks.


---

1. Scalable Architecture

┌─ injector (UOWalkPatch.exe) ─────────────────────────────────────┐
│ 1. enumerate signatures[] table (JSON)                           │
│ 2. for each sig:  validate-or-scan  →  absolute address          │
│ 3. write PatchInfo { addresses[], stubSize } into remote page    │
│ 4. copy stub blob (contains generic registrar)                   │
│ 5. CreateRemoteThread(stub)                                      │
└───────────────────────────────────────────────────────────────────┘
                       │
                       ▼
┌─ remote stub (generic, position-independent) ────────────────────┐
│ • AllocConsole  → “UOWalkPatch console”                          │
│ • foreach entry in PatchInfo.functions[]                         │
│       lua_register( L, entry.luaName, entry.bridgeThunk )        │
│ • printf  “[UOWalk] %u functions registered\n”                   │
│ • ExitThread                                                     │
└───────────────────────────────────────────────────────────────────┘

1.1 signatures.json  (extensible)

{
  "exe_sha1": "AUTO-POPULATED",
  "functions": [
    {
      "lua_name":  "walk",
      "pattern":   "55 8B EC 83 E4 ?? 83 EC ?? F3 0F 10 45 08 53 56 8B F1 57",
      "mask":      "xxx xx x? xx x? xxxxxxxxxxx",
      "bridge":    "walk_bridge"          // symbol inside stub
    },
    {
      "lua_name":  "cast",
      "pattern":   "8B 0D ?? ?? ?? ?? 8B 01 8B 40 38 FF D0 8B 44 24 0C",
      "mask":      "xx????xxxxxxxxxx",
      "bridge":    "cast_bridge"
    },
    {
      "lua_name":  "useSkill",
      "pattern":   "6A 01 6A 00 6A ?? 6A ?? 8B 0D ?? ?? ?? ?? FF 15 ?? ?? ?? ??",
      "mask":      "xxxxx?x?xx????xx????",
      "bridge":    "skill_bridge"
    },
    {
      "lua_name":  "processCommand",
      "pattern":   "83 EC 58 53 55 8B 6C 24 64 56 57 8B F0 B9 ?? ?? ?? ?? 66 8B 10 66 3B 11 75 1E 66 85 D2 74 15 66 8B 50 02 66 3B 51 02 75 0F 83 C0 04 83 C1 04 66 85 D2 75 DE 33 C0 EB 05 1B C0 83 D8 FF 85 C0 0F 85 ?? ?? ?? ?? 8B 4C 24 70 8D 44 24 18 50 51 B8 34 00 00 00 E8 ?? ?? ?? ?? 8B 74 24 18 85 F6 8B 7C 24 1C 74 79 8B 16 8B 42 2C 8B CE FF D0 83 F8 34 75 6B 8B D5 8D 44 24 4C E8 ?? ?? ?? ?? 85 FF 89 74 24 18 89 7C 24 1C 74 0C 8D 4F 04 BA 01 00 00 00 F0 0F C1 11",
      "mask":      "xxxxxxxxxxxx????xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx????xxxxxxxxxxxxxxxxxxxxxxxxxxxx????xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
      "bridge":    "process_bridge"
    }
  ],
  "globals": {
    "LuaState": {
      "pattern": "A1 ?? ?? ?? ?? 85 C0 75 ?? 8B 08",
      "mask":    "x????xxxx?xx"
    },
    "MoveComp": {
      "pattern": "A1 ?? ?? ?? ?? 83 ?? ?? 68 ?? ?? ?? ?? 50 E8",
      "mask":    "x????xx?x????xx"
    }
  }
}

To add a new Lua native:

1. Reverse the target function; craft a unique byte signature.


2. Write a tiny bridge thunk in the stub (same style as walk_bridge).


3. Add a JSON entry (lua_name, pattern, mask, bridge).


4. Rebuild stub_bin.h only – no injector changes.




---

2. Cache & Validation (per exe build)

First run
*️⃣ scans → fills absolute addresses → saves addr_cache.json.

Subsequent runs

1. If SHA-1 of uosa.exe unchanged


2. check first 16 bytes at each cached addr against pattern mask.
all match → instant load (no heavy scan).
any fail  → full rescan; cache refreshed.




---

3. Stub Layout (generic)

struct FunctionEntry {
    void* rva;                // filled by injector
    char  luaName[16];        // "walk", "cast", …
    void (__cdecl* thunk)(lua_State*);   // bridge in stub
};
struct PatchInfo {
    void* luaStatePtr;
    uint8_t fastSeq;
    uint32_t numFuncs;
    FunctionEntry funcs[8];   // growable
};

The stub loops for(i<numFuncs) lua_register(L, funcs[i].luaName, funcs[i].thunk);


---

5. HOWTO: add a new Lua native

1. Reverse client; locate function you want (CastSpell, UseSkill, etc.).


2. Grab 12-20 bytes at entry; wildcard version-dependent bytes → produce pattern/mask.


3. In stub/bridges.asm add:



cast_bridge:
    push  ebp
    mov   ebp, esp
    ; read spellId from Lua arg 1, etc…
    ; call [PatchInfo.funcs[?].rva]  ; actual CastSpellRequest
    xor   eax,eax
    pop   ebp
    ret   4

4. Update signatures.json with lua_name, pattern, mask, bridge.


5. make → UOWalkPatch.exe updated; no injector code touch.




---

Example Lua usage once spell bridge added

cast(42)        -- cast spell #42
useSkill(4)     -- use skill #4 (Hiding, etc.)


---

Keep this README and TODOClientPatch.md in the repo root; extend the signatures.json and bridges.asm as you (or the community) reverse additional client capabilities.

