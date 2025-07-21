

> Everything here assumes the July 2025 retail Enhanced Client.
Replace pattern bytes / RVAs as you discover new builds.




---

0. Purpose

UOWalkPatch.exe attaches to a running uosa.exe, injects a stub that registers one or many extra Lua natives (today: walk(dir,run), tomorrow: cast(spellId), useSkill(id), etc.).
It never touches files on disk; all hooks are found at runtime by signature scan and cached.


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
      "pattern":   "55 8B EC 83 EC ?? 56 8B F1 8B 0D ?? ?? ?? ?? 8B 01 FF 50 ??",
      "mask":      "xxxx?xxxxx????xxx?",
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

4. TODO checklist (scalable version)

#	Item	Owner/notes

1	Implement JSON-driven signature loader	RapidJSON or nlohmann/json
2	Modular stub build: emit bridges as symbols, auto-populate funcs[]	Section .bridges in stub
3	Template bridge generator (Python)	Given fastcallSig, output asm thunk
4	Spell-casting research<br> • identify CastSpellRequest function<br> • craft pattern + bridge	
5	Skill use research (UseSkillRequest)	
6	Console command list inside patch console → prints all registered Lua natives	
7	CLI flags<br> --force-rescan, --add-func walk.json, --list-cache	
8	Graceful failure: if any pattern not found, warn & skip that Lua native but continue others.	
9	CI script (GitHub Actions) builds 32-bit EXE from stub + injector	
10	Documentation updates for contributors (HOWTO add new native)	



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

Keep this README/TODO in the repo root; extend the signatures.json and bridges.asm as you (or the community) reverse additional client capabilities.

