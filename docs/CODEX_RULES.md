# CODEX_RULES.md — UOFlow / UOWalkPatch Working Rules

Purpose: keep future Codex sessions aligned with what has already been learned, reduce regressions, and avoid repeating dead-end debugging loops.

## 0) Read-first requirement
Before making any changes, always read:
1. `README.md`
2. `UOWalkPatch/README.md`
3. `docs/CODEX_RULES.md` (this file)

Then summarize in 5-10 bullets what you think is true before coding.

---

## 1) Known truths from this project

1. There are multiple Lua execution domains/states in the client (at least evaluator/console domain and gameplay domain).
2. A function being registered/logged does **not** prove it is callable from the specific VP runtime context.
3. `DummyPrint()` and simple log probes proved evaluator-domain Lua→C works.
4. Ghidra confirmed the client uses one common registration helper (`UOSA.exe+0x594E1F` / `FUN_00994e1f`) for built-ins, but the built-ins themselves are **not** plain stock `lua_CFunction` callbacks.
5. Client-registered built-ins are written in a LuaPlus-style callback model:
   - parse args via helper routines such as `FUN_00996fd1`
   - stage returns via helpers such as `FUN_0099d545` / `FUN_0099d5f9`
   - finalize returns via `FUN_0099e3d8`
   - then return the number of values
6. `DummyPrint()` working does **not** prove evaluator/VP can safely execute our gameplay `lua_CFunction` spell helpers. It only proves the evaluator can dispatch a minimal raw callback.
7. `pcall` / `xpcall` are not reliable in this environment for debugging or cast execution. They can hide the real failure point and must be removed from critical VP/debug/cast paths.
8. `DummyPrint("text")` is the only proven script-to-DLL logging surface in the evaluator domain. Use it through `UOWNativeLog(...)` for UOFlow-owned Lua scripts.
9. `Debug.Log`, `UOW.Debug.Log`, `uow_debug_log`, and `__uow_debug_log_v1` are not reliable primary script-call surfaces here, even when they appear bound in logs.
10. Public script spell APIs should be Lua wrappers (`UOFlow.Spell.cast`, `UOW.Spell.cast`, `uow.cmd.cast`) over simple raw globals such as `UOWCastSpellRaw`, not native dotted registrations.
11. Generic action queue lines (e.g. enqueue return addresses) are not sufficient proof of spell-cast execution.
12. For cast debugging, treat these as required proof lines (or equivalent):
   - `CALL_CAST_V1 invoked ...`
   - `BRIDGE_V1 vp_cast invoked ...`
   - `UOFlow.Spell.cast invoked ...`
   - `UOWCastSpellRaw invoked ...`
13. If those lines are missing, do not claim cast path is reached.
14. `UserActionCastSpell` / `UserActionCastSpellOnId` client pointers are LuaPlus/raw ABI callbacks, not `int(lua_State*)` call targets. Do not invoke the captured original pointers through `InvokeClientLuaFn(...)`.
15. Phase-1 native cast recovery uses the direct client action path:
   - gate `DAT_00E3D540 + 0x5C2`
   - action factory `0x005648F0`
   - enqueue `0x00560BD0`
   - action tail `0x00475460` / `0x00476020`
16. `PrimeSpellUseRequestState(...)` is debug-only and must not be in the raw callback critical path for spell casting.

---

## 2) Primary debugging principle

Prefer one deterministic direct path over layered helper resolution.

For spell tests:
- Use a single direct callable entry (e.g. `__uow_call_cast_v1`) for proof.
- Prefer a simple raw global following the `DummyPrint` model over dotted gameplay names when the callback ABI is in doubt.
- Do not fan out across many helpers in debug mode.
- Do not treat `ok=true` with nil returns and no state change as success.
- When the client callback ABI is in question, prefer a true client-style shim over another plain `lua_CFunction` experiment.

---

## 3) Regression guardrails

1. Do not couple execution correctness to bridge health/getter diagnostics.
2. Keep bridge/getter checks diagnostic-only unless explicitly testing bridge integrity.
3. Avoid repeated rebinding spam in hot callback loops (latch/one-shot per `(ctx, L)` generation).
4. Avoid introducing broad architectural changes while direct cast lane is not proven.
5. Any change that adds context/FSM complexity must include explicit logs showing state transitions and why execution is blocked.
6. Do not add `pcall` / `xpcall` around cast execution, VP button handlers, or native logging shims in this client.

---

## 4) Logging requirements (mandatory)

When debugging cast path, logs must include:
1. VP-side before-call line with run id and spell id.
2. Native entry line at first instruction of direct cast trampoline.
3. Native entry/exit line for `UOFlow.Spell.cast` wrapper.
4. Final result line with `(ok, msg)`.

If a stage is missing in logs, stop and diagnose that stage before further changes.

---

## 5) Domain/Context checks

Always verify and log:
- callback `L`
- engine/global `L`
- owner thread id
- caller thread id
- script context pointer

Never assume these are identical; prove equivalence in the logs.

---

## 6) Definition of done for spell-cast milestone

A change is not done until all are true:
1. VP test button triggers direct cast entry deterministically.
2. Required proof logs appear in sequence.
3. Cast succeeds repeatedly without requiring incidental UI clicks.
4. Failure path returns explicit `(false, reason)` and never silent nil/nil.

---

## 7) Suggested workflow per attempt

1. Reproduce once with fresh log.
2. Confirm direct probe still works (`DummyPrint`, log probe).
3. Confirm whether the function being tested is a raw evaluator callback or a gameplay LuaPlus callback.
4. Run one direct cast probe (`__uow_call_cast_v1(...)`) only if the callback ABI is already proven for that domain.
5. Compare expected log sequence vs actual.
6. Make smallest possible patch.
7. Re-test and update this file if a new durable rule is discovered.

---

## 8) What to avoid

- Big refactors before direct path is proven.
- Mixing evaluator and gameplay assumptions without logs.
- Treating queue/hotbar noise as cast proof.
- “It should work” claims without the proof-log sequence.

---

## 9) Session handoff template

When handing off to another coding session/model, include:
- Current commit hash
- Last known good probe commands and outputs
- Required proof-log sequence
- Which stage currently fails (VP pre-call / trampoline / cast wrapper / post-result)

This prevents spinning wheels across sessions.
