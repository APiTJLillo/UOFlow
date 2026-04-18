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
12. For cast debugging, treat these as required proof stages (or equivalent current labels):
   - direct entry: `CALL_CAST_V1 invoked ...`
   - bridge/global cast entry: `uow_vp_cast invoked ...` (legacy equivalent: `BRIDGE_V1 vp_cast invoked ...`)
   - cast wrapper entry: `uow_spell_cast invoked ...` or `UOFlow.Spell.cast invoked ...` (path-dependent)
   - final result line: `CALL_CAST_V1 result ok=... msg=...` (or equivalent wrapper result line)
   - for raw-evaluator route, also require `UOWCastSpellRaw invoked ...` and queued result/evidence logs before claiming success
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
3. Native bridge/wrapper entry line (`uow_vp_cast` + `uow_spell_cast`, or `UOFlow.Spell.cast` on that route).
4. Final result line with `(ok, msg)` (`CALL_CAST_V1 result ...` or equivalent wrapper result line).

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

---

## 10) Current working VP block model (April 2026)

These rules describe the current good state after rolling back from later regressions.

1. Treat **visual order** as the source of truth for execution order.
2. The current sort rule is:
   - middle column first
   - right column second
   - then `y`
   - then stable `id`
3. The canonical helper for that sort is `VisualProgrammingInterface.Manager:getBlocksInVisualOrder()` in `UOFlow/Source/UOFlow/VisualProgrammingManager.lua`.
4. `VisualProgrammingInterface.Manager:rebuildLinearConnectionsFromVisualOrder()` is now effectively a **diagnostic/logging helper**. It logs current visual order, but execution must not depend on `.connections`.
5. Do **not** reintroduce execution logic that traverses block `connections`. That was the root cause of moved blocks still running in stale order.
6. `Execution:testFlow()` and `Execution:start()` must build their queue from the current live visual order, not from the old graph.
7. `Execution:testFlow()` currently pulls live ordered blocks directly, stores them in `self.executionQueue`, and kicks off the first block immediately.
8. `Execution:start()` currently uses `buildExecutionSnapshot()` / `buildExecutionQueueFromSnapshot()`, but those helpers also derive order from current visual order.
9. Block IDs are **stable identity only**. They are not execution position and must not be shown or interpreted as ordering.
10. The block label formatter intentionally omits `[id]` now so reordering does not leave misleading `1,3,2` text on screen.

### Block creation rules

1. The working `CreateBlock` implementation is the **three-argument** version in `UOFlow/Source/UOFlow/VisualProgrammingTypes.lua`:
   - `VisualProgrammingInterface.CreateBlock(blockType, index, column)`
2. That function must:
   - create the manager block with the requested `column`
   - choose the correct scroll child based on `column`
   - anchor the new window into that same scroll child
3. The add-block context-menu path must call `CreateBlock(..., targetColumn)`.
4. The current add-block path lives in `UOFlow/Source/UOFlow/VisualProgrammingEvents.lua`.
5. `VisualProgrammingCore.lua` should not define a second `CreateBlock`; keep one authoritative implementation in `VisualProgrammingTypes.lua`.
6. If block creation starts throwing `Invalid Parameter passed to 'error()'` again after add/move/test changes, first verify:
   - the three-arg `CreateBlock(...)` is still the effective runtime definition
   - the block is being created in the correct scroll child for its column
   - no callback-time reorder logic is mutating extra state during UI events

### Reordering rules

1. `ContextMenuCallback("move_up" / "move_down")` must only reorder blocks by visual position and re-anchor the windows.
2. Drag/drop must only update block `y`/`column` and anchors.
3. Do not rebuild a synthetic graph inside add/move/drag callbacks.
4. Earlier attempts to rewrite the graph during UI callbacks caused:
   - `BlockSelectionCallback` failures
   - `ContextMenu.MenuItemLButtonUp` failures
   - `OnTestFlowClick` failures
   - in-game `Invalid Parameter passed to 'error()'`

---

## 11) Current working spell-cast lane

### Public Lua spell surface

1. The primary public Lua spell wrappers live in `UOFlow/Source/Debug.lua`.
2. Resolver order prefers raw helpers first:
   - `UOWCastSpellOnIdRaw`
   - `UOWCastSpellRaw`
   - then `uow_vp_cast(_on_id)`
   - then `uow_spell_cast(_on_id)`
   - then dotted wrappers
3. For raw helpers specifically, `ok == nil` with no Lua error is treated as **queued success**, not failure.
4. This is intentional. Raw evaluator callbacks often return **no Lua values** on success.

### Raw callback rules

1. `UOWCastSpellRaw` and `UOWCastSpellOnIdRaw` are **LuaPlus/raw evaluator callbacks**, not normal `lua_CFunction` gameplay helpers.
2. They must only do four things:
   - extract args from the LuaPlus callback context
   - log the request
   - queue a pending raw cast request
   - return `0` / no values immediately
3. Do **not** reintroduce LuaPlus return staging/finalization for these raw callbacks.
4. Earlier attempts to make raw callbacks return booleans through LuaPlus helpers caused:
   - `return stage failed`
   - access violations
   - swallowed VP control flow

### Current cast execution path

1. Working cast dispatch is:
   - raw callback queues request
   - VP or poller pumps queued raw casts
   - `ConsumePendingRawCastRequest(...)` runs on the owner/game thread
   - that path uses the direct native action-construction/enqueue helper
2. The key consumer lives in `UOWalkPatch/src/Engine/LuaBridge.cpp`.
3. `ConsumePendingRawCastRequest(...)` currently:
   - begins a manual cast attempt token
   - arms expected-cast hook evidence
   - dispatches through `DispatchNoClickCommand(...)`
   - uses `ScopedForcedActionGate`
   - calls `DirectBuildAndEnqueueSpell(...)` or `DirectBuildAndEnqueueSpellOnId(...)`
4. Do not bypass that owner-thread queued path from evaluator raw callbacks.
5. The direct native helper is the real phase-1 implementation. The old synthetic Lua/UI priming path is not the authoritative cast path.

### Direct native cast facts

1. Current known native addresses:
   - `ActionFactoryLookup = 0x005648F0`
   - `ActionQueueEnqueue = 0x00560BD0`
   - `ActionPostWakeA = 0x00475460`
   - `ActionPostWakeB = 0x00476020`
2. The cast gate is `DAT_00E3D540 + 0x5C2`.
3. The gate is a transient client-owned bit. It may need a scoped forced-open guard around the direct helper.
4. A known-target cast is only considered proven if enqueue evidence matches.
5. For `cast_on_id`, the expected enqueue evidence is:
   - `targetType=4`
   - `targetId=<expected object id>`
   - `flag18=1`
6. Generic queue noise is not enough. The specific `QueuedRawCast` / `CastExpect` evidence line is the proof.

### VP spell node rules

1. The current working `Cast Spell` node logic lives in `UOFlow/Source/UOFlow/VisualProgrammingTypes.lua`.
2. For known target / self target spells, VP should prefer the raw `cast_on_id` path.
3. The node must **pre-arm cast/recovery timers before dispatching** the raw cast helper.
4. The node must not rely on the raw callback returning to Lua normally.
5. The current good pattern is:
   - pre-arm timers
   - schedule `Execution.pendingRawDispatch`
   - let `VisualProgrammingExecutionTimer.lua` perform `queue -> pump -> done`
6. Do not revert to “call raw helper inline and continue immediately”; that previously broke block handoff and completion.
7. `UOWPumpQueuedRawCasts()` is the correct helper to pump queued raw spell dispatch from Lua.
8. Despite the name, `UOWPumpQueuedRawCasts()` also pumps queued raw walk requests.

### Known-target/self spell rule

1. If a spell target is known in advance, prefer `cast_on_id` over click-target fallback.
2. `Clumsy(self)` is the baseline proof case:
   - no manual click
   - visible cast behavior
   - enqueue evidence must match `targetType=4`, `flag18=1`

---

## 12) Current working walk/run lane

### Public Lua movement surface

1. The working Lua movement wrappers also live in `UOFlow/Source/Debug.lua`.
2. Public wrappers are:
   - `UOFlow.Walk.step`
   - `UOFlow.Walk.walk`
   - `UOFlow.Walk.run`
   - plus `UOW.Walk.*` and `uow.cmd.*` aliases
3. Resolver order prefers raw helpers first:
   - `UOWWalkStepPackedRaw`
   - `UOWWalkStepRaw`
   - `__uow_call_walk_v1`
   - `uow_vp_walk`
   - `uow_walk_step`
4. For raw walk helpers, `nil` return with no Lua error is treated as queued success.

### Raw walk callback rules

1. `UOWWalkStepRaw` and `UOWWalkStepPackedRaw` are evaluator/raw transport callbacks.
2. Like raw spell callbacks, they must:
   - extract args
   - queue a pending raw walk request
   - return no values immediately
3. `UOWWalkStepPackedRaw` encoding is:
   - low byte = direction
   - bit 8 = run flag

### Current walk execution path

1. Working queued walk dispatch is:
   - raw walk callback queues
   - `UOWPumpQueuedRawCasts()` or the poller consumes
   - `ConsumePendingRawWalkRequest(...)` runs
   - owner thread eventually calls `Engine::SendWalkStep(...)`
2. `ConsumePendingRawWalkRequest(...)` is allowed to repost onto the owner thread if invoked from the wrong thread.
3. If movement is not ready, it can queue a retry instead of hard failing immediately.

### Direct native movement facts

1. The current direct movement path is in `UOWalkPatch/src/Engine/Movement.cpp`.
2. `Engine::SendWalkStepInternal(...)` requires:
   - direction `0..7`
   - owner thread
   - movement component ready
3. It normalizes direction before dispatch.
4. The current native mode is:
   - `1` = walk
   - `2` = run
5. It currently calls the client movement update function directly (`g_origUpdate` / `updateDataStructureState`) on the movement component.
6. Success is determined by the low byte of the client return code being non-zero.
7. On success the wrapper returns `"queued"`.
8. This is a **client state update path**, not just raw packet spoofing.

### Walk controller facts

1. The higher-level target walker is in `UOWalkPatch/src/Walk/WalkController.cpp`.
2. `Walk::Controller::RequestTarget(x, y, z, run)` starts a controller that:
   - tracks current movement snapshots
   - computes 8-way direction from current position to target
   - limits inflight steps
   - uses adaptive step delay
   - times out and resyncs when progress stalls
3. The current controller is conservative and only partly proven; treat it as “working enough to experiment,” not fully solved pathfinding.
4. Future RE for walking/running should focus on:
   - movement component readiness
   - `updateDataStructureState` semantics
   - queue head / inflight / snapshot behavior
   - acknowledgement and resync behavior
5. Do not assume packet-layer work alone is enough if native movement state disagrees.

---

## 13) Logging and runtime pitfalls worth remembering

1. `UOWNativeLog(...)` routed through `DummyPrint(...)` remains the most reliable Lua-side log surface.
2. `Debug.Print(...)` is fine for noncritical UI/debug messages, but do not trust it in hot VP/runtime callback paths.
3. Several earlier `Invalid Parameter passed to 'error()'` failures were caused by seemingly harmless UI-side/logging work in callback-critical paths.
4. If a path must be rock-solid, prefer `UOWNativeLog(...)` over `Debug.Print(...)`.
5. `pcall` / `xpcall` remain off-limits in critical VP/cast/walk paths.
6. If you add new proof logs, place them at:
   - raw transport entry
   - queued request
   - pump/consume
   - final native evidence/result

---

## 14) Repo landmines / future-self warnings

1. There are duplicate or stale-looking definitions in the repo. Do not assume the first search hit is the live one.
2. `VisualProgrammingInterface.CreateBlock` is now single-source in `UOFlow/Source/UOFlow/VisualProgrammingTypes.lua` (three-arg, column-aware). Keep it there.
3. If a change breaks add-block, drag/drop, or test execution in a way that looks unrelated, check for accidental reintroduction of duplicate definitions first.
4. `Manager:rebuildLinearConnectionsFromVisualOrder()` should stay cheap and safe. Do not turn it back into a graph-mutating function unless you are intentionally redesigning the execution model.
5. `UOWPumpQueuedRawCasts()` currently pumps both casts and walks. Do not rename or narrow it casually without updating VP timer code and pollers.
6. If raw callbacks start “working” only when called manually but VP breaks, suspect control-flow/return behavior first, not the native spell or movement helper.
7. Keep execution ownership split clean:
   - `UOFlow/Source/UOFlow/VisualProgrammingExecution.lua` owns queue/snapshot builders and `Execution:start()`
   - `UOFlow/Source/UOFlow/VisualProgrammingExecutionFlow.lua` owns flow controls (`hardResetForTestRun`, `pause`, `resume`, `stop`, `continueExecution`)
   - if overlap is reintroduced, `UOFlow/Source/UOFlow/VisualProgramming.xml` load order still means later definitions win
8. Keep action-system ownership clean:
   - `UOFlow/Source/UOFlow/VisualProgrammingActions.lua` owns `Actions:register/get/validateParams/execute/initialize`
   - `UOFlow/Source/UOFlow/VisualProgramming.lua` should only bootstrap shared tables/utilities, not redefine `Actions` core methods
9. Do not keep tracked C++/header backup artifacts (`*.bak*`) in `UOWalkPatch`; they create stale-code search hits and drift risk.

---

## 15) Local RE/tooling paths (Windows host)

Use these concrete paths when reproducing reverse-engineering context on this machine:

1. Ghidra install root:
   - `C:\Users\dukey\OneDrive\Desktop\ghidra_12.0.4_PUBLIC`
2. Ghidra launcher:
   - `C:\Users\dukey\OneDrive\Desktop\ghidra_12.0.4_PUBLIC\ghidraRun.bat`
3. UOSA artifacts root:
   - `C:\Users\dukey\OneDrive\Documents`
4. Confirmed UOSA artifact currently present:
   - `C:\Users\dukey\OneDrive\Documents\UOSA.exe.gzf`

If you move to separate extracted files (e.g., `UOSA.exe`, `.gpr`, `.rep`), update this section immediately with exact absolute paths.
