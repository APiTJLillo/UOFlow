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
4. Generic action queue lines (e.g. enqueue return addresses) are not sufficient proof of spell-cast execution.
5. For cast debugging, treat these as required proof lines (or equivalent):
   - `CALL_CAST_V1 invoked ...`
   - `BRIDGE_V1 vp_cast invoked ...`
   - `UOFlow.Spell.cast invoked ...`
6. If those lines are missing, do not claim cast path is reached.

---

## 2) Primary debugging principle

Prefer one deterministic direct path over layered helper resolution.

For spell tests:
- Use a single direct callable entry (e.g. `__uow_call_cast_v1`) for proof.
- Do not fan out across many helpers in debug mode.
- Do not treat `ok=true` with nil returns and no state change as success.

---

## 3) Regression guardrails

1. Do not couple execution correctness to bridge health/getter diagnostics.
2. Keep bridge/getter checks diagnostic-only unless explicitly testing bridge integrity.
3. Avoid repeated rebinding spam in hot callback loops (latch/one-shot per `(ctx, L)` generation).
4. Avoid introducing broad architectural changes while direct cast lane is not proven.
5. Any change that adds context/FSM complexity must include explicit logs showing state transitions and why execution is blocked.

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
3. Run one direct cast probe (`__uow_call_cast_v1(...)`).
4. Compare expected log sequence vs actual.
5. Make smallest possible patch.
6. Re-test and update this file if a new durable rule is discovered.

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
