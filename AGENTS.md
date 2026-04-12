# AGENTS.md

Codex / agent startup instructions for this repo.

## Required first read
Before making any code changes, read:
1. `README.md`
2. `UOWalkPatch/README.md`
3. `docs/CODEX_RULES.md`

Then summarize current understanding in 5-10 bullets before editing.

## Non-negotiable debugging rule for spell casting
Do not claim cast path is working unless logs show the full proof sequence (or equivalent):
1. `CALL_CAST_V1 invoked ...`
2. `BRIDGE_V1 vp_cast invoked ...`
3. `UOFlow.Spell.cast invoked ...`
4. final `(ok,msg)` result log

If any stage is missing, stop and diagnose that stage.

## Context caution
This project has multiple Lua states/domains (evaluator vs gameplay). Never assume they are the same; prove with logs.

## Source of truth
Detailed rules, known findings, anti-regression notes, and handoff format are in:
- `docs/CODEX_RULES.md`
