# UOWalkPatch TODO

This file tracks remaining tasks for the UOWalkPatch helper.

- [x] Implement JSON-driven signature loader
- [ ] Modular stub build: emit bridges as symbols, auto-populate funcs[] (section .bridges in stub)
- [ ] Template bridge generator (Python)
- [ ] Spell-casting research - identify CastSpellRequest function and craft pattern + bridge
- [ ] Skill use research (UseSkillRequest)
- [ ] Console command list inside patch console – prints all registered Lua natives
- [ ] CLI flags (`--force-rescan`, `--add-func walk.json`, `--list-cache`)
- [ ] Graceful failure if any pattern not found – warn & skip that Lua native but continue others
- [ ] CI script (GitHub Actions) builds 32-bit EXE from stub + injector
- [x] Documentation updates for contributors (HOWTO add new native)
