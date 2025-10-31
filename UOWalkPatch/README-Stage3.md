# UOWalkPatch Stage 3 Notes

## Build & Test
- Configure the project as usual (e.g. `cmake -S . -B build-codex`).
- Build the tests: `cmake --build build-codex --target UOWalkPatchTests`.
- Run the suite: `build-codex\bin\UOWalkPatchTests.exe`.
- Rebuild the DLL when needed: `cmake --build build-codex --target UOWalkPatchDLL`.

## Safe Testing Guidance
- The DLL installs runtime hooks; keep automated tests scoped to the synthetic harness.
- Exercise new logic against the client only in a controlled environment or a dedicated test shard.
- Monitor logs filtered by `SEND_SAMPLE`, `TRUST_CACHE`, `REJECT`, `TELEMETRY[PASS]`, and `BACKOFF` to verify Stage 3 behaviour.
