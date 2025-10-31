# Scanner Stage 3 Tests

## Build and Run

```
cmake --build build-codex --target UOWalkPatchTests
build-codex\bin\UOWalkPatchTests.exe
```

## Safety Notes

- The test binary exercises the stage 3 instrumentation logic in isolation; it does **not** inject into or hook the Ultima Online client.
- Always run the tests outside of the live game client to avoid interfering with a running session.
