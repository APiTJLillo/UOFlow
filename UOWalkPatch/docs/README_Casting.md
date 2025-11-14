# Casting Spell Probe Notes

Spell casts no longer sit behind a fixed packet id. Recent logs showed ids such as `0x57`, `0x77`, `0x70`, `0x22`, `0xB8`, and `0xE0` for the exact same UI action. The one constant is the targeting packet: `id=0x2E len=7` appears for every targeting flow (even via `sendto`). Treat `0x2E` as the stable cursor anchor and use call stacks—not packet ids—to pick the helper you want to probe.

## Config highlights

```
CAST_CORR_ENABLE=1
CAST_CORR_WINDOW_MS=400     # correlation window (ms) after UserActionCastSpell
CAST_CORR_LEN_HINT=9        # expected cast packet length (tweak as needed)
CAST_SENDER_DETOUR_ENABLE=1 # auto-detour the cast sender helper
CAST_SENDER_ADDR=UOSA.exe+0x2486A4  # default small-send wrapper
TARGET_SENDER_ADDR=UOSA.exe+0x24B6A2
CAST_SENDER_LOG_CTX=1       # include ctx-word/payload-source logs
CAST_SENDER_DUMP_BYTES=16   # bytes of payload to dump from EDX
CAST_SENDER_MAX_HITS=64     # entries logged before auto-quiet
CAST_SENDER_DEBOUNCE_MS=25  # debounce between ENTER/LEAVE logs
TRACE_PACKET_STACKS=1       # recommended during discovery
TRACE_PACKET_ID_FILTER=0x2E # set while hunting the target helper
```

## Workflow

1. **Lock in the cursor helper (id `0x2E`).**  
   Enable `TRACE_PACKET_STACKS=1` and set `TRACE_PACKET_ID_FILTER=0x2E`. When the targeting packet fires you’ll see `[CastCorrelator] target sender frame set to UOSA.exe+0x……` in the log. That frame is stored so cast correlation won’t confuse targeting and casting helpers. Already know the cursor helper? Set `TARGET_SENDER_ADDR=UOSA.exe+0x24B6A2` (or whatever offset you captured) and the correlator will arm it immediately on attach.

2. **Let the correlator pick the cast sender.**  
   With `CAST_CORR_ENABLE=1`, every `UserActionCastSpell`/`UserActionCastSpellOnId` call opens a 400 ms window. The next outbound Winsock packet whose stack’s first non-system frame lives in `UOSA.exe` (and whose length matches `CAST_CORR_LEN_HINT`) is marked as the cast candidate:
   ```
   [CastCorrelator] send t=+32 ms id=77 len=9 top=UOSA.exe+0x6A3528 -> CAST CANDIDATE
   ```

3. **Automatic sender detour.**  
   As soon as a candidate is identified, the correlator arms the cast-sender detour (default target: `UOSA.exe+0x2486A4`). Expect:
   ```
   [CastCorrelator] stack: #0 UOSA.exe+0x2486A4 #1 ...
   [CastSender:ENTER] addr=UOSA.exe+0x2486A4 ecx=00000002 edx=XXXXXXXX len=9 ...
   [CastSender:DUMP] 12 34 56 ...
   [CastSender:LEAVE] addr=UOSA.exe+0x2486A4 EAX=....
   ```
   ECX/EDX and the stack args line up with the small-send wrapper, giving you both the payload pointer and the length (len=9 for encrypted casts in the latest logs). The detour also dumps the first few bytes so you can correlate spells even when the packet id mutates.
   - Want to pin a helper immediately on attach? Set `CAST_SENDER_ADDR=UOSA.exe+0x2486A4` (or any offset from your logs) and the detour arms at boot.

4. **Switching focus.**  
   Keep `TRACE_PACKET_ID_FILTER=0x2E` whenever you need to re-sample the target/cursor helper. The correlator will remember that frame and continue treating any other `UOSA.exe+offset` discovered inside the cast window as the cast sender, even if the packet id churns.

## Late wrap recovery & native fallback

- Set `debug.casttrace=1` (or `UOW_DEBUG_CASTTRACE=1`) during bring-up to light up `[CastTrace] debug.casttrace enabled (cfg) – fingerprint capture active` and `[SendPacket] debug.casttrace enabled`. The same flag arms the `debug.native_cast_fallback` toggle by default.
- When the Lua console binds land you should see `[LateWrap] guard reset (console_bind, L=0x…)` followed by `[LateWrap] wrapped UserActionCastSpell (console_bind)` / `…OnId`. If the wrappers race registration, the retry timer will keep calling `ForceLateCastWrapInstall` every 500 ms until both globals are wrapped.
- Flip `debug.latewrap_verbose=1` in `uowalkpatch.cfg` to watch `[LateWrap] attempt=N … (cooldown=300ms)` instrumentation on each retry.
- The native fallback probes the `BuildAction` serializer (RVA `0x0053E630`) and CastSpell vtable (`RVA_Vtbl_CastSpell` in `src/Engine/Addresses.h`). On startup you’ll see `[Gate] module base=…` and `[Gate] BuildAction at … prologue_ok=1`. Every CastSpell object flowing through that serializer emits `[CastUI/native] self=… vtbl=… spellId=… targetType=… targetId=XXXXXXXX iconId=N`, so the correlator can still bridge into `[CastExec]` even if the Lua wrap never sticks.
- Rollback: set `debug.native_cast_fallback=0` (or drop `debug.casttrace=0`) and the detour won’t arm. To disable verbose retries, set `debug.latewrap_verbose=0`.
- Client updates: adjust `RVA_BuildAction`/`RVA_Vtbl_CastSpell` in `src/Engine/Addresses.h` when the disassembly shifts. The prologue guards will log `[Gate] signature mismatch at 0x0053E630, native fallback disabled.` if the constant drifts.
