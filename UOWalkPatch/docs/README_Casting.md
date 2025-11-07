# Casting Spell Probe Notes

1. **Find the helper frame.**
   - Enable stack capture for spell packets by setting `TRACE_PACKET_STACKS=1`.
   - Restrict to the cast request with `TRACE_PACKET_ID_FILTER=0xDA` (use `0x2E` when you want the targeting/cursor path).
   - Cast once from the spellbook and watch the `[PacketTrace] … UOSA.exe+0xXXXXXXXX` frames; grab the first non-system `UOSA.exe+offset` that follows `send id=DA`.

2. **Aim the RET-probe.**
   - Keep `UOW_DEBUG_ENABLE=1` (dev profile only) and add these keys to `uowalkpatch.cfg`:
     ```
     SPELL_PROBE_ENABLE=1
     SPELL_PROBE_ADDR=UOSA.exe+0x6A3528    # replace with the offset you copied
     SPELL_PROBE_ARGS=4                    # how many dwords from [ESP+4..]
     SPELL_PROBE_HITS=16                   # auto-quiet after N entries
     SPELL_PROBE_RATE_MS=50                # debounce window
     ```
   - Restart the helper; the log should show `[spell.probe] RET-probe armed …`.

3. **Correlate with packet tracing.**
   - When the address is correct you should see a block like:
     ```
     [SpellProbe:ENTER] eip=... ecx=... arg0=...
     [PacketTrace] send id=DA len=...
     [SpellProbe:LEAVE] retSite=... EAX=...
     ```
   - If you only see `ENTER`, move the probe one frame up/down the captured stack and try again.

4. **Switch between cast vs target helpers.**
   - Keep `SPELL_PROBE_ADDR` pointed at the `UOSA.exe+offset` that matches the packet you are chasing.
   - Flip `TRACE_PACKET_ID_FILTER` between `0xDA` (spell cast) and `0x2E` (target/cursor) to rediscover the right helper frame before re-arming the probe.
