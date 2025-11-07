#pragma once

#include <cstdint>

struct SpellSenderOptions {
    bool enable = true;
    bool logCtx = true;
    int dumpBytes = 16;
    int maxHits = 64;
    int debounceMs = 25;
};

void SpellSenderDetour_Configure(const SpellSenderOptions& opts);
void SpellSenderDetour_EnsureArmed(uintptr_t entryAddr);
void SpellSenderDetour_Disarm();
