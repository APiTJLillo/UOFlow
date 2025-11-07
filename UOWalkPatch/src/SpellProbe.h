#pragma once

#include <cstdint>

uintptr_t ResolveModulePlusOffset(const char* spec);

void SpellProbe_SetDefaults(int argCount, int maxHits, int debounceMs);
void SpellProbe_EnsureArmed(uintptr_t entry);
void SpellProbe_DisarmAll();

// Legacy manual entry-points (still exposed for direct configuration, but
// most callers should prefer the helpers above).
void SpellProbe_Install(uintptr_t entry, int nArgs, int maxHits, int rateMs);
void SpellProbe_Remove();
