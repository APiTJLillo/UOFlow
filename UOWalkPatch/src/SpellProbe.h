#pragma once

#include <cstdint>

uintptr_t ResolveModulePlusOffset(const char* spec);
void SpellProbe_Install(uintptr_t entry, int nArgs, int maxHits, int rateMs);
void SpellProbe_Remove();
