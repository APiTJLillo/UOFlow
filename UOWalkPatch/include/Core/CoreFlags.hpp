#pragma once

#include <windows.h>

struct CoreFlags {
    volatile LONG lua_slot_seen = 0;
    volatile LONG lua_tracer_attached = 0;
    volatile LONG lua_reg_seen = 0;
};

extern CoreFlags g_flags;
