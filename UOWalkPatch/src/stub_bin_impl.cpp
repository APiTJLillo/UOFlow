#include "../include/stub_bin.h"

// Hook stub offsets implementation
const unsigned int HOOK_DEBUG_OFF     = 9;     // offset of debug counter address
const unsigned int HOOK_LUASTATE_OFF  = 23;    // offset of lua state address
const unsigned int HOOK_REG_OFF1      = 43;    // offset of RegisterLuaFunction address