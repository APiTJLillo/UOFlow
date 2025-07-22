#include "../include/stub_bin.h"

// Implementation of hook stub offsets
const unsigned int HOOK_LUASTATE_OFF = 4;  // Offset of lua state ptr address
const unsigned int HOOK_FLAG_OFF   = 11;   // Offset of flag address
const unsigned int HOOK_NUM_OFF    = 30;   // Offset of number of functions
const unsigned int HOOK_FUNCS_OFF  = 35;   // Offset of functions array
const unsigned int HOOK_REG_OFF1   = 50;   // Offset of RegisterLuaFunction in loop
const unsigned int HOOK_REG_OFF2   = 50;   // Offset of RegisterLuaFunction in second call (same as first)
const unsigned int HOOK_RET_OFF    = 64;   // Offset of return address