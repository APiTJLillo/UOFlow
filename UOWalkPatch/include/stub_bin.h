#pragma once

// Template for the remote thread that hooks Lua registration
extern const unsigned char hook_stub_template[];
extern const size_t hook_stub_template_len;

// Template for a bridge function that handles Lua calls
extern const unsigned char bridge_template[];
extern const size_t bridge_template_len;
extern const unsigned int BRIDGE_FUNC_OFF;  // Offset where function pointer is patched

// Template for the stub that calls original RegisterLuaFunction
extern const unsigned char stub_template[];
extern const size_t stub_template_len;
extern const unsigned int STUB_NAME_OFF;   // Offset where name pointer is patched
extern const unsigned int STUB_BRIDGE_OFF;  // Offset where bridge pointer is patched
extern const unsigned int STUB_STATE_OFF;   // Offset where Lua state is passed
extern const unsigned int STUB_REG_OFF;     // Offset where RegisterLuaFunction is called

// Hook stub offsets - declared here but defined in stub_bin_impl.cpp
extern const unsigned int HOOK_LUASTATE_OFF; // Offset where Lua state ptr is saved
extern const unsigned int HOOK_FLAG_OFF;     // Offset where hook state flag is checked/set
extern const unsigned int HOOK_NUM_OFF;      // Offset where number of functions is set
extern const unsigned int HOOK_FUNCS_OFF;    // Offset where function array pointer is set
extern const unsigned int HOOK_REG_OFF1;     // Offset where RegisterLuaFunction is called (first)
extern const unsigned int HOOK_REG_OFF2;     // Offset where RegisterLuaFunction is called (second)
extern const unsigned int HOOK_RET_OFF;      // Offset where return address is set