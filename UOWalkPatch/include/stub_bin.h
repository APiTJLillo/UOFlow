#pragma once

// Template for the remote thread that hooks Lua registration
extern const unsigned char hook_stub_template [];
extern const size_t hook_stub_template_len;

// Template for a bridge function that handles Lua calls
extern const unsigned char bridge_template [];
extern const size_t bridge_template_len;
extern const unsigned int BRIDGE_FUNC_OFF;  // Offset where function pointer is patched

// Template for the stub that calls original RegisterLuaFunction
extern const unsigned char stub_template [];
extern const size_t stub_template_len;
extern const unsigned int STUB_NAME_OFF;   // Offset where name pointer is patched
extern const unsigned int STUB_BRIDGE_OFF;  // Offset where bridge pointer is patched
extern const unsigned int STUB_STATE_OFF;   // Offset where Lua state is passed
extern const unsigned int STUB_REG_OFF;     // Offset where RegisterLuaFunction is called

// Hook stub offsets - updated for memory-safe version
extern const unsigned int HOOK_DEBUG_OFF;     // Offset of debug counter address
extern const unsigned int HOOK_LUASTATE_OFF;  // Offset of lua state address
extern const unsigned int HOOK_REG_OFF1;      // Offset of RegisterLuaFunction address
