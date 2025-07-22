#pragma once

// Declare external variables
extern const unsigned char stub_template[];
extern const size_t stub_template_len;
extern const unsigned int STUB_NAME_OFF;
extern const unsigned int STUB_BRIDGE_OFF;
extern const unsigned int STUB_STATE_OFF;
extern const unsigned int STUB_REG_OFF;

extern const unsigned char bridge_template[];
extern const size_t bridge_template_len;
extern const unsigned int BRIDGE_FUNC_OFF;

extern const unsigned char hook_stub_template[];
extern const size_t hook_stub_template_len;
extern const unsigned int HOOK_REG_OFF1;
extern const unsigned int HOOK_FLAG_OFF;
extern const unsigned int HOOK_NUM_OFF;
extern const unsigned int HOOK_FUNCS_OFF;
extern const unsigned int HOOK_REG_OFF2;
extern const unsigned int HOOK_RET_OFF;