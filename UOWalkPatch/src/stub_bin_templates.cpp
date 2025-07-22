#include "../include/stub_bin.h"

const unsigned char stub_template[] = {
    0x55,
    0x89, 0xE5,
    0x68, 0x00, 0x00, 0x00, 0x00,
    0x68, 0x00, 0x00, 0x00, 0x00,
    0x56,
    0xB8, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xD0,
    0x83, 0xC4, 0x0C,
    0x5D,
    0xC2, 0x04, 0x00
};

const size_t stub_template_len = sizeof(stub_template);

const unsigned char bridge_template[] = {
    0xB8, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xE0
};

const size_t bridge_template_len = sizeof(bridge_template);

const unsigned char hook_stub_template[] = {
    // Proper function prologue
    0x55,                    // push ebp
    0x89, 0xE5,             // mov ebp, esp
    0x83, 0xEC, 0x24,       // sub esp, 24h
    0x53,                    // push ebx
    0x56,                    // push esi
    0x57,                    // push edi,

    // Get debug counter
    0xB8, 0x00, 0x00, 0x00, 0x00,    // mov eax, debug_counter_addr
    0x85, 0xC0,                       // test eax, eax
    0x74, 0x0A,                       // jz skip_counter
    0x8B, 0x08,                       // mov ecx, [eax]
    0x41,                             // inc ecx
    0x89, 0x08,                       // mov [eax], ecx
    // skip_counter:

    // Get lua state ptr
    0xB8, 0x00, 0x00, 0x00, 0x00,    // mov eax, lua_state_ptr_addr
    0x85, 0xC0,                       // test eax, eax
    0x74, 0x08,                       // jz skip_lua
    0x8B, 0x4D, 0x08,                // mov ecx, [ebp+8]
    0x89, 0x08,                       // mov [eax], ecx
    // skip_lua:

    // Call original function - preserve args
    0xFF, 0x75, 0x10,                // push dword [ebp+10h] ; arg3
    0xFF, 0x75, 0x0C,                // push dword [ebp+0Ch] ; arg2
    0xFF, 0x75, 0x08,                // push dword [ebp+08h] ; arg1
    0xB8, 0x00, 0x00, 0x00, 0x00,    // mov eax, RegisterLuaFunction
    0xFF, 0xD0,                       // call eax
    0x83, 0xC4, 0x0C,                // add esp, 0Ch

    // Epilogue - same as original function
    0x5F,                            // pop edi
    0x5E,                            // pop esi
    0x5B,                            // pop ebx
    0x89, 0xEC,                      // mov esp, ebp
    0x5D,                            // pop ebp
    0xC2, 0x0C, 0x00                 // ret 0Ch
};

const size_t hook_stub_template_len = sizeof(hook_stub_template);

const unsigned int STUB_NAME_OFF   = 4;
const unsigned int STUB_BRIDGE_OFF = 9;
const unsigned int STUB_STATE_OFF  = 14;
const unsigned int STUB_REG_OFF    = 15;

const unsigned int BRIDGE_FUNC_OFF = 1;