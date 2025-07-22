#pragma once

// Template for the remote thread. Addresses for the string name, bridge
// function, lua_State pointer and RegisterLuaFunction are patched in at
// runtime before the stub is written to the remote process.
static const unsigned char stub_template[] = {
    0x55, 0x89, 0xE5,                         // push ebp; mov ebp, esp
    0x68, 0x00, 0x00, 0x00, 0x00,             // push name ptr (patched)
    0x68, 0x00, 0x00, 0x00, 0x00,             // push bridge ptr (patched)
    0x68, 0x00, 0x00, 0x00, 0x00,             // push lua_State* (patched)
    0xB8, 0x00, 0x00, 0x00, 0x00,             // mov eax, RegisterLuaFunction (patched)
    0xFF, 0xD0,                               // call eax
    0x83, 0xC4, 0x0C,                         // add esp, 0xC
    0x5D,                                     // pop ebp
    0xC2, 0x04, 0x00                          // ret 4
};

static const unsigned int STUB_NAME_OFF   = 4;
static const unsigned int STUB_BRIDGE_OFF = 9;
static const unsigned int STUB_STATE_OFF  = 14;
static const unsigned int STUB_REG_OFF    = 19;
static const unsigned int stub_template_len = sizeof(stub_template);

// Template for a bridge that simply jumps to a builtin function. The builtin
// address is patched at runtime.
static const unsigned char bridge_template[] = {
    0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, <builtin>
    0xFF, 0xE0                    // jmp eax
};

static const unsigned int BRIDGE_FUNC_OFF = 1;
static const unsigned int bridge_template_len = sizeof(bridge_template);

// Hook stub that intercepts the RegisterLuaFunction call during client
// startup. It first calls the original function, then registers a list of
// additional natives using the same lua_State pointer. The stub executes only
// once thanks to a flag stored in remote memory.
static const unsigned char hook_stub_template[] = {
    0x53,                         // push ebx
    0x57,                         // push edi
    0x89, 0xF3,                   // mov  ebx, esi
    0xB8, 0,0,0,0,                // mov  eax, RegisterLuaFunction (patched)
    0xFF, 0xD0,                   // call eax
    0x89, 0xDE,                   // mov  esi, ebx
    0xA1, 0,0,0,0,                // mov  eax, [executed flag] (patched)
    0x83, 0x38, 0x00,             // cmp  dword ptr [eax], 0
    0x75, 0x27,                   // jne  skip_register
    0xC7, 0x00, 0x01,0x00,0x00,0x00, // mov dword ptr [eax],1
    0xB9, 0,0,0,0,                // mov  ecx, numFuncs (patched)
    0xBF, 0,0,0,0,                // mov  edi, funcs array (patched)
    0x85, 0xC9,                   // test ecx, ecx
    0x74, 0x13,                   // jz   done
    0xFF, 0x37,                   // push dword ptr [edi]
    0xFF, 0x77, 0x04,             // push dword ptr [edi+4]
    0x56,                         // push esi
    0xB8, 0,0,0,0,                // mov  eax, RegisterLuaFunction (patched)
    0xFF, 0xD0,                   // call eax
    0x83, 0xC7, 0x08,             // add  edi, 8
    0x49,                         // dec  ecx
    0x75, 0xE9,                   // jnz  loop
    0x5F,                         // done: pop edi
    0x5B,                         // pop ebx
    0xB8, 0,0,0,0,                // mov  eax, return address (patched)
    0xFF, 0xE0                    // jmp  eax
};

static const unsigned int HOOK_REG_OFF1   = 5;
static const unsigned int HOOK_FLAG_OFF   = 14;
static const unsigned int HOOK_NUM_OFF    = 30;
static const unsigned int HOOK_FUNCS_OFF  = 35;
static const unsigned int HOOK_REG_OFF2   = 50;
static const unsigned int HOOK_RET_OFF    = 65;
static const unsigned int hook_stub_template_len = sizeof(hook_stub_template);
