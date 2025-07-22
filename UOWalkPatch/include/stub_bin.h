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

static const unsigned char bridge_stub[] = { 0x31, 0xC0, 0xC3 }; // xor eax,eax; ret
static const unsigned int bridge_stub_len = sizeof(bridge_stub);
