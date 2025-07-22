#include "../include/stub_bin.h"

// Template for the remote thread
const unsigned char stub_template[] = {
    0x55,                         // push ebp
    0x89, 0xE5,                   // mov ebp, esp
    0x68, 0x00, 0x00, 0x00, 0x00, // push name ptr (patched)
    0x68, 0x00, 0x00, 0x00, 0x00, // push bridge ptr (patched)
    0x56,                         // push esi (lua_State*)
    0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, RegisterLuaFunction (patched)
    0xFF, 0xD0,                   // call eax
    0x83, 0xC4, 0x0C,             // add esp, 0xC
    0x5D,                         // pop ebp
    0xC2, 0x04, 0x00              // ret 4
};

const size_t stub_template_len = sizeof(stub_template);
const unsigned int STUB_NAME_OFF   = 4;
const unsigned int STUB_BRIDGE_OFF = 9;
const unsigned int STUB_STATE_OFF  = 14;
const unsigned int STUB_REG_OFF    = 15;

// Template for a bridge
const unsigned char bridge_template[] = {
    0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, <builtin>
    0xFF, 0xE0                    // jmp eax
};

const size_t bridge_template_len = sizeof(bridge_template);
const unsigned int BRIDGE_FUNC_OFF = 1;

// Hook stub template that captures Lua state from ESI
const unsigned char hook_stub_template[] = {
    // Save registers we'll use
    0x53,                         // push ebx
    0x56,                         // push esi
    0x57,                         // push edi
    
    // Save Lua state from ESI to global variable
    0xA3, 0x00, 0x00, 0x00, 0x00, // mov [lua_state_ptr], esi
    
    // Check if we already registered
    0xA1, 0x00, 0x00, 0x00, 0x00, // mov eax, [flag]
    0x85, 0xC0,                   // test eax, eax
    0x75, 0x31,                   // jnz skip_register
    
    // Set flag to indicate we've registered
    0xC7, 0x05,                  // mov dword ptr
    0x00, 0x00, 0x00, 0x00,      // [flag] (address patched)
    0x01, 0x00, 0x00, 0x00,      // 1
    
    // Setup for function registration loop
    0xB9, 0x00, 0x00, 0x00, 0x00, // mov ecx, numFuncs
    0xBF, 0x00, 0x00, 0x00, 0x00, // mov edi, funcs array
    0x85, 0xC9,                   // test ecx, ecx
    0x74, 0x17,                   // jz done
    
    // Registration loop
    0xFF, 0x37,                   // push dword ptr [edi]    ; name
    0xFF, 0x77, 0x04,            // push dword ptr [edi+4]  ; bridge
    0x56,                        // push esi                ; lua_State*
    0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, RegisterLuaFunction
    0xFF, 0xD0,                   // call eax
    0x83, 0xC7, 0x08,            // add edi, 8
    0x49,                        // dec ecx
    0x75, 0xED,                   // jnz back to loop start
    
    // Restore registers
    0x5F,                         // pop edi
    0x5E,                         // pop esi  
    0x5B,                         // pop ebx
    
    // Jump back to original code
    0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, return address
    0xFF, 0xE0                    // jmp eax
};

const size_t hook_stub_template_len = sizeof(hook_stub_template);