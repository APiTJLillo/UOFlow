; Minimal bridge for walk(dir, run) to be called from Lua
; This is x86, stdcall, for use in the injected stub
; Arguments: int dir (lua arg 1), int run (lua arg 2)
; Calls the real walk function (address patched in by injector)

section .text
    global walk_bridge
    global regfunc_trampoline

section .data
    walk_func_ptr: dd 0
    reg_msg: db '[UOWalkPatch] Registered native: ',0

    extern printf

walk_bridge:
    push    ebp
    mov     ebp, esp
    sub     esp, 8
    
    ; get lua_State* from [esp+8] (stdcall)
    mov     eax, [ebp+8]
    
    ; get dir (lua arg 1)
    push    1
    push    eax
    call    lua_tointeger
    add     esp, 8
    mov     [ebp-4], eax
    
    ; get run (lua arg 2)
    push    2
    push    [ebp+8]
    call    lua_tointeger
    add     esp, 8
    mov     [ebp-8], eax
    
    ; call the real walk function: walk(dir, run)
    mov     eax, [walk_func_ptr] ; patched by injector
    mov     ecx, [ebp-4]         ; dir
    mov     edx, [ebp-8]         ; run
    push    edx
    push    ecx
    call    eax
    
    ; log registration (for stub registration loop)
    push    dword [ebp+8] ; push lua_State* (for printf, not strictly needed)
    push    reg_msg
    call    printf
    add     esp, 8
    
    xor     eax, eax ; return 0 to Lua
    mov     esp, ebp
    pop     ebp
    ret     4

section .text

; regfunc_trampoline(lua_State*, name, bridge)
regfunc_trampoline:
    push    ebp
    mov     ebp, esp
    sub     esp, 8
    
    ; log registration attempt
    push    dword [ebp+0C] ; name
    push    reg_msg
    call    printf
    add     esp, 8
    
    ; call real RegisterLuaFunction
    mov     eax, [real_regfunc_ptr]
    push    dword [ebp+10] ; bridge
    push    dword [ebp+0C] ; name
    push    dword [ebp+8]  ; lua_State*
    call    eax
    
    mov     esp, ebp
    pop     ebp
    ret     0C

section .data
    real_regfunc_ptr: dd 0
    reg_msg: db '[UOWalkPatch] RegisterLuaFunction: %s', 10, 0
