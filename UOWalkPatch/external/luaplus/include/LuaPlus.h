#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef struct lua_State lua_State;

// Type definitions
#define LUA_TNONE           (-1)
#define LUA_TNIL            0
#define LUA_TBOOLEAN        1
#define LUA_TLIGHTUSERDATA  2
#define LUA_TNUMBER         3
#define LUA_TSTRING         4
#define LUA_TTABLE          5
#define LUA_TFUNCTION       6
#define LUA_TUSERDATA       7
#define LUA_TTHREAD         8

// Core API functions
int lua_gettop(lua_State* L);
void lua_settop(lua_State* L, int idx);
const char* lua_typename(lua_State* L, int tp);
int lua_type(lua_State* L, int idx);

// Push operations
void lua_pushnil(lua_State* L);
void lua_pushnumber(lua_State* L, double n);
void lua_pushstring(lua_State* L, const char* s);
void lua_pushboolean(lua_State* L, int b);

// Get operations
int lua_toboolean(lua_State* L, int idx);
long lua_tointeger(lua_State* L, int idx);
const char* lua_tostring(lua_State* L, int idx);
void* lua_touserdata(lua_State* L, int idx);

// Table operations
void lua_createtable(lua_State* L, int narr, int nrec);
void lua_getfield(lua_State* L, int idx, const char* k);
void lua_setfield(lua_State* L, int idx, const char* k);
void lua_rawget(lua_State* L, int idx);
void lua_rawset(lua_State* L, int idx);
void lua_rawgeti(lua_State* L, int idx, int n);
void lua_rawseti(lua_State* L, int idx, int n);
int lua_setmetatable(lua_State* L, int objindex);
int lua_getmetatable(lua_State* L, int objindex);

// Userdata operations
void* lua_newuserdata(lua_State* L, size_t size);

// Function operations
int lua_pcall(lua_State* L, int nargs, int nresults, int errfunc);

// LuaPlus specific function declarations
typedef bool (__stdcall *RegisterLuaFunction_t)(lua_State* L, void* func, const char* name);

#ifdef __cplusplus
}
#endif

// C++ wrapper (optional, can be expanded as needed)
namespace LuaPlus {
    typedef lua_State State;
}
