#pragma once
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

	/* Define LUA_API to dllimport when linking the import lib */
#ifndef LUA_API
#  ifdef _MSC_VER
#    define LUA_API __declspec(dllimport)
#  else
#    define LUA_API
#  endif
#endif

	typedef struct lua_State lua_State;

	/* type tags */
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

	typedef double lua_Number;
	typedef int    lua_Integer;

	/* Prototypes (match C API; use cdecl by default on MSVC) */
	LUA_API int          lua_gettop(lua_State* L);
	LUA_API void         lua_settop(lua_State* L, int idx);
	LUA_API const char* lua_typename(lua_State* L, int tp);
	LUA_API int          lua_type(lua_State* L, int idx);

	LUA_API void         lua_pushnil(lua_State* L);
	LUA_API void         lua_pushnumber(lua_State* L, double n);
	LUA_API void         lua_pushstring(lua_State* L, const char* s);
	LUA_API void         lua_pushboolean(lua_State* L, int b);

	LUA_API int          lua_toboolean(lua_State* L, int idx);
	LUA_API int          lua_tointeger(lua_State* L, int idx);   /* LuaPlus 5.1 uses int */
	LUA_API const char* lua_tostring(lua_State* L, int idx);
	LUA_API void* lua_touserdata(lua_State* L, int idx);

	LUA_API void         lua_createtable(lua_State* L, int narr, int nrec);
	LUA_API void         lua_getfield(lua_State* L, int idx, const char* k);
	LUA_API void         lua_setfield(lua_State* L, int idx, const char* k);
	LUA_API void         lua_rawget(lua_State* L, int idx);
	LUA_API void         lua_rawset(lua_State* L, int idx);
	LUA_API void         lua_rawgeti(lua_State* L, int idx, int n);
	LUA_API void         lua_rawseti(lua_State* L, int idx, int n);
	LUA_API int          lua_setmetatable(lua_State* L, int objindex);
	LUA_API int          lua_getmetatable(lua_State* L, int objindex);

	LUA_API void* lua_newuserdata(lua_State* L, size_t size);

	LUA_API int          lua_pcall(lua_State* L, int nargs, int nresults, int errfunc);

	/* Project-specific; keep cdecl */
	typedef int(__cdecl* RegisterLuaFunction_t)(lua_State* L, void* func, const char* name);

#ifdef __cplusplus
}
#endif
