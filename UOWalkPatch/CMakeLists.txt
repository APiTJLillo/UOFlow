cmake_minimum_required(VERSION 3.10)
project(UOWalkPatch LANGUAGES C CXX)

# ---------------------------------------------------------------
# Build settings
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Force 32-bit tool-chain ("Win32")
set(CMAKE_GENERATOR_PLATFORM Win32)
set_property(GLOBAL PROPERTY FIND_LIBRARY_USE_LIB32_PATHS TRUE)

# ---------------------------------------------------------------
# MSVC-specific flags
if(MSVC)
  # Link the static CRT (/MT, /MTd)
  foreach(flag_var
          CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE
          CMAKE_C_FLAGS_MINSIZEREL CMAKE_C_FLAGS_RELWITHDEBINFO
          CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
          CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO)
    if(${flag_var} MATCHES "/MD")
      string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
    endif()
  endforeach()

  add_compile_options(
    /EHa        # Enable SEH + C++ exceptions
    /MP         # Multi-processor compilation
    /wd4996     # Disable deprecated-API warnings
    /Zi         # Generate PDBs
    /Gy         # Function-level linking
    /Gm-        # Disable minimal rebuild
    /GS         # Enable buffer security checks
    /GF         # String pooling
    /GT         # Enable fiber-safe TLS accesses 
  )

  add_compile_definitions(
    _CRT_SECURE_NO_WARNINGS
    _CRT_NONSTDC_NO_WARNINGS
    NOMINMAX
    WIN32_LEAN_AND_MEAN
    UNICODE
    _UNICODE
  )
endif()

# ---------------------------------------------------------------
# Output directories (one place for all artefacts)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ---------------------------------------------------------------
# Third-party : LuaPlus source build
add_library(lua51 STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/libs/luaplus/lua51-luaplus/src/lapi.c
  ${CMAKE_CURRENT_SOURCE_DIR}/libs/luaplus/lua51-luaplus/src/lauxlib.c
  ${CMAKE_CURRENT_SOURCE_DIR}/libs/luaplus/lua51-luaplus/src/lbaselib.c
  ${CMAKE_CURRENT_SOURCE_DIR}/libs/luaplus/lua51-luaplus/src/lcode.c
  ${CMAKE_CURRENT_SOURCE_DIR}/libs/luaplus/lua51-luaplus/src/ldblib.c
  ${CMAKE_CURRENT_SOURCE_DIR}/libs/luaplus/lua51-luaplus/src/ldebug.c
  ${CMAKE_CURRENT_SOURCE_DIR}/libs/luaplus/lua51-luaplus/src/ldo.c
  ${CMAKE_CURRENT_SOURCE_DIR}/libs/luaplus/lua51-luaplus/src/ldump.c
  ${CMAKE_CURRENT_SOURCE_DIR}/libs/luaplus/lua51-luaplus/src/lfunc.c
  ${CMAKE_CURRENT_SOURCE_DIR}/libs/luaplus/lua51-luaplus/src/lgc.c
  ${CMAKE_CURRENT_SOURCE_DIR}/libs/luaplus/lua51-luaplus/src/linit.c
  ${CMAKE_CURRENT_SOURCE_DIR}/libs/luaplus/lua51-luaplus/src/liolib.c
  ${CMAKE_CURRENT_SOURCE_DIR}/libs/luaplus/lua51-luaplus/src/llex.c
  ${CMAKE_CURRENT_SOURCE_DIR}/libs/luaplus/lua51-luaplus/src/lmathlib.c
  ${CMAKE_CURRENT_SOURCE_DIR}/libs/luaplus/lua51-luaplus/src/lmem.c
  ${CMAKE_CURRENT_SOURCE_DIR}/libs/luaplus/lua51-luaplus/src/loadlib.c
  ${CMAKE_CURRENT_SOURCE_DIR}/libs/luaplus/lua51-luaplus/src/lobject.c
  ${CMAKE_CURRENT_SOURCE_DIR}/libs/luaplus/lua51-luaplus/src/lopcodes.c
  ${CMAKE_CURRENT_SOURCE_DIR}/libs/luaplus/lua51-luaplus/src/loslib.c
  ${CMAKE_CURRENT_SOURCE_DIR}/libs/luaplus/lua51-luaplus/src/lparser.c
  ${CMAKE_CURRENT_SOURCE_DIR}/libs/luaplus/lua51-luaplus/src/lstate.c
  ${CMAKE_CURRENT_SOURCE_DIR}/libs/luaplus/lua51-luaplus/src/lstring.c
  ${CMAKE_CURRENT_SOURCE_DIR}/libs/luaplus/lua51-luaplus/src/lstrlib.c
  ${CMAKE_CURRENT_SOURCE_DIR}/libs/luaplus/lua51-luaplus/src/ltable.c
  ${CMAKE_CURRENT_SOURCE_DIR}/libs/luaplus/lua51-luaplus/src/ltablib.c
  ${CMAKE_CURRENT_SOURCE_DIR}/libs/luaplus/lua51-luaplus/src/ltm.c
  ${CMAKE_CURRENT_SOURCE_DIR}/libs/luaplus/lua51-luaplus/src/lundump.c
  ${CMAKE_CURRENT_SOURCE_DIR}/libs/luaplus/lua51-luaplus/src/lvm.c
  ${CMAKE_CURRENT_SOURCE_DIR}/libs/luaplus/lua51-luaplus/src/lzio.c
)

target_include_directories(lua51 PUBLIC 
  ${CMAKE_CURRENT_SOURCE_DIR}/libs/luaplus/lua51-luaplus/src
)

# Add compile definitions for Lua library
target_compile_definitions(lua51 PRIVATE 
  LUA_BUILD_AS_DLL
  _CRT_SECURE_NO_WARNINGS
)

# ---------------------------------------------------------------
# DLL project
add_library(UOWalkPatchDLL SHARED
  src/dllmain.cpp
  src/minhook.cpp
)

target_include_directories(UOWalkPatchDLL PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/libs/luaplus/lua51-luaplus/src
)

target_link_libraries(UOWalkPatchDLL PRIVATE
  lua51
  psapi kernel32 user32
)

# Copy required assets next to our DLL
add_custom_command(TARGET UOWalkPatchDLL POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${CMAKE_CURRENT_SOURCE_DIR}/signatures.json"
          "$<TARGET_FILE_DIR:UOWalkPatchDLL>/signatures.json"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${CMAKE_CURRENT_SOURCE_DIR}/command_list.json"
          "$<TARGET_FILE_DIR:UOWalkPatchDLL>/command_list.json"
)

set_target_properties(UOWalkPatchDLL PROPERTIES
  RUNTIME_OUTPUT_NAME "UOWalkPatchDLL"
  PREFIX ""
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"  # Force static runtime
)

# Linker flags per-configuration
target_link_options(UOWalkPatchDLL PRIVATE
  $<$<CONFIG:Debug>:
    /SUBSYSTEM:WINDOWS 
    /SAFESEH:NO 
    /NXCOMPAT:NO 
    /MACHINE:X86 
    /DEBUG:FULL
    /INCREMENTAL:NO 
    /OPT:NOREF 
    /OPT:NOICF 
    /DYNAMICBASE:NO  # Disable ASLR
    /NODEFAULTLIB:msvcrt.lib
  >
  $<$<CONFIG:Release>:
    /SUBSYSTEM:WINDOWS 
    /SAFESEH:NO 
    /NXCOMPAT:NO 
    /MACHINE:X86 
    /DEBUG
    /INCREMENTAL:NO 
    /OPT:REF 
    /OPT:ICF 
    /DYNAMICBASE:NO  # Disable ASLR
    /NODEFAULTLIB:msvcrt.lib
  >
)

# ---------------------------------------------------------------
# Injector executable
add_executable(UOInjector src/injector.cpp)

target_compile_features(UOInjector PRIVATE cxx_std_17)

target_link_libraries(UOInjector PRIVATE
  kernel32 psapi user32
)

set_target_properties(UOInjector PROPERTIES
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)

target_link_options(UOInjector PRIVATE
  $<$<CONFIG:Debug>:
    /MACHINE:X86 /SUBSYSTEM:CONSOLE /DEBUG:FULL /INCREMENTAL:NO /OPT:NOREF /OPT:NOICF /NODEFAULTLIB:msvcrt.lib
  >
  $<$<CONFIG:Release>:
    /MACHINE:X86 /SUBSYSTEM:CONSOLE /DEBUG /INCREMENTAL:NO /OPT:REF /OPT:ICF /NODEFAULTLIB:msvcrt.lib
  >
)

# ---------------------------------------------------------------
# Copy DLLs and assets to injector directory as well
add_custom_command(TARGET UOInjector POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "$<TARGET_FILE:UOWalkPatchDLL>"
          "$<TARGET_FILE_DIR:UOInjector>"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${CMAKE_CURRENT_SOURCE_DIR}/signatures.json"
          "$<TARGET_FILE_DIR:UOInjector>/signatures.json"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${CMAKE_CURRENT_SOURCE_DIR}/command_list.json"
          "$<TARGET_FILE_DIR:UOInjector>/command_list.json"
)
