# Minimum CMake version / project meta
cmake_minimum_required(VERSION 3.10)
project(UOWalkPatch LANGUAGES C CXX)

# ???????????????????????????????????????????????????????????????
# Build settings
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Force 32?bit tool?chain ("Win32")
set(CMAKE_GENERATOR_PLATFORM Win32)
set_property(GLOBAL PROPERTY FIND_LIBRARY_USE_LIB32_PATHS TRUE)

# ???????????????????????????????????????????????????????????????
# MSVC?specific flags
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
    /MP         # Multi?processor compilation
    /wd4996     # Disable deprecated?API warnings
    /Zi         # Generate PDBs
    /Gy         # Function?level linking
    /Gm-        # Disable minimal rebuild
    /GS-        # Disable buffer security check
    /GF         # String pooling
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

# ???????????????????????????????????????????????????????????????
# Output directories (one place for all artefacts)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ???????????????????????????????????????????????????????????????
# Third?party : LuaPlus 1100 (pre?built DLL + import?lib)
set(LUAPLUS_ROOT "${CMAKE_CURRENT_LIST_DIR}/libs")
set(LUAPLUS_INCLUDE "${LUAPLUS_ROOT}/luaplus/lua51-luaplus/src")

add_library(LuaPlus1100 SHARED IMPORTED)
set_target_properties(LuaPlus1100 PROPERTIES
  IMPORTED_LOCATION "${LUAPLUS_ROOT}/luaplus_1100.dll"
  IMPORTED_IMPLIB   "${LUAPLUS_ROOT}/luaplus_1100.lib"
  INTERFACE_INCLUDE_DIRECTORIES "${LUAPLUS_INCLUDE}"
)

# ???????????????????????????????????????????????????????????????
# DLL project
add_library(UOWalkPatchDLL SHARED
  src/dllmain.cpp
  src/minhook.cpp
)

# Header search paths for our DLL
#   • src             : project headers
#   • LUAPLUS_INCLUDE : libs/luaplus/src ? contains "Lua/" sub?folder
#   • ${LUAPLUS_INCLUDE}/Lua : allow "lua.h" directly if you ever change includes
# You can drop the last entry if you always include via "Lua/lua.h".

target_include_directories(UOWalkPatchDLL PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${LUAPLUS_INCLUDE}
  ${LUAPLUS_INCLUDE}/Lua
)

target_link_libraries(UOWalkPatchDLL PRIVATE
  LuaPlus1100            # new dependency
  psapi kernel32 user32
)

# Copy LuaPlus DLL next to our DLL for easy debugging / install
add_custom_command(TARGET UOWalkPatchDLL POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${LUAPLUS_ROOT}/luaplus_1100.dll"
          "$<TARGET_FILE_DIR:UOWalkPatchDLL>"
)

set_target_properties(UOWalkPatchDLL PROPERTIES
  RUNTIME_OUTPUT_NAME "UOWalkPatchDLL"
  PREFIX ""
)

# Linker flags per?configuration (kept from your original setup)
target_link_options(UOWalkPatchDLL PRIVATE
  $<$<CONFIG:Debug>:
    /SUBSYSTEM:WINDOWS /SAFESEH:NO /NXCOMPAT:NO /MACHINE:X86 /DEBUG:FULL
    /INCREMENTAL:NO /OPT:NOREF /OPT:NOICF /NODEFAULTLIB:msvcrt.lib
  >
  $<$<CONFIG:Release>:
    /SUBSYSTEM:WINDOWS /SAFESEH:NO /NXCOMPAT:NO /MACHINE:X86 /DEBUG
    /INCREMENTAL:NO /OPT:REF /OPT:ICF /NODEFAULTLIB:msvcrt.lib
  >
)

# ???????????????????????????????????????????????????????????????
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

# ???????????????????????????????????????????????????????????????
# Runtime assets
add_custom_command(TARGET UOWalkPatchDLL POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${CMAKE_CURRENT_SOURCE_DIR}/signatures.json"
          "$<TARGET_FILE_DIR:UOWalkPatchDLL>/signatures.json"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${CMAKE_CURRENT_SOURCE_DIR}/signatures.json"
          "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/signatures.json"
)

add_custom_command(TARGET UOInjector POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "$<TARGET_FILE:UOWalkPatchDLL>"
          "$<TARGET_FILE_DIR:UOInjector>"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${LUAPLUS_ROOT}/luaplus_1100.dll"
          "$<TARGET_FILE_DIR:UOInjector>"
)
