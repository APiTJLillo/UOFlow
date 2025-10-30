cmake_minimum_required(VERSION 3.10)
project(UOWalkPatch)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Force 32-bit build
set(CMAKE_GENERATOR_PLATFORM Win32)
set_property(GLOBAL PROPERTY FIND_LIBRARY_USE_LIB32_PATHS TRUE)

# LuaPlus configuration
set(LUAPLUS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/external/luaplus")
set(LUAPLUS_INCLUDE_DIR "${LUAPLUS_ROOT}/include")

# Find lib.exe in Visual Studio Developer Command Prompt environment
find_program(VS_LIB_EXE lib REQUIRED)

# Generate import library at build time
add_custom_command(
    OUTPUT "${CMAKE_BINARY_DIR}/luaplus_1100.lib"
    COMMAND ${VS_LIB_EXE} /def:"${CMAKE_CURRENT_SOURCE_DIR}/luaplus.def" /machine:x86 /out:"${CMAKE_BINARY_DIR}/luaplus_1100.lib"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/luaplus.def"
    COMMENT "Generating LuaPlus import library"
)

add_custom_target(luaplus_import_lib
    DEPENDS "${CMAKE_BINARY_DIR}/luaplus_1100.lib"
)

set(LUAPLUS_LIBRARY "${CMAKE_BINARY_DIR}/luaplus_1100.lib")

add_subdirectory(external/minhook/src)

if(MSVC)
    # Force static runtime linking
    foreach(flag_var
        CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
        CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO)
        if(${flag_var} MATCHES "/MD")
            string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
        endif()
    endforeach()
    
    # Compiler flags
    add_compile_options(
        /EHa       # Enable SEH exceptions
        /MP        # Multi-processor compilation
        /wd4996   # Disable deprecation warnings
        /Zi        # Generate debug info
        /Gy       # Function-level linking
        /Gm-      # Disable minimal rebuild
        /GS-      # Disable buffer security check
        /GF       # String pooling
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

# Set output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

# Add the DLL project
add_library(UOWalkPatchDLL SHARED
    src/dllmain.cpp
    src/Core/Config.cpp
    src/Core/Logging.cpp
    src/Core/PatternScan.cpp
    src/Core/Utils.cpp
    src/Core/MinHookHelpers.cpp
    src/Core/CrashHandler.cpp
    src/Net/PacketTrace.cpp
    src/Net/SendBuilder.cpp
    src/Engine/GlobalState.cpp
    src/Engine/Movement.cpp
    src/Engine/LuaBridge.cpp
    src/Engine/lua_safe.cpp
    src/Engine/LuaStateRegistry.cpp
    src/Walk/WalkController.cpp
)

target_compile_definitions(UOWalkPatchDLL PRIVATE SAFE_LUA_API_GUARD=1)

target_include_directories(UOWalkPatchDLL PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/external/luaplus/include
)

target_link_libraries(UOWalkPatchDLL PRIVATE
    minhook
    psapi
    kernel32
    user32
    dbghelp
    ws2_32
    ${LUAPLUS_LIBRARY}
    delayimp
)
add_dependencies(UOWalkPatchDLL luaplus_import_lib)

# Delay-load LuaPlus so it can be loaded manually from our directory
target_link_options(UOWalkPatchDLL PRIVATE "/DELAYLOAD:luaplus_1100.dll")

# Set DLL properties
set_target_properties(UOWalkPatchDLL PROPERTIES
    RUNTIME_OUTPUT_NAME "UOWalkPatchDLL"
    PREFIX ""
)

# Copy LuaPlus DLL to output directory and injector directory
add_custom_command(
    TARGET UOWalkPatchDLL POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${LUAPLUS_ROOT}/luaplus_1100.dll"
        "$<TARGET_FILE_DIR:UOWalkPatchDLL>"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${LUAPLUS_ROOT}/luaplus_1100.dll"
        "${CMAKE_BINARY_DIR}/bin"
)

set(LUAPLUS_DLL "${CMAKE_SOURCE_DIR}/external/luaplus/luaplus_1100.dll")

add_custom_command(
  TARGET UOWalkPatchDLL
  POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${LUAPLUS_DLL}"
          "$<TARGET_FILE_DIR:UOWalkPatchDLL>/luaplus_1100.dll"
  COMMENT "Copying luaplus_1100.dll next to UOWalkPatchDLL"
)

target_link_libraries(UOWalkPatchDLL PRIVATE
    "${CMAKE_SOURCE_DIR}/external/luaplus/luaplus_1100.lib")

# Set DLL-specific flags
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
        /NODEFAULTLIB:msvcrt.lib
    >
)

# Add the injector executable
add_executable(UOInjector src/injector.cpp)

target_compile_features(UOInjector PRIVATE cxx_std_17)

target_link_libraries(UOInjector PRIVATE 
    kernel32 
    psapi
    user32
)

# Set injector properties
set_target_properties(UOInjector PROPERTIES
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)

target_link_options(UOInjector PRIVATE
    $<$<CONFIG:Debug>:
        /MACHINE:X86
        /SUBSYSTEM:CONSOLE
        /DEBUG:FULL
        /INCREMENTAL:NO
        /OPT:NOREF
        /OPT:NOICF
        /NODEFAULTLIB:msvcrt.lib
    >
    $<$<CONFIG:Release>:
        /MACHINE:X86
        /SUBSYSTEM:CONSOLE
        /DEBUG
        /INCREMENTAL:NO
        /OPT:REF
        /OPT:ICF
        /NODEFAULTLIB:msvcrt.lib
    >
)

# Copy signatures.json to multiple locations to ensure it's found
add_custom_command(
    TARGET UOWalkPatchDLL POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_CURRENT_SOURCE_DIR}/signatures.json"
        "$<TARGET_FILE_DIR:UOWalkPatchDLL>/signatures.json"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_CURRENT_SOURCE_DIR}/signatures.json"
        "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/signatures.json"
)

# Ensure the DLL is copied next to the injector
add_custom_command(
    TARGET UOInjector POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "$<TARGET_FILE:UOWalkPatchDLL>"
        "$<TARGET_FILE_DIR:UOInjector>"
)

add_executable(DumpAnalyzer tools/DumpAnalyzer.cpp)
target_link_libraries(DumpAnalyzer PRIVATE dbghelp)
set_target_properties(DumpAnalyzer PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
