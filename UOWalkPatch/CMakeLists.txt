cmake_minimum_required(VERSION 3.10)
project(UOWalkPatch)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Force 32-bit build
set(CMAKE_GENERATOR_PLATFORM Win32)
set_property(GLOBAL PROPERTY FIND_LIBRARY_USE_LIB32_PATHS TRUE)
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
    src/Core/Logging.cpp
    src/Core/PatternScan.cpp
    src/Core/Utils.cpp
    src/Net/PacketTrace.cpp
    src/Net/SendBuilder.cpp
    src/Engine/GlobalState.cpp
    src/Engine/Movement.cpp
    src/Engine/LuaBridge.cpp
)

target_include_directories(UOWalkPatchDLL PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(UOWalkPatchDLL PRIVATE
    minhook
    psapi
    kernel32
    user32
    dbghelp
    ws2_32
)

# Set DLL properties
set_target_properties(UOWalkPatchDLL PROPERTIES
    RUNTIME_OUTPUT_NAME "UOWalkPatchDLL"
    PREFIX ""
)

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