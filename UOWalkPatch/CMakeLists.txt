# UOWalkPatch CMake configuration
cmake_minimum_required(VERSION 3.10)
project(UOWalkPatch)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add Windows-specific compile definitions
add_definitions(-DWIN32 -D_WINDOWS)

# Configure MSVC-specific options
if(MSVC)
    # Remove any existing /EHsc flags
    string(REPLACE "/EHsc" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
    
    # Add our own exception handling flags
    add_compile_options(/EHa)
    
    # Disable specific warnings
    add_compile_options(/wd4996)
    
    # Enable multi-threaded compilation
    add_compile_options(/MP)
    
    # Additional MSVC-specific flags
    add_compile_definitions(
        _CRT_SECURE_NO_WARNINGS
        _CRT_NONSTDC_NO_WARNINGS
        NOMINMAX
        WIN32_LEAN_AND_MEAN
    )
endif()

# Set source files
set(SOURCES
    src/main.cpp
    src/main_impl.cpp
    src/uowalkpatch.cpp
    src/stub_bin_templates.cpp
)

# Create executable
add_executable(UOWalkPatch ${SOURCES})

# Include directories - add both include and src directories
target_include_directories(UOWalkPatch PRIVATE 
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

# Link libraries
target_link_libraries(UOWalkPatch PRIVATE psapi)

# Force 32-bit linker
if(MSVC)
    set_target_properties(UOWalkPatch PROPERTIES LINK_FLAGS "/MACHINE:X86")
endif()

# Copy required JSON files to build directory
configure_file(${CMAKE_SOURCE_DIR}/signatures.json ${CMAKE_BINARY_DIR}/signatures.json COPYONLY)
configure_file(${CMAKE_SOURCE_DIR}/command_list.json ${CMAKE_BINARY_DIR}/command_list.json COPYONLY)

# Assemble bridges.asm to object file
if(MSVC)
    set(BRIDGES_OBJ ${CMAKE_CURRENT_BINARY_DIR}/bridges.obj)
    add_custom_command(
        OUTPUT ${BRIDGES_OBJ}
        COMMAND ml.exe /c /Fo${BRIDGES_OBJ} ${CMAKE_SOURCE_DIR}/src/bridges.asm
        DEPENDS ${CMAKE_SOURCE_DIR}/src/bridges.asm
        COMMENT "Assembling bridges.asm"
    )
    set_source_files_properties(${BRIDGES_OBJ} PROPERTIES EXTERNAL_OBJECT TRUE)
    list(APPEND SOURCES ${BRIDGES_OBJ})
endif()
