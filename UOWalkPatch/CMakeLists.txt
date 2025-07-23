cmake_minimum_required(VERSION 3.10)
project(UOWalkPatch)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_definitions(-DWIN32 -D_WINDOWS)

if(MSVC)
    string(REPLACE "/EHsc" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
    add_compile_options(/EHa /MP /wd4996)
    add_compile_definitions(
        _CRT_SECURE_NO_WARNINGS
        _CRT_NONSTDC_NO_WARNINGS
        NOMINMAX
        WIN32_LEAN_AND_MEAN
    )
endif()

set(DLL_SOURCES
    src/dllmain.cpp
    src/minhook.cpp
)
add_library(UOWalkPatchDLL SHARED ${DLL_SOURCES})
target_include_directories(UOWalkPatchDLL PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(UOWalkPatchDLL PRIVATE psapi)

add_executable(UOInjector src/injector.cpp)
target_link_libraries(UOInjector PRIVATE kernel32 psapi)

if(MSVC)
    set_target_properties(UOWalkPatchDLL PROPERTIES LINK_FLAGS "/MACHINE:X86")
    set_target_properties(UOInjector PROPERTIES LINK_FLAGS "/MACHINE:X86")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /MACHINE:X86")
endif()
