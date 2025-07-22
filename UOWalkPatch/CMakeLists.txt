cmake_minimum_required(VERSION 3.10)
project(UOWalkPatch)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

# Static linking flags
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -static-libgcc -static-libstdc++")



add_executable(UOWalkPatch src/main.cpp)
target_include_directories(UOWalkPatch PRIVATE include)
target_link_libraries(UOWalkPatch PRIVATE psapi)

# Copy required JSON files to build directory
configure_file(${CMAKE_SOURCE_DIR}/signatures.json ${CMAKE_BINARY_DIR}/signatures.json COPYONLY)
configure_file(${CMAKE_SOURCE_DIR}/command_list.json ${CMAKE_BINARY_DIR}/command_list.json COPYONLY)
