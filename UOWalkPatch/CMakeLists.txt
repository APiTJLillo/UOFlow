cmake_minimum_required(VERSION 3.10)
project(UOWalkPatch)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(UOWalkPatch src/main.cpp)

target_include_directories(UOWalkPatch PRIVATE include)
