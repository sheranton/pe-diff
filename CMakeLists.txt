cmake_minimum_required(VERSION 3.15)
project(pe_diff CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(pe-diff src/main.cpp)

if(MSVC)
    target_compile_options(pe-diff PRIVATE /W4 /permissive-)
else()
    target_compile_options(pe-diff PRIVATE -Wall -Wextra -Wpedantic)
endif()
