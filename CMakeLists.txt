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

# Tests: golden-file comparisons against fixture DLLs built from
# tests/fixtures/sample.cpp (see tests/fixtures/build.cmd).
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR AND NOT CMAKE_CROSSCOMPILING)
    enable_testing()
    function(golden_test name expected_rc args)
        add_test(NAME ${name}
                 COMMAND ${CMAKE_COMMAND}
                         -DTOOL=$<TARGET_FILE:pe-diff>
                         "-DARGS=${args}"
                         -DWORKDIR=${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures
                         -DEXPECTED=${CMAKE_CURRENT_SOURCE_DIR}/tests/expected/${name}.txt
                         -DEXPECTED_RC=${expected_rc}
                         -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_golden.cmake)
    endfunction()
    golden_test(identical 0 "sample64.dll|sample64.dll")
    golden_test(v1-to-v2 1 "sample64.dll|sample64-v2.dll")
    golden_test(v1-to-v2-ignore-timestamp 1 "-T|sample64.dll|sample64-v2.dll")
    golden_test(missing-file 2 "sample64.dll|does-not-exist.dll")
    golden_test(usage 2 "")
endif()
