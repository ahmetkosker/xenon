cmake_minimum_required(VERSION 3.16)
project(xenon C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_executable(xenon src/xenon.c)

enable_testing()
add_test(NAME xenon_cli_test COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_xenon.sh $<TARGET_FILE:xenon>)
set_tests_properties(xenon_cli_test PROPERTIES WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
