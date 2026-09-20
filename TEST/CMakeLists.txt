cmake_minimum_required(VERSION 3.10)
project(ecbs_test C)

set(CMAKE_C_STANDARD 17)

add_executable(ecbs_test test.c)
target_link_libraries(ecbs_test ecbs-c)

target_compile_options(ecbs_test PRIVATE -Werror -Wno-attributes)
