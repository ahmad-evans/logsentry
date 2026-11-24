cmake_minimum_required(VERSION 3.16)
project(logsentry VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)  # used by clang-tidy

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

option(ENABLE_SANITIZERS "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)

add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Werror)

if(ENABLE_SANITIZERS)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
  add_link_options(-fsanitize=address,undefined)
endif()

# Core logic as a library, so the app and the tests share the exact same code
add_library(logsentry_core src/parser.cpp src/detector.cpp src/report.cpp)
target_include_directories(logsentry_core PUBLIC include)

add_executable(logsentry src/main.cpp)
target_link_libraries(logsentry PRIVATE logsentry_core)

enable_testing()
add_executable(logsentry_tests tests/test_main.cpp tests/test_parser.cpp tests/test_detector.cpp)
target_link_libraries(logsentry_tests PRIVATE logsentry_core)
add_test(NAME unit_tests COMMAND logsentry_tests)

# End-to-end test: run the real program on the sample log; exit code 3 = critical alert found
add_test(NAME sample_log COMMAND logsentry ${CMAKE_SOURCE_DIR}/samples/auth.log)
# Passes if the planted compromise is detected (PASS_REGULAR_EXPRESSION ignores the exit code)
set_property(TEST sample_log PROPERTY PASS_REGULAR_EXPRESSION "SUCCESS_AFTER_FAILURES  *192.0.2.77")
