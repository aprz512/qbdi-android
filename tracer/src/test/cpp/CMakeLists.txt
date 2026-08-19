cmake_minimum_required(VERSION 3.22.1)
project(qbdi_tracer_native_tests LANGUAGES CXX)
enable_testing()

function(add_trace_test name)
    add_executable(${name} ${ARGN})
    target_compile_features(${name} PRIVATE cxx_std_20)
    target_compile_definitions(${name} PRIVATE QTRACE_HOST_TEST=1)
    target_include_directories(${name} PRIVATE ../../main/cpp)
    add_test(NAME ${name} COMMAND ${name})
endfunction()

add_trace_test(trace_config_test
    trace_config_test.cpp
    ../../main/cpp/core/trace_config.cpp)
