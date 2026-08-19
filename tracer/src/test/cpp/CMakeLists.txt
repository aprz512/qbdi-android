cmake_minimum_required(VERSION 3.22.1)
project(qbdi_tracer_native_tests LANGUAGES C CXX)
enable_testing()

set(LZ4_ROOT ../../main/cpp/third_party/lz4/lib)
add_library(lz4_static STATIC
    ${LZ4_ROOT}/lz4.c
    ${LZ4_ROOT}/lz4frame.c
    ${LZ4_ROOT}/lz4hc.c
    ${LZ4_ROOT}/xxhash.c)
target_compile_features(lz4_static PRIVATE c_std_99)
target_include_directories(lz4_static PUBLIC ${LZ4_ROOT})

function(add_trace_test name)
    add_executable(${name} ${ARGN})
    target_compile_features(${name} PRIVATE cxx_std_20)
    target_compile_definitions(${name} PRIVATE QTRACE_HOST_TEST=1)
    target_include_directories(${name} PRIVATE
        ../../main/cpp
        ../../main/cpp/third_party/qbdi/include)
    add_test(NAME ${name} COMMAND ${name})
endfunction()

add_trace_test(trace_config_test
    trace_config_test.cpp
    ../../main/cpp/core/trace_config.cpp)

add_trace_test(instruction_cache_test
    instruction_cache_test.cpp
    ../../main/cpp/core/instruction_cache.cpp)

add_trace_test(instruction_collector_test
    instruction_collector_test.cpp
    ../../main/cpp/core/pending_instruction.cpp)

add_trace_test(qbdi_instruction_decoder_test
    qbdi_instruction_decoder_test.cpp
    ../../main/cpp/core/qbdi_instruction_decoder.cpp
    ../../main/cpp/core/instruction_cache.cpp)

add_trace_test(code_rule_test
    code_rule_test.cpp
    ../../main/cpp/rules/code_rule.cpp)

add_trace_test(trace_encoder_test
    trace_encoder_test.cpp
    ../../main/cpp/events/trace_encoder.cpp)

find_package(Threads REQUIRED)
add_trace_test(async_trace_writer_test
    async_trace_writer_test.cpp
    ../../main/cpp/events/async_trace_writer.cpp)
target_link_libraries(async_trace_writer_test PRIVATE lz4_static Threads::Threads)

add_trace_test(text_trace_writer_test
    text_trace_writer_test.cpp
    ../../main/cpp/events/text_trace_writer.cpp
    ../../main/cpp/events/trace_encoder.cpp
    ../../main/cpp/events/async_trace_writer.cpp)
target_link_libraries(text_trace_writer_test PRIVATE lz4_static Threads::Threads)
target_link_options(text_trace_writer_test PRIVATE
    -Wl,--wrap=open
    -Wl,--wrap=write
    -Wl,--wrap=close)

add_trace_test(trace_callback_gate_test
    trace_callback_gate_test.cpp)

add_trace_test(trace_number_formatter_test
    trace_number_formatter_test.cpp)
