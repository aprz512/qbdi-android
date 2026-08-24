cmake_minimum_required(VERSION 3.22.1)
project(qbdi_tracer_native_tests LANGUAGES C CXX)
enable_testing()
find_package(Threads REQUIRED)

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

add_trace_test(flight_format_test
    flight_format_test.cpp)

add_trace_test(flight_atomic_u32_test
    flight_atomic_u32_test.cpp)
target_link_libraries(flight_atomic_u32_test PRIVATE Threads::Threads)

add_trace_test(demo_pthread_fixture_test
    demo_pthread_fixture_test.cpp
    ../../../../app/src/main/cpp/demo_target/pthread_fixture.cpp)
target_include_directories(demo_pthread_fixture_test PRIVATE
    ../../../../app/src/main/cpp)
target_link_libraries(demo_pthread_fixture_test PRIVATE Threads::Threads)

add_trace_test(flight_acceptance_protocol_test
    flight_acceptance_protocol_test.cpp
    ../../../../app/src/main/cpp/demo_target/flight_acceptance_protocol.cpp)
target_include_directories(flight_acceptance_protocol_test PRIVATE
    ../../../../app/src/main/cpp)
target_link_libraries(flight_acceptance_protocol_test PRIVATE Threads::Threads)

add_trace_test(flight_artifact_test
    flight_artifact_test.cpp
    ../../main/cpp/flight/flight_artifact.cpp)
target_link_libraries(flight_artifact_test PRIVATE Threads::Threads)
target_link_options(flight_artifact_test PRIVATE
    -Wl,--wrap=ftruncate
    -Wl,--wrap=mmap)

add_trace_test(flight_chunk_writer_test
    flight_chunk_writer_test.cpp
    ../../main/cpp/flight/flight_artifact.cpp
    ../../main/cpp/flight/flight_chunk_writer.cpp)
target_link_libraries(flight_chunk_writer_test PRIVATE Threads::Threads)

add_trace_test(flight_encoder_test
    flight_encoder_test.cpp
    ../../main/cpp/flight/flight_artifact.cpp
    ../../main/cpp/flight/flight_chunk_writer.cpp
    ../../main/cpp/flight/flight_encoder.cpp
    ../../main/cpp/events/binary_trace_encoder.cpp)
target_link_libraries(flight_encoder_test PRIVATE Threads::Threads)

add_trace_test(flight_trace_sink_test
    flight_trace_sink_test.cpp
    ../../main/cpp/flight/flight_artifact.cpp
    ../../main/cpp/flight/flight_chunk_writer.cpp
    ../../main/cpp/flight/flight_encoder.cpp
    ../../main/cpp/flight/flight_trace_sink.cpp
    ../../main/cpp/events/binary_trace_encoder.cpp)
target_link_libraries(flight_trace_sink_test PRIVATE Threads::Threads)

add_trace_test(instruction_cache_test
    instruction_cache_test.cpp
    ../../main/cpp/core/instruction_cache.cpp)

add_trace_test(instruction_collector_test
    instruction_collector_test.cpp
    ../../main/cpp/core/pending_instruction.cpp)

add_trace_test(instruction_collector_integration_test
    instruction_collector_integration_test.cpp
    ../../main/cpp/core/instruction_collector.cpp
    ../../main/cpp/core/instruction_cache.cpp
    ../../main/cpp/core/arm64_memory_operand.cpp
    ../../main/cpp/core/memory_trace_policy.cpp
    ../../main/cpp/core/qbdi_instruction_decoder.cpp
    ../../main/cpp/core/safe_memory.cpp
    ../../main/cpp/core/pending_instruction.cpp
    ../../main/cpp/core/trace_process_lifecycle.cpp
    ../../main/cpp/events/binary_trace_writer.cpp
    ../../main/cpp/events/binary_trace_encoder.cpp
    ../../main/cpp/events/trace_dictionary.cpp
    ../../main/cpp/events/async_trace_writer.cpp
    ../../main/cpp/rules/code_rule.cpp
    ../../main/cpp/rules/code_rule_context.cpp)
target_compile_options(instruction_collector_integration_test PRIVATE -ffunction-sections)
target_link_options(instruction_collector_integration_test PRIVATE -Wl,--gc-sections)
target_link_libraries(instruction_collector_integration_test PRIVATE lz4_static Threads::Threads)

add_trace_test(qbdi_instruction_decoder_test
    qbdi_instruction_decoder_test.cpp
    ../../main/cpp/core/qbdi_instruction_decoder.cpp
    ../../main/cpp/core/arm64_memory_operand.cpp
    ../../main/cpp/core/safe_memory.cpp
    ../../main/cpp/core/instruction_cache.cpp)

add_trace_test(code_rule_test
    code_rule_test.cpp
    ../../main/cpp/rules/code_rule.cpp)

add_trace_test(shadowhook_retention_contract_test
    shadowhook_retention_contract_test.cpp)
target_compile_definitions(shadowhook_retention_contract_test PRIVATE
    QTRACE_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../../main/cpp/third_party/android-inline-hook/shadowhook/src/main/cpp"
    QTRACE_CPP_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../../main/cpp"
    QTRACE_REPO_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../../../..")

add_trace_test(production_trace_contract_test
    production_trace_contract_test.cpp)
target_compile_definitions(production_trace_contract_test PRIVATE
    QTRACE_CPP_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../../main/cpp"
    QTRACE_HOST_BUILD_DIR="${CMAKE_CURRENT_BINARY_DIR}")

add_trace_test(binary_trace_encoder_test
    binary_trace_encoder_test.cpp
    ../../main/cpp/events/binary_trace_encoder.cpp)

add_trace_test(trace_dictionary_test
    trace_dictionary_test.cpp
    ../../main/cpp/events/trace_dictionary.cpp)

add_trace_test(memory_profile_test
    memory_profile_test.cpp
    ../../main/cpp/core/instruction_cache.cpp
    ../../main/cpp/core/arm64_memory_operand.cpp
    ../../main/cpp/core/memory_trace_policy.cpp
    ../../main/cpp/core/pending_instruction.cpp
    ../../main/cpp/core/safe_memory.cpp
    ../../main/cpp/events/binary_trace_encoder.cpp)

add_trace_test(binary_trace_writer_test
    binary_trace_writer_test.cpp
    ../../main/cpp/core/trace_process_lifecycle.cpp
    ../../main/cpp/events/binary_trace_writer.cpp
    ../../main/cpp/events/binary_trace_encoder.cpp
    ../../main/cpp/events/trace_dictionary.cpp
    ../../main/cpp/events/async_trace_writer.cpp)
target_link_libraries(binary_trace_writer_test PRIVATE lz4_static Threads::Threads)
target_link_options(binary_trace_writer_test PRIVATE
    -Wl,--wrap=open
    -Wl,--wrap=write
    -Wl,--wrap=close)

add_trace_test(async_trace_writer_test
    async_trace_writer_test.cpp
    ../../main/cpp/core/trace_process_lifecycle.cpp
    ../../main/cpp/events/async_trace_writer.cpp)
target_link_libraries(async_trace_writer_test PRIVATE lz4_static Threads::Threads)

add_trace_test(qbdi_runner_lifecycle_test
    qbdi_runner_lifecycle_test.cpp
    ../../main/cpp/core/qbdi_runner_lifecycle.cpp
    ../../main/cpp/core/trace_process_lifecycle.cpp
    ../../main/cpp/events/binary_trace_writer.cpp
    ../../main/cpp/events/binary_trace_encoder.cpp
    ../../main/cpp/events/trace_dictionary.cpp
    ../../main/cpp/events/async_trace_writer.cpp)
target_link_libraries(qbdi_runner_lifecycle_test PRIVATE lz4_static Threads::Threads)

add_trace_test(qbdi_thread_session_test
    qbdi_thread_session_test.cpp
    ../../main/cpp/core/qbdi_execution_control.cpp
    ../../main/cpp/core/qbdi_thread_session.cpp
    ../../main/cpp/core/trace_process_lifecycle.cpp)
add_dependencies(production_trace_contract_test qbdi_thread_session_test)

add_trace_test(flight_transfer_event_test
    flight_transfer_event_test.cpp
    ../../main/cpp/core/flight_transfer_event.cpp)

add_trace_test(capture_coordinator_test
    capture_coordinator_test.cpp
    ../../main/cpp/core/capture_coordinator.cpp
    ../../main/cpp/core/qbdi_execution_control.cpp
    ../../main/cpp/core/qbdi_thread_session.cpp
    ../../main/cpp/core/module_maps.cpp
    ../../main/cpp/core/trace_config.cpp
    ../../main/cpp/core/trace_process_lifecycle.cpp)
target_link_libraries(capture_coordinator_test PRIVATE Threads::Threads)

add_trace_test(thread_create_gateway_test
    thread_create_gateway_test.cpp
    ../../main/cpp/hooks/thread_create_gateway.cpp
    ../../main/cpp/core/capture_coordinator.cpp
    ../../main/cpp/core/qbdi_execution_control.cpp
    ../../main/cpp/core/qbdi_thread_session.cpp
    ../../main/cpp/core/module_maps.cpp
    ../../main/cpp/core/trace_config.cpp
    ../../main/cpp/core/trace_process_lifecycle.cpp)
target_link_libraries(thread_create_gateway_test PRIVATE Threads::Threads)
target_link_options(thread_create_gateway_test PRIVATE
    -Wl,--wrap=_ZnwmRKSt9nothrow_t
    -rdynamic)

add_trace_test(trace_run_session_test
    trace_run_session_test.cpp
    ../../main/cpp/core/qbdi_runner_lifecycle.cpp
    ../../main/cpp/core/trace_run_session.cpp
    ../../main/cpp/core/trace_process_lifecycle.cpp
    ../../main/cpp/events/binary_trace_writer.cpp
    ../../main/cpp/events/binary_trace_encoder.cpp
    ../../main/cpp/events/trace_dictionary.cpp
    ../../main/cpp/events/async_trace_writer.cpp)
target_link_libraries(trace_run_session_test PRIVATE lz4_static Threads::Threads)

add_trace_test(failure_state_test
    failure_state_test.cpp
    ../../main/cpp/core/crash_marker.cpp
    ../../main/cpp/core/trace_process_lifecycle.cpp
    ../../main/cpp/events/binary_trace_writer.cpp
    ../../main/cpp/events/binary_trace_encoder.cpp
    ../../main/cpp/events/trace_dictionary.cpp
    ../../main/cpp/events/async_trace_writer.cpp)
target_link_libraries(failure_state_test PRIVATE lz4_static Threads::Threads)

add_trace_test(trace_callback_gate_test
    trace_callback_gate_test.cpp)

add_trace_test(trace_number_formatter_test
    trace_number_formatter_test.cpp)

add_trace_test(arm64_syscall_test
    arm64_syscall_test.cpp
    ../../main/cpp/core/arm64_syscall.cpp)

add_trace_test(signal_context_arm64_test
    signal_context_arm64_test.cpp
    ../../main/cpp/core/signal_context_arm64.cpp)

add_trace_test(signal_broker_test
    signal_broker_test.cpp
    ../../main/cpp/core/signal_broker.cpp
    ../../main/cpp/core/arm64_syscall.cpp
    ../../main/cpp/core/signal_context_arm64.cpp
    ../../main/cpp/core/instruction_collector.cpp
    ../../main/cpp/core/instruction_cache.cpp
    ../../main/cpp/core/arm64_memory_operand.cpp
    ../../main/cpp/core/memory_trace_policy.cpp
    ../../main/cpp/core/qbdi_instruction_decoder.cpp
    ../../main/cpp/core/safe_memory.cpp
    ../../main/cpp/core/pending_instruction.cpp
    ../../main/cpp/core/trace_process_lifecycle.cpp
    ../../main/cpp/events/binary_trace_writer.cpp
    ../../main/cpp/events/binary_trace_encoder.cpp
    ../../main/cpp/events/trace_dictionary.cpp
    ../../main/cpp/events/async_trace_writer.cpp
    ../../main/cpp/rules/code_rule.cpp
    ../../main/cpp/rules/code_rule_context.cpp
    ../../main/cpp/flight/flight_artifact.cpp)
target_link_libraries(signal_broker_test PRIVATE lz4_static Threads::Threads)
target_compile_options(signal_broker_test PRIVATE -ffunction-sections)
target_link_options(signal_broker_test PRIVATE -Wl,--gc-sections)

add_trace_test(termination_syscall_test
    termination_syscall_test.cpp
    ../../main/cpp/core/signal_broker.cpp
    ../../main/cpp/core/arm64_syscall.cpp
    ../../main/cpp/core/signal_context_arm64.cpp
    ../../main/cpp/core/instruction_collector.cpp
    ../../main/cpp/core/instruction_cache.cpp
    ../../main/cpp/core/arm64_memory_operand.cpp
    ../../main/cpp/core/memory_trace_policy.cpp
    ../../main/cpp/core/qbdi_instruction_decoder.cpp
    ../../main/cpp/core/safe_memory.cpp
    ../../main/cpp/core/pending_instruction.cpp
    ../../main/cpp/core/trace_process_lifecycle.cpp
    ../../main/cpp/events/binary_trace_writer.cpp
    ../../main/cpp/events/binary_trace_encoder.cpp
    ../../main/cpp/events/trace_dictionary.cpp
    ../../main/cpp/events/async_trace_writer.cpp
    ../../main/cpp/rules/code_rule.cpp
    ../../main/cpp/rules/code_rule_context.cpp
    ../../main/cpp/flight/flight_artifact.cpp)
target_link_libraries(termination_syscall_test PRIVATE lz4_static Threads::Threads)
target_compile_options(termination_syscall_test PRIVATE -ffunction-sections)
target_link_options(termination_syscall_test PRIVATE -Wl,--gc-sections)

add_trace_test(tracer_entry_proxy_test
    tracer_entry_proxy_test.cpp
    ../../main/cpp/tracer_entry.cpp
    ../../main/cpp/hooks/thread_create_gateway.cpp
    ../../main/cpp/core/capture_coordinator.cpp
    ../../main/cpp/core/qbdi_execution_control.cpp
    ../../main/cpp/core/qbdi_thread_session.cpp
    ../../main/cpp/core/module_maps.cpp
    ../../main/cpp/core/trace_process_lifecycle.cpp
    ../../main/cpp/core/trace_config.cpp)
target_link_libraries(tracer_entry_proxy_test PRIVATE Threads::Threads)
target_link_options(tracer_entry_proxy_test PRIVATE
    -Wl,--wrap=_Znwm
    -Wl,--wrap=_ZnwmRKSt9nothrow_t
    -Wl,--wrap=_ZdlPv
    -Wl,--wrap=_ZdlPvm
    -Wl,--wrap=_ZdaPv
    -Wl,--wrap=_ZdaPvm)
