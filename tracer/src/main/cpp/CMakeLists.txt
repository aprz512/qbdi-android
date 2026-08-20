cmake_minimum_required(VERSION 3.22.1)
project(qbdi_tracer)
enable_language(ASM)

set(ANDROID_16KB_PAGE_LINK_OPTIONS "-Wl,-z,max-page-size=16384")

set(QBDI_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/third_party/qbdi)
set(SHADOWHOOK_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/third_party/android-inline-hook/shadowhook/src/main/cpp)
set(LZ4_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lz4/lib)

add_library(lz4_static STATIC
        ${LZ4_ROOT}/lz4.c
        ${LZ4_ROOT}/lz4frame.c
        ${LZ4_ROOT}/lz4hc.c
        ${LZ4_ROOT}/xxhash.c)
target_compile_features(lz4_static PRIVATE c_std_99)
target_include_directories(lz4_static PUBLIC ${LZ4_ROOT})

if(${ANDROID_ABI} STREQUAL "arm64-v8a")
    set(SHADOWHOOK_ARCH "arm64")
elseif(${ANDROID_ABI} STREQUAL "armeabi-v7a")
    set(SHADOWHOOK_ARCH "arm")
else()
    message(FATAL_ERROR "Unsupported ABI for ShadowHook: ${ANDROID_ABI}")
endif()

file(GLOB SHADOWHOOK_SRC
        ${SHADOWHOOK_ROOT}/*.c
        ${SHADOWHOOK_ROOT}/arch/${SHADOWHOOK_ARCH}/*.c
        ${SHADOWHOOK_ROOT}/arch/${SHADOWHOOK_ARCH}/*.S
        ${SHADOWHOOK_ROOT}/common/*.c
        ${SHADOWHOOK_ROOT}/third_party/*/*.c)

add_library(shadowhook_static STATIC ${SHADOWHOOK_SRC})
target_compile_features(shadowhook_static PRIVATE c_std_11)
target_compile_definitions(shadowhook_static PRIVATE SHADOWHOOK_DISABLE_LINKER_INIT)
target_compile_options(shadowhook_static PRIVATE -Os -ffunction-sections -fdata-sections)
target_include_directories(shadowhook_static PUBLIC ${SHADOWHOOK_ROOT}/include)
target_include_directories(shadowhook_static PRIVATE
        ${SHADOWHOOK_ROOT}
        ${SHADOWHOOK_ROOT}/arch/${SHADOWHOOK_ARCH}
        ${SHADOWHOOK_ROOT}/common
        ${SHADOWHOOK_ROOT}/third_party/xdl
        ${SHADOWHOOK_ROOT}/third_party/bsd
        ${SHADOWHOOK_ROOT}/third_party/lss)

add_library(qbdi_static STATIC IMPORTED)
set_target_properties(qbdi_static PROPERTIES
        IMPORTED_LOCATION ${QBDI_ROOT}/lib/arm64-v8a/libQBDI.a)

add_library(qbdi_tracer SHARED
        tracer_entry.cpp
        core/module_maps.cpp
        core/instruction_cache.cpp
        core/arm64_memory_operand.cpp
        core/memory_trace_policy.cpp
        core/trace_run_session.cpp
        core/qbdi_instruction_decoder.cpp
        core/pending_instruction.cpp
        core/instruction_collector.cpp
        core/safe_memory.cpp
        core/crash_marker.cpp
        events/text_trace_writer.cpp
        events/async_trace_writer.cpp
        events/trace_encoder.cpp
        core/trace_config.cpp
        hooks/inline_hook_adapter.cpp
        core/qbdi_runner.cpp
        core/native_fallback_arm64.S
        handlers/call_handlers.cpp
        rules/code_rule.cpp
        rules/code_rule_context.cpp
        rules/user_code_rules.cpp
        jni/jni_state.cpp
        jni/jni_formatter.cpp)

target_compile_features(qbdi_tracer PRIVATE cxx_std_20)
target_compile_options(qbdi_tracer PRIVATE
        -Wall
        -Wextra
        $<$<CONFIG:Debug>:-O2>
        $<$<CONFIG:Debug>:-g>)
target_link_options(qbdi_tracer PRIVATE ${ANDROID_16KB_PAGE_LINK_OPTIONS})
target_include_directories(qbdi_tracer PRIVATE
        ${QBDI_ROOT}/include
        ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(qbdi_tracer PRIVATE
        qbdi_static
        shadowhook_static
        lz4_static
        android
        log)
