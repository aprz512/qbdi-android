cmake_minimum_required(VERSION 3.22.1)
project(qbdi_tracer)

set(QBDI_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/third_party/qbdi)

find_package(shadowhook REQUIRED CONFIG)

add_library(qbdi_static STATIC IMPORTED)
set_target_properties(qbdi_static PROPERTIES
    IMPORTED_LOCATION ${QBDI_ROOT}/lib/arm64-v8a/libQBDI.a)

add_library(qbdi_tracer SHARED
    tracer_entry.cpp
    core/module_maps.cpp
    core/safe_memory.cpp
    events/text_trace_writer.cpp
    core/trace_config.cpp
    hooks/inline_hook_adapter.cpp
    core/qbdi_runner.cpp
    handlers/call_handlers.cpp)

target_compile_features(qbdi_tracer PRIVATE cxx_std_20)
target_compile_options(qbdi_tracer PRIVATE -Wall -Wextra)
target_include_directories(qbdi_tracer PRIVATE
    ${QBDI_ROOT}/include
    ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(qbdi_tracer PRIVATE
    qbdi_static
    shadowhook::shadowhook
    android
    log)
