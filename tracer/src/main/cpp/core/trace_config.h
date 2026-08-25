#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

struct SceneConfig {
    size_t index = 0;
    std::string name;
    uintptr_t offset = 0;
    uintptr_t end_offset = 0;
};

enum class TraceProfile : uint8_t { Fast, Balanced, Full };

struct TraceOptions {
    TraceProfile profile = TraceProfile::Fast;
    bool compression_enabled = true;
    int lz4_level = 0;
    bool auto_buffer_size = true;
    size_t buffer_bytes = 0;
    size_t hexdump_limit = 32;

    bool memory_enabled() const { return profile != TraceProfile::Fast; }
    bool hexdump_enabled() const { return profile == TraceProfile::Full; }
};

struct FlightOptions {
    bool enabled = false;
    std::string entry_scene;
    uint64_t capacity_bytes = 512ULL * 1024 * 1024;
    uint32_t chunk_bytes = 256U * 1024;
    uint32_t max_threads = 256;
    uint32_t protected_chunks = 4;
};

struct SessionOptions {
    std::string id;
    uint64_t duration_ms = 0;

    bool enabled() const noexcept { return !id.empty(); }
    bool timed() const noexcept { return duration_ms != 0; }
};

struct TraceConfig {
    std::string package_name = "com.aprz.qbdiandroid";
    std::string target_so = "libdemo_target.so";
    std::vector<SceneConfig> scenes;
    // JNI 函数名列表，命中时打印调用栈（回溯）
    std::vector<std::string> jni_backtrace_funcs;
    TraceOptions trace;
    FlightOptions flight;
    SessionOptions session;
#ifndef NDEBUG
    bool test_fail_setup = false;
#endif
};

TraceConfig default_trace_config();

const char *trace_profile_name(TraceProfile profile);
