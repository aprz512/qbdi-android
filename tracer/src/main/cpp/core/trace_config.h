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

struct TraceConfig {
    std::string package_name = "com.aprz.qbdiandroid";
    std::string target_so = "libdemo_target.so";
    std::vector<SceneConfig> scenes;
    // JNI 函数名列表，命中时打印调用栈（回溯）
    std::vector<std::string> jni_backtrace_funcs;
};

TraceConfig default_trace_config();

TraceConfig parse_trace_config(const char *encoded_config);
