#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

struct SceneConfig {
    size_t index = 0;
    std::string name;
    uintptr_t offset = 0;
    bool bypass_text = false;
    bool bypass_maps = false;
};

struct TraceConfig {
    std::string package_name = "com.aprz.qbdiandroid";
    std::string target_so = "libdemo_target.so";
    std::vector<SceneConfig> scenes;
};

TraceConfig default_trace_config();
TraceConfig parse_trace_config(const char *encoded_config);
