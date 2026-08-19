#pragma once

#include <cstdint>
#include <string>

struct TraceContext {
    // Empty selects the Android app-private trace directory. Tests and host tools may override it.
    std::string output_directory;
    std::string package_name;
    std::string scene_name;
    std::string target_so;
    uintptr_t module_base = 0;
    uintptr_t target_offset = 0;
    uintptr_t target_address = 0;
    int pid = 0;
    int tid = 0;
};
