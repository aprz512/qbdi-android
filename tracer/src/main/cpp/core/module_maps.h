#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct ModuleRange {
    uintptr_t start = 0;
    uintptr_t end = 0;
    uintptr_t file_offset = 0;
    std::string permissions;
    std::string path;

    bool executable() const { return permissions.find('x') != std::string::npos; }
    uintptr_t size() const { return end > start ? end - start : 0; }
};

std::vector<ModuleRange> read_process_maps();
bool find_module_executable_range(const std::string &soname, ModuleRange *out);
std::string basename_of(const std::string &path);
