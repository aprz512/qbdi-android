#include "core/module_maps.h"

#include <cstdlib>
#include <fstream>
#include <sstream>

std::string basename_of(const std::string &path) {
    size_t pos = path.find_last_of('/');
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

std::vector<ModuleRange> read_process_maps() {
    std::vector<ModuleRange> ranges;
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        std::istringstream input(line);
        std::string addresses;
        std::string offset;
        std::string dev;
        std::string inode;
        ModuleRange range;
        input >> addresses >> range.permissions >> offset >> dev >> inode;
        std::getline(input, range.path);
        if (!range.path.empty() && range.path[0] == ' ') {
            size_t first = range.path.find_first_not_of(' ');
            range.path = first == std::string::npos ? std::string() : range.path.substr(first);
        }
        size_t dash = addresses.find('-');
        if (dash == std::string::npos) continue;
        range.start = strtoull(addresses.substr(0, dash).c_str(), nullptr, 16);
        range.end = strtoull(addresses.substr(dash + 1).c_str(), nullptr, 16);
        range.file_offset = strtoull(offset.c_str(), nullptr, 16);
        ranges.push_back(range);
    }
    return ranges;
}

bool find_module_executable_range(const std::string &soname, ModuleRange *out) {
    for (const auto &range: read_process_maps()) {
        if (!range.executable()) continue;
        if (basename_of(range.path) == soname) {
            if (out != nullptr) *out = range;
            return true;
        }
    }
    return false;
}
