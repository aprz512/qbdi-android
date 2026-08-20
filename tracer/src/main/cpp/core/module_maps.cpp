#include "core/module_maps.h"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <limits>
#include <sstream>
#include <utility>

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

namespace {

bool mapped_path_matches(const std::string &requested, const std::string &mapped) {
    if (requested.find('/') != std::string::npos) return requested == mapped;
    return basename_of(mapped) == requested;
}

} // namespace

bool normalize_module_ranges(const std::vector<ModuleRange> &maps,
                             const std::string &requested_path,
                             uintptr_t observed_base, uintptr_t observed_size,
                             ModuleRange *out) {
    if (requested_path.empty() || out == nullptr) return false;
    uintptr_t observed_end = 0;
    if (observed_size != 0) {
        if (observed_base == 0 ||
            observed_size > std::numeric_limits<uintptr_t>::max() - observed_base) {
            return false;
        }
        observed_end = observed_base + observed_size;
    }

    uintptr_t load_bias = 0;
    std::string mapped_path;
    bool found = false;
    for (const ModuleRange &range: maps) {
        if (!range.executable() || range.start >= range.end || range.file_offset > range.start ||
            !mapped_path_matches(requested_path, range.path)) {
            continue;
        }
        const uintptr_t candidate_bias = range.start - range.file_offset;
        if (observed_size != 0) {
            if (candidate_bias != observed_base) continue;
            if (range.start < observed_base || range.end > observed_end) return false;
        }
        if (found && (candidate_bias != load_bias || range.path != mapped_path)) return false;
        found = true;
        load_bias = candidate_bias;
        mapped_path = range.path;
    }
    if (!found) return false;

    ModuleRange normalized;
    normalized.start = load_bias;
    normalized.end = observed_size != 0 ? observed_end : load_bias;
    normalized.path = mapped_path;
    for (const ModuleRange &range: maps) {
        if (range.path != mapped_path || range.start >= range.end ||
            range.file_offset > range.start || range.start - range.file_offset != load_bias) {
            continue;
        }
        if (observed_size != 0 &&
            (range.start < observed_base || range.end > observed_end)) {
            continue;
        }
        normalized.end = std::max(normalized.end, range.end);
        if (!range.executable()) continue;
        normalized.permissions = range.permissions;
        if (range.permissions.find('r') == std::string::npos ||
            normalized.readable_executable_range_count ==
                    normalized.readable_executable_ranges.size()) {
            continue;
        }
        normalized.readable_executable_ranges[normalized.readable_executable_range_count++] =
                {range.start, range.end};
    }
    *out = std::move(normalized);
    return true;
}

bool find_loaded_module(const std::string &requested_path, uintptr_t observed_base,
                        uintptr_t observed_size, ModuleRange *out) {
    return normalize_module_ranges(read_process_maps(), requested_path, observed_base,
                                   observed_size, out);
}

bool module_offset_address(const ModuleRange &module, uintptr_t offset,
                           bool allow_end, uintptr_t *address) {
    if (address == nullptr || module.start >= module.end) return false;
    const uintptr_t module_size = module.end - module.start;
    if (offset > module_size || (!allow_end && offset == module_size)) return false;
    *address = module.start + offset;
    return true;
}
