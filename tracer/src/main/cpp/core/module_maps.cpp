#include "core/module_maps.h"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <link.h>
#include <limits>
#include <sstream>
#include <unistd.h>
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

bool module_range_from_phdr(const dl_phdr_info &info,
                            ModuleRange *out) noexcept {
    if (out == nullptr || info.dlpi_name == nullptr ||
        info.dlpi_name[0] == '\0' || info.dlpi_phdr == nullptr) {
        return false;
    }
    const long page_size_value = ::sysconf(_SC_PAGESIZE);
    if (page_size_value <= 0) return false;
    const uintptr_t page_size = static_cast<uintptr_t>(page_size_value);
    const uintptr_t base = static_cast<uintptr_t>(info.dlpi_addr);
    const uintptr_t maximum = std::numeric_limits<uintptr_t>::max();
    ModuleRange module;
    module.start = base;
    uintptr_t maximum_load_end = 0;
    bool have_load = false;
    bool have_executable = false;
    for (ElfW(Half) index = 0; index < info.dlpi_phnum; ++index) {
        const ElfW(Phdr) &header = info.dlpi_phdr[index];
        if (header.p_type != PT_LOAD || header.p_memsz == 0) continue;
        if (header.p_vaddr > maximum - header.p_memsz) return false;
        const uintptr_t relative_end = header.p_vaddr + header.p_memsz;
        maximum_load_end = std::max(maximum_load_end, relative_end);
        have_load = true;
        if ((header.p_flags & PF_X) == 0) continue;
        if (module.readable_executable_range_count ==
            module.readable_executable_ranges.size()) {
            return false;
        }
        if (header.p_vaddr > maximum - base || relative_end > maximum - base) {
            return false;
        }
        module.readable_executable_ranges[
                module.readable_executable_range_count++] =
                {base + header.p_vaddr, base + relative_end};
        have_executable = true;
    }
    if (!have_load) return false;
    const uintptr_t remainder = maximum_load_end % page_size;
    if (remainder != 0) {
        const uintptr_t padding = page_size - remainder;
        if (maximum_load_end > maximum - padding) return false;
        maximum_load_end += padding;
    }
    if (maximum_load_end == 0 || maximum_load_end > maximum - base) return false;
    module.end = base + maximum_load_end;
    module.path = info.dlpi_name;
    if (have_executable) module.permissions = "r-xp";
    *out = std::move(module);
    return true;
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
    normalized.end = load_bias;
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
