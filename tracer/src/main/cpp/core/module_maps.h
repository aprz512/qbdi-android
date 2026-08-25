#pragma once

#include "core/trace_config.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

struct dl_phdr_info;

struct AddressRange {
    uintptr_t start = 0;
    uintptr_t end = 0;
};

struct AddressDiagnostic {
    std::string code;
    std::string message;
};

struct SceneAddressDiagnostics {
    bool valid = false;
    uintptr_t runtime_address = 0;
    uintptr_t runtime_end = 0;
    std::vector<AddressDiagnostic> warnings;
    AddressDiagnostic error;
};

struct ModuleRange {
    static constexpr size_t kMaxReadableExecutableRanges = 8;

    uintptr_t start = 0;
    uintptr_t end = 0;
    uintptr_t file_offset = 0;
    std::string permissions;
    std::string path;
    std::array<AddressRange, kMaxReadableExecutableRanges> readable_executable_ranges{};
    size_t readable_executable_range_count = 0;

    bool executable() const { return permissions.find('x') != std::string::npos; }

    uintptr_t size() const { return end > start ? end - start : 0; }
};

std::vector<ModuleRange> read_process_maps();

bool module_range_from_phdr(const dl_phdr_info &info,
                            ModuleRange *out) noexcept;

bool normalize_module_ranges(const std::vector<ModuleRange> &maps,
                             const std::string &requested_path,
                             uintptr_t observed_base, uintptr_t observed_size,
                             ModuleRange *out);

bool find_loaded_module(const std::string &requested_path, uintptr_t observed_base,
                        uintptr_t observed_size, ModuleRange *out);

bool module_offset_address(const ModuleRange &module, uintptr_t offset,
                           bool allow_end, uintptr_t *address);

bool checked_offset_address(uintptr_t base, uintptr_t offset,
                            uintptr_t *address) noexcept;

SceneAddressDiagnostics diagnose_scene_address(
        const ModuleRange &module,
        const std::vector<ModuleRange> &process_maps,
        const SceneConfig &scene);

std::string basename_of(const std::string &path);
