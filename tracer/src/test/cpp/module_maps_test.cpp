#include "core/module_maps.h"

#include <cstdio>
#include <cstdlib>
#include <link.h>
#include <limits>
#include <string>
#include <utility>
#include <vector>

static void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\\n", line, expression);
    std::abort();
}
#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

static std::vector<dl_phdr_info> loaded_modules;

extern "C" int __wrap_dl_iterate_phdr(
        int (*callback)(dl_phdr_info *, size_t, void *), void *data) {
    for (auto &info : loaded_modules) {
        int result = callback(&info, sizeof(info), data);
        if (result != 0) return result;
    }
    return 0;
}

static void loaded_module_with_16kb_segments_uses_linker_load_bias() {
    // DIGIMON UP's libmain.so repeats file page zero at base + 0x4000.
    // Executable mapping start minus file offset is therefore NOT its base.
    const ElfW(Phdr) headers[] = {
        {.p_type = PT_LOAD, .p_flags = PF_R, .p_offset = 0, .p_vaddr = 0,
         .p_filesz = 0xa20, .p_memsz = 0xa20, .p_align = 0x4000},
        {.p_type = PT_LOAD, .p_flags = PF_R | PF_X, .p_offset = 0xa20,
         .p_vaddr = 0x4a20, .p_filesz = 0x500, .p_memsz = 0x500, .p_align = 0x4000},
        {.p_type = PT_LOAD, .p_flags = PF_R | PF_W, .p_offset = 0x1150,
         .p_vaddr = 0xd150, .p_filesz = 0x30, .p_memsz = 0x40, .p_align = 0x4000},
    };
    dl_phdr_info info{};
    info.dlpi_addr = 0x70000000;
    info.dlpi_name = "/data/app/libmain.so";
    info.dlpi_phdr = headers;
    info.dlpi_phnum = std::size(headers);
    loaded_modules = {info};

    ModuleRange constructor, polled, observed;
    CHECK(module_range_from_phdr(info, &constructor));
    CHECK(find_loaded_module("libmain.so", 0, 0, &polled));
    CHECK(polled.start == 0x70000000);
    CHECK(polled.start == constructor.start);
    CHECK(polled.end == constructor.end);
    CHECK(polled.readable_executable_range_count == 1);
    CHECK(polled.readable_executable_ranges[0].start == 0x70004a20);
    CHECK(polled.readable_executable_ranges[0].end == 0x70004f20);
    CHECK(find_loaded_module(info.dlpi_name, info.dlpi_addr, 0x10000, &observed));
    CHECK(observed.start == polled.start && observed.end == polled.end);
    CHECK(!find_loaded_module(info.dlpi_name, info.dlpi_addr + 0x4000,
                              0x10000, &observed));
    CHECK(!find_loaded_module(info.dlpi_name, info.dlpi_addr, 0x4000, &observed));
    CHECK(!find_loaded_module(info.dlpi_name, UINTPTR_MAX - 1, 4, &observed));

    info.dlpi_addr = 0x71000000;
    info.dlpi_name = "/other/libmain.so";
    loaded_modules.push_back(info);
    CHECK(!find_loaded_module("libmain.so", 0, 0, &observed));
    CHECK(find_loaded_module("/data/app/libmain.so", 0, 0, &observed));
    CHECK(observed.start == polled.start);
    CHECK(find_loaded_module("libmain.so", 0x71000000, 0x10000, &observed));
    CHECK(observed.start == 0x71000000);
    CHECK(!find_loaded_module("", 0, 0, &observed));
    CHECK(!find_loaded_module("libmain.so", 0, 0, nullptr));
    loaded_modules.clear();
}

static ModuleRange mapping(uintptr_t start, uintptr_t end,
                           std::string permissions, std::string path) {
    ModuleRange range;
    range.start = start;
    range.end = end;
    range.permissions = std::move(permissions);
    range.path = std::move(path);
    return range;
}

static void unpacked_regions_require_a_contiguous_readable_executable_mapping() {
    const auto anonymous = mapping(0x70000000, 0x70184000, "rwxp", "");
    ModuleRange region;
    CHECK(module_range_from_region({anonymous}, "unpacked.so", 0x70000000, 0x184000, &region));
    CHECK(region.start == anonymous.start && region.end == anonymous.end);
    CHECK(region.path == "unpacked.so");
    CHECK(region.readable_executable_range_count == 1);
    CHECK(region.readable_executable_ranges[0].end == anonymous.end);
    CHECK(module_range_from_region({anonymous}, "unpacked.so", 0x70001000, 0x1000, &region));
    CHECK(region.start == 0x70001000 && region.end == 0x70002000);
    CHECK(!module_range_from_region({anonymous}, "unpacked.so", 0x70000000, 0x185000, &region));
    CHECK(!module_range_from_region({anonymous}, "unpacked.so", UINTPTR_MAX - 1, 4, &region));
    CHECK(!module_range_from_region({anonymous}, "unpacked.so", 0, 4, &region));
    CHECK(!module_range_from_region({anonymous}, "unpacked.so", 0x70000000, 0, &region));
    CHECK(!module_range_from_region({anonymous}, "", 0x70000000, 0x1000, &region));
    CHECK(!module_range_from_region({anonymous}, "unpacked.so", 0x70000000, 0x1000, nullptr));
    CHECK(!module_range_from_region({mapping(0x70000000, 0x70184000, "rw-p", "")},
                                    "unpacked.so", 0x70000000, 0x1000, &region));
    CHECK(!module_range_from_region({mapping(0x70000000, 0x70184000, "--xp", "")},
                                    "unpacked.so", 0x70000000, 0x1000, &region));
}

static void in_module_executable_address_has_no_warning() {
    const ModuleRange module = mapping(0x100000, 0x101000, "r-xp", "/data/libtarget.so");
    const SceneConfig scene{0, "entry", 0x20, 0};

    const SceneAddressDiagnostics diagnostics = diagnose_scene_address(module, {module}, scene);

    CHECK(diagnostics.valid);
    CHECK(diagnostics.runtime_address == 0x100020);
    CHECK(diagnostics.runtime_end == 0);
    CHECK(diagnostics.warnings.empty());
    CHECK(diagnostics.error.code.empty());
}

static void in_module_non_executable_address_warns() {
    const ModuleRange module = mapping(0x100000, 0x101000, "rw-p", "/data/libtarget.so");
    const SceneConfig scene{0, "data", 0x20, 0};

    const SceneAddressDiagnostics diagnostics = diagnose_scene_address(module, {module}, scene);

    CHECK(diagnostics.valid);
    CHECK(diagnostics.warnings.size() == 1);
    CHECK(diagnostics.warnings.at(0).code == "ADDRESS_NOT_EXECUTABLE");
}

static void executable_anonymous_address_outside_module_warns_in_code_order() {
    const ModuleRange module = mapping(0x100000, 0x101000, "r-xp", "/data/libtarget.so");
    const ModuleRange runtime_mapping = mapping(0x102000, 0x103000, "r-xp", "");
    const SceneConfig scene{0, "unpacked", 0x2010, 0};

    const SceneAddressDiagnostics diagnostics = diagnose_scene_address(
            module, {module, runtime_mapping}, scene);

    CHECK(diagnostics.valid);
    CHECK(diagnostics.runtime_address == 0x102010);
    CHECK(diagnostics.warnings.size() == 2);
    CHECK(diagnostics.warnings.at(0).code == "ADDRESS_OUTSIDE_TARGET_MODULE");
    CHECK(diagnostics.warnings.at(1).code == "ADDRESS_IN_RUNTIME_MAPPING");
}

static void unmapped_address_warns_outside_and_not_executable() {
    const ModuleRange module = mapping(0x100000, 0x101000, "r-xp", "/data/libtarget.so");
    const SceneConfig scene{0, "missing", 0x2010, 0};

    const SceneAddressDiagnostics diagnostics = diagnose_scene_address(module, {module}, scene);

    CHECK(diagnostics.valid);
    CHECK(diagnostics.warnings.size() == 2);
    CHECK(diagnostics.warnings.at(0).code == "ADDRESS_OUTSIDE_TARGET_MODULE");
    CHECK(diagnostics.warnings.at(1).code == "ADDRESS_NOT_EXECUTABLE");
}

static void end_range_outside_executable_mapping_warns() {
    const ModuleRange module = mapping(0x100000, 0x101000, "r-xp", "/data/libtarget.so");
    const ModuleRange executable = mapping(0x100000, 0x100080, "r-xp", "/data/libtarget.so");
    const SceneConfig scene{0, "range", 0x20, 0x90};

    const SceneAddressDiagnostics diagnostics = diagnose_scene_address(module, {executable}, scene);

    CHECK(diagnostics.valid);
    CHECK(diagnostics.runtime_address == 0x100020);
    CHECK(diagnostics.runtime_end == 0x100090);
    CHECK(diagnostics.warnings.size() == 1);
    CHECK(diagnostics.warnings.at(0).code == "ADDRESS_NOT_EXECUTABLE");
}

static void overflow_is_a_hard_address_diagnostic() {
    const uintptr_t maximum = std::numeric_limits<uintptr_t>::max();
    const ModuleRange module = mapping(maximum - 0x10, maximum, "r-xp", "/data/libtarget.so");
    const SceneConfig scene{0, "overflow", 0x20, 0};

    const SceneAddressDiagnostics diagnostics = diagnose_scene_address(module, {module}, scene);

    CHECK(!diagnostics.valid);
    CHECK(diagnostics.error.code == "ADDRESS_OVERFLOW");
    CHECK(!diagnostics.error.message.empty());
    CHECK(diagnostics.warnings.empty());
}

static void nonzero_elf_origins_and_reload_preserve_scene_offsets() {
    for (uintptr_t padding : {0x1000, 0x4000}) {
        std::array<ElfW(Phdr), 3> headers{};
        headers[0].p_type = PT_LOAD;
        headers[0].p_flags = PF_R;
        headers[0].p_vaddr = 0x10000;
        headers[0].p_memsz = 0x100;
        headers[1].p_type = headers[2].p_type = PT_LOAD;
        headers[1].p_flags = headers[2].p_flags = PF_R | PF_X;
        headers[1].p_offset = 0x100;
        headers[1].p_vaddr = 0x10100 + padding;
        headers[1].p_memsz = 0x100;
        headers[2].p_offset = 0x200;
        headers[2].p_vaddr = 0x10200 + 2 * padding;
        headers[2].p_memsz = 0x100;
        dl_phdr_info info{};
        info.dlpi_name = "/data/app/reloaded.so";
        info.dlpi_phdr = headers.data();
        info.dlpi_phnum = headers.size();
        for (uintptr_t base : {0x70000000, 0x71000000}) {
            info.dlpi_addr = base;
            ModuleRange module;
            CHECK(module_range_from_phdr(info, &module));
            CHECK(module.start == base + 0x10000);
            CHECK(module.readable_executable_range_count == 2);
            uintptr_t address = 0;
            CHECK(module_offset_address(module, padding + 0x100, false, &address));
            CHECK(address == module.readable_executable_ranges[0].start);
        }
    }
}

int main() {
    nonzero_elf_origins_and_reload_preserve_scene_offsets();
    loaded_module_with_16kb_segments_uses_linker_load_bias();
    unpacked_regions_require_a_contiguous_readable_executable_mapping();
    in_module_executable_address_has_no_warning();
    in_module_non_executable_address_warns();
    executable_anonymous_address_outside_module_warns_in_code_order();
    unmapped_address_warns_outside_and_not_executable();
    end_range_outside_executable_mapping_warns();
    overflow_is_a_hard_address_diagnostic();
}
