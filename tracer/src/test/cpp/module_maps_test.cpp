#include "core/module_maps.h"

#include <cstdio>
#include <cstdlib>
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

static ModuleRange mapping(uintptr_t start, uintptr_t end,
                           std::string permissions, std::string path) {
    ModuleRange range;
    range.start = start;
    range.end = end;
    range.permissions = std::move(permissions);
    range.path = std::move(path);
    return range;
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

int main() {
    in_module_executable_address_has_no_warning();
    in_module_non_executable_address_warns();
    executable_anonymous_address_outside_module_warns_in_code_order();
    unmapped_address_warns_outside_and_not_executable();
    end_range_outside_executable_mapping_warns();
    overflow_is_a_hard_address_diagnostic();
}
