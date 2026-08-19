#include "core/module_maps.h"
#include "core/native_fallback_arm64.h"
#include "core/qbdi_runner.h"
#include "core/trace_config.h"
#include "handlers/call_handlers.h"
#include "hooks/inline_hook_adapter.h"

#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>

extern "C" uint64_t trace_proxy_dispatch(size_t index, const uint64_t args[8],
                                          uint64_t indirect_result);
extern "C" {
char trace_proxy_stubs[32768]{};
}

using RegistrationGate = void (*)();
void trace_proxy_test_reset(const TraceConfig &config);
bool trace_proxy_test_update(const TraceConfig &config, const SceneConfig &scene,
                             const ModuleRange &module);
void trace_proxy_test_set_registration_gate(RegistrationGate gate);
void trace_proxy_test_set_stub_entry_gate(RegistrationGate gate);
size_t trace_proxy_test_generation(size_t scene_index);

void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

namespace {

std::mutex g_fake_mutex;
TraceInvocation g_seen_invocation;
TraceConfig g_seen_config;
size_t g_runner_calls = 0;
size_t g_bridge_calls = 0;
size_t g_hook_calls = 0;
size_t g_unhook_calls = 0;
bool g_fail_unhook = false;
bool g_fail_next_hook = false;
bool g_install_residual_hook = false;
std::atomic<size_t> g_old_calls{0};
std::atomic<size_t> g_new_calls{0};

std::mutex g_gate_mutex;
std::condition_variable g_gate_condition;
bool g_registration_entered = false;
bool g_release_registration = false;
bool g_stub_entry_entered = false;
bool g_release_stub_entry = false;
bool g_use_runner_gate = false;
bool g_runner_entered = false;
bool g_release_runner = false;
bool g_use_bridge_gate = false;
size_t g_bridge_gate_entries = 0;
bool g_release_bridge = false;

uint64_t old_target(uint64_t value, uint64_t, uint64_t, uint64_t,
                    uint64_t, uint64_t, uint64_t, uint64_t) {
    ++g_old_calls;
    return value + 0x100;
}

uint64_t new_target(uint64_t value, uint64_t, uint64_t, uint64_t,
                    uint64_t, uint64_t, uint64_t, uint64_t) {
    ++g_new_calls;
    return value + 0x200;
}

void registration_gate() {
    std::unique_lock<std::mutex> lock(g_gate_mutex);
    g_registration_entered = true;
    g_gate_condition.notify_all();
    g_gate_condition.wait(lock, [] { return g_release_registration; });
}

void stub_entry_gate() {
    std::unique_lock<std::mutex> lock(g_gate_mutex);
    g_stub_entry_entered = true;
    g_gate_condition.notify_all();
    g_gate_condition.wait(lock, [] { return g_release_stub_entry; });
}

void reset_fakes() {
    std::lock_guard<std::mutex> lock(g_fake_mutex);
    g_seen_invocation = {};
    g_seen_config = {};
    g_runner_calls = 0;
    g_bridge_calls = 0;
    g_hook_calls = 0;
    g_unhook_calls = 0;
    g_fail_unhook = false;
    g_fail_next_hook = false;
    g_install_residual_hook = false;
    g_old_calls = 0;
    g_new_calls = 0;
    {
        std::lock_guard<std::mutex> gate_lock(g_gate_mutex);
        g_registration_entered = false;
        g_release_registration = false;
        g_stub_entry_entered = false;
        g_release_stub_entry = false;
        g_use_runner_gate = false;
        g_runner_entered = false;
        g_release_runner = false;
        g_use_bridge_gate = false;
        g_bridge_gate_entries = 0;
        g_release_bridge = false;
    }
}

TraceConfig config_named(const char *name) {
    TraceConfig config = default_trace_config();
    config.package_name = name;
    config.scenes.clear();
    return config;
}

SceneConfig scene_named(const char *name, uintptr_t target, size_t index = 0) {
    SceneConfig scene;
    scene.index = index;
    scene.name = name;
    scene.offset = target;
    scene.end_offset = target + 4;
    return scene;
}

ModuleRange module_named(const char *path, uintptr_t end = 0x100000) {
    ModuleRange module;
    module.start = 0;
    module.end = end;
    module.permissions = "r-xp";
    module.path = path;
    return module;
}

void branch_before_dispatch_keeps_its_generation_snapshot_and_bypass() {
    reset_fakes();
    const TraceConfig old_config = config_named("old-generation");
    const SceneConfig old_scene = scene_named("old-generation",
                                              reinterpret_cast<uintptr_t>(old_target));
    trace_proxy_test_reset(old_config);
    CHECK(trace_proxy_test_update(old_config, old_scene, module_named("old-module")));
    const size_t old_generation = trace_proxy_test_generation(old_scene.index);
    trace_proxy_test_set_stub_entry_gate(stub_entry_gate);

    uint64_t args[8]{5};
    uint64_t old_result = 0;
    std::thread delayed([&] {
        old_result = trace_proxy_dispatch(old_generation, args, 0x66);
    });
    {
        std::unique_lock<std::mutex> lock(g_gate_mutex);
        g_gate_condition.wait(lock, [] { return g_stub_entry_entered; });
    }

    const TraceConfig new_config = config_named("new-generation");
    SceneConfig new_scene = scene_named("new-generation",
                                        reinterpret_cast<uintptr_t>(old_target));
    new_scene.end_offset += 0x20;
    CHECK(trace_proxy_test_update(new_config, new_scene, module_named("new-module")));
    const size_t new_generation = trace_proxy_test_generation(new_scene.index);
    CHECK(new_generation != old_generation);

    {
        std::lock_guard<std::mutex> lock(g_gate_mutex);
        g_release_stub_entry = true;
    }
    g_gate_condition.notify_all();
    delayed.join();
    trace_proxy_test_set_stub_entry_gate(nullptr);

    CHECK(old_result == 0x105);
    CHECK(g_seen_config.package_name == "old-generation");
    CHECK(g_seen_invocation.scene.name == "old-generation");
    CHECK(g_seen_invocation.module.path == "old-module");
    CHECK(trace_proxy_dispatch(new_generation, args, 0x77) == 0x105);
    CHECK(g_seen_config.package_name == "new-generation");
    CHECK(g_seen_invocation.scene.name == "new-generation");
    CHECK(g_seen_invocation.module.path == "new-module");
}

void entrant_registration_and_snapshot_are_atomic_with_install() {
    reset_fakes();
    const TraceConfig old_config = config_named("old-config");
    const SceneConfig old_scene = scene_named("old-scene",
                                              reinterpret_cast<uintptr_t>(old_target));
    trace_proxy_test_reset(old_config);
    CHECK(trace_proxy_test_update(old_config, old_scene, module_named("old-module")));
    trace_proxy_test_set_registration_gate(registration_gate);
    {
        std::lock_guard<std::mutex> lock(g_gate_mutex);
        g_use_runner_gate = true;
    }

    uint64_t args[8]{7};
    uint64_t result = 0;
    std::thread entrant([&] { result = trace_proxy_dispatch(0, args, 0x88); });
    {
        std::unique_lock<std::mutex> lock(g_gate_mutex);
        g_gate_condition.wait(lock, [] { return g_registration_entered; });
    }

    TraceConfig new_config = config_named("new-config");
    SceneConfig new_scene = scene_named("new-scene",
                                        reinterpret_cast<uintptr_t>(new_target));
    new_scene.end_offset += 8;
    const ModuleRange new_module = module_named("new-module", 0x200000);
    std::atomic<bool> installer_started{false};
    std::atomic<bool> installer_finished{false};
    std::thread installer([&] {
        installer_started = true;
        CHECK(trace_proxy_test_update(new_config, new_scene, new_module));
        installer_finished = true;
    });
    while (!installer_started.load()) std::this_thread::yield();
    CHECK(!installer_finished.load());

    {
        std::lock_guard<std::mutex> lock(g_gate_mutex);
        g_release_registration = true;
    }
    g_gate_condition.notify_all();
    {
        std::unique_lock<std::mutex> lock(g_gate_mutex);
        g_gate_condition.wait(lock, [] { return g_runner_entered; });
    }
    installer.join();
    CHECK(installer_finished.load());
    {
        std::lock_guard<std::mutex> lock(g_gate_mutex);
        g_release_runner = true;
    }
    g_gate_condition.notify_all();
    entrant.join();
    trace_proxy_test_set_registration_gate(nullptr);

    CHECK(result == 0x107);
    CHECK(g_old_calls == 1);
    CHECK(g_new_calls == 0);
    CHECK(g_seen_config.package_name == "old-config");
    CHECK(g_seen_invocation.scene.name == "old-scene");
    CHECK(g_seen_invocation.module.path == "old-module");

    CHECK(trace_proxy_dispatch(trace_proxy_test_generation(new_scene.index), args, 0x99) ==
          0x207);
    CHECK(g_new_calls == 1);
    CHECK(g_seen_config.package_name == "new-config");
    CHECK(g_seen_invocation.scene.name == "new-scene");
    CHECK(g_seen_invocation.scene.end_offset == new_scene.end_offset);
    CHECK(g_seen_invocation.module.path == "new-module");
}

void unhook_failure_uses_the_saved_original_exactly_once() {
    reset_fakes();
    const TraceConfig config = config_named("unhook-failure");
    const SceneConfig scene = scene_named("unhook-failure",
                                          reinterpret_cast<uintptr_t>(old_target));
    trace_proxy_test_reset(config);
    CHECK(trace_proxy_test_update(config, scene, module_named("module")));
    g_fail_unhook = true;

    uint64_t args[8]{9};
    CHECK(trace_proxy_dispatch(0, args, 0x1234) == 0x109);
    CHECK(g_old_calls == 1);
    CHECK(g_bridge_calls == 1);
    CHECK(g_runner_calls == 0);
    CHECK(g_unhook_calls == 1);
}

void rehook_failure_leaves_a_coherent_direct_execution_state() {
    reset_fakes();
    const TraceConfig config = config_named("rehook-failure");
    const SceneConfig scene = scene_named("rehook-failure",
                                          reinterpret_cast<uintptr_t>(old_target));
    trace_proxy_test_reset(config);
    CHECK(trace_proxy_test_update(config, scene, module_named("module")));
    g_fail_next_hook = true;

    uint64_t args[8]{11};
    CHECK(trace_proxy_dispatch(0, args, 0) == 0x10b);
    CHECK(g_old_calls == 1);
    CHECK(trace_proxy_dispatch(0, args, 0) == 0x10b);
    CHECK(g_old_calls == 2);
    CHECK(g_new_calls == 0);
}

void every_physical_rehook_gets_a_new_proxy_identity() {
    reset_fakes();
    const TraceConfig config = config_named("physical-rehook-generation");
    const SceneConfig scene = scene_named("physical-rehook-generation",
                                          reinterpret_cast<uintptr_t>(old_target));
    trace_proxy_test_reset(config);
    CHECK(trace_proxy_test_update(config, scene, module_named("module")));
    const size_t first_generation = trace_proxy_test_generation(scene.index);
    uint64_t args[8]{19};
    CHECK(trace_proxy_dispatch(first_generation, args, 0) == 0x113);
    const size_t second_generation = trace_proxy_test_generation(scene.index);
    CHECK(second_generation != first_generation);
    CHECK(g_hook_calls == 2);

    // A delayed call already carrying the first identity remains valid and cannot
    // resolve the second generation.
    CHECK(trace_proxy_dispatch(first_generation, args, 0) == 0x113);
    CHECK(g_seen_config.package_name == "physical-rehook-generation");
}

void concurrent_unhook_failures_keep_the_original_bypass_alive() {
    reset_fakes();
    const TraceConfig config = config_named("concurrent-unhook-failure");
    const SceneConfig scene = scene_named("concurrent-unhook-failure",
                                          reinterpret_cast<uintptr_t>(old_target));
    trace_proxy_test_reset(config);
    CHECK(trace_proxy_test_update(config, scene, module_named("module")));
    g_fail_unhook = true;
    {
        std::lock_guard<std::mutex> lock(g_gate_mutex);
        g_use_bridge_gate = true;
    }

    uint64_t args[8]{13};
    uint64_t first_result = 0;
    uint64_t second_result = 0;
    std::thread first([&] { first_result = trace_proxy_dispatch(0, args, 0); });
    {
        std::unique_lock<std::mutex> lock(g_gate_mutex);
        g_gate_condition.wait(lock, [] { return g_bridge_gate_entries == 1; });
    }
    std::thread second([&] { second_result = trace_proxy_dispatch(0, args, 0); });
    {
        std::unique_lock<std::mutex> lock(g_gate_mutex);
        g_gate_condition.wait(lock, [] { return g_bridge_gate_entries == 2; });
    }
    {
        std::lock_guard<std::mutex> lock(g_fake_mutex);
        CHECK(g_unhook_calls == 1);
    }
    {
        std::lock_guard<std::mutex> lock(g_gate_mutex);
        g_release_bridge = true;
    }
    g_gate_condition.notify_all();
    first.join();
    second.join();
    CHECK(first_result == 0x10d);
    CHECK(second_result == 0x10d);
    CHECK(g_old_calls == 2);
}

void same_address_updates_replace_all_metadata_and_hook_generation() {
    reset_fakes();
    TraceConfig first_config = config_named("first-config");
    SceneConfig first_scene = scene_named("first", reinterpret_cast<uintptr_t>(old_target));
    trace_proxy_test_reset(first_config);
    CHECK(trace_proxy_test_update(first_config, first_scene, module_named("first-module")));
    const size_t initial_hook_calls = g_hook_calls;

    TraceConfig second_config = config_named("second-config");
    SceneConfig second_scene = scene_named("second", reinterpret_cast<uintptr_t>(old_target));
    second_scene.end_offset += 0x40;
    CHECK(trace_proxy_test_update(second_config, second_scene,
                                   module_named("reloaded-module", 0x300000)));
    CHECK(g_hook_calls == initial_hook_calls + 1);
    CHECK(g_unhook_calls == 1);

    uint64_t args[8]{3};
    CHECK(trace_proxy_dispatch(trace_proxy_test_generation(second_scene.index), args, 0) ==
          0x103);
    CHECK(g_seen_config.package_name == "second-config");
    CHECK(g_seen_invocation.scene.name == "second");
    CHECK(g_seen_invocation.scene.end_offset == second_scene.end_offset);
    CHECK(g_seen_invocation.module.path == "reloaded-module");
    CHECK(g_seen_invocation.module.end == 0x300000);
}

void scene_indices_outside_the_stub_region_are_rejected() {
    reset_fakes();
    const TraceConfig config = config_named("bounds");
    const SceneConfig scene = scene_named("bounds", reinterpret_cast<uintptr_t>(old_target),
                                          256);
    trace_proxy_test_reset(config);
    CHECK(!trace_proxy_test_update(config, scene, module_named("module")));
    CHECK(g_hook_calls == 0);
}

void proxy_generation_identities_are_never_reused_and_exhaust_safely() {
    reset_fakes();
    const TraceConfig config = config_named("generation-capacity");
    const SceneConfig scene = scene_named("generation-capacity",
                                          reinterpret_cast<uintptr_t>(old_target));
    trace_proxy_test_reset(config);
    for (size_t generation = 0; generation < 4096; ++generation) {
        CHECK(trace_proxy_test_update(config, scene, module_named("module")));
        CHECK(trace_proxy_test_generation(scene.index) == generation);
    }
    CHECK(!trace_proxy_test_update(config, scene, module_named("module")));
    CHECK(g_hook_calls == 4096);
}

void residual_hook_without_an_original_never_branches_to_null() {
    reset_fakes();
    const TraceConfig config = config_named("residual");
    const SceneConfig scene = scene_named("residual", reinterpret_cast<uintptr_t>(old_target));
    trace_proxy_test_reset(config);
    g_install_residual_hook = true;
    CHECK(!trace_proxy_test_update(config, scene, module_named("module")));
    g_fail_unhook = true;

    uint64_t args[8]{17};
    CHECK(trace_proxy_dispatch(0, args, 0) == 0);
    CHECK(g_bridge_calls == 0);
    CHECK(g_runner_calls == 0);
    CHECK(g_old_calls == 0);
    CHECK(g_unhook_calls == 1);
}

} // namespace

bool init_inline_hook() { return true; }

bool hook_function_address(uintptr_t target, void *, HookHandle *handle) {
    std::lock_guard<std::mutex> lock(g_fake_mutex);
    ++g_hook_calls;
    if (g_install_residual_hook) {
        g_install_residual_hook = false;
        handle->target = target;
        handle->original = nullptr;
        handle->retained_original = nullptr;
        handle->stub = reinterpret_cast<void *>(g_hook_calls + 1);
        handle->residual_hook = true;
        return false;
    }
    if (g_fail_next_hook) {
        g_fail_next_hook = false;
        return false;
    }
    handle->target = target;
    handle->original = reinterpret_cast<void *>(target);
    handle->retained_original = handle->original;
    handle->stub = reinterpret_cast<void *>(g_hook_calls + 1);
    return true;
}

bool unhook_function(HookHandle *handle) {
    std::lock_guard<std::mutex> lock(g_fake_mutex);
    ++g_unhook_calls;
    if (g_fail_unhook) return false;
    handle->stub = nullptr;
    handle->original = reinterpret_cast<void *>(new_target);
    return true;
}

TraceRunResult run_with_qbdi(const TraceConfig &config, const TraceInvocation &invocation) {
    {
        std::lock_guard<std::mutex> lock(g_fake_mutex);
        ++g_runner_calls;
        g_seen_config = config;
        g_seen_invocation = invocation;
    }
    std::unique_lock<std::mutex> gate_lock(g_gate_mutex);
    if (g_use_runner_gate) {
        g_runner_entered = true;
        g_gate_condition.notify_all();
        g_gate_condition.wait(gate_lock, [] { return g_release_runner; });
        g_use_runner_gate = false;
    }
    return {false, 0};
}

extern "C" uint64_t call_target_arm64(uintptr_t target, const uint64_t args[8], uint64_t) {
    {
        std::lock_guard<std::mutex> lock(g_fake_mutex);
        ++g_bridge_calls;
    }
    std::unique_lock<std::mutex> gate_lock(g_gate_mutex);
    if (g_use_bridge_gate) {
        ++g_bridge_gate_entries;
        g_gate_condition.notify_all();
        g_gate_condition.wait(gate_lock, [] { return g_release_bridge; });
    }
    gate_lock.unlock();
    const auto function = reinterpret_cast<GenericTargetFn>(target);
    return function(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);
}

bool find_module_executable_range(const std::string &, ModuleRange *) { return false; }
std::string basename_of(const std::string &path) { return path; }
std::vector<ModuleRange> read_process_maps() { return {}; }
void set_jni_backtrace_funcs(const std::vector<std::string> &) {}

int main() {
    branch_before_dispatch_keeps_its_generation_snapshot_and_bypass();
    entrant_registration_and_snapshot_are_atomic_with_install();
    unhook_failure_uses_the_saved_original_exactly_once();
    rehook_failure_leaves_a_coherent_direct_execution_state();
    every_physical_rehook_gets_a_new_proxy_identity();
    concurrent_unhook_failures_keep_the_original_bypass_alive();
    same_address_updates_replace_all_metadata_and_hook_generation();
    scene_indices_outside_the_stub_region_are_rejected();
    proxy_generation_identities_are_never_reused_and_exhaust_safely();
    residual_hook_without_an_original_never_branches_to_null();
    return 0;
}
