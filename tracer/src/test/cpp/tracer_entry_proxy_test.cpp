#include "core/capture_coordinator.h"
#include "core/module_maps.h"
#include "core/native_fallback_arm64.h"
#include "core/qbdi_runner.h"
#include "core/qbdi_thread_session.h"
#include "core/trace_process_lifecycle.h"
#include "core/trace_config.h"
#include "handlers/call_handlers.h"
#include "hooks/inline_hook_adapter.h"

#include <atomic>
#include <condition_variable>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <chrono>
#include <mutex>
#include <new>
#include <memory>
#include <string>
#include <thread>
#include <sys/wait.h>
#include <unistd.h>

extern "C" uint64_t trace_proxy_dispatch(size_t index, const uint64_t args[8],
                                          uint64_t indirect_result);
extern "C" {
char trace_proxy_stubs[32768]{};
}

using RegistrationGate = void (*)();
void trace_proxy_test_reset(const TraceConfig &config);
bool trace_proxy_test_update(const TraceConfig &config, const SceneConfig &scene,
                             const ModuleRange &module);
bool trace_proxy_test_repeat_current_install(const SceneConfig &scene,
                                             const ModuleRange &module);
void trace_proxy_test_set_registration_gate(RegistrationGate gate);
void trace_proxy_test_set_stub_entry_gate(RegistrationGate gate);
size_t trace_proxy_test_generation(size_t scene_index);
void trace_proxy_test_set_coordinator(
        const std::shared_ptr<CaptureCoordinator> &coordinator);
CaptureCoordinator *trace_proxy_test_hook_coordinator(size_t generation);

void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

volatile sig_atomic_t g_fail_on_child_delete = 0;
volatile sig_atomic_t g_fail_next_nothrow_allocation = 0;
std::atomic<size_t> g_throwing_allocation_calls{0};

extern "C" void *__real__Znwm(std::size_t);
extern "C" void *__wrap__Znwm(std::size_t size) {
    g_throwing_allocation_calls.fetch_add(1, std::memory_order_relaxed);
    return __real__Znwm(size);
}

extern "C" void *__real__ZnwmRKSt9nothrow_t(std::size_t, const std::nothrow_t &);
extern "C" void *__wrap__ZnwmRKSt9nothrow_t(
        std::size_t size, const std::nothrow_t &tag) {
    if (g_fail_next_nothrow_allocation != 0) {
        g_fail_next_nothrow_allocation = 0;
        return nullptr;
    }
    return __real__ZnwmRKSt9nothrow_t(size, tag);
}

extern "C" void __real__ZdlPv(void *);
extern "C" void __wrap__ZdlPv(void *pointer) {
    if (g_fail_on_child_delete != 0) _exit(96);
    __real__ZdlPv(pointer);
}

extern "C" void __real__ZdlPvm(void *, std::size_t);
extern "C" void __wrap__ZdlPvm(void *pointer, std::size_t size) {
    if (g_fail_on_child_delete != 0) _exit(96);
    __real__ZdlPvm(pointer, size);
}

extern "C" void __real__ZdaPv(void *);
extern "C" void __wrap__ZdaPv(void *pointer) {
    if (g_fail_on_child_delete != 0) _exit(96);
    __real__ZdaPv(pointer);
}

extern "C" void __real__ZdaPvm(void *, std::size_t);
extern "C" void __wrap__ZdaPvm(void *pointer, std::size_t size) {
    if (g_fail_on_child_delete != 0) _exit(96);
    __real__ZdaPvm(pointer, size);
}

namespace {

std::mutex g_fake_mutex;
TraceInvocation g_seen_invocation;
TraceConfig g_seen_config;
size_t g_runner_calls = 0;
size_t g_allocations_at_runner_entry = 0;
size_t g_bridge_calls = 0;
size_t g_hook_calls = 0;
size_t g_unhook_calls = 0;
bool g_fail_unhook = false;
bool g_fail_next_hook = false;
bool g_install_residual_hook = false;
uintptr_t g_original_override = 0;
std::atomic<size_t> g_old_calls{0};
std::atomic<size_t> g_new_calls{0};
int g_nested_fork_status = -1;
bool g_runner_forks = false;
pid_t g_runner_fork_child = -1;
std::vector<ModuleRange> g_fake_maps;

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

struct FlightProxyFactory {
    std::atomic<size_t> artifact_creates{0};
    std::atomic<size_t> session_creates{0};
    std::atomic<size_t> session_calls{0};
    std::atomic<size_t> coverage_gaps{0};
    std::atomic<uintptr_t> last_gap_pc{0};
    std::atomic<CoverageGapReason> last_gap_reason{
            CoverageGapReason::SessionFailure};
    std::atomic<uintptr_t> last_execution_entry{0};
    std::mutex gate_mutex;
    std::condition_variable gate_condition;
    size_t blocked_entries = 0;
    bool block_sessions = false;
    bool release_sessions = false;
};

FlightProxyFactory g_flight_factory;

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

uint64_t forking_target(uint64_t, uint64_t, uint64_t, uint64_t,
                        uint64_t, uint64_t, uint64_t, uint64_t) {
    const pid_t child = ::fork();
    if (child == 0) return 0xCAFE;
    if (child < 0 || ::waitpid(child, &g_nested_fork_status, 0) != child) return 0;
    return 0xBEEF;
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
    g_allocations_at_runner_entry = 0;
    g_bridge_calls = 0;
    g_hook_calls = 0;
    g_unhook_calls = 0;
    g_fail_unhook = false;
    g_fail_next_hook = false;
    g_install_residual_hook = false;
    g_original_override = 0;
    g_runner_forks = false;
    g_runner_fork_child = -1;
    g_fail_on_child_delete = 0;
    g_fail_next_nothrow_allocation = 0;
    g_throwing_allocation_calls.store(0, std::memory_order_relaxed);
    g_old_calls = 0;
    g_new_calls = 0;
    g_fake_maps.clear();
    g_flight_factory.artifact_creates.store(0, std::memory_order_relaxed);
    g_flight_factory.session_creates.store(0, std::memory_order_relaxed);
    g_flight_factory.session_calls.store(0, std::memory_order_relaxed);
    g_flight_factory.coverage_gaps.store(0, std::memory_order_relaxed);
    g_flight_factory.last_gap_pc.store(0, std::memory_order_relaxed);
    g_flight_factory.last_gap_reason.store(CoverageGapReason::SessionFailure,
                                           std::memory_order_relaxed);
    g_flight_factory.last_execution_entry.store(0, std::memory_order_relaxed);
    {
        std::lock_guard<std::mutex> flight_lock(g_flight_factory.gate_mutex);
        g_flight_factory.blocked_entries = 0;
        g_flight_factory.block_sessions = false;
        g_flight_factory.release_sessions = false;
    }
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

ModuleRange module_named(const char *path, uintptr_t end = UINTPTR_MAX - 1U) {
    ModuleRange module;
    module.start = 0;
    module.end = end;
    module.permissions = "r-xp";
    module.path = path;
    return module;
}

void *create_flight_proxy_artifact(
        void *opaque, const char *, const FlightOptions &,
        const FlightArtifactIdentityView &) noexcept {
    auto *factory = static_cast<FlightProxyFactory *>(opaque);
    factory->artifact_creates.fetch_add(1, std::memory_order_relaxed);
    return factory;
}

void destroy_flight_proxy_artifact(void *, void *) noexcept {}

TraceRunResult execute_flight_proxy_session(
        void *opaque, QbdiThreadSession *, uintptr_t entry,
        const uint64_t args[8], uint64_t indirect_result) noexcept {
    auto *factory = static_cast<FlightProxyFactory *>(opaque);
    factory->session_calls.fetch_add(1, std::memory_order_relaxed);
    factory->last_execution_entry.store(entry, std::memory_order_relaxed);
    {
        std::unique_lock<std::mutex> lock(factory->gate_mutex);
        if (factory->block_sessions) {
            ++factory->blocked_entries;
            factory->gate_condition.notify_all();
            factory->gate_condition.wait(lock, [&] {
                return factory->release_sessions;
            });
        }
    }
    return {true, call_target_arm64(entry, args, indirect_result)};
}

QbdiThreadSession *create_flight_proxy_session(
        void *opaque, void *, const TraceConfig &, const ModuleRange &,
        const SceneConfig &, uint32_t tid,
        uint32_t module_generation) noexcept {
    auto *factory = static_cast<FlightProxyFactory *>(opaque);
    factory->session_creates.fetch_add(1, std::memory_order_relaxed);
    return QbdiThreadSession::create_for_test(
            tid, module_generation, execute_flight_proxy_session, factory);
}

void destroy_flight_proxy_session(void *, QbdiThreadSession *session) noexcept {
    delete session;
}

void mark_flight_proxy_gap(void *opaque, void *, uint32_t,
                           uintptr_t pc, CoverageGapReason reason) noexcept {
    auto *factory = static_cast<FlightProxyFactory *>(opaque);
    factory->coverage_gaps.fetch_add(1, std::memory_order_relaxed);
    factory->last_gap_pc.store(pc, std::memory_order_relaxed);
    factory->last_gap_reason.store(reason, std::memory_order_relaxed);
}

CaptureCoordinatorFactories flight_proxy_factories() {
    return {&g_flight_factory, create_flight_proxy_artifact,
            destroy_flight_proxy_artifact, create_flight_proxy_session,
            destroy_flight_proxy_session, mark_flight_proxy_gap};
}

TraceConfig flight_proxy_config(const SceneConfig &scene) {
    TraceConfig config = config_named("flight-proxy");
    config.target_so = "libflight-proxy.so";
    config.flight.enabled = true;
    config.flight.max_threads = 4;
    config.flight.capacity_bytes = 64ULL * 1024ULL * 1024ULL;
    config.flight.chunk_bytes = 64U * 1024U;
    config.flight.protected_chunks = 1;
    config.scenes.push_back(scene);
    return config;
}

std::shared_ptr<CaptureCoordinator> start_flight_proxy_coordinator(
        const TraceConfig &config, const ModuleRange &module) {
    const std::shared_ptr<CaptureCoordinator> coordinator(
            new CaptureCoordinator(flight_proxy_factories()));
    CHECK(coordinator != nullptr);
    CHECK(coordinator->start(config, module, 77));
    trace_proxy_test_set_coordinator(coordinator);
    return coordinator;
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
    CHECK(g_seen_invocation.scene->name == "old-generation");
    CHECK(g_seen_invocation.module->path == "old-module");
    CHECK(trace_proxy_dispatch(new_generation, args, 0x77) == 0x105);
    CHECK(g_seen_config.package_name == "new-generation");
    CHECK(g_seen_invocation.scene->name == "new-generation");
    CHECK(g_seen_invocation.module->path == "new-module");
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
    const ModuleRange new_module = module_named("new-module", UINTPTR_MAX);
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
    CHECK(g_seen_invocation.scene->name == "old-scene");
    CHECK(g_seen_invocation.module->path == "old-module");

    CHECK(trace_proxy_dispatch(trace_proxy_test_generation(new_scene.index), args, 0x99) ==
          0x207);
    CHECK(g_new_calls == 1);
    CHECK(g_seen_config.package_name == "new-config");
    CHECK(g_seen_invocation.scene->name == "new-scene");
    CHECK(g_seen_invocation.scene->end_offset == new_scene.end_offset);
    CHECK(g_seen_invocation.module->path == "new-module");
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

void physical_rehook_keeps_its_original_capture_coordinator() {
    reset_fakes();
    const TraceConfig config = config_named("coordinator-generation");
    const SceneConfig scene = scene_named(
            "coordinator-generation", reinterpret_cast<uintptr_t>(old_target));
    trace_proxy_test_reset(config);
    const std::shared_ptr<CaptureCoordinator> original =
            std::make_shared<CaptureCoordinator>();
    const std::shared_ptr<CaptureCoordinator> replacement =
            std::make_shared<CaptureCoordinator>();
    trace_proxy_test_set_coordinator(original);
    CHECK(trace_proxy_test_update(config, scene, module_named("module")));
    const size_t first_generation = trace_proxy_test_generation(scene.index);
    CHECK(trace_proxy_test_hook_coordinator(first_generation) == original.get());

    trace_proxy_test_set_coordinator(replacement);
    uint64_t args[8]{41};
    CHECK(trace_proxy_dispatch(first_generation, args, 0) == 0x129);
    const size_t second_generation = trace_proxy_test_generation(scene.index);

    CHECK(second_generation != first_generation);
    CHECK(trace_proxy_test_hook_coordinator(second_generation) == original.get());
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
                                   module_named("reloaded-module", UINTPTR_MAX)));
    CHECK(g_hook_calls == initial_hook_calls + 1);
    CHECK(g_unhook_calls == 1);

    uint64_t args[8]{3};
    CHECK(trace_proxy_dispatch(trace_proxy_test_generation(second_scene.index), args, 0) ==
          0x103);
    CHECK(g_seen_config.package_name == "second-config");
    CHECK(g_seen_invocation.scene->name == "second");
    CHECK(g_seen_invocation.scene->end_offset == second_scene.end_offset);
    CHECK(g_seen_invocation.module->path == "reloaded-module");
    CHECK(g_seen_invocation.module->end == UINTPTR_MAX);
}

void duplicate_install_for_one_configuration_generation_is_idempotent() {
    reset_fakes();
    const TraceConfig config = config_named("one-generation");
    const SceneConfig scene = scene_named("one-generation",
                                          reinterpret_cast<uintptr_t>(old_target));
    const ModuleRange module = module_named("same-module");
    trace_proxy_test_reset(config);

    CHECK(trace_proxy_test_repeat_current_install(scene, module));
    const size_t generation = trace_proxy_test_generation(scene.index);
    CHECK(trace_proxy_test_repeat_current_install(scene, module));

    CHECK(trace_proxy_test_generation(scene.index) == generation);
    CHECK(g_hook_calls == 1);
    CHECK(g_unhook_calls == 0);
}

void failed_same_generation_install_is_retried() {
    reset_fakes();
    const TraceConfig config = config_named("retry-generation");
    const SceneConfig scene = scene_named("retry-generation",
                                          reinterpret_cast<uintptr_t>(old_target));
    const ModuleRange module = module_named("retry-module");
    trace_proxy_test_reset(config);
    g_fail_next_hook = true;

    CHECK(!trace_proxy_test_repeat_current_install(scene, module));
    const size_t failed_generation = trace_proxy_test_generation(scene.index);
    CHECK(trace_proxy_test_repeat_current_install(scene, module));

    CHECK(g_hook_calls == 2);
    CHECK(trace_proxy_test_generation(scene.index) != failed_generation);
}

void duplicate_during_an_active_call_schedules_only_the_required_rehook() {
    reset_fakes();
    const TraceConfig config = config_named("active-duplicate");
    const SceneConfig scene = scene_named("active-duplicate",
                                          reinterpret_cast<uintptr_t>(old_target));
    const ModuleRange module = module_named("active-module");
    trace_proxy_test_reset(config);
    CHECK(trace_proxy_test_repeat_current_install(scene, module));
    const size_t first_generation = trace_proxy_test_generation(scene.index);
    {
        std::lock_guard<std::mutex> lock(g_gate_mutex);
        g_use_runner_gate = true;
    }

    uint64_t args[8]{23};
    uint64_t result = 0;
    std::thread active([&] { result = trace_proxy_dispatch(first_generation, args, 0); });
    {
        std::unique_lock<std::mutex> lock(g_gate_mutex);
        g_gate_condition.wait(lock, [] { return g_runner_entered; });
    }
    CHECK(trace_proxy_test_repeat_current_install(scene, module));
    {
        std::lock_guard<std::mutex> lock(g_gate_mutex);
        g_release_runner = true;
    }
    g_gate_condition.notify_all();
    active.join();

    CHECK(result == 0x117);
    CHECK(g_hook_calls == 2);
    CHECK(g_unhook_calls == 1);
    CHECK(trace_proxy_test_generation(scene.index) != first_generation);
}

void observer_module_is_normalized_to_load_bias_and_exact_readable_exec_map() {
    reset_fakes();
    ModuleRange read_only;
    read_only.start = 0x70000000;
    read_only.end = 0x70001000;
    read_only.file_offset = 0;
    read_only.permissions = "r--p";
    read_only.path = "/data/app/libtarget.so";
    ModuleRange execute_only;
    execute_only.start = 0x70001000;
    execute_only.end = 0x70002000;
    execute_only.file_offset = 0x1000;
    execute_only.permissions = "--xp";
    execute_only.path = read_only.path;
    ModuleRange executable;
    executable.start = 0x70002000;
    executable.end = 0x70004000;
    executable.file_offset = 0x2000;
    executable.permissions = "r-xp";
    executable.path = read_only.path;
    g_fake_maps = {read_only, execute_only, executable};

    ModuleRange normalized;
    CHECK(normalize_module_ranges(g_fake_maps, executable.path, 0x70000000, 0x4000,
                                  &normalized));
    CHECK(normalized.start == 0x70000000);
    CHECK(normalized.end == 0x70004000);
    CHECK(normalized.readable_executable_range_count == 1);
    CHECK(normalized.readable_executable_ranges[0].start == 0x70002000);
    CHECK(normalized.readable_executable_ranges[0].end == 0x70004000);
    CHECK(normalized.path == executable.path);

    ModuleRange detached;
    CHECK(normalize_module_ranges(g_fake_maps, "libtarget.so", 0, 0, &detached));
    CHECK(detached.start == normalized.start);
    CHECK(detached.readable_executable_range_count ==
          normalized.readable_executable_range_count);

    CHECK(!normalize_module_ranges(g_fake_maps, executable.path, UINTPTR_MAX - 1U, 4,
                                   &normalized));

    ModuleRange outside_observer = executable;
    outside_observer.start = 0x70004000;
    outside_observer.end = 0x70005000;
    outside_observer.file_offset = 0x4000;
    g_fake_maps.push_back(outside_observer);
    CHECK(!normalize_module_ranges(g_fake_maps, executable.path, 0x70000000, 0x4000,
                                   &normalized));
    g_fake_maps.pop_back();

    ModuleRange duplicate = executable;
    duplicate.start = 0x71002000;
    duplicate.end = 0x71004000;
    duplicate.path = "/other/libtarget.so";
    g_fake_maps.push_back(duplicate);
    CHECK(!normalize_module_ranges(g_fake_maps, "libtarget.so", 0, 0, &normalized));
}

void scene_offsets_must_stay_inside_the_normalized_module() {
    reset_fakes();
    const TraceConfig config = config_named("bounded-scene");
    trace_proxy_test_reset(config);
    const ModuleRange module = module_named("bounded-module", 0x100);

    SceneConfig outside = scene_named("outside", 0x100);
    CHECK(!trace_proxy_test_repeat_current_install(outside, module));

    SceneConfig bad_end = scene_named("bad-end", 0x80);
    bad_end.end_offset = 0x101;
    CHECK(!trace_proxy_test_repeat_current_install(bad_end, module));

    uintptr_t address = 0;
    CHECK(module_offset_address(module, 0xff, false, &address));
    CHECK(address == 0xff);
    CHECK(module_offset_address(module, 0x100, true, &address));
    CHECK(address == 0x100);
    CHECK(!module_offset_address(module, 0x100, false, &address));
    CHECK(!module_offset_address(module, 0x101, true, &address));
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

void fork_waits_for_transition_and_child_uses_inherited_bypass_without_deadlock() {
    reset_fakes();
    const TraceConfig config = config_named("fork-generation");
    const SceneConfig scene = scene_named("fork-generation",
                                          reinterpret_cast<uintptr_t>(old_target));
    trace_proxy_test_reset(config);
    CHECK(trace_proxy_test_update(config, scene, module_named("fork-module")));
    trace_proxy_test_set_registration_gate(registration_gate);

    uint64_t args[8]{9};
    std::thread entrant([&] { (void)trace_proxy_dispatch(0, args, 0); });
    {
        std::unique_lock<std::mutex> lock(g_gate_mutex);
        g_gate_condition.wait(lock, [] { return g_registration_entered; });
    }
    std::atomic<bool> fork_started{false};
    int child_status = -1;
    std::thread forker([&] {
        fork_started = true;
        const pid_t child = ::fork();
        if (child == 0) {
            const size_t runner_before = g_runner_calls;
            const uint64_t value = trace_proxy_dispatch(0, args, 0);
            _exit(value == 0x109 && g_runner_calls == runner_before ? 0 : 93);
        }
        if (child < 0 || ::waitpid(child, &child_status, 0) != child) child_status = -1;
    });
    while (!fork_started.load()) std::this_thread::yield();
    {
        std::lock_guard<std::mutex> lock(g_gate_mutex);
        g_release_registration = true;
    }
    g_gate_condition.notify_all();
    entrant.join();
    forker.join();
    trace_proxy_test_set_registration_gate(nullptr);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
}

void target_fork_child_skips_inherited_proxy_postamble() {
    reset_fakes();
    g_nested_fork_status = -1;
    const TraceConfig config = config_named("target-fork");
    const SceneConfig scene = scene_named("target-fork",
                                          reinterpret_cast<uintptr_t>(forking_target));
    trace_proxy_test_reset(config);
    CHECK(trace_proxy_test_update(config, scene, module_named("fork-module")));
    uint64_t args[8]{};
    const uint64_t result = trace_proxy_dispatch(0, args, 0);
    if (result == 0xCAFE) _exit(0);
    CHECK(result == 0xBEEF);
    CHECK(WIFEXITED(g_nested_fork_status) && WEXITSTATUS(g_nested_fork_status) == 0);
}

void traced_runner_fork_child_performs_no_proxy_deallocation() {
    reset_fakes();
    const TraceConfig config = config_named(
            "traced-runner-fork-with-non-small-string-storage");
    const SceneConfig scene = scene_named(
            "traced-runner-fork-with-non-small-string-storage",
            reinterpret_cast<uintptr_t>(old_target));
    trace_proxy_test_reset(config);
    CHECK(trace_proxy_test_update(config, scene, module_named(
            "traced-runner-fork-module-with-non-small-string-storage")));
    g_runner_forks = true;

    uint64_t args[8]{};
    const uint64_t result = trace_proxy_dispatch(0, args, 0);
    if (result == 0xCAFE) _exit(0);
    CHECK(result == 0xBEEF);

    int status = -1;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    pid_t waited = 0;
    while ((waited = ::waitpid(g_runner_fork_child, &status, WNOHANG)) == 0 &&
           std::chrono::steady_clock::now() < deadline) {
        ::usleep(1000);
    }
    if (waited == 0) {
        (void)::kill(g_runner_fork_child, SIGKILL);
        waited = ::waitpid(g_runner_fork_child, &status, 0);
    }
    CHECK(waited == g_runner_fork_child);
    CHECK(WIFEXITED(status));
    if (WEXITSTATUS(status) != 0) {
        std::fprintf(stderr, "traced runner child exit=%d\n", WEXITSTATUS(status));
    }
    CHECK(WEXITSTATUS(status) == 0);
}

void proxy_runtime_allocation_failure_executes_the_target_once() {
    reset_fakes();
    const TraceConfig config = config_named("proxy-runtime-allocation-failure");
    const SceneConfig scene = scene_named(
            "proxy-runtime-allocation-failure",
            reinterpret_cast<uintptr_t>(old_target));
    trace_proxy_test_reset(config);
    CHECK(trace_proxy_test_update(config, scene, module_named("allocation-failure-module")));

    uint64_t args[8]{29};
    g_fail_next_nothrow_allocation = 1;
    CHECK(trace_proxy_dispatch(0, args, 0x1234) == 0x11D);
    CHECK(g_old_calls == 1);
    CHECK(g_runner_calls == 0);
}

void proxy_runtime_snapshot_performs_no_throwing_allocation() {
    reset_fakes();
    const TraceConfig config = config_named(
            "proxy-runtime-zero-copy-snapshot-with-long-storage");
    const SceneConfig scene = scene_named(
            "proxy-runtime-zero-copy-snapshot-with-long-storage",
            reinterpret_cast<uintptr_t>(old_target));
    trace_proxy_test_reset(config);
    CHECK(trace_proxy_test_update(config, scene, module_named(
            "proxy-runtime-zero-copy-module-with-long-storage")));

    uint64_t args[8]{31};
    g_throwing_allocation_calls.store(0, std::memory_order_relaxed);
    CHECK(trace_proxy_dispatch(0, args, 0) == 0x11F);
    CHECK(g_allocations_at_runner_entry == 0);
    CHECK(g_old_calls == 1);
}

void atfork_install_failure_bypasses_tracing_and_executes_target_once() {
    reset_fakes();
    const TraceConfig config = config_named("atfork-registration-failure");
    const SceneConfig scene = scene_named(
            "atfork-registration-failure", reinterpret_cast<uintptr_t>(old_target));
    trace_proxy_test_reset(config);
    CHECK(trace_proxy_test_update(config, scene, module_named("atfork-failure-module")));

    trace_process_test_force_lifecycle_error(ENOMEM);
    uint64_t args[8]{37};
    CHECK(trace_proxy_dispatch(0, args, 0) == 0x125);
    CHECK(g_old_calls == 1);
    CHECK(g_runner_calls == 0);
    CHECK(!trace_proxy_test_update(config, scene, module_named("must-not-install")));
}

void flight_hook_install_failure_latches_a_specific_gap() {
    reset_fakes();
    const SceneConfig scene = scene_named(
            "flight-install-failure", reinterpret_cast<uintptr_t>(new_target));
    const TraceConfig config = flight_proxy_config(scene);
    const ModuleRange module = module_named("/data/app/libflight-proxy.so");
    trace_proxy_test_reset(config);
    const std::shared_ptr<CaptureCoordinator> coordinator =
            start_flight_proxy_coordinator(config, module);
    g_fail_next_hook = true;

    CHECK(!trace_proxy_test_update(config, scene, module));
    CHECK(coordinator->incomplete());
    CHECK(g_flight_factory.coverage_gaps.load(std::memory_order_relaxed) == 1);
    CHECK(g_flight_factory.last_gap_pc.load(std::memory_order_relaxed) ==
          reinterpret_cast<uintptr_t>(new_target));
    CHECK(g_flight_factory.last_gap_reason.load(std::memory_order_relaxed) ==
          CoverageGapReason::HookSetup);
}

void concurrent_flight_gateway_keeps_the_hook_persistent() {
    reset_fakes();
    const SceneConfig scene = scene_named(
            "persistent-flight", reinterpret_cast<uintptr_t>(new_target));
    const TraceConfig config = flight_proxy_config(scene);
    const ModuleRange module = module_named("/data/app/libflight-proxy.so");
    trace_proxy_test_reset(config);
    const std::shared_ptr<CaptureCoordinator> coordinator =
            start_flight_proxy_coordinator(config, module);
    (void)coordinator;
    g_original_override = reinterpret_cast<uintptr_t>(old_target);
    CHECK(trace_proxy_test_update(config, scene, module));
    const size_t generation = trace_proxy_test_generation(scene.index);
    {
        std::lock_guard<std::mutex> lock(g_flight_factory.gate_mutex);
        g_flight_factory.block_sessions = true;
    }

    uint64_t first_args[8]{51};
    uint64_t second_args[8]{52};
    uint64_t first_result = 0;
    uint64_t second_result = 0;
    std::thread first([&] {
        first_result = trace_proxy_dispatch(generation, first_args, 0);
    });
    std::thread second([&] {
        second_result = trace_proxy_dispatch(generation, second_args, 0);
    });
    {
        std::unique_lock<std::mutex> lock(g_flight_factory.gate_mutex);
        g_flight_factory.gate_condition.wait(lock, [] {
            return g_flight_factory.blocked_entries == 2;
        });
        g_flight_factory.release_sessions = true;
    }
    g_flight_factory.gate_condition.notify_all();
    first.join();
    second.join();

    CHECK(first_result == 0x133);
    CHECK(second_result == 0x134);
    CHECK(g_unhook_calls == 0);
    CHECK(g_hook_calls == 1);
    CHECK(g_flight_factory.session_creates.load(std::memory_order_relaxed) == 2);
    CHECK(g_flight_factory.session_calls.load(std::memory_order_relaxed) == 2);
    CHECK(g_flight_factory.last_execution_entry.load(std::memory_order_relaxed) ==
          reinterpret_cast<uintptr_t>(old_target));
    CHECK(!coordinator->incomplete());
}

void flight_rejects_a_different_same_basename_mapping() {
    reset_fakes();
    SceneConfig scene = scene_named("module-generation", 0x100);
    const TraceConfig config = flight_proxy_config(scene);
    ModuleRange retained = module_named("/data/app/a/libflight-proxy.so", 0x71010000);
    retained.start = 0x71000000;
    retained.readable_executable_ranges[0] = {retained.start, retained.end};
    retained.readable_executable_range_count = 1;
    ModuleRange replacement = retained;
    replacement.start = 0x72000000;
    replacement.end = 0x72010000;
    replacement.path = "/data/app/b/libflight-proxy.so";
    replacement.readable_executable_ranges[0] = {replacement.start, replacement.end};
    trace_proxy_test_reset(config);
    const std::shared_ptr<CaptureCoordinator> coordinator =
            start_flight_proxy_coordinator(config, retained);

    CHECK(!trace_proxy_test_update(config, scene, replacement));
    CHECK(g_hook_calls == 0);
    CHECK(coordinator->incomplete());
    CHECK(g_flight_factory.coverage_gaps.load(std::memory_order_relaxed) == 1);
    CHECK(g_flight_factory.last_gap_pc.load(std::memory_order_relaxed) ==
          replacement.start + scene.offset);
}

void flight_native_bypass_latches_a_coverage_gap() {
    reset_fakes();
    const SceneConfig scene = scene_named(
            "flight-native-bypass", reinterpret_cast<uintptr_t>(new_target));
    const TraceConfig config = flight_proxy_config(scene);
    const ModuleRange module = module_named("/data/app/libflight-proxy.so");
    trace_proxy_test_reset(config);
    const std::shared_ptr<CaptureCoordinator> coordinator =
            start_flight_proxy_coordinator(config, module);
    g_original_override = reinterpret_cast<uintptr_t>(old_target);
    CHECK(trace_proxy_test_update(config, scene, module));
    const size_t generation = trace_proxy_test_generation(scene.index);

    uint64_t args[8]{61};
    g_fail_next_nothrow_allocation = 1;
    CHECK(trace_proxy_dispatch(generation, args, 0) == 0x13D);
    CHECK(g_old_calls == 1);
    CHECK(g_flight_factory.session_calls.load(std::memory_order_relaxed) == 0);
    CHECK(coordinator->incomplete());
    CHECK(g_flight_factory.coverage_gaps.load(std::memory_order_relaxed) == 1);
    CHECK(g_flight_factory.last_gap_pc.load(std::memory_order_relaxed) ==
          reinterpret_cast<uintptr_t>(new_target));
    CHECK(g_flight_factory.last_gap_reason.load(std::memory_order_relaxed) ==
          CoverageGapReason::NativeBypass);
}

void active_flight_reconfiguration_is_rejected_as_incomplete() {
    reset_fakes();
    const SceneConfig scene = scene_named(
            "active-flight-reconfigure", reinterpret_cast<uintptr_t>(new_target));
    const TraceConfig first_config = flight_proxy_config(scene);
    const ModuleRange module = module_named("/data/app/libflight-proxy.so");
    trace_proxy_test_reset(first_config);
    const std::shared_ptr<CaptureCoordinator> first_coordinator =
            start_flight_proxy_coordinator(first_config, module);
    (void)first_coordinator;
    g_original_override = reinterpret_cast<uintptr_t>(old_target);
    CHECK(trace_proxy_test_update(first_config, scene, module));
    const size_t generation = trace_proxy_test_generation(scene.index);
    {
        std::lock_guard<std::mutex> lock(g_flight_factory.gate_mutex);
        g_flight_factory.block_sessions = true;
    }
    uint64_t args[8]{71};
    uint64_t result = 0;
    std::thread active([&] { result = trace_proxy_dispatch(generation, args, 0); });
    {
        std::unique_lock<std::mutex> lock(g_flight_factory.gate_mutex);
        g_flight_factory.gate_condition.wait(lock, [] {
            return g_flight_factory.blocked_entries == 1;
        });
    }

    TraceConfig replacement_config = first_config;
    replacement_config.package_name = "replacement-flight";
    const std::shared_ptr<CaptureCoordinator> replacement_coordinator =
            start_flight_proxy_coordinator(replacement_config, module);
    CHECK(!trace_proxy_test_update(replacement_config, scene, module));
    CHECK(replacement_coordinator->incomplete());
    CHECK(g_unhook_calls == 0);
    CHECK(g_hook_calls == 1);

    {
        std::lock_guard<std::mutex> lock(g_flight_factory.gate_mutex);
        g_flight_factory.release_sessions = true;
    }
    g_flight_factory.gate_condition.notify_all();
    active.join();
    CHECK(result == 0x147);
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
    handle->original = reinterpret_cast<void *>(
            g_original_override != 0 ? g_original_override : target);
    handle->retained_original = handle->original;
    handle->retained_original_bytes = kShadowHookArm64OriginalSlotBytes;
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
        g_allocations_at_runner_entry =
                g_throwing_allocation_calls.load(std::memory_order_relaxed);
        g_seen_config = config;
        g_seen_invocation = invocation;
    }
    if (g_runner_forks) {
        const pid_t child = ::fork();
        if (child == 0) {
            g_fail_on_child_delete = 1;
            return {true, 0xCAFE};
        }
        if (child < 0) return {true, 0};
        g_runner_fork_child = child;
        return {true, 0xBEEF};
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

void set_jni_backtrace_funcs(const std::vector<std::string> &) {}

int main(int argc, char **argv) {
    if (argc == 2) {
        const std::string_view selected(argv[1]);
        if (selected == "flight-hook-failure") {
            flight_hook_install_failure_latches_a_specific_gap();
            return 0;
        }
        if (selected == "persistent-flight") {
            concurrent_flight_gateway_keeps_the_hook_persistent();
            return 0;
        }
        if (selected == "module-generation") {
            flight_rejects_a_different_same_basename_mapping();
            return 0;
        }
        if (selected == "flight-native-bypass") {
            flight_native_bypass_latches_a_coverage_gap();
            return 0;
        }
        if (selected == "flight-active-reconfigure") {
            active_flight_reconfiguration_is_rejected_as_incomplete();
            return 0;
        }
        return 2;
    }
    branch_before_dispatch_keeps_its_generation_snapshot_and_bypass();
    entrant_registration_and_snapshot_are_atomic_with_install();
    unhook_failure_uses_the_saved_original_exactly_once();
    rehook_failure_leaves_a_coherent_direct_execution_state();
    every_physical_rehook_gets_a_new_proxy_identity();
    physical_rehook_keeps_its_original_capture_coordinator();
    concurrent_unhook_failures_keep_the_original_bypass_alive();
    same_address_updates_replace_all_metadata_and_hook_generation();
    duplicate_install_for_one_configuration_generation_is_idempotent();
    failed_same_generation_install_is_retried();
    duplicate_during_an_active_call_schedules_only_the_required_rehook();
    observer_module_is_normalized_to_load_bias_and_exact_readable_exec_map();
    scene_offsets_must_stay_inside_the_normalized_module();
    scene_indices_outside_the_stub_region_are_rejected();
    proxy_generation_identities_are_never_reused_and_exhaust_safely();
    residual_hook_without_an_original_never_branches_to_null();
    fork_waits_for_transition_and_child_uses_inherited_bypass_without_deadlock();
    target_fork_child_skips_inherited_proxy_postamble();
    traced_runner_fork_child_performs_no_proxy_deallocation();
    proxy_runtime_allocation_failure_executes_the_target_once();
    proxy_runtime_snapshot_performs_no_throwing_allocation();
    flight_hook_install_failure_latches_a_specific_gap();
    concurrent_flight_gateway_keeps_the_hook_persistent();
    flight_rejects_a_different_same_basename_mapping();
    flight_native_bypass_latches_a_coverage_gap();
    active_flight_reconfiguration_is_rejected_as_incomplete();
    atfork_install_failure_bypasses_tracing_and_executes_target_once();
    return 0;
}
