#include "core/capture_coordinator.h"
#include "core/logging.h"
#include "core/module_maps.h"
#include "core/native_fallback_arm64.h"
#include "core/qbdi_runner.h"
#include "core/qbdi_thread_session.h"
#include "core/trace_config.h"
#include "core/trace_process_lifecycle.h"
#include "handlers/call_handlers.h"
#include "hooks/inline_hook_adapter.h"
#include "hooks/thread_create_gateway.h"

#include <array>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <memory>
#include <mutex>
#include <new>
#include <pthread.h>
#include <link.h>
#include <sys/syscall.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

struct InstalledSceneHook {
    std::mutex transition_mutex;
    TraceConfig config;
    SceneConfig scene;
    HookHandle hook;
    ModuleRange module;
    std::shared_ptr<CaptureCoordinator> coordinator;
    TraceConfig pending_config;
    SceneConfig pending_scene;
    ModuleRange pending_module;
    std::shared_ptr<CaptureCoordinator> pending_coordinator;
    size_t active_proxy_calls = 0;
    size_t proxy_generation = 0;
    uint64_t config_generation = 0;
    uint64_t pending_config_generation = 0;
    bool pending_install = false;
    bool unhook_failed_window = false;
    bool installed = false;
    bool retired = false;
};

struct ProxyCallRuntime {
    std::shared_ptr<InstalledSceneHook> hook;
    TraceInvocation invocation;
};

static std::mutex g_lock;
static TraceConfig g_config = default_trace_config();
static bool g_configured = false;
static uint64_t g_config_generation = 0;
static std::shared_ptr<CaptureCoordinator> g_capture_coordinator;

static constexpr size_t kMaxScenes = 256;
static constexpr size_t kMaxProxyGenerations = 4096;
static constexpr size_t kProxyStubBytes = 8;
static std::array<std::shared_ptr<InstalledSceneHook>, kMaxScenes> g_scene_hooks;
static std::array<std::shared_ptr<InstalledSceneHook>, kMaxProxyGenerations>
        g_hook_generations;
static std::array<InstalledSceneHook *, kMaxProxyGenerations> g_hook_generation_raw{};
static size_t g_next_proxy_generation = 0;
static size_t g_atfork_locked_generations = 0;
static std::atomic<int> g_tracer_atfork_error{EAGAIN};
static std::atomic<int> g_module_callback_state{0};

#if defined(QTRACE_HOST_TEST)
using RegistrationGate = void (*)();
static RegistrationGate g_registration_gate = nullptr;
static std::atomic<RegistrationGate> g_stub_entry_gate{nullptr};
#endif

static void *proxy_for_generation(size_t generation);
static bool create_hook_generation_locked(const TraceConfig &config,
                                          const SceneConfig &scene,
                                          const ModuleRange &module,
                                          uint64_t config_generation,
                                          const std::shared_ptr<CaptureCoordinator> &coordinator);
static void install_hooks_for_module(const ModuleRange &module,
                                     uint64_t expected_generation,
                                     bool loading);
static bool install_scene_hook_locked(const TraceConfig &config, const SceneConfig &scene,
                                      const ModuleRange &module,
                                      uint64_t config_generation,
                                      const std::shared_ptr<CaptureCoordinator> &coordinator);
extern "C" char trace_proxy_stubs[];

static bool tracer_fork_lifecycle_ready() noexcept {
    return trace_process_lifecycle_ready() &&
           g_tracer_atfork_error.load(std::memory_order_acquire) == 0;
}

static void install_nonflight_hooks_when_ready(
        const TraceConfig &config, uint64_t generation) {
    for (int attempt = 0; attempt < 200; ++attempt) {
        ModuleRange module;
        if (find_loaded_module(config.target_so, 0, 0, &module)) {
            install_hooks_for_module(module, generation, false);
            return;
        }
        (void)::usleep(50 * 1000);
    }
    QTRACE_E("target module %s not found", config.target_so.c_str());
}

static void retire_module_generation(uintptr_t module_base,
                                     const char *module_path) noexcept {
    if (module_path == nullptr || module_path[0] == '\0') return;
    std::lock_guard<std::mutex> registry_guard(g_lock);
    for (size_t generation = 0; generation < g_next_proxy_generation;
         ++generation) {
        const std::shared_ptr<InstalledSceneHook> &slot =
                g_hook_generations[generation];
        if (slot == nullptr) continue;
        std::lock_guard<std::mutex> transition_guard(slot->transition_mutex);
        if (slot->retired || !slot->installed ||
            slot->module.start != module_base ||
            slot->module.path != module_path) {
            continue;
        }
        slot->pending_install = false;
        slot->installed = false;
        slot->unhook_failed_window = false;
        slot->retired = true;
        if (slot->scene.index < g_scene_hooks.size() &&
            g_scene_hooks[slot->scene.index] == slot) {
            g_scene_hooks[slot->scene.index].reset();
        }
        if (slot->coordinator != nullptr && slot->coordinator->started() &&
            !slot->coordinator->detached()) {
            slot->coordinator->mark_coverage_gap(
                    static_cast<uint32_t>(::syscall(SYS_gettid)),
                    module_base, CoverageGapReason::ModuleGeneration);
        }
    }
}

static void module_constructor_pre(struct dl_phdr_info *info, size_t,
                                   void *) noexcept {
    if (info == nullptr) return;
    ModuleRange module;
    if (!module_range_from_phdr(*info, &module)) return;
    install_hooks_for_module(module, 0, true);
}

static void module_destructor_post(struct dl_phdr_info *info, size_t,
                                   void *) noexcept {
    if (info == nullptr) return;
    retire_module_generation(static_cast<uintptr_t>(info->dlpi_addr),
                             info->dlpi_name);
}

static bool prepare_module_callbacks() noexcept {
    int expected = 0;
    if (!g_module_callback_state.compare_exchange_strong(
                expected, 2, std::memory_order_acq_rel,
                std::memory_order_acquire)) {
        return expected == 1;
    }
    const bool init_registered = register_inline_hook_dl_init_callback(
            module_constructor_pre, nullptr);
    const bool fini_registered = init_registered &&
            register_inline_hook_dl_fini_callback(
                    module_destructor_post, nullptr);
    const bool registered = init_registered && fini_registered;
    g_module_callback_state.store(registered ? 1 : -1,
                                  std::memory_order_release);
    if (!registered) {
        QTRACE_E("cannot register linker module lifecycle callbacks");
        return false;
    }
    return true;
}
static uintptr_t scene_logical_pc(const ModuleRange &module,
                                  const SceneConfig &scene) noexcept {
    uintptr_t pc = 0;
    return module_offset_address(module, scene.offset, false, &pc) ? pc : 0;
}

static void mark_flight_gateway_gap(
        const TraceConfig &config,
        const std::shared_ptr<CaptureCoordinator> &coordinator,
        const ModuleRange &module, const SceneConfig &scene,
        CoverageGapReason gap_reason,
        const char *reason) noexcept {
    (void)reason;
    if (!config.flight.enabled || coordinator == nullptr ||
        !coordinator->started()) {
        return;
    }
    const uintptr_t pc = scene_logical_pc(module, scene);
    QTRACE_E("flight gateway coverage gap scene=%s pc=0x%lx reason=%s",
             scene.name.c_str(), static_cast<unsigned long>(pc), reason);
    coordinator->mark_coverage_gap(
            static_cast<uint32_t>(::syscall(SYS_gettid)), pc, gap_reason);
}

static bool resolve_flight_thread_start(
        void *opaque, uintptr_t logical_entry,
        ThreadExecutionControl *control) noexcept {
    auto *coordinator = static_cast<CaptureCoordinator *>(opaque);
    if (coordinator == nullptr || control == nullptr) {
        return false;
    }
    if (!coordinator->contains_target_address(logical_entry)) return false;
    std::lock_guard<std::mutex> guard(g_lock);
    for (size_t generation = 0; generation < g_next_proxy_generation;
         ++generation) {
        const std::shared_ptr<InstalledSceneHook> &hook =
                g_hook_generations[generation];
        if (hook == nullptr || hook->retired || !hook->installed ||
            hook->hook.target != logical_entry ||
            hook->hook.retained_original == nullptr ||
            hook->hook.retained_original_bytes == 0) {
            continue;
        }
        const uintptr_t retained =
                reinterpret_cast<uintptr_t>(hook->hook.retained_original);
        *control = {retained, retained, hook->hook.retained_original_bytes,
                    hook};
        return true;
    }
    return false;
}

static uint64_t call_retained_original_parent(size_t generation,
                                              const uint64_t args[8],
                                              uint64_t indirect_result) {
    uintptr_t fallback_target = 0;
    std::shared_ptr<InstalledSceneHook> hook;
    {
        std::lock_guard<std::mutex> registry_guard(g_lock);
        if (generation < g_next_proxy_generation &&
            g_hook_generations[generation] != nullptr) {
            hook = g_hook_generations[generation];
            InstalledSceneHook *const raw_hook = hook.get();
            std::lock_guard<std::mutex> transition_guard(raw_hook->transition_mutex);
            fallback_target = reinterpret_cast<uintptr_t>(
                    raw_hook->hook.retained_original);
        }
    }
    if (hook != nullptr) {
        mark_flight_gateway_gap(hook->config, hook->coordinator, hook->module,
                                hook->scene,
                                CoverageGapReason::NativeBypass,
                                "proxy runtime unavailable; native bypass");
    }
    return fallback_target == 0
                   ? 0
                   : call_target_arm64(fallback_target, args, indirect_result);
}

extern "C" uint64_t trace_proxy_dispatch(size_t generation, const uint64_t args[8],
                                          uint64_t indirect_result) {
    if (trace_process_child_detached()) {
        if (generation >= kMaxProxyGenerations ||
            g_hook_generation_raw[generation] == nullptr) {
            return 0;
        }
        const uintptr_t target = reinterpret_cast<uintptr_t>(
                g_hook_generation_raw[generation]->hook.retained_original);
        return target == 0 ? 0 : call_target_arm64(target, args, indirect_result);
    }
    if (!tracer_fork_lifecycle_ready()) {
        return call_retained_original_parent(generation, args, indirect_result);
    }
#if defined(QTRACE_HOST_TEST)
    const RegistrationGate stub_gate = g_stub_entry_gate.load(std::memory_order_acquire);
    if (stub_gate != nullptr) stub_gate();
#endif
    ProxyCallRuntime *runtime = new (std::nothrow) ProxyCallRuntime();
    if (runtime == nullptr) {
        QTRACE_E("cannot allocate proxy call runtime generation=%zu", generation);
        return call_retained_original_parent(generation, args, indirect_result);
    }
    uintptr_t execution_target = 0;
    bool use_original_bypass = false;
    bool safe_to_dispatch = true;
    {
        std::lock_guard<std::mutex> registry_guard(g_lock);
        if (generation >= g_next_proxy_generation ||
            g_hook_generations[generation] == nullptr) {
            QTRACE_E("trace proxy for invalid generation=%zu", generation);
            delete runtime;
            return 0;
        }
        runtime->hook = g_hook_generations[generation];
#if defined(QTRACE_HOST_TEST)
        if (g_registration_gate != nullptr) g_registration_gate();
#endif
        std::lock_guard<std::mutex> transition_guard(runtime->hook->transition_mutex);
        runtime->invocation.scene = &runtime->hook->scene;
        runtime->invocation.module = &runtime->hook->module;
        runtime->invocation.target_address =
                runtime->hook->module.start + runtime->hook->scene.offset;
        runtime->invocation.execution_address = runtime->invocation.target_address;
        std::memcpy(runtime->invocation.args.data(), args,
                    sizeof(runtime->invocation.args));
        runtime->invocation.indirect_result = indirect_result;
        execution_target = runtime->invocation.target_address;
        const bool persistent_flight = runtime->hook->config.flight.enabled &&
                                       runtime->hook->coordinator != nullptr;
        if (runtime->hook->retired) {
            execution_target = reinterpret_cast<uintptr_t>(
                    runtime->hook->hook.retained_original);
            runtime->invocation.execution_address = execution_target;
        } else if (persistent_flight) {
            execution_target = reinterpret_cast<uintptr_t>(
                    runtime->hook->hook.retained_original);
            runtime->invocation.execution_address = execution_target;
            if (!runtime->hook->installed || execution_target == 0 ||
                runtime->hook->hook.retained_original_bytes == 0) {
                mark_flight_gateway_gap(
                        runtime->hook->config, runtime->hook->coordinator,
                        runtime->hook->module, runtime->hook->scene,
                        CoverageGapReason::GatewayUnavailable,
                        "persistent hook has no retained original");
                safe_to_dispatch = false;
            }
        } else if (runtime->hook->installed) {
            if (runtime->hook->unhook_failed_window) {
                execution_target = reinterpret_cast<uintptr_t>(
                        runtime->hook->hook.retained_original);
                runtime->invocation.execution_address = execution_target;
                use_original_bypass = true;
            } else if (!unhook_function(&runtime->hook->hook)) {
                if (runtime->hook->hook.retained_original == nullptr) {
                    QTRACE_E("residual hook has no safe original bypass generation=%zu",
                             generation);
                    safe_to_dispatch = false;
                } else {
                    execution_target = reinterpret_cast<uintptr_t>(
                            runtime->hook->hook.retained_original);
                    runtime->invocation.execution_address = execution_target;
                    use_original_bypass = true;
                    runtime->hook->unhook_failed_window = true;
                    QTRACE_E("trace proxy using original bypass after unhook failure generation=%zu",
                             generation);
                }
            } else {
                runtime->hook->installed = false;
            }
        }
        // This transaction matches the installer's g_lock -> transition_mutex order.
        if (safe_to_dispatch) ++runtime->hook->active_proxy_calls;
    }
    if (!safe_to_dispatch) {
        delete runtime;
        return 0;
    }

    TraceRunResult traced{};
    if (execution_target != 0 && !use_original_bypass) {
        if (runtime->hook->config.flight.enabled &&
            runtime->hook->coordinator != nullptr) {
            CaptureCoordinator *const coordinator =
                    runtime->hook->coordinator.get();
            const uint32_t tid = static_cast<uint32_t>(::syscall(SYS_gettid));
            QbdiThreadSession *const session =
                    coordinator->enter(tid, *runtime->invocation.scene);
            if (session != nullptr) {
                traced = session->call_gateway(
                        runtime->invocation.target_address, execution_target,
                        execution_target,
                        runtime->hook->hook.retained_original_bytes,
                        runtime->invocation.args.data(),
                        runtime->invocation.indirect_result);
                if (!trace_process_child_detached()) coordinator->leave(session);
            }
        } else {
            traced = run_with_qbdi(runtime->hook->config,
                                   runtime->invocation);
        }
    }
    const bool deferred_thread_exit = traced.exit_requested;
    const uint64_t result = traced.target_executed
                                    ? traced.value
                                    : execution_target != 0
                                              ? call_target_arm64(
                                                        execution_target,
                                                        runtime->invocation.args.data(),
                                                        runtime->invocation.indirect_result)
                                              : 0;
    // atfork child already closed trace file descriptors. Keep every allocator- or
    // refcount-owning object in this one heap allocation and intentionally leak it in
    // the child; the inherited allocator and pthread state must remain untouched.
    if (trace_process_child_detached()) return result;
    {
        std::lock_guard<std::mutex> registry_guard(g_lock);
        std::lock_guard<std::mutex> transition_guard(runtime->hook->transition_mutex);
        --runtime->hook->active_proxy_calls;
        if (runtime->hook->active_proxy_calls == 0) {
            if (!runtime->hook->retired && runtime->hook->pending_install) {
                if (runtime->hook->installed &&
                    !unhook_function(&runtime->hook->hook)) {
                    runtime->hook->unhook_failed_window = false;
                } else {
                    runtime->hook->installed = false;
                    runtime->hook->unhook_failed_window = false;
                    runtime->hook->retired = true;
                    const TraceConfig pending_config =
                            std::move(runtime->hook->pending_config);
                    const SceneConfig pending_scene =
                            std::move(runtime->hook->pending_scene);
                    const ModuleRange pending_module =
                            std::move(runtime->hook->pending_module);
                    const std::shared_ptr<CaptureCoordinator> pending_coordinator =
                            std::move(runtime->hook->pending_coordinator);
                    const uint64_t pending_config_generation =
                            runtime->hook->pending_config_generation;
                    runtime->hook->pending_install = false;
                    (void)create_hook_generation_locked(
                            pending_config, pending_scene, pending_module,
                            pending_config_generation, pending_coordinator);
                }
            } else if (!runtime->hook->retired && !runtime->hook->installed) {
                // Every physical hook installation gets a distinct proxy identity.
                // A thread may still be paused in this generation's old stub.
                runtime->hook->retired = true;
                (void)create_hook_generation_locked(
                        runtime->hook->config, runtime->hook->scene,
                        runtime->hook->module, runtime->hook->config_generation,
                        runtime->hook->coordinator);
            } else if (!runtime->hook->retired) {
                runtime->hook->unhook_failed_window = false;
            }
        }
    }
    delete runtime;
    if (deferred_thread_exit) {
        ::pthread_exit(reinterpret_cast<void *>(
                static_cast<uintptr_t>(result)));
    }
    return result;
}

static void *proxy_for_generation(size_t generation) {
    if (generation >= kMaxProxyGenerations) return nullptr;
    return trace_proxy_stubs + generation * kProxyStubBytes;
}

static bool create_hook_generation_locked(const TraceConfig &config,
                                          const SceneConfig &scene,
                                          const ModuleRange &module,
                                          uint64_t config_generation,
                                          const std::shared_ptr<CaptureCoordinator> &coordinator) {
    if (g_next_proxy_generation >= kMaxProxyGenerations) {
        QTRACE_E("proxy generation capacity exhausted=%zu", kMaxProxyGenerations);
        mark_flight_gateway_gap(config, coordinator, module, scene,
                                CoverageGapReason::HookSetup,
                                "proxy generation capacity exhausted");
        return false;
    }
    uintptr_t target = 0;
    if (!module_offset_address(module, scene.offset, false, &target)) {
        QTRACE_E("scene %s offset=0x%lx outside module size=0x%lx", scene.name.c_str(),
                 static_cast<unsigned long>(scene.offset),
                 static_cast<unsigned long>(module.size()));
        mark_flight_gateway_gap(config, coordinator, module, scene,
                                CoverageGapReason::HookSetup,
                                "scene target outside retained module generation");
        return false;
    }
    const size_t generation = g_next_proxy_generation++;
    const std::shared_ptr<InstalledSceneHook> slot =
            std::make_shared<InstalledSceneHook>();
    slot->config = config;
    slot->scene = scene;
    slot->module = module;
    slot->coordinator = coordinator;
    slot->config_generation = config_generation;
    slot->proxy_generation = generation;
    g_hook_generations[generation] = slot;
    g_hook_generation_raw[generation] = slot.get();
    g_scene_hooks[scene.index] = slot;
    const bool hooked = hook_function_address(target, proxy_for_generation(generation),
                                              &slot->hook);
    slot->installed = hooked || slot->hook.residual_hook;
    if (!hooked) {
        mark_flight_gateway_gap(config, coordinator, module, scene,
                                CoverageGapReason::HookSetup,
                                slot->hook.residual_hook
                                        ? "hook install left residual gateway"
                                        : "hook install failed");
    }
    return hooked;
}

static bool install_scene_hook_locked(const TraceConfig &config, const SceneConfig &scene,
                                      const ModuleRange &module,
                                      uint64_t config_generation,
                                      const std::shared_ptr<CaptureCoordinator> &coordinator) {
    if (config.flight.enabled && coordinator != nullptr &&
        coordinator->started() && !coordinator->matches_module(module)) {
        mark_flight_gateway_gap(config, coordinator, module, scene,
                                CoverageGapReason::ModuleGeneration,
                                "module generation differs from flight artifact");
        return false;
    }
    if (scene.offset == 0) {
        QTRACE_W("scene %s offset is 0, skip", scene.name.c_str());
        mark_flight_gateway_gap(config, coordinator, module, scene,
                                CoverageGapReason::HookSetup,
                                "gateway offset is zero");
        return false;
    }
    if (scene.index >= kMaxScenes) {
        QTRACE_E("scene index=%zu exceeds proxy stub capacity=%zu", scene.index, kMaxScenes);
        mark_flight_gateway_gap(config, coordinator, module, scene,
                                CoverageGapReason::HookSetup,
                                "gateway scene index exceeds capacity");
        return false;
    }
    uintptr_t target = 0;
    if (!module_offset_address(module, scene.offset, false, &target)) {
        mark_flight_gateway_gap(config, coordinator, module, scene,
                                CoverageGapReason::HookSetup,
                                "gateway target outside module generation");
        return false;
    }
    if (scene.end_offset != 0) {
        uintptr_t range_end = 0;
        if (!module_offset_address(module, scene.end_offset, true, &range_end) ||
            range_end <= target) {
            mark_flight_gateway_gap(config, coordinator, module, scene,
                                    CoverageGapReason::HookSetup,
                                    "gateway end outside module generation");
            return false;
        }
    }
    const std::shared_ptr<InstalledSceneHook> previous = g_scene_hooks[scene.index];
    if (previous != nullptr) {
        std::lock_guard<std::mutex> transition_guard(previous->transition_mutex);
        uintptr_t previous_target = 0;
        const bool previous_target_valid = module_offset_address(
                previous->module, previous->scene.offset, false, &previous_target);
        if (!previous->retired && previous->installed &&
            previous->config_generation == config_generation &&
            previous_target_valid && previous_target == target &&
            basename_of(previous->module.path) == basename_of(module.path)) {
            return true;
        }
        if (config.flight.enabled && !previous->retired && previous->installed) {
            if (previous_target_valid && previous_target == target) {
                if (previous->active_proxy_calls != 0) {
                    mark_flight_gateway_gap(
                            config, coordinator, module, scene,
                            CoverageGapReason::Reconfiguration,
                            "gateway reconfiguration raced an active call");
                    return false;
                } else {
                    previous->config = config;
                    previous->scene = scene;
                    previous->module = module;
                    previous->coordinator = coordinator;
                    previous->config_generation = config_generation;
                }
                return true;
            }
            mark_flight_gateway_gap(config, coordinator, module, scene,
                                    CoverageGapReason::Reconfiguration,
                                    "persistent gateway target changed");
            return false;
        }
        if (previous->active_proxy_calls != 0) {
            previous->pending_config = config;
            previous->pending_scene = scene;
            previous->pending_module = module;
            previous->pending_coordinator = coordinator;
            previous->pending_config_generation = config_generation;
            previous->pending_install = true;
            return true;
        }
        if (previous->installed && !unhook_function(&previous->hook)) {
            mark_flight_gateway_gap(config, coordinator, module, scene,
                                    CoverageGapReason::HookSetup,
                                    "previous gateway unhook failed");
            return false;
        }
        previous->installed = false;
        previous->unhook_failed_window = false;
        previous->retired = true;
    }
    return create_hook_generation_locked(config, scene, module, config_generation,
                                         coordinator);
}

#if defined(QTRACE_HOST_TEST)
void trace_proxy_test_reset(const TraceConfig &config) {
    std::lock_guard<std::mutex> guard(g_lock);
    g_scene_hooks.fill(nullptr);
    g_hook_generations.fill(nullptr);
    g_hook_generation_raw.fill(nullptr);
    g_next_proxy_generation = 0;
    g_config = config;
    g_capture_coordinator.reset();
    ++g_config_generation;
    g_configured = true;
    g_registration_gate = nullptr;
    g_stub_entry_gate.store(nullptr, std::memory_order_release);
}

bool trace_proxy_test_update(const TraceConfig &config, const SceneConfig &scene,
                             const ModuleRange &module) {
    if (trace_process_child_detached() || !tracer_fork_lifecycle_ready()) return false;
    std::lock_guard<std::mutex> guard(g_lock);
    g_config = config;
    ++g_config_generation;
    return install_scene_hook_locked(config, scene, module, g_config_generation,
                                     g_capture_coordinator);
}

bool trace_proxy_test_repeat_current_install(const SceneConfig &scene,
                                             const ModuleRange &module) {
    if (!tracer_fork_lifecycle_ready()) return false;
    std::lock_guard<std::mutex> guard(g_lock);
    return install_scene_hook_locked(g_config, scene, module, g_config_generation,
                                     g_capture_coordinator);
}

void trace_proxy_test_set_registration_gate(RegistrationGate gate) {
    std::lock_guard<std::mutex> guard(g_lock);
    g_registration_gate = gate;
}

void trace_proxy_test_set_stub_entry_gate(RegistrationGate gate) {
    g_stub_entry_gate.store(gate, std::memory_order_release);
}

size_t trace_proxy_test_generation(size_t scene_index) {
    std::lock_guard<std::mutex> guard(g_lock);
    if (scene_index >= kMaxScenes || g_scene_hooks[scene_index] == nullptr) {
        return kMaxProxyGenerations;
    }
    return g_scene_hooks[scene_index]->proxy_generation;
}

void trace_proxy_test_set_coordinator(
        const std::shared_ptr<CaptureCoordinator> &coordinator) {
    std::lock_guard<std::mutex> guard(g_lock);
    g_capture_coordinator = coordinator;
    if (coordinator != nullptr) {
        coordinator->set_thread_start_resolver(resolve_flight_thread_start,
                                               coordinator.get());
    }
}

CaptureCoordinator *trace_proxy_test_hook_coordinator(size_t generation) {
    std::lock_guard<std::mutex> guard(g_lock);
    if (generation >= g_next_proxy_generation ||
        g_hook_generations[generation] == nullptr) {
        return nullptr;
    }
    return g_hook_generations[generation]->coordinator.get();
}

void trace_proxy_test_install_loading_module(const ModuleRange &module) {
    install_hooks_for_module(module, 0, true);
}

void trace_proxy_test_module_fini(uintptr_t module_base,
                                  const char *module_path) {
    retire_module_generation(module_base, module_path);
}

bool trace_proxy_test_generation_retired(size_t generation) {
    std::lock_guard<std::mutex> guard(g_lock);
    return generation < g_next_proxy_generation &&
           g_hook_generations[generation] != nullptr &&
           g_hook_generations[generation]->retired;
}
#endif

static void tracer_atfork_prepare() {
    if (trace_process_child_detached()) return;
    g_lock.lock();
    g_atfork_locked_generations = 0;
    for (size_t generation = 0; generation < g_next_proxy_generation; ++generation) {
        if (g_hook_generations[generation] == nullptr) continue;
        g_hook_generations[generation]->transition_mutex.lock();
        ++g_atfork_locked_generations;
    }
}

static void tracer_atfork_parent() {
    if (trace_process_child_detached()) return;
    size_t remaining = g_atfork_locked_generations;
    for (size_t generation = g_next_proxy_generation; generation-- > 0 && remaining != 0;) {
        if (g_hook_generations[generation] == nullptr) continue;
        g_hook_generations[generation]->transition_mutex.unlock();
        --remaining;
    }
    g_atfork_locked_generations = 0;
    g_lock.unlock();
}

static void tracer_atfork_child() {
    trace_process_mark_child_detached();
    process_thread_create_gateway().detach_after_fork_child();
    if (g_capture_coordinator != nullptr) {
        g_capture_coordinator->detach_after_fork_child();
    }
    for (size_t generation = 0; generation < g_next_proxy_generation;
         ++generation) {
        InstalledSceneHook *const hook = g_hook_generation_raw[generation];
        if (hook != nullptr && hook->coordinator != nullptr) {
            hook->coordinator->detach_after_fork_child();
        }
    }
}

static void install_hooks_for_module(const ModuleRange &module,
                                     uint64_t expected_generation,
                                     bool loading) {
    if (trace_process_child_detached() || !tracer_fork_lifecycle_ready()) return;
    std::lock_guard<std::mutex> guard(g_lock);
    if (!g_configured || trace_process_child_detached()) return;
    if (expected_generation != 0 && expected_generation != g_config_generation) return;
    if (basename_of(module.path) != g_config.target_so) return;
    (void)loading;
    if (g_config.flight.enabled) {
        if (g_capture_coordinator == nullptr || g_config_generation == 0 ||
            g_config_generation > UINT32_MAX) {
            QTRACE_E("flight coordinator unavailable");
            return;
        }
        if (!g_capture_coordinator->started() &&
            !g_capture_coordinator->start(
                    g_config, module,
                    static_cast<uint32_t>(g_config_generation))) {
            QTRACE_E("cannot start flight capture artifact");
            return;
        }
        g_capture_coordinator->set_thread_start_resolver(
                resolve_flight_thread_start, g_capture_coordinator.get());
        if (!process_thread_create_gateway().install(
                    g_capture_coordinator)) {
            QTRACE_E("cannot install persistent pthread_create gateway");
        }
    }
    QTRACE_I("target module %s base=0x%lx", g_config.target_so.c_str(),
             static_cast<unsigned long>(module.start));
    for (const auto &scene: g_config.scenes) {
        install_scene_hook_locked(g_config, scene, module, g_config_generation,
                                  g_capture_coordinator);
    }
}

extern "C" __attribute__((visibility("default"))) void
qbdi_tracer_configure(const char *encoded_config) {
    if (trace_process_child_detached() || !tracer_fork_lifecycle_ready()) return;
    TraceConfig config = parse_trace_config(encoded_config);
    if (!config.valid) {
        QTRACE_E("invalid tracer configuration: %s", config.error.c_str());
        return;
    }
    std::shared_ptr<CaptureCoordinator> coordinator;
    if (config.flight.enabled) {
        const SceneConfig *init_scene = nullptr;
        for (const SceneConfig &scene : config.scenes) {
            if (scene.index == 0 && scene.name == "init") {
                init_scene = &scene;
                break;
            }
        }
        if (init_scene == nullptr || init_scene->offset == 0) {
            QTRACE_E("flight capture requires a configured init scene");
            return;
        }
        coordinator.reset(new (std::nothrow) CaptureCoordinator());
        if (coordinator == nullptr) {
            QTRACE_E("cannot allocate flight capture coordinator");
            return;
        }
    }
    if (!init_inline_hook()) return;
    if (!prepare_module_callbacks()) return;
    uint64_t generation = 0;
    {
        std::lock_guard<std::mutex> guard(g_lock);
        g_config = config;
        g_capture_coordinator = std::move(coordinator);
        g_configured = true;
        generation = ++g_config_generation;
    }
    QTRACE_I("configure tracer package=%s target=%s", config.package_name.c_str(),
             config.target_so.c_str());
    if (!config.jni_backtrace_funcs.empty()) {
        set_jni_backtrace_funcs(config.jni_backtrace_funcs);
        QTRACE_I("jni backtrace enabled for %zu functions",
                 config.jni_backtrace_funcs.size());
    }
    ModuleRange loaded;
    if (find_loaded_module(config.target_so, 0, 0, &loaded)) {
        install_hooks_for_module(loaded, generation, false);
    } else if (!config.flight.enabled) {
        std::thread(install_nonflight_hooks_when_ready, config,
                    generation).detach();
    }
}

extern "C" __attribute__((visibility("default"))) int
qbdi_tracer_set_shadowhook_helper_path(const char *helper_path) {
    return configure_inline_hook_dl_init_helper_path(helper_path) ? 0 : -1;
}

extern "C" __attribute__((visibility("default"))) void
qbdi_tracer_install_module(const char *module_path, uintptr_t module_base, uintptr_t module_size) {
    if (trace_process_child_detached() || !tracer_fork_lifecycle_ready()) return;
    if (module_path == nullptr || module_base == 0 || module_size == 0) return;

    ModuleRange module;
    if (!find_loaded_module(module_path, module_base, module_size, &module)) {
        QTRACE_E("cannot validate observer module path=%s base=0x%lx size=0x%lx", module_path,
                 static_cast<unsigned long>(module_base),
                 static_cast<unsigned long>(module_size));
        return;
    }

    QTRACE_I("install hooks from observer module=%s base=0x%lx size=0x%lx", module_path,
             static_cast<unsigned long>(module.start), static_cast<unsigned long>(module.size()));
    install_hooks_for_module(module, 0, false);
}

__attribute__((constructor)) static void qbdi_tracer_init() {
    int install_error = trace_process_lifecycle_error();
    if (install_trace_process_lifecycle()) {
        install_error = ::pthread_atfork(tracer_atfork_prepare, tracer_atfork_parent,
                                         tracer_atfork_child);
    }
    g_tracer_atfork_error.store(install_error, std::memory_order_release);
    if (install_error != 0) {
        QTRACE_E("cannot install tracer fork lifecycle error=%d", install_error);
        return;
    }
    QTRACE_I("libqbdi_tracer loaded; waiting for qbdi_tracer_configure");
}
