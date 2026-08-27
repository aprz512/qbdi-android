#include "core/capture_coordinator.h"
#include "core/logging.h"
#include "core/module_maps.h"
#include "core/native_fallback_arm64.h"
#include "core/qbdi_runner.h"
#include "core/qbdi_thread_session.h"
#include "core/trace_config.h"
#include "core/trace_process_lifecycle.h"
#include "core/tracer_configuration.h"
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
#include <limits>
#include <sys/syscall.h>
#include <thread>
#include <type_traits>
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
    std::shared_ptr<TraceGenerationRuntime> runtime;
    TraceConfig pending_config;
    SceneConfig pending_scene;
    ModuleRange pending_module;
    std::shared_ptr<CaptureCoordinator> pending_coordinator;
    std::shared_ptr<TraceGenerationRuntime> pending_runtime;
    size_t active_proxy_calls = 0;
    size_t proxy_generation = 0;
    uint64_t config_generation = 0;
    uint64_t pending_config_generation = 0;
    bool pending_install = false;
    bool pending_batch_install = false;
    bool unhook_failed_window = false;
    bool residual_cleanup_in_progress = false;
    bool rollback_residual = false;
    bool installed = false;
    bool retired = false;
};

struct ProxyCallRuntime {
    std::shared_ptr<InstalledSceneHook> hook;
    std::shared_ptr<CaptureCoordinator> coordinator;
    TraceInvocation invocation;
};

struct DeferredRuntimeReleases {
    void reserve(size_t capacity) {
        runtimes.reserve(capacity);
        coordinators.reserve(capacity);
    }
    void push_back(std::shared_ptr<TraceGenerationRuntime> runtime) {
        if (runtime != nullptr) runtimes.push_back(std::move(runtime));
    }
    void push_back(std::shared_ptr<CaptureCoordinator> coordinator) {
        if (coordinator != nullptr) {
            coordinators.push_back(std::move(coordinator));
        }
    }

    std::vector<std::shared_ptr<TraceGenerationRuntime>> runtimes;
    std::vector<std::shared_ptr<CaptureCoordinator>> coordinators;
};

// Called only while the registry and hook transition mutexes are held. Moving
// ownership into a caller-declared collector makes the potentially joining
// runtime destructor run after those locks have been released.
static void retire_runtime_ownership_locked(
        InstalledSceneHook *hook,
        DeferredRuntimeReleases *releases) {
    if (hook == nullptr || releases == nullptr) return;
    if (hook->runtime != nullptr) {
        releases->push_back(std::move(hook->runtime));
    }
    if (hook->pending_runtime != nullptr) {
        releases->push_back(std::move(hook->pending_runtime));
    }
    if (hook->coordinator != nullptr) {
        releases->push_back(std::move(hook->coordinator));
    }
    if (hook->pending_coordinator != nullptr) {
        releases->push_back(std::move(hook->pending_coordinator));
    }
}

static std::mutex g_lock;
static std::mutex g_configuration_call_lock;
static TracerConfiguration g_tracer_configuration;
static TraceConfig g_config = default_trace_config();
static bool g_configured = false;
static uint64_t g_config_generation = 0;
static uint64_t g_failed_install_generation = 0;
static std::shared_ptr<CaptureCoordinator> g_capture_coordinator;
static std::shared_ptr<TraceGenerationRuntime> g_generation_runtime;

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
static std::atomic<RegistrationGate> g_atfork_prepare_gate{nullptr};
static std::atomic<RegistrationGate> g_stub_entry_gate{nullptr};
static RegistrationGate g_installed_status_gate = nullptr;
static RegistrationGate g_hook_commit_gate = nullptr;
static RegistrationGate g_registry_transition_gate = nullptr;
static std::atomic<bool> g_throw_during_configuration_apply{false};
static std::string g_status_output_directory;
#endif

static void *proxy_for_generation(size_t generation);
static bool create_hook_generation_locked(const TraceConfig &config,
                                          const SceneConfig &scene,
                                          const ModuleRange &module,
                                          uint64_t config_generation,
                                          const std::shared_ptr<CaptureCoordinator> &coordinator,
                                          const std::shared_ptr<TraceGenerationRuntime> &runtime,
                                          DeferredRuntimeReleases *releases,
                                          std::unique_lock<std::mutex> *registry_lock);
static void install_hooks_for_module(const ModuleRange &module,
                                     uint64_t expected_generation,
                                     bool loading);
static bool install_scene_hook_locked(const TraceConfig &config, const SceneConfig &scene,
                                      const ModuleRange &module,
                                      uint64_t config_generation,
                                      const std::shared_ptr<CaptureCoordinator> &coordinator,
                                      const std::shared_ptr<TraceGenerationRuntime> &runtime,
                                      bool batch_install,
                                      DeferredRuntimeReleases *releases,
                                      std::unique_lock<std::mutex> *registry_lock);
static std::vector<SceneConfigurationStatus> installation_statuses(
        const TraceConfig &config,
        const std::vector<SceneAddressDiagnostics> &diagnostics);
static void fail_installation_statuses(
        uint64_t generation, std::vector<SceneConfigurationStatus> *statuses,
        const char *code, int hook_error, bool registry_locked = false,
        DeferredRuntimeReleases *releases = nullptr);
static bool retire_superseded_hooks(
        uint64_t generation,
        std::vector<SceneConfigurationStatus> *statuses,
        bool append_residual_status = false,
        std::vector<size_t> *reported_residual_generations = nullptr,
        DeferredRuntimeReleases *releases = nullptr);
static bool cleanup_authoritative_residuals_locked(
        uint64_t generation,
        std::vector<SceneConfigurationStatus> *statuses,
        bool *cleaned_current_generation,
        DeferredRuntimeReleases *releases,
        std::unique_lock<std::mutex> *registry_lock);
extern "C" char trace_proxy_stubs[];

static bool tracer_fork_lifecycle_ready() noexcept {
    return trace_process_lifecycle_ready() &&
           g_tracer_atfork_error.load(std::memory_order_acquire) == 0;
}

static std::shared_ptr<TraceGenerationRuntime> create_generation_runtime(
        const TraceConfig &config, uint64_t generation) noexcept {
    TraceGenerationLimits limits;
    limits.max_scenes = kMaxScenes;
    limits.flight_max_threads = config.flight.max_threads;
    TraceGenerationStatusOptions status;
    status.config = config;
#if defined(QTRACE_HOST_TEST)
    status.output_directory = g_status_output_directory;
#endif
    return TraceGenerationRuntime::create(
            generation, config.session, limits, {}, std::move(status));
}

static bool finish_module_observation_failure(uint64_t generation) {
    std::lock_guard<std::mutex> call_guard(g_configuration_call_lock);
    uint64_t current_generation = 0;
    TraceConfig current_config;
    if (!g_tracer_configuration.current(&current_generation, &current_config) ||
        current_generation != generation) {
        return false;
    }
    constexpr const char *code = "MODULE_OBSERVATION_FAILED";
    QTRACE_E("generation=%llu code=%s target module %s unavailable",
             static_cast<unsigned long long>(generation), code,
             current_config.target_so.c_str());
    std::vector<SceneConfigurationStatus> statuses =
            installation_statuses(current_config, {});
    fail_installation_statuses(generation, &statuses, code, 0);
    return true;
}

static void install_nonflight_hooks_when_ready(
        const TraceConfig &config, uint64_t generation) {
    for (;;) {
        {
            std::lock_guard<std::mutex> guard(g_lock);
            if (!g_configured || g_config_generation != generation) return;
        }
        ModuleRange module;
        if (find_loaded_module(config.target_so, 0, 0, &module)) {
            install_hooks_for_module(module, generation, false);
            return;
        }
        (void)::usleep(50 * 1000);
    }
}

static void retire_module_generation(uintptr_t module_base,
                                     const char *module_path) noexcept {
    if (module_path == nullptr || module_path[0] == '\0') return;
    DeferredRuntimeReleases releases;
    releases.reserve(kMaxScenes * 2U);
    std::lock_guard<std::mutex> registry_guard(g_lock);
    for (size_t generation = 0; generation < g_next_proxy_generation;
         ++generation) {
        const std::shared_ptr<InstalledSceneHook> &slot =
                g_hook_generations[generation];
        if (slot == nullptr) continue;
#if defined(QTRACE_HOST_TEST)
        if (g_registry_transition_gate != nullptr) {
            g_registry_transition_gate();
        }
#endif
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
        retire_runtime_ownership_locked(slot.get(), &releases);
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
    return registered;
}
static uintptr_t scene_logical_pc(const ModuleRange &module,
                                  const SceneConfig &scene) noexcept {
    uintptr_t pc = 0;
    return checked_offset_address(module.start, scene.offset, &pc) ? pc : 0;
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
    bool proxy_registered = false;
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
        runtime->invocation.runtime = runtime->hook->runtime;
        runtime->coordinator = runtime->hook->coordinator;
        execution_target = runtime->invocation.target_address;
        const bool persistent_flight = runtime->hook->config.flight.enabled &&
                                       runtime->coordinator != nullptr;
        if (runtime->hook->retired) {
            execution_target = reinterpret_cast<uintptr_t>(
                    runtime->hook->hook.retained_original);
            runtime->invocation.execution_address = execution_target;
            use_original_bypass = true;
            safe_to_dispatch = execution_target != 0;
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
        } else if (!persistent_flight) {
            if (runtime->hook->hook.residual_hook) {
                if (!unhook_function(&runtime->hook->hook)) {
                    safe_to_dispatch = false;
                } else {
                    runtime->hook->installed = false;
                    use_original_bypass = true;
                }
            } else if (runtime->hook->unhook_failed_window) {
                execution_target = reinterpret_cast<uintptr_t>(
                        runtime->hook->hook.retained_original);
                runtime->invocation.execution_address = execution_target;
                use_original_bypass = true;
            } else {
                const uint32_t tid = static_cast<uint32_t>(
                        ::syscall(SYS_gettid));
                const TraceAdmissionResult admitted =
                        runtime->invocation.runtime == nullptr
                                ? TraceAdmissionResult{
                                          TraceAdmissionStatus::NotRunning, {}}
                                : runtime->invocation.runtime->try_begin_call(
                                          runtime->hook->config_generation,
                                          runtime->hook->scene.index, tid);
                if (admitted.status != TraceAdmissionStatus::Admitted) {
                    execution_target = reinterpret_cast<uintptr_t>(
                            runtime->hook->hook.retained_original);
                    runtime->invocation.execution_address = execution_target;
                    use_original_bypass = true;
                    safe_to_dispatch = execution_target != 0;
                } else {
                    runtime->invocation.admission = admitted.admission;
                    if (runtime->hook->installed &&
                        !unhook_function(&runtime->hook->hook)) {
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
                    } else if (runtime->hook->installed) {
                        runtime->hook->installed = false;
                    }
                }
            }
        }
        // This transaction matches the installer's g_lock -> transition_mutex order.
        if (safe_to_dispatch &&
            (persistent_flight || runtime->invocation.admission.serial != 0)) {
            ++runtime->hook->active_proxy_calls;
            proxy_registered = true;
        }
    }
    if (!safe_to_dispatch) {
        if (runtime->invocation.runtime != nullptr &&
            runtime->invocation.admission.serial != 0) {
            runtime->invocation.runtime->finish_call(
                    runtime->invocation.admission, false);
        }
        delete runtime;
        return 0;
    }

    TraceRunResult traced{};
    if (execution_target != 0 && !use_original_bypass) {
        if (runtime->hook->config.flight.enabled &&
            runtime->coordinator != nullptr) {
            CaptureCoordinator *const coordinator = runtime->coordinator.get();
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
    if (runtime->invocation.runtime != nullptr &&
        runtime->invocation.admission.serial != 0 &&
        !traced.admission_finished) {
        runtime->invocation.runtime->finish_call(
                runtime->invocation.admission, false);
    }
    if (!proxy_registered) {
        delete runtime;
        return result;
    }
    bool resume_pending_batch = false;
    ModuleRange pending_batch_module;
    uint64_t pending_batch_generation = 0;
    DeferredRuntimeReleases releases;
    releases.reserve(4);
    {
        std::unique_lock<std::mutex> registry_guard(g_lock);
        std::unique_lock<std::mutex> transition_guard(
                runtime->hook->transition_mutex);
        --runtime->hook->active_proxy_calls;
        if (runtime->hook->active_proxy_calls == 0) {
            if (!runtime->hook->retired && runtime->hook->pending_install) {
                const bool pending_batch =
                        runtime->hook->pending_batch_install;
                if (runtime->hook->installed &&
                    !unhook_function(&runtime->hook->hook)) {
                    runtime->hook->unhook_failed_window = false;
                    const bool pending_is_current =
                            runtime->hook->pending_config_generation ==
                                    g_config_generation &&
                            runtime->hook->pending_runtime != nullptr &&
                            runtime->hook->pending_runtime ==
                                    g_generation_runtime;
                    if (pending_batch && pending_is_current) {
                        pending_batch_module = runtime->hook->pending_module;
                        pending_batch_generation =
                                runtime->hook->pending_config_generation;
                        resume_pending_batch = true;
                    }
                    runtime->hook->pending_install = false;
                    runtime->hook->pending_batch_install = false;
                    releases.push_back(std::move(
                            runtime->hook->pending_runtime));
                    releases.push_back(std::move(
                            runtime->hook->pending_coordinator));
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
                    std::shared_ptr<CaptureCoordinator> pending_coordinator =
                            std::move(runtime->hook->pending_coordinator);
                    std::shared_ptr<TraceGenerationRuntime> pending_runtime =
                            std::move(runtime->hook->pending_runtime);
                    const uint64_t pending_config_generation =
                            runtime->hook->pending_config_generation;
                    const bool pending_is_current =
                            pending_config_generation == g_config_generation &&
                            pending_runtime != nullptr &&
                            pending_runtime == g_generation_runtime;
                    runtime->hook->pending_install = false;
                    runtime->hook->pending_batch_install = false;
                    retire_runtime_ownership_locked(runtime->hook.get(),
                                                    &releases);
                    if (pending_batch && pending_is_current) {
                        pending_batch_module = pending_module;
                        pending_batch_generation = pending_config_generation;
                        resume_pending_batch = true;
                    } else if (pending_is_current) {
                        const bool installed = create_hook_generation_locked(
                                pending_config, pending_scene, pending_module,
                                pending_config_generation, pending_coordinator,
                                pending_runtime, &releases, &registry_guard);
                        if (installed && pending_runtime != nullptr) {
                            (void)pending_runtime->publish_installed_status();
                            (void)pending_runtime->arm();
                        }
                    }
                    releases.push_back(std::move(pending_runtime));
                    releases.push_back(std::move(pending_coordinator));
                }
            } else if (!runtime->hook->retired && !runtime->hook->installed) {
                // Every physical hook installation gets a distinct proxy identity.
                // A thread may still be paused in this generation's old stub.
                const TraceConfig rehook_config = runtime->hook->config;
                const SceneConfig rehook_scene = runtime->hook->scene;
                const ModuleRange rehook_module = runtime->hook->module;
                const std::shared_ptr<CaptureCoordinator> rehook_coordinator =
                        runtime->hook->coordinator;
                const std::shared_ptr<TraceGenerationRuntime> rehook_runtime =
                        runtime->hook->runtime;
                runtime->hook->retired = true;
                retire_runtime_ownership_locked(runtime->hook.get(),
                                                &releases);
                // create_hook_generation_locked drops and reacquires g_lock
                // across ShadowHook. Never carry the retired generation's
                // transition lock into that registry reacquisition: atfork
                // holds g_lock while it claims every transition lock.
                transition_guard.unlock();
                (void)create_hook_generation_locked(
                        rehook_config, rehook_scene, rehook_module,
                        runtime->hook->config_generation,
                        rehook_coordinator, rehook_runtime,
                        &releases, &registry_guard);
            } else if (!runtime->hook->retired) {
                runtime->hook->unhook_failed_window = false;
            }
        }
    }
    if (resume_pending_batch) {
        install_hooks_for_module(pending_batch_module,
                                 pending_batch_generation, false);
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
                                          const std::shared_ptr<CaptureCoordinator> &coordinator,
                                          const std::shared_ptr<TraceGenerationRuntime> &runtime,
                                          DeferredRuntimeReleases *releases,
                                          std::unique_lock<std::mutex> *registry_lock) {
    if (g_next_proxy_generation >= kMaxProxyGenerations) {
        QTRACE_E("generation=%llu code=HOOK_INSTALL_FAILED proxy capacity exhausted=%zu",
                 static_cast<unsigned long long>(config_generation),
                 kMaxProxyGenerations);
        mark_flight_gateway_gap(config, coordinator, module, scene,
                                CoverageGapReason::HookSetup,
                                "proxy generation capacity exhausted");
        return false;
    }
    uintptr_t target = 0;
    if (!checked_offset_address(module.start, scene.offset, &target)) {
        QTRACE_E("generation=%llu code=ADDRESS_OVERFLOW scene=%s offset=0x%lx",
                 static_cast<unsigned long long>(config_generation),
                 scene.name.c_str(), static_cast<unsigned long>(scene.offset));
        mark_flight_gateway_gap(config, coordinator, module, scene,
                                CoverageGapReason::HookSetup,
                                "scene target address overflow");
        return false;
    }
    const size_t generation = g_next_proxy_generation++;
    const std::shared_ptr<InstalledSceneHook> slot =
            std::make_shared<InstalledSceneHook>();
    slot->config = config;
    slot->scene = scene;
    slot->module = module;
    slot->coordinator = coordinator;
    slot->runtime = runtime;
    slot->config_generation = config_generation;
    slot->proxy_generation = generation;
    g_hook_generations[generation] = slot;
    g_hook_generation_raw[generation] = slot.get();
    g_scene_hooks[scene.index] = slot;
    // ShadowHook may acquire bionic's linker lock and synchronously invoke a
    // module callback. Publish the proxy identity first, then leave the
    // registry unlocked for the entire linker operation. The transition lock
    // keeps a reachable proxy from observing a partially populated gateway.
    std::unique_lock<std::mutex> transition_lock(slot->transition_mutex);
    registry_lock->unlock();
    const bool hooked = hook_function_address(target, proxy_for_generation(generation),
                                              &slot->hook);
    slot->installed = hooked || slot->hook.residual_hook;
    if (!hooked) {
        const char *code = slot->hook.residual_hook
                           ? "HOOK_INSTALL_RESIDUAL"
                           : "HOOK_INSTALL_FAILED";
        const int hook_error = slot->hook.unhook_error != 0
                               ? slot->hook.unhook_error
                               : slot->hook.hook_error;
        QTRACE_E("generation=%llu code=%s scene=%s hook_error=%d",
                 static_cast<unsigned long long>(config_generation), code,
                 scene.name.c_str(), hook_error);
        mark_flight_gateway_gap(config, coordinator, module, scene,
                                CoverageGapReason::HookSetup,
                                slot->hook.residual_hook
                                        ? "hook install left residual gateway"
                                        : "hook install failed");
    }
    transition_lock.unlock();
#if defined(QTRACE_HOST_TEST)
    if (g_hook_commit_gate != nullptr) g_hook_commit_gate();
#endif
    registry_lock->lock();
    std::unique_lock<std::mutex> commit_lock(slot->transition_mutex);
    bool module_unchanged =
            slot->module.start == module.start &&
            slot->module.end == module.end &&
            slot->module.file_offset == module.file_offset &&
            slot->module.permissions == module.permissions &&
            slot->module.path == module.path &&
            slot->module.readable_executable_range_count ==
                    module.readable_executable_range_count;
    for (size_t index = 0;
         module_unchanged && index < module.readable_executable_range_count;
         ++index) {
        module_unchanged =
                slot->module.readable_executable_ranges[index].start ==
                        module.readable_executable_ranges[index].start &&
                slot->module.readable_executable_ranges[index].end ==
                        module.readable_executable_ranges[index].end;
    }
    const bool still_current =
            g_configured &&
            g_config_generation == config_generation &&
            g_scene_hooks[scene.index] == slot &&
            g_hook_generations[generation] == slot &&
            !slot->retired && slot->installed &&
            slot->config_generation == config_generation &&
            module_unchanged;
    if (still_current) return hooked;
    if (!hooked && !slot->hook.residual_hook) return false;

    // A module-fini or configuration replacement can retire this slot while
    // ShadowHook is operating without the registry lock. Claim the stale stub
    // under g_lock -> transition_mutex, then leave only the immutable retained
    // bypass in the retired slot. A proxy or loader callback in the external
    // unhook window therefore observes passthrough state and cannot unhook the
    // same stub, publish Installed, or acquire an admission.
    HookHandle rollback_hook = slot->hook;
    const bool needs_unhook = rollback_hook.stub != nullptr;
    slot->hook.stub = nullptr;
    slot->hook.residual_hook = false;
    slot->pending_install = false;
    slot->pending_batch_install = false;
    slot->installed = false;
    slot->unhook_failed_window = false;
    slot->residual_cleanup_in_progress = needs_unhook;
    slot->rollback_residual = false;
    slot->retired = true;
    retire_runtime_ownership_locked(slot.get(), releases);

    // ShadowHook may synchronously re-enter a loader callback. It must run
    // without either tracer mutex held. Re-enter the state machine strictly in
    // registry -> transition order after the external ownership operation.
    commit_lock.unlock();
    registry_lock->unlock();
    bool unhooked = true;
    if (needs_unhook) {
        unhooked = unhook_function(&rollback_hook);
    }
    registry_lock->lock();
    commit_lock.lock();

    slot->hook = rollback_hook;
    slot->residual_cleanup_in_progress = false;
    slot->installed = !unhooked && needs_unhook;
    slot->hook.residual_hook = !unhooked && needs_unhook;
    slot->rollback_residual = !unhooked && needs_unhook;
    if (unhooked && g_scene_hooks[scene.index] == slot) {
        g_scene_hooks[scene.index].reset();
    }
    QTRACE_E("generation=%llu code=%s scene=%s hook commit retired before publication",
             static_cast<unsigned long long>(config_generation),
             unhooked ? "HOOK_INSTALL_FAILED" : "HOOK_ROLLBACK_FAILED",
             scene.name.c_str());
    return false;
}

static bool install_scene_hook_locked(const TraceConfig &config, const SceneConfig &scene,
                                      const ModuleRange &module,
                                      uint64_t config_generation,
                                      const std::shared_ptr<CaptureCoordinator> &coordinator,
                                      const std::shared_ptr<TraceGenerationRuntime> &runtime,
                                      bool batch_install,
                                      DeferredRuntimeReleases *releases,
                                      std::unique_lock<std::mutex> *registry_lock) {
    if (config.flight.enabled && coordinator != nullptr &&
        coordinator->started() && !coordinator->matches_module(module)) {
        mark_flight_gateway_gap(config, coordinator, module, scene,
                                CoverageGapReason::ModuleGeneration,
                                "module generation differs from flight artifact");
        return false;
    }
    if (scene.offset == 0) {
        QTRACE_E("generation=%llu code=ZERO_SCENE_OFFSET scene=%s",
                 static_cast<unsigned long long>(config_generation),
                 scene.name.c_str());
        mark_flight_gateway_gap(config, coordinator, module, scene,
                                CoverageGapReason::HookSetup,
                                "gateway offset is zero");
        return false;
    }
    if (scene.index >= kMaxScenes) {
        QTRACE_E("generation=%llu code=HOOK_INSTALL_FAILED scene=%s index=%zu capacity=%zu",
                 static_cast<unsigned long long>(config_generation),
                 scene.name.c_str(), scene.index, kMaxScenes);
        mark_flight_gateway_gap(config, coordinator, module, scene,
                                CoverageGapReason::HookSetup,
                                "gateway scene index exceeds capacity");
        return false;
    }
    uintptr_t target = 0;
    if (!checked_offset_address(module.start, scene.offset, &target)) {
        mark_flight_gateway_gap(config, coordinator, module, scene,
                                CoverageGapReason::HookSetup,
                                "gateway target outside module generation");
        return false;
    }
    if (scene.end_offset != 0) {
        uintptr_t range_end = 0;
        if (!checked_offset_address(module.start, scene.end_offset, &range_end) ||
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
        const bool previous_target_valid = checked_offset_address(
                previous->module.start, previous->scene.offset, &previous_target);
        const bool previous_bypass_healthy =
                !previous->hook.residual_hook &&
                previous->hook.retained_original != nullptr;
        if (!previous->retired && previous->installed &&
            previous_bypass_healthy &&
            previous->config_generation == config_generation &&
            previous_target_valid && previous_target == target &&
            basename_of(previous->module.path) == basename_of(module.path)) {
            return true;
        }
        if (config.flight.enabled && !previous->retired &&
            previous->installed && previous_bypass_healthy) {
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
                    previous->runtime = runtime;
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
            if (!previous_bypass_healthy) {
                QTRACE_E("generation=%llu code=HOOK_INSTALL_RESIDUAL scene=%s hook_error=%d",
                         static_cast<unsigned long long>(config_generation),
                         scene.name.c_str(), previous->hook.unhook_error);
                return false;
            }
            previous->pending_config = config;
            previous->pending_scene = scene;
            previous->pending_module = module;
            previous->pending_coordinator = coordinator;
            previous->pending_runtime = runtime;
            previous->pending_config_generation = config_generation;
            previous->pending_install = true;
            previous->pending_batch_install = batch_install;
            return true;
        }
        if (previous->installed && !unhook_function(&previous->hook)) {
            QTRACE_E("generation=%llu code=HOOK_INSTALL_RESIDUAL scene=%s hook_error=%d",
                     static_cast<unsigned long long>(config_generation),
                     scene.name.c_str(), previous->hook.unhook_error);
            mark_flight_gateway_gap(config, coordinator, module, scene,
                                    CoverageGapReason::HookSetup,
                                    "previous gateway unhook failed");
            return false;
        }
        previous->installed = false;
        previous->unhook_failed_window = false;
        previous->retired = true;
        retire_runtime_ownership_locked(previous.get(), releases);
    }
    return create_hook_generation_locked(config, scene, module, config_generation,
                                         coordinator, runtime, releases,
                                         registry_lock);
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
    g_failed_install_generation = 0;
    g_generation_runtime = create_generation_runtime(config,
                                                     g_config_generation);
    if (g_generation_runtime != nullptr) {
        (void)g_generation_runtime->arm();
    }
    g_configured = true;
    g_registration_gate = nullptr;
    g_atfork_prepare_gate.store(nullptr, std::memory_order_release);
    g_stub_entry_gate.store(nullptr, std::memory_order_release);
    g_installed_status_gate = nullptr;
    g_hook_commit_gate = nullptr;
    g_registry_transition_gate = nullptr;
}

bool trace_proxy_test_current_configuration(uint64_t *generation,
                                            TraceConfig *config) {
    if (generation == nullptr || config == nullptr) return false;
    std::lock_guard<std::mutex> guard(g_lock);
    if (!g_configured) return false;
    *generation = g_config_generation;
    *config = g_config;
    return true;
}

CaptureCoordinator *trace_proxy_test_current_coordinator() {
    std::lock_guard<std::mutex> guard(g_lock);
    return g_capture_coordinator.get();
}

bool trace_proxy_test_update(const TraceConfig &config, const SceneConfig &scene,
                             const ModuleRange &module) {
    if (trace_process_child_detached() || !tracer_fork_lifecycle_ready()) return false;
    DeferredRuntimeReleases releases;
    releases.reserve(3);
    std::unique_lock<std::mutex> guard(g_lock);
    g_config = config;
    ++g_config_generation;
    if (g_generation_runtime != nullptr) {
        releases.push_back(std::move(g_generation_runtime));
    }
    g_generation_runtime = create_generation_runtime(config,
                                                     g_config_generation);
    const bool installed = install_scene_hook_locked(
            config, scene, module, g_config_generation,
            g_capture_coordinator, g_generation_runtime, false, &releases,
            &guard);
    if (installed && g_generation_runtime != nullptr &&
        scene.index < g_scene_hooks.size() &&
        g_scene_hooks[scene.index] != nullptr &&
        !g_scene_hooks[scene.index]->pending_install) {
        (void)g_generation_runtime->publish_installed_status();
        (void)g_generation_runtime->arm();
    }
    return installed;
}

bool trace_proxy_test_repeat_current_install(const SceneConfig &scene,
                                             const ModuleRange &module) {
    if (!tracer_fork_lifecycle_ready()) return false;
    DeferredRuntimeReleases releases;
    releases.reserve(2);
    std::unique_lock<std::mutex> guard(g_lock);
    const bool installed = install_scene_hook_locked(
            g_config, scene, module, g_config_generation,
            g_capture_coordinator, g_generation_runtime, false, &releases,
            &guard);
    if (installed && g_generation_runtime != nullptr &&
        scene.index < g_scene_hooks.size() &&
        g_scene_hooks[scene.index] != nullptr &&
        !g_scene_hooks[scene.index]->pending_install) {
        (void)g_generation_runtime->publish_installed_status();
        (void)g_generation_runtime->arm();
    }
    return installed;
}

void trace_proxy_test_set_registration_gate(RegistrationGate gate) {
    std::lock_guard<std::mutex> guard(g_lock);
    g_registration_gate = gate;
}

void trace_proxy_test_set_atfork_prepare_gate(RegistrationGate gate) {
    g_atfork_prepare_gate.store(gate, std::memory_order_release);
}

void trace_proxy_test_set_stub_entry_gate(RegistrationGate gate) {
    g_stub_entry_gate.store(gate, std::memory_order_release);
}

void trace_proxy_test_set_installed_status_gate(RegistrationGate gate) {
    std::lock_guard<std::mutex> guard(g_lock);
    g_installed_status_gate = gate;
}

void trace_proxy_test_set_hook_commit_gate(RegistrationGate gate) {
    std::lock_guard<std::mutex> guard(g_lock);
    g_hook_commit_gate = gate;
}

void trace_proxy_test_set_registry_transition_gate(RegistrationGate gate) {
    std::lock_guard<std::mutex> guard(g_lock);
    g_registry_transition_gate = gate;
}

void trace_proxy_test_set_status_output_directory(const char *directory) {
    std::lock_guard<std::mutex> guard(g_lock);
    g_status_output_directory = directory == nullptr ? "" : directory;
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
    std::shared_ptr<CaptureCoordinator> previous;
    {
        std::lock_guard<std::mutex> guard(g_lock);
        previous = std::move(g_capture_coordinator);
        g_capture_coordinator = coordinator;
        if (coordinator != nullptr) {
            coordinator->set_thread_start_resolver(
                    resolve_flight_thread_start, coordinator.get());
        }
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

std::shared_ptr<TraceGenerationRuntime> trace_proxy_test_current_runtime() {
    std::lock_guard<std::mutex> guard(g_lock);
    return g_generation_runtime;
}

std::shared_ptr<TraceGenerationRuntime> trace_proxy_test_hook_runtime(
        size_t generation) {
    std::lock_guard<std::mutex> guard(g_lock);
    if (generation >= g_next_proxy_generation ||
        g_hook_generations[generation] == nullptr) {
        return {};
    }
    return g_hook_generations[generation]->runtime;
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

bool trace_proxy_test_generation_installed(size_t generation) {
    std::lock_guard<std::mutex> guard(g_lock);
    return generation < g_next_proxy_generation &&
           g_hook_generations[generation] != nullptr &&
           g_hook_generations[generation]->installed;
}

bool trace_proxy_test_generation_locks_available(size_t generation) {
    if (!g_lock.try_lock()) return false;
    const std::shared_ptr<InstalledSceneHook> hook =
            generation < g_hook_generations.size()
                    ? g_hook_generations[generation]
                    : nullptr;
    if (hook == nullptr) {
        g_lock.unlock();
        return false;
    }
    const bool transition_available = hook->transition_mutex.try_lock();
    if (transition_available) hook->transition_mutex.unlock();
    g_lock.unlock();
    return transition_available;
}

bool trace_proxy_test_finish_module_observation_failure(uint64_t generation) {
    return finish_module_observation_failure(generation);
}

void trace_proxy_test_throw_during_configuration_apply() {
    g_throw_during_configuration_apply.store(true,
                                             std::memory_order_release);
}
#endif

static void tracer_atfork_prepare() {
    if (trace_process_child_detached()) return;
    g_configuration_call_lock.lock();
    // The gateway transition lock must precede the registry. Its installer may
    // be inside ShadowHook waiting for bionic's linker lock while a loader
    // callback needs g_lock; taking these in the reverse order recreates that
    // three-party cycle during fork.
    process_thread_create_gateway().prepare_for_fork();
#if defined(QTRACE_HOST_TEST)
    const RegistrationGate prepare_gate =
            g_atfork_prepare_gate.load(std::memory_order_acquire);
    if (prepare_gate != nullptr) prepare_gate();
#endif
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
    process_thread_create_gateway().resume_after_fork_parent();
    g_configuration_call_lock.unlock();
}

static void tracer_atfork_child() {
    trace_process_mark_child_detached();
    process_thread_create_gateway().detach_after_fork_child();
    if (g_generation_runtime != nullptr) {
        g_generation_runtime->detach_after_fork_child();
    }
    if (g_capture_coordinator != nullptr) {
        g_capture_coordinator->detach_after_fork_child();
    }
    for (size_t generation = 0; generation < g_next_proxy_generation;
         ++generation) {
        InstalledSceneHook *const hook = g_hook_generation_raw[generation];
        if (hook != nullptr && hook->runtime != nullptr) {
            hook->runtime->detach_after_fork_child();
        }
        if (hook != nullptr && hook->coordinator != nullptr) {
            hook->coordinator->detach_after_fork_child();
        }
    }
}

static std::vector<SceneConfigurationStatus> installation_statuses(
        const TraceConfig &config,
        const std::vector<SceneAddressDiagnostics> &diagnostics) {
    std::vector<SceneConfigurationStatus> statuses;
    statuses.reserve(config.scenes.size());
    for (size_t index = 0; index < config.scenes.size(); ++index) {
        const SceneConfig &scene = config.scenes[index];
        SceneConfigurationStatus status;
        status.name = scene.name;
        status.offset = scene.offset;
        status.state = SceneConfigurationState::Installing;
        if (index < diagnostics.size()) {
            const SceneAddressDiagnostics &diagnostic = diagnostics[index];
            status.runtime_address = diagnostic.runtime_address;
            status.runtime_end = diagnostic.runtime_end;
            for (const AddressDiagnostic &warning : diagnostic.warnings) {
                status.warnings.push_back(
                        {warning.code,
                         "$.scenes[" + std::to_string(index) + "].location",
                         warning.message});
            }
        }
        statuses.push_back(std::move(status));
    }
    return statuses;
}

static void record_installation_warnings(
        const std::shared_ptr<TraceGenerationRuntime> &runtime,
        const std::vector<SceneConfigurationStatus> &statuses) {
    if (runtime == nullptr) return;
    for (const SceneConfigurationStatus &status : statuses) {
        for (const ConfigurationIssue &warning : status.warnings) {
            (void)runtime->record_status_warning(
                    warning.code, warning.path, warning.message);
        }
    }
}

static void deactivate_flight_gateway_if_current(
        uint64_t generation, bool registry_locked) {
    bool deactivate = false;
    if (registry_locked) {
        deactivate = g_configured && g_config_generation == generation &&
                     g_config.flight.enabled;
    } else {
        std::lock_guard<std::mutex> guard(g_lock);
        deactivate = g_configured && g_config_generation == generation &&
                     g_config.flight.enabled;
    }
    if (deactivate) process_thread_create_gateway().deactivate();
}

static void fail_installation_statuses(
        uint64_t generation, std::vector<SceneConfigurationStatus> *statuses,
        const char *code, int hook_error, bool registry_locked,
        DeferredRuntimeReleases *releases) {
    if (statuses == nullptr) return;
    DeferredRuntimeReleases local_releases;
    if (releases == nullptr) {
        local_releases.reserve(kMaxScenes * 2U);
        releases = &local_releases;
    }
    for (SceneConfigurationStatus &status : *statuses) {
        status.state = SceneConfigurationState::HookFailed;
        status.error_code = code;
        status.hook_error = hook_error;
    }
    bool cleanup_succeeded = false;
    if (registry_locked) {
        cleanup_succeeded = retire_superseded_hooks(
                generation, statuses, true, nullptr, releases);
    } else {
        std::unique_lock<std::mutex> guard(g_lock);
        bool cleaned_current_generation = false;
        const bool residuals_cleaned =
                cleanup_authoritative_residuals_locked(
                        generation, statuses, &cleaned_current_generation,
                        releases, &guard);
        const bool superseded_cleaned = retire_superseded_hooks(
                generation, statuses, true, nullptr, releases);
        cleanup_succeeded = residuals_cleaned && superseded_cleaned;
    }
    deactivate_flight_gateway_if_current(generation, registry_locked);
    const bool terminal_published = g_tracer_configuration.finish_install(
            generation,
            cleanup_succeeded ? ConfigurationState::HookFailed
                              : ConfigurationState::RollbackFailed,
            std::move(*statuses));
    if (!terminal_published) return;
    if (registry_locked) {
        if (g_config_generation == generation) {
            g_failed_install_generation = generation;
        }
    } else {
        std::lock_guard<std::mutex> guard(g_lock);
        if (g_config_generation == generation) {
            g_failed_install_generation = generation;
        }
    }
}

enum class BatchRollbackKind {
    PhysicalHook,
    PendingUpdate,
    MetadataUpdate,
};

struct BatchInstalledScene {
    size_t status_index = 0;
    BatchRollbackKind rollback_kind = BatchRollbackKind::PhysicalHook;
    std::shared_ptr<InstalledSceneHook> hook;
    TraceConfig previous_config;
    SceneConfig previous_scene;
    ModuleRange previous_module;
    std::shared_ptr<CaptureCoordinator> previous_coordinator;
    std::shared_ptr<TraceGenerationRuntime> previous_runtime;
    uint64_t previous_config_generation = 0;
};

static void set_status_hook_ownership(
        SceneConfigurationStatus *status,
        const InstalledSceneHook &hook) {
    if (status == nullptr) return;
    status->name = hook.scene.name;
    status->offset = hook.scene.offset;
    status->runtime_address = 0;
    status->runtime_end = 0;
    status->warnings.clear();
    (void)checked_offset_address(hook.module.start, hook.scene.offset,
                                 &status->runtime_address);
    if (hook.scene.end_offset != 0) {
        (void)checked_offset_address(hook.module.start, hook.scene.end_offset,
                                     &status->runtime_end);
    }
}

// Generation slots, rather than the active scene table, are the authoritative
// owners of residual physical hooks. This keeps a retired proxy's immutable
// bypass alive while preventing that residual from being admitted as active.
static void record_residual_cleanup_failure(
        uint64_t generation, const InstalledSceneHook &hook, int hook_error,
        std::vector<SceneConfigurationStatus> *statuses) {
    if (statuses == nullptr) return;
    SceneConfigurationStatus residual_status;
    set_status_hook_ownership(&residual_status, hook);
    residual_status.state = SceneConfigurationState::RollbackFailed;
    residual_status.error_code = "HOOK_ROLLBACK_FAILED";
    residual_status.hook_error = hook_error;
    const size_t scene_index = hook.scene.index;
    if (scene_index < statuses->size() &&
        statuses->at(scene_index).state !=
                SceneConfigurationState::RollbackFailed) {
        statuses->at(scene_index) = std::move(residual_status);
    } else {
        statuses->push_back(std::move(residual_status));
    }
    QTRACE_E("generation=%llu code=HOOK_ROLLBACK_FAILED scene=%s hook_error=%d",
             static_cast<unsigned long long>(generation),
             hook.scene.name.c_str(), hook_error);
}

// Claim each residual while holding g_lock -> transition_mutex, publish only
// retired passthrough state, then call ShadowHook with both locks released.
// Failed cleanup restores the same strongly-owned generation slot; successful
// cleanup clears physical ownership but never reuses the proxy identity.
static bool cleanup_authoritative_residuals_locked(
        uint64_t generation,
        std::vector<SceneConfigurationStatus> *statuses,
        bool *cleaned_current_generation,
        DeferredRuntimeReleases *releases,
        std::unique_lock<std::mutex> *registry_lock) {
    if (registry_lock == nullptr || !registry_lock->owns_lock()) return false;
    bool cleanup_succeeded = true;
    for (size_t proxy_generation = 0;
         proxy_generation < g_next_proxy_generation; ++proxy_generation) {
        const std::shared_ptr<InstalledSceneHook> slot =
                g_hook_generations[proxy_generation];
        if (slot == nullptr) continue;

        HookHandle claimed_hook;
        bool claimed = false;
        bool failed = false;
        int hook_error = 0;
        {
            std::unique_lock<std::mutex> transition_lock(
                    slot->transition_mutex);
            const bool residual = slot->residual_cleanup_in_progress ||
                                  (slot->installed &&
                                   slot->hook.residual_hook);
            if (!residual) continue;
            if (cleaned_current_generation != nullptr &&
                slot->config_generation == generation) {
                *cleaned_current_generation = true;
            }
            if (slot->residual_cleanup_in_progress) {
                failed = true;
                hook_error = slot->hook.unhook_error != 0
                                     ? slot->hook.unhook_error
                                     : EBUSY;
            } else if (slot->active_proxy_calls != 0) {
                slot->retired = true;
                slot->rollback_residual = true;
                failed = true;
                hook_error = EBUSY;
            } else {
                claimed_hook = slot->hook;
                slot->hook.stub = nullptr;
                slot->hook.residual_hook = false;
                slot->installed = false;
                slot->retired = true;
                slot->residual_cleanup_in_progress = true;
                if (slot->scene.index < g_scene_hooks.size() &&
                    g_scene_hooks[slot->scene.index] == slot) {
                    g_scene_hooks[slot->scene.index].reset();
                }
                retire_runtime_ownership_locked(slot.get(), releases);
                claimed = true;
            }
        }

        if (claimed) {
            registry_lock->unlock();
            const bool unhooked = claimed_hook.stub == nullptr ||
                                  unhook_function(&claimed_hook);
            registry_lock->lock();
            std::lock_guard<std::mutex> transition_lock(
                    slot->transition_mutex);
            slot->hook = claimed_hook;
            slot->residual_cleanup_in_progress = false;
            slot->installed = !unhooked;
            slot->hook.residual_hook = !unhooked;
            slot->rollback_residual = !unhooked;
            failed = !unhooked;
            hook_error = claimed_hook.unhook_error;
        }
        if (failed) {
            cleanup_succeeded = false;
            record_residual_cleanup_failure(
                    generation, *slot, hook_error, statuses);
        }
    }
    return cleanup_succeeded;
}

static std::shared_ptr<InstalledSceneHook>
find_failed_scene_residual_locked(uint64_t generation,
                                  const SceneConfig &scene,
                                  const ModuleRange &module) {
    for (size_t proxy_generation = g_next_proxy_generation;
         proxy_generation-- > 0;) {
        const std::shared_ptr<InstalledSceneHook> slot =
                g_hook_generations[proxy_generation];
        if (slot == nullptr) continue;
        std::lock_guard<std::mutex> transition_lock(slot->transition_mutex);
        if (slot->config_generation == generation &&
            slot->scene.index == scene.index &&
            slot->module.start == module.start &&
            slot->module.path == module.path &&
            slot->installed && slot->hook.residual_hook) {
            return slot;
        }
    }
    return {};
}

static bool retire_superseded_hooks(
        uint64_t generation,
        std::vector<SceneConfigurationStatus> *statuses,
        bool append_residual_status,
        std::vector<size_t> *reported_residual_generations,
        DeferredRuntimeReleases *releases) {
    bool cleanup_failed = false;
    for (size_t scene_index = g_scene_hooks.size(); scene_index-- > 0;) {
        const std::shared_ptr<InstalledSceneHook> hook =
                g_scene_hooks[scene_index];
        if (hook == nullptr || hook->config_generation == generation ||
            hook->retired) {
            continue;
        }
        bool residual_already_reported = false;
        if (reported_residual_generations != nullptr) {
            for (const size_t reported_generation :
                 *reported_residual_generations) {
                if (reported_generation == hook->proxy_generation) {
                    residual_already_reported = true;
                    break;
                }
            }
        }
        if (residual_already_reported) {
            cleanup_failed = true;
            continue;
        }
        std::lock_guard<std::mutex> transition_guard(hook->transition_mutex);
        if (!hook->installed) {
            hook->pending_install = false;
            hook->pending_batch_install = false;
            hook->unhook_failed_window = false;
            hook->retired = true;
            retire_runtime_ownership_locked(hook.get(), releases);
            if (g_scene_hooks[scene_index] == hook) {
                g_scene_hooks[scene_index].reset();
            }
            continue;
        }
        if (hook->active_proxy_calls != 0 ||
            !unhook_function(&hook->hook)) {
            hook->hook.residual_hook = true;
            hook->rollback_residual = true;
            // A reachable residual proxy has a retained native gateway. Retire
            // its tracing identity so future entrants bypass QBDI without
            // keeping the superseded runtime/status workers alive.
            hook->retired = true;
            retire_runtime_ownership_locked(hook.get(), releases);
            cleanup_failed = true;
            if (reported_residual_generations != nullptr) {
                reported_residual_generations->push_back(
                        hook->proxy_generation);
            }
            if (statuses != nullptr) {
                SceneConfigurationStatus residual_status;
                set_status_hook_ownership(&residual_status, *hook);
                residual_status.state =
                        SceneConfigurationState::RollbackFailed;
                residual_status.error_code = "HOOK_ROLLBACK_FAILED";
                residual_status.hook_error = hook->hook.unhook_error;
                if (!append_residual_status &&
                    scene_index < statuses->size()) {
                    statuses->at(scene_index) = std::move(residual_status);
                } else {
                    statuses->push_back(std::move(residual_status));
                }
            }
            QTRACE_E("generation=%llu code=HOOK_ROLLBACK_FAILED scene=%s hook_error=%d",
                     static_cast<unsigned long long>(generation),
                     hook->scene.name.c_str(), hook->hook.unhook_error);
            continue;
        }
        hook->pending_install = false;
        hook->pending_batch_install = false;
        hook->installed = false;
        hook->unhook_failed_window = false;
        hook->retired = true;
        retire_runtime_ownership_locked(hook.get(), releases);
        if (g_scene_hooks[scene_index] == hook) {
            g_scene_hooks[scene_index].reset();
        }
    }
    return !cleanup_failed;
}

static void install_hooks_for_module(const ModuleRange &module,
                                     uint64_t expected_generation,
                                     bool loading) {
    if (trace_process_child_detached() || !tracer_fork_lifecycle_ready()) return;
    DeferredRuntimeReleases releases;
    releases.reserve(kMaxScenes * 2U);
    std::unique_lock<std::mutex> guard(g_lock);
    if (!g_configured || trace_process_child_detached()) return;
    if (expected_generation != 0 && expected_generation != g_config_generation) return;
    if (basename_of(module.path) != g_config.target_so) return;
    (void)loading;
    const uint64_t generation = g_config_generation;
    const std::vector<ModuleRange> process_maps = read_process_maps();
    std::vector<SceneAddressDiagnostics> diagnostics;
    diagnostics.reserve(g_config.scenes.size());
    for (const SceneConfig &scene : g_config.scenes) {
        diagnostics.push_back(diagnose_scene_address(module, process_maps, scene));
    }
    g_tracer_configuration.mark_installing(generation, module, diagnostics);
    std::vector<SceneConfigurationStatus> statuses =
            installation_statuses(g_config, diagnostics);
    bool cleaned_current_generation = false;
    if (!cleanup_authoritative_residuals_locked(
                generation, &statuses, &cleaned_current_generation,
                &releases, &guard)) {
        // The owner of a cleanup already in flight for this generation will
        // publish its terminal result. A reentrant loader must not race it or
        // replace its diagnostics with a provisional EBUSY failure.
        if (cleaned_current_generation) return;
        deactivate_flight_gateway_if_current(generation, true);
        const bool terminal_published = g_tracer_configuration.finish_install(
                generation, ConfigurationState::RollbackFailed,
                std::move(statuses));
        if (terminal_published) g_failed_install_generation = generation;
        return;
    }
    // A residual owned by this generation implies its first terminal install
    // already failed. Cleanup may make later generations safe, but must not
    // re-admit or rewrite the failed generation itself.
    if (cleaned_current_generation ||
        g_failed_install_generation == generation) {
        return;
    }
    if (g_config.flight.enabled) {
        const std::shared_ptr<CaptureCoordinator> flight_coordinator =
                g_capture_coordinator;
        if (flight_coordinator == nullptr || generation == 0 ||
            generation > UINT32_MAX) {
            constexpr const char *code = "COORDINATOR_UNAVAILABLE";
            QTRACE_E("generation=%llu code=%s flight coordinator unavailable",
                     static_cast<unsigned long long>(generation), code);
            fail_installation_statuses(generation, &statuses, code, 0, true,
                                       &releases);
            return;
        }
        if (!flight_coordinator->started() &&
            !flight_coordinator->start(
                    g_config, module,
                    static_cast<uint32_t>(generation),
                    g_generation_runtime)) {
            constexpr const char *code = "COORDINATOR_START_FAILED";
            QTRACE_E("generation=%llu code=%s cannot start flight capture artifact",
                     static_cast<unsigned long long>(generation), code);
            fail_installation_statuses(generation, &statuses, code, 0, true,
                                       &releases);
            return;
        }
        flight_coordinator->set_thread_start_resolver(
                resolve_flight_thread_start, flight_coordinator.get());
        // The persistent pthread gateway enters ShadowHook, which may acquire
        // bionic's linker lock and synchronously invoke a module callback. Do
        // not hold the registry anywhere across that external transition.
        guard.unlock();
        const bool gateway_installed =
                process_thread_create_gateway().install(flight_coordinator);
        const int gateway_hook_error = gateway_installed
                                       ? 0
                                       : process_thread_create_gateway().hook_error();
        guard.lock();
        const bool flight_still_current =
                g_configured && g_config_generation == generation &&
                g_config.flight.enabled &&
                g_capture_coordinator == flight_coordinator;
        if (!flight_still_current) {
            if (gateway_installed) {
                process_thread_create_gateway().deactivate_if(
                        flight_coordinator);
            }
            return;
        }
        if (!gateway_installed) {
            constexpr const char *code = "CALLBACK_REGISTRATION_FAILED";
            QTRACE_E("generation=%llu code=%s hook_error=%d cannot install "
                     "persistent pthread_create gateway",
                     static_cast<unsigned long long>(generation), code,
                     gateway_hook_error);
            fail_installation_statuses(generation, &statuses, code,
                                       gateway_hook_error, true, &releases);
            return;
        }
    }
    QTRACE_I("generation=%llu target module %s base=0x%lx",
             static_cast<unsigned long long>(generation),
             g_config.target_so.c_str(),
             static_cast<unsigned long>(module.start));
    std::vector<BatchInstalledScene> installed;
    installed.reserve(g_config.scenes.size());
    std::vector<size_t> reported_residual_generations;
    size_t failed_index = g_config.scenes.size();
    bool failed_scene_residual = false;
    for (size_t index = 0; index < g_config.scenes.size(); ++index) {
        const SceneConfig &scene = g_config.scenes[index];
        const std::shared_ptr<InstalledSceneHook> previous =
                scene.index < g_scene_hooks.size()
                        ? g_scene_hooks[scene.index]
                        : nullptr;
        const uint64_t previous_generation =
                previous == nullptr ? 0 : previous->config_generation;
        TraceConfig previous_config;
        SceneConfig previous_scene;
        ModuleRange previous_module;
        std::shared_ptr<CaptureCoordinator> previous_coordinator;
        std::shared_ptr<TraceGenerationRuntime> previous_runtime;
        if (previous != nullptr) {
            previous_config = previous->config;
            previous_scene = previous->scene;
            previous_module = previous->module;
            previous_coordinator = previous->coordinator;
            previous_runtime = previous->runtime;
        }

        if (!install_scene_hook_locked(g_config, scene, module, generation,
                                       g_capture_coordinator,
                                       g_generation_runtime, true, &releases,
                                       &guard)) {
            failed_index = index;
            SceneConfigurationStatus &status = statuses[index];
            status.state = SceneConfigurationState::HookFailed;
            const std::shared_ptr<InstalledSceneHook> failed =
                    scene.index < g_scene_hooks.size()
                            ? g_scene_hooks[scene.index]
                            : nullptr;
            const std::shared_ptr<InstalledSceneHook> residual =
                    find_failed_scene_residual_locked(
                            generation, scene, module);
            if (scene.offset == 0) {
                status.error_code = "ZERO_SCENE_OFFSET";
            } else if (!diagnostics[index].valid) {
                status.error_code = diagnostics[index].error.code;
            } else if (residual != nullptr) {
                set_status_hook_ownership(&status, *residual);
                status.state = SceneConfigurationState::RollbackFailed;
                status.error_code = residual->rollback_residual
                                            ? "HOOK_ROLLBACK_FAILED"
                                            : "HOOK_INSTALL_RESIDUAL";
                status.hook_error = residual->hook.unhook_error != 0
                                            ? residual->hook.unhook_error
                                            : residual->hook.hook_error;
                failed_scene_residual = true;
            } else if (failed != nullptr && failed == previous &&
                       failed->installed && failed->hook.unhook_error != 0) {
                set_status_hook_ownership(&status, *failed);
                status.state = SceneConfigurationState::RollbackFailed;
                status.error_code = "HOOK_INSTALL_RESIDUAL";
                status.hook_error = failed->hook.unhook_error;
                failed_scene_residual = true;
            } else {
                status.error_code = "HOOK_INSTALL_FAILED";
                if (failed != nullptr && failed->config_generation == generation) {
                    status.hook_error = failed->hook.hook_error;
                }
            }
            QTRACE_E("generation=%llu code=%s scene=%s hook_error=%d",
                     static_cast<unsigned long long>(generation),
                     status.error_code.c_str(), status.name.c_str(),
                     status.hook_error);
            break;
        }

        statuses[index].state = SceneConfigurationState::Installed;
        const std::shared_ptr<InstalledSceneHook> current =
                g_scene_hooks[scene.index];
        BatchInstalledScene member;
        member.status_index = index;
        member.hook = current;
        member.previous_config = std::move(previous_config);
        member.previous_scene = std::move(previous_scene);
        member.previous_module = std::move(previous_module);
        member.previous_coordinator = std::move(previous_coordinator);
        member.previous_runtime = std::move(previous_runtime);
        member.previous_config_generation = previous_generation;
        if (current == previous && current != nullptr &&
            current->pending_install &&
            current->pending_config_generation == generation) {
            member.rollback_kind = BatchRollbackKind::PendingUpdate;
        } else if (current == previous && current != nullptr &&
                   previous_generation != generation &&
                   current->config_generation == generation) {
            member.rollback_kind = BatchRollbackKind::MetadataUpdate;
        } else {
            member.rollback_kind = BatchRollbackKind::PhysicalHook;
        }
        installed.push_back(std::move(member));
        if (installed.back().rollback_kind ==
            BatchRollbackKind::PendingUpdate) {
            return;
        }
    }

    if (failed_index == g_config.scenes.size() &&
        retire_superseded_hooks(generation, &statuses, false,
                                &reported_residual_generations,
                                &releases)) {
        for (BatchInstalledScene &member : installed) {
            if (member.rollback_kind != BatchRollbackKind::MetadataUpdate) {
                continue;
            }
            releases.push_back(std::move(member.previous_runtime));
            releases.push_back(std::move(member.previous_coordinator));
        }
        record_installation_warnings(g_generation_runtime, statuses);
        const bool installed_published = g_tracer_configuration.finish_install(
                generation, ConfigurationState::Installed, std::move(statuses));
        if (installed_published && g_generation_runtime != nullptr &&
            g_generation_runtime->snapshot().generation == generation) {
            (void)g_generation_runtime->publish_installed_status();
#if defined(QTRACE_HOST_TEST)
            if (g_installed_status_gate != nullptr) {
                g_installed_status_gate();
            }
#endif
            if (!g_generation_runtime->arm()) {
                (void)g_generation_runtime->record_status_error(
                        "RUNTIME_ARM_FAILED", "$.session",
                        "generation runtime could not be armed");
            }
        }
        QTRACE_I("generation=%llu hooks installed scenes=%zu",
                 static_cast<unsigned long long>(generation),
                 g_config.scenes.size());
        return;
    }
    if (failed_index == g_config.scenes.size()) {
        failed_scene_residual = true;
    }

    if (failed_index < g_config.scenes.size()) {
        for (size_t index = failed_index + 1; index < g_config.scenes.size();
             ++index) {
            statuses[index].state = SceneConfigurationState::HookFailed;
            statuses[index].error_code = "HOOK_INSTALL_FAILED";
        }
    }

    bool rollback_failed = failed_scene_residual;
    for (auto iterator = installed.rbegin(); iterator != installed.rend(); ++iterator) {
        BatchInstalledScene &member = *iterator;
        SceneConfigurationStatus &status = statuses[member.status_index];
        if (member.hook == nullptr) {
            status.state = SceneConfigurationState::RollbackFailed;
            status.error_code = "HOOK_ROLLBACK_FAILED";
            rollback_failed = true;
            continue;
        }
        std::lock_guard<std::mutex> transition_guard(
                member.hook->transition_mutex);
        if (member.rollback_kind == BatchRollbackKind::PendingUpdate) {
            member.hook->pending_install = false;
            member.hook->pending_batch_install = false;
            if (member.hook->pending_runtime != nullptr) {
                releases.push_back(
                        std::move(member.hook->pending_runtime));
            }
            if (member.hook->pending_coordinator != nullptr) {
                releases.push_back(
                        std::move(member.hook->pending_coordinator));
            }
            status.state = SceneConfigurationState::RolledBack;
            continue;
        }
        if (member.rollback_kind == BatchRollbackKind::MetadataUpdate) {
            if (member.hook->runtime != nullptr) {
                releases.push_back(std::move(member.hook->runtime));
            }
            if (member.hook->coordinator != nullptr) {
                releases.push_back(std::move(member.hook->coordinator));
            }
            member.hook->config = std::move(member.previous_config);
            member.hook->scene = std::move(member.previous_scene);
            member.hook->module = std::move(member.previous_module);
            member.hook->coordinator = std::move(member.previous_coordinator);
            member.hook->runtime = std::move(member.previous_runtime);
            member.hook->config_generation = member.previous_config_generation;
            status.state = SceneConfigurationState::RolledBack;
            continue;
        }
        if (member.hook->active_proxy_calls != 0 ||
            (member.hook->installed &&
             !unhook_function(&member.hook->hook))) {
            member.hook->hook.residual_hook = true;
            member.hook->rollback_residual = true;
            member.hook->retired = true;
            retire_runtime_ownership_locked(member.hook.get(), &releases);
            status.state = SceneConfigurationState::RollbackFailed;
            status.error_code = "HOOK_ROLLBACK_FAILED";
            status.hook_error = member.hook->hook.unhook_error;
            reported_residual_generations.push_back(
                    member.hook->proxy_generation);
            rollback_failed = true;
            QTRACE_E("generation=%llu code=%s scene=%s hook_error=%d",
                     static_cast<unsigned long long>(generation),
                     status.error_code.c_str(), status.name.c_str(),
                     status.hook_error);
            continue;
        }
        member.hook->installed = false;
        member.hook->unhook_failed_window = false;
        member.hook->retired = true;
        retire_runtime_ownership_locked(member.hook.get(), &releases);
        if (member.hook->scene.index < g_scene_hooks.size() &&
            g_scene_hooks[member.hook->scene.index] == member.hook) {
            g_scene_hooks[member.hook->scene.index].reset();
        }
        status.state = SceneConfigurationState::RolledBack;
    }
    if (!retire_superseded_hooks(generation, &statuses, false,
                                 &reported_residual_generations,
                                 &releases)) {
        rollback_failed = true;
    }
    const ConfigurationState terminal = rollback_failed
                                        ? ConfigurationState::RollbackFailed
                                        : ConfigurationState::HookFailed;
    deactivate_flight_gateway_if_current(generation, true);
    const bool terminal_published = g_tracer_configuration.finish_install(
            generation, terminal, std::move(statuses));
    if (terminal_published) g_failed_install_generation = generation;
}

static void apply_accepted_configuration(TraceConfig config,
                                         TraceConfig active_config,
                                         uint64_t generation) noexcept {
    static_assert(std::is_nothrow_move_constructible_v<TraceConfig>);
    static_assert(std::is_nothrow_move_assignable_v<TraceConfig>);
    try {
        if (trace_process_child_detached() || !tracer_fork_lifecycle_ready()) return;
        process_thread_create_gateway().deactivate();
        std::shared_ptr<TraceGenerationRuntime> runtime =
                create_generation_runtime(config, generation);
        std::shared_ptr<CaptureCoordinator> coordinator;
        if (config.flight.enabled) {
            CaptureCoordinator *const allocated =
                    new (std::nothrow) CaptureCoordinator();
            if (allocated != nullptr) {
                try {
                    coordinator.reset(allocated);
                } catch (...) {
                    // shared_ptr construction deletes the supplied pointer on failure.
                }
            }
        }
        const bool runtime_ready = runtime != nullptr;
        const bool coordinator_ready = !config.flight.enabled || coordinator != nullptr;
        std::shared_ptr<TraceGenerationRuntime> superseded_runtime;
        std::shared_ptr<CaptureCoordinator> superseded_coordinator;
        {
            std::lock_guard<std::mutex> guard(g_lock);
            g_config = std::move(active_config);
            superseded_coordinator = std::move(g_capture_coordinator);
            g_capture_coordinator = std::move(coordinator);
            superseded_runtime = std::move(g_generation_runtime);
            g_generation_runtime = std::move(runtime);
            g_configured = true;
            g_config_generation = generation;
            g_failed_install_generation = 0;
        }
#if defined(QTRACE_HOST_TEST)
        if (g_throw_during_configuration_apply.exchange(
                    false, std::memory_order_acq_rel)) {
            throw std::bad_alloc();
        }
#endif
        QTRACE_I("generation=%llu configure tracer package=%s target=%s",
                 static_cast<unsigned long long>(generation),
                 config.package_name.c_str(), config.target_so.c_str());
        if (!runtime_ready) {
            constexpr const char *code = "RUNTIME_ALLOCATION_FAILED";
            QTRACE_E("generation=%llu code=%s cannot allocate generation runtime",
                     static_cast<unsigned long long>(generation), code);
            std::vector<SceneConfigurationStatus> statuses =
                    installation_statuses(config, {});
            fail_installation_statuses(generation, &statuses, code, 0);
            return;
        }
        if (!coordinator_ready) {
            constexpr const char *code = "COORDINATOR_ALLOCATION_FAILED";
            QTRACE_E("generation=%llu code=%s cannot allocate flight capture coordinator",
                     static_cast<unsigned long long>(generation), code);
            std::vector<SceneConfigurationStatus> statuses =
                    installation_statuses(config, {});
            fail_installation_statuses(generation, &statuses, code, 0);
            return;
        }
        if (!init_inline_hook()) {
            constexpr const char *code = "HOOK_INITIALIZATION_FAILED";
            QTRACE_E("generation=%llu code=%s cannot initialize inline hooks",
                     static_cast<unsigned long long>(generation), code);
            std::vector<SceneConfigurationStatus> statuses =
                    installation_statuses(config, {});
            fail_installation_statuses(generation, &statuses, code, 0);
            return;
        }
        if (!prepare_module_callbacks()) {
            constexpr const char *code = "MODULE_CALLBACK_REGISTRATION_FAILED";
            QTRACE_E("generation=%llu code=%s cannot register linker module lifecycle callbacks",
                     static_cast<unsigned long long>(generation), code);
            std::vector<SceneConfigurationStatus> statuses =
                    installation_statuses(config, {});
            fail_installation_statuses(generation, &statuses, code, 0);
            return;
        }
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
    } catch (...) {
        constexpr const char *code = "CONFIGURATION_APPLY_EXCEPTION";
        QTRACE_E("generation=%llu code=%s unexpected configuration activation exception",
                 static_cast<unsigned long long>(generation), code);
        process_thread_create_gateway().deactivate();
        try {
            std::vector<SceneConfigurationStatus> statuses =
                    installation_statuses(config, {});
            fail_installation_statuses(generation, &statuses, code, 0);
        } catch (...) {
            // The ABI response is already accepted; preserve no-unwind even if
            // terminal status enrichment also runs out of memory.
        }
    }
}

static int32_t write_json_result(const JsonCallResult &result, char *response,
                                 uint64_t *response_size) noexcept {
    *response_size = result.required_size;
    if (result.transport_code != QTRACE_JSON_OK) return result.transport_code;
    if (result.required_size != result.payload.size() + 1) {
        *response_size = 0;
        return QTRACE_JSON_INVALID_ARGUMENT;
    }
    std::memcpy(response, result.payload.c_str(), result.payload.size() + 1);
    return QTRACE_JSON_OK;
}

static int32_t write_internal_error_json(
        char *response, uint64_t response_capacity,
        uint64_t *response_size) noexcept {
    static constexpr char payload[] =
            R"json({"responseSchemaVersion":1,"ok":false,"error":{"code":"INTERNAL_ERROR","path":"$","message":"internal tracer configuration error"}})json";
    constexpr uint64_t required_size = sizeof(payload);
    *response_size = required_size;
    if (response_capacity < required_size) {
        return QTRACE_JSON_RESPONSE_TOO_SMALL;
    }
    std::memcpy(response, payload, sizeof(payload));
    return QTRACE_JSON_OK;
}

extern "C" __attribute__((visibility("default"))) int32_t
qbdi_tracer_configure_json(const char *request, uint64_t request_size,
                           char *response, uint64_t response_capacity,
                           uint64_t *response_size) noexcept {
    if (response_size == nullptr) return QTRACE_JSON_INVALID_ARGUMENT;
    *response_size = 0;
    if (request == nullptr || response == nullptr ||
        request_size > std::numeric_limits<size_t>::max() ||
        response_capacity > std::numeric_limits<size_t>::max()) {
        return QTRACE_JSON_INVALID_ARGUMENT;
    }
    if (trace_process_child_detached() || !tracer_fork_lifecycle_ready()) {
        return QTRACE_JSON_INVALID_ARGUMENT;
    }

    try {
        std::lock_guard<std::mutex> call_guard(g_configuration_call_lock);
        JsonCallResult result = g_tracer_configuration.configure(
                std::string_view(request, static_cast<size_t>(request_size)),
                response_capacity);
        const int32_t transport_code = write_json_result(
                result, response, response_size);
        if (transport_code != QTRACE_JSON_OK) return transport_code;
        if (result.published()) {
            apply_accepted_configuration(
                    std::move(result.published_config),
                    std::move(result.active_config),
                    result.published_generation);
        }
        return QTRACE_JSON_OK;
    } catch (...) {
        return write_internal_error_json(response, response_capacity,
                                         response_size);
    }
}

extern "C" __attribute__((visibility("default"))) int32_t
qbdi_tracer_get_status_json(uint64_t generation, char *response,
                            uint64_t response_capacity,
                            uint64_t *response_size) noexcept {
    if (response_size == nullptr) return QTRACE_JSON_INVALID_ARGUMENT;
    *response_size = 0;
    if (response == nullptr ||
        response_capacity > std::numeric_limits<size_t>::max()) {
        return QTRACE_JSON_INVALID_ARGUMENT;
    }
    if (trace_process_child_detached() || !tracer_fork_lifecycle_ready()) {
        return QTRACE_JSON_INVALID_ARGUMENT;
    }
    try {
        return write_json_result(g_tracer_configuration.status(
                                         generation, response_capacity),
                                 response, response_size);
    } catch (...) {
        return write_internal_error_json(response, response_capacity,
                                         response_size);
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
    uint64_t generation = 0;
    TraceConfig config;
    if (!g_tracer_configuration.current(&generation, &config) ||
        basename_of(module_path) != config.target_so) {
        return;
    }

    ModuleRange module;
    if (!find_loaded_module(module_path, module_base, module_size, &module)) {
        (void)finish_module_observation_failure(generation);
        return;
    }

    QTRACE_I("generation=%llu install hooks from observer module=%s "
             "base=0x%lx size=0x%lx",
             static_cast<unsigned long long>(generation), module_path,
             static_cast<unsigned long>(module.start), static_cast<unsigned long>(module.size()));
    install_hooks_for_module(module, generation, false);
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
    QTRACE_I("libqbdi_tracer loaded; waiting for structured JSON configuration");
}
