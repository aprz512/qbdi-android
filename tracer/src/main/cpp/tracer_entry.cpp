#include "core/logging.h"
#include "core/module_maps.h"
#include "core/native_fallback_arm64.h"
#include "core/qbdi_runner.h"
#include "core/trace_config.h"
#include "core/trace_process_lifecycle.h"
#include "handlers/call_handlers.h"
#include "hooks/inline_hook_adapter.h"

#include <array>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstring>
#if defined(__ANDROID__)
#include <dlfcn.h>
#endif
#include <memory>
#include <mutex>
#include <new>
#include <pthread.h>
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
    TraceConfig pending_config;
    SceneConfig pending_scene;
    ModuleRange pending_module;
    void *module_guard = nullptr;
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

#if defined(QTRACE_HOST_TEST)
using RegistrationGate = void (*)();
static RegistrationGate g_registration_gate = nullptr;
static std::atomic<RegistrationGate> g_stub_entry_gate{nullptr};
#endif

static void *proxy_for_generation(size_t generation);
static bool create_hook_generation_locked(const TraceConfig &config,
                                          const SceneConfig &scene,
                                          const ModuleRange &module,
                                          uint64_t config_generation);
static bool install_scene_hook_locked(const TraceConfig &config, const SceneConfig &scene,
                                      const ModuleRange &module,
                                      uint64_t config_generation);
extern "C" char trace_proxy_stubs[];

static bool tracer_fork_lifecycle_ready() noexcept {
    return trace_process_lifecycle_ready() &&
           g_tracer_atfork_error.load(std::memory_order_acquire) == 0;
}

static uint64_t call_retained_original_parent(size_t generation,
                                              const uint64_t args[8],
                                              uint64_t indirect_result) {
    uintptr_t fallback_target = 0;
    {
        std::lock_guard<std::mutex> registry_guard(g_lock);
        if (generation < g_next_proxy_generation &&
            g_hook_generations[generation] != nullptr) {
            InstalledSceneHook *const raw_hook =
                    g_hook_generations[generation].get();
            std::lock_guard<std::mutex> transition_guard(raw_hook->transition_mutex);
            fallback_target = reinterpret_cast<uintptr_t>(
                    raw_hook->hook.retained_original);
        }
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
        if (runtime->hook->retired) {
            execution_target = reinterpret_cast<uintptr_t>(
                    runtime->hook->hook.retained_original);
            runtime->invocation.execution_address = execution_target;
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
        traced = run_with_qbdi(runtime->hook->config, runtime->invocation);
    }
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
                    const uint64_t pending_config_generation =
                            runtime->hook->pending_config_generation;
                    runtime->hook->pending_install = false;
                    (void)create_hook_generation_locked(
                            pending_config, pending_scene, pending_module,
                            pending_config_generation);
                }
            } else if (!runtime->hook->retired && !runtime->hook->installed) {
                // Every physical hook installation gets a distinct proxy identity.
                // A thread may still be paused in this generation's old stub.
                runtime->hook->retired = true;
                (void)create_hook_generation_locked(
                        runtime->hook->config, runtime->hook->scene,
                        runtime->hook->module, runtime->hook->config_generation);
            } else if (!runtime->hook->retired) {
                runtime->hook->unhook_failed_window = false;
            }
        }
    }
    delete runtime;
    return result;
}

static void *proxy_for_generation(size_t generation) {
    if (generation >= kMaxProxyGenerations) return nullptr;
    return trace_proxy_stubs + generation * kProxyStubBytes;
}

static bool create_hook_generation_locked(const TraceConfig &config,
                                          const SceneConfig &scene,
                                          const ModuleRange &module,
                                          uint64_t config_generation) {
    if (g_next_proxy_generation >= kMaxProxyGenerations) {
        QTRACE_E("proxy generation capacity exhausted=%zu", kMaxProxyGenerations);
        return false;
    }
    uintptr_t target = 0;
    if (!module_offset_address(module, scene.offset, false, &target)) {
        QTRACE_E("scene %s offset=0x%lx outside module size=0x%lx", scene.name.c_str(),
                 static_cast<unsigned long>(scene.offset),
                 static_cast<unsigned long>(module.size()));
        return false;
    }
    const size_t generation = g_next_proxy_generation++;
    const std::shared_ptr<InstalledSceneHook> slot =
            std::make_shared<InstalledSceneHook>();
    slot->config = config;
    slot->scene = scene;
    slot->module = module;
    slot->config_generation = config_generation;
#if defined(__ANDROID__)
    slot->module_guard = ::dlopen(module.path.c_str(), RTLD_NOW | RTLD_NOLOAD);
    if (slot->module_guard == nullptr) {
        const std::string module_name = basename_of(module.path);
        slot->module_guard = ::dlopen(module_name.c_str(), RTLD_NOW | RTLD_NOLOAD);
    }
    if (slot->module_guard == nullptr) {
        QTRACE_E("cannot retain module generation path=%s", module.path.c_str());
        return false;
    }
#endif
    slot->proxy_generation = generation;
    g_hook_generations[generation] = slot;
    g_hook_generation_raw[generation] = slot.get();
    g_scene_hooks[scene.index] = slot;
    const bool hooked = hook_function_address(target, proxy_for_generation(generation),
                                              &slot->hook);
    slot->installed = hooked || slot->hook.residual_hook;
    return hooked;
}

static bool install_scene_hook_locked(const TraceConfig &config, const SceneConfig &scene,
                                      const ModuleRange &module,
                                      uint64_t config_generation) {
    if (scene.offset == 0) {
        QTRACE_W("scene %s offset is 0, skip", scene.name.c_str());
        return false;
    }
    if (scene.index >= kMaxScenes) {
        QTRACE_E("scene index=%zu exceeds proxy stub capacity=%zu", scene.index, kMaxScenes);
        return false;
    }
    uintptr_t target = 0;
    if (!module_offset_address(module, scene.offset, false, &target)) return false;
    if (scene.end_offset != 0) {
        uintptr_t range_end = 0;
        if (!module_offset_address(module, scene.end_offset, true, &range_end) ||
            range_end <= target) {
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
        if (previous->active_proxy_calls != 0) {
            previous->pending_config = config;
            previous->pending_scene = scene;
            previous->pending_module = module;
            previous->pending_config_generation = config_generation;
            previous->pending_install = true;
            return true;
        }
        if (previous->installed && !unhook_function(&previous->hook)) return false;
        previous->installed = false;
        previous->unhook_failed_window = false;
        previous->retired = true;
    }
    return create_hook_generation_locked(config, scene, module, config_generation);
}

#if defined(QTRACE_HOST_TEST)
void trace_proxy_test_reset(const TraceConfig &config) {
    std::lock_guard<std::mutex> guard(g_lock);
    g_scene_hooks.fill(nullptr);
    g_hook_generations.fill(nullptr);
    g_hook_generation_raw.fill(nullptr);
    g_next_proxy_generation = 0;
    g_config = config;
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
    return install_scene_hook_locked(config, scene, module, g_config_generation);
}

bool trace_proxy_test_repeat_current_install(const SceneConfig &scene,
                                             const ModuleRange &module) {
    if (!tracer_fork_lifecycle_ready()) return false;
    std::lock_guard<std::mutex> guard(g_lock);
    return install_scene_hook_locked(g_config, scene, module, g_config_generation);
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
}

static void install_hooks_for_module(const ModuleRange &module,
                                     uint64_t expected_generation = 0) {
    if (trace_process_child_detached() || !tracer_fork_lifecycle_ready()) return;
    std::lock_guard<std::mutex> guard(g_lock);
    if (!g_configured || trace_process_child_detached()) return;
    if (expected_generation != 0 && expected_generation != g_config_generation) return;
    if (basename_of(module.path) != g_config.target_so) return;
    QTRACE_I("target module %s base=0x%lx", g_config.target_so.c_str(),
             static_cast<unsigned long>(module.start));
    for (const auto &scene: g_config.scenes) {
        install_scene_hook_locked(g_config, scene, module, g_config_generation);
    }
}

static void install_hooks_when_ready(const TraceConfig &config, uint64_t generation) {
    for (int attempt = 0; attempt < 200; ++attempt) {
        ModuleRange module;
        if (find_loaded_module(config.target_so, 0, 0, &module)) {
            install_hooks_for_module(module, generation);
            return;
        }
        usleep(50 * 1000);
    }
    QTRACE_E("target module %s not found", config.target_so.c_str());
}

extern "C" __attribute__((visibility("default"))) void
qbdi_tracer_configure(const char *encoded_config) {
    if (trace_process_child_detached() || !tracer_fork_lifecycle_ready()) return;
    TraceConfig config = parse_trace_config(encoded_config);
    if (!config.valid) {
        QTRACE_E("invalid tracer configuration: %s", config.error.c_str());
        return;
    }
    if (!init_inline_hook()) return;
    uint64_t generation = 0;
    {
        std::lock_guard<std::mutex> guard(g_lock);
        g_config = config;
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
    std::thread(install_hooks_when_ready, config, generation).detach();
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
    install_hooks_for_module(module);
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
