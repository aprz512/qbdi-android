#include "core/logging.h"
#include "core/module_maps.h"
#include "core/native_fallback_arm64.h"
#include "core/qbdi_runner.h"
#include "core/trace_config.h"
#include "handlers/call_handlers.h"
#include "hooks/inline_hook_adapter.h"

#include <cstring>
#include <memory>
#include <mutex>
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
    size_t active_proxy_calls = 0;
    bool pending_install = false;
    bool unhook_failed_window = false;
    bool installed = false;
};

static std::mutex g_lock;
static TraceConfig g_config = default_trace_config();
static std::vector<std::shared_ptr<InstalledSceneHook>> g_hooks;
static bool g_configured = false;
static uint64_t g_config_generation = 0;

static constexpr size_t kMaxScenes = 256;
static constexpr size_t kProxyStubBytes = 8;

#if defined(QTRACE_HOST_TEST)
using RegistrationGate = void (*)();
static RegistrationGate g_registration_gate = nullptr;
#endif

static void *proxy_for_index(size_t index);
extern "C" char trace_proxy_stubs[];

extern "C" uint64_t trace_proxy_dispatch(size_t index, const uint64_t args[8],
                                          uint64_t indirect_result) {
    std::shared_ptr<InstalledSceneHook> hook;
    TraceInvocation invocation;
    TraceConfig config;
    uintptr_t execution_target = 0;
    bool use_original_bypass = false;
    {
        std::lock_guard<std::mutex> registry_guard(g_lock);
        if (index >= g_hooks.size() || g_hooks[index] == nullptr) {
            QTRACE_E("trace proxy for invalid scene index=%zu", index);
            return 0;
        }
        hook = g_hooks[index];
#if defined(QTRACE_HOST_TEST)
        if (g_registration_gate != nullptr) g_registration_gate();
#endif
        std::lock_guard<std::mutex> transition_guard(hook->transition_mutex);
        config = hook->config;
        invocation.scene = hook->scene;
        invocation.module = hook->module;
        invocation.target_address = hook->module.start + hook->scene.offset;
        std::memcpy(invocation.args.data(), args, sizeof(invocation.args));
        invocation.indirect_result = indirect_result;
        execution_target = invocation.target_address;
        if (hook->installed) {
            if (hook->unhook_failed_window) {
                execution_target = reinterpret_cast<uintptr_t>(hook->hook.original);
                use_original_bypass = true;
            } else if (!unhook_function(&hook->hook)) {
                if (hook->hook.original == nullptr) {
                    QTRACE_E("residual hook has no safe original bypass index=%zu", index);
                    return 0;
                }
                execution_target = reinterpret_cast<uintptr_t>(hook->hook.original);
                use_original_bypass = true;
                hook->unhook_failed_window = true;
                QTRACE_E("trace proxy using original bypass after unhook failure index=%zu",
                         index);
            } else {
                hook->installed = false;
            }
        }
        // This transaction matches the installer's g_lock -> transition_mutex order.
        ++hook->active_proxy_calls;
    }

    TraceRunResult traced{};
    if (!use_original_bypass) traced = run_with_qbdi(config, invocation);
    const uint64_t result = traced.target_executed
                                    ? traced.value
                                    : call_target_arm64(execution_target, invocation.args.data(),
                                                        invocation.indirect_result);
    {
        std::lock_guard<std::mutex> transition_guard(hook->transition_mutex);
        --hook->active_proxy_calls;
        if (hook->active_proxy_calls == 0) {
            if (hook->pending_install) {
                if (hook->installed && !unhook_function(&hook->hook)) {
                    hook->unhook_failed_window = false;
                    return result;
                }
                hook->installed = false;
                hook->unhook_failed_window = false;
                hook->config = std::move(hook->pending_config);
                hook->scene = std::move(hook->pending_scene);
                hook->module = std::move(hook->pending_module);
                hook->pending_install = false;
            }
            if (!hook->installed) {
                const uintptr_t target = hook->module.start + hook->scene.offset;
                const bool hooked = hook_function_address(target, proxy_for_index(index),
                                                          &hook->hook);
                hook->installed = hooked || hook->hook.residual_hook;
            } else {
                hook->unhook_failed_window = false;
            }
        }
    }
    return result;
}

static void *proxy_for_index(size_t index) {
    if (index >= kMaxScenes) return nullptr;
    return trace_proxy_stubs + index * kProxyStubBytes;
}

static bool install_scene_hook_locked(const TraceConfig &config, const SceneConfig &scene,
                                      const ModuleRange &module) {
    if (scene.offset == 0) {
        QTRACE_W("scene %s offset is 0, skip", scene.name.c_str());
        return false;
    }
    if (scene.index >= kMaxScenes) {
        QTRACE_E("scene index=%zu exceeds proxy stub capacity=%zu", scene.index, kMaxScenes);
        return false;
    }
    if (scene.index >= g_hooks.size()) {
        g_hooks.resize(scene.index + 1);
    }
    if (g_hooks[scene.index] == nullptr) {
        g_hooks[scene.index] = std::make_shared<InstalledSceneHook>();
    }
    const std::shared_ptr<InstalledSceneHook> &slot = g_hooks[scene.index];
    std::lock_guard<std::mutex> transition_guard(slot->transition_mutex);
    if (slot->active_proxy_calls != 0) {
        slot->pending_config = config;
        slot->pending_scene = scene;
        slot->pending_module = module;
        slot->pending_install = true;
        return true;
    }
    if (slot->installed) {
        if (!unhook_function(&slot->hook)) return false;
        slot->installed = false;
    }
    slot->config = config;
    slot->scene = scene;
    slot->module = module;
    slot->pending_install = false;
    const uintptr_t target = module.start + scene.offset;
    const bool hooked = hook_function_address(target, proxy_for_index(scene.index), &slot->hook);
    slot->installed = hooked || slot->hook.residual_hook;
    return hooked;
}

#if defined(QTRACE_HOST_TEST)
void trace_proxy_test_reset(const TraceConfig &config) {
    std::lock_guard<std::mutex> guard(g_lock);
    g_hooks.clear();
    g_config = config;
    ++g_config_generation;
    g_configured = true;
    g_registration_gate = nullptr;
}

bool trace_proxy_test_update(const TraceConfig &config, const SceneConfig &scene,
                             const ModuleRange &module) {
    std::lock_guard<std::mutex> guard(g_lock);
    g_config = config;
    ++g_config_generation;
    return install_scene_hook_locked(config, scene, module);
}

void trace_proxy_test_set_registration_gate(RegistrationGate gate) {
    std::lock_guard<std::mutex> guard(g_lock);
    g_registration_gate = gate;
}
#endif

static void install_hooks_for_module(const ModuleRange &module,
                                     uint64_t expected_generation = 0) {
    std::lock_guard<std::mutex> guard(g_lock);
    if (!g_configured) return;
    if (expected_generation != 0 && expected_generation != g_config_generation) return;
    if (basename_of(module.path) != g_config.target_so) return;
    QTRACE_I("target module %s base=0x%lx", g_config.target_so.c_str(),
             static_cast<unsigned long>(module.start));
    for (const auto &scene: g_config.scenes) {
        install_scene_hook_locked(g_config, scene, module);
    }
}

static void install_hooks_when_ready(const TraceConfig &config, uint64_t generation) {
    for (int attempt = 0; attempt < 200; ++attempt) {
        ModuleRange module;
        if (find_module_executable_range(config.target_so, &module)) {
            install_hooks_for_module(module, generation);
            return;
        }
        usleep(50 * 1000);
    }
    QTRACE_E("target module %s not found", config.target_so.c_str());
}

extern "C" __attribute__((visibility("default"))) void
qbdi_tracer_configure(const char *encoded_config) {
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
    if (module_path == nullptr || module_base == 0 || module_size == 0) return;

    ModuleRange module;
    module.start = module_base;
    module.end = module_base + module_size;
    module.permissions = "r-xp";
    module.path = module_path;

    QTRACE_I("install hooks from observer module=%s base=0x%lx size=0x%lx", module_path,
             static_cast<unsigned long>(module.start), static_cast<unsigned long>(module.size()));
    install_hooks_for_module(module);
}

__attribute__((constructor)) static void qbdi_tracer_init() {
    QTRACE_I("libqbdi_tracer loaded; waiting for qbdi_tracer_configure");
}
