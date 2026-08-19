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
    SceneConfig scene;
    HookHandle hook;
    ModuleRange module;
    SceneConfig pending_scene;
    ModuleRange pending_module;
    size_t active_proxy_calls = 0;
    bool pending_install = false;
    bool installed = false;
};

static std::mutex g_lock;
static TraceConfig g_config = default_trace_config();
static std::vector<std::shared_ptr<InstalledSceneHook>> g_hooks;
static bool g_configured = false;

static void *proxy_for_index(size_t index);
extern "C" char trace_proxy_stubs[];

extern "C" uint64_t trace_proxy_dispatch(size_t index, const uint64_t args[8],
                                          uint64_t indirect_result) {
    std::shared_ptr<InstalledSceneHook> hook;
    TraceConfig config;
    {
        std::lock_guard<std::mutex> registry_guard(g_lock);
        if (index >= g_hooks.size() || g_hooks[index] == nullptr) {
            QTRACE_E("trace proxy for invalid scene index=%zu", index);
            return 0;
        }
        hook = g_hooks[index];
        config = g_config;
    }

    TraceInvocation invocation;
    std::memcpy(invocation.args.data(), args, sizeof(invocation.args));
    invocation.indirect_result = indirect_result;
    {
        std::lock_guard<std::mutex> transition_guard(hook->transition_mutex);
        invocation.scene = hook->scene;
        invocation.module = hook->module;
        invocation.target_address = hook->module.start + hook->scene.offset;
        if (hook->installed) {
            if (!unhook_function(&hook->hook)) {
                QTRACE_E("trace proxy could not safely unhook scene index=%zu", index);
                return 0;
            }
            hook->installed = false;
        }
        // Entrants that reached the proxy before the unhook may arrive here later. They
        // share the already-safe unhooked window and keep it open until all have returned.
        ++hook->active_proxy_calls;
    }

    const TraceRunResult traced = run_with_qbdi(config, invocation);
    const uint64_t result = traced.target_executed
                                    ? traced.value
                                    : call_target_arm64(invocation.target_address,
                                                        invocation.args.data(),
                                                        invocation.indirect_result);
    {
        std::lock_guard<std::mutex> transition_guard(hook->transition_mutex);
        --hook->active_proxy_calls;
        if (hook->active_proxy_calls == 0 && !hook->installed) {
            if (hook->pending_install) {
                hook->scene = std::move(hook->pending_scene);
                hook->module = std::move(hook->pending_module);
                hook->pending_install = false;
            }
            const uintptr_t target = hook->module.start + hook->scene.offset;
            hook->installed = hook_function_address(target,
                                                     proxy_for_index(index), &hook->hook);
        }
    }
    return result;
}

static constexpr size_t kMaxScenes = 256;
static constexpr size_t kProxyStubBytes = 8;

static void *proxy_for_index(size_t index) {
    if (index >= kMaxScenes) return nullptr;
    return trace_proxy_stubs + index * kProxyStubBytes;
}

static bool install_scene_hook_locked(const SceneConfig &scene, const ModuleRange &module) {
    if (scene.offset == 0) {
        QTRACE_W("scene %s offset is 0, skip", scene.name.c_str());
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
        slot->pending_scene = scene;
        slot->pending_module = module;
        slot->pending_install = true;
        return true;
    }
    const uintptr_t target = module.start + scene.offset;
    const uintptr_t installed_target = slot->module.start + slot->scene.offset;
    if (slot->installed && installed_target == target) return true;
    if (slot->installed) {
        if (!unhook_function(&slot->hook)) return false;
        slot->installed = false;
    }
    slot->scene = scene;
    slot->module = module;
    slot->installed = hook_function_address(target, proxy_for_index(scene.index), &slot->hook);
    return slot->installed;
}

static void install_hooks_for_module(const ModuleRange &module) {
    std::lock_guard<std::mutex> guard(g_lock);
    if (!g_configured) return;
    QTRACE_I("target module %s base=0x%lx", g_config.target_so.c_str(),
             static_cast<unsigned long>(module.start));
    for (const auto &scene: g_config.scenes) install_scene_hook_locked(scene, module);
}

static void install_hooks_when_ready(const TraceConfig &config) {
    for (int attempt = 0; attempt < 200; ++attempt) {
        ModuleRange module;
        if (find_module_executable_range(config.target_so, &module)) {
            install_hooks_for_module(module);
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
    {
        std::lock_guard<std::mutex> guard(g_lock);
        g_config = config;
        g_configured = true;
    }
    QTRACE_I("configure tracer package=%s target=%s", config.package_name.c_str(),
             config.target_so.c_str());
    if (!config.jni_backtrace_funcs.empty()) {
        set_jni_backtrace_funcs(config.jni_backtrace_funcs);
        QTRACE_I("jni backtrace enabled for %zu functions",
                 config.jni_backtrace_funcs.size());
    }
    std::thread(install_hooks_when_ready, config).detach();
}

extern "C" __attribute__((visibility("default"))) void
qbdi_tracer_install_module(const char *module_path, uintptr_t module_base, uintptr_t module_size) {
    if (module_path == nullptr || module_base == 0 || module_size == 0) return;
    std::string target_so;
    {
        std::lock_guard<std::mutex> guard(g_lock);
        target_so = g_config.target_so;
    }
    if (basename_of(module_path) != target_so) return;

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
