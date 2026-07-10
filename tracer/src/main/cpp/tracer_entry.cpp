#include "core/logging.h"
#include "core/module_maps.h"
#include "core/qbdi_runner.h"
#include "core/trace_config.h"
#include "hooks/inline_hook_adapter.h"

#include <array>
#include <cstring>
#include <link.h>
#include <mutex>
#include <thread>
#include <unistd.h>

#include <shadowhook.h>

struct InstalledSceneHook {
    SceneConfig scene;
    HookHandle hook;
    ModuleRange module;
    bool installed = false;
};

static std::mutex g_lock;
static TraceConfig g_config = default_trace_config();
static std::array<InstalledSceneHook, 5> g_hooks;
static bool g_configured = false;

static uint64_t trace_proxy_init(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
static uint64_t trace_proxy_jni(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
static uint64_t trace_proxy_libc(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
static uint64_t trace_proxy_algorithm(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
static uint64_t trace_proxy_integrity(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

static void *proxy_for_index(size_t index) {
    switch (index) {
        case 0: return reinterpret_cast<void *>(trace_proxy_init);
        case 1: return reinterpret_cast<void *>(trace_proxy_jni);
        case 2: return reinterpret_cast<void *>(trace_proxy_libc);
        case 3: return reinterpret_cast<void *>(trace_proxy_algorithm);
        case 4: return reinterpret_cast<void *>(trace_proxy_integrity);
        default: return nullptr;
    }
}

static uint64_t trace_proxy_for(size_t index, uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3,
                                uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7) {
    if (index >= g_hooks.size() || !g_hooks[index].installed) {
        QTRACE_E("trace proxy for invalid scene index=%zu", index);
        return 0;
    }

    InstalledSceneHook &hook = g_hooks[index];
    TraceInvocation invocation;
    invocation.scene = hook.scene;
    invocation.module = hook.module;
    invocation.target_address = hook.module.start + hook.scene.offset;
    invocation.args = {x0, x1, x2, x3, x4, x5, x6, x7};

    unhook_function(&hook.hook);
    hook.installed = false;
    uint64_t result = run_with_qbdi(g_config, invocation);
    hook.installed = hook_function_address(invocation.target_address, proxy_for_index(index), &hook.hook);
    return result;
}

static uint64_t trace_proxy_init(uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3,
                                 uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7) {
    return trace_proxy_for(0, x0, x1, x2, x3, x4, x5, x6, x7);
}

static uint64_t trace_proxy_jni(uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3,
                                uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7) {
    return trace_proxy_for(1, x0, x1, x2, x3, x4, x5, x6, x7);
}

static uint64_t trace_proxy_libc(uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3,
                                 uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7) {
    return trace_proxy_for(2, x0, x1, x2, x3, x4, x5, x6, x7);
}

static uint64_t trace_proxy_algorithm(uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3,
                                      uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7) {
    return trace_proxy_for(3, x0, x1, x2, x3, x4, x5, x6, x7);
}

static uint64_t trace_proxy_integrity(uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3,
                                      uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7) {
    return trace_proxy_for(4, x0, x1, x2, x3, x4, x5, x6, x7);
}

static bool install_scene_hook_locked(const SceneConfig &scene, const ModuleRange &module) {
    if (scene.index >= g_hooks.size()) return false;
    if (scene.offset == 0) {
        QTRACE_W("scene %s offset is 0, skip", scene.name.c_str());
        return false;
    }
    InstalledSceneHook &slot = g_hooks[scene.index];
    if (slot.installed) return true;
    slot.scene = scene;
    slot.module = module;
    uintptr_t target = module.start + scene.offset;
    slot.installed = hook_function_address(target, proxy_for_index(scene.index), &slot.hook);
    return slot.installed;
}

static void install_hooks_for_module(const ModuleRange &module) {
    std::lock_guard<std::mutex> guard(g_lock);
    if (!g_configured) return;
    QTRACE_I("target module %s base=0x%lx", g_config.target_so.c_str(), static_cast<unsigned long>(module.start));
    for (const auto &scene : g_config.scenes) install_scene_hook_locked(scene, module);
}

static void install_hooks_when_ready(const TraceConfig& config) {
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

static void on_dl_init_pre(dl_phdr_info *info, size_t, void *) {
    if (info == nullptr || info->dlpi_name == nullptr) return;
    std::lock_guard<std::mutex> guard(g_lock);
    if (!g_configured || basename_of(info->dlpi_name) != g_config.target_so) return;

    ModuleRange module;
    if (find_module_executable_range(g_config.target_so, &module)) {
        QTRACE_I("installing hooks before init_array for %s", info->dlpi_name);
        for (const auto &scene : g_config.scenes) install_scene_hook_locked(scene, module);
    }
}

extern "C" __attribute__((visibility("default"))) void qbdi_tracer_configure(const char *encoded_config) {
    if (!init_inline_hook()) return;
    TraceConfig config = parse_trace_config(encoded_config);
    {
        std::lock_guard<std::mutex> guard(g_lock);
        g_config = config;
        g_configured = true;
    }
    shadowhook_register_dl_init_callback(on_dl_init_pre, nullptr, nullptr);
    QTRACE_I("configure tracer package=%s target=%s", config.package_name.c_str(), config.target_so.c_str());
    std::thread(install_hooks_when_ready, config).detach();
}

__attribute__((constructor)) static void qbdi_tracer_init() {
    QTRACE_I("libqbdi_tracer loaded; waiting for qbdi_tracer_configure");
}
