#include "core/logging.h"
#include "core/module_maps.h"
#include "core/qbdi_runner.h"
#include "core/trace_config.h"
#include "handlers/call_handlers.h"
#include "hooks/inline_hook_adapter.h"

#include <array>
#include <cstring>
#include <mutex>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

struct InstalledSceneHook {
    SceneConfig scene;
    HookHandle hook;
    ModuleRange module;
    bool installed = false;
};

static std::mutex g_lock;
static TraceConfig g_config = default_trace_config();
static std::vector<InstalledSceneHook> g_hooks;
static bool g_configured = false;

static void *proxy_for_index(size_t index);

static inline __attribute__((always_inline)) uint64_t capture_x8() {
    uint64_t value;
    __asm__ volatile("mov %0, x8" : "=r"(value));
    return value;
}

static uint64_t trace_proxy_for(size_t index, uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3,
                                uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7,
                                uint64_t indirect_result) {
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
    invocation.indirect_result = indirect_result;

    unhook_function(&hook.hook);
    hook.installed = false;
    uint64_t result = run_with_qbdi(g_config, invocation);
    hook.installed = hook_function_address(invocation.target_address, proxy_for_index(index),
                                           &hook.hook);
    return result;
}

template <size_t I>
static uint64_t trace_proxy(uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3,
                            uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7) {
    uint64_t x8_val = capture_x8();
    return trace_proxy_for(I, x0, x1, x2, x3, x4, x5, x6, x7, x8_val);
}

template <size_t... Is>
static auto make_proxy_table(std::index_sequence<Is...>) {
    return std::array<void *, sizeof...(Is)>{reinterpret_cast<void *>(trace_proxy<Is>)...};
}

static constexpr size_t kMaxScenes = 256;

static void *proxy_for_index(size_t index) {
    static auto table = make_proxy_table(std::make_index_sequence<kMaxScenes>{});
    if (index >= table.size()) return nullptr;
    return table[index];
}

static bool install_scene_hook_locked(const SceneConfig &scene, const ModuleRange &module) {
    if (scene.offset == 0) {
        QTRACE_W("scene %s offset is 0, skip", scene.name.c_str());
        return false;
    }
    if (scene.index >= g_hooks.size()) {
        g_hooks.resize(scene.index + 1);
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
    if (basename_of(module_path) != g_config.target_so) return;

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
