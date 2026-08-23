#pragma once

#include <cstddef>
#include <cstdint>

#include "third_party/android-inline-hook/shadowhook/src/main/cpp/common/sh_config.h"

struct dl_phdr_info;
using InlineHookDlInitCallback = void (*)(struct dl_phdr_info *, size_t,
                                          void *);

// Keep this in lockstep with sh_enter.c: the bundled production configuration
// uses branch islands and therefore allocates 64-byte sh_enter slots.
#if defined(SH_CONFIG_TRY_HOOK_WITHOUT_ISLAND)
constexpr size_t kShadowHookArm64OriginalSlotBytes = 256;
#else
constexpr size_t kShadowHookArm64OriginalSlotBytes = 64;
#endif

struct HookHandle {
    void *stub = nullptr;
    void *original = nullptr;
    // Optional caller-owned atomic publication slot. ShadowHook writes the
    // retained bypass here before the replacement can become reachable.
    void **published_original = nullptr;
    // ShadowHook's rewritten entry is generation-owned and intentionally retained
    // after unhook so an invocation that already branched to an old proxy can still
    // bypass that exact hook generation.
    void *retained_original = nullptr;
    void *retained_resource = nullptr;
    size_t retained_original_bytes = 0;
    uintptr_t target = 0;
    bool residual_hook = false;
};

bool init_inline_hook();
bool configure_inline_hook_dl_init_helper_path(const char *helper_path);
bool register_inline_hook_dl_init_callback(InlineHookDlInitCallback pre,
                                           InlineHookDlInitCallback post,
                                           void *opaque);

bool hook_function_address(uintptr_t target, void *replacement, HookHandle *handle);

// Exported process APIs use ShadowHook's symbol-aware address path. The
// retained original remains valid for process-lifetime gateways that never
// unhook.
bool hook_symbol_address(uintptr_t target, void *replacement, HookHandle *handle);

bool unhook_function(HookHandle *handle);
