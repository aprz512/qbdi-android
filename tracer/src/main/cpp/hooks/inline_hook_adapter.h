#pragma once

#include <cstddef>
#include <cstdint>

constexpr size_t kShadowHookArm64OriginalSlotBytes = 256;

struct HookHandle {
    void *stub = nullptr;
    void *original = nullptr;
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

bool hook_function_address(uintptr_t target, void *replacement, HookHandle *handle);

bool unhook_function(HookHandle *handle);
