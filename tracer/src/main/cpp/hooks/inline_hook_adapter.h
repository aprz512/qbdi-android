#pragma once

#include <cstdint>

struct HookHandle {
    void *stub = nullptr;
    void *original = nullptr;
    uintptr_t target = 0;
};

bool init_inline_hook();
bool hook_function_address(uintptr_t target, void *replacement, HookHandle *handle);
bool unhook_function(HookHandle *handle);
