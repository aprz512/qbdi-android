#include "hooks/inline_hook_adapter.h"
#include "core/logging.h"

#include <shadowhook.h>

bool init_inline_hook() {
    int result = shadowhook_init(SHADOWHOOK_MODE_UNIQUE, true);
    if (result != 0) {
        QTRACE_E("shadowhook_init failed: %d", result);
        return false;
    }
    return true;
}

bool hook_function_address(uintptr_t target, void *replacement, HookHandle *handle) {
    if (target == 0 || replacement == nullptr || handle == nullptr) return false;
    handle->target = target;
    handle->stub = nullptr;
    handle->original = nullptr;
    handle->retained_original = nullptr;
    handle->retained_resource = nullptr;
    handle->residual_hook = false;
    handle->stub = shadowhook_hook_func_addr(reinterpret_cast<void *>(target), replacement,
                                             &handle->original);
    if (handle->stub == nullptr) {
        int err = shadowhook_get_errno();
        QTRACE_E("hook 0x%lx failed: %d %s", static_cast<unsigned long>(target), err,
                 shadowhook_to_errmsg(err));
        return false;
    }
    if (handle->original == nullptr) {
        QTRACE_E("hook 0x%lx returned no original bypass",
                 static_cast<unsigned long>(target));
        if (shadowhook_unhook(handle->stub) == 0) {
            handle->stub = nullptr;
            handle->target = 0;
        } else {
            handle->residual_hook = true;
            QTRACE_E("cleanup unhook 0x%lx failed; preserving residual hook ownership",
                     static_cast<unsigned long>(target));
        }
        return false;
    }
    handle->retained_original = handle->original;
    QTRACE_I("hooked 0x%lx original=%p", static_cast<unsigned long>(target), handle->original);
    return true;
}

bool unhook_function(HookHandle *handle) {
    if (handle == nullptr || handle->stub == nullptr) return true;
    void *retained = nullptr;
    int result = shadowhook_unhook_qtrace_retain(handle->stub, &retained);
    if (result != 0) {
        int err = shadowhook_get_errno();
        QTRACE_E("unhook 0x%lx failed: %d %s", static_cast<unsigned long>(handle->target), err,
                 shadowhook_to_errmsg(err));
        return false;
    }
    handle->stub = nullptr;
    handle->retained_resource = retained;
    handle->residual_hook = false;
    return true;
}
