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
    handle->stub = shadowhook_hook_func_addr(reinterpret_cast<void *>(target), replacement, &handle->original);
    if (handle->stub == nullptr) {
        int err = shadowhook_get_errno();
        QTRACE_E("hook 0x%lx failed: %d %s", static_cast<unsigned long>(target), err, shadowhook_to_errmsg(err));
        return false;
    }
    QTRACE_I("hooked 0x%lx original=%p", static_cast<unsigned long>(target), handle->original);
    return true;
}

bool unhook_function(HookHandle *handle) {
    if (handle == nullptr || handle->stub == nullptr) return true;
    int result = shadowhook_unhook(handle->stub);
    if (result != 0) {
        int err = shadowhook_get_errno();
        QTRACE_E("unhook 0x%lx failed: %d %s", static_cast<unsigned long>(handle->target), err, shadowhook_to_errmsg(err));
        return false;
    }
    handle->stub = nullptr;
    return true;
}
