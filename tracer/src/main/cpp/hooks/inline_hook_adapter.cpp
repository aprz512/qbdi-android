#include "hooks/inline_hook_adapter.h"
#include "core/logging.h"

#include <shadowhook.h>

namespace {

using ShadowHookAddressFunction = void *(*)(void *, void *, void **);

bool hook_address(uintptr_t target, void *replacement, HookHandle *handle,
                  ShadowHookAddressFunction hooker) {
    if (handle != nullptr) {
        handle->hook_error = 0;
        handle->unhook_error = 0;
    }
    if (target == 0 || replacement == nullptr || handle == nullptr ||
        hooker == nullptr) {
        return false;
    }
    handle->target = target;
    handle->stub = nullptr;
    handle->original = nullptr;
    handle->retained_original = nullptr;
    handle->retained_resource = nullptr;
    handle->retained_original_bytes = 0;
    handle->residual_hook = false;
    void **const original_output = handle->published_original != nullptr
                                           ? handle->published_original
                                           : &handle->original;
    handle->stub = hooker(reinterpret_cast<void *>(target), replacement,
                          original_output);
    handle->original = __atomic_load_n(original_output, __ATOMIC_ACQUIRE);
    if (handle->stub == nullptr) {
        const int err = shadowhook_get_errno();
        handle->hook_error = err;
        return false;
    }
    if (handle->original == nullptr) {
        if (shadowhook_unhook(handle->stub) == 0) {
            handle->stub = nullptr;
            handle->target = 0;
        } else {
            handle->unhook_error = shadowhook_get_errno();
            handle->residual_hook = true;
        }
        return false;
    }
    handle->retained_original = handle->original;
    handle->retained_original_bytes = kShadowHookArm64OriginalSlotBytes;
    return true;
}

} // namespace

bool init_inline_hook() {
    int result = shadowhook_init(SHADOWHOOK_MODE_UNIQUE, true);
    return result == 0;
}

bool configure_inline_hook_dl_init_helper_path(const char *helper_path) {
    const int result = shadowhook_set_dl_init_helper_path(helper_path);
    if (result != 0) {
        QTRACE_E("cannot configure ShadowHook dl-init helper path: %d", result);
        return false;
    }
    return true;
}

bool register_inline_hook_dl_init_callback(InlineHookDlInitCallback callback,
                                           void *opaque) {
    const int result = shadowhook_register_dl_init_callback(
            callback, nullptr, opaque);
    return result == 0;
}

bool register_inline_hook_dl_fini_callback(InlineHookDlInitCallback callback,
                                           void *opaque) {
    const int result = shadowhook_register_dl_fini_callback(
            nullptr, callback, opaque);
    return result == 0;
}

bool hook_function_address(uintptr_t target, void *replacement, HookHandle *handle) {
    return hook_address(target, replacement, handle, shadowhook_hook_func_addr);
}

bool hook_symbol_address(uintptr_t target, void *replacement, HookHandle *handle) {
    return hook_address(target, replacement, handle, shadowhook_hook_sym_addr);
}

bool unhook_function(HookHandle *handle) {
    if (handle != nullptr) handle->unhook_error = 0;
    if (handle == nullptr || handle->stub == nullptr) return true;
    void *retained = nullptr;
    int result = shadowhook_unhook_qtrace_retain(handle->stub, &retained);
    if (result != 0) {
        const int err = shadowhook_get_errno();
        handle->unhook_error = err;
        return false;
    }
    handle->stub = nullptr;
    handle->retained_resource = retained;
    handle->residual_hook = false;
    return true;
}
