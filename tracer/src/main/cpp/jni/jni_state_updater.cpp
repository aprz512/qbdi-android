#include "jni/jni_state_updater.h"

#include "core/safe_memory.h"

#include <cstring>

namespace {

std::optional<std::string> copy_argument(const uint64_t *arguments, size_t index,
                                         size_t maximum_length = 256) {
    if (arguments == nullptr) return std::nullopt;
    return copy_c_string(arguments[index], maximum_length);
}

} // namespace

void update_jni_state(JniState &state, const JniFuncInfo &function,
                      const uint64_t *arguments, uint64_t result) {
    if (arguments == nullptr) return;
    const char *name = function.name;

    if (std::strcmp(name, "FindClass") == 0) {
        const auto class_name = copy_argument(arguments, 0);
        if (class_name) state.on_find_class(result, class_name->c_str());
    } else if (std::strcmp(name, "DefineClass") == 0) {
        const auto class_name = copy_argument(arguments, 0);
        if (class_name) state.on_define_class(result, class_name->c_str());
    } else if (std::strcmp(name, "GetObjectClass") == 0) {
        state.on_get_object_class(arguments[0], result);
    } else if (std::strcmp(name, "GetMethodID") == 0 ||
               std::strcmp(name, "GetStaticMethodID") == 0) {
        const auto method_name = copy_argument(arguments, 1);
        const auto signature = copy_argument(arguments, 2);
        if (!method_name || !signature) return;
        if (std::strcmp(name, "GetMethodID") == 0) {
            state.on_get_method_id(result, method_name->c_str(), signature->c_str());
        } else {
            state.on_get_static_method_id(result, method_name->c_str(),
                                          signature->c_str());
        }
    } else if (std::strcmp(name, "GetFieldID") == 0 ||
               std::strcmp(name, "GetStaticFieldID") == 0) {
        const auto field_name = copy_argument(arguments, 1);
        const auto signature = copy_argument(arguments, 2);
        if (!field_name || !signature) return;
        if (std::strcmp(name, "GetFieldID") == 0) {
            state.on_get_field_id(result, field_name->c_str(), signature->c_str());
        } else {
            state.on_get_static_field_id(result, field_name->c_str(),
                                         signature->c_str());
        }
    } else if (std::strcmp(name, "NewStringUTF") == 0) {
        const auto value = copy_argument(arguments, 0, 1024);
        if (value) state.on_new_string_utf(result, value->c_str());
    } else if (std::strcmp(name, "NewGlobalRef") == 0) {
        state.on_new_global_ref(result, arguments[0]);
    } else if (std::strcmp(name, "NewLocalRef") == 0) {
        state.on_new_local_ref(result, arguments[0]);
    } else if (std::strcmp(name, "DeleteGlobalRef") == 0) {
        state.on_delete_global_ref(arguments[0]);
    } else if (std::strcmp(name, "DeleteLocalRef") == 0) {
        state.on_delete_local_ref(arguments[0]);
    } else if (std::strcmp(name, "NewWeakGlobalRef") == 0) {
        state.on_new_weak_global_ref(result, arguments[0]);
    } else if (std::strcmp(name, "DeleteWeakGlobalRef") == 0) {
        state.on_delete_weak_global_ref(arguments[0]);
    }
}
