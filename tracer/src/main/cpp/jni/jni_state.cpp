#include "jni/jni_state.h"

#include <cstring>

JniState &jni_state() {
    static JniState instance;
    return instance;
}

std::optional<std::string> JniState::class_name(uintptr_t jclass) const {
    std::lock_guard<std::mutex> guard(lock_);
    auto it = classes_.find(jclass);
    if (it != classes_.end()) return it->second;
    auto obj = objects_.find(jclass);
    if (obj != objects_.end()) return obj->second;
    return std::nullopt;
}

std::optional<std::string> JniState::method_sig(uintptr_t jmethodID) const {
    std::lock_guard<std::mutex> guard(lock_);
    auto it = methods_.find(jmethodID);
    if (it == methods_.end()) return std::nullopt;
    return it->second;
}

std::optional<std::string> JniState::field_sig(uintptr_t jfieldID) const {
    std::lock_guard<std::mutex> guard(lock_);
    auto it = fields_.find(jfieldID);
    if (it == fields_.end()) return std::nullopt;
    return it->second;
}

std::optional<std::string> JniState::string_value(uintptr_t jstring) const {
    std::lock_guard<std::mutex> guard(lock_);
    auto it = strings_.find(jstring);
    if (it == strings_.end()) return std::nullopt;
    return it->second;
}

std::optional<std::string> JniState::object_type(uintptr_t jobject) const {
    std::lock_guard<std::mutex> guard(lock_);
    auto it = objects_.find(jobject);
    if (it == objects_.end()) return std::nullopt;
    return it->second;
}

// ── 更新方法 ──

void JniState::on_find_class(uintptr_t jclass, const char *name) {
    std::lock_guard<std::mutex> guard(lock_);
    classes_[jclass] = name;
}

void JniState::on_define_class(uintptr_t jclass, const char *name) {
    std::lock_guard<std::mutex> guard(lock_);
    classes_[jclass] = name;
}

void JniState::on_get_object_class(uintptr_t jobject, uintptr_t jclass) {
    std::lock_guard<std::mutex> guard(lock_);
    auto it = objects_.find(jobject);
    if (it != objects_.end()) {
        classes_[jclass] = it->second;
    }
}

void JniState::on_get_method_id(uintptr_t jmethodID, const char *name, const char *sig) {
    std::lock_guard<std::mutex> guard(lock_);
    methods_[jmethodID] = std::string(name) + sig;
}

void JniState::on_get_static_method_id(uintptr_t jmethodID, const char *name, const char *sig) {
    on_get_method_id(jmethodID, name, sig);
}

void JniState::on_get_field_id(uintptr_t jfieldID, const char *name, const char *sig) {
    std::lock_guard<std::mutex> guard(lock_);
    fields_[jfieldID] = std::string(name) + ":" + sig;
}

void JniState::on_get_static_field_id(uintptr_t jfieldID, const char *name, const char *sig) {
    on_get_field_id(jfieldID, name, sig);
}

void JniState::on_new_string_utf(uintptr_t jstring, const char *value) {
    std::lock_guard<std::mutex> guard(lock_);
    strings_[jstring] = value;
}

void JniState::on_new_global_ref(uintptr_t new_ref, uintptr_t old_ref) {
    std::lock_guard<std::mutex> guard(lock_);
    auto it = objects_.find(old_ref);
    if (it != objects_.end()) objects_[new_ref] = it->second;
}

void JniState::on_new_local_ref(uintptr_t new_ref, uintptr_t old_ref) {
    on_new_global_ref(new_ref, old_ref);
}

void JniState::on_delete_global_ref(uintptr_t ref) {
    std::lock_guard<std::mutex> guard(lock_);
    objects_.erase(ref);
}

void JniState::on_delete_local_ref(uintptr_t ref) {
    on_delete_global_ref(ref);
}

void JniState::on_new_weak_global_ref(uintptr_t new_ref, uintptr_t old_ref) {
    on_new_global_ref(new_ref, old_ref);
}

void JniState::on_delete_weak_global_ref(uintptr_t ref) {
    on_delete_global_ref(ref);
}

void JniState::on_new_object(uintptr_t jobject, const char *class_name) {
    std::lock_guard<std::mutex> guard(lock_);
    objects_[jobject] = class_name;
}

void JniState::on_call_object_method(uintptr_t result, const char *return_type) {
    std::lock_guard<std::mutex> guard(lock_);
    if (result != 0 && return_type != nullptr) {
        objects_[result] = return_type;
    }
}

// ── 解析 JNI 方法签名参数 ──
// 对标 jnitrace JavaMethod 的 params 解析
// "(Ljava/lang/String;IZ)V" → {"jstring", "jint", "jboolean"}
std::vector<std::string> JniState::parse_method_params(const char *sig) {
    std::vector<std::string> params;
    if (sig == nullptr) return params;

    // 跳过方法名部分，找到 '(' 
    const char *p = strchr(sig, '(');
    if (p == nullptr) return params;
    ++p;

    while (*p && *p != ')') {
        bool is_array = false;
        while (*p == '[') { is_array = true; ++p; }

        std::string jtype;
        switch (*p) {
            case 'Z': jtype = "jboolean"; break;
            case 'B': jtype = "jbyte";    break;
            case 'C': jtype = "jchar";    break;
            case 'S': jtype = "jshort";   break;
            case 'I': jtype = "jint";     break;
            case 'J': jtype = "jlong";    break;
            case 'F': jtype = "jfloat";   break;
            case 'D': jtype = "jdouble";  break;
            case 'L': {
                const char *end = strchr(p, ';');
                if (end == nullptr) return params;
                std::string class_name(p + 1, end - p - 1);
                if (class_name == "java/lang/String")
                    jtype = "jstring";
                else if (class_name == "java/lang/Class")
                    jtype = "jclass";
                else
                    jtype = "jobject";
                p = end;
                break;
            }
            default: return params; // 解析失败
        }
        ++p;

        if (is_array) jtype += "Array";
        params.push_back(jtype);
    }
    return params;
}
