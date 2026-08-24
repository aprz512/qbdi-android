#pragma once

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

// ── JNI 调用状态追踪 ────────────────────────────────────────
// 对标 jnitrace-engine 的 DataTransport.updateState()
// 在 onLeave 时更新，在后续调用时 enrich 输出
//
// 追踪内容:
//   jclass    ← FindClass / DefineClass / GetObjectClass
//   jmethodID ← GetMethodID / GetStaticMethodID
//   jfieldID  ← GetFieldID / GetStaticFieldID
//   jstring   ← NewStringUTF / NewString
//   jobject   ← 各种引用创建/传递

class JniState {
public:
    // ── 查询（format 时用） ──
    std::optional<std::string> class_name(uintptr_t jclass) const;
    std::optional<std::string> method_sig(uintptr_t jmethodID) const;
    std::optional<std::string> field_sig(uintptr_t jfieldID) const;
    std::optional<std::string> string_value(uintptr_t jstring) const;
    std::optional<std::string> object_type(uintptr_t jobject) const;

    // ── 更新（onLeave 时调） ──
    void on_find_class(uintptr_t jclass, const char *name);
    void on_define_class(uintptr_t jclass, const char *name);
    void on_get_object_class(uintptr_t jobject, uintptr_t jclass);
    void on_get_method_id(uintptr_t jmethodID, const char *name, const char *sig);
    void on_get_static_method_id(uintptr_t jmethodID, const char *name, const char *sig);
    void on_get_field_id(uintptr_t jfieldID, const char *name, const char *sig);
    void on_get_static_field_id(uintptr_t jfieldID, const char *name, const char *sig);
    void on_new_string_utf(uintptr_t jstring, const char *value);
    void on_new_string(uintptr_t jstring, const char *value);
    void on_new_global_ref(uintptr_t new_ref, uintptr_t old_ref);
    void on_new_local_ref(uintptr_t new_ref, uintptr_t old_ref);
    void on_delete_global_ref(uintptr_t ref);
    void on_delete_local_ref(uintptr_t ref);
    void on_new_weak_global_ref(uintptr_t new_ref, uintptr_t old_ref);
    void on_delete_weak_global_ref(uintptr_t ref);
    void on_new_object(uintptr_t jobject, const char *class_name);
    void on_call_object_method(uintptr_t result, const char *return_type);

    // ── 辅助: 解析 JNI 方法签名，提取参数表中的 Java 类型 ──
    // 输入 "(Ljava/lang/String;I)Z" → 返回 {"jstring", "jint"}
    static std::vector<std::string> parse_method_params(const char *sig);

private:
    mutable std::mutex lock_;

    // jclass (地址) → 类名
    std::unordered_map<uintptr_t, std::string> classes_;
    // jmethodID → "name(sig)"
    std::unordered_map<uintptr_t, std::string> methods_;
    // jfieldID → "name:type"
    std::unordered_map<uintptr_t, std::string> fields_;
    // jstring → UTF-8 内容
    std::unordered_map<uintptr_t, std::string> strings_;
    // jobject → 类型名
    std::unordered_map<uintptr_t, std::string> objects_;
};

// 全局单例
JniState &jni_state();
