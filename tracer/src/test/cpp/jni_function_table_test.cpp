#include "jni/jni_function_table.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string_view>

namespace {

void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

size_t standard_slot(std::string_view name, std::string_view interface_name,
                     size_t first_slot) {
    size_t slot = first_slot;
    for (const auto &function: build_jni_function_table()) {
        if (interface_name != function.struct_name) continue;
        if (name == function.name) return slot;
        ++slot;
    }
    return static_cast<size_t>(-1);
}

JniFuncInfo function_named(std::string_view name) {
    for (const auto &function: build_jni_function_table()) {
        if (name == function.name) return function;
    }
    std::abort();
}

void jni_env_entries_follow_the_standard_native_interface_slots() {
    CHECK(standard_slot("GetVersion", "JNIEnv", 4) == 4);
    CHECK(standard_slot("FindClass", "JNIEnv", 4) == 6);
    CHECK(standard_slot("GetMethodID", "JNIEnv", 4) == 33);
    CHECK(standard_slot("GetFieldID", "JNIEnv", 4) == 94);
    CHECK(standard_slot("GetStaticMethodID", "JNIEnv", 4) == 113);
    CHECK(standard_slot("GetStaticFieldID", "JNIEnv", 4) == 144);
    CHECK(standard_slot("GetArrayLength", "JNIEnv", 4) == 171);
    CHECK(standard_slot("NewBooleanArray", "JNIEnv", 4) == 175);
    CHECK(standard_slot("GetBooleanArrayElements", "JNIEnv", 4) == 183);
    CHECK(standard_slot("ReleaseBooleanArrayElements", "JNIEnv", 4) == 191);
    CHECK(standard_slot("GetBooleanArrayRegion", "JNIEnv", 4) == 199);
    CHECK(standard_slot("SetBooleanArrayRegion", "JNIEnv", 4) == 207);
    CHECK(standard_slot("GetJavaVM", "JNIEnv", 4) == 219);
    CHECK(standard_slot("GetStringRegion", "JNIEnv", 4) == 220);
    CHECK(standard_slot("GetPrimitiveArrayCritical", "JNIEnv", 4) == 222);
    CHECK(standard_slot("GetStringCritical", "JNIEnv", 4) == 224);
    CHECK(standard_slot("NewWeakGlobalRef", "JNIEnv", 4) == 226);
    CHECK(standard_slot("ExceptionCheck", "JNIEnv", 4) == 228);
    CHECK(standard_slot("NewDirectByteBuffer", "JNIEnv", 4) == 229);
    CHECK(standard_slot("GetObjectRefType", "JNIEnv", 4) == 232);
}

void java_vm_entries_follow_the_standard_invoke_interface_slots() {
    CHECK(standard_slot("DestroyJavaVM", "JavaVM", 3) == 3);
    CHECK(standard_slot("AttachCurrentThread", "JavaVM", 3) == 4);
    CHECK(standard_slot("DetachCurrentThread", "JavaVM", 3) == 5);
    CHECK(standard_slot("GetEnv", "JavaVM", 3) == 6);
    CHECK(standard_slot("AttachCurrentThreadAsDaemon", "JavaVM", 3) == 7);
}

void java_vm_metadata_excludes_the_implicit_receiver() {
    CHECK(function_named("DestroyJavaVM").args.empty());
    CHECK(function_named("AttachCurrentThread").args.size() == 2);
    CHECK(std::string_view(function_named("AttachCurrentThread").args[0]) ==
          JniType::kPointer);
    CHECK(std::string_view(function_named("AttachCurrentThread").args[1]) ==
          JniType::kPointer);
    CHECK(function_named("DetachCurrentThread").args.empty());
    CHECK(function_named("GetEnv").args.size() == 2);
    CHECK(std::string_view(function_named("GetEnv").args[0]) == JniType::kPointer);
    CHECK(std::string_view(function_named("GetEnv").args[1]) == JniType::kInt);
    CHECK(function_named("AttachCurrentThreadAsDaemon").args.size() == 2);
}

} // namespace

int main() {
    jni_env_entries_follow_the_standard_native_interface_slots();
    java_vm_entries_follow_the_standard_invoke_interface_slots();
    java_vm_metadata_excludes_the_implicit_receiver();
}
