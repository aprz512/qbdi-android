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

void jni_env_entries_follow_the_standard_native_interface_slots() {
    CHECK(standard_slot("GetVersion", "JNIEnv", 4) == 4);
    CHECK(standard_slot("FindClass", "JNIEnv", 4) == 6);
    CHECK(standard_slot("GetMethodID", "JNIEnv", 4) == 33);
    CHECK(standard_slot("GetFieldID", "JNIEnv", 4) == 94);
    CHECK(standard_slot("GetStaticMethodID", "JNIEnv", 4) == 113);
    CHECK(standard_slot("GetStaticFieldID", "JNIEnv", 4) == 144);
}

void java_vm_entries_follow_the_standard_invoke_interface_slots() {
    CHECK(standard_slot("DestroyJavaVM", "JavaVM", 3) == 3);
    CHECK(standard_slot("AttachCurrentThread", "JavaVM", 3) == 4);
    CHECK(standard_slot("DetachCurrentThread", "JavaVM", 3) == 5);
    CHECK(standard_slot("GetEnv", "JavaVM", 3) == 6);
    CHECK(standard_slot("AttachCurrentThreadAsDaemon", "JavaVM", 3) == 7);
}

} // namespace

int main() {
    jni_env_entries_follow_the_standard_native_interface_slots();
    java_vm_entries_follow_the_standard_invoke_interface_slots();
}
