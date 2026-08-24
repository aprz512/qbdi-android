#include "jni/jni_state_updater.h"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <optional>
#include <string>

namespace {

void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

JniFuncInfo function_named(const char *name) {
    return {name, JniType::kPointer, "JNIEnv", {}};
}

void valid_c_strings_update_the_expected_handles() {
    JniState state;
    const char class_name[] = "java/lang/String";
    const uint64_t find_args[] = {reinterpret_cast<uintptr_t>(class_name)};
    update_jni_state(state, function_named("FindClass"), find_args, 0x2001);
    CHECK(state.class_name(0x2001) ==
          std::optional<std::string>("java/lang/String"));

    const char method_name[] = "length";
    const char method_sig[] = "()I";
    const uint64_t method_args[] = {
            0x2001,
            reinterpret_cast<uintptr_t>(method_name),
            reinterpret_cast<uintptr_t>(method_sig),
    };
    update_jni_state(state, function_named("GetMethodID"), method_args, 0x2002);
    CHECK(state.method_sig(0x2002) == std::optional<std::string>("length()I"));

    const char text[] = "captured";
    const uint64_t string_args[] = {reinterpret_cast<uintptr_t>(text)};
    update_jni_state(state, function_named("NewStringUTF"), string_args, 0x2003);
    CHECK(state.string_value(0x2003) == std::optional<std::string>("captured"));
}

void failed_c_string_reads_do_not_pollute_state() {
    JniState state;
    const uint64_t unreadable_find_args[] = {1};
    update_jni_state(state, function_named("FindClass"), unreadable_find_args, 0x3001);
    CHECK(!state.class_name(0x3001));

    const char control_name[] = {'b', '\x01', '\0'};
    const char valid_sig[] = "()V";
    const uint64_t method_args[] = {
            0x3001,
            reinterpret_cast<uintptr_t>(control_name),
            reinterpret_cast<uintptr_t>(valid_sig),
    };
    update_jni_state(state, function_named("GetMethodID"), method_args, 0x3002);
    CHECK(!state.method_sig(0x3002));

    std::array<char, 1024> unterminated{};
    unterminated.fill('x');
    const uint64_t string_args[] = {
            reinterpret_cast<uintptr_t>(unterminated.data()),
    };
    update_jni_state(state, function_named("NewStringUTF"), string_args, 0x3003);
    CHECK(!state.string_value(0x3003));
}

void failed_handle_returns_do_not_populate_zero_key() {
    const char class_name[] = "java/lang/String";
    const uint64_t class_args[] = {reinterpret_cast<uintptr_t>(class_name)};
    for (const char *function_name : {"FindClass", "DefineClass"}) {
        JniState state;
        update_jni_state(state, function_named(function_name), class_args, 0);
        CHECK(!state.class_name(0));
    }

    {
        JniState state;
        constexpr uintptr_t object = 0x4001;
        state.on_new_object(object, "java/lang/String");
        const uint64_t arguments[] = {object};
        update_jni_state(state, function_named("GetObjectClass"), arguments, 0);
        CHECK(!state.class_name(0));
    }

    const char member_name[] = "value";
    const char method_signature[] = "()I";
    const uint64_t method_args[] = {
            0x4002,
            reinterpret_cast<uintptr_t>(member_name),
            reinterpret_cast<uintptr_t>(method_signature),
    };
    for (const char *function_name : {"GetMethodID", "GetStaticMethodID"}) {
        JniState state;
        update_jni_state(state, function_named(function_name), method_args, 0);
        CHECK(!state.method_sig(0));
    }

    const char field_signature[] = "I";
    const uint64_t field_args[] = {
            0x4003,
            reinterpret_cast<uintptr_t>(member_name),
            reinterpret_cast<uintptr_t>(field_signature),
    };
    for (const char *function_name : {"GetFieldID", "GetStaticFieldID"}) {
        JniState state;
        update_jni_state(state, function_named(function_name), field_args, 0);
        CHECK(!state.field_sig(0));
    }

    {
        JniState state;
        const char text[] = "captured";
        const uint64_t arguments[] = {reinterpret_cast<uintptr_t>(text)};
        update_jni_state(state, function_named("NewStringUTF"), arguments, 0);
        CHECK(!state.string_value(0));
    }

    for (const char *function_name : {
                 "NewGlobalRef", "NewLocalRef", "NewWeakGlobalRef"}) {
        JniState state;
        constexpr uintptr_t old_reference = 0x4004;
        state.on_new_object(old_reference, "java/lang/String");
        const uint64_t arguments[] = {old_reference};
        update_jni_state(state, function_named(function_name), arguments, 0);
        CHECK(!state.object_type(0));
    }
}

} // namespace

int main() {
    valid_c_strings_update_the_expected_handles();
    failed_c_string_reads_do_not_pollute_state();
    failed_handle_returns_do_not_populate_zero_key();
}
