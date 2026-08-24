#include "jni/jni_formatter.h"
#include "jni/jni_state.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>

namespace {

void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

void only_c_string_values_are_read_for_metadata() {
    JniFormatter formatter;
    JniFuncInfo new_string_utf{"NewStringUTF", JniType::kString, "JNIEnv",
                               {JniType::kCString}};
    const char opaque_handle_bytes[] = "must-not-read";
    const std::string output = formatter.format_leave(
            7, 0, new_string_utf, reinterpret_cast<uintptr_t>(opaque_handle_bytes));
    CHECK(output.find("must-not-read") == std::string::npos);

    JniFuncInfo get_utf{"GetStringUTFChars", JniType::kCString, "JNIEnv",
                        {JniType::kString, JniType::kBoolean}};
    const char text[] = "captured";
    const std::string utf_output = formatter.format_leave(
            7, 0, get_utf, reinterpret_cast<uintptr_t>(text));
    CHECK(utf_output.find("captured") != std::string::npos);
}

void function_table_marks_c_string_positions() {
    const auto table = build_jni_function_table();
    const auto find = [&](std::string_view name) -> const JniFuncInfo & {
        return *std::find_if(table.begin(), table.end(), [&](const JniFuncInfo &func) {
            return name == func.name;
        });
    };
    CHECK(std::string_view(find("FindClass").args[0]) == JniType::kCString);
    CHECK(std::string_view(find("NewStringUTF").args[0]) == JniType::kCString);
    CHECK(std::string_view(find("GetStringUTFChars").ret_type) == JniType::kCString);
}

void c_string_values_use_pointer_formatting() {
    CHECK(JniFormatter::format_ret(JniType::kCString, 0x1234) == "0x1234");
}

void known_jstrings_use_captured_state_without_reading_unknown_handles() {
    constexpr uintptr_t known_handle = 0x4567;
    constexpr uintptr_t unknown_handle = 0x5678;
    jni_state().on_new_string_utf(known_handle, "captured-jstring");

    JniFormatter formatter;
    JniFuncInfo returns_string{"NewStringUTF", JniType::kString, "JNIEnv",
                               {JniType::kCString}};
    const std::string known = formatter.format_leave(7, 0, returns_string, known_handle);
    const std::string unknown = formatter.format_leave(7, 0, returns_string, unknown_handle);

    CHECK(known.find("captured-jstring") != std::string::npos);
    CHECK(unknown.find("captured-jstring") == std::string::npos);
}

void known_jstrings_do_not_require_pointer_like_handle_values() {
    constexpr uintptr_t low_handle = 1;
    jni_state().on_new_string_utf(low_handle, "low-handle");

    JniFormatter formatter;
    JniFuncInfo returns_string{"NewStringUTF", JniType::kString, "JNIEnv",
                               {JniType::kCString}};
    const std::string output = formatter.format_leave(7, 0, returns_string, low_handle);

    CHECK(output.find("low-handle") != std::string::npos);
}

void null_state_handles_do_not_resolve_metadata() {
    auto &state = jni_state();
    state.on_find_class(0, "null-class");
    state.on_new_string_utf(0, "null-string");
    state.on_new_object(0, "null-object");
    state.on_get_method_id(0, "nullMethod", "()V");
    state.on_get_field_id(0, "nullField", "I");

    struct NullCase {
        const char *type;
        const char *forbidden_metadata;
    };
    const NullCase cases[] = {
            {JniType::kClass, "null-class"},
            {JniType::kString, "null-string"},
            {JniType::kObject, "null-object"},
            {JniType::kThrowable, "null-object"},
            {JniType::kWeak, "null-object"},
            {JniType::kMethodID, "nullMethod()V"},
            {JniType::kFieldID, "nullField:I"},
    };

    JniFormatter formatter;
    for (const auto &test_case : cases) {
        JniFuncInfo returns_null{"ReturnsNull", test_case.type, "JNIEnv", {}};
        const std::string output = formatter.format_leave(7, 0, returns_null, 0);
        CHECK(output.find(test_case.forbidden_metadata) == std::string::npos);
    }
}

} // namespace

int main() {
    only_c_string_values_are_read_for_metadata();
    function_table_marks_c_string_positions();
    c_string_values_use_pointer_formatting();
    known_jstrings_use_captured_state_without_reading_unknown_handles();
    known_jstrings_do_not_require_pointer_like_handle_values();
    null_state_handles_do_not_resolve_metadata();
}
