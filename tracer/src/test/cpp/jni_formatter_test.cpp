#include "jni/jni_formatter.h"

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

} // namespace

int main() {
    only_c_string_values_are_read_for_metadata();
    function_table_marks_c_string_positions();
}
