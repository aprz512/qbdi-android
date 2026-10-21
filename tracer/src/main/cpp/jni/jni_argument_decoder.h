#pragma once

#include "jni/jni_function_table.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// Snapshot at EXEC_TRANSFER_CALL, before the native callee changes registers or
// consumes its va_list. Only the low 64 bits of v0-v7 are needed for JNI scalars.
struct Arm64JniArguments {
    std::array<uint64_t, 8> general{};
    std::array<uint64_t, 8> floating{};
    uintptr_t stack = 0;
    bool has_floating = false;
};

struct JniDecodedArgument {
    std::string type;
    uint64_t bits = 0;
};

struct JniDecodedArguments {
    std::vector<JniDecodedArgument> values;
    std::string error;
};

using JniArgumentMemoryReader = bool (*)(uintptr_t, void *, size_t);

// Decode declared JNI parameters after JNIEnv*/JavaVM*. Fixed floats are passed
// as float32, unlike the double promotion used by Java variadic arguments.
JniDecodedArguments decode_arm64_jni_fixed_arguments(
        const JniFuncInfo &function, const Arm64JniArguments &arguments,
        JniArgumentMemoryReader read_memory);

// Decode Java method arguments for ordinary, V and A JNI calls, including
// nonvirtual calls and constructors. No JNI operations or target-memory writes.
JniDecodedArguments decode_arm64_jni_arguments(
        const JniFuncInfo &function, const Arm64JniArguments &arguments,
        const std::optional<std::string> &signature,
        JniArgumentMemoryReader read_memory);
