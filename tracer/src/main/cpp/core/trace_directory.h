#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string_view>

inline bool trace_output_package_component_is_safe(
        std::string_view package) noexcept {
    if (package.empty() || package.size() > 512 || package == "." || package == "..")
        return false;
    for (const unsigned char character : package) {
        const bool alphabetic = (character >= 'a' && character <= 'z') ||
                                (character >= 'A' && character <= 'Z');
        const bool decimal = character >= '0' && character <= '9';
        if (!alphabetic && !decimal && character != '.' &&
            character != '_' && character != '-') {
            return false;
        }
    }
    return true;
}

inline bool trace_default_output_directory(
        std::string_view package, uint32_t uid,
        char *output, size_t capacity) noexcept {
    constexpr uint32_t kAndroidUserRange = 100000;
    if (!trace_output_package_component_is_safe(package) ||
        output == nullptr || capacity == 0)
        return false;
    const uint32_t android_user = uid / kAndroidUserRange;
    const int count = std::snprintf(
            output, capacity, "/data/user/%u/%.*s/files/qbdi-traces",
            android_user, static_cast<int>(package.size()), package.data());
    return count > 0 && static_cast<size_t>(count) < capacity;
}
