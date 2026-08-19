#pragma once

#include <cstddef>

constexpr size_t kMaxFixedSixBytes = 48;

struct FixedSixResult {
    bool ok = false;
    size_t size = 0;
};

inline FixedSixResult format_fixed_six(char *output, size_t capacity,
                                       unsigned __int128 numerator,
                                       unsigned __int128 denominator) noexcept {
    const unsigned __int128 whole = denominator == 0 ? 0 : numerator / denominator;
    unsigned __int128 remainder = denominator == 0 ? 0 : numerator % denominator;
    char reversed[40];
    size_t whole_size = 0;
    unsigned __int128 value = whole;
    do {
        reversed[whole_size++] = static_cast<char>('0' + value % 10U);
        value /= 10U;
    } while (value != 0);

    const size_t required = whole_size + 7U;
    if (output == nullptr || capacity < required) return {false, required};

    size_t offset = 0;
    while (whole_size != 0) output[offset++] = reversed[--whole_size];
    output[offset++] = '.';
    for (size_t index = 0; index < 6; ++index) {
        const unsigned __int128 digit = denominator == 0 ? 0 : (remainder * 10U) / denominator;
        remainder = denominator == 0 ? 0 : (remainder * 10U) % denominator;
        output[offset++] = static_cast<char>('0' + digit);
    }
    return {true, offset};
}
