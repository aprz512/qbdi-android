#include "core/safe_memory.h"

#include <cstdio>
#include <cstdlib>

namespace {

void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

void copies_a_printable_nul_terminated_string() {
    const char valid[] = "java/lang/String";
    CHECK(copy_c_string(reinterpret_cast<uintptr_t>(valid), sizeof(valid)).value() == valid);
}

void rejects_an_invalid_address() {
    CHECK(!copy_c_string(1, 32).has_value());
}

void rejects_a_string_without_a_terminator_in_range() {
    const char unterminated[] = {'a', 'b', 'c'};
    CHECK(!copy_c_string(reinterpret_cast<uintptr_t>(unterminated), sizeof(unterminated)).has_value());
}

void rejects_control_bytes() {
    const char control[] = {'a', '\x01', '\0'};
    CHECK(!copy_c_string(reinterpret_cast<uintptr_t>(control), sizeof(control)).has_value());
}

} // namespace

int main() {
    copies_a_printable_nul_terminated_string();
    rejects_an_invalid_address();
    rejects_a_string_without_a_terminator_in_range();
    rejects_control_bytes();
}
