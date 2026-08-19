#include "events/trace_number_formatter.h"

#include <array>
#include <cstdint>
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

void formats_fixed_six_rates_without_allocation() {
    char output[kMaxFixedSixBytes]{};
    FixedSixResult result = format_fixed_six(output, sizeof(output), 9, 10);
    CHECK(result.ok);
    CHECK(std::string_view(output, result.size) == "0.900000");

    result = format_fixed_six(output, sizeof(output), 1, 0);
    CHECK(result.ok);
    CHECK(std::string_view(output, result.size) == "0.000000");

    const unsigned __int128 large = static_cast<unsigned __int128>(~uint64_t{0}) * 1000U;
    result = format_fixed_six(output, sizeof(output), large, 1);
    CHECK(result.ok);
    CHECK(std::string_view(output, result.size) == "18446744073709551615000.000000");

    const unsigned __int128 maximum = ~static_cast<unsigned __int128>(0);
    result = format_fixed_six(output, sizeof(output), maximum - 1U, maximum);
    CHECK(result.ok);
    CHECK(std::string_view(output, result.size) == "0.999999");
}

void rejects_small_output_without_partial_writes() {
    std::array<char, 4> output{'#', '#', '#', '#'};
    const FixedSixResult result = format_fixed_six(output.data(), output.size(), 1, 3);
    CHECK(!result.ok);
    CHECK(result.size == 8);
    for (char value : output) CHECK(value == '#');
}

} // namespace

int main() {
    formats_fixed_six_rates_without_allocation();
    rejects_small_output_without_partial_writes();
}
