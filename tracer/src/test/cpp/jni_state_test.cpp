#include "jni/jni_state.h"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <optional>
#include <thread>

namespace {

void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

void query_results_remain_valid_after_state_updates() {
    JniState state;
    state.on_find_class(1, "first");
    const auto snapshot = state.class_name(1);
    state.on_find_class(1, "second");
    CHECK(snapshot == std::optional<std::string>("first"));
    CHECK(state.class_name(1) == std::optional<std::string>("second"));
}

void class_queries_are_safe_during_concurrent_updates() {
    JniState state;
    std::atomic<bool> start{false};
    std::thread writer([&] {
        while (!start.load()) {}
        for (int i = 0; i < 10000; ++i) state.on_find_class(2, "stable");
    });
    std::thread reader([&] {
        start.store(true);
        for (int i = 0; i < 10000; ++i) {
            const auto value = state.class_name(2);
            if (value) CHECK(*value == "stable");
        }
    });
    writer.join();
    reader.join();
}

} // namespace

int main() {
    query_results_remain_valid_after_state_updates();
    class_queries_are_safe_during_concurrent_updates();
}
