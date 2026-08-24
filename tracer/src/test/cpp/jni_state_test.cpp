#include "jni/jni_state.h"

#include <atomic>
#include <barrier>
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

void class_queries_overlap_alternating_updates() {
    JniState state;
    state.on_find_class(3, "first");
    constexpr int kIterations = 10000;
    std::atomic<bool> writer_in_call{false};
    std::atomic<bool> reader_in_call{false};
    std::barrier entered_call(2);
    std::barrier finished_call(2);
    std::barrier cleared_call(2);

    std::thread writer([&] {
        for (int i = 0; i < kIterations; ++i) {
            writer_in_call.store(true);
            entered_call.arrive_and_wait();
            CHECK(reader_in_call.load());
            state.on_find_class(3, i % 2 == 0 ? "second" : "first");
            finished_call.arrive_and_wait();
            writer_in_call.store(false);
            cleared_call.arrive_and_wait();
        }
    });
    std::thread reader([&] {
        for (int i = 0; i < kIterations; ++i) {
            reader_in_call.store(true);
            entered_call.arrive_and_wait();
            CHECK(writer_in_call.load());
            const auto value = state.class_name(3);
            CHECK(value == std::optional<std::string>("first") ||
                  value == std::optional<std::string>("second"));
            finished_call.arrive_and_wait();
            reader_in_call.store(false);
            cleared_call.arrive_and_wait();
        }
    });
    writer.join();
    reader.join();
}

} // namespace

int main() {
    query_results_remain_valid_after_state_updates();
    class_queries_overlap_alternating_updates();
}
