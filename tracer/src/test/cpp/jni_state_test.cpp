#include "jni/jni_state.h"

#include <barrier>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <mutex>
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
    std::mutex phase_lock;
    std::condition_variable phase_changed;
    enum class Phase { PublishSnapshot, ReadSnapshot, PublishReplacement, CheckSnapshot };
    Phase phase = Phase::PublishSnapshot;
    constexpr int kIterations = 10000;

    std::thread writer([&] {
        for (int i = 0; i < kIterations; ++i) {
            const char *snapshot_value = i % 2 == 0 ? "first" : "second";
            const char *replacement_value = i % 2 == 0 ? "second" : "first";

            {
                std::unique_lock<std::mutex> lock(phase_lock);
                phase_changed.wait(lock, [&] { return phase == Phase::PublishSnapshot; });
                state.on_find_class(2, snapshot_value);
                phase = Phase::ReadSnapshot;
            }
            phase_changed.notify_one();

            {
                std::unique_lock<std::mutex> lock(phase_lock);
                phase_changed.wait(lock, [&] { return phase == Phase::PublishReplacement; });
                state.on_find_class(2, replacement_value);
                phase = Phase::CheckSnapshot;
            }
            phase_changed.notify_one();

            {
                std::unique_lock<std::mutex> lock(phase_lock);
                phase_changed.wait(lock, [&] { return phase == Phase::PublishSnapshot; });
            }
        }
    });
    std::thread reader([&] {
        for (int i = 0; i < kIterations; ++i) {
            const char *snapshot_value = i % 2 == 0 ? "first" : "second";
            const char *replacement_value = i % 2 == 0 ? "second" : "first";
            std::optional<std::string> snapshot;

            {
                std::unique_lock<std::mutex> lock(phase_lock);
                phase_changed.wait(lock, [&] { return phase == Phase::ReadSnapshot; });
                snapshot = state.class_name(2);
                CHECK(snapshot == std::optional<std::string>(snapshot_value));
                phase = Phase::PublishReplacement;
            }
            phase_changed.notify_one();

            {
                std::unique_lock<std::mutex> lock(phase_lock);
                phase_changed.wait(lock, [&] { return phase == Phase::CheckSnapshot; });
                CHECK(snapshot == std::optional<std::string>(snapshot_value));
                CHECK(state.class_name(2) == std::optional<std::string>(replacement_value));
                phase = Phase::PublishSnapshot;
            }
            phase_changed.notify_one();
        }
    });
    writer.join();
    reader.join();
}

void class_queries_overlap_alternating_updates() {
    JniState state;
    state.on_find_class(3, "first");
    constexpr int kIterations = 10000;
    std::barrier start_round(2);
    std::barrier finish_round(2);

    std::thread writer([&] {
        for (int i = 0; i < kIterations; ++i) {
            start_round.arrive_and_wait();
            state.on_find_class(3, i % 2 == 0 ? "second" : "first");
            finish_round.arrive_and_wait();
        }
    });
    std::thread reader([&] {
        for (int i = 0; i < kIterations; ++i) {
            start_round.arrive_and_wait();
            const auto value = state.class_name(3);
            CHECK(value == std::optional<std::string>("first") ||
                  value == std::optional<std::string>("second"));
            finish_round.arrive_and_wait();
        }
    });
    writer.join();
    reader.join();
}

} // namespace

int main() {
    query_results_remain_valid_after_state_updates();
    class_queries_are_safe_during_concurrent_updates();
    class_queries_overlap_alternating_updates();
}
