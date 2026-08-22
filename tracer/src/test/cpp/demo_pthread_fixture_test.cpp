#include "demo_target/pthread_fixture.h"

#include <pthread.h>

#include <cstdio>
#include <cstdint>
#include <cstdlib>

namespace {

void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

void *return_argument(void *argument) {
    return argument;
}

void target_parent_preserves_child_status_and_result() {
    int token = 0x5142;
    DemoPthreadParentArgs arguments{
            return_argument, &token, {-101, -102},
            reinterpret_cast<void *>(static_cast<uintptr_t>(1))};
    pthread_t parent{};
    CHECK(pthread_create(&parent, nullptr, demo_pthread_parent_start,
                         &arguments) == 0);
    void *parent_result = nullptr;
    CHECK(pthread_join(parent, &parent_result) == 0);

    CHECK(arguments.status.create == 0);
    CHECK(arguments.status.join == 0);
    CHECK(arguments.result == &token);
    CHECK(parent_result == &token);
}

} // namespace

int main() {
    target_parent_preserves_child_status_and_result();
}
