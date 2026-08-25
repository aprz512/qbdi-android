#include "core/trace_generation_runtime.h"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <sched.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

struct FakeDeadline {
    static void wait_until(void *opaque, uint64_t) noexcept {
        auto *deadline = static_cast<FakeDeadline *>(opaque);
        deadline->entries.fetch_add(1, std::memory_order_relaxed);
        deadline->entered.store(true, std::memory_order_release);
        while (!deadline->release.load(std::memory_order_acquire)) ::sched_yield();
        deadline->exited.store(true, std::memory_order_release);
    }

    std::atomic<bool> entered{false};
    std::atomic<bool> release{false};
    std::atomic<bool> exited{false};
    std::atomic<unsigned int> entries{0};
};

SessionOptions timed_session(uint64_t duration_ms) {
    SessionOptions session{};
    session.id = "test";
    session.duration_ms = duration_ms;
    return session;
}

void wait_for(const std::atomic<bool> &value) {
    while (!value.load(std::memory_order_acquire)) ::sched_yield();
}

// Catches an implementation that permits new calls after a deadline request or
// never seals the active pair that acknowledged the requested stop.
void deadline_requests_stop_and_the_active_call_seals_the_generation() {
    FakeDeadline deadline;
    auto runtime = TraceGenerationRuntime::create(
            3, timed_session(60000), DeadlineWait{&deadline, &FakeDeadline::wait_until});
    CHECK(runtime != nullptr);
    CHECK(runtime->arm());
    CHECK(runtime->try_begin_call(3, 101));
    wait_for(deadline.entered);
    deadline.release.store(true, std::memory_order_release);
    runtime->join_deadline_for_test();
    CHECK(runtime->stop_token().requested());
    CHECK(runtime->stop_token().reason() == TraceStopReason::DurationElapsed);
    CHECK(!runtime->try_begin_call(3, 102));
    runtime->acknowledge_sealed(3, 101);
    CHECK(runtime->snapshot().phase == TraceGenerationPhase::Sealed);
}

// Catches an acknowledgement that matches only a tid, or an acknowledgement
// that can move a terminal generation out of Sealed.
void wrong_pair_and_repeated_acknowledgements_are_idempotent() {
    FakeDeadline deadline;
    auto runtime = TraceGenerationRuntime::create(
            7, timed_session(60000), DeadlineWait{&deadline, &FakeDeadline::wait_until});
    CHECK(runtime != nullptr);
    CHECK(runtime->arm());
    CHECK(runtime->try_begin_call(7, 303));
    wait_for(deadline.entered);
    deadline.release.store(true, std::memory_order_release);
    runtime->join_deadline_for_test();

    runtime->acknowledge_sealed(8, 303);
    CHECK(runtime->snapshot().phase == TraceGenerationPhase::StopRequested);
    runtime->acknowledge_sealed(7, 303);
    CHECK(runtime->snapshot().phase == TraceGenerationPhase::Sealed);
    runtime->acknowledge_sealed(7, 303);
    CHECK(runtime->snapshot().phase == TraceGenerationPhase::Sealed);
}

// Catches a stop request which leaves an idle timed generation indefinitely in
// StopRequested instead of publishing its terminal state.
void idle_generation_seals_immediately_after_the_deadline() {
    FakeDeadline deadline;
    auto runtime = TraceGenerationRuntime::create(
            9, timed_session(60000), DeadlineWait{&deadline, &FakeDeadline::wait_until});
    CHECK(runtime != nullptr);
    CHECK(runtime->arm());
    wait_for(deadline.entered);
    deadline.release.store(true, std::memory_order_release);
    runtime->join_deadline_for_test();
    CHECK(runtime->snapshot().phase == TraceGenerationPhase::Sealed);
    CHECK(!runtime->try_begin_call(9, 404));
}

// Catches monitor mode accidentally creating a deadline thread or rejecting
// ordinary call entry/finish transitions.
void monitor_mode_runs_without_a_deadline_worker() {
    FakeDeadline deadline;
    SessionOptions session{};
    session.id = "monitor";
    auto runtime = TraceGenerationRuntime::create(
            11, session, DeadlineWait{&deadline, &FakeDeadline::wait_until});
    CHECK(runtime != nullptr);
    CHECK(runtime->arm());
    CHECK(!deadline.entered.load(std::memory_order_acquire));
    CHECK(runtime->snapshot().phase == TraceGenerationPhase::Running);
    CHECK(runtime->try_begin_call(11, 505));
    runtime->finish_call(11, 505, false);
    CHECK(runtime->snapshot().phase == TraceGenerationPhase::Running);
}

// Catches a timed runtime spawning more than one worker when arm is repeated,
// which would make independent deadline requests race each other.
void repeated_arm_is_idempotent() {
    FakeDeadline deadline;
    auto runtime = TraceGenerationRuntime::create(
            12, timed_session(60000), DeadlineWait{&deadline, &FakeDeadline::wait_until});
    CHECK(runtime != nullptr);
    CHECK(runtime->arm());
    CHECK(runtime->arm());
    wait_for(deadline.entered);
    CHECK(deadline.entries.load(std::memory_order_acquire) == 1);
    deadline.release.store(true, std::memory_order_release);
    runtime->join_deadline_for_test();
}

// Catches a stopped call that fails to seal from being reported as a clean
// terminal artifact.
void unsealed_last_active_call_marks_stop_incomplete() {
    FakeDeadline deadline;
    auto runtime = TraceGenerationRuntime::create(
            14, timed_session(60000), DeadlineWait{&deadline, &FakeDeadline::wait_until});
    CHECK(runtime != nullptr);
    CHECK(runtime->arm());
    CHECK(runtime->try_begin_call(14, 606));
    wait_for(deadline.entered);
    deadline.release.store(true, std::memory_order_release);
    runtime->join_deadline_for_test();
    runtime->finish_call(14, 606, false);
    CHECK(runtime->snapshot().phase == TraceGenerationPhase::StopIncomplete);
}

// Catches callback-time registration growing unboundedly instead of rejecting
// a pair beyond its preallocated active-session capacity.
void admission_rejects_calls_beyond_the_fixed_capacity() {
    SessionOptions session{};
    session.id = "monitor";
    auto runtime = TraceGenerationRuntime::create(17, session);
    CHECK(runtime != nullptr);
    CHECK(runtime->arm());
    for (uint32_t tid = 1; tid <= 512; ++tid) CHECK(runtime->try_begin_call(17, tid));
    CHECK(!runtime->try_begin_call(17, 513));
    CHECK(runtime->snapshot().active_calls == 512);
    for (uint32_t tid = 1; tid <= 512; ++tid) runtime->finish_call(17, tid, false);
    CHECK(runtime->snapshot().active_calls == 0);
}

// Catches duplicate entry for one active pair: two successful owners would let
// one finish remove the other's registration and seal too early after a stop.
void admission_rejects_a_duplicate_active_pair() {
    SessionOptions session{};
    session.id = "monitor";
    auto runtime = TraceGenerationRuntime::create(18, session);
    CHECK(runtime != nullptr);
    CHECK(runtime->arm());
    CHECK(runtime->try_begin_call(18, 707));
    CHECK(!runtime->try_begin_call(18, 707));
    CHECK(runtime->snapshot().active_calls == 1);
    runtime->finish_call(18, 707, false);
    CHECK(runtime->snapshot().active_calls == 0);
}

// Catches destructors that abandon a completed deadline pthread rather than
// joining it before releasing runtime ownership.
void destruction_joins_the_deadline_worker() {
    FakeDeadline deadline;
    {
        auto runtime = TraceGenerationRuntime::create(
                13, timed_session(60000), DeadlineWait{&deadline, &FakeDeadline::wait_until});
        CHECK(runtime != nullptr);
        CHECK(runtime->arm());
        wait_for(deadline.entered);
        deadline.release.store(true, std::memory_order_release);
    }
    CHECK(deadline.exited.load(std::memory_order_acquire));
}

// Catches a child destructor trying to pthread_join a worker inherited through
// fork, which has no joinable peer in that child process.
void forked_child_detaches_the_inherited_deadline_worker() {
    FakeDeadline deadline;
    auto runtime = TraceGenerationRuntime::create(
            15, timed_session(60000), DeadlineWait{&deadline, &FakeDeadline::wait_until});
    CHECK(runtime != nullptr);
    CHECK(runtime->arm());
    wait_for(deadline.entered);
    const pid_t child = ::fork();
    CHECK(child >= 0);
    if (child == 0) {
        runtime->detach_after_fork_child();
        runtime.reset();
        _exit(0);
    }
    deadline.release.store(true, std::memory_order_release);
    runtime.reset();
    int status = 0;
    CHECK(::waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status));
    CHECK(WEXITSTATUS(status) == 0);
}

} // namespace

int main() {
    deadline_requests_stop_and_the_active_call_seals_the_generation();
    wrong_pair_and_repeated_acknowledgements_are_idempotent();
    idle_generation_seals_immediately_after_the_deadline();
    monitor_mode_runs_without_a_deadline_worker();
    repeated_arm_is_idempotent();
    unsealed_last_active_call_marks_stop_incomplete();
    admission_rejects_calls_beyond_the_fixed_capacity();
    admission_rejects_a_duplicate_active_pair();
    destruction_joins_the_deadline_worker();
    forked_child_detaches_the_inherited_deadline_worker();
}
