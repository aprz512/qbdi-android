#include "core/trace_generation_runtime.h"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <sched.h>
#include <sys/wait.h>
#include <thread>
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

TraceAdmission admit(const std::shared_ptr<TraceGenerationRuntime> &runtime,
                     uint64_t generation, size_t scene_index, uint32_t tid) {
    const TraceAdmissionResult result = runtime->try_begin_call(generation, scene_index, tid);
    CHECK(result.status == TraceAdmissionStatus::Admitted);
    return result.admission;
}

// Catches an implementation that permits new calls after a deadline request or
// never seals the active pair that acknowledged the requested stop.
void deadline_requests_stop_and_the_active_call_seals_the_generation() {
    FakeDeadline deadline;
    auto runtime = TraceGenerationRuntime::create(
            3, timed_session(60000), DeadlineWait{&deadline, &FakeDeadline::wait_until});
    CHECK(runtime != nullptr);
    CHECK(runtime->arm());
    const TraceAdmission admission = admit(runtime, 3, 3, 101);
    wait_for(deadline.entered);
    deadline.release.store(true, std::memory_order_release);
    runtime->join_deadline_for_test();
    CHECK(runtime->stop_token().requested());
    CHECK(runtime->stop_token().reason() == TraceStopReason::DurationElapsed);
    CHECK(runtime->try_begin_call(3, 3, 102).status == TraceAdmissionStatus::NotRunning);
    runtime->acknowledge_sealed(admission);
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
    const TraceAdmission admission = admit(runtime, 7, 7, 303);
    wait_for(deadline.entered);
    deadline.release.store(true, std::memory_order_release);
    runtime->join_deadline_for_test();

    runtime->acknowledge_sealed(TraceAdmission{7, 8, 303, admission.serial});
    CHECK(runtime->snapshot().phase == TraceGenerationPhase::StopRequested);
    runtime->acknowledge_sealed(admission);
    CHECK(runtime->snapshot().phase == TraceGenerationPhase::Sealed);
    runtime->acknowledge_sealed(admission);
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
    CHECK(runtime->try_begin_call(9, 9, 404).status == TraceAdmissionStatus::NotRunning);
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
    runtime->finish_call(admit(runtime, 11, 11, 505), false);
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
    const TraceAdmission admission = admit(runtime, 14, 14, 606);
    wait_for(deadline.entered);
    deadline.release.store(true, std::memory_order_release);
    runtime->join_deadline_for_test();
    runtime->finish_call(admission, false);
    CHECK(runtime->snapshot().phase == TraceGenerationPhase::StopIncomplete);
}

// Catches callback-time registration growing unboundedly instead of rejecting
// a pair beyond its preallocated active-session capacity.
void admission_rejects_calls_beyond_the_fixed_capacity() {
    SessionOptions session{};
    session.id = "monitor";
    auto runtime = TraceGenerationRuntime::create(
            17, session, TraceGenerationLimits{2, 3});
    CHECK(runtime != nullptr);
    CHECK(runtime->arm());
    std::array<TraceAdmission, 5> admissions{};
    for (uint32_t tid = 1; tid <= 5; ++tid) admissions[tid - 1] = admit(runtime, 17, 0, tid);
    CHECK(runtime->try_begin_call(17, 0, 6).status == TraceAdmissionStatus::ActiveSessionLimit);
    CHECK(runtime->snapshot().active_calls == 5);
    for (const TraceAdmission &admission : admissions) runtime->finish_call(admission, false);
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
    const TraceAdmission admission = admit(runtime, 18, 0, 707);
    CHECK(runtime->try_begin_call(18, 0, 707).status == TraceAdmissionStatus::Duplicate);
    CHECK(runtime->snapshot().active_calls == 1);
    runtime->finish_call(admission, false);
    CHECK(runtime->snapshot().active_calls == 0);
}

// Catches callers that cannot distinguish a stopped runtime, another
// generation, a duplicate pair, and capacity exhaustion for policy reporting.
void admission_statuses_identify_every_rejection_reason() {
    SessionOptions session{};
    session.id = "monitor";
    auto runtime = TraceGenerationRuntime::create(19, session, TraceGenerationLimits{1, 0});
    CHECK(runtime != nullptr);
    CHECK(runtime->try_begin_call(19, 0, 1).status == TraceAdmissionStatus::NotRunning);
    CHECK(runtime->arm());
    CHECK(runtime->try_begin_call(20, 0, 1).status == TraceAdmissionStatus::WrongGeneration);
    const TraceAdmission admission = admit(runtime, 19, 0, 1);
    CHECK(runtime->try_begin_call(19, 0, 1).status == TraceAdmissionStatus::Duplicate);
    CHECK(runtime->try_begin_call(19, 0, 2).status == TraceAdmissionStatus::ActiveSessionLimit);
    runtime->finish_call(admission, false);
}

// Catches invalid capacity configuration before it can produce an unbounded or
// zero-sized callback-time admission store.
void invalid_generation_limits_are_rejected() {
    SessionOptions session{};
    session.id = "monitor";
    CHECK(TraceGenerationRuntime::create(20, session, TraceGenerationLimits{257, 0}) == nullptr);
    CHECK(TraceGenerationRuntime::create(20, session, TraceGenerationLimits{256, 1025}) == nullptr);
    CHECK(TraceGenerationRuntime::create(20, session, TraceGenerationLimits{0, 0}) == nullptr);
}

// Catches a stale generation or serial acknowledgement removing a later call
// that reuses the same (scene, tid) pair.
void stale_admission_cannot_remove_a_reused_pair() {
    SessionOptions session{};
    session.id = "monitor";
    auto runtime = TraceGenerationRuntime::create(21, session);
    CHECK(runtime != nullptr);
    CHECK(runtime->arm());
    const TraceAdmission old_admission = admit(runtime, 21, 1, 808);
    runtime->finish_call(old_admission, false);
    const TraceAdmission current_admission = admit(runtime, 21, 1, 808);
    runtime->acknowledge_sealed(old_admission);
    runtime->acknowledge_sealed(TraceAdmission{22, 1, 808, current_admission.serial});
    CHECK(runtime->snapshot().active_calls == 1);
    runtime->finish_call(current_admission, false);
    CHECK(runtime->snapshot().active_calls == 0);
}

struct StopRaceBarrier {
    static void after_active_removal(void *opaque) noexcept {
        auto *barrier = static_cast<StopRaceBarrier *>(opaque);
        barrier->active_removed.store(true, std::memory_order_release);
        while (!barrier->allow_finish.load(std::memory_order_acquire)) ::sched_yield();
    }

    static void before_deadline_stop_lock(void *opaque) noexcept {
        static_cast<StopRaceBarrier *>(opaque)->deadline_attempted.store(
                true, std::memory_order_release);
    }

    std::atomic<bool> active_removed{false};
    std::atomic<bool> deadline_attempted{false};
    std::atomic<bool> allow_finish{false};
};

struct ArmBarrier {
    static void after_enters_arming(void *opaque) noexcept {
        auto *barrier = static_cast<ArmBarrier *>(opaque);
        barrier->entered.store(true, std::memory_order_release);
        while (!barrier->release.load(std::memory_order_acquire)) ::sched_yield();
    }

    std::atomic<bool> entered{false};
    std::atomic<bool> release{false};
};

struct ArmFailure {
    static bool fail_clock(void *opaque) noexcept {
        return static_cast<ArmFailure *>(opaque)->clock;
    }

    static bool fail_thread_create(void *opaque) noexcept {
        return static_cast<ArmFailure *>(opaque)->thread_create;
    }

    bool clock = false;
    bool thread_create = false;
};

// Catches the former false-success path where a second caller observed only
// armed_=true while the first caller was still performing fallible setup.
void concurrent_arm_reports_success_only_after_setup_completes() {
    SessionOptions session{};
    session.id = "monitor";
    ArmBarrier barrier;
    auto runtime = TraceGenerationRuntime::create(24, session);
    CHECK(runtime != nullptr);
    TraceGenerationTestHooks hooks{};
    hooks.opaque = &barrier;
    hooks.after_arm_enters_arming = &ArmBarrier::after_enters_arming;
    runtime->set_test_hooks(hooks);

    std::atomic<bool> first_result{false};
    std::thread first([&] { first_result.store(runtime->arm(), std::memory_order_release); });
    wait_for(barrier.entered);
    CHECK(!runtime->arm());
    barrier.release.store(true, std::memory_order_release);
    first.join();
    CHECK(first_result.load(std::memory_order_acquire));
    CHECK(runtime->arm());
}

// Catches failed clock or pthread setup being advertised as a successfully
// armed generation to a later caller.
void failed_arm_is_never_reported_as_successful() {
    for (const ArmFailure failure : {ArmFailure{true, false}, ArmFailure{false, true}}) {
        ArmFailure injected = failure;
        auto runtime = TraceGenerationRuntime::create(25, timed_session(60000));
        CHECK(runtime != nullptr);
        TraceGenerationTestHooks hooks{};
        hooks.opaque = &injected;
        hooks.fail_clock_read = &ArmFailure::fail_clock;
        hooks.fail_thread_create = &ArmFailure::fail_thread_create;
        runtime->set_test_hooks(hooks);
        CHECK(!runtime->arm());
        CHECK(!runtime->arm());
    }
}

// Catches the former interleaving where finish removed the final call before
// recording failure and the deadline worker then sealed it as successful.
void concurrent_deadline_and_unsealed_last_finish_select_stop_incomplete() {
    FakeDeadline deadline;
    StopRaceBarrier barrier;
    auto runtime = TraceGenerationRuntime::create(
            23, timed_session(60000), DeadlineWait{&deadline, &FakeDeadline::wait_until});
    CHECK(runtime != nullptr);
    runtime->set_test_hooks(TraceGenerationTestHooks{
            &barrier, &StopRaceBarrier::after_active_removal,
            &StopRaceBarrier::before_deadline_stop_lock});
    CHECK(runtime->arm());
    const TraceAdmission admission = admit(runtime, 23, 0, 909);
    wait_for(deadline.entered);
    std::thread finisher([&] { runtime->finish_call(admission, false); });
    wait_for(barrier.active_removed);
    deadline.release.store(true, std::memory_order_release);
    wait_for(barrier.deadline_attempted);
    barrier.allow_finish.store(true, std::memory_order_release);
    finisher.join();
    runtime->join_deadline_for_test();
    CHECK(runtime->snapshot().phase == TraceGenerationPhase::StopIncomplete);
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
    admission_statuses_identify_every_rejection_reason();
    invalid_generation_limits_are_rejected();
    stale_admission_cannot_remove_a_reused_pair();
    concurrent_arm_reports_success_only_after_setup_completes();
    failed_arm_is_never_reported_as_successful();
    concurrent_deadline_and_unsealed_last_finish_select_stop_incomplete();
    destruction_joins_the_deadline_worker();
    forked_child_detaches_the_inherited_deadline_worker();
}
