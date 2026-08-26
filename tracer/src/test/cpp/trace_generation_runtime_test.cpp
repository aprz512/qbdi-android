#include "core/trace_generation_runtime.h"
#include "third_party/nlohmann/json.hpp"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <sched.h>
#include <sys/wait.h>
#include <thread>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>

namespace {

void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

struct FakeDeadline {
    static void wait_until(void *opaque, uint64_t, const std::atomic<bool> *stop) noexcept {
        auto *deadline = static_cast<FakeDeadline *>(opaque);
        deadline->entries.fetch_add(1, std::memory_order_relaxed);
        deadline->entered.store(true, std::memory_order_release);
        while (!deadline->release.load(std::memory_order_acquire) &&
               !stop->load(std::memory_order_acquire)) ::sched_yield();
        deadline->exited.store(true, std::memory_order_release);
    }

    std::atomic<bool> entered{false};
    std::atomic<bool> release{false};
    std::atomic<bool> exited{false};
    std::atomic<unsigned int> entries{0};
};

struct CancellableDeadline {
    static void wait_until(void *opaque, uint64_t, const std::atomic<bool> *stop) noexcept {
        auto *deadline = static_cast<CancellableDeadline *>(opaque);
        deadline->entered.store(true, std::memory_order_release);
        while (!stop->load(std::memory_order_acquire)) ::sched_yield();
        deadline->exited.store(true, std::memory_order_release);
    }

    std::atomic<bool> entered{false};
    std::atomic<bool> exited{false};
};

struct SelfDestroyingDeadline {
    static void wait_until(void *opaque, uint64_t, const std::atomic<bool> *stop) noexcept {
        auto *deadline = static_cast<SelfDestroyingDeadline *>(opaque);
        deadline->entered.store(true, std::memory_order_release);
        while (!deadline->release.load(std::memory_order_acquire) &&
               !stop->load(std::memory_order_acquire)) ::sched_yield();
        deadline->owner->reset();
        deadline->released_owner.store(true, std::memory_order_release);
    }

    std::shared_ptr<TraceGenerationRuntime> *owner = nullptr;
    std::atomic<bool> entered{false};
    std::atomic<bool> release{false};
    std::atomic<bool> released_owner{false};
};

struct TemporaryDirectory {
    TemporaryDirectory() {
        char template_path[] = "/tmp/qtrace-runtime-status-XXXXXX";
        CHECK(::mkdtemp(template_path) != nullptr);
        path = template_path;
    }

    ~TemporaryDirectory() {
        DIR *directory = ::opendir(path.c_str());
        if (directory != nullptr) {
            while (dirent *entry = ::readdir(directory)) {
                if (entry->d_name[0] == '.') continue;
                const std::string child = path + "/" + entry->d_name;
                (void)::unlink(child.c_str());
            }
            (void)::closedir(directory);
        }
        (void)::rmdir(path.c_str());
    }

    std::string path;
};

struct ControlledStatusPoll {
    static void wait(void *opaque, const std::atomic<bool> *stop) noexcept {
        auto *poll = static_cast<ControlledStatusPoll *>(opaque);
        poll->waits.fetch_add(1, std::memory_order_release);
        while (poll->permits.load(std::memory_order_acquire) == 0 &&
               !stop->load(std::memory_order_acquire)) ::sched_yield();
        if (poll->permits.load(std::memory_order_acquire) != 0)
            poll->permits.fetch_sub(1, std::memory_order_acq_rel);
    }

    void allow_one() noexcept { permits.fetch_add(1, std::memory_order_release); }

    std::atomic<unsigned int> waits{0};
    std::atomic<unsigned int> permits{0};
};

struct SelfDestroyingStatusPoll {
    static void wait(void *opaque, const std::atomic<bool> *stop) noexcept {
        auto *poll = static_cast<SelfDestroyingStatusPoll *>(opaque);
        poll->entered.store(true, std::memory_order_release);
        while (!poll->release.load(std::memory_order_acquire) &&
               !stop->load(std::memory_order_acquire)) ::sched_yield();
        poll->owner->reset();
        poll->released_owner.store(true, std::memory_order_release);
    }

    std::shared_ptr<TraceGenerationRuntime> *owner = nullptr;
    std::atomic<bool> entered{false};
    std::atomic<bool> release{false};
    std::atomic<bool> released_owner{false};
};

struct StatusWorkerFailure {
    static bool fail_context_allocation(void *opaque) noexcept {
        return static_cast<StatusWorkerFailure *>(opaque)->fail_context;
    }

    static bool fail_thread_create(void *opaque) noexcept {
        return static_cast<StatusWorkerFailure *>(opaque)->fail_thread;
    }

    bool fail_context = false;
    bool fail_thread = false;
};

void wait_for_count(const std::atomic<unsigned int> &value, unsigned int minimum) {
    while (value.load(std::memory_order_acquire) < minimum) ::sched_yield();
}

std::string read_text(const std::string &path) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0);
    std::string text;
    char buffer[512];
    for (;;) {
        const ssize_t count = ::read(fd, buffer, sizeof(buffer));
        CHECK(count >= 0);
        if (count == 0) break;
        text.append(buffer, static_cast<size_t>(count));
    }
    CHECK(::close(fd) == 0);
    return text;
}

ino_t inode_of(const std::string &path) {
    struct stat status{};
    CHECK(::stat(path.c_str(), &status) == 0);
    return status.st_ino;
}

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

// Catches destruction joining a 24-hour deadline sleep before signalling it
// to stop. The injected wait has no release other than the runtime stop token.
void destruction_cancels_a_24_hour_deadline_worker() {
    CancellableDeadline deadline;
    {
        auto runtime = TraceGenerationRuntime::create(
                30, timed_session(86400000), DeadlineWait{&deadline, &CancellableDeadline::wait_until});
        CHECK(runtime != nullptr);
        CHECK(runtime->arm());
        wait_for(deadline.entered);
    }
    CHECK(deadline.exited.load(std::memory_order_acquire));
}

// Catches a deadline entry dereferencing raw runtime storage after its injected
// wait releases the last shared owner from the worker thread itself.
void deadline_worker_survives_releasing_the_last_runtime_owner() {
    std::shared_ptr<TraceGenerationRuntime> runtime;
    SelfDestroyingDeadline deadline{&runtime};
    runtime = TraceGenerationRuntime::create(
            34, timed_session(86400000), DeadlineWait{&deadline, &SelfDestroyingDeadline::wait_until});
    CHECK(runtime != nullptr);
    CHECK(runtime->arm());
    wait_for(deadline.entered);
    deadline.release.store(true, std::memory_order_release);
    wait_for(deadline.released_owner);
    CHECK(runtime == nullptr);
}

// Catches a status poll callback releasing the final owner and leaving the
// loop to dereference its former raw runtime pointer after that callback.
void status_worker_survives_releasing_the_last_runtime_owner() {
    TemporaryDirectory directory;
    std::shared_ptr<TraceGenerationRuntime> runtime;
    SelfDestroyingStatusPoll poll{&runtime};
    TraceConfig config{};
    config.package_name = "com.example.runtime";
    config.session.id = "7d5807cf-cf09-4f21-92de-1ad92802610a";
    TraceGenerationStatusOptions status{};
    status.config = config;
    status.output_directory = directory.path;
    status.poll_wait = StatusPollWait{&poll, &SelfDestroyingStatusPoll::wait};
    runtime = TraceGenerationRuntime::create(
            35, config.session, TraceGenerationLimits{}, DeadlineWait{}, std::move(status));
    CHECK(runtime != nullptr);
    CHECK(runtime->arm());
    wait_for(poll.entered);
    poll.release.store(true, std::memory_order_release);
    wait_for(poll.released_owner);
    CHECK(runtime == nullptr);
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

// Catches status I/O occurring from the deadline/callback transition itself,
// publishing unchanged data, or abandoning the dedicated status pthread at
// destruction. The controlled wait is a deterministic 25 ms poll substitute.
void installed_status_is_published_before_running_worker_state() {
    TemporaryDirectory directory;
    ControlledStatusPoll poll;
    TraceConfig config{};
    config.package_name = "com.example.runtime";
    config.session.id = "7d5807cf-cf09-4f21-92de-1ad92802610a";
    config.scenes = {{0, "entry", 16, 32}};
    TraceGenerationStatusOptions status{};
    status.config = config;
    status.output_directory = directory.path;
    status.poll_wait = StatusPollWait{&poll, &ControlledStatusPoll::wait};
    auto runtime = TraceGenerationRuntime::create(
            31, config.session, TraceGenerationLimits{}, DeadlineWait{}, std::move(status));
    CHECK(runtime != nullptr);
    const std::string path = directory.path + "/session-" + config.session.id + ".status.json";
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    CHECK(poll.waits.load(std::memory_order_acquire) == 0);
    CHECK(::access(path.c_str(), F_OK) != 0);
    CHECK(runtime->publish_installed_status());
    CHECK(read_text(path).find("\"state\":\"installed\"") !=
          std::string::npos);
    CHECK(poll.waits.load(std::memory_order_acquire) == 0);
    CHECK(runtime->arm());
    wait_for_count(poll.waits, 1);
    CHECK(read_text(path).find("\"state\":\"running\"") != std::string::npos);
    CHECK(runtime->record_status_warning(
            "FINAL_WARNING", "$.warnings", "published during retirement"));
    runtime.reset();
    CHECK(read_text(path).find("\"code\":\"FINAL_WARNING\"") !=
          std::string::npos);
}

void status_worker_failure_preserves_initial_and_final_publication() {
    const auto run_case = [](const char *session_id, uint64_t generation,
                             bool fail_context, bool fail_thread,
                             int expected_error) {
        TemporaryDirectory directory;
        TraceConfig config{};
        config.package_name = "com.example.runtime";
        config.session.id = session_id;
        TraceGenerationStatusOptions status{};
        status.config = config;
        status.output_directory = directory.path;
        auto runtime = TraceGenerationRuntime::create(
                generation, config.session, TraceGenerationLimits{},
                DeadlineWait{}, std::move(status));
        CHECK(runtime != nullptr);
        StatusWorkerFailure failure{};
        failure.fail_context = fail_context;
        failure.fail_thread = fail_thread;
        runtime->set_test_hooks(TraceGenerationTestHooks{
                .opaque = &failure,
                .fail_status_context_allocation =
                        &StatusWorkerFailure::fail_context_allocation,
                .fail_status_thread_create =
                        &StatusWorkerFailure::fail_thread_create,
        });
        const std::string path = directory.path + "/session-" +
                                 config.session.id + ".status.json";
        CHECK(runtime->publish_installed_status());
        CHECK(read_text(path).find("\"state\":\"installed\"") !=
              std::string::npos);
        CHECK(runtime->arm());
        CHECK(runtime->snapshot().phase == TraceGenerationPhase::Running);
        CHECK(runtime->snapshot().status_error == expected_error);
        runtime.reset();
        const nlohmann::json final = nlohmann::json::parse(read_text(path));
        CHECK(final.at("state") == "running");
        CHECK(final.at("errors").at(0).at("code") ==
              "STATUS_PUBLICATION_FAILED");
    };
    run_case("7d5807cf-cf09-4f21-92de-1ad92802610a", 38, false, true,
             EAGAIN);
    run_case("a850590f-cc92-4b19-ad3f-6de57df0e7c1", 39, true, false,
             ENOMEM);
}

void final_status_failure_retries_once_with_a_stable_diagnostic() {
    TemporaryDirectory directory;
    ControlledStatusPoll poll;
    TraceConfig config{};
    config.package_name = "com.example.runtime";
    config.session.id = "5ae884fd-c3cc-4ae5-be8f-c7219b13c59d";
    TraceGenerationStatusOptions status{};
    status.config = config;
    status.output_directory = directory.path;
    status.poll_wait = StatusPollWait{&poll, &ControlledStatusPoll::wait};
    auto runtime = TraceGenerationRuntime::create(
            40, config.session, TraceGenerationLimits{}, DeadlineWait{},
            std::move(status));
    CHECK(runtime != nullptr);
    const std::string path = directory.path + "/session-" +
                             config.session.id + ".status.json";
    CHECK(runtime->publish_installed_status());
    CHECK(runtime->arm());
    wait_for_count(poll.waits, 1);
    CHECK(read_text(path).find("\"state\":\"running\"") !=
          std::string::npos);
    session_status_test_inject_fault(SessionStatusFaultPoint::FileFsync, EIO);
    runtime.reset();
    const nlohmann::json final = nlohmann::json::parse(read_text(path));
    CHECK(final.at("state") == "running");
    CHECK(final.at("errors").at(0).at("code") ==
          "STATUS_PUBLICATION_FAILED");
}

// Catches a failed status publication being marked published forever. Every
// retry is gated by the 25 ms poll wait; after the fault clears, the first
// retry must include the latched diagnostic without a new runtime transition.
void status_publication_failure_is_exposed_and_retried_without_a_runtime_event() {
    TemporaryDirectory directory;
    ControlledStatusPoll poll;
    TraceConfig config{};
    config.package_name = "com.example.runtime";
    config.session.id = "7d5807cf-cf09-4f21-92de-1ad92802610a";
    TraceGenerationStatusOptions status{};
    status.config = config;
    status.output_directory = directory.path;
    status.poll_wait = StatusPollWait{&poll, &ControlledStatusPoll::wait};
    session_status_test_inject_fault(SessionStatusFaultPoint::FileFsync, EIO);
    auto runtime = TraceGenerationRuntime::create(
            32, config.session, TraceGenerationLimits{}, DeadlineWait{}, std::move(status));
    CHECK(runtime != nullptr);
    CHECK(!runtime->publish_installed_status());
    CHECK(runtime->snapshot().status_error == EIO);
    session_status_test_inject_fault(SessionStatusFaultPoint::FileFsync, EIO);
    CHECK(runtime->arm());
    wait_for_count(poll.waits, 1);
    CHECK(runtime->snapshot().status_error == EIO);
    const std::string path = directory.path + "/session-" + config.session.id + ".status.json";
    CHECK(::access(path.c_str(), F_OK) != 0);

    // A permanent error consumes at most one retry per controlled poll.
    session_status_test_inject_fault(SessionStatusFaultPoint::FileFsync, EIO);
    poll.allow_one();
    wait_for_count(poll.waits, 2);
    CHECK(::access(path.c_str(), F_OK) != 0);
    session_status_test_inject_fault(SessionStatusFaultPoint::None, 0);
    poll.allow_one();
    wait_for_count(poll.waits, 3);
    const std::string recovered = read_text(path);
    CHECK(recovered.find("\"errors\":[{\"code\":\"STATUS_PUBLICATION_FAILED\"") !=
          std::string::npos);
    CHECK(runtime->snapshot().status_error == EIO);
    runtime.reset();
}

// Catches an empty status handoff: Task 5/6 cold-path producers must be able
// to publish bounded artifacts and diagnostics without instruction callbacks.
void status_metadata_producers_publish_artifacts_warnings_and_errors() {
    TemporaryDirectory directory;
    ControlledStatusPoll poll;
    TraceConfig config{};
    config.package_name = "com.example.runtime";
    config.session.id = "7d5807cf-cf09-4f21-92de-1ad92802610a";
    TraceGenerationStatusOptions status{};
    status.config = config;
    status.output_directory = directory.path;
    status.poll_wait = StatusPollWait{&poll, &ControlledStatusPoll::wait};
    auto runtime = TraceGenerationRuntime::create(
            33, config.session, TraceGenerationLimits{}, DeadlineWait{}, std::move(status));
    CHECK(runtime != nullptr);
    CHECK(runtime->arm());
    wait_for_count(poll.waits, 1);
    CHECK(runtime->record_artifact("flight.trace.bin.lz4"));
    CHECK(runtime->record_status_warning("FLIGHT_DEGRADED", "$.flight", "ring wrapped"));
    CHECK(runtime->record_status_error("SEAL_FAILED", "$.seal", "seal deferred"));
    CHECK(!runtime->record_artifact("flight.trace.bin.lz4"));
    for (unsigned int index = 0; index != 128; ++index) {
        const std::string artifact = "artifact" + std::to_string(index) + ".bin";
        if (!runtime->record_artifact(artifact)) break;
    }
    poll.allow_one();
    wait_for_count(poll.waits, 2);
    const std::string path = directory.path + "/session-" + config.session.id + ".status.json";
    const std::string published = read_text(path);
    CHECK(published.find("\"flight.trace.bin.lz4\"") != std::string::npos);
    CHECK(published.find("\"code\":\"FLIGHT_DEGRADED\"") != std::string::npos);
    CHECK(published.find("\"code\":\"SEAL_FAILED\"") != std::string::npos);
    CHECK(published.find("\"code\":\"STATUS_ARTIFACT_DUPLICATE\"") != std::string::npos);
    CHECK(published.find("\"code\":\"STATUS_ARTIFACT_CAPACITY\"") != std::string::npos);
    runtime.reset();
}

// Catches producer diagnostics consuming the warning/error capacity or
// classifying duplicate and invalid inputs as generic metadata overflow.
void status_metadata_producers_deduplicate_and_classify_each_rejection() {
    TemporaryDirectory directory;
    ControlledStatusPoll poll;
    TraceConfig config{};
    config.package_name = "com.example.runtime";
    config.session.id = "7d5807cf-cf09-4f21-92de-1ad92802610a";
    TraceGenerationStatusOptions status{};
    status.config = config;
    status.output_directory = directory.path;
    status.poll_wait = StatusPollWait{&poll, &ControlledStatusPoll::wait};
    auto runtime = TraceGenerationRuntime::create(
            36, config.session, TraceGenerationLimits{}, DeadlineWait{}, std::move(status));
    CHECK(runtime != nullptr);
    CHECK(runtime->arm());
    wait_for_count(poll.waits, 1);

    CHECK(runtime->record_artifact("one.trace"));
    CHECK(!runtime->record_artifact("one.trace"));
    CHECK(!runtime->record_artifact("one.trace"));
    CHECK(!runtime->record_artifact("../invalid.trace"));
    size_t accepted_artifacts = 1;
    for (size_t index = 0; index != 64; ++index) {
        const std::string artifact = "artifact-" + std::to_string(index) + ".trace";
        if (!runtime->record_artifact(artifact)) break;
        ++accepted_artifacts;
    }
    CHECK(!runtime->record_artifact("after-artifact-capacity.trace"));
    CHECK(runtime->record_status_warning("WARN", "$.warning", "one"));
    CHECK(!runtime->record_status_warning("WARN", "$.warning", "one"));
    CHECK(!runtime->record_status_warning("WARN", "$.warning", "one"));
    CHECK(runtime->record_status_error("ERROR", "$.error", "one"));
    CHECK(!runtime->record_status_error("ERROR", "$.error", "one"));
    CHECK(!runtime->record_status_error("ERROR", "$.error", "one"));
    CHECK(!runtime->record_status_warning("", "$.warning", "invalid"));
    CHECK(!runtime->record_status_error("ERROR", "$.error", std::string(129, 'x')));

    size_t accepted_warnings = 1;
    for (size_t index = 0; index != 64; ++index) {
        const std::string message = "warning-" + std::to_string(index);
        if (!runtime->record_status_warning("WARN", "$.warning", message)) break;
        ++accepted_warnings;
    }
    CHECK(!runtime->record_status_warning("WARN", "$.warning", "after-capacity"));

    size_t accepted_errors = 1;
    for (size_t index = 0; index != 64; ++index) {
        const std::string message = "error-" + std::to_string(index);
        if (!runtime->record_status_error("ERROR", "$.error", message)) break;
        ++accepted_errors;
    }
    CHECK(!runtime->record_status_error("ERROR", "$.error", "after-capacity"));

    poll.allow_one();
    wait_for_count(poll.waits, 2);
    const std::string path = directory.path + "/session-" + config.session.id + ".status.json";
    const nlohmann::json published = nlohmann::json::parse(read_text(path));
    CHECK(published.at("artifacts").size() == accepted_artifacts);
    CHECK(published.at("warnings").size() == accepted_warnings);
    size_t actual_error_count = 0;
    size_t artifact_duplicate_count = 0;
    size_t warning_duplicate_count = 0;
    size_t error_duplicate_count = 0;
    size_t artifact_invalid_count = 0;
    size_t artifact_capacity_count = 0;
    size_t warning_invalid_count = 0;
    size_t error_invalid_count = 0;
    size_t warning_capacity_count = 0;
    size_t error_capacity_count = 0;
    for (const nlohmann::json &error : published.at("errors")) {
        const std::string code = error.at("code");
        if (code == "ERROR") ++actual_error_count;
        if (code == "STATUS_ARTIFACT_DUPLICATE") ++artifact_duplicate_count;
        if (code == "STATUS_ARTIFACT_INVALID") ++artifact_invalid_count;
        if (code == "STATUS_ARTIFACT_CAPACITY") ++artifact_capacity_count;
        if (code == "STATUS_WARNING_DUPLICATE") ++warning_duplicate_count;
        if (code == "STATUS_ERROR_DUPLICATE") ++error_duplicate_count;
        if (code == "STATUS_WARNING_INVALID") ++warning_invalid_count;
        if (code == "STATUS_ERROR_INVALID") ++error_invalid_count;
        if (code == "STATUS_WARNING_CAPACITY") ++warning_capacity_count;
        if (code == "STATUS_ERROR_CAPACITY") ++error_capacity_count;
        CHECK(code != "STATUS_METADATA_OVERFLOW");
    }
    CHECK(actual_error_count == accepted_errors);
    CHECK(artifact_duplicate_count == 1);
    CHECK(artifact_invalid_count == 1);
    CHECK(artifact_capacity_count == 1);
    CHECK(warning_duplicate_count == 1);
    CHECK(error_duplicate_count == 1);
    CHECK(warning_invalid_count == 1);
    CHECK(error_invalid_count == 1);
    CHECK(warning_capacity_count == 1);
    CHECK(error_capacity_count == 1);
    runtime.reset();
}

// Catches repeated rejected metadata bumping the transition sequence after its
// stable diagnostic bit already exists. A changed sequence causes the status
// worker to rename a freshly serialized file, which is observable as a new inode.
void repeated_metadata_rejections_do_not_republish_unchanged_status() {
    TemporaryDirectory directory;
    ControlledStatusPoll poll;
    TraceConfig config{};
    config.package_name = "com.example.runtime";
    config.session.id = "7d5807cf-cf09-4f21-92de-1ad92802610a";
    TraceGenerationStatusOptions status{};
    status.config = config;
    status.output_directory = directory.path;
    status.poll_wait = StatusPollWait{&poll, &ControlledStatusPoll::wait};
    auto runtime = TraceGenerationRuntime::create(
            37, config.session, TraceGenerationLimits{}, DeadlineWait{}, std::move(status));
    CHECK(runtime != nullptr);
    CHECK(runtime->arm());
    wait_for_count(poll.waits, 1);
    const std::string path = directory.path + "/session-" + config.session.id + ".status.json";
    unsigned int next_wait = 2;
    const auto publish_transition = [&] {
        const ino_t before = inode_of(path);
        poll.allow_one();
        wait_for_count(poll.waits, next_wait++);
        CHECK(inode_of(path) != before);
    };
    const auto poll_without_transition = [&] {
        const ino_t before = inode_of(path);
        poll.allow_one();
        wait_for_count(poll.waits, next_wait++);
        CHECK(inode_of(path) == before);
    };

    CHECK(runtime->record_artifact("one.trace"));
    CHECK(!runtime->record_artifact("one.trace"));
    publish_transition();
    CHECK(!runtime->record_artifact("one.trace"));
    poll_without_transition();
    CHECK(!runtime->record_artifact("../invalid.trace"));
    publish_transition();
    CHECK(!runtime->record_artifact("../invalid.trace"));
    poll_without_transition();
    for (size_t index = 1; index != 64; ++index) {
        if (!runtime->record_artifact("artifact-" + std::to_string(index) + ".trace")) break;
    }
    publish_transition();
    CHECK(!runtime->record_artifact("artifact-overflow.trace"));
    poll_without_transition();

    CHECK(runtime->record_status_warning("WARN", "$.warning", "one"));
    CHECK(!runtime->record_status_warning("WARN", "$.warning", "one"));
    publish_transition();
    CHECK(!runtime->record_status_warning("WARN", "$.warning", "one"));
    poll_without_transition();
    CHECK(!runtime->record_status_warning("", "$.warning", "invalid"));
    publish_transition();
    CHECK(!runtime->record_status_warning("", "$.warning", "invalid"));
    poll_without_transition();
    for (size_t index = 1; index != 64; ++index) {
        if (!runtime->record_status_warning(
                    "WARN", "$.warning", "warning-" + std::to_string(index))) break;
    }
    publish_transition();
    CHECK(!runtime->record_status_warning("WARN", "$.warning", "warning-overflow"));
    poll_without_transition();

    CHECK(runtime->record_status_error("ERROR", "$.error", "one"));
    CHECK(!runtime->record_status_error("ERROR", "$.error", "one"));
    publish_transition();
    CHECK(!runtime->record_status_error("ERROR", "$.error", "one"));
    poll_without_transition();
    CHECK(!runtime->record_status_error("ERROR", "$.error", std::string(129, 'x')));
    publish_transition();
    CHECK(!runtime->record_status_error("ERROR", "$.error", std::string(129, 'x')));
    poll_without_transition();
    for (size_t index = 1; index != 64; ++index) {
        if (!runtime->record_status_error(
                    "ERROR", "$.error", "error-" + std::to_string(index))) break;
    }
    publish_transition();
    CHECK(!runtime->record_status_error("ERROR", "$.error", "error-overflow"));
    poll_without_transition();
    runtime.reset();
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
    destruction_cancels_a_24_hour_deadline_worker();
    deadline_worker_survives_releasing_the_last_runtime_owner();
    status_worker_survives_releasing_the_last_runtime_owner();
    forked_child_detaches_the_inherited_deadline_worker();
    installed_status_is_published_before_running_worker_state();
    status_worker_failure_preserves_initial_and_final_publication();
    final_status_failure_retries_once_with_a_stable_diagnostic();
    status_publication_failure_is_exposed_and_retried_without_a_runtime_event();
    status_metadata_producers_publish_artifacts_warnings_and_errors();
    status_metadata_producers_deduplicate_and_classify_each_rejection();
    repeated_metadata_rejections_do_not_republish_unchanged_status();
}
