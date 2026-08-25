#include "core/trace_generation_runtime.h"

#include <cerrno>
#include <ctime>
#include <limits>
#include <new>
#include <unistd.h>

namespace {

constexpr uint64_t kNanosecondsPerMillisecond = 1000000ULL;
constexpr uint64_t kNanosecondsPerSecond = 1000000000ULL;

uint64_t monotonic_now_ns() noexcept {
    timespec now{};
    if (::clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return static_cast<uint64_t>(now.tv_sec) * kNanosecondsPerSecond +
           static_cast<uint64_t>(now.tv_nsec);
}

bool is_stopping(TraceGenerationPhase phase) noexcept {
    return phase == TraceGenerationPhase::StopRequested ||
           phase == TraceGenerationPhase::Stopping;
}

} // namespace

bool TraceStopToken::requested() const noexcept {
    return requested_.load(std::memory_order_acquire);
}

TraceStopReason TraceStopToken::reason() const noexcept {
    return static_cast<TraceStopReason>(reason_.load(std::memory_order_acquire));
}

void TraceStopToken::request(TraceStopReason reason) noexcept {
    reason_.store(static_cast<uint8_t>(reason), std::memory_order_relaxed);
    requested_.store(true, std::memory_order_release);
}

TraceGenerationRuntime::TraceGenerationRuntime(uint64_t generation, SessionOptions session,
                                               TraceGenerationLimits limits,
                                               DeadlineWait wait) noexcept
        : generation_(generation), session_(std::move(session)), wait_(wait),
          active_capacity_(limits.max_scenes + limits.flight_max_threads), owner_pid_(::getpid()) {}

TraceGenerationRuntime::~TraceGenerationRuntime() {
    join_deadline();
}

std::shared_ptr<TraceGenerationRuntime> TraceGenerationRuntime::create(
        uint64_t generation, SessionOptions session, DeadlineWait wait) noexcept {
    return create(generation, std::move(session), TraceGenerationLimits{}, wait);
}

std::shared_ptr<TraceGenerationRuntime> TraceGenerationRuntime::create(
        uint64_t generation, SessionOptions session, TraceGenerationLimits limits,
        DeadlineWait wait) noexcept {
    if (limits.max_scenes > kMaxScenes || limits.flight_max_threads > kMaxFlightThreads ||
        limits.max_scenes + limits.flight_max_threads == 0) {
        return {};
    }
    TraceGenerationRuntime *runtime = new (std::nothrow)
            TraceGenerationRuntime(generation, std::move(session), limits, wait);
    if (runtime == nullptr) return {};
    // Under the project-wide -fno-exceptions policy std::shared_ptr has no
    // portable control-block OOM return path. tracer_entry uses the same fatal
    // policy, so this first-object allocation check is intentionally not a
    // claim that every shared_ptr allocation failure is recoverable.
    return std::shared_ptr<TraceGenerationRuntime>(runtime);
}

bool TraceGenerationRuntime::arm() noexcept {
    ArmState expected = ArmState::Unarmed;
    if (!arm_state_.compare_exchange_strong(expected, ArmState::Arming, std::memory_order_acq_rel,
                                            std::memory_order_acquire)) {
        return expected == ArmState::Armed;
    }
#if defined(QTRACE_HOST_TEST)
    if (test_hooks_.after_arm_enters_arming != nullptr)
        test_hooks_.after_arm_enters_arming(test_hooks_.opaque);
#endif

    if (session_.timed()) {
        uint64_t now = monotonic_now_ns();
#if defined(QTRACE_HOST_TEST)
        if (test_hooks_.fail_clock_read != nullptr &&
            test_hooks_.fail_clock_read(test_hooks_.opaque)) {
            now = 0;
        }
#endif
        const uint64_t duration = session_.duration_ms;
        if (now == 0 || duration > std::numeric_limits<uint64_t>::max() / kNanosecondsPerMillisecond ||
            now > std::numeric_limits<uint64_t>::max() - duration * kNanosecondsPerMillisecond) {
            std::lock_guard<std::mutex> lock(active_mutex_);
            phase_.store(TraceGenerationPhase::StopIncomplete, std::memory_order_release);
            arm_state_.store(ArmState::Failed, std::memory_order_release);
            return false;
        }
        deadline_monotonic_ns_ = now + duration * kNanosecondsPerMillisecond;
        int error = 0;
#if defined(QTRACE_HOST_TEST)
        if (test_hooks_.fail_thread_create != nullptr &&
            test_hooks_.fail_thread_create(test_hooks_.opaque)) {
            error = EAGAIN;
        } else
#endif
        {
            error = ::pthread_create(&deadline_thread_, nullptr,
                                     &TraceGenerationRuntime::deadline_entry, this);
        }
        if (error != 0) {
            std::lock_guard<std::mutex> lock(active_mutex_);
            phase_.store(TraceGenerationPhase::StopIncomplete, std::memory_order_release);
            arm_state_.store(ArmState::Failed, std::memory_order_release);
            return false;
        }
        deadline_thread_started_.store(true, std::memory_order_release);
    }
    {
        std::lock_guard<std::mutex> lock(active_mutex_);
        TraceGenerationPhase waiting = TraceGenerationPhase::Waiting;
        if (!phase_.compare_exchange_strong(waiting, TraceGenerationPhase::Running,
                                            std::memory_order_acq_rel,
                                            std::memory_order_acquire)) {
            return false;
        }
        publish_deadline_stop_locked();
        complete_stop_if_idle_locked();
    }
    arm_state_.store(ArmState::Armed, std::memory_order_release);
    return true;
}

void *TraceGenerationRuntime::deadline_entry(void *opaque) noexcept {
    auto *runtime = static_cast<TraceGenerationRuntime *>(opaque);
    DeadlineWait wait = runtime->wait_;
    if (wait.wait_until == nullptr) wait = DeadlineWait{nullptr, &monotonic_wait_until};
    wait.wait_until(wait.opaque, runtime->deadline_monotonic_ns_);
    runtime->request_deadline_stop();
    return nullptr;
}

void TraceGenerationRuntime::monotonic_wait_until(void *, uint64_t deadline_monotonic_ns) noexcept {
    timespec deadline{
            static_cast<time_t>(deadline_monotonic_ns / kNanosecondsPerSecond),
            static_cast<long>(deadline_monotonic_ns % kNanosecondsPerSecond),
    };
    int error = 0;
    do {
        error = ::clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, nullptr);
    } while (error == EINTR);
}

void TraceGenerationRuntime::request_deadline_stop() noexcept {
    deadline_pending_.store(true, std::memory_order_release);
#if defined(QTRACE_HOST_TEST)
    if (test_hooks_.before_deadline_stop_lock != nullptr)
        test_hooks_.before_deadline_stop_lock(test_hooks_.opaque);
#endif
    std::lock_guard<std::mutex> lock(active_mutex_);
    publish_deadline_stop_locked();
    complete_stop_if_idle_locked();
}

void TraceGenerationRuntime::publish_deadline_stop_locked() noexcept {
    if (!deadline_pending_.load(std::memory_order_acquire)) return;
    if (phase_.load(std::memory_order_acquire) != TraceGenerationPhase::Running) return;
    stop_token_.request(TraceStopReason::DurationElapsed);
    phase_.store(TraceGenerationPhase::StopRequested, std::memory_order_release);
}

TraceAdmissionResult TraceGenerationRuntime::try_begin_call(
        uint64_t generation, size_t scene_index, uint32_t tid) noexcept {
    std::lock_guard<std::mutex> lock(active_mutex_);
    if (generation != generation_) return {TraceAdmissionStatus::WrongGeneration, {}};
    publish_deadline_stop_locked();
    if (phase_.load(std::memory_order_acquire) != TraceGenerationPhase::Running) {
        complete_stop_if_idle_locked();
        return {TraceAdmissionStatus::NotRunning, {}};
    }
    for (size_t index = 0; index < active_size_; ++index) {
        if (active_calls_[index].scene_index == scene_index && active_calls_[index].tid == tid)
            return {TraceAdmissionStatus::Duplicate, {}};
    }
    if (active_size_ >= active_capacity_)
        return {TraceAdmissionStatus::ActiveSessionLimit, {}};
    const TraceAdmission admission{generation_, scene_index, tid, next_admission_serial_++};
    active_calls_[active_size_++] = ActiveCall{scene_index, tid, admission.serial};
    return {TraceAdmissionStatus::Admitted, admission};
}

void TraceGenerationRuntime::finish_call(const TraceAdmission &admission, bool sealed) noexcept {
    std::lock_guard<std::mutex> lock(active_mutex_);
    complete_call_locked(admission, sealed);
}

void TraceGenerationRuntime::acknowledge_sealed(const TraceAdmission &admission) noexcept {
    std::lock_guard<std::mutex> lock(active_mutex_);
    complete_call_locked(admission, true);
}

void TraceGenerationRuntime::complete_call_locked(const TraceAdmission &admission, bool sealed) noexcept {
    publish_deadline_stop_locked();
    if (admission.generation != generation_ || admission.serial == 0) {
        return;
    }
    size_t index = active_size_;
    for (size_t candidate = 0; candidate < active_size_; ++candidate) {
        if (active_calls_[candidate].scene_index == admission.scene_index &&
            active_calls_[candidate].tid == admission.tid &&
            active_calls_[candidate].serial == admission.serial) {
            index = candidate;
            break;
        }
    }
    if (index == active_size_) return;
    active_calls_[index] = active_calls_[active_size_ - 1];
    --active_size_;
#if defined(QTRACE_HOST_TEST)
    if (test_hooks_.after_active_removal != nullptr)
        test_hooks_.after_active_removal(test_hooks_.opaque);
#endif
    // The deadline may become pending while this owner holds active_mutex_.
    // Re-observe it before selecting the terminal outcome for the removed call.
    publish_deadline_stop_locked();
    const TraceGenerationPhase phase = phase_.load(std::memory_order_acquire);
    if (is_stopping(phase)) {
        if (!sealed) stop_incomplete_.store(true, std::memory_order_release);
        if (phase == TraceGenerationPhase::StopRequested)
            phase_.store(TraceGenerationPhase::Stopping, std::memory_order_release);
        complete_stop_if_idle_locked();
    }
}

void TraceGenerationRuntime::complete_stop_if_idle_locked() noexcept {
    if (active_size_ != 0) return;
    const TraceGenerationPhase phase = phase_.load(std::memory_order_acquire);
    if (!is_stopping(phase)) return;
    phase_.store(stop_incomplete_.load(std::memory_order_acquire)
                         ? TraceGenerationPhase::StopIncomplete
                         : TraceGenerationPhase::Sealed,
                 std::memory_order_release);
}

const TraceStopToken &TraceGenerationRuntime::stop_token() const noexcept {
    return stop_token_;
}

TraceGenerationSnapshot TraceGenerationRuntime::snapshot() const noexcept {
    std::lock_guard<std::mutex> lock(active_mutex_);
    return TraceGenerationSnapshot{
            generation_,
            phase_.load(std::memory_order_acquire),
            active_size_,
            detached_.load(std::memory_order_acquire),
    };
}

#if defined(QTRACE_HOST_TEST)
void TraceGenerationRuntime::set_test_hooks(TraceGenerationTestHooks hooks) noexcept {
    std::lock_guard<std::mutex> lock(active_mutex_);
    test_hooks_ = hooks;
}
#endif

void TraceGenerationRuntime::detach_after_fork_child() noexcept {
    detached_.store(true, std::memory_order_release);
    deadline_thread_started_.store(false, std::memory_order_release);
}

void TraceGenerationRuntime::join_deadline_for_test() noexcept {
    join_deadline();
}

void TraceGenerationRuntime::join_deadline() noexcept {
    if (detached_.load(std::memory_order_acquire) || ::getpid() != owner_pid_) return;
    bool started = true;
    if (!deadline_thread_started_.compare_exchange_strong(started, false, std::memory_order_acq_rel,
                                                          std::memory_order_acquire)) {
        return;
    }
    (void)::pthread_join(deadline_thread_, nullptr);
}
