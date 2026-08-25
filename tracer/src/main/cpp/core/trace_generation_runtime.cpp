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
                                               DeadlineWait wait) noexcept
        : generation_(generation), session_(std::move(session)), wait_(wait),
          owner_pid_(::getpid()) {}

TraceGenerationRuntime::~TraceGenerationRuntime() {
    join_deadline();
}

std::shared_ptr<TraceGenerationRuntime> TraceGenerationRuntime::create(
        uint64_t generation, SessionOptions session, DeadlineWait wait) noexcept {
    TraceGenerationRuntime *runtime = new (std::nothrow)
            TraceGenerationRuntime(generation, std::move(session), wait);
    if (runtime == nullptr) return {};
    return std::shared_ptr<TraceGenerationRuntime>(runtime);
}

bool TraceGenerationRuntime::arm() noexcept {
    bool expected = false;
    if (!armed_.compare_exchange_strong(expected, true, std::memory_order_acq_rel,
                                        std::memory_order_acquire)) {
        return phase_.load(std::memory_order_acquire) != TraceGenerationPhase::StopIncomplete;
    }

    TraceGenerationPhase waiting = TraceGenerationPhase::Waiting;
    if (!phase_.compare_exchange_strong(waiting, TraceGenerationPhase::Running,
                                        std::memory_order_acq_rel,
                                        std::memory_order_acquire)) {
        return false;
    }
    if (!session_.timed()) return true;

    const uint64_t now = monotonic_now_ns();
    const uint64_t duration = session_.duration_ms;
    if (now == 0 || duration > std::numeric_limits<uint64_t>::max() / kNanosecondsPerMillisecond ||
        now > std::numeric_limits<uint64_t>::max() - duration * kNanosecondsPerMillisecond) {
        phase_.store(TraceGenerationPhase::StopIncomplete, std::memory_order_release);
        return false;
    }
    const uint64_t deadline = now + duration * kNanosecondsPerMillisecond;
    deadline_monotonic_ns_ = deadline;
    const int error = ::pthread_create(&deadline_thread_, nullptr, &TraceGenerationRuntime::deadline_entry,
                                       this);
    if (error != 0) {
        phase_.store(TraceGenerationPhase::StopIncomplete, std::memory_order_release);
        return false;
    }
    deadline_thread_started_.store(true, std::memory_order_release);
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
    TraceGenerationPhase running = TraceGenerationPhase::Running;
    if (phase_.compare_exchange_strong(running, TraceGenerationPhase::StopRequested,
                                       std::memory_order_acq_rel,
                                       std::memory_order_acquire)) {
        stop_token_.request(TraceStopReason::DurationElapsed);
        complete_stop_if_idle();
    }
}

bool TraceGenerationRuntime::try_begin_call(size_t scene_index, uint32_t tid) noexcept {
    if (phase_.load(std::memory_order_acquire) != TraceGenerationPhase::Running) return false;
    pending_admissions_.fetch_add(1, std::memory_order_acq_rel);
    if (phase_.load(std::memory_order_acquire) != TraceGenerationPhase::Running) {
        pending_admissions_.fetch_sub(1, std::memory_order_acq_rel);
        complete_stop_if_idle();
        return false;
    }

    bool admitted = false;
    {
        std::lock_guard<std::mutex> lock(active_mutex_);
        // This is the admission linearization point. The deadline may have
        // published StopRequested after the optimistic check above, but it
        // cannot seal while pending_admissions_ still protects this decision.
        if (phase_.load(std::memory_order_acquire) == TraceGenerationPhase::Running) {
            bool duplicate = false;
            for (size_t index = 0; index < active_size_; ++index) {
                if (active_calls_[index].scene_index == scene_index &&
                    active_calls_[index].tid == tid) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate && active_size_ < active_calls_.size()) {
                active_calls_[active_size_++] = ActiveCall{scene_index, tid};
                active_count_.fetch_add(1, std::memory_order_release);
                admitted = true;
            }
        }
    }
    pending_admissions_.fetch_sub(1, std::memory_order_acq_rel);
    complete_stop_if_idle();
    return admitted;
}

void TraceGenerationRuntime::finish_call(size_t scene_index, uint32_t tid, bool sealed) noexcept {
    complete_call(scene_index, tid, sealed);
}

void TraceGenerationRuntime::acknowledge_sealed(size_t scene_index, uint32_t tid) noexcept {
    complete_call(scene_index, tid, true);
}

void TraceGenerationRuntime::complete_call(size_t scene_index, uint32_t tid, bool sealed) noexcept {
    bool removed = false;
    {
        std::lock_guard<std::mutex> lock(active_mutex_);
        for (size_t index = 0; index < active_size_; ++index) {
            if (active_calls_[index].scene_index != scene_index || active_calls_[index].tid != tid) continue;
            active_calls_[index] = active_calls_[active_size_ - 1];
            --active_size_;
            active_count_.fetch_sub(1, std::memory_order_release);
            removed = true;
            break;
        }
    }
    if (!removed) return;

    const TraceGenerationPhase phase = phase_.load(std::memory_order_acquire);
    if (is_stopping(phase)) {
        if (!sealed) stop_incomplete_.store(true, std::memory_order_release);
        TraceGenerationPhase requested = TraceGenerationPhase::StopRequested;
        (void)phase_.compare_exchange_strong(requested, TraceGenerationPhase::Stopping,
                                             std::memory_order_acq_rel,
                                             std::memory_order_acquire);
        complete_stop_if_idle();
    }
}

void TraceGenerationRuntime::complete_stop_if_idle() noexcept {
    if (active_count_.load(std::memory_order_acquire) != 0 ||
        pending_admissions_.load(std::memory_order_acquire) != 0) {
        return;
    }
    TraceGenerationPhase phase = phase_.load(std::memory_order_acquire);
    while (is_stopping(phase)) {
        const TraceGenerationPhase terminal = stop_incomplete_.load(std::memory_order_acquire)
                                                      ? TraceGenerationPhase::StopIncomplete
                                                      : TraceGenerationPhase::Sealed;
        if (phase_.compare_exchange_weak(phase, terminal, std::memory_order_acq_rel,
                                         std::memory_order_acquire)) {
            return;
        }
    }
}

const TraceStopToken &TraceGenerationRuntime::stop_token() const noexcept {
    return stop_token_;
}

TraceGenerationSnapshot TraceGenerationRuntime::snapshot() const noexcept {
    return TraceGenerationSnapshot{
            generation_,
            phase_.load(std::memory_order_acquire),
            active_count_.load(std::memory_order_acquire),
            detached_.load(std::memory_order_acquire),
    };
}

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
