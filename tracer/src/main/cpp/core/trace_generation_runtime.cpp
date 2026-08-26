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

struct TraceGenerationRuntime::DeadlineWorkerContext {
    std::atomic<bool> stop{false};
    std::atomic<TraceGenerationRuntime *> runtime{nullptr};
    DeadlineWait wait{};
    uint64_t deadline_monotonic_ns = 0;
};

struct TraceGenerationRuntime::StatusWorkerContext {
    std::atomic<bool> stop{false};
    std::atomic<TraceGenerationRuntime *> runtime{nullptr};
    StatusPollWait wait{};
};

struct TraceGenerationRuntime::DeadlineThreadStart {
    std::shared_ptr<DeadlineWorkerContext> context;
};

struct TraceGenerationRuntime::StatusThreadStart {
    std::shared_ptr<StatusWorkerContext> context;
};

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
                                               DeadlineWait wait,
                                               TraceGenerationStatusOptions status) noexcept
        : generation_(generation), session_(std::move(session)), wait_(wait),
          active_capacity_(limits.max_scenes + limits.flight_max_threads),
          status_options_(std::move(status)), owner_pid_(::getpid()) {
    if (!status_options_.enabled()) return;
    if (status_options_.config.session.id != session_.id ||
        !status_publisher_.open(status_options_.config, generation_, status_options_.output_directory)) {
        status_error_.store(status_publisher_.error_code() == 0 ? EINVAL : status_publisher_.error_code(),
                            std::memory_order_release);
        return;
    }
    status_enabled_.store(true, std::memory_order_release);
}

TraceGenerationRuntime::~TraceGenerationRuntime() {
    join_deadline();
    join_status();
}

std::shared_ptr<TraceGenerationRuntime> TraceGenerationRuntime::create(
        uint64_t generation, SessionOptions session, DeadlineWait wait) noexcept {
    return create(generation, std::move(session), TraceGenerationLimits{}, wait, {});
}

std::shared_ptr<TraceGenerationRuntime> TraceGenerationRuntime::create(
        uint64_t generation, SessionOptions session, TraceGenerationLimits limits,
        DeadlineWait wait, TraceGenerationStatusOptions status) noexcept {
    if (limits.max_scenes > kMaxScenes || limits.flight_max_threads > kMaxFlightThreads ||
        limits.max_scenes + limits.flight_max_threads == 0) {
        return {};
    }
    TraceGenerationRuntime *runtime = new (std::nothrow)
            TraceGenerationRuntime(generation, std::move(session), limits, wait, std::move(status));
    if (runtime == nullptr) return {};
    // Under the project-wide -fno-exceptions policy std::shared_ptr has no
    // portable control-block OOM return path. tracer_entry uses the same fatal
    // policy, so this first-object allocation check is intentionally not a
    // claim that every shared_ptr allocation failure is recoverable.
    runtime->start_status();
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
            note_transition();
            arm_state_.store(ArmState::Failed, std::memory_order_release);
            return false;
        }
        deadline_monotonic_ns_ = now + duration * kNanosecondsPerMillisecond;
        int error = 0;
        deadline_context_ = std::shared_ptr<DeadlineWorkerContext>(
                new (std::nothrow) DeadlineWorkerContext{});
        if (deadline_context_ == nullptr) {
            error = ENOMEM;
        } else {
            deadline_context_->runtime.store(this, std::memory_order_release);
            deadline_context_->wait = wait_;
            deadline_context_->deadline_monotonic_ns = deadline_monotonic_ns_;
        }
        DeadlineThreadStart *start = error == 0
                ? new (std::nothrow) DeadlineThreadStart{deadline_context_}
                : nullptr;
        if (error == 0 && start == nullptr) error = ENOMEM;
#if defined(QTRACE_HOST_TEST)
        if (error == 0 && test_hooks_.fail_thread_create != nullptr &&
            test_hooks_.fail_thread_create(test_hooks_.opaque)) {
            error = EAGAIN;
        }
#endif
        if (error == 0) {
            error = ::pthread_create(&deadline_thread_, nullptr,
                                     &TraceGenerationRuntime::deadline_entry, start);
        }
        if (error != 0) delete start;
        if (error != 0) {
            std::lock_guard<std::mutex> lock(active_mutex_);
            phase_.store(TraceGenerationPhase::StopIncomplete, std::memory_order_release);
            note_transition();
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
        note_transition();
        publish_deadline_stop_locked();
        complete_stop_if_idle_locked();
    }
    arm_state_.store(ArmState::Armed, std::memory_order_release);
    return true;
}

void *TraceGenerationRuntime::deadline_entry(void *opaque) noexcept {
    std::unique_ptr<DeadlineThreadStart> start(static_cast<DeadlineThreadStart *>(opaque));
    std::shared_ptr<DeadlineWorkerContext> context = std::move(start->context);
    DeadlineWait wait = context->wait;
    if (wait.wait_until == nullptr) wait = DeadlineWait{nullptr, &monotonic_wait_until};
    wait.wait_until(wait.opaque, context->deadline_monotonic_ns, &context->stop);
    if (context->stop.load(std::memory_order_acquire)) return nullptr;
    TraceGenerationRuntime *runtime = context->runtime.load(std::memory_order_acquire);
    if (runtime != nullptr && !context->stop.load(std::memory_order_acquire))
        runtime->request_deadline_stop();
    return nullptr;
}

void TraceGenerationRuntime::monotonic_wait_until(
        void *, uint64_t deadline_monotonic_ns, const std::atomic<bool> *stop) noexcept {
    while (!stop->load(std::memory_order_acquire)) {
        const uint64_t now = monotonic_now_ns();
        if (now == 0 || now >= deadline_monotonic_ns) return;
        constexpr uint64_t kCancellationPollNanoseconds = 25ULL * kNanosecondsPerMillisecond;
        const uint64_t wakeup = deadline_monotonic_ns - now > kCancellationPollNanoseconds
                                        ? now + kCancellationPollNanoseconds
                                        : deadline_monotonic_ns;
        const timespec absolute_wakeup{
                static_cast<time_t>(wakeup / kNanosecondsPerSecond),
                static_cast<long>(wakeup % kNanosecondsPerSecond),
        };
        int error = 0;
        do {
            error = ::clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &absolute_wakeup, nullptr);
        } while (error == EINTR && !stop->load(std::memory_order_acquire));
        if (error != 0 && error != EINTR) return;
    }
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
    note_transition();
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
    note_transition();
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

bool TraceGenerationRuntime::record_artifact(std::string_view artifact_basename) noexcept {
    std::lock_guard<std::mutex> lock(status_metadata_mutex_);
    if (!session_status_artifact_basename_is_valid(artifact_basename) ||
        !session_status_string_is_valid_utf8(artifact_basename)) {
        record_metadata_error_locked("STATUS_ARTIFACT_INVALID", "$.artifacts",
                                     "artifact must be a UTF-8 basename");
        note_transition();
        return false;
    }
    for (const std::string &artifact : status_artifacts_) {
        if (artifact == artifact_basename) {
            record_metadata_error_locked("STATUS_ARTIFACT_DUPLICATE", "$.artifacts",
                                         "artifact was already recorded");
            note_transition();
            return false;
        }
    }
    if (status_artifacts_.size() >= kMaxStatusArtifacts) {
        status_metadata_overflow_ = true;
        note_transition();
        return false;
    }
    status_artifacts_.emplace_back(artifact_basename);
    note_transition();
    return true;
}

bool TraceGenerationRuntime::record_status_warning(
        std::string_view code, std::string_view path, std::string_view message) noexcept {
    return record_status_issue(true, code, path, message);
}

bool TraceGenerationRuntime::record_status_error(
        std::string_view code, std::string_view path, std::string_view message) noexcept {
    return record_status_issue(false, code, path, message);
}

void TraceGenerationRuntime::record_metadata_error_locked(
        std::string_view code, std::string_view path, std::string_view message) noexcept {
    if (status_errors_.size() >= kMaxStatusIssues) {
        status_metadata_overflow_ = true;
        return;
    }
    status_errors_.push_back(ConfigurationIssue{std::string(code), std::string(path),
                                                std::string(message)});
}

bool TraceGenerationRuntime::record_status_issue(
        bool warning, std::string_view code, std::string_view path, std::string_view message) noexcept {
    std::lock_guard<std::mutex> lock(status_metadata_mutex_);
    if (code.empty() || path.empty() || !session_status_string_is_valid_utf8(code) ||
        !session_status_string_is_valid_utf8(path) || !session_status_string_is_valid_utf8(message)) {
        status_metadata_overflow_ = true;
        note_transition();
        return false;
    }
    if (code.size() > kMaxStatusTextBytes || path.size() > kMaxStatusTextBytes ||
        message.size() > kMaxStatusTextBytes) {
        status_metadata_overflow_ = true;
        note_transition();
        return false;
    }
    std::vector<ConfigurationIssue> &issues = warning ? status_warnings_ : status_errors_;
    if (issues.size() >= kMaxStatusIssues) {
        status_metadata_overflow_ = true;
        note_transition();
        return false;
    }
    issues.push_back(ConfigurationIssue{std::string(code), std::string(path), std::string(message)});
    note_transition();
    return true;
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
    note_transition();
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
        if (phase == TraceGenerationPhase::StopRequested) {
            phase_.store(TraceGenerationPhase::Stopping, std::memory_order_release);
            note_transition();
        }
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
    note_transition();
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
            status_error_.load(std::memory_order_acquire),
    };
}

void TraceGenerationRuntime::note_transition() noexcept {
    transition_sequence_.fetch_add(1, std::memory_order_release);
}

void *TraceGenerationRuntime::status_entry(void *opaque) noexcept {
    std::unique_ptr<StatusThreadStart> start(static_cast<StatusThreadStart *>(opaque));
    std::shared_ptr<StatusWorkerContext> context = std::move(start->context);
    TraceGenerationRuntime *runtime = context->runtime.load(std::memory_order_acquire);
    if (runtime != nullptr && !context->stop.load(std::memory_order_acquire))
        runtime->publish_status_loop(context.get());
    return nullptr;
}

void TraceGenerationRuntime::status_poll_wait(void *, const std::atomic<bool> *) noexcept {
    constexpr long kStatusPollNanoseconds = 25L * 1000L * 1000L;
    const timespec interval{0, kStatusPollNanoseconds};
    int error = 0;
    do {
        error = ::clock_nanosleep(CLOCK_MONOTONIC, 0, &interval, nullptr);
    } while (error == EINTR);
}

void TraceGenerationRuntime::start_status() noexcept {
    if (!status_enabled_.load(std::memory_order_acquire)) return;
    status_context_ = std::shared_ptr<StatusWorkerContext>(new (std::nothrow) StatusWorkerContext{});
    if (status_context_ == nullptr) {
        status_enabled_.store(false, std::memory_order_release);
        status_error_.store(ENOMEM, std::memory_order_release);
        return;
    }
    status_context_->runtime.store(this, std::memory_order_release);
    status_context_->wait = status_options_.poll_wait;
    auto *start = new (std::nothrow) StatusThreadStart{status_context_};
    if (start == nullptr) {
        status_enabled_.store(false, std::memory_order_release);
        status_error_.store(ENOMEM, std::memory_order_release);
        return;
    }
    const int error = ::pthread_create(&status_thread_, nullptr,
                                       &TraceGenerationRuntime::status_entry, start);
    if (error != 0) {
        delete start;
        status_enabled_.store(false, std::memory_order_release);
        status_error_.store(error, std::memory_order_release);
        return;
    }
    status_thread_started_.store(true, std::memory_order_release);
}

void TraceGenerationRuntime::join_status() noexcept {
    if (detached_.load(std::memory_order_acquire) || ::getpid() != owner_pid_) return;
    if (status_context_ != nullptr) {
        status_context_->runtime.store(nullptr, std::memory_order_release);
        status_context_->stop.store(true, std::memory_order_release);
    }
    bool started = true;
    if (!status_thread_started_.compare_exchange_strong(started, false, std::memory_order_acq_rel,
                                                        std::memory_order_acquire)) return;
    if (::pthread_equal(::pthread_self(), status_thread_)) {
        (void)::pthread_detach(status_thread_);
        return;
    }
    (void)::pthread_join(status_thread_, nullptr);
}

SessionStatusSnapshot TraceGenerationRuntime::status_snapshot() const {
    SessionStatusSnapshot snapshot{};
    snapshot.session_id = status_options_.config.session.id;
    snapshot.generation = generation_;
    snapshot.package = status_options_.config.package_name;
    snapshot.pid = static_cast<uint32_t>(::getpid());
    snapshot.transition_monotonic_ns = monotonic_now_ns();
    const TraceGenerationPhase phase = phase_.load(std::memory_order_acquire);
    switch (phase) {
        case TraceGenerationPhase::Waiting: snapshot.state = "installed"; break;
        case TraceGenerationPhase::Running: snapshot.state = "running"; break;
        case TraceGenerationPhase::StopRequested: snapshot.state = "stop_requested"; break;
        case TraceGenerationPhase::Stopping: snapshot.state = "stopping"; break;
        case TraceGenerationPhase::Sealed: snapshot.state = "sealed"; break;
        case TraceGenerationPhase::StopIncomplete: snapshot.state = "stop_incomplete"; break;
    }
    if (stop_token_.requested() && stop_token_.reason() == TraceStopReason::DurationElapsed)
        snapshot.reason = "duration_elapsed";
    snapshot.stop_acknowledged = phase == TraceGenerationPhase::Sealed ||
                                 phase == TraceGenerationPhase::StopIncomplete;
    for (const SceneConfig &scene : status_options_.config.scenes) {
        snapshot.normalized_scenes.push_back(ResolvedSceneStatus{
                scene.name, static_cast<uint64_t>(scene.offset), static_cast<uint64_t>(scene.end_offset)});
    }
    {
        std::lock_guard<std::mutex> lock(active_mutex_);
        for (size_t index = 0; index < active_size_; ++index) {
            snapshot.active_scenes.push_back(SessionActiveScene{
                    active_calls_[index].scene_index, active_calls_[index].tid, false});
        }
    }
    {
        std::lock_guard<std::mutex> lock(status_metadata_mutex_);
        snapshot.artifacts = status_artifacts_;
        snapshot.warnings = status_warnings_;
        snapshot.errors = status_errors_;
        if (status_metadata_overflow_) {
            snapshot.errors.push_back(ConfigurationIssue{
                    "STATUS_METADATA_OVERFLOW", "$.status", "status metadata capacity exceeded"});
        }
    }
    const int error = status_error_.load(std::memory_order_acquire);
    if (error != 0) {
        snapshot.errors.push_back(ConfigurationIssue{
                "STATUS_PUBLICATION_FAILED", "$.status", "status publication error"});
    }
    return snapshot;
}

void TraceGenerationRuntime::publish_status_loop(StatusWorkerContext *context) noexcept {
    uint64_t published_sequence = 0;
    StatusPollWait wait = context->wait;
    if (wait.wait == nullptr) wait = StatusPollWait{nullptr, &status_poll_wait};
    while (!context->stop.load(std::memory_order_acquire)) {
        const uint64_t transition = transition_sequence_.load(std::memory_order_acquire);
        if (transition != published_sequence) {
            const SessionStatusSnapshot snapshot = status_snapshot();
            if (!status_publisher_.publish(snapshot)) {
                int expected = 0;
                const int error = status_publisher_.error_code() == 0
                                      ? EIO
                                      : status_publisher_.error_code();
                (void)status_error_.compare_exchange_strong(
                        expected, error, std::memory_order_acq_rel, std::memory_order_acquire);
                // Do not lose the failure behind published_sequence. Scheduling one
                // successor keeps retries bounded by the 25 ms poll wait and lets a
                // recovered publication serialize the latched error without a new
                // callback-side transition.
                note_transition();
            }
            published_sequence = transition;
        }
        if (!context->stop.load(std::memory_order_acquire)) wait.wait(wait.opaque, &context->stop);
        if (context->stop.load(std::memory_order_acquire) ||
            context->runtime.load(std::memory_order_acquire) == nullptr) return;
    }
}

#if defined(QTRACE_HOST_TEST)
void TraceGenerationRuntime::set_test_hooks(TraceGenerationTestHooks hooks) noexcept {
    std::lock_guard<std::mutex> lock(active_mutex_);
    test_hooks_ = hooks;
}
#endif

void TraceGenerationRuntime::detach_after_fork_child() noexcept {
    detached_.store(true, std::memory_order_release);
    if (deadline_context_ != nullptr) {
        deadline_context_->runtime.store(nullptr, std::memory_order_release);
        deadline_context_->stop.store(true, std::memory_order_release);
    }
    deadline_thread_started_.store(false, std::memory_order_release);
    if (status_context_ != nullptr) {
        status_context_->runtime.store(nullptr, std::memory_order_release);
        status_context_->stop.store(true, std::memory_order_release);
    }
    status_thread_started_.store(false, std::memory_order_release);
}

void TraceGenerationRuntime::join_deadline_for_test() noexcept {
    if (detached_.load(std::memory_order_acquire) || ::getpid() != owner_pid_) return;
    bool started = true;
    if (!deadline_thread_started_.compare_exchange_strong(started, false, std::memory_order_acq_rel,
                                                          std::memory_order_acquire)) return;
    (void)::pthread_join(deadline_thread_, nullptr);
}

void TraceGenerationRuntime::join_deadline() noexcept {
    if (detached_.load(std::memory_order_acquire) || ::getpid() != owner_pid_) return;
    if (deadline_context_ != nullptr) {
        deadline_context_->runtime.store(nullptr, std::memory_order_release);
        deadline_context_->stop.store(true, std::memory_order_release);
    }
    bool started = true;
    if (!deadline_thread_started_.compare_exchange_strong(started, false, std::memory_order_acq_rel,
                                                          std::memory_order_acquire)) {
        return;
    }
    if (::pthread_equal(::pthread_self(), deadline_thread_)) {
        (void)::pthread_detach(deadline_thread_);
        return;
    }
    (void)::pthread_join(deadline_thread_, nullptr);
}
