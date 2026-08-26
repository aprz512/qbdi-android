#pragma once

#include "core/session_status.h"
#include "core/trace_config.h"
#include "events/binary_trace_format.h"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <pthread.h>
#include <string>
#include <string_view>
#include <sys/types.h>

enum class TraceGenerationPhase : uint8_t {
    Waiting,
    Running,
    StopRequested,
    Stopping,
    Sealed,
    StopIncomplete,
};

struct TraceGenerationSnapshot {
    uint64_t generation = 0;
    TraceGenerationPhase phase = TraceGenerationPhase::Waiting;
    size_t active_calls = 0;
    bool detached = false;
    int status_error = 0;
};

struct TraceGenerationLimits {
    size_t max_scenes = 256;
    uint32_t flight_max_threads = 256;
};

enum class TraceAdmissionStatus : uint8_t {
    Admitted,
    NotRunning,
    Duplicate,
    ActiveSessionLimit,
    WrongGeneration,
};

struct TraceAdmission {
    uint64_t generation = 0;
    size_t scene_index = 0;
    uint32_t tid = 0;
    uint64_t serial = 0;
};

struct TraceAdmissionResult {
    TraceAdmissionStatus status = TraceAdmissionStatus::NotRunning;
    TraceAdmission admission{};
};

class TraceStopToken final {
public:
    bool requested() const noexcept {
        return requested_.load(std::memory_order_acquire);
    }
    TraceStopReason reason() const noexcept {
        return static_cast<TraceStopReason>(
                reason_.load(std::memory_order_acquire));
    }

#if defined(QTRACE_HOST_TEST)
    void request_for_test(TraceStopReason reason) noexcept { request(reason); }
#endif

private:
    friend class TraceGenerationRuntime;

    void request(TraceStopReason reason) noexcept {
        reason_.store(static_cast<uint8_t>(reason), std::memory_order_relaxed);
        requested_.store(true, std::memory_order_release);
    }

    std::atomic<bool> requested_{false};
    std::atomic<uint8_t> reason_{0};
};

struct DeadlineWait {
    void *opaque = nullptr;
    void (*wait_until)(void *opaque, uint64_t deadline_monotonic_ns,
                       const std::atomic<bool> *stop) noexcept = nullptr;
};

struct StatusPollWait {
    void *opaque = nullptr;
    void (*wait)(void *opaque, const std::atomic<bool> *stop) noexcept = nullptr;
};

struct TraceGenerationStatusOptions {
    TraceConfig config;
    std::string output_directory;
    StatusPollWait poll_wait{};

    bool enabled() const noexcept { return config.session.enabled(); }
};

#if defined(QTRACE_HOST_TEST)
struct TraceGenerationTestHooks {
    void *opaque = nullptr;
    void (*after_active_removal)(void *opaque) noexcept = nullptr;
    void (*before_deadline_stop_lock)(void *opaque) noexcept = nullptr;
    void (*after_arm_enters_arming)(void *opaque) noexcept = nullptr;
    bool (*fail_clock_read)(void *opaque) noexcept = nullptr;
    bool (*fail_thread_create)(void *opaque) noexcept = nullptr;
};
#endif

class TraceGenerationRuntime final {
public:
    static std::shared_ptr<TraceGenerationRuntime> create(
            uint64_t generation, SessionOptions session, DeadlineWait wait = {}) noexcept;
    static std::shared_ptr<TraceGenerationRuntime> create(
            uint64_t generation, SessionOptions session, TraceGenerationLimits limits,
            DeadlineWait wait = {}, TraceGenerationStatusOptions status = {}) noexcept;

    ~TraceGenerationRuntime();

    TraceGenerationRuntime(const TraceGenerationRuntime &) = delete;
    TraceGenerationRuntime &operator=(const TraceGenerationRuntime &) = delete;

    bool arm() noexcept;
    bool request_stop(TraceStopReason reason) noexcept;
    TraceAdmissionResult try_begin_call(
            uint64_t generation, size_t scene_index, uint32_t tid) noexcept;
    void finish_call(const TraceAdmission &admission, bool sealed) noexcept;
    void acknowledge_sealed(const TraceAdmission &admission) noexcept;
    // Cold-path producer API for installation/sealing code. These calls may
    // lock and copy metadata and are forbidden from instruction callbacks.
    bool record_artifact(std::string_view artifact_basename) noexcept;
    bool record_status_warning(std::string_view code, std::string_view path,
                               std::string_view message) noexcept;
    bool record_status_error(std::string_view code, std::string_view path,
                             std::string_view message) noexcept;
    // Stable lifecycle producers may encounter the same generation-wide
    // failure in more than one invocation. Suppress an exact repeat without
    // manufacturing a STATUS_ERROR_DUPLICATE diagnostic.
    bool record_status_error_once(std::string_view code, std::string_view path,
                                  std::string_view message) noexcept;
    const TraceStopToken &stop_token() const noexcept;
    TraceGenerationSnapshot snapshot() const noexcept;

    // Call only in a post-fork child. It drops inherited pthread ownership;
    // child destruction must never join a worker created by its parent.
    void detach_after_fork_child() noexcept;

    // The public production lifecycle joins in the destructor. This narrow
    // hook makes deterministic injected-wait tests able to observe the worker.
    void join_deadline_for_test() noexcept;

#if defined(QTRACE_HOST_TEST)
    void set_test_hooks(TraceGenerationTestHooks hooks) noexcept;
#endif

private:
    enum class ArmState : uint8_t { Unarmed, Arming, Armed, Failed };

    struct ActiveCall {
        size_t scene_index = 0;
        uint32_t tid = 0;
        uint64_t serial = 0;
    };
    struct DeadlineWorkerContext;
    struct StatusWorkerContext;
    struct DeadlineThreadStart;
    struct StatusThreadStart;
    enum class StatusMetadataDiagnostic : uint8_t {
        ArtifactInvalid,
        ArtifactDuplicate,
        ArtifactCapacity,
        WarningInvalid,
        WarningDuplicate,
        WarningCapacity,
        ErrorInvalid,
        ErrorDuplicate,
        ErrorCapacity,
    };

    // The planner bounds configuration at 256 scenes and 1024 flight threads.
    // Fixed storage keeps instruction callbacks allocation-free; active_capacity_
    // applies the actual configuration limit at runtime.
    static constexpr size_t kMaxScenes = 256;
    static constexpr size_t kMaxFlightThreads = 1024;
    static constexpr size_t kMaxActiveCalls = kMaxScenes + kMaxFlightThreads;

    TraceGenerationRuntime(uint64_t generation, SessionOptions session,
                           TraceGenerationLimits limits, DeadlineWait wait,
                           TraceGenerationStatusOptions status) noexcept;

    static void *deadline_entry(void *opaque) noexcept;
    static void *status_entry(void *opaque) noexcept;
    static void monotonic_wait_until(void *opaque, uint64_t deadline_monotonic_ns,
                                     const std::atomic<bool> *stop) noexcept;
    static void status_poll_wait(void *opaque, const std::atomic<bool> *stop) noexcept;
    void request_deadline_stop() noexcept;
    void publish_deadline_stop_locked() noexcept;
    void complete_stop_if_idle_locked() noexcept;
    void complete_call_locked(const TraceAdmission &admission, bool sealed) noexcept;
    void join_deadline() noexcept;
    void start_status() noexcept;
    void join_status() noexcept;
    void publish_status_loop(StatusWorkerContext *context) noexcept;
    SessionStatusSnapshot status_snapshot() const;
    bool record_status_issue(bool warning, std::string_view code,
                             std::string_view path, std::string_view message,
                             bool diagnose_duplicate = true) noexcept;
    bool record_metadata_diagnostic_locked(StatusMetadataDiagnostic diagnostic) noexcept;
    void note_transition() noexcept;

    uint64_t generation_ = 0;
    SessionOptions session_;
    DeadlineWait wait_;
    std::atomic<TraceGenerationPhase> phase_{TraceGenerationPhase::Waiting};
    TraceStopToken stop_token_;
    std::atomic<bool> deadline_pending_{false};
    std::atomic<bool> stop_incomplete_{false};
    mutable std::mutex active_mutex_;
    std::array<ActiveCall, kMaxActiveCalls> active_calls_{};
    size_t active_size_ = 0;
    size_t active_capacity_ = 0;
    uint64_t next_admission_serial_ = 1;
    // Bound producer-owned data so it cannot independently exhaust the
    // publisher's fixed JSON serialization budget.
    static constexpr size_t kMaxStatusArtifacts = 16;
    static constexpr size_t kMaxStatusIssues = 8;
    static constexpr size_t kMaxStatusTextBytes = 128;
    mutable std::mutex status_metadata_mutex_;
    std::vector<std::string> status_artifacts_;
    std::vector<ConfigurationIssue> status_warnings_;
    std::vector<ConfigurationIssue> status_errors_;
    uint16_t status_metadata_diagnostics_ = 0;
    pthread_t deadline_thread_{};
    std::atomic<bool> deadline_thread_started_{false};
    std::shared_ptr<DeadlineWorkerContext> deadline_context_;
    uint64_t deadline_monotonic_ns_ = 0;
    std::atomic<ArmState> arm_state_{ArmState::Unarmed};
    std::atomic<bool> detached_{false};
    TraceGenerationStatusOptions status_options_;
    SessionStatusPublisher status_publisher_;
    std::atomic<bool> status_enabled_{false};
    std::atomic<bool> status_thread_started_{false};
    std::atomic<uint64_t> transition_sequence_{1};
    std::atomic<int> status_error_{0};
    pthread_t status_thread_{};
    std::shared_ptr<StatusWorkerContext> status_context_;
    pid_t owner_pid_ = 0;

#if defined(QTRACE_HOST_TEST)
    TraceGenerationTestHooks test_hooks_{};
#endif
};
