#pragma once

#include "core/trace_config.h"
#include "events/binary_trace_format.h"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <pthread.h>
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
};

class TraceStopToken final {
public:
    bool requested() const noexcept;
    TraceStopReason reason() const noexcept;

private:
    friend class TraceGenerationRuntime;

    void request(TraceStopReason reason) noexcept;

    std::atomic<bool> requested_{false};
    std::atomic<uint8_t> reason_{0};
};

struct DeadlineWait {
    void *opaque = nullptr;
    void (*wait_until)(void *opaque, uint64_t deadline_monotonic_ns) noexcept = nullptr;
};

class TraceGenerationRuntime final {
public:
    static std::shared_ptr<TraceGenerationRuntime> create(
            uint64_t generation, SessionOptions session, DeadlineWait wait = {}) noexcept;

    ~TraceGenerationRuntime();

    TraceGenerationRuntime(const TraceGenerationRuntime &) = delete;
    TraceGenerationRuntime &operator=(const TraceGenerationRuntime &) = delete;

    bool arm() noexcept;
    bool try_begin_call(size_t scene_index, uint32_t tid) noexcept;
    void finish_call(size_t scene_index, uint32_t tid, bool sealed) noexcept;
    void acknowledge_sealed(size_t scene_index, uint32_t tid) noexcept;
    const TraceStopToken &stop_token() const noexcept;
    TraceGenerationSnapshot snapshot() const noexcept;

    // Call only in a post-fork child. It drops inherited pthread ownership;
    // child destruction must never join a worker created by its parent.
    void detach_after_fork_child() noexcept;

    // The public production lifecycle joins in the destructor. This narrow
    // hook makes deterministic injected-wait tests able to observe the worker.
    void join_deadline_for_test() noexcept;

private:
    struct ActiveCall {
        size_t scene_index = 0;
        uint32_t tid = 0;
    };

    // 256 configured scenes plus the default maximum number of flight threads.
    // This is fixed storage so entry/finish cannot allocate in a callback.
    static constexpr size_t kMaxActiveCalls = 512;

    TraceGenerationRuntime(uint64_t generation, SessionOptions session,
                           DeadlineWait wait) noexcept;

    static void *deadline_entry(void *opaque) noexcept;
    static void monotonic_wait_until(void *opaque, uint64_t deadline_monotonic_ns) noexcept;
    void request_deadline_stop() noexcept;
    void complete_stop_if_idle() noexcept;
    void complete_call(size_t scene_index, uint32_t tid, bool sealed) noexcept;
    void join_deadline() noexcept;

    uint64_t generation_ = 0;
    SessionOptions session_;
    DeadlineWait wait_;
    std::atomic<TraceGenerationPhase> phase_{TraceGenerationPhase::Waiting};
    TraceStopToken stop_token_;
    std::atomic<size_t> active_count_{0};
    std::atomic<size_t> pending_admissions_{0};
    std::atomic<bool> stop_incomplete_{false};
    std::mutex active_mutex_;
    std::array<ActiveCall, kMaxActiveCalls> active_calls_{};
    size_t active_size_ = 0;
    pthread_t deadline_thread_{};
    std::atomic<bool> deadline_thread_started_{false};
    uint64_t deadline_monotonic_ns_ = 0;
    std::atomic<bool> armed_{false};
    std::atomic<bool> detached_{false};
    pid_t owner_pid_ = 0;
};
