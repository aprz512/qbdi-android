#pragma once

#include "core/module_maps.h"
#include "core/trace_config.h"
#include "core/trace_generation_runtime.h"
#include "flight/flight_format.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>

class QbdiThreadSession;
struct ThreadExecutionControl {
    uintptr_t execution_entry = 0;
    uintptr_t control_start = 0;
    size_t control_bytes = 0;
    std::shared_ptr<const void> owner;
};
using CaptureThreadStartResolver =
        bool (*)(void *opaque, uintptr_t logical_entry,
                 ThreadExecutionControl *control) noexcept;

enum class CoverageGapReason : uint32_t {
    SessionFailure = 1,
    HookSetup = 2,
    NativeBypass = 3,
    ModuleGeneration = 4,
    Reconfiguration = 5,
    GatewayUnavailable = 6,
    ThreadStartAllocation = 7,
    ThreadCreate = 8,
    ThreadAbnormalExit = 9,
    RetirementCapacity = 10,
};

struct CaptureCoordinatorFactories {
    void *opaque = nullptr;
    void *(*create_artifact)(void *opaque, const char *path,
                             const FlightOptions &options,
                             const FlightArtifactIdentityView &identity) noexcept = nullptr;
    void (*destroy_artifact)(void *opaque, void *artifact) noexcept = nullptr;
    QbdiThreadSession *(*create_session)(
            void *opaque, void *artifact, const TraceConfig &config,
            const ModuleRange &module, const SceneConfig &scene, uint32_t tid,
            uint32_t module_generation) noexcept = nullptr;
    void (*destroy_session)(void *opaque,
                            QbdiThreadSession *session) noexcept = nullptr;
    void (*mark_coverage_gap)(void *opaque, void *artifact, uint32_t tid,
                              uintptr_t pc, CoverageGapReason reason) noexcept = nullptr;
};

class CaptureCoordinator final
        : public std::enable_shared_from_this<CaptureCoordinator> {
public:
    explicit CaptureCoordinator(CaptureCoordinatorFactories factories = {}) noexcept;
    ~CaptureCoordinator();

    CaptureCoordinator(const CaptureCoordinator &) = delete;
    CaptureCoordinator &operator=(const CaptureCoordinator &) = delete;

    // With a runtime, the coordinator is the sole admission owner for each
    // persistent Flight slot. Task 6's proxy gate must skip Flight calls;
    // normal captures continue to own their proxy admission there.
    bool start(TraceConfig config, ModuleRange module,
               uint32_t module_generation,
               std::shared_ptr<TraceGenerationRuntime> runtime = {});
    bool request_stop(TraceStopReason reason) noexcept;
    // Called by the native timeout/status owner after its acknowledgement
    // deadline. It retires only runtime admissions; live sessions and writers
    // remain owned by their target threads and are never sealed here.
    bool report_stop_incomplete() noexcept;
    QbdiThreadSession *enter(uint32_t tid, const SceneConfig &scene) noexcept;
    QbdiThreadSession *enter_thread(uint32_t tid, uintptr_t entry) noexcept;
    void leave(QbdiThreadSession *session) noexcept;
    void finish_thread(QbdiThreadSession *session,
                       bool retain_active_session = false) noexcept;
    void mark_coverage_gap(
            uint32_t tid, uintptr_t pc,
            CoverageGapReason reason = CoverageGapReason::SessionFailure) noexcept;
    void detach_after_fork_child() noexcept;

    bool started() const noexcept {
        return started_.load(std::memory_order_acquire);
    }
    bool incomplete() const noexcept {
        return incomplete_.load(std::memory_order_acquire);
    }
    bool detached() const noexcept {
        return detached_.load(std::memory_order_acquire);
    }
    uint64_t run_id() const noexcept {
        return run_id_.load(std::memory_order_acquire);
    }
    uint32_t module_generation() const noexcept {
        return module_generation_.load(std::memory_order_acquire);
    }
    uint64_t dropped_gap_count() const noexcept {
        return dropped_gap_count_.load(std::memory_order_acquire);
    }
    bool copy_module(ModuleRange *module) const;
    bool matches_module(const ModuleRange &module) const noexcept;
    bool contains_target_address(uintptr_t address) const noexcept;
    void set_thread_start_resolver(CaptureThreadStartResolver resolver,
                                   void *opaque) noexcept;
    bool resolve_thread_start(uintptr_t logical_entry,
                              ThreadExecutionControl *control) const noexcept;

private:
    struct ThreadSlot {
        CaptureCoordinator *owner = nullptr;
        uint32_t tid = 0;
        QbdiThreadSession *session = nullptr;
        // Exact generation/scene/TID/serial admission owned by this slot.
        TraceAdmission admission{};
        bool stop_finished = false;
    };

    void mark_coverage_gap_locked(uint32_t tid, uintptr_t pc,
                                  CoverageGapReason reason) noexcept;
    ThreadSlot *find_slot_locked(uint32_t tid) noexcept;
    QbdiThreadSession *enter_locked(uint32_t tid, const SceneConfig &scene,
                                    uintptr_t pc) noexcept;
    static void report_session_gap(void *opaque, uint32_t tid,
                                   uintptr_t pc) noexcept;
    static bool seal_flight_slot(void *opaque,
                                 TraceStopReason reason) noexcept;
    static void acknowledge_flight_slot(void *opaque, bool sealed) noexcept;
    static void publish_flight_slot_committed(void *opaque) noexcept;
    void acknowledge_flight_slot_locked(ThreadSlot *slot,
                                        bool sealed) noexcept;
    void publish_committed_artifact_locked(ThreadSlot *slot) noexcept;
    bool stop_requested_locked() noexcept;

    CaptureCoordinatorFactories factories_{};
    mutable std::mutex mutex_;
    TraceConfig config_{};
    ModuleRange module_{};
    ThreadSlot *slots_ = nullptr;
    void *artifact_ = nullptr;
    std::shared_ptr<TraceGenerationRuntime> runtime_;
    size_t slot_count_ = 0;
    uint64_t runtime_generation_ = 0;
    std::atomic<uint64_t> run_id_{0};
    std::atomic<uint32_t> module_generation_{0};
    std::atomic<bool> incomplete_{false};
    std::atomic<bool> detached_{false};
    std::atomic<uint64_t> dropped_gap_count_{0};
    std::atomic<CaptureThreadStartResolver> thread_start_resolver_{nullptr};
    std::atomic<void *> thread_start_resolver_opaque_{nullptr};
    uint64_t coverage_gap_count_ = 0;
    bool stop_requested_ = false;
    bool stop_incomplete_reported_ = false;
    bool artifact_recorded_ = false;
    bool start_attempted_ = false;
    std::atomic<bool> started_{false};
};
