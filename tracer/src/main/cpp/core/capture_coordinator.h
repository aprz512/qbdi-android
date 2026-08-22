#pragma once

#include "core/module_maps.h"
#include "core/trace_config.h"
#include "flight/flight_format.h"

#include <atomic>
#include <cstdint>
#include <mutex>

class QbdiThreadSession;

enum class CoverageGapReason : uint32_t {
    SessionFailure = 1,
    HookSetup = 2,
    NativeBypass = 3,
    ModuleGeneration = 4,
    Reconfiguration = 5,
    GatewayUnavailable = 6,
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

class CaptureCoordinator final {
public:
    explicit CaptureCoordinator(CaptureCoordinatorFactories factories = {}) noexcept;
    ~CaptureCoordinator();

    CaptureCoordinator(const CaptureCoordinator &) = delete;
    CaptureCoordinator &operator=(const CaptureCoordinator &) = delete;

    bool start(TraceConfig config, ModuleRange module,
               uint32_t module_generation);
    QbdiThreadSession *enter(uint32_t tid, const SceneConfig &scene) noexcept;
    void leave(QbdiThreadSession *session) noexcept;
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
    bool copy_module(ModuleRange *module) const;
    bool matches_module(const ModuleRange &module) const noexcept;

private:
    struct ThreadSlot {
        uint32_t tid = 0;
        QbdiThreadSession *session = nullptr;
    };

    void mark_coverage_gap_locked(uint32_t tid, uintptr_t pc,
                                  CoverageGapReason reason) noexcept;
    ThreadSlot *find_slot_locked(uint32_t tid) noexcept;
    static void report_session_gap(void *opaque, uint32_t tid,
                                   uintptr_t pc) noexcept;

    CaptureCoordinatorFactories factories_{};
    mutable std::mutex mutex_;
    TraceConfig config_{};
    ModuleRange module_{};
    ThreadSlot *slots_ = nullptr;
    void *artifact_ = nullptr;
    size_t slot_count_ = 0;
    std::atomic<uint64_t> run_id_{0};
    std::atomic<uint32_t> module_generation_{0};
    std::atomic<bool> incomplete_{false};
    std::atomic<bool> detached_{false};
    bool start_attempted_ = false;
    std::atomic<bool> started_{false};
};
