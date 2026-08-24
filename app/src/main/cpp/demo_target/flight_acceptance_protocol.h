#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <type_traits>

constexpr uint32_t kDemoFlightAcceptanceWorkers = 16;
constexpr uint32_t kDemoFlightAcceptanceReady = 2;

struct DemoFlightAcceptanceSnapshot {
    uint64_t generation = 0;
    uint64_t seed = 0;
    uint64_t original_pc = 0;
    uint32_t state = 0;
    uint32_t mode = 0;
    uint32_t selected_worker = 0;
    uint32_t selected_tid = 0;
    uint32_t probe = 0;
    uint32_t rotations = 0;
    uint32_t worker_count = 0;
    uint32_t reserved = 0;
    uint32_t tids[kDemoFlightAcceptanceWorkers]{};
};

static_assert(sizeof(DemoFlightAcceptanceSnapshot) == 120);
static_assert(std::is_standard_layout_v<DemoFlightAcceptanceSnapshot>);
static_assert(offsetof(DemoFlightAcceptanceSnapshot, generation) == 0);
static_assert(offsetof(DemoFlightAcceptanceSnapshot, seed) == 8);
static_assert(offsetof(DemoFlightAcceptanceSnapshot, original_pc) == 16);
static_assert(offsetof(DemoFlightAcceptanceSnapshot, state) == 24);
static_assert(offsetof(DemoFlightAcceptanceSnapshot, mode) == 28);
static_assert(offsetof(DemoFlightAcceptanceSnapshot, selected_worker) == 32);
static_assert(offsetof(DemoFlightAcceptanceSnapshot, selected_tid) == 36);
static_assert(offsetof(DemoFlightAcceptanceSnapshot, probe) == 40);
static_assert(offsetof(DemoFlightAcceptanceSnapshot, rotations) == 44);
static_assert(offsetof(DemoFlightAcceptanceSnapshot, worker_count) == 48);
static_assert(offsetof(DemoFlightAcceptanceSnapshot, tids) == 56);

class FlightAcceptanceProtocol {
  public:
    uint64_t start(uint64_t seed, uint32_t mode,
                   uint32_t selected_worker) noexcept;
    bool publish_ready(uint64_t generation, uint32_t selected_tid,
                       uintptr_t original_pc, uint32_t probe,
                       uint32_t completed_rotations,
                       const uint32_t *tids, size_t tid_count) noexcept;
    bool snapshot(DemoFlightAcceptanceSnapshot *snapshot) noexcept;
    bool release(uint64_t generation) noexcept;
    bool released(uint64_t generation) const noexcept;

  private:
    mutable std::mutex mutex_;
    DemoFlightAcceptanceSnapshot snapshot_{};
    std::atomic<uint64_t> next_generation_{0};
    std::atomic<uint64_t> active_generation_{0};
    std::atomic<uint64_t> published_generation_{0};
    std::atomic<uint64_t> released_generation_{0};
};
