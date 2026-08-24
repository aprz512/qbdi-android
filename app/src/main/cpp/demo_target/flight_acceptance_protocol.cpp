#include "flight_acceptance_protocol.h"

#include <cstring>

uint64_t FlightAcceptanceProtocol::start(uint64_t seed, uint32_t mode,
                                         uint32_t selected_worker) noexcept {
    if (mode > 4 || selected_worker >= kDemoFlightAcceptanceWorkers ||
        (mode == 4 && selected_worker != 0)) {
        return 0;
    }
    uint64_t generation = next_generation_.fetch_add(1, std::memory_order_relaxed) + 1;
    if (generation == 0) return 0;
    std::lock_guard<std::mutex> guard(mutex_);
    published_generation_.store(0, std::memory_order_relaxed);
    released_generation_.store(0, std::memory_order_relaxed);
    snapshot_ = {};
    snapshot_.generation = generation;
    snapshot_.seed = seed;
    snapshot_.mode = mode;
    snapshot_.selected_worker = selected_worker;
    active_generation_.store(generation, std::memory_order_release);
    return generation;
}

bool FlightAcceptanceProtocol::publish_ready(
        uint64_t generation, uint32_t selected_tid, uintptr_t original_pc,
        uint32_t probe, uint32_t completed_rotations,
        const uint32_t *tids, size_t tid_count) noexcept {
    if (generation == 0 || completed_rotations == 0 || tids == nullptr ||
        tid_count != kDemoFlightAcceptanceWorkers ||
        active_generation_.load(std::memory_order_acquire) != generation) {
        return false;
    }
    std::lock_guard<std::mutex> guard(mutex_);
    if (active_generation_.load(std::memory_order_relaxed) != generation ||
        snapshot_.generation != generation ||
        published_generation_.load(std::memory_order_relaxed) != 0) {
        return false;
    }
    const bool external = snapshot_.mode == 4;
    if ((external && (selected_tid != 0 || original_pc != 0)) ||
        (!external && (selected_tid == 0 || original_pc == 0))) {
        return false;
    }
    snapshot_.original_pc = original_pc;
    snapshot_.selected_tid = selected_tid;
    snapshot_.probe = probe;
    snapshot_.rotations = completed_rotations;
    snapshot_.worker_count = kDemoFlightAcceptanceWorkers;
    std::memcpy(snapshot_.tids, tids, sizeof(snapshot_.tids));
    snapshot_.state = kDemoFlightAcceptanceReady;
    published_generation_.store(generation, std::memory_order_release);
    return true;
}

bool FlightAcceptanceProtocol::snapshot(
        DemoFlightAcceptanceSnapshot *snapshot) noexcept {
    if (snapshot == nullptr) return false;
    const uint64_t published = published_generation_.load(std::memory_order_acquire);
    if (published == 0) return false;
    std::lock_guard<std::mutex> guard(mutex_);
    if (published_generation_.load(std::memory_order_relaxed) != published ||
        snapshot_.generation != published) {
        return false;
    }
    *snapshot = snapshot_;
    return true;
}

bool FlightAcceptanceProtocol::release(uint64_t generation) noexcept {
    if (generation == 0 ||
        active_generation_.load(std::memory_order_acquire) != generation ||
        published_generation_.load(std::memory_order_acquire) != generation) {
        return false;
    }
    released_generation_.store(generation, std::memory_order_release);
    return true;
}

bool FlightAcceptanceProtocol::released(uint64_t generation) const noexcept {
    return generation != 0 &&
           released_generation_.load(std::memory_order_acquire) == generation;
}
