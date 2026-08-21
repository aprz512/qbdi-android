#pragma once

#include "core/trace_config.h"
#include "flight/flight_format.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <pthread.h>

constexpr uint32_t kFlightEmergencyCommitted = 0x80000000U;
constexpr uint32_t kFlightInvalidIndex = UINT32_MAX;

enum class FlightDirectoryState : uint32_t {
    Free = 0,
    Active = 1,
    Rotating = 2,
};

enum class FlightChunkState : uint32_t {
    Free = 0,
    Active = 1,
    Sealed = 2,
};

enum class FlightIncompleteReason : uint32_t {
    None = 0,
    DirectoryExhausted = 1U << 0U,
    ChunkExhausted = 1U << 1U,
    WriterFailure = 1U << 2U,
    EmergencyFailure = 1U << 3U,
};

struct FlightThreadRegistration {
    uint32_t directory_index = kFlightInvalidIndex;
    uint32_t tid = 0;
};

struct FlightChunkLease {
    uint32_t chunk_index = kFlightInvalidIndex;
    uint32_t generation = 0;
    uint32_t tid = 0;
    uint8_t *data = nullptr;
    size_t capacity = 0;

    explicit operator bool() const noexcept {
        return chunk_index != kFlightInvalidIndex && generation != 0 && data != nullptr;
    }
};

struct FlightChunkSnapshot {
    FlightChunkState state = FlightChunkState::Free;
    uint32_t chunk_index = kFlightInvalidIndex;
    uint32_t tid = 0;
    uint32_t generation = 0;
    uint64_t first_sequence = 0;
    uint64_t last_sequence = 0;
    uint32_t committed_bytes = 0;
    uint32_t record_count = 0;
    uint32_t checksum = 0;
};

class FlightSequenceAllocator {
public:
    explicit FlightSequenceAllocator(uint64_t initial = 1) noexcept : next_(initial) {}

    uint64_t next() noexcept {
        uint64_t current = next_.load(std::memory_order_relaxed);
        while (current != 0 && current != UINT64_MAX) {
            if (next_.compare_exchange_weak(current, current + 1U,
                                            std::memory_order_relaxed,
                                            std::memory_order_relaxed)) {
                return current;
            }
        }
        return 0;
    }

    void reset() noexcept { next_.store(1, std::memory_order_relaxed); }

private:
    std::atomic<uint64_t> next_;
};

uint32_t flight_u32_to_le(uint32_t value) noexcept;
bool flight_atomic_u32_aligned(const uint8_t *address) noexcept;
void flight_atomic_store_u32_le(uint8_t *destination, uint32_t value,
                                std::memory_order order) noexcept;
uint32_t flight_atomic_load_u32_le(const uint8_t *source,
                                   std::memory_order order) noexcept;
uint32_t flight_atomic_fetch_or_u32_le(uint8_t *destination, uint32_t value,
                                       std::memory_order order) noexcept;
bool scan_flight_emergency(const uint8_t *bytes,
                           FlightEmergencyRecord *record) noexcept;

class FlightArtifact {
public:
    FlightArtifact() noexcept = default;
    ~FlightArtifact();

    FlightArtifact(const FlightArtifact &) = delete;
    FlightArtifact &operator=(const FlightArtifact &) = delete;

    bool create(const char *path, const FlightOptions &options) noexcept;
    void close() noexcept;
    void detach_after_fork_child() noexcept;

    bool valid() const noexcept { return mapping_ != nullptr; }
    int fd() const noexcept { return fd_; }
    uint8_t *bytes() noexcept { return mapping_; }
    const uint8_t *bytes() const noexcept { return mapping_; }
    size_t size() const noexcept { return mapping_size_; }
    uint32_t chunk_count() const noexcept { return chunk_count_; }
    uint32_t chunk_data_capacity() const noexcept;

    bool register_thread(uint32_t tid, FlightThreadRegistration *registration) noexcept;
    bool acquire_chunk(const FlightThreadRegistration &registration, uint64_t first_sequence,
                       FlightChunkLease *lease) noexcept;

    void mark_incomplete(FlightIncompleteReason reason) noexcept;
    bool incomplete() const noexcept { return flags() != 0; }
    uint32_t flags() const noexcept;

    bool write_emergency(const FlightThreadRegistration &registration,
                         const FlightEmergencyRecord &record) noexcept;
    bool write_emergency(uint32_t slot_index,
                         const FlightEmergencyRecord &record) noexcept;
    const uint8_t *emergency_bytes(uint32_t directory_index) const noexcept;

    const uint8_t *chunk_data(uint32_t chunk_index) const noexcept;
    uint8_t *chunk_data(uint32_t chunk_index) noexcept;
    uint32_t chunk_generation(uint32_t chunk_index) const noexcept;
    uint32_t chunk_tid(uint32_t chunk_index) const noexcept;
    bool chunk_is_protected(uint32_t chunk_index) const noexcept;
    bool read_chunk(uint32_t chunk_index, FlightChunkSnapshot *snapshot) const noexcept;

    uint64_t next_sequence() noexcept;
    bool publish_thread_sequence(const FlightThreadRegistration &registration,
                                 const FlightChunkLease &lease, uint64_t first_sequence,
                                 uint64_t last_sequence) noexcept;
    bool seal_chunk(const FlightChunkLease &lease, uint64_t first_sequence,
                    uint64_t last_sequence, uint32_t committed_bytes,
                    uint32_t record_count, uint32_t checksum) noexcept;

private:
    struct RuntimeChunkMetadata;
    struct RuntimeThreadMetadata;
    struct RuntimeEmergencyMetadata;

    uint8_t *directory_entry(uint32_t index) noexcept;
    const uint8_t *directory_entry(uint32_t index) const noexcept;
    uint8_t *chunk(uint32_t index) noexcept;
    const uint8_t *chunk(uint32_t index) const noexcept;
    void publish_exhaustion(uint32_t tid, uint32_t slot_index,
                            FlightIncompleteReason reason) noexcept;
    void reset_state() noexcept;

    int fd_ = -1;
    uint8_t *mapping_ = nullptr;
    size_t mapping_size_ = 0;
    void *runtime_mapping_ = nullptr;
    size_t runtime_mapping_size_ = 0;
    RuntimeChunkMetadata *chunk_metadata_ = nullptr;
    RuntimeThreadMetadata *thread_metadata_ = nullptr;
    RuntimeEmergencyMetadata *emergency_metadata_ = nullptr;
    FlightOptions options_{};
    uint64_t directory_offset_ = 0;
    uint64_t emergency_offset_ = 0;
    uint32_t emergency_record_count_ = 0;
    uint64_t chunk_offset_ = 0;
    uint32_t chunk_count_ = 0;
    uint64_t allocation_epoch_ = 0;
    FlightSequenceAllocator sequence_allocator_{};
    pthread_mutex_t rotation_mutex_ = PTHREAD_MUTEX_INITIALIZER;
};
