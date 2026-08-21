#pragma once

#include "flight/flight_artifact.h"

#include <cstddef>
#include <cstdint>
#include <span>

struct FlightDecodedRecord {
    FlightRecordType type = FlightRecordType::ChunkBegin;
    uint16_t flags = 0;
    uint32_t total_bytes = 0;
    uint32_t storage_bytes = 0;
    uint64_t sequence = 0;
    const uint8_t *payload = nullptr;
    size_t payload_bytes = 0;
};

uint32_t flight_checksum32(const uint8_t *bytes, size_t size) noexcept;
bool scan_flight_record(const uint8_t *bytes, size_t available, uint32_t generation,
                        FlightDecodedRecord *record) noexcept;

class FlightChunkWriter {
public:
    FlightChunkWriter() noexcept = default;
    ~FlightChunkWriter() = default;

    FlightChunkWriter(const FlightChunkWriter &) = delete;
    FlightChunkWriter &operator=(const FlightChunkWriter &) = delete;

    bool initialize(FlightArtifact *artifact,
                    const FlightThreadRegistration &registration) noexcept;
    bool append(FlightRecordType type, std::span<const uint8_t> payload,
                uint16_t flags = 0) noexcept;
    bool seal() noexcept;
    bool rotate() noexcept;
    void detach() noexcept;

    bool active() const noexcept { return artifact_ != nullptr && static_cast<bool>(lease_); }
    uint32_t chunk_index() const noexcept { return lease_.chunk_index; }
    uint32_t generation() const noexcept { return lease_.generation; }
    uint32_t committed_bytes() const noexcept { return committed_extent_; }
    uint32_t record_count() const noexcept { return record_count_; }

    const uint8_t *active_bytes() const noexcept { return interrupted_record_; }
    size_t active_size() const noexcept { return interrupted_record_size_; }
    const uint8_t *previous_record_bytes() const noexcept { return previous_record_; }
    uint8_t *mutable_previous_record_bytes() noexcept { return previous_record_; }
    size_t previous_record_size() const noexcept { return previous_record_size_; }

    // Host-test fault injection: leaves one syntactically complete record unpublished.
    void test_interrupt_before_commit() noexcept;

private:
    bool write_record(FlightRecordType type, std::span<const uint8_t> payload,
                      uint16_t flags, bool publish) noexcept;
    void reset_chunk_state() noexcept;

    FlightArtifact *artifact_ = nullptr;
    FlightThreadRegistration registration_{};
    FlightChunkLease lease_{};
    uint32_t write_offset_ = 0;
    uint32_t committed_extent_ = 0;
    uint32_t record_count_ = 0;
    uint64_t first_sequence_ = 0;
    uint64_t last_sequence_ = 0;
    uint8_t *previous_record_ = nullptr;
    size_t previous_record_size_ = 0;
    uint8_t *interrupted_record_ = nullptr;
    size_t interrupted_record_size_ = 0;
    bool sealed_ = false;
};
