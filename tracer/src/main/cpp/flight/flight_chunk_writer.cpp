#include "flight/flight_chunk_writer.h"

#include <cstring>

namespace {

constexpr uint32_t kRecordAlignment = 8;
constexpr uint32_t kFnvOffsetBasis = 2166136261U;
constexpr uint32_t kFnvPrime = 16777619U;

bool checked_record_sizes(size_t payload_size, uint32_t *total,
                          uint32_t *storage) noexcept {
    if (total == nullptr || storage == nullptr ||
        payload_size > UINT32_MAX - kFlightRecordHeaderBytes) {
        return false;
    }
    const uint32_t exact =
            static_cast<uint32_t>(kFlightRecordHeaderBytes + payload_size);
    if (exact > UINT32_MAX - (kRecordAlignment - 1U)) return false;
    *total = exact;
    *storage = (exact + (kRecordAlignment - 1U)) & ~(kRecordAlignment - 1U);
    return true;
}

uint32_t checksum_update(uint32_t checksum, const uint8_t *bytes, size_t size) noexcept {
    for (size_t index = 0; index < size; ++index) {
        checksum ^= bytes[index];
        checksum *= kFnvPrime;
    }
    return checksum;
}

uint32_t record_checksum(const uint8_t *record, uint32_t total_bytes) noexcept {
    uint32_t checksum = checksum_update(kFnvOffsetBasis, record, 16);
    return checksum_update(checksum, record + kFlightRecordHeaderBytes,
                           total_bytes - kFlightRecordHeaderBytes);
}

bool valid_record_type(uint16_t type) noexcept {
    return type >= static_cast<uint16_t>(FlightRecordType::ChunkBegin) &&
           type <= static_cast<uint16_t>(FlightRecordType::CoverageGap);
}

} // namespace

uint32_t flight_checksum32(const uint8_t *bytes, size_t size) noexcept {
    if (bytes == nullptr && size != 0) return 0;
    return checksum_update(kFnvOffsetBasis, bytes, size);
}

bool scan_flight_record(const uint8_t *bytes, size_t available, uint32_t generation,
                        FlightDecodedRecord *record) noexcept {
    if (bytes == nullptr || record == nullptr || available < kFlightRecordHeaderBytes ||
        generation == 0 || !flight_atomic_u32_aligned(bytes + 20)) {
        return false;
    }
    const uint16_t type = flight_read_u16_le(bytes + 0);
    const uint16_t flags = flight_read_u16_le(bytes + 2);
    const uint32_t total_bytes = flight_read_u32_le(bytes + 4);
    uint32_t checked_total = 0;
    uint32_t storage_bytes = 0;
    if (!valid_record_type(type) || total_bytes < kFlightRecordHeaderBytes ||
        !checked_record_sizes(total_bytes - kFlightRecordHeaderBytes, &checked_total,
                              &storage_bytes) ||
        checked_total != total_bytes || total_bytes > available || storage_bytes > available) {
        return false;
    }
    const uint32_t expected_commit = kFlightRecordCommit ^ total_bytes ^ generation;
    if (flight_atomic_load_u32_le(bytes + 20, std::memory_order_acquire) != expected_commit) {
        return false;
    }
    if (flight_read_u32_le(bytes + 16) != record_checksum(bytes, total_bytes)) return false;
    record->type = static_cast<FlightRecordType>(type);
    record->flags = flags;
    record->total_bytes = total_bytes;
    record->storage_bytes = storage_bytes;
    record->sequence = flight_read_u64_le(bytes + 8);
    record->payload = bytes + kFlightRecordHeaderBytes;
    record->payload_bytes = total_bytes - kFlightRecordHeaderBytes;
    return true;
}

bool FlightChunkWriter::initialize(FlightArtifact *artifact,
                                   const FlightThreadRegistration &registration) noexcept {
    if (active() || artifact == nullptr || !artifact->valid()) return false;
    FlightChunkLease lease{};
    if (!artifact->acquire_chunk(registration, 0, &lease)) return false;
    artifact_ = artifact;
    registration_ = registration;
    lease_ = lease;
    reset_chunk_state();
    return true;
}

bool FlightChunkWriter::append(FlightRecordType type, std::span<const uint8_t> payload,
                               uint16_t flags) noexcept {
    return write_record(type, payload, flags, true);
}

bool FlightChunkWriter::write_record(FlightRecordType type, std::span<const uint8_t> payload,
                                     uint16_t flags, bool publish) noexcept {
    const uint16_t encoded_type = static_cast<uint16_t>(type);
    uint32_t total_bytes = 0;
    uint32_t storage_bytes = 0;
    if (!active() || sealed_ || interrupted_record_ != nullptr ||
        !valid_record_type(encoded_type) ||
        (payload.data() == nullptr && !payload.empty()) ||
        !checked_record_sizes(payload.size(), &total_bytes, &storage_bytes) ||
        storage_bytes > lease_.capacity - write_offset_) {
        return false;
    }
    const uint64_t sequence = artifact_->next_sequence();
    if (sequence == 0) return false;
    uint8_t *destination = lease_.data + write_offset_;
    std::memset(destination, 0, storage_bytes);
    flight_write_u16_le(destination + 0, encoded_type);
    flight_write_u16_le(destination + 2, flags);
    flight_write_u32_le(destination + 4, total_bytes);
    flight_write_u64_le(destination + 8, sequence);
    flight_atomic_store_u32_le(destination + 20, 0, std::memory_order_relaxed);
    if (!payload.empty()) {
        std::memcpy(destination + kFlightRecordHeaderBytes, payload.data(), payload.size());
    }
    flight_write_u32_le(destination + 16, record_checksum(destination, total_bytes));
    write_offset_ += storage_bytes;
    if (!publish) {
        interrupted_record_ = destination;
        interrupted_record_size_ = storage_bytes;
        return true;
    }
    const uint32_t commit = kFlightRecordCommit ^ total_bytes ^ lease_.generation;
    flight_atomic_store_u32_le(destination + 20, commit, std::memory_order_release);
    committed_extent_ = write_offset_;
    previous_record_ = destination;
    previous_record_size_ = storage_bytes;
    ++record_count_;
    if (first_sequence_ == 0) first_sequence_ = sequence;
    last_sequence_ = sequence;
    if (!artifact_->publish_thread_sequence(registration_, lease_, first_sequence_,
                                            last_sequence_)) {
        artifact_->mark_incomplete(FlightIncompleteReason::WriterFailure);
        return false;
    }
    return true;
}

bool FlightChunkWriter::seal() noexcept {
    if (!active()) return false;
    if (sealed_) return true;
    const uint32_t checksum = flight_checksum32(lease_.data, committed_extent_);
    if (!artifact_->seal_chunk(lease_, first_sequence_, last_sequence_, committed_extent_,
                               record_count_, checksum)) {
        artifact_->mark_incomplete(FlightIncompleteReason::WriterFailure);
        return false;
    }
    sealed_ = true;
    return true;
}

bool FlightChunkWriter::rotate() noexcept {
    if (!active() || interrupted_record_ != nullptr || !seal()) return false;
    FlightChunkLease next{};
    if (!artifact_->acquire_chunk(registration_, 0, &next)) return false;
    lease_ = next;
    reset_chunk_state();
    return true;
}

void FlightChunkWriter::detach() noexcept {
    artifact_ = nullptr;
    registration_ = {};
    lease_ = {};
    reset_chunk_state();
}

void FlightChunkWriter::test_interrupt_before_commit() noexcept {
    const std::span<const uint8_t> empty;
    (void)write_record(FlightRecordType::Instruction, empty, 0, false);
}

void FlightChunkWriter::reset_chunk_state() noexcept {
    write_offset_ = 0;
    committed_extent_ = 0;
    record_count_ = 0;
    first_sequence_ = 0;
    last_sequence_ = 0;
    previous_record_ = nullptr;
    previous_record_size_ = 0;
    interrupted_record_ = nullptr;
    interrupted_record_size_ = 0;
    sealed_ = false;
}
