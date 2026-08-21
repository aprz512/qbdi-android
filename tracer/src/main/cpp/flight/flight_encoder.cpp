#include "flight/flight_encoder.h"

#include "core/instruction_cache.h"
#include "events/binary_trace_encoder.h"
#include "events/binary_trace_format.h"

#include <array>
#include <cstring>
#include <span>

namespace {

constexpr size_t kChunkMetadataFixedBytes = 40;
constexpr uint64_t kFnvOffsetBasis = 14695981039346656037ULL;
constexpr uint64_t kFnvPrime = 1099511628211ULL;

bool utf8_continuation(unsigned char byte) noexcept {
    return (byte & 0xc0U) == 0x80U;
}

size_t detail_chunk_end(std::string_view detail, size_t offset) noexcept {
    const size_t remaining = detail.size() - offset;
    size_t end = offset + (remaining < kBinaryMaxCallChunkDetailBytes
                                   ? remaining
                                   : kBinaryMaxCallChunkDetailBytes);
    if (end == detail.size()) return end;
    while (end > offset &&
           utf8_continuation(static_cast<unsigned char>(detail[end]))) {
        --end;
    }
    return end == offset ? offset + kBinaryMaxCallChunkDetailBytes : end;
}

uint64_t string_hash(std::string_view value) noexcept {
    uint64_t hash = kFnvOffsetBasis;
    for (char byte : value) {
        hash ^= static_cast<uint8_t>(byte);
        hash *= kFnvPrime;
    }
    return hash;
}

bool encode_profile(TraceProfile profile, uint8_t *wire) noexcept {
    if (wire == nullptr) return false;
    switch (profile) {
        case TraceProfile::Fast:
            *wire = 0;
            return true;
        case TraceProfile::Balanced:
            *wire = 1;
            return true;
        case TraceProfile::Full:
            *wire = 2;
            return true;
    }
    return false;
}

} // namespace

bool FlightEncoder::initialize(FlightChunkWriter *writer, TraceProfile profile,
                               const TraceContext &context,
                               const QBDI::GPRState *gpr) noexcept {
    uint8_t ignored_profile = 0;
    if (writer_ != nullptr || writer == nullptr || !writer->active() || gpr == nullptr ||
        !encode_profile(profile, &ignored_profile) || context.pid < 0 || context.tid < 0 ||
        context.target_so.size() > target_name_.size() ||
        context.scene_name.size() > scene_name_.size()) {
        return fail();
    }
    writer_ = writer;
    gpr_ = gpr;
    profile_ = profile;
    module_base_ = context.module_base;
    target_offset_ = context.target_offset;
    target_address_ = context.target_address;
    pid_ = static_cast<uint32_t>(context.pid);
    tid_ = static_cast<uint32_t>(context.tid);
    target_name_bytes_ = static_cast<uint16_t>(context.target_so.size());
    scene_name_bytes_ = static_cast<uint16_t>(context.scene_name.size());
    if (target_name_bytes_ != 0) {
        std::memcpy(target_name_.data(), context.target_so.data(), target_name_bytes_);
    }
    if (scene_name_bytes_ != 0) {
        std::memcpy(scene_name_.data(), context.scene_name.data(), scene_name_bytes_);
    }
    reset_chunk_state();
    if (!write_chunk_preamble(*gpr)) return fail();
    return true;
}

bool FlightEncoder::fail() noexcept {
    failed_ = true;
    return false;
}

void FlightEncoder::reset_chunk_state() noexcept {
    for (InstructionSlot &slot : instructions_) slot = {};
    for (StringSlot &slot : strings_) slot = {};
    string_pool_used_ = 0;
    next_instruction_id_ = 1;
    next_string_id_ = 1;
    previous_gpr_.fill(0);
    have_previous_gpr_ = false;
}

void FlightEncoder::snapshot_gpr(
        const QBDI::GPRState &gpr,
        std::array<uint64_t, kFlightGprCount> *values) noexcept {
    if (values == nullptr) return;
    for (size_t index = 0; index < 31; ++index) {
        (*values)[index] = static_cast<uint64_t>(QBDI_GPR_GET(&gpr, index));
    }
    (*values)[31] = static_cast<uint64_t>(gpr.sp);
    (*values)[32] = static_cast<uint64_t>(gpr.pc);
    (*values)[33] = static_cast<uint64_t>(gpr.nzcv);
}

bool FlightEncoder::append_no_rotate(FlightRecordType type, const uint8_t *payload,
                                     size_t payload_bytes, uint16_t flags) noexcept {
    if (failed_ || writer_ == nullptr || (payload == nullptr && payload_bytes != 0)) return false;
    return writer_->append(type, {payload, payload_bytes}, flags);
}

bool FlightEncoder::write_chunk_preamble(const QBDI::GPRState &gpr) noexcept {
    std::array<uint8_t, kChunkMetadataFixedBytes + 2U * kContextStringBytes> metadata{};
    uint8_t profile = 0;
    if (!encode_profile(profile_, &profile)) return false;
    metadata[0] = profile;
    metadata[1] = static_cast<uint8_t>(sizeof(uintptr_t));
    flight_write_u16_le(metadata.data() + 2, target_name_bytes_);
    flight_write_u16_le(metadata.data() + 4, scene_name_bytes_);
    flight_write_u16_le(metadata.data() + 6, 0);
    flight_write_u32_le(metadata.data() + 8, pid_);
    flight_write_u32_le(metadata.data() + 12, tid_);
    flight_write_u64_le(metadata.data() + 16, module_base_);
    flight_write_u64_le(metadata.data() + 24, target_offset_);
    flight_write_u64_le(metadata.data() + 32, target_address_);
    size_t metadata_bytes = kChunkMetadataFixedBytes;
    if (target_name_bytes_ != 0) {
        std::memcpy(metadata.data() + metadata_bytes, target_name_.data(), target_name_bytes_);
        metadata_bytes += target_name_bytes_;
    }
    if (scene_name_bytes_ != 0) {
        std::memcpy(metadata.data() + metadata_bytes, scene_name_.data(), scene_name_bytes_);
        metadata_bytes += scene_name_bytes_;
    }
    if (!append_no_rotate(FlightRecordType::ChunkBegin, metadata.data(), metadata_bytes)) {
        return false;
    }

    std::array<uint64_t, kFlightGprCount> snapshot{};
    snapshot_gpr(gpr, &snapshot);
    std::array<uint8_t, kFlightGprCount * sizeof(uint64_t)> checkpoint{};
    for (size_t index = 0; index < snapshot.size(); ++index) {
        flight_write_u64_le(checkpoint.data() + index * sizeof(uint64_t), snapshot[index]);
    }
    if (!append_no_rotate(FlightRecordType::RegisterDelta, checkpoint.data(),
                          checkpoint.size(), kFlightRegisterCheckpointFlag)) {
        return false;
    }
    previous_gpr_ = snapshot;
    have_previous_gpr_ = true;
    return true;
}

bool FlightEncoder::rotate_to(const QBDI::GPRState &gpr) noexcept {
    if (failed_ || writer_ == nullptr || !writer_->rotate()) return fail();
    reset_chunk_state();
    if (!write_chunk_preamble(gpr)) return fail();
    return true;
}

bool FlightEncoder::rotate() noexcept {
    if (failed_ || gpr_ == nullptr) return fail();
    return rotate_to(*gpr_);
}

bool FlightEncoder::append_single_with_rotation(
        FlightRecordType type, const uint8_t *payload, size_t payload_bytes,
        uint16_t flags, const QBDI::GPRState &rotation_gpr) noexcept {
    if (append_no_rotate(type, payload, payload_bytes, flags)) return true;
    if (!rotate_to(rotation_gpr)) return false;
    if (!append_no_rotate(type, payload, payload_bytes, flags)) return fail();
    return true;
}

bool FlightEncoder::registers(const QBDI::GPRState &gpr) noexcept {
    if (failed_ || writer_ == nullptr || !have_previous_gpr_) return fail();
    std::array<uint64_t, kFlightGprCount> current{};
    snapshot_gpr(gpr, &current);
    uint64_t mask = 0;
    size_t changed = 0;
    for (size_t index = 0; index < current.size(); ++index) {
        if (current[index] == previous_gpr_[index]) continue;
        mask |= 1ULL << index;
        ++changed;
    }
    if (mask == 0) return true;
    std::array<uint8_t, sizeof(uint64_t) + kFlightGprCount * sizeof(uint64_t)> payload{};
    flight_write_u64_le(payload.data(), mask);
    size_t offset = sizeof(uint64_t);
    for (size_t index = 0; index < current.size(); ++index) {
        if ((mask & (1ULL << index)) == 0) continue;
        flight_write_u64_le(payload.data() + offset, current[index]);
        offset += sizeof(uint64_t);
    }
    if (append_no_rotate(FlightRecordType::RegisterDelta, payload.data(), offset)) {
        previous_gpr_ = current;
        return true;
    }
    // A fresh checkpoint already represents this exact state, so no redundant delta follows it.
    return rotate_to(gpr);
}

FlightEncoder::LookupResult FlightEncoder::find_instruction(
        uint32_t opcode, uint32_t *id, size_t *slot_index) const noexcept {
    const size_t start = (static_cast<uint64_t>(opcode) * 2654435761U) &
                         (kInstructionDictionarySlots - 1U);
    for (size_t probe = 0; probe < kInstructionDictionarySlots; ++probe) {
        const size_t index = (start + probe) & (kInstructionDictionarySlots - 1U);
        const InstructionSlot &slot = instructions_[index];
        if (!slot.occupied) {
            if (slot_index != nullptr) *slot_index = index;
            return LookupResult::Missing;
        }
        if (slot.opcode == opcode) {
            if (id != nullptr) *id = slot.id;
            if (slot_index != nullptr) *slot_index = index;
            return LookupResult::Found;
        }
    }
    return LookupResult::Full;
}

bool FlightEncoder::insert_instruction(size_t slot, uint32_t opcode,
                                       uint32_t id) noexcept {
    if (slot >= instructions_.size() || instructions_[slot].occupied || id == 0) return false;
    instructions_[slot] = {opcode, id, true};
    return true;
}

bool FlightEncoder::write_instruction(const InstructionRecord &record) noexcept {
    if (failed_ || record.decoded == nullptr) return fail();
    BinaryTraceEncoder binary;
    for (unsigned int attempt = 0; attempt < 2; ++attempt) {
        uint32_t id = 0;
        size_t slot = 0;
        const LookupResult lookup = find_instruction(record.decoded->opcode, &id, &slot);
        if (lookup == LookupResult::Full) {
            if (attempt == 0 && gpr_ != nullptr && rotate_to(*gpr_)) continue;
            return fail();
        }
        const bool definition_needed = lookup == LookupResult::Missing;
        if (definition_needed) id = next_instruction_id_;

        std::array<uint8_t, kBinaryMaxInstructionRecordBytes> encoded_event{};
        const BinaryEncodeResult event = binary.encode_instruction(
                encoded_event.data(), encoded_event.size(), 1, id, record);
        if (!event.ok) return fail();

        std::array<uint8_t, kBinaryMaxInstructionDefinitionRecordBytes> definition{};
        BinaryEncodeResult encoded_definition{true, 0};
        if (definition_needed) {
            encoded_definition = binary.encode_instruction_definition(
                    definition.data(), definition.size(), id, *record.decoded);
            if (!encoded_definition.ok) return fail();
            if (!append_no_rotate(FlightRecordType::Instruction, definition.data(),
                                  encoded_definition.size, kFlightDefinitionFlag)) {
                if (attempt == 0 && gpr_ != nullptr && rotate_to(*gpr_)) continue;
                return fail();
            }
            if (!insert_instruction(slot, record.decoded->opcode, id)) return fail();
            ++next_instruction_id_;
        }
        if (append_no_rotate(FlightRecordType::Instruction, encoded_event.data(), event.size)) {
            return true;
        }
        if (attempt == 0 && gpr_ != nullptr && rotate_to(*gpr_)) continue;
        return fail();
    }
    return fail();
}

bool FlightEncoder::instruction(const TraceContext &context,
                                const InstructionRecord &record) noexcept {
    if (failed_ || record.memory_count > record.memory.size() ||
        !write_instruction(record)) {
        return fail();
    }
    for (size_t index = 0; index < record.memory_count; ++index) {
        if (!memory(context, record.pc, record.memory[index])) return false;
    }
    if (gpr_ != nullptr && !registers(*gpr_)) return false;
    return true;
}

bool FlightEncoder::memory(const TraceContext &context, uintptr_t pc,
                           const MemoryRecord &record) noexcept {
    if (failed_ || gpr_ == nullptr || pc < context.module_base) return fail();
    BinaryTraceEncoder binary;
    std::array<uint8_t, kBinaryMaxMemoryRecordBytes> payload{};
    const BinaryEncodeResult encoded = binary.encode_memory(
            payload.data(), payload.size(), 1, pc - context.module_base, record);
    if (!encoded.ok) return fail();
    return append_single_with_rotation(FlightRecordType::Memory, payload.data(),
                                       encoded.size, 0, *gpr_);
}

FlightEncoder::LookupResult FlightEncoder::find_string(
        std::string_view value, uint32_t *id, size_t *slot_index) const noexcept {
    const uint64_t hash = string_hash(value);
    const size_t start = hash & (kStringDictionarySlots - 1U);
    for (size_t probe = 0; probe < kStringDictionarySlots; ++probe) {
        const size_t index = (start + probe) & (kStringDictionarySlots - 1U);
        const StringSlot &slot = strings_[index];
        if (!slot.occupied) {
            if (slot_index != nullptr) *slot_index = index;
            return LookupResult::Missing;
        }
        if (slot.hash == hash && slot.size == value.size() &&
            (value.empty() || std::memcmp(string_pool_.data() + slot.offset,
                                          value.data(), value.size()) == 0)) {
            if (id != nullptr) *id = slot.id;
            if (slot_index != nullptr) *slot_index = index;
            return LookupResult::Found;
        }
    }
    return LookupResult::Full;
}

bool FlightEncoder::insert_string(size_t slot_index, std::string_view value,
                                  uint64_t hash, uint32_t id) noexcept {
    if (slot_index >= strings_.size() || strings_[slot_index].occupied || id == 0 ||
        value.size() > UINT16_MAX || value.size() > string_pool_.size() - string_pool_used_) {
        return false;
    }
    const uint32_t offset = static_cast<uint32_t>(string_pool_used_);
    if (!value.empty()) std::memcpy(string_pool_.data() + offset, value.data(), value.size());
    string_pool_used_ += value.size();
    strings_[slot_index] = {hash, id, offset, static_cast<uint16_t>(value.size()), true};
    return true;
}

bool FlightEncoder::write_string_event(FlightRecordType type, std::string_view first,
                                       std::string_view second,
                                       std::string_view third, uint64_t event_id,
                                       uint32_t total_detail_bytes,
                                       uint16_t chunk_index,
                                       uint16_t chunk_count) noexcept {
    if (failed_ || gpr_ == nullptr ||
        (type != FlightRecordType::Call && type != FlightRecordType::Rule &&
         type != FlightRecordType::Error) ||
        first.size() > kBinaryMaxEventDetailBytes ||
        second.size() > kBinaryMaxEventDetailBytes ||
        third.size() > kBinaryMaxEventDetailBytes) {
        return fail();
    }
    const bool chunked = event_id != 0;
    const size_t detail_bytes = type == FlightRecordType::Call ? third.size() : second.size();
    if (chunked && (chunk_count < 2 || chunk_index >= chunk_count ||
                    total_detail_bytes < detail_bytes)) {
        return fail();
    }
    const std::array<std::string_view, 3> values{first, second, third};
    const size_t value_count = type == FlightRecordType::Call ? 3U : 2U;
    for (unsigned int attempt = 0; attempt < 2; ++attempt) {
        std::array<uint32_t, 3> ids{};
        bool retry = false;
        for (size_t index = 0; index < value_count; ++index) {
            size_t slot = 0;
            const LookupResult lookup = find_string(values[index], &ids[index], &slot);
            if (lookup == LookupResult::Full ||
                (lookup == LookupResult::Missing &&
                 values[index].size() > string_pool_.size() - string_pool_used_)) {
                retry = true;
                break;
            }
            if (lookup == LookupResult::Found) continue;
            ids[index] = next_string_id_;
            std::array<uint8_t, 8U + kBinaryMaxEventDetailBytes> definition{};
            flight_write_u32_le(definition.data(), ids[index]);
            flight_write_u32_le(definition.data() + 4,
                                static_cast<uint32_t>(values[index].size()));
            if (!values[index].empty()) {
                std::memcpy(definition.data() + 8, values[index].data(), values[index].size());
            }
            if (!append_no_rotate(FlightRecordType::Call, definition.data(),
                                  8U + values[index].size(),
                                  kFlightDefinitionFlag | kFlightStringDefinitionFlag)) {
                retry = true;
                break;
            }
            if (!insert_string(slot, values[index], string_hash(values[index]), ids[index])) {
                return fail();
            }
            ++next_string_id_;
        }
        if (!retry) {
            std::array<uint8_t, 16U + 3U * sizeof(uint32_t)> payload{};
            size_t payload_offset = 0;
            if (chunked) {
                flight_write_u64_le(payload.data(), event_id);
                flight_write_u32_le(payload.data() + 8, total_detail_bytes);
                flight_write_u16_le(payload.data() + 12, chunk_index);
                flight_write_u16_le(payload.data() + 14, chunk_count);
                payload_offset = 16;
            }
            for (size_t index = 0; index < value_count; ++index) {
                flight_write_u32_le(payload.data() + payload_offset +
                                            index * sizeof(uint32_t),
                                    ids[index]);
            }
            if (append_no_rotate(type, payload.data(),
                                 payload_offset + value_count * sizeof(uint32_t),
                                 chunked ? kFlightEventChunkFlag : 0)) {
                return true;
            }
            retry = true;
        }
        if (retry && attempt == 0 && rotate_to(*gpr_)) continue;
        return fail();
    }
    return fail();
}

bool FlightEncoder::write_chunked_event(FlightRecordType type,
                                        std::string_view first,
                                        std::string_view detail) noexcept {
    size_t chunk_count = 0;
    for (size_t offset = 0; offset < detail.size();
         offset = detail_chunk_end(detail, offset)) {
        ++chunk_count;
    }
    if (chunk_count < 2 || chunk_count > UINT16_MAX || detail.size() > UINT32_MAX) {
        return fail();
    }
    uint64_t event_id = next_event_id_++;
    if (event_id == 0) event_id = next_event_id_++;
    size_t offset = 0;
    for (size_t index = 0; index < chunk_count; ++index) {
        const size_t end = detail_chunk_end(detail, offset);
        if (type == FlightRecordType::Call) {
            // The caller passes category and name packed as two adjacent string views via
            // write_string_event directly; this helper is for two-string semantic events.
            return fail();
        }
        if (!write_string_event(type, first, detail.substr(offset, end - offset), {},
                                event_id, static_cast<uint32_t>(detail.size()),
                                static_cast<uint16_t>(index),
                                static_cast<uint16_t>(chunk_count))) {
            return false;
        }
        offset = end;
    }
    return true;
}

bool FlightEncoder::call(const char *category, std::string_view name,
                         std::string_view detail) noexcept {
    const std::string_view category_view = category == nullptr ? std::string_view{} : category;
    if (category_view.size() > kBinaryMaxCallCategoryBytes ||
        name.size() > kBinaryMaxCallNameBytes ||
        detail.size() > kBinaryMaxLogicalCallDetailBytes) {
        return fail();
    }
    if (detail.size() <= kBinaryMaxCallChunkDetailBytes) {
        return write_string_event(FlightRecordType::Call, category_view, name, detail);
    }
    size_t chunk_count = 0;
    for (size_t offset = 0; offset < detail.size();
         offset = detail_chunk_end(detail, offset)) {
        ++chunk_count;
    }
    if (chunk_count < 2 || chunk_count > UINT16_MAX) return fail();
    uint64_t event_id = next_event_id_++;
    if (event_id == 0) event_id = next_event_id_++;
    size_t offset = 0;
    for (size_t index = 0; index < chunk_count; ++index) {
        const size_t end = detail_chunk_end(detail, offset);
        if (!write_string_event(FlightRecordType::Call, category_view, name,
                                detail.substr(offset, end - offset), event_id,
                                static_cast<uint32_t>(detail.size()),
                                static_cast<uint16_t>(index),
                                static_cast<uint16_t>(chunk_count))) {
            return false;
        }
        offset = end;
    }
    return true;
}

bool FlightEncoder::rule(const std::string &name, const std::string &detail) noexcept {
    if (name.size() > kBinaryMaxEventNameBytes || detail.size() > kBinaryMaxEventDetailBytes) {
        return fail();
    }
    if (detail.size() <= kBinaryMaxEventChunkDetailBytes) {
        return write_string_event(FlightRecordType::Rule, name, detail, {});
    }
    return write_chunked_event(FlightRecordType::Rule, name, detail);
}

bool FlightEncoder::error(const std::string &message) noexcept {
    if (message.size() > kBinaryMaxEventDetailBytes) return fail();
    if (message.size() <= kBinaryMaxEventChunkDetailBytes) {
        return write_string_event(FlightRecordType::Error, {}, message, {});
    }
    return write_chunked_event(FlightRecordType::Error, {}, message);
}
