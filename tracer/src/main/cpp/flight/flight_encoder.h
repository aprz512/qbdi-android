#pragma once

#include "core/trace_config.h"
#include "events/trace_event.h"
#include "events/trace_record.h"
#include "flight/flight_chunk_writer.h"

#include <QBDI/State.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

constexpr size_t kFlightGprCount = 34;
constexpr uint16_t kFlightDefinitionFlag = 1U << 0U;
constexpr uint16_t kFlightStringDefinitionFlag = 1U << 1U;
constexpr uint16_t kFlightRegisterCheckpointFlag = 1U << 0U;
constexpr uint16_t kFlightCallChunkFlag = 1U << 2U;
constexpr uint16_t kFlightEventChunkFlag = kFlightCallChunkFlag;

// Flight payloads are explicitly little-endian:
// - ChunkBegin: profile u8, pointer-width u8, target/scene lengths u16, reserved u16,
//   pid/tid u32, module-base/target-offset/target-address u64, then target and scene bytes.
// - RegisterDelta checkpoint: 34 u64 values in x0..x30, sp, pc, nzcv order.
// - RegisterDelta delta: changed-mask u64, then changed u64 values in ascending index order.
// - Definition-flag Instruction: one complete QTRB instruction-definition record.
// - Ordinary Instruction/Memory: one complete QTRB event record.
// - String definition: string-id u32, byte-count u32, bytes; ordinary string events use IDs.
// - Chunked string event: event-id u64, total-detail u32, chunk-index/count u16, then IDs.

class FlightEncoder {
public:
    FlightEncoder() noexcept = default;

    // gpr is copied during this call; no pointer or reference is retained.
    bool initialize(FlightChunkWriter *writer, TraceProfile profile,
                    const TraceContext &context,
                    const QBDI::GPRState *gpr) noexcept;
    bool rotate() noexcept;
    bool registers(const QBDI::GPRState &gpr) noexcept;

    bool instruction(const TraceContext &context,
                     const InstructionRecord &record) noexcept;
    bool instruction(const TraceContext &context, const InstructionRecord &record,
                     const RegisterSnapshot &post_registers) noexcept;
    bool memory(const TraceContext &context, uintptr_t pc,
                const MemoryRecord &record) noexcept;
    bool call(const char *category, std::string_view name,
              std::string_view detail) noexcept;
    bool rule(const std::string &name, const std::string &detail) noexcept;
    bool error(const std::string &message) noexcept;

    bool failed() const noexcept { return failed_; }

private:
    static constexpr size_t kInstructionDictionarySlots = 256;
    static constexpr size_t kStringDictionarySlots = 256;
    static constexpr size_t kStringPoolBytes = 16U * 1024U;
    static constexpr size_t kContextStringBytes = 255;

    struct InstructionSlot {
        uint32_t opcode = 0;
        uint32_t id = 0;
        bool occupied = false;
    };

    struct StringSlot {
        uint64_t hash = 0;
        uint32_t id = 0;
        uint32_t offset = 0;
        uint16_t size = 0;
        bool occupied = false;
    };

    enum class LookupResult : uint8_t { Found, Missing, Full };

    bool fail() noexcept;
    void reset_chunk_state() noexcept;
    bool write_chunk_preamble(
            const std::array<uint64_t, kFlightGprCount> &gpr) noexcept;
    bool rotate_to(const std::array<uint64_t, kFlightGprCount> &gpr) noexcept;
    FlightWriteResult append_no_rotate(FlightRecordType type, const uint8_t *payload,
                                       size_t payload_bytes,
                                       uint16_t flags = 0) noexcept;
    bool append_single_with_rotation(FlightRecordType type, const uint8_t *payload,
                                     size_t payload_bytes, uint16_t flags) noexcept;
    bool write_instruction(const InstructionRecord &record) noexcept;
    bool write_register_snapshot(
            const std::array<uint64_t, kFlightGprCount> &current) noexcept;
    bool instruction_post_state(
            const InstructionRecord &record,
            std::array<uint64_t, kFlightGprCount> *post) const noexcept;
    bool write_instruction_with_post_state(
            const TraceContext &context, const InstructionRecord &record,
            const std::array<uint64_t, kFlightGprCount> &post) noexcept;
    bool write_string_event(FlightRecordType type,
                            const std::array<std::string_view, 3> &fields,
                            size_t field_count, size_t detail_field,
                            uint64_t event_id = 0,
                            uint32_t total_detail_bytes = 0,
                            uint16_t chunk_index = 0,
                            uint16_t chunk_count = 0) noexcept;
    bool write_chunked_event(FlightRecordType type, std::string_view category,
                             std::string_view name, std::string_view detail) noexcept;

    LookupResult find_instruction(uint32_t opcode, uint32_t *id,
                                  size_t *slot) const noexcept;
    bool insert_instruction(size_t slot, uint32_t opcode, uint32_t id) noexcept;
    LookupResult find_string(std::string_view value, uint32_t *id,
                             size_t *slot) const noexcept;
    bool insert_string(size_t slot, std::string_view value, uint64_t hash,
                       uint32_t id) noexcept;

    static void snapshot_gpr(const QBDI::GPRState &gpr,
                             std::array<uint64_t, kFlightGprCount> *values) noexcept;
    static void snapshot_registers(
            const RegisterSnapshot &registers,
            std::array<uint64_t, kFlightGprCount> *values) noexcept;

    FlightChunkWriter *writer_ = nullptr;
    TraceProfile profile_ = TraceProfile::Full;
    uint64_t module_base_ = 0;
    uint64_t target_offset_ = 0;
    uint64_t target_address_ = 0;
    uint32_t pid_ = 0;
    uint32_t tid_ = 0;
    std::array<char, kContextStringBytes> target_name_{};
    std::array<char, kContextStringBytes> scene_name_{};
    uint16_t target_name_bytes_ = 0;
    uint16_t scene_name_bytes_ = 0;
    std::array<InstructionSlot, kInstructionDictionarySlots> instructions_{};
    std::array<StringSlot, kStringDictionarySlots> strings_{};
    std::array<char, kStringPoolBytes> string_pool_{};
    size_t string_pool_used_ = 0;
    uint32_t next_instruction_id_ = 1;
    uint32_t next_string_id_ = 1;
    uint64_t next_event_id_ = 1;
    std::array<uint64_t, kFlightGprCount> previous_gpr_{};
    bool have_previous_gpr_ = false;
    bool failed_ = false;
};
