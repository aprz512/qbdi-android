#pragma once

#include <cstddef>
#include <cstdint>

// QTRB v1 is byte-packed and little-endian. There is no implicit padding and no native struct is
// copied to the stream. Strings are a u16 byte length followed by uninterpreted UTF-8 bytes.
// uintptr_t values are widened to u64 on the wire; the stream header records the source pointer
// width so a decoder can validate the producer ABI.
inline constexpr uint8_t kBinaryTraceMagic[] = {'Q', 'T', 'R', 'B'};
inline constexpr uint8_t kBinaryTraceMajorVersion = 1;
inline constexpr uint8_t kBinaryTraceMinorVersion = 0;
inline constexpr uint8_t kBinaryLittleEndianMarker = 1;
inline constexpr uint16_t kBinaryStreamHeaderBytes = 16;
inline constexpr uint16_t kBinaryRecordHeaderBytes = 8;
inline constexpr uint16_t kBinaryRecordFlags = 0;
inline constexpr uint32_t kBinaryRequiredFeatures = 0;

// StreamHeader (16 bytes): magic[4], major u8, minor u8, endian u8, pointer_width u8,
// profile u8 (fast=0, balanced=1, full=2), reserved u8=0, header_bytes u16,
// required_features u32.

enum class BinaryRecordType : uint16_t {
    TraceBegin = 1,
    ModuleDefinition = 2,
    InstructionDefinition = 3,
    Instruction = 4,
    Memory = 5,
    Call = 6,
    Rule = 7,
    Error = 8,
    TraceEnd = 9,
};

// RecordHeader (8 bytes): type u16, flags u16 (zero in v1), payload_bytes u32.

inline constexpr size_t kBinaryMaxContextStringBytes = 255;
inline constexpr size_t kBinaryMaxModuleNameBytes = 255;
inline constexpr size_t kBinaryMaxCallCategoryBytes = 255;
inline constexpr size_t kBinaryMaxCallNameBytes = 255;
inline constexpr size_t kBinaryMaxEventNameBytes = 255;
inline constexpr size_t kBinaryMaxEventDetailBytes = 4096;
inline constexpr size_t kBinaryMaxMnemonicBytes = 16;
inline constexpr size_t kBinaryMaxOperandsBytes = 96;
inline constexpr size_t kBinaryMaxDisassemblyBytes = 112;
inline constexpr size_t kBinaryMaxRegisterNameBytes = 16;

// TRACE_BEGIN payload: module_base u64, target_offset u64, target_address u64, pid u32, tid u32,
// profile u8 (fast=0, balanced=1, full=2), compression_enabled u8, effective_buffer_bytes u64,
// run_id u64, scene string, target string.
inline constexpr size_t kBinaryTraceBeginFixedPayloadBytes = 54;
inline constexpr size_t kBinaryMaxTraceBeginRecordBytes =
        kBinaryRecordHeaderBytes + kBinaryTraceBeginFixedPayloadBytes +
        2U * kBinaryMaxContextStringBytes;

// MODULE_DEF payload: module_id u32, module_base u64, module_name string.
inline constexpr size_t kBinaryModuleDefinitionFixedPayloadBytes = 14;
inline constexpr size_t kBinaryMaxModuleDefinitionRecordBytes =
        kBinaryRecordHeaderBytes + kBinaryModuleDefinitionFixedPayloadBytes +
        kBinaryMaxModuleNameBytes;

// INSTRUCTION_DEF fixed payload: metadata_id u32, opcode u32, read_mask u64, write_mask u64,
// pc_displacement i64-as-bits, instruction_flags u32, pc_kind u8, condition u8,
// memory_operand_count u8, slow_memory_path u8. It is followed by mnemonic, operands, and
// disassembly strings; then one (width u8, name string) entry per set read-mask bit and set
// write-mask bit, in ascending bit order; then memory operands in source order.
// MemoryOperand wire fields (19 bytes): base u8, index u8, extend u8, address_mode u8, shift u8,
// access_kind u8, writeback u8, access_size u32, displacement i64-as-bits.
inline constexpr size_t kBinaryInstructionDefinitionFixedPayloadBytes = 40;
inline constexpr size_t kBinaryEncodedMemoryOperandBytes = 19;
inline constexpr size_t kBinaryMaxGprCount = 34;
inline constexpr size_t kBinaryMaxMemoryOperandCount = 4;
inline constexpr size_t kBinaryMaxInstructionDefinitionRecordBytes =
        kBinaryRecordHeaderBytes + kBinaryInstructionDefinitionFixedPayloadBytes +
        (2U + kBinaryMaxMnemonicBytes) + (2U + kBinaryMaxOperandsBytes) +
        (2U + kBinaryMaxDisassemblyBytes) +
        2U * kBinaryMaxGprCount * (1U + 2U + kBinaryMaxRegisterNameBytes) +
        kBinaryMaxMemoryOperandCount * kBinaryEncodedMemoryOperandBytes;

// INSTRUCTION payload: sequence u64, module_id u32, module_relative_pc u64, metadata_id u32,
// read_count u8, write_count u8, then read and write u64 values in definition-mask bit order.
inline constexpr size_t kBinaryInstructionFixedPayloadBytes = 26;
inline constexpr size_t kBinaryMaxInstructionRecordBytes =
        kBinaryRecordHeaderBytes + kBinaryInstructionFixedPayloadBytes +
        2U * kBinaryMaxGprCount * sizeof(uint64_t);

// MEMORY payload: module_id u32, module_relative_pc u64, access_kind u8,
// metadata_available u8, flags u16, address u64, access_size u32, value u64,
// then before and after as (state u8, byte_count u8, bytes[byte_count]).
inline constexpr size_t kBinaryMemoryFixedPayloadBytes = 40;
inline constexpr size_t kBinaryMaxCapturedMemoryBytes = 64;
inline constexpr size_t kBinaryMaxMemoryRecordBytes =
        kBinaryRecordHeaderBytes + kBinaryMemoryFixedPayloadBytes +
        2U * kBinaryMaxCapturedMemoryBytes;

// CALL payload: category string, name string, detail string.
inline constexpr size_t kBinaryCallFixedPayloadBytes = 6;
inline constexpr size_t kBinaryMaxCallRecordBytes =
        kBinaryRecordHeaderBytes + kBinaryCallFixedPayloadBytes +
        kBinaryMaxCallCategoryBytes + kBinaryMaxCallNameBytes +
        kBinaryMaxEventDetailBytes;

// RULE/ERROR payload: name string, detail string.
inline constexpr size_t kBinaryRuleErrorFixedPayloadBytes = 4;
inline constexpr size_t kBinaryMaxRuleErrorRecordBytes =
        kBinaryRecordHeaderBytes + kBinaryRuleErrorFixedPayloadBytes +
        kBinaryMaxEventNameBytes + kBinaryMaxEventDetailBytes;

// Largest complete v1 record; useful for fixed scratch/test buffers.
inline constexpr size_t kBinaryMaxRecordBytes = kBinaryMaxCallRecordBytes;

// TRACE_END payload: success u8, return_value u64, elapsed_ms u64, then ten u64 counters in
// TraceMetrics declaration order.
inline constexpr size_t kBinaryTraceEndPayloadBytes = 97;
inline constexpr size_t kBinaryTraceEndRecordBytes =
        kBinaryRecordHeaderBytes + kBinaryTraceEndPayloadBytes;

static_assert(kBinaryMaxTraceBeginRecordBytes == 572);
static_assert(kBinaryMaxModuleDefinitionRecordBytes == 277);
static_assert(kBinaryMaxInstructionDefinitionRecordBytes == 1646);
static_assert(kBinaryMaxInstructionRecordBytes == 578);
static_assert(kBinaryMaxMemoryRecordBytes == 176);
static_assert(kBinaryMaxCallRecordBytes == 4620);
static_assert(kBinaryMaxRuleErrorRecordBytes == 4363);
static_assert(kBinaryTraceEndRecordBytes == 105);
