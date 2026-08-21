#pragma once

#include <cstddef>
#include <cstdint>
#include <type_traits>

constexpr uint32_t kFlightMagic = 0x51464c54U;
constexpr uint16_t kFlightVersion = 1;
constexpr uint32_t kFlightRecordCommit = 0x51434d54U;

constexpr size_t kFlightSuperblockBytes = 4096;
constexpr size_t kFlightDirectoryEntryBytes = 64;
constexpr size_t kFlightChunkHeaderBytes = 64;
constexpr size_t kFlightRecordHeaderBytes = 24;
constexpr size_t kFlightEmergencyRecordBytes = 64;

enum class FlightRecordType : uint16_t {
    ChunkBegin = 1,
    ThreadBegin = 2,
    ThreadEnd = 3,
    Instruction = 4,
    Memory = 5,
    Call = 6,
    Rule = 7,
    Error = 8,
    RegisterDelta = 9,
    Syscall = 10,
    Signal = 11,
    SignalHandlerBegin = 12,
    SignalHandlerReturn = 13,
    TerminationIntent = 14,
    CoverageGap = 15,
};

struct FlightSuperblock {
    uint32_t magic;
    uint16_t version;
    uint16_t header_bytes;
    uint64_t artifact_bytes;
    uint64_t directory_offset;
    uint32_t directory_entry_bytes;
    uint32_t directory_entries;
    uint64_t chunk_offset;
    uint32_t chunk_bytes;
    uint32_t chunk_count;
    uint64_t emergency_offset;
    uint32_t emergency_record_bytes;
    uint32_t emergency_record_count;
    uint32_t flags;
    uint8_t reserved[kFlightSuperblockBytes - 68];
};

struct FlightDirectoryEntry {
    uint32_t tid;
    uint32_t state;
    uint64_t first_sequence;
    uint64_t last_sequence;
    uint32_t chunk_index;
    uint32_t chunk_generation;
    uint8_t reserved[kFlightDirectoryEntryBytes - 32];
};

struct FlightChunkHeader {
    uint32_t magic;
    uint16_t version;
    uint16_t header_bytes;
    uint32_t chunk_index;
    uint32_t state;
    uint32_t tid;
    uint32_t generation;
    uint64_t first_sequence;
    uint64_t last_sequence;
    uint32_t committed_bytes;
    uint32_t record_count;
    uint32_t checksum;
    uint8_t reserved[kFlightChunkHeaderBytes - 52];
};

struct FlightRecordHeader {
    uint16_t type;
    uint16_t flags;
    uint32_t total_bytes;
    uint64_t sequence;
    uint32_t checksum;
    uint32_t commit;
};

struct FlightEmergencyRecord {
    uint32_t type;
    uint32_t tid;
    uint64_t sequence;
    uint64_t pc;
    uint64_t sp;
    uint64_t fault_address;
    uint32_t signal_number;
    uint32_t signal_code;
    uint32_t flags;
    uint8_t reserved[kFlightEmergencyRecordBytes - 52];
};

static_assert(sizeof(FlightSuperblock) == kFlightSuperblockBytes);
static_assert(sizeof(FlightDirectoryEntry) == kFlightDirectoryEntryBytes);
static_assert(sizeof(FlightChunkHeader) == kFlightChunkHeaderBytes);
static_assert(sizeof(FlightRecordHeader) == kFlightRecordHeaderBytes);
static_assert(sizeof(FlightEmergencyRecord) == kFlightEmergencyRecordBytes);

static_assert(std::is_standard_layout_v<FlightSuperblock>);
static_assert(std::is_standard_layout_v<FlightDirectoryEntry>);
static_assert(std::is_standard_layout_v<FlightChunkHeader>);
static_assert(std::is_standard_layout_v<FlightRecordHeader>);
static_assert(std::is_standard_layout_v<FlightEmergencyRecord>);
static_assert(std::is_trivially_copyable_v<FlightSuperblock>);
static_assert(std::is_trivially_copyable_v<FlightDirectoryEntry>);
static_assert(std::is_trivially_copyable_v<FlightChunkHeader>);
static_assert(std::is_trivially_copyable_v<FlightRecordHeader>);
static_assert(std::is_trivially_copyable_v<FlightEmergencyRecord>);
static_assert(std::is_trivial_v<FlightSuperblock>);
static_assert(std::is_trivial_v<FlightDirectoryEntry>);
static_assert(std::is_trivial_v<FlightChunkHeader>);
static_assert(std::is_trivial_v<FlightRecordHeader>);
static_assert(std::is_trivial_v<FlightEmergencyRecord>);
