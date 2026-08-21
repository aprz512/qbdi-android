#pragma once

#include <cstddef>
#include <cstdint>
#include <type_traits>

constexpr uint32_t kFlightMagic = 0x51464c54U;
constexpr uint16_t kFlightVersion = 1;
constexpr uint32_t kFlightRecordCommit = 0x51434d54U;
constexpr uint8_t kFlightByteOrderLittleEndian = 1;
constexpr uint8_t kFlightPointerWidth32 = 4;
constexpr uint8_t kFlightPointerWidth64 = 8;

constexpr size_t kFlightSuperblockBytes = 4096;
constexpr size_t kFlightDirectoryEntryBytes = 64;
constexpr size_t kFlightChunkHeaderBytes = 64;
constexpr size_t kFlightRecordHeaderBytes = 24;
constexpr size_t kFlightEmergencyRecordBytes = 64;
constexpr size_t kFlightTargetNameBytes = 128;
constexpr size_t kFlightTargetNameOffset = 98;

struct FlightArtifactIdentityView {
    uint64_t run_id;
    uint32_t pid;
    uint32_t module_generation;
    const char *target_name;
    uint16_t target_name_bytes;
};

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
    uint8_t byte_order;
    uint8_t pointer_width;
    uint16_t header_bytes;
    uint8_t header_reserved[6];
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
    uint8_t identity_reserved[4];
    uint64_t run_id;
    uint32_t pid;
    uint32_t module_generation;
    uint16_t target_name_bytes;
    uint8_t target_name[kFlightTargetNameBytes];
    uint8_t reserved[kFlightSuperblockBytes - 226];
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

// Persistent flight artifacts are always serialized with these explicit
// little-endian helpers; native struct byte order is never persisted.
inline void flight_write_u16_le(uint8_t *destination, uint16_t value) noexcept {
    destination[0] = static_cast<uint8_t>(value);
    destination[1] = static_cast<uint8_t>(value >> 8);
}

inline void flight_write_u32_le(uint8_t *destination, uint32_t value) noexcept {
    for (size_t index = 0; index < sizeof(value); ++index) {
        destination[index] = static_cast<uint8_t>(value >> (index * 8));
    }
}

inline void flight_write_u64_le(uint8_t *destination, uint64_t value) noexcept {
    for (size_t index = 0; index < sizeof(value); ++index) {
        destination[index] = static_cast<uint8_t>(value >> (index * 8));
    }
}

inline uint16_t flight_read_u16_le(const uint8_t *source) noexcept {
    return static_cast<uint16_t>(source[0]) |
           (static_cast<uint16_t>(source[1]) << 8);
}

inline uint32_t flight_read_u32_le(const uint8_t *source) noexcept {
    uint32_t value = 0;
    for (size_t index = 0; index < sizeof(value); ++index) {
        value |= static_cast<uint32_t>(source[index]) << (index * 8);
    }
    return value;
}

inline uint64_t flight_read_u64_le(const uint8_t *source) noexcept {
    uint64_t value = 0;
    for (size_t index = 0; index < sizeof(value); ++index) {
        value |= static_cast<uint64_t>(source[index]) << (index * 8);
    }
    return value;
}

inline bool flight_pointer_width_valid(uint8_t pointer_width) noexcept {
    return pointer_width == kFlightPointerWidth32 || pointer_width == kFlightPointerWidth64;
}

inline bool flight_identity_view_valid(const FlightArtifactIdentityView &identity) noexcept {
    if (identity.run_id == 0 || identity.pid == 0 || identity.target_name == nullptr ||
        identity.target_name_bytes == 0 || identity.target_name_bytes > kFlightTargetNameBytes) {
        return false;
    }
    for (size_t index = 0; index < identity.target_name_bytes; ++index) {
        if (identity.target_name[index] == '\0') return false;
    }
    return true;
}

inline bool flight_superblock_identity_valid(const FlightSuperblock &superblock) noexcept {
    if (superblock.run_id == 0 || superblock.pid == 0 || superblock.target_name_bytes == 0 ||
        superblock.target_name_bytes > kFlightTargetNameBytes) {
        return false;
    }
    for (size_t index = 0; index < superblock.target_name_bytes; ++index) {
        if (superblock.target_name[index] == 0) return false;
    }
    for (size_t index = superblock.target_name_bytes; index < kFlightTargetNameBytes; ++index) {
        if (superblock.target_name[index] != 0) return false;
    }
    return true;
}

inline bool flight_set_superblock_identity(FlightSuperblock *superblock,
                                           const FlightArtifactIdentityView &identity) noexcept {
    if (superblock == nullptr || !flight_identity_view_valid(identity)) return false;
    superblock->run_id = identity.run_id;
    superblock->pid = identity.pid;
    superblock->module_generation = identity.module_generation;
    superblock->target_name_bytes = identity.target_name_bytes;
    for (size_t index = 0; index < kFlightTargetNameBytes; ++index) {
        superblock->target_name[index] = index < identity.target_name_bytes
                                                 ? static_cast<uint8_t>(identity.target_name[index])
                                                 : 0;
    }
    return true;
}

inline bool flight_get_superblock_identity(const FlightSuperblock &superblock,
                                           FlightArtifactIdentityView *identity) noexcept {
    if (identity == nullptr || !flight_superblock_identity_valid(superblock)) return false;
    identity->run_id = superblock.run_id;
    identity->pid = superblock.pid;
    identity->module_generation = superblock.module_generation;
    identity->target_name = reinterpret_cast<const char *>(superblock.target_name);
    identity->target_name_bytes = superblock.target_name_bytes;
    return true;
}

inline bool encode_flight_superblock_le(const FlightSuperblock &superblock, uint8_t *destination,
                                        size_t destination_size) noexcept {
    if (destination == nullptr || destination_size != kFlightSuperblockBytes ||
        superblock.byte_order != kFlightByteOrderLittleEndian ||
        !flight_pointer_width_valid(superblock.pointer_width) ||
        !flight_superblock_identity_valid(superblock)) {
        return false;
    }
    for (size_t index = 0; index < kFlightSuperblockBytes; ++index) destination[index] = 0;
    flight_write_u32_le(destination + 0, superblock.magic);
    flight_write_u16_le(destination + 4, superblock.version);
    destination[6] = superblock.byte_order;
    destination[7] = superblock.pointer_width;
    flight_write_u16_le(destination + 8, superblock.header_bytes);
    flight_write_u64_le(destination + 16, superblock.artifact_bytes);
    flight_write_u64_le(destination + 24, superblock.directory_offset);
    flight_write_u32_le(destination + 32, superblock.directory_entry_bytes);
    flight_write_u32_le(destination + 36, superblock.directory_entries);
    flight_write_u64_le(destination + 40, superblock.chunk_offset);
    flight_write_u32_le(destination + 48, superblock.chunk_bytes);
    flight_write_u32_le(destination + 52, superblock.chunk_count);
    flight_write_u64_le(destination + 56, superblock.emergency_offset);
    flight_write_u32_le(destination + 64, superblock.emergency_record_bytes);
    flight_write_u32_le(destination + 68, superblock.emergency_record_count);
    flight_write_u32_le(destination + 72, superblock.flags);
    flight_write_u64_le(destination + 80, superblock.run_id);
    flight_write_u32_le(destination + 88, superblock.pid);
    flight_write_u32_le(destination + 92, superblock.module_generation);
    flight_write_u16_le(destination + 96, superblock.target_name_bytes);
    for (size_t index = 0; index < kFlightTargetNameBytes; ++index) {
        destination[kFlightTargetNameOffset + index] = superblock.target_name[index];
    }
    return true;
}

inline bool decode_flight_superblock_le(const uint8_t *source, size_t source_size,
                                        FlightSuperblock *superblock) noexcept {
    if (source == nullptr || superblock == nullptr || source_size != kFlightSuperblockBytes) {
        return false;
    }
    for (size_t index = 0; index < sizeof(FlightSuperblock::identity_reserved); ++index) {
        if (source[76 + index] != 0) return false;
    }
    FlightSuperblock decoded{};
    decoded.magic = flight_read_u32_le(source + 0);
    decoded.version = flight_read_u16_le(source + 4);
    decoded.byte_order = source[6];
    decoded.pointer_width = source[7];
    decoded.header_bytes = flight_read_u16_le(source + 8);
    decoded.artifact_bytes = flight_read_u64_le(source + 16);
    decoded.directory_offset = flight_read_u64_le(source + 24);
    decoded.directory_entry_bytes = flight_read_u32_le(source + 32);
    decoded.directory_entries = flight_read_u32_le(source + 36);
    decoded.chunk_offset = flight_read_u64_le(source + 40);
    decoded.chunk_bytes = flight_read_u32_le(source + 48);
    decoded.chunk_count = flight_read_u32_le(source + 52);
    decoded.emergency_offset = flight_read_u64_le(source + 56);
    decoded.emergency_record_bytes = flight_read_u32_le(source + 64);
    decoded.emergency_record_count = flight_read_u32_le(source + 68);
    decoded.flags = flight_read_u32_le(source + 72);
    decoded.run_id = flight_read_u64_le(source + 80);
    decoded.pid = flight_read_u32_le(source + 88);
    decoded.module_generation = flight_read_u32_le(source + 92);
    decoded.target_name_bytes = flight_read_u16_le(source + 96);
    for (size_t index = 0; index < kFlightTargetNameBytes; ++index) {
        decoded.target_name[index] = source[kFlightTargetNameOffset + index];
    }
    if (decoded.magic != kFlightMagic || decoded.version != kFlightVersion ||
        decoded.byte_order != kFlightByteOrderLittleEndian ||
        !flight_pointer_width_valid(decoded.pointer_width) ||
        decoded.header_bytes != kFlightSuperblockBytes ||
        !flight_superblock_identity_valid(decoded)) {
        return false;
    }
    *superblock = decoded;
    return true;
}

static_assert(sizeof(FlightSuperblock) == kFlightSuperblockBytes);
static_assert(sizeof(FlightDirectoryEntry) == kFlightDirectoryEntryBytes);
static_assert(sizeof(FlightChunkHeader) == kFlightChunkHeaderBytes);
static_assert(sizeof(FlightRecordHeader) == kFlightRecordHeaderBytes);
static_assert(sizeof(FlightEmergencyRecord) == kFlightEmergencyRecordBytes);
static_assert(offsetof(FlightSuperblock, magic) == 0);
static_assert(offsetof(FlightSuperblock, version) == 4);
static_assert(offsetof(FlightSuperblock, byte_order) == 6);
static_assert(offsetof(FlightSuperblock, pointer_width) == 7);
static_assert(offsetof(FlightSuperblock, header_bytes) == 8);
static_assert(offsetof(FlightSuperblock, artifact_bytes) == 16);
static_assert(offsetof(FlightSuperblock, directory_offset) == 24);
static_assert(offsetof(FlightSuperblock, chunk_offset) == 40);
static_assert(offsetof(FlightSuperblock, emergency_offset) == 56);
static_assert(offsetof(FlightSuperblock, flags) == 72);
static_assert(offsetof(FlightSuperblock, identity_reserved) == 76);
static_assert(offsetof(FlightSuperblock, run_id) == 80);
static_assert(offsetof(FlightSuperblock, pid) == 88);
static_assert(offsetof(FlightSuperblock, module_generation) == 92);
static_assert(offsetof(FlightSuperblock, target_name_bytes) == 96);
static_assert(offsetof(FlightSuperblock, target_name) == kFlightTargetNameOffset);

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
