#include "flight/flight_format.h"

#include <cstdio>
#include <cstdlib>
#include <cstddef>
#include <cstring>
#include <type_traits>

static void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

int main() {
    const char target_name[] = "libdemo_target.so";
    FlightArtifactIdentityView identity{0x0102030405060708ULL, 1234, 7, target_name,
                                        static_cast<uint16_t>(sizeof(target_name) - 1U)};
    CHECK(kFlightMagic == 0x51464c54U);
    CHECK(kFlightVersion == 1);
    CHECK(kFlightRecordCommit == 0x51434d54U);
    CHECK(kFlightTargetNameBytes == 128);
    CHECK(sizeof(FlightSuperblock) == kFlightSuperblockBytes);
    CHECK(sizeof(FlightDirectoryEntry) == kFlightDirectoryEntryBytes);
    CHECK(sizeof(FlightChunkHeader) == kFlightChunkHeaderBytes);
    CHECK(sizeof(FlightRecordHeader) == kFlightRecordHeaderBytes);
    CHECK(sizeof(FlightEmergencyRecord) == kFlightEmergencyRecordBytes);
    CHECK(static_cast<uint16_t>(FlightRecordType::ChunkBegin) == 1);
    CHECK(static_cast<uint16_t>(FlightRecordType::ThreadBegin) == 2);
    CHECK(static_cast<uint16_t>(FlightRecordType::ThreadEnd) == 3);
    CHECK(static_cast<uint16_t>(FlightRecordType::Instruction) == 4);
    CHECK(static_cast<uint16_t>(FlightRecordType::Memory) == 5);
    CHECK(static_cast<uint16_t>(FlightRecordType::Call) == 6);
    CHECK(static_cast<uint16_t>(FlightRecordType::Rule) == 7);
    CHECK(static_cast<uint16_t>(FlightRecordType::Error) == 8);
    CHECK(static_cast<uint16_t>(FlightRecordType::RegisterDelta) == 9);
    CHECK(static_cast<uint16_t>(FlightRecordType::Syscall) == 10);
    CHECK(static_cast<uint16_t>(FlightRecordType::Signal) == 11);
    CHECK(static_cast<uint16_t>(FlightRecordType::SignalHandlerBegin) == 12);
    CHECK(static_cast<uint16_t>(FlightRecordType::SignalHandlerReturn) == 13);
    CHECK(static_cast<uint16_t>(FlightRecordType::TerminationIntent) == 14);
    CHECK(static_cast<uint16_t>(FlightRecordType::CoverageGap) == 15);
    CHECK(std::is_trivially_copyable_v<FlightSuperblock>);
    CHECK(std::is_trivially_copyable_v<FlightDirectoryEntry>);
    CHECK(std::is_trivially_copyable_v<FlightChunkHeader>);
    CHECK(std::is_trivially_copyable_v<FlightRecordHeader>);
    CHECK(std::is_trivially_copyable_v<FlightEmergencyRecord>);
    CHECK(std::is_trivial_v<FlightSuperblock>);
    CHECK(std::is_trivial_v<FlightDirectoryEntry>);
    CHECK(std::is_trivial_v<FlightChunkHeader>);
    CHECK(std::is_trivial_v<FlightRecordHeader>);
    CHECK(std::is_trivial_v<FlightEmergencyRecord>);

    CHECK(offsetof(FlightSuperblock, magic) == 0);
    CHECK(offsetof(FlightSuperblock, version) == 4);
    CHECK(offsetof(FlightSuperblock, byte_order) == 6);
    CHECK(offsetof(FlightSuperblock, pointer_width) == 7);
    CHECK(offsetof(FlightSuperblock, header_bytes) == 8);
    CHECK(offsetof(FlightSuperblock, artifact_bytes) == 16);
    CHECK(offsetof(FlightSuperblock, directory_offset) == 24);
    CHECK(offsetof(FlightSuperblock, chunk_offset) == 40);
    CHECK(offsetof(FlightSuperblock, emergency_offset) == 56);
    CHECK(offsetof(FlightSuperblock, flags) == 72);
    CHECK(offsetof(FlightSuperblock, run_id) == 80);
    CHECK(offsetof(FlightSuperblock, pid) == 88);
    CHECK(offsetof(FlightSuperblock, module_generation) == 92);
    CHECK(offsetof(FlightSuperblock, target_name_bytes) == 96);
    CHECK(offsetof(FlightSuperblock, target_name) == kFlightTargetNameOffset);
    CHECK(offsetof(FlightRecordHeader, type) == 0);
    CHECK(offsetof(FlightRecordHeader, sequence) == 8);
    CHECK(offsetof(FlightRecordHeader, commit) == 20);
    CHECK(offsetof(FlightDirectoryEntry, tid) == 0);
    CHECK(offsetof(FlightDirectoryEntry, state) == 4);
    CHECK(offsetof(FlightDirectoryEntry, first_sequence) == 8);
    CHECK(offsetof(FlightDirectoryEntry, last_sequence) == 16);
    CHECK(offsetof(FlightDirectoryEntry, chunk_index) == 24);
    CHECK(offsetof(FlightDirectoryEntry, chunk_generation) == 28);
    CHECK(offsetof(FlightChunkHeader, magic) == 0);
    CHECK(offsetof(FlightChunkHeader, version) == 4);
    CHECK(offsetof(FlightChunkHeader, header_bytes) == 6);
    CHECK(offsetof(FlightChunkHeader, chunk_index) == 8);
    CHECK(offsetof(FlightChunkHeader, tid) == 16);
    CHECK(offsetof(FlightChunkHeader, first_sequence) == 24);
    CHECK(offsetof(FlightChunkHeader, committed_bytes) == 40);
    CHECK(offsetof(FlightChunkHeader, checksum) == 48);
    CHECK(offsetof(FlightEmergencyRecord, type) == 0);
    CHECK(offsetof(FlightEmergencyRecord, tid) == 4);
    CHECK(offsetof(FlightEmergencyRecord, sequence) == 8);
    CHECK(offsetof(FlightEmergencyRecord, pc) == 16);
    CHECK(offsetof(FlightEmergencyRecord, sp) == 24);
    CHECK(offsetof(FlightEmergencyRecord, fault_address) == 32);
    CHECK(offsetof(FlightEmergencyRecord, signal_number) == 40);
    CHECK(offsetof(FlightEmergencyRecord, flags) == 48);

    FlightSuperblock superblock{};
    superblock.magic = kFlightMagic;
    superblock.version = kFlightVersion;
    superblock.byte_order = kFlightByteOrderLittleEndian;
    superblock.pointer_width = kFlightPointerWidth64;
    superblock.header_bytes = kFlightSuperblockBytes;
    superblock.artifact_bytes = 0x0102030405060708ULL;
    superblock.directory_offset = 0x1112131415161718ULL;
    superblock.directory_entry_bytes = kFlightDirectoryEntryBytes;
    superblock.directory_entries = 0x21222324U;
    superblock.chunk_offset = 0x3132333435363738ULL;
    superblock.chunk_bytes = 0x41424344U;
    superblock.chunk_count = 0x51525354U;
    superblock.emergency_offset = 0x6162636465666768ULL;
    superblock.emergency_record_bytes = kFlightEmergencyRecordBytes;
    superblock.emergency_record_count = 0x71727374U;
    superblock.flags = 0x81828384U;
    CHECK(flight_set_superblock_identity(&superblock, identity));

    uint8_t encoded[kFlightSuperblockBytes];
    std::memset(encoded, 0xa5, sizeof(encoded));
    CHECK(encode_flight_superblock_le(superblock, encoded, sizeof(encoded)));
    CHECK(encoded[0] == 0x54 && encoded[1] == 0x4c && encoded[2] == 0x46 && encoded[3] == 0x51);
    CHECK(encoded[4] == 0x01 && encoded[5] == 0x00);
    CHECK(encoded[6] == kFlightByteOrderLittleEndian);
    CHECK(encoded[7] == kFlightPointerWidth64);
    CHECK(encoded[8] == 0x00 && encoded[9] == 0x10);
    CHECK(encoded[16] == 0x08 && encoded[17] == 0x07 && encoded[22] == 0x02 && encoded[23] == 0x01);
    CHECK(encoded[72] == 0x84 && encoded[73] == 0x83 && encoded[74] == 0x82 && encoded[75] == 0x81);
    CHECK(encoded[10] == 0 && encoded[15] == 0 && encoded[76] == 0 &&
          encoded[kFlightSuperblockBytes - 1U] == 0);

    FlightSuperblock decoded{};
    CHECK(decode_flight_superblock_le(encoded, sizeof(encoded), &decoded));
    CHECK(decoded.magic == superblock.magic);
    CHECK(decoded.version == superblock.version);
    CHECK(decoded.byte_order == kFlightByteOrderLittleEndian);
    CHECK(decoded.pointer_width == kFlightPointerWidth64);
    CHECK(decoded.artifact_bytes == superblock.artifact_bytes);
    CHECK(decoded.directory_offset == superblock.directory_offset);
    CHECK(decoded.chunk_offset == superblock.chunk_offset);
    CHECK(decoded.emergency_offset == superblock.emergency_offset);
    CHECK(decoded.flags == superblock.flags);
    encoded[6] = 0;
    CHECK(!decode_flight_superblock_le(encoded, sizeof(encoded), &decoded));

    FlightSuperblock identity_superblock{};
    CHECK(flight_set_superblock_identity(&identity_superblock, identity));
    CHECK(identity_superblock.run_id == identity.run_id);
    CHECK(identity_superblock.pid == identity.pid);
    CHECK(identity_superblock.module_generation == identity.module_generation);
    CHECK(identity_superblock.target_name_bytes == identity.target_name_bytes);
    CHECK(identity_superblock.target_name[0] == 'l');
    CHECK(identity_superblock.target_name[identity.target_name_bytes] == 0);

    identity_superblock.magic = kFlightMagic;
    identity_superblock.version = kFlightVersion;
    identity_superblock.byte_order = kFlightByteOrderLittleEndian;
    identity_superblock.pointer_width = kFlightPointerWidth64;
    identity_superblock.header_bytes = kFlightSuperblockBytes;
    CHECK(encode_flight_superblock_le(identity_superblock, encoded, sizeof(encoded)));
    CHECK(encoded[80] == 0x08 && encoded[81] == 0x07 && encoded[86] == 0x02 &&
          encoded[87] == 0x01);
    CHECK(encoded[88] == 0xd2 && encoded[89] == 0x04);
    CHECK(encoded[92] == 0x07 && encoded[93] == 0x00);
    CHECK(encoded[96] == identity.target_name_bytes && encoded[97] == 0x00);
    CHECK(encoded[kFlightTargetNameOffset] == 'l');
    CHECK(encoded[kFlightTargetNameOffset + identity.target_name_bytes] == 0);
    CHECK(encoded[kFlightSuperblockBytes - 1U] == 0);
    CHECK(decode_flight_superblock_le(encoded, sizeof(encoded), &decoded));
    CHECK(decoded.run_id == identity.run_id);
    CHECK(decoded.pid == identity.pid);
    CHECK(decoded.module_generation == identity.module_generation);
    CHECK(decoded.target_name_bytes == identity.target_name_bytes);
    CHECK(std::memcmp(decoded.target_name, target_name, identity.target_name_bytes) == 0);

    FlightArtifactIdentityView invalid_identity = identity;
    invalid_identity.run_id = 0;
    CHECK(!flight_set_superblock_identity(&identity_superblock, invalid_identity));
    invalid_identity = identity;
    invalid_identity.pid = 0;
    CHECK(!flight_set_superblock_identity(&identity_superblock, invalid_identity));
    invalid_identity = identity;
    invalid_identity.target_name_bytes = 0;
    CHECK(!flight_set_superblock_identity(&identity_superblock, invalid_identity));
    char long_name[kFlightTargetNameBytes + 1]{};
    for (size_t index = 0; index < sizeof(long_name); ++index) long_name[index] = 'x';
    invalid_identity = {identity.run_id, identity.pid, identity.module_generation, long_name,
                        static_cast<uint16_t>(sizeof(long_name))};
    CHECK(!flight_set_superblock_identity(&identity_superblock, invalid_identity));
    char embedded_nul[] = {'a', '\0', 'b'};
    invalid_identity = {identity.run_id, identity.pid, identity.module_generation, embedded_nul,
                        static_cast<uint16_t>(sizeof(embedded_nul))};
    CHECK(!flight_set_superblock_identity(&identity_superblock, invalid_identity));
    encoded[98 + identity.target_name_bytes + 1U] = 1;
    CHECK(!decode_flight_superblock_le(encoded, sizeof(encoded), &decoded));
    encoded[98 + identity.target_name_bytes + 1U] = 0;
    encoded[76] = 1;
    CHECK(!decode_flight_superblock_le(encoded, sizeof(encoded), &decoded));

    uint8_t invalid_encoded[kFlightSuperblockBytes];
    std::memcpy(invalid_encoded, encoded, sizeof(invalid_encoded));
    invalid_encoded[76] = 0;
    std::memset(invalid_encoded + 80, 0, sizeof(uint64_t));
    CHECK(!decode_flight_superblock_le(invalid_encoded, sizeof(invalid_encoded), &decoded));
    std::memcpy(invalid_encoded, encoded, sizeof(invalid_encoded));
    invalid_encoded[76] = 0;
    std::memset(invalid_encoded + 88, 0, sizeof(uint32_t));
    CHECK(!decode_flight_superblock_le(invalid_encoded, sizeof(invalid_encoded), &decoded));
    std::memcpy(invalid_encoded, encoded, sizeof(invalid_encoded));
    invalid_encoded[76] = 0;
    invalid_encoded[96] = 0;
    invalid_encoded[97] = 0;
    CHECK(!decode_flight_superblock_le(invalid_encoded, sizeof(invalid_encoded), &decoded));
    std::memcpy(invalid_encoded, encoded, sizeof(invalid_encoded));
    invalid_encoded[76] = 0;
    invalid_encoded[96] = 129;
    invalid_encoded[97] = 0;
    CHECK(!decode_flight_superblock_le(invalid_encoded, sizeof(invalid_encoded), &decoded));
    std::memcpy(invalid_encoded, encoded, sizeof(invalid_encoded));
    invalid_encoded[76] = 0;
    invalid_encoded[kFlightTargetNameOffset + 1] = 0;
    CHECK(!decode_flight_superblock_le(invalid_encoded, sizeof(invalid_encoded), &decoded));
    CHECK(!decode_flight_superblock_le(nullptr, sizeof(encoded), &decoded));
    CHECK(!decode_flight_superblock_le(encoded, sizeof(encoded), nullptr));

    char maximum_name[kFlightTargetNameBytes];
    std::memset(maximum_name, 'x', sizeof(maximum_name));
    FlightArtifactIdentityView maximum_identity{identity.run_id, identity.pid,
                                                 identity.module_generation, maximum_name,
                                                 kFlightTargetNameBytes};
    FlightSuperblock maximum_superblock = identity_superblock;
    CHECK(flight_set_superblock_identity(&maximum_superblock, maximum_identity));
    std::memset(encoded, 0xa5, sizeof(encoded));
    CHECK(encode_flight_superblock_le(maximum_superblock, encoded, sizeof(encoded)));
    CHECK(encoded[kFlightTargetNameOffset + kFlightTargetNameBytes - 1U] == 'x');
    CHECK(decode_flight_superblock_le(encoded, sizeof(encoded), &decoded));
    CHECK(decoded.target_name_bytes == kFlightTargetNameBytes);
}
