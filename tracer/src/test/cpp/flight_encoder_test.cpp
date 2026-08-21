#include "flight/flight_encoder.h"

#include "core/instruction_cache.h"
#include "flight/flight_artifact.h"
#include "flight/flight_chunk_writer.h"

#include <QBDI/State.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>
#include <vector>

namespace {

void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

FlightArtifactIdentityView test_identity() {
    static constexpr char kTarget[] = "libencoder_target.so";
    return {0x1122334455667788ULL, 7201, 9, kTarget,
            static_cast<uint16_t>(sizeof(kTarget) - 1U)};
}

struct Fixture {
    explicit Fixture(uint32_t chunk_bytes = 64U * 1024U) {
        char directory_template[] = "/tmp/qtrace-flight-encoder-XXXXXX";
        char *created = ::mkdtemp(directory_template);
        CHECK(created != nullptr);
        directory = created;
        path = directory + "/artifact.flight.bin";
        FlightOptions options;
        options.enabled = true;
        options.capacity_bytes = 8ULL * 1024ULL * 1024ULL;
        options.chunk_bytes = chunk_bytes;
        options.max_threads = 2;
        options.protected_chunks = 1;
        CHECK(artifact.create(path.c_str(), options, test_identity()));
        CHECK(artifact.register_thread(731, &thread));
        CHECK(writer.initialize(&artifact, thread));
        context.scene_name = "encoder-scene";
        context.target_so = "libencoder_target.so";
        context.module_base = 0x71000000;
        context.target_offset = 0x1234;
        context.target_address = context.module_base + context.target_offset;
        context.pid = 7201;
        context.tid = 731;
    }

    ~Fixture() {
        writer.detach();
        artifact.close();
        (void)::unlink(path.c_str());
        (void)::rmdir(directory.c_str());
    }

    std::string directory;
    std::string path;
    FlightArtifact artifact;
    FlightThreadRegistration thread{};
    FlightChunkWriter writer;
    TraceContext context;
};

struct Records {
    std::vector<FlightDecodedRecord> values;
};

Records records_in(const Fixture &fixture, uint32_t chunk_index, uint32_t generation,
                   uint32_t committed_bytes) {
    Records result;
    const uint8_t *bytes = fixture.artifact.chunk_data(chunk_index);
    size_t offset = 0;
    while (offset < committed_bytes) {
        FlightDecodedRecord record{};
        CHECK(scan_flight_record(bytes + offset, committed_bytes - offset, generation, &record));
        result.values.push_back(record);
        offset += record.storage_bytes;
    }
    CHECK(offset == committed_bytes);
    return result;
}

CachedInstruction instruction_metadata() {
    CachedInstruction decoded{};
    decoded.opcode = 0xd2800020U;
    decoded.read_gpr_mask = 1ULL << 1U;
    decoded.write_gpr_mask = 1ULL << 0U;
    decoded.read_gpr_widths[1] = 8;
    decoded.write_gpr_widths[0] = 8;
    std::memcpy(decoded.mnemonic, "mov", 4);
    std::memcpy(decoded.operands, "x0, #1", 7);
    std::memcpy(decoded.disassembly, "mov x0, #1", 11);
    std::memcpy(decoded.read_register_names[1], "x1", 3);
    std::memcpy(decoded.write_register_names[0], "x0", 3);
    return decoded;
}

InstructionRecord instruction_record(const TraceContext &context,
                                     const CachedInstruction *decoded) {
    InstructionRecord record{};
    record.sequence = 41;
    record.pc = context.module_base + 0x88;
    record.module_base = context.module_base;
    record.decoded = decoded;
    record.reads.count = 1;
    record.reads.values[0] = 0x1111;
    record.writes.count = 1;
    record.writes.values[0] = 0x2222;
    return record;
}

void second_chunk_has_its_own_metadata_checkpoint_and_definitions() {
    Fixture fixture;
    QBDI::GPRState gpr{};
    gpr.x0 = 10;
    gpr.pc = fixture.context.module_base + 0x88;
    FlightEncoder encoder;
    CHECK(encoder.initialize(&fixture.writer, TraceProfile::Full, fixture.context, &gpr));
    CachedInstruction decoded = instruction_metadata();
    InstructionRecord event = instruction_record(fixture.context, &decoded);
    CHECK(encoder.instruction(fixture.context, event));
    CHECK(encoder.call("jni", "first", "old chunk"));
    const uint32_t discarded_chunk = fixture.writer.chunk_index();

    CHECK(encoder.rotate());
    const uint32_t retained_chunk = fixture.writer.chunk_index();
    CHECK(retained_chunk != discarded_chunk);
    CHECK(encoder.instruction(fixture.context, event));
    CHECK(encoder.call("jni", "second", "retained detail"));

    const Records records = records_in(fixture, retained_chunk, fixture.writer.generation(),
                                       fixture.writer.committed_bytes());
    CHECK(records.values.size() == 8);
    CHECK(records.values[0].type == FlightRecordType::ChunkBegin);
    CHECK(records.values[1].type == FlightRecordType::RegisterDelta);
    CHECK(records.values[1].flags == kFlightRegisterCheckpointFlag);
    CHECK(records.values[1].payload_bytes == kFlightGprCount * sizeof(uint64_t));
    CHECK(records.values[2].type == FlightRecordType::Instruction);
    CHECK(records.values[2].flags == kFlightDefinitionFlag);
    CHECK(records.values[3].type == FlightRecordType::Instruction);
    CHECK(records.values[3].flags == 0);
    CHECK(flight_read_u32_le(records.values[2].payload + 8) == 1);
    CHECK(flight_read_u32_le(records.values[3].payload + 28) == 1);

    for (size_t index = 4; index < 7; ++index) {
        CHECK(records.values[index].type == FlightRecordType::Call);
        CHECK(records.values[index].flags ==
              (kFlightDefinitionFlag | kFlightStringDefinitionFlag));
        CHECK(flight_read_u32_le(records.values[index].payload) == index - 3U);
    }
    CHECK(records.values[7].type == FlightRecordType::Call);
    CHECK(records.values[7].flags == 0);
    CHECK(flight_read_u32_le(records.values[7].payload + 0) == 1);
    CHECK(flight_read_u32_le(records.values[7].payload + 4) == 2);
    CHECK(flight_read_u32_le(records.values[7].payload + 8) == 3);
}

void checkpoint_and_delta_reconstruct_exact_gpr_state_in_artifact_order() {
    Fixture fixture;
    QBDI::GPRState initial{};
    for (size_t index = 0; index < 31; ++index) QBDI_GPR_SET(&initial, index, 1000 + index);
    initial.sp = 2000;
    initial.pc = 3000;
    initial.nzcv = 4000;
    FlightEncoder encoder;
    CHECK(encoder.initialize(&fixture.writer, TraceProfile::Full, fixture.context, &initial));

    QBDI::GPRState changed = initial;
    changed.x0 = 0xa0;
    changed.x19 = 0xb19;
    changed.sp = 0xc31;
    changed.nzcv = 0xd33;
    CHECK(encoder.registers(changed));

    const Records records = records_in(fixture, fixture.writer.chunk_index(),
                                       fixture.writer.generation(),
                                       fixture.writer.committed_bytes());
    CHECK(records.values.size() == 3);
    const FlightDecodedRecord &checkpoint = records.values[1];
    CHECK(checkpoint.flags == kFlightRegisterCheckpointFlag);
    std::array<uint64_t, kFlightGprCount> reconstructed{};
    for (size_t index = 0; index < reconstructed.size(); ++index) {
        reconstructed[index] = flight_read_u64_le(checkpoint.payload + index * 8U);
    }
    CHECK(reconstructed[0] == 1000);
    CHECK(reconstructed[19] == 1019);
    CHECK(reconstructed[31] == 2000);
    CHECK(reconstructed[32] == 3000);
    CHECK(reconstructed[33] == 4000);

    const FlightDecodedRecord &delta = records.values[2];
    CHECK(delta.flags == 0);
    const uint64_t expected_mask = (1ULL << 0U) | (1ULL << 19U) | (1ULL << 31U) |
                                   (1ULL << 33U);
    CHECK(flight_read_u64_le(delta.payload) == expected_mask);
    CHECK(delta.payload_bytes == 8U + 4U * sizeof(uint64_t));
    CHECK(flight_read_u64_le(delta.payload + 8) == changed.x0);
    CHECK(flight_read_u64_le(delta.payload + 16) == changed.x19);
    CHECK(flight_read_u64_le(delta.payload + 24) == changed.sp);
    CHECK(flight_read_u64_le(delta.payload + 32) == changed.nzcv);
}

void memory_payload_preserves_full_profile_pre_and_post_bytes() {
    Fixture fixture;
    QBDI::GPRState gpr{};
    FlightEncoder encoder;
    CHECK(encoder.initialize(&fixture.writer, TraceProfile::Full, fixture.context, &gpr));
    MemoryRecord memory{};
    memory.kind = MemoryAccessKind::ReadWrite;
    memory.metadata_available = true;
    memory.flags = 0x1234;
    memory.address = 0xfeed0000;
    memory.size = 8;
    memory.value = 0x8877665544332211ULL;
    memory.before.state = MemoryBytesState::Available;
    memory.before.size = 3;
    memory.before.data[0] = 0x10;
    memory.before.data[1] = 0x11;
    memory.before.data[2] = 0x12;
    memory.after.state = MemoryBytesState::Available;
    memory.after.size = 2;
    memory.after.data[0] = 0x20;
    memory.after.data[1] = 0x21;
    CHECK(encoder.memory(fixture.context, fixture.context.module_base + 0x44, memory));

    const Records records = records_in(fixture, fixture.writer.chunk_index(),
                                       fixture.writer.generation(),
                                       fixture.writer.committed_bytes());
    CHECK(records.values.size() == 3);
    const FlightDecodedRecord &encoded = records.values[2];
    CHECK(encoded.type == FlightRecordType::Memory);
    CHECK(flight_read_u16_le(encoded.payload + 0) == 5);
    CHECK(flight_read_u32_le(encoded.payload + 4) == 45);
    CHECK(encoded.payload[44] == static_cast<uint8_t>(MemoryBytesState::Available));
    CHECK(encoded.payload[45] == 3);
    CHECK(encoded.payload[46] == 0x10 && encoded.payload[48] == 0x12);
    CHECK(encoded.payload[49] == static_cast<uint8_t>(MemoryBytesState::Available));
    CHECK(encoded.payload[50] == 2);
    CHECK(encoded.payload[51] == 0x20 && encoded.payload[52] == 0x21);
}

void no_fit_rotates_once_and_never_publishes_a_partial_record() {
    Fixture fixture(512);
    QBDI::GPRState gpr{};
    FlightEncoder encoder;
    CHECK(encoder.initialize(&fixture.writer, TraceProfile::Full, fixture.context, &gpr));
    const uint32_t first_chunk = fixture.writer.chunk_index();
    CHECK(!encoder.call("a", "b", std::string(100, 'c')));
    CHECK(encoder.failed());
    CHECK(fixture.writer.chunk_index() != first_chunk);

    const Records records = records_in(fixture, fixture.writer.chunk_index(),
                                       fixture.writer.generation(),
                                       fixture.writer.committed_bytes());
    CHECK(records.values.size() == 3);
    CHECK(records.values[0].type == FlightRecordType::ChunkBegin);
    CHECK(records.values[1].type == FlightRecordType::RegisterDelta);
    CHECK(records.values[1].flags == kFlightRegisterCheckpointFlag);
    CHECK(records.values[2].type == FlightRecordType::Call);
    CHECK(records.values[2].flags ==
          (kFlightDefinitionFlag | kFlightStringDefinitionFlag));
}

} // namespace

int main() {
    second_chunk_has_its_own_metadata_checkpoint_and_definitions();
    checkpoint_and_delta_reconstruct_exact_gpr_state_in_artifact_order();
    memory_payload_preserves_full_profile_pre_and_post_bytes();
    no_fit_rotates_once_and_never_publishes_a_partial_record();
}
