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

void thread_lifecycle_records_preserve_exact_identity_fields() {
    Fixture fixture;
    QBDI::GPRState initial{};
    FlightEncoder encoder;
    CHECK(encoder.initialize(&fixture.writer, TraceProfile::Full,
                             fixture.context, &initial));
    constexpr uint32_t creator_tid = 701;
    constexpr uint32_t worker_tid = 731;
    constexpr uintptr_t start_routine = 0x71004568;
    constexpr uint32_t module_generation = 9;
    CHECK(encoder.thread_begin(creator_tid, worker_tid, start_routine,
                               module_generation));
    CHECK(encoder.thread_end(worker_tid));
    CHECK(fixture.writer.seal());

    FlightChunkSnapshot snapshot{};
    CHECK(fixture.artifact.read_chunk(fixture.writer.chunk_index(), &snapshot));
    CHECK(snapshot.state == FlightChunkState::Sealed);

    const Records records = records_in(
            fixture, fixture.writer.chunk_index(), fixture.writer.generation(),
            fixture.writer.committed_bytes());
    CHECK(records.values.size() == 4);
    const FlightDecodedRecord &begin = records.values[2];
    CHECK(begin.type == FlightRecordType::ThreadBegin);
    CHECK(begin.flags == 0);
    CHECK(begin.payload_bytes == 24);
    CHECK(flight_read_u32_le(begin.payload) == creator_tid);
    CHECK(flight_read_u32_le(begin.payload + 4) == worker_tid);
    CHECK(flight_read_u64_le(begin.payload + 8) == start_routine);
    CHECK(flight_read_u64_le(begin.payload + 16) == module_generation);
    const FlightDecodedRecord &end = records.values[3];
    CHECK(end.type == FlightRecordType::ThreadEnd);
    CHECK(end.flags == 0);
    CHECK(end.payload_bytes == 4);
    CHECK(flight_read_u32_le(end.payload) == worker_tid);
}

void active_incomplete_thread_stream_is_recoverable_without_cleanup() {
    Fixture fixture;
    QBDI::GPRState initial{};
    FlightEncoder encoder;
    CHECK(encoder.initialize(&fixture.writer, TraceProfile::Full,
                             fixture.context, &initial));
    CHECK(encoder.thread_begin(701, fixture.thread.tid, 0x71004568, 9));
    CHECK(encoder.call("pthread", "worker", "active-before-crash"));
    fixture.artifact.mark_incomplete(FlightIncompleteReason::WriterFailure);

    FlightChunkSnapshot snapshot{};
    CHECK(fixture.artifact.read_chunk(fixture.writer.chunk_index(), &snapshot));
    CHECK(snapshot.state == FlightChunkState::Active);
    CHECK(snapshot.committed_bytes == 0);
    CHECK(fixture.artifact.incomplete());

    const Records records = records_in(fixture, snapshot.chunk_index,
                                       snapshot.generation,
                                       fixture.writer.committed_bytes());
    CHECK(records.values.size() == 7);
    CHECK(records.values[0].type == FlightRecordType::ChunkBegin);
    CHECK(records.values[1].type == FlightRecordType::RegisterDelta);
    CHECK(records.values[2].type == FlightRecordType::ThreadBegin);
    CHECK(records.values[6].type == FlightRecordType::Call);
    for (const FlightDecodedRecord &record : records.values) {
        CHECK(record.type != FlightRecordType::ThreadEnd);
    }
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

void instruction_rotation_checkpoints_pre_state_then_emits_post_state_delta() {
    Fixture fixture(1024);
    QBDI::GPRState live{};
    live.x0 = 0x11;
    live.pc = fixture.context.module_base + 0x88;
    FlightEncoder encoder;
    CHECK(encoder.initialize(&fixture.writer, TraceProfile::Full, fixture.context, &live));
    const uint32_t old_chunk = fixture.writer.chunk_index();
    const size_t remaining = fixture.artifact.chunk_data_capacity() -
                             fixture.writer.committed_bytes();
    CHECK(remaining > 184);
    std::vector<uint8_t> padding(remaining - 160U - kFlightRecordHeaderBytes, 0x5a);
    CHECK(fixture.writer.append(FlightRecordType::Rule, padding) ==
          FlightWriteResult::Written);

    CachedInstruction decoded = instruction_metadata();
    InstructionRecord event = instruction_record(fixture.context, &decoded);
    event.writes.values[0] = 0x99;
    live.x0 = 0x99;
    CHECK(encoder.instruction(fixture.context, event));
    CHECK(fixture.writer.chunk_index() != old_chunk);

    const Records records = records_in(fixture, fixture.writer.chunk_index(),
                                       fixture.writer.generation(),
                                       fixture.writer.committed_bytes());
    CHECK(records.values.size() == 5);
    CHECK(records.values[0].type == FlightRecordType::ChunkBegin);
    CHECK(records.values[1].type == FlightRecordType::RegisterDelta);
    CHECK(records.values[1].flags == kFlightRegisterCheckpointFlag);
    CHECK(flight_read_u64_le(records.values[1].payload) == 0x11);
    CHECK(records.values[3].type == FlightRecordType::Instruction);
    CHECK(records.values[3].flags == 0);
    CHECK(records.values[4].type == FlightRecordType::RegisterDelta);
    CHECK(flight_read_u64_le(records.values[4].payload) == 1);
    CHECK(flight_read_u64_le(records.values[4].payload + 8) == 0x99);
}

void explicit_rotation_uses_the_latest_owned_register_snapshot() {
    Fixture fixture;
    QBDI::GPRState initialization_object{};
    for (size_t index = 0; index < 31; ++index) {
        QBDI_GPR_SET(&initialization_object, index, 100 + index);
    }
    initialization_object.sp = 131;
    initialization_object.pc = 132;
    initialization_object.nzcv = 133;
    FlightEncoder encoder;
    CHECK(encoder.initialize(&fixture.writer, TraceProfile::Full, fixture.context,
                             &initialization_object));

    QBDI::GPRState latest = initialization_object;
    for (size_t index = 0; index < 31; ++index) QBDI_GPR_SET(&latest, index, 1000 + index);
    latest.sp = 1031;
    latest.pc = 1032;
    latest.nzcv = 1033;
    CHECK(encoder.registers(latest));
    std::memset(&initialization_object, 0xee, sizeof(initialization_object));
    CHECK(encoder.rotate());

    const Records records = records_in(fixture, fixture.writer.chunk_index(),
                                       fixture.writer.generation(),
                                       fixture.writer.committed_bytes());
    CHECK(records.values.size() == 2);
    CHECK(records.values[1].flags == kFlightRegisterCheckpointFlag);
    for (size_t index = 0; index < kFlightGprCount; ++index) {
        CHECK(flight_read_u64_le(records.values[1].payload + index * 8U) == 1000 + index);
    }
}

void rejects_module_metadata_mismatches_in_instruction_and_memory_events() {
    {
        Fixture fixture;
        QBDI::GPRState initial{};
        FlightEncoder encoder;
        CHECK(encoder.initialize(&fixture.writer, TraceProfile::Full, fixture.context, &initial));
        CachedInstruction decoded = instruction_metadata();
        InstructionRecord event = instruction_record(fixture.context, &decoded);
        event.module_base -= 0x1000;
        CHECK(!encoder.instruction(fixture.context, event));
        CHECK(encoder.failed());
    }
    {
        Fixture fixture;
        QBDI::GPRState initial{};
        FlightEncoder encoder;
        CHECK(encoder.initialize(&fixture.writer, TraceProfile::Full, fixture.context, &initial));
        TraceContext mismatch = fixture.context;
        mismatch.module_base -= 0x1000;
        MemoryRecord memory{};
        CHECK(!encoder.memory(mismatch, fixture.context.module_base + 0x44, memory));
        CHECK(encoder.failed());
    }
}

void preamble_capacity_failure_commits_neither_metadata_nor_checkpoint() {
    Fixture fixture(512);
    fixture.context.target_so.assign(100, 't');
    fixture.context.scene_name.assign(100, 's');
    QBDI::GPRState initial{};
    FlightEncoder encoder;
    CHECK(!encoder.initialize(&fixture.writer, TraceProfile::Full, fixture.context, &initial));
    CHECK(fixture.writer.committed_bytes() == 0);
    CHECK(fixture.writer.record_count() == 0);
}

void colliding_instruction_dictionary_rotates_after_all_256_slots_are_used() {
    Fixture fixture(1024U * 1024U);
    QBDI::GPRState initial{};
    FlightEncoder encoder;
    CHECK(encoder.initialize(&fixture.writer, TraceProfile::Full, fixture.context, &initial));
    const uint32_t first_chunk = fixture.writer.chunk_index();
    CachedInstruction decoded{};
    std::memcpy(decoded.mnemonic, "nop", 4);
    std::memcpy(decoded.disassembly, "nop", 4);
    InstructionRecord event{};
    event.pc = fixture.context.module_base + 4;
    event.module_base = fixture.context.module_base;
    event.decoded = &decoded;
    for (uint32_t index = 0; index < 257; ++index) {
        // These opcodes share the same low byte and therefore the same initial table slot.
        decoded.opcode = 1U + index * 256U;
        event.sequence = index + 1U;
        CHECK(encoder.instruction(fixture.context, event));
    }
    CHECK(fixture.writer.chunk_index() != first_chunk);
    const Records records = records_in(fixture, fixture.writer.chunk_index(),
                                       fixture.writer.generation(),
                                       fixture.writer.committed_bytes());
    CHECK(records.values.size() == 4);
    CHECK(records.values[2].flags == kFlightDefinitionFlag);
    CHECK(flight_read_u32_le(records.values[2].payload + 8) == 1);
    CHECK(records.values[3].flags == 0);
}

void string_pool_exhaustion_rotates_and_restarts_local_ids() {
    Fixture fixture(1024U * 1024U);
    QBDI::GPRState initial{};
    FlightEncoder encoder;
    CHECK(encoder.initialize(&fixture.writer, TraceProfile::Full, fixture.context, &initial));
    const uint32_t first_chunk = fixture.writer.chunk_index();
    for (size_t index = 0; index < 6; ++index) {
        std::string name = "rule-" + std::to_string(index);
        std::string detail(3000, static_cast<char>('a' + index));
        CHECK(encoder.rule(name, detail));
    }
    CHECK(fixture.writer.chunk_index() != first_chunk);
    const Records records = records_in(fixture, fixture.writer.chunk_index(),
                                       fixture.writer.generation(),
                                       fixture.writer.committed_bytes());
    CHECK(records.values.size() == 5);
    CHECK(records.values[2].flags ==
          (kFlightDefinitionFlag | kFlightStringDefinitionFlag));
    CHECK(flight_read_u32_le(records.values[2].payload) == 1);
    CHECK(records.values[3].flags ==
          (kFlightDefinitionFlag | kFlightStringDefinitionFlag));
    CHECK(flight_read_u32_le(records.values[3].payload) == 2);
    CHECK(records.values[4].type == FlightRecordType::Rule);
    CHECK(records.values[4].flags == 0);
}

void writer_state_errors_fail_without_rotating() {
    Fixture fixture;
    QBDI::GPRState initial{};
    FlightEncoder encoder;
    CHECK(encoder.initialize(&fixture.writer, TraceProfile::Full, fixture.context, &initial));
    const uint32_t chunk = fixture.writer.chunk_index();
    CHECK(fixture.writer.seal());
    CHECK(!encoder.call("category", "name", "detail"));
    CHECK(encoder.failed());
    CHECK(fixture.writer.chunk_index() == chunk);
}

} // namespace

int main() {
    second_chunk_has_its_own_metadata_checkpoint_and_definitions();
    checkpoint_and_delta_reconstruct_exact_gpr_state_in_artifact_order();
    thread_lifecycle_records_preserve_exact_identity_fields();
    active_incomplete_thread_stream_is_recoverable_without_cleanup();
    memory_payload_preserves_full_profile_pre_and_post_bytes();
    no_fit_rotates_once_and_never_publishes_a_partial_record();
    instruction_rotation_checkpoints_pre_state_then_emits_post_state_delta();
    explicit_rotation_uses_the_latest_owned_register_snapshot();
    rejects_module_metadata_mismatches_in_instruction_and_memory_events();
    preamble_capacity_failure_commits_neither_metadata_nor_checkpoint();
    colliding_instruction_dictionary_rotates_after_all_256_slots_are_used();
    string_pool_exhaustion_rotates_and_restarts_local_ids();
    writer_state_errors_fail_without_rotating();
}
