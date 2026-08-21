#include "flight/flight_trace_sink.h"

#include "core/instruction_cache.h"
#include "flight/flight_artifact.h"

#include <QBDI/State.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <array>
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
    static constexpr char kTarget[] = "libsink_target.so";
    return {0x8877665544332211ULL, 4400, 3, kTarget,
            static_cast<uint16_t>(sizeof(kTarget) - 1U)};
}

void maps_all_trace_sink_events_and_fails_closed() {
    char directory_template[] = "/tmp/qtrace-flight-sink-XXXXXX";
    char *created = ::mkdtemp(directory_template);
    CHECK(created != nullptr);
    const std::string path = std::string(created) + "/artifact.flight.bin";
    FlightOptions options;
    options.enabled = true;
    options.capacity_bytes = 8ULL * 1024ULL * 1024ULL;
    options.chunk_bytes = 64U * 1024U;
    options.max_threads = 1;
    options.protected_chunks = 1;
    FlightArtifact artifact;
    CHECK(artifact.create(path.c_str(), options, test_identity()));
    FlightThreadRegistration thread{};
    CHECK(artifact.register_thread(4411, &thread));
    FlightChunkWriter writer;
    CHECK(writer.initialize(&artifact, thread));
    TraceContext context;
    context.scene_name = "sink-scene";
    context.target_so = "libsink_target.so";
    context.module_base = 0x72000000;
    context.target_offset = 0x80;
    context.target_address = context.module_base + context.target_offset;
    context.pid = 4400;
    context.tid = 4411;
    QBDI::GPRState gpr{};
    gpr.pc = context.target_address;
    FlightTraceSink sink;
    CHECK(sink.initialize(&writer, TraceProfile::Full, context, &gpr));
    CHECK(!sink.failed());

    CachedInstruction decoded{};
    decoded.opcode = 0xd503201fU;
    std::memcpy(decoded.mnemonic, "nop", 4);
    std::memcpy(decoded.disassembly, "nop", 4);
    InstructionRecord instruction{};
    instruction.sequence = 7;
    instruction.pc = context.target_address;
    instruction.module_base = context.module_base;
    instruction.decoded = &decoded;
    instruction.memory_count = 1;
    instruction.memory[0].kind = MemoryAccessKind::Read;
    instruction.memory[0].address = 0x1000;
    instruction.memory[0].size = 4;
    instruction.memory[0].before.state = MemoryBytesState::Available;
    instruction.memory[0].before.size = 2;
    instruction.memory[0].before.data[0] = 0xaa;
    instruction.memory[0].before.data[1] = 0xbb;
    CHECK(sink.instruction(context, instruction));

    MemoryRecord overflow = instruction.memory[0];
    overflow.address = 0x2000;
    CHECK(sink.memory(context, instruction.pc, overflow));
    CHECK(sink.call("libc", "malloc", "size=16"));
    CHECK(sink.rule(std::string("rewrite"), std::string("x0=1")));
    CHECK(sink.error(std::string("diagnostic")));

    bool saw_checkpoint = false;
    bool saw_instruction = false;
    size_t memories = 0;
    bool saw_call = false;
    bool saw_rule = false;
    bool saw_error = false;
    const uint8_t *bytes = artifact.chunk_data(writer.chunk_index());
    size_t offset = 0;
    while (offset < writer.committed_bytes()) {
        FlightDecodedRecord record{};
        CHECK(scan_flight_record(bytes + offset, writer.committed_bytes() - offset,
                                 writer.generation(), &record));
        if (record.type == FlightRecordType::RegisterDelta &&
            record.flags == kFlightRegisterCheckpointFlag) saw_checkpoint = true;
        if (record.type == FlightRecordType::Instruction && record.flags == 0)
            saw_instruction = true;
        if (record.type == FlightRecordType::Memory) ++memories;
        if (record.type == FlightRecordType::Call && record.flags == 0) saw_call = true;
        if (record.type == FlightRecordType::Rule && record.flags == 0) saw_rule = true;
        if (record.type == FlightRecordType::Error && record.flags == 0) saw_error = true;
        offset += record.storage_bytes;
    }
    CHECK(saw_checkpoint);
    CHECK(saw_instruction);
    CHECK(memories == 2);
    CHECK(saw_call && saw_rule && saw_error);

    InstructionRecord invalid = instruction;
    invalid.decoded = nullptr;
    CHECK(!sink.instruction(context, invalid));
    CHECK(sink.failed());
    CHECK(!sink.call("ignored", "after failure", "must not write"));

    writer.detach();
    artifact.close();
    CHECK(::unlink(path.c_str()) == 0);
    CHECK(::rmdir(created) == 0);
}

void full_post_state_drives_deltas_and_the_next_rotation_checkpoint() {
    char directory_template[] = "/tmp/qtrace-flight-post-state-XXXXXX";
    char *created = ::mkdtemp(directory_template);
    CHECK(created != nullptr);
    const std::string path = std::string(created) + "/artifact.flight.bin";
    FlightOptions options;
    options.enabled = true;
    options.capacity_bytes = 8ULL * 1024ULL * 1024ULL;
    options.chunk_bytes = 4096;
    options.max_threads = 1;
    options.protected_chunks = 1;
    FlightArtifact artifact;
    CHECK(artifact.create(path.c_str(), options, test_identity()));
    FlightThreadRegistration thread{};
    CHECK(artifact.register_thread(7788, &thread));
    FlightChunkWriter writer;
    CHECK(writer.initialize(&artifact, thread));
    TraceContext context;
    context.target_so = "libsink_target.so";
    context.module_base = 0x72000000;
    context.pid = 4400;
    context.tid = 7788;

    QBDI::GPRState initial{};
    for (size_t index = 0; index < 31; ++index) QBDI_GPR_SET(&initial, index, 100 + index);
    initial.sp = 131;
    initial.pc = context.module_base + 0x40;
    initial.nzcv = 133;
    FlightTraceSink sink;
    CHECK(sink.initialize(&writer, TraceProfile::Full, context, &initial));

    CachedInstruction branch{};
    branch.opcode = 0x14000010;
    branch.write_gpr_mask = 1ULL;
    branch.write_gpr_widths[0] = 8;
    branch.flags = InstructionFlags::Branch;
    std::memcpy(branch.mnemonic, "b", 2);
    std::memcpy(branch.disassembly, "b #0x40", 8);
    InstructionRecord event{};
    event.sequence = 1;
    event.pc = initial.pc;
    event.module_base = context.module_base;
    event.decoded = &branch;
    event.writes.count = 1;
    event.writes.values[0] = 1000;

    RegisterSnapshot post{};
    for (size_t index = 0; index < 31; ++index) post.values[index] = 1000 + index;
    post.values[31] = 1031;
    post.values[32] = 1033;
    post.values[33] = context.module_base + 0x180;
    TraceSink &event_sink = sink;
    CHECK(event_sink.instruction(context, event, post));

    const uint32_t instruction_chunk = writer.chunk_index();
    const uint32_t instruction_generation = writer.generation();
    const uint32_t instruction_bytes = writer.committed_bytes();
    const uint8_t *bytes = artifact.chunk_data(instruction_chunk);
    size_t offset = 0;
    FlightDecodedRecord delta{};
    while (offset < instruction_bytes) {
        FlightDecodedRecord record{};
        CHECK(scan_flight_record(bytes + offset, instruction_bytes - offset,
                                 instruction_generation, &record));
        if (record.type == FlightRecordType::RegisterDelta && record.flags == 0) delta = record;
        offset += record.storage_bytes;
    }
    CHECK(delta.payload != nullptr);
    CHECK(flight_read_u64_le(delta.payload) == kTraceValidGprMask);
    CHECK(delta.payload_bytes == sizeof(uint64_t) + 34U * sizeof(uint64_t));
    for (size_t index = 0; index < 32; ++index) {
        CHECK(flight_read_u64_le(delta.payload + 8U + index * 8U) == 1000 + index);
    }
    CHECK(flight_read_u64_le(delta.payload + 8U + 32U * 8U) ==
          context.module_base + 0x180);
    CHECK(flight_read_u64_le(delta.payload + 8U + 33U * 8U) == 1033);

    const size_t remaining = artifact.chunk_data_capacity() - writer.committed_bytes();
    CHECK(remaining > 48U + kFlightRecordHeaderBytes);
    std::vector<uint8_t> padding(remaining - 48U - kFlightRecordHeaderBytes, 0x5a);
    CHECK(writer.append(FlightRecordType::Rule, padding) == FlightWriteResult::Written);
    CHECK(sink.call("cat", "rotate", "post-state"));
    CHECK(writer.chunk_index() != instruction_chunk);

    bytes = artifact.chunk_data(writer.chunk_index());
    FlightDecodedRecord metadata{};
    FlightDecodedRecord checkpoint{};
    CHECK(scan_flight_record(bytes, writer.committed_bytes(), writer.generation(), &metadata));
    CHECK(scan_flight_record(bytes + metadata.storage_bytes,
                             writer.committed_bytes() - metadata.storage_bytes,
                             writer.generation(), &checkpoint));
    CHECK(checkpoint.type == FlightRecordType::RegisterDelta);
    CHECK(checkpoint.flags == kFlightRegisterCheckpointFlag);
    for (size_t index = 0; index < 32; ++index) {
        CHECK(flight_read_u64_le(checkpoint.payload + index * 8U) == 1000 + index);
    }
    CHECK(flight_read_u64_le(checkpoint.payload + 32U * 8U) ==
          context.module_base + 0x180);
    CHECK(flight_read_u64_le(checkpoint.payload + 33U * 8U) == 1033);

    writer.detach();
    artifact.close();
    CHECK(::unlink(path.c_str()) == 0);
    CHECK(::rmdir(created) == 0);
}

void preserves_large_logical_call_behavior_with_independent_fragments() {
    char directory_template[] = "/tmp/qtrace-flight-large-call-XXXXXX";
    char *created = ::mkdtemp(directory_template);
    CHECK(created != nullptr);
    const std::string path = std::string(created) + "/artifact.flight.bin";
    FlightOptions options;
    options.enabled = true;
    options.capacity_bytes = 8ULL * 1024ULL * 1024ULL;
    options.chunk_bytes = 4096;
    options.max_threads = 1;
    options.protected_chunks = 1;
    FlightArtifact artifact;
    CHECK(artifact.create(path.c_str(), options, test_identity()));
    FlightThreadRegistration thread{};
    CHECK(artifact.register_thread(991, &thread));
    FlightChunkWriter writer;
    CHECK(writer.initialize(&artifact, thread));
    TraceContext context;
    context.target_so = "libsink_target.so";
    context.module_base = 0x72000000;
    context.pid = 4400;
    context.tid = 991;
    QBDI::GPRState gpr{};
    FlightTraceSink sink;
    CHECK(sink.initialize(&writer, TraceProfile::Full, context, &gpr));

    const std::string detail = std::string(3071, 'a') + "\xe2\x82\xac" +
                               std::string(6926, 'z');
    CHECK(sink.call("jni", "large", detail));

    struct Chunk {
        uint32_t index;
        uint32_t generation;
        uint32_t committed;
        uint64_t first_sequence;
    };
    std::vector<Chunk> retained;
    for (uint32_t index = 0; index < artifact.chunk_count(); ++index) {
        FlightChunkSnapshot snapshot{};
        if (!artifact.read_chunk(index, &snapshot) || snapshot.tid != thread.tid) continue;
        const uint32_t committed = index == writer.chunk_index()
                                           ? writer.committed_bytes()
                                           : snapshot.committed_bytes;
        if (committed != 0) {
            retained.push_back({index, snapshot.generation, committed,
                                snapshot.first_sequence});
        }
    }
    std::sort(retained.begin(), retained.end(), [](const Chunk &left, const Chunk &right) {
        return left.first_sequence < right.first_sequence;
    });
    CHECK(retained.size() > 1);

    std::array<std::string, 4> fragments{};
    std::array<bool, 4> seen{};
    size_t fragments_observed = 0;
    size_t fragment_chunks = 0;
    uint64_t event_id = 0;
    for (const Chunk &chunk : retained) {
        std::array<std::string, 257> definitions{};
        std::array<bool, 257> defined{};
        bool chunk_has_fragment = false;
        const uint8_t *bytes = artifact.chunk_data(chunk.index);
        size_t offset = 0;
        while (offset < chunk.committed) {
            FlightDecodedRecord record{};
            CHECK(scan_flight_record(bytes + offset, chunk.committed - offset,
                                     chunk.generation, &record));
            if (record.type == FlightRecordType::Call &&
                record.flags == (kFlightDefinitionFlag | kFlightStringDefinitionFlag)) {
                const uint32_t id = flight_read_u32_le(record.payload);
                const uint32_t size = flight_read_u32_le(record.payload + 4);
                CHECK(id < definitions.size());
                CHECK(8U + size == record.payload_bytes);
                definitions[id].assign(reinterpret_cast<const char *>(record.payload + 8), size);
                defined[id] = true;
            }
            if (record.type == FlightRecordType::Call &&
                record.flags == kFlightCallChunkFlag) {
                chunk_has_fragment = true;
                ++fragments_observed;
                const uint64_t observed_id = flight_read_u64_le(record.payload);
                CHECK(observed_id != 0);
                if (event_id == 0) event_id = observed_id;
                CHECK(observed_id == event_id);
                CHECK(flight_read_u32_le(record.payload + 8) == detail.size());
                const uint16_t index = flight_read_u16_le(record.payload + 12);
                CHECK(index < fragments.size());
                CHECK(flight_read_u16_le(record.payload + 14) == fragments.size());
                const uint32_t category_id = flight_read_u32_le(record.payload + 16);
                const uint32_t name_id = flight_read_u32_le(record.payload + 20);
                const uint32_t detail_id = flight_read_u32_le(record.payload + 24);
                CHECK(category_id < defined.size() && defined[category_id]);
                CHECK(name_id < defined.size() && defined[name_id]);
                CHECK(detail_id < defined.size() && defined[detail_id]);
                CHECK(definitions[category_id] == "jni");
                CHECK(definitions[name_id] == "large");
                fragments[index] = definitions[detail_id];
                seen[index] = true;
            }
            offset += record.storage_bytes;
        }
        if (chunk_has_fragment) ++fragment_chunks;
    }
    CHECK(fragment_chunks > 1);
    CHECK(fragments_observed == fragments.size());
    std::string reconstructed;
    for (size_t index = 0; index < fragments.size(); ++index) {
        CHECK(seen[index]);
        reconstructed += fragments[index];
    }
    CHECK(reconstructed == detail);

    writer.detach();
    artifact.close();
    CHECK(::unlink(path.c_str()) == 0);
    CHECK(::rmdir(created) == 0);
}

} // namespace

int main() {
    maps_all_trace_sink_events_and_fails_closed();
    full_post_state_drives_deltas_and_the_next_rotation_checkpoint();
    preserves_large_logical_call_behavior_with_independent_fragments();
}
