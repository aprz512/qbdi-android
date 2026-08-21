#include "flight/flight_trace_sink.h"

#include "core/instruction_cache.h"
#include "flight/flight_artifact.h"

#include <QBDI/State.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>

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

void preserves_large_logical_call_behavior_with_independent_fragments() {
    char directory_template[] = "/tmp/qtrace-flight-large-call-XXXXXX";
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

    const std::string detail(5000, 'z');
    CHECK(sink.call("jni", "large", detail));

    size_t chunks = 0;
    uint64_t event_id = 0;
    const uint8_t *bytes = artifact.chunk_data(writer.chunk_index());
    size_t offset = 0;
    while (offset < writer.committed_bytes()) {
        FlightDecodedRecord record{};
        CHECK(scan_flight_record(bytes + offset, writer.committed_bytes() - offset,
                                 writer.generation(), &record));
        if (record.type == FlightRecordType::Call &&
            record.flags == kFlightCallChunkFlag) {
            ++chunks;
            const uint64_t observed_id = flight_read_u64_le(record.payload);
            CHECK(observed_id != 0);
            if (event_id == 0) event_id = observed_id;
            CHECK(observed_id == event_id);
            CHECK(flight_read_u32_le(record.payload + 8) == detail.size());
            CHECK(flight_read_u16_le(record.payload + 14) == 2);
        }
        offset += record.storage_bytes;
    }
    CHECK(chunks == 2);

    writer.detach();
    artifact.close();
    CHECK(::unlink(path.c_str()) == 0);
    CHECK(::rmdir(created) == 0);
}

} // namespace

int main() {
    maps_all_trace_sink_events_and_fails_closed();
    preserves_large_logical_call_behavior_with_independent_fragments();
}
