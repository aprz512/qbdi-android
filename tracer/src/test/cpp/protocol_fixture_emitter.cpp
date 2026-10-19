// Deterministic compatibility artifacts from the production encoders. No decoder lives here.
#include "core/instruction_cache.h"
#include "events/binary_trace_encoder.h"
#include "flight/flight_encoder.h"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace {
void require(bool value) {
    if (!value) {
        std::fprintf(stderr, "protocol fixture encoder failed\n");
        std::exit(1);
    }
}

TraceContext context() {
    TraceContext value{};
    value.scene_name = "native-\xe4\xb8\xad\n\"scene";
    value.target_so = "libnative.so";
    value.module_base = 0x71000000;
    value.target_offset = 0x88;
    value.target_address = value.module_base + value.target_offset;
    value.pid = 7201;
    value.tid = 731;
    return value;
}

CachedInstruction definition() {
    CachedInstruction value{};
    value.opcode = 0x91000420;
    value.read_gpr_mask = 1ULL << 1U;
    value.write_gpr_mask = 1ULL;
    value.read_gpr_widths[1] = 8;
    value.write_gpr_widths[0] = 4;
    std::strcpy(value.read_register_names[1], "X1");
    std::strcpy(value.write_register_names[0], "W0");
    std::strcpy(value.mnemonic, "ADD");
    std::strcpy(value.operands, "w0, w1, #1");
    std::strcpy(value.disassembly, "ADD w0, w1, #1");
    value.memory_operand_count = 1;
    value.memory_operands[0].base_reg = 1;
    value.memory_operands[0].kind = MemoryAccessKind::Read;
    value.memory_operands[0].access_size = 8;
    value.memory_operands[0].displacement = -16;
    return value;
}

InstructionRecord instruction(const TraceContext &ctx, const CachedInstruction &decoded) {
    InstructionRecord value{};
    value.sequence = 1;
    value.module_base = ctx.module_base;
    value.pc = ctx.target_address;
    value.decoded = &decoded;
    value.reads.count = value.writes.count = 1;
    value.reads.values[0] = 0x1234;
    value.writes.values[0] = 0x1235;
    return value;
}

MemoryRecord memory() {
    MemoryRecord value{};
    value.kind = MemoryAccessKind::ReadWrite;
    value.metadata_available = true;
    value.address = 0x223344;
    value.size = 8;
    value.value = 0x1235;
    value.before.state = MemoryBytesState::Available;
    value.before.size = 2;
    value.before.data[0] = 0;
    value.before.data[1] = 0xff;
    value.after.state = MemoryBytesState::Unavailable;
    return value;
}

void write(const std::filesystem::path &path, const std::vector<uint8_t> &bytes) {
    std::ofstream output(path, std::ios::binary);
    output.write(reinterpret_cast<const char *>(bytes.data()), bytes.size());
    require(output.good());
}

void qtrb(const std::filesystem::path &path, bool stopped) {
    const BinaryTraceEncoder encoder;
    const TraceContext ctx = context();
    const CachedInstruction decoded = definition();
    const InstructionRecord event = instruction(ctx, decoded);
    std::array<uint8_t, kBinaryMaxRecordBytes> scratch{};
    std::vector<uint8_t> bytes;
    auto append = [&](BinaryEncodeResult result) {
        require(result.ok);
        bytes.insert(bytes.end(), scratch.begin(), scratch.begin() + result.size);
    };
    append(encoder.encode_stream_header(scratch.data(), scratch.size(), TraceProfile::Full));
    TraceBeginInfo info{};
    info.profile = TraceProfile::Full;
    info.compression_enabled = false;
    info.run_id = 0x11223344;
    info.effective_buffer_bytes = 4096;
    append(encoder.encode_begin(scratch.data(), scratch.size(), ctx, info));
    append(encoder.encode_module_definition(scratch.data(), scratch.size(), 1,
                                             ctx.target_so, ctx.module_base));
    append(encoder.encode_instruction_definition(scratch.data(), scratch.size(), 1, decoded));
    append(encoder.encode_instruction(scratch.data(), scratch.size(), 1, 1, event));
    append(encoder.encode_memory(scratch.data(), scratch.size(), 1, 0x88, memory()));
    append(encoder.encode_call(scratch.data(), scratch.size(), "jni", "native", "line\n\"utf8: \xe2\x82\xac"));
    // Split a UTF-8 code point across raw fragments; both readers must reassemble first.
    append(encoder.encode_call_chunk(scratch.data(), scratch.size(), {1, 3, 0, 2},
                                     "jni", "chunk", std::string_view("\xe2", 1)));
    append(encoder.encode_call_chunk(scratch.data(), scratch.size(), {1, 3, 1, 2},
                                     "jni", "chunk", std::string_view("\x82\xac", 2)));
    append(encoder.encode_event_chunk(scratch.data(), scratch.size(), BinaryRecordType::Rule,
                                      {2, 3, 0, 2}, "guard", std::string_view("\xe2", 1)));
    append(encoder.encode_event_chunk(scratch.data(), scratch.size(), BinaryRecordType::Rule,
                                      {2, 3, 1, 2}, "guard", std::string_view("\x82\xac", 2)));
    append(encoder.encode_event(scratch.data(), scratch.size(), BinaryRecordType::Error,
                                "native-error", "detail"));
    TraceMetrics metrics{};
    metrics.instructions = 1;
    metrics.encoded_bytes = bytes.size() + (stopped ? kBinaryTraceStopRecordBytes : kBinaryTraceEndRecordBytes);
    metrics.compressed_bytes = metrics.encoded_bytes;
    metrics.effective_buffer_bytes = 4096;
    if (stopped) {
        append(encoder.encode_stop(scratch.data(), scratch.size(), TraceStopReason::DurationElapsed, 17, metrics));
    } else {
        append(encoder.encode_end(scratch.data(), scratch.size(), true, 0x55, 17, metrics));
    }
    require(bytes.size() == metrics.encoded_bytes);
    write(path, bytes);
}

void flight(const std::filesystem::path &path, bool sealed) {
    const TraceContext ctx = context();
    FlightOptions options{};
    options.enabled = true;
    options.capacity_bytes = 64 * 1024;
    options.chunk_bytes = 4096;
    options.max_threads = 2;
    options.protected_chunks = 1;
    FlightArtifact artifact;
    const FlightArtifactIdentityView identity{0x11223344, 7201, 9, "libnative.so", 12};
    require(artifact.create(path.c_str(), options, identity));
    FlightThreadRegistration thread{};
    require(artifact.register_thread(ctx.tid, &thread));
    FlightChunkWriter writer;
    require(writer.initialize(&artifact, thread));
    QBDI::GPRState registers{};
    registers.x1 = 0x1234;
    registers.pc = ctx.target_address;
    FlightEncoder encoder;
    require(encoder.initialize(&writer, TraceProfile::Full, ctx, &registers));
    require(encoder.thread_begin(701, ctx.tid, ctx.target_address, 9));
    const CachedInstruction decoded = definition();
    require(encoder.instruction(ctx, instruction(ctx, decoded)));
    require(encoder.memory(ctx, ctx.target_address, memory()));
    require(encoder.call("jni", "native", "line\n\"utf8: \xe2\x82\xac"));
    require(encoder.rule("guard", "native-\xe4\xb8\xad"));
    require(encoder.error("native-error"));
    require(encoder.thread_end(ctx.tid));
    if (sealed) require(writer.seal());
    writer.detach();
    artifact.close();
}

void constants(const std::filesystem::path &path) {
    std::ofstream out(path);
    out << "{\n\"qtrb\":{"
        << "\"major\":" << unsigned(kBinaryTraceMajorVersion)
        << ",\"minor\":" << unsigned(kBinaryTraceMinorVersion)
        << ",\"features\":" << kBinaryRequiredFeatures
        << ",\"stream_header\":" << kBinaryStreamHeaderBytes
        << ",\"record_header\":" << kBinaryRecordHeaderBytes
        << ",\"instruction_fixed\":" << kBinaryInstructionFixedPayloadBytes
        << ",\"definition_fixed\":" << kBinaryInstructionDefinitionFixedPayloadBytes
        << ",\"memory_operand\":" << kBinaryEncodedMemoryOperandBytes
        << ",\"end_payload\":" << kBinaryTraceEndPayloadBytes
        << ",\"stop_payload\":" << kBinaryTraceStopPayloadBytes
        << ",\"max_record\":" << kBinaryMaxRecordBytes
        << "},\n\"flight\":{\"version\":" << kFlightVersion
        << ",\"superblock\":" << kFlightSuperblockBytes
        << ",\"directory_entry\":" << kFlightDirectoryEntryBytes
        << ",\"chunk_header\":" << kFlightChunkHeaderBytes
        << ",\"record_header\":" << kFlightRecordHeaderBytes
        << ",\"emergency_record\":" << kFlightEmergencyRecordBytes
        << ",\"emergency_slot\":" << kFlightEmergencySlotBytes
        << ",\"record_commit\":" << kFlightRecordCommit << "}\n}\n";
    require(out.good());
}
} // namespace

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    const std::filesystem::path output(argv[1]);
    std::filesystem::create_directories(output);
    qtrb(output / "qtrb-completed.bin", false);
    qtrb(output / "qtrb-stopped.bin", true);
    flight(output / "flight-active.bin", false);
    flight(output / "flight-sealed.bin", true);
    constants(output / "constants.json");
    return 0;
}
