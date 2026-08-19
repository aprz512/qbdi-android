#include "events/trace_encoder.h"

#include <array>
#include <cassert>
#include <cstring>
#include <limits>
#include <string_view>

namespace {

InstructionRecord instruction_record() {
    CachedInstruction decoded{};
    std::strcpy(decoded.mnemonic, "add");
    std::strcpy(decoded.operands, "x0, x1, x2");
    decoded.read_gpr_mask = (1ULL << 1U) | (1ULL << 2U);
    decoded.write_gpr_mask = 1ULL;

    InstructionRecord record{};
    record.sequence = 7;
    record.pc = 0x1010;
    record.module_base = 0x1000;
    record.decoded = &decoded;
    record.before[1] = 2;
    record.before[2] = 3;
    record.after[0] = 5;

    // The decoder lives for the duration of each test through this static fixture.
    static CachedInstruction fixture = decoded;
    record.decoded = &fixture;
    return record;
}

void encodes_instruction_exactly() {
    const InstructionRecord record = instruction_record();

    char output[256]{};
    TraceEncoder encoder;
    EncodeResult result = encoder.encode_instruction(output, sizeof(output), "libx.so", record);
    assert(result.ok);
    assert(std::string_view(output, result.size) ==
           "7 libx.so+0x10 add x0, x1, x2 | R:X1=0x2 X2=0x3 | W:X0=0x5\n");
}

void preserves_architecture_register_display_names() {
    static CachedInstruction decoded{};
    std::strcpy(decoded.mnemonic, "mov");
    decoded.read_gpr_mask = (1ULL << 0U) | (1ULL << 30U) | (1ULL << 31U);
    decoded.write_gpr_mask = (1ULL << 32U) | (1ULL << 33U);

    InstructionRecord record{};
    record.sequence = 8;
    record.pc = 0x1020;
    record.module_base = 0x1000;
    record.decoded = &decoded;
    record.register_names[0] = "W0";
    record.register_names[30] = "LR";
    record.register_names[31] = "SP";
    record.register_names[32] = "NZCV";
    record.register_names[33] = "PC";
    record.before[0] = 1;
    record.before[30] = 2;
    record.before[31] = 3;
    record.after[32] = 4;
    record.after[33] = 5;

    char output[256]{};
    TraceEncoder encoder;
    const EncodeResult result =
        encoder.encode_instruction(output, sizeof(output), "libx.so", record);
    assert(result.ok);
    assert(std::string_view(output, result.size) ==
           "8 libx.so+0x20 mov | R:W0=0x1 LR=0x2 SP=0x3 | W:NZCV=0x4 PC=0x5\n");
}

void encodes_memory_event_exactly() {
    MemoryRecord memory{};
    memory.type = 'w';
    memory.address = 0x2000;
    memory.size = 8;
    memory.value = 0x42;

    char output[256]{};
    TraceEncoder encoder;
    const EncodeResult result =
        encoder.encode_memory(output, sizeof(output), "libx.so", 0x10, memory);
    assert(result.ok);
    assert(std::string_view(output, result.size) ==
           "MEM libx.so+0x10 type=w addr=0x2000 size=8 value=0x42\n");
}

void rejects_insufficient_instruction_buffer_without_writing() {
    const InstructionRecord record = instruction_record();
    char tiny[8];
    std::memset(tiny, '#', sizeof(tiny));

    TraceEncoder encoder;
    const EncodeResult result = encoder.encode_instruction(tiny, sizeof(tiny), "libx.so", record);
    assert(!result.ok);
    assert(result.size > sizeof(tiny));
    for (char c: tiny) assert(c == '#');
}

void encodes_begin_end_and_semantic_event() {
    TraceContext context{};
    context.scene_name = "demo";
    context.target_so = "libx.so";
    context.target_offset = 0x10;
    context.module_base = 0x1000;
    context.target_address = 0x1010;
    context.pid = 12;
    context.tid = 34;
    TraceMetrics metrics{};
    metrics.instructions = 9;
    metrics.raw_bytes = 300;
    metrics.cache_hits = 9;
    metrics.cache_misses = 1;
    metrics.buffer_swaps = 4;
    metrics.producer_waits = 2;
    metrics.producer_wait_ns = 75;
    TraceEncoder encoder;
    char output[512]{};

    EncodeResult result = encoder.encode_begin(output, sizeof(output), context, TraceProfile::Balanced,
                                                true, 4096);
    assert(result.ok);
    assert(std::string_view(output, result.size) ==
           "TRACE_BEGIN format=2 scene=demo target=libx.so+0x10 base=0x1000 address=0x1010 pid=12 tid=34 profile=balanced compression=1 effective_buffer_bytes=4096\n");

    result = encoder.encode_end(output, sizeof(output), true, 0x42, 7, metrics);
    assert(result.ok);
    assert(std::string_view(output, result.size) ==
           "TRACE_END status=ok ret=0x42 elapsed_ms=7 instructions=9 raw_bytes=300 cache_hit_rate=0.900000 buffer_swaps=4 producer_waits=2 producer_wait_ns=75\n");

    result = encoder.encode_event(output, sizeof(output), "CALL", "jni.find", "resolved");
    assert(result.ok);
    assert(std::string_view(output, result.size) == "CALL jni.find resolved\n");
}

void bounds_memory_hexdump_and_null_inputs() {
    InstructionRecord record{};
    record.sequence = 1;
    record.pc = 0x1000;
    record.module_base = 0x1000;
    record.memory_count = static_cast<uint8_t>(kMaxMemoryRecords + 1U);
    for (size_t i = 0; i < kMaxMemoryRecords; ++i) {
        record.memory[i].type = 'w';
        record.memory[i].address = 0x2000 + i;
        record.memory[i].size = 4;
        record.memory[i].value = i;
        record.memory[i].hexdump_size = static_cast<uint8_t>(kMaxHexdumpBytes + 1U);
        for (size_t j = 0; j < kMaxHexdumpBytes; ++j) record.memory[i].hexdump[j] = 0xab;
    }

    char output[kMaxInstructionLineBytes]{};
    TraceEncoder encoder;
    const EncodeResult result = encoder.encode_instruction(output, sizeof(output), nullptr, record);
    assert(result.ok);
    const std::string_view text(output, result.size);
    assert(text.starts_with("1 <unknown>+0x0 <undecoded>"));
    assert(text.find("MEM:w addr=0x2000 size=4 value=0x0 hex=abab") != std::string_view::npos);
    assert(text.find("MEM:w addr=0x2008") == std::string_view::npos);
    const size_t first_hex = text.find(" hex=");
    const size_t second_memory = text.find(" | MEM:", first_hex);
    assert(first_hex != std::string_view::npos);
    assert(second_memory - (first_hex + 5U) == kMaxHexdumpBytes * 2U);
}

void rejects_overflowing_records() {
    const InstructionRecord record = instruction_record();
    char output[1] = {'!'};
    TraceEncoder encoder;
    const EncodeResult result = encoder.encode_instruction(output, sizeof(output), "module", record);
    assert(!result.ok);
    assert(result.size > sizeof(output));
    assert(output[0] == '!');
}

void rejects_instruction_lines_above_the_fixed_bound() {
    const InstructionRecord record = instruction_record();
    std::array<char, kMaxInstructionLineBytes + 1U> module{};
    std::memset(module.data(), 'm', module.size() - 1U);
    std::array<char, kMaxInstructionLineBytes + 512U> output{};
    std::memset(output.data(), '?', output.size());

    TraceEncoder encoder;
    const EncodeResult result = encoder.encode_instruction(output.data(), output.size(), module.data(), record);
    assert(!result.ok);
    assert(result.size > kMaxInstructionLineBytes);
    for (char c: output) assert(c == '?');
}

void encodes_cache_hit_rate_with_an_overflowing_counter_total() {
    TraceMetrics metrics{};
    metrics.cache_hits = 1ULL << 63U;
    metrics.cache_misses = std::numeric_limits<uint64_t>::max();
    char output[256]{};

    TraceEncoder encoder;
    const EncodeResult result = encoder.encode_end(output, sizeof(output), true, 0, 0, metrics);
    assert(result.ok);
    assert(std::string_view(output, result.size).find("cache_hit_rate=0.333333") !=
           std::string_view::npos);
}

void encodes_zero_cache_total_as_zero_rate() {
    char output[256]{};
    TraceEncoder encoder;
    const EncodeResult result = encoder.encode_end(output, sizeof(output), true, 0, 0, {});
    assert(result.ok);
    assert(std::string_view(output, result.size).find("cache_hit_rate=0.000000") !=
           std::string_view::npos);
}

} // namespace

int main() {
    encodes_instruction_exactly();
    preserves_architecture_register_display_names();
    encodes_memory_event_exactly();
    rejects_insufficient_instruction_buffer_without_writing();
    encodes_begin_end_and_semantic_event();
    bounds_memory_hexdump_and_null_inputs();
    rejects_overflowing_records();
    rejects_instruction_lines_above_the_fixed_bound();
    encodes_cache_hit_rate_with_an_overflowing_counter_total();
    encodes_zero_cache_total_as_zero_rate();
}
