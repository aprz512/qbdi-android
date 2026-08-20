#include "core/instruction_cache.h"
#include "events/binary_trace_format.h"
#include "events/binary_trace_writer.h"
#include "lz4frame.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

namespace {

void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

class CountingBackend final : public TraceWriterBackend {
public:
    int open_file(const char *, int, unsigned int) noexcept override {
        ++open_calls;
        return 91;
    }

    ssize_t write_file(int, const void *, size_t size) noexcept override {
        ++write_calls;
        if (write_error != 0) {
            errno = write_error;
            return -1;
        }
        bytes_written += size;
        return static_cast<ssize_t>(size);
    }

    int close_file(int) noexcept override {
        ++close_calls;
        return 0;
    }

    int write_error = 0;
    unsigned int open_calls = 0;
    unsigned int write_calls = 0;
    unsigned int close_calls = 0;
    uint64_t bytes_written = 0;
};

class PointFaults final : public TraceFaultInjector {
public:
    int failure(FailurePoint point) noexcept override {
        return point == selected ? error_code : 0;
    }

    FailurePoint selected = FailurePoint::None;
    int error_code = 0;
};

std::string temporary_directory() {
    char path[] = "/tmp/qbdi-binary-writer-XXXXXX";
    char *created = ::mkdtemp(path);
    CHECK(created != nullptr);
    return created;
}

TraceContext context_for(const std::string &directory) {
    TraceContext context{};
    context.output_directory = directory;
    context.package_name = "com.example";
    context.scene_name = "scene";
    context.target_so = "libtarget.so";
    context.module_base = 0x1000;
    context.target_offset = 0x20;
    context.target_address = 0x1020;
    context.pid = 12;
    context.tid = 34;
    return context;
}

InstructionRecord instruction(uint64_t sequence, const CachedInstruction *decoded) {
    InstructionRecord record{};
    record.sequence = sequence;
    record.pc = 0x1020 + sequence * 4;
    record.module_base = 0x1000;
    record.decoded = decoded;
    return record;
}

std::vector<uint8_t> read_bytes(const std::string &path) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0);
    std::vector<uint8_t> output;
    uint8_t buffer[4096];
    for (;;) {
        const ssize_t count = ::read(fd, buffer, sizeof(buffer));
        CHECK(count >= 0);
        if (count == 0) break;
        output.insert(output.end(), buffer, buffer + count);
    }
    CHECK(::close(fd) == 0);
    return output;
}

std::string read_text(const std::string &path) {
    const std::vector<uint8_t> bytes = read_bytes(path);
    return {reinterpret_cast<const char *>(bytes.data()), bytes.size()};
}

std::vector<uint8_t> decompress_frames(const std::vector<uint8_t> &compressed,
                                       size_t *frame_count) {
    std::vector<uint8_t> decoded;
    size_t input_offset = 0;
    *frame_count = 0;
    while (input_offset < compressed.size()) {
        LZ4F_dctx *context = nullptr;
        CHECK(!LZ4F_isError(LZ4F_createDecompressionContext(&context, LZ4F_VERSION)));
        size_t remaining = 1;
        while (remaining != 0) {
            uint8_t chunk[4096];
            size_t source_size = compressed.size() - input_offset;
            size_t destination_size = sizeof(chunk);
            remaining = LZ4F_decompress(context, chunk, &destination_size,
                                        compressed.data() + input_offset, &source_size, nullptr);
            CHECK(!LZ4F_isError(remaining));
            CHECK(source_size != 0 || destination_size != 0 || remaining == 0);
            input_offset += source_size;
            decoded.insert(decoded.end(), chunk, chunk + destination_size);
        }
        LZ4F_freeDecompressionContext(context);
        ++*frame_count;
    }
    return decoded;
}

uint16_t u16(const std::vector<uint8_t> &bytes, size_t offset) {
    return static_cast<uint16_t>(bytes[offset]) |
           static_cast<uint16_t>(bytes[offset + 1]) << 8U;
}

uint32_t u32(const std::vector<uint8_t> &bytes, size_t offset) {
    return static_cast<uint32_t>(bytes[offset]) |
           static_cast<uint32_t>(bytes[offset + 1]) << 8U |
           static_cast<uint32_t>(bytes[offset + 2]) << 16U |
           static_cast<uint32_t>(bytes[offset + 3]) << 24U;
}

uint64_t u64(const std::vector<uint8_t> &bytes, size_t offset) {
    uint64_t value = 0;
    for (unsigned int byte = 0; byte < 8; ++byte)
        value |= static_cast<uint64_t>(bytes[offset + byte]) << (byte * 8U);
    return value;
}

std::vector<BinaryRecordType> record_types(const std::vector<uint8_t> &bytes) {
    CHECK(bytes.size() >= kBinaryStreamHeaderBytes);
    std::vector<BinaryRecordType> types;
    size_t offset = kBinaryStreamHeaderBytes;
    while (offset < bytes.size()) {
        CHECK(bytes.size() - offset >= kBinaryRecordHeaderBytes);
        types.push_back(static_cast<BinaryRecordType>(u16(bytes, offset)));
        const size_t size = kBinaryRecordHeaderBytes + u32(bytes, offset + 4);
        CHECK(size <= bytes.size() - offset);
        offset += size;
    }
    CHECK(offset == bytes.size());
    return types;
}

size_t count_type(const std::vector<BinaryRecordType> &types, BinaryRecordType type) {
    size_t count = 0;
    for (const BinaryRecordType actual : types) count += actual == type ? 1U : 0U;
    return count;
}

std::string metric_value(const std::string &metrics, std::string_view key) {
    const std::string prefix = std::string(key) + "=";
    const size_t begin = metrics.find(prefix);
    if (begin == std::string::npos) return {};
    const size_t value_begin = begin + prefix.size();
    const size_t end = metrics.find('\n', value_begin);
    return metrics.substr(value_begin, end - value_begin);
}

void compressed_stream_definitions_footer_and_metrics_v2_are_consistent() {
    const std::string directory = temporary_directory();
    TraceOptions options{};
    options.profile = TraceProfile::Balanced;
    options.compression_enabled = true;
    options.auto_buffer_size = false;
    options.buffer_bytes = 8192;
    TraceMetrics metrics{};
    BinaryTraceWriter writer(options, &metrics);
    const TraceContext context = context_for(directory);
    CachedInstruction decoded{};
    decoded.opcode = 0xd503201fU;
    std::strcpy(decoded.mnemonic, "nop");
    std::strcpy(decoded.disassembly, "nop");

    CHECK(writer.prepare(context));
    CHECK(writer.open_prepared());
    CHECK(writer.begin(context));
    CHECK(writer.instruction(context, instruction(1, &decoded)));
    CHECK(writer.instruction(context, instruction(2, &decoded)));
    for (uint64_t sequence = 3; sequence <= 400; ++sequence)
        CHECK(writer.instruction(context, instruction(sequence, &decoded)));
    CHECK(writer.call("jni", "GetIntField", "ok"));
    CHECK(writer.rule("branch", "taken=1"));
    CHECK(writer.error("diagnostic"));
    CHECK(writer.end(0x42, true, 7));
    CHECK(writer.close());
    CHECK(writer.close());
    CHECK(writer.path().ends_with(".trace.bin.lz4"));

    size_t frames = 0;
    const std::vector<uint8_t> compressed = read_bytes(writer.path());
    const std::vector<uint8_t> decoded_stream = decompress_frames(compressed, &frames);
    CHECK(frames >= 1);
    CHECK(std::memcmp(decoded_stream.data(), "QTRB", 4) == 0);
    const std::vector<BinaryRecordType> types = record_types(decoded_stream);
    CHECK(types.front() == BinaryRecordType::TraceBegin);
    CHECK(types.back() == BinaryRecordType::TraceEnd);
    CHECK(count_type(types, BinaryRecordType::ModuleDefinition) == 1);
    CHECK(count_type(types, BinaryRecordType::InstructionDefinition) == 1);
    CHECK(count_type(types, BinaryRecordType::Instruction) == 400);
    size_t definition = 0;
    size_t first_instruction = 0;
    for (size_t index = 0; index < types.size(); ++index) {
        if (types[index] == BinaryRecordType::InstructionDefinition) definition = index;
        if (types[index] == BinaryRecordType::Instruction && first_instruction == 0)
            first_instruction = index;
    }
    CHECK(definition < first_instruction);
    const size_t footer_offset = decoded_stream.size() - kBinaryTraceEndRecordBytes;
    CHECK(u64(decoded_stream, footer_offset + kBinaryRecordHeaderBytes + 25) ==
          decoded_stream.size());

    const std::string sidecar = read_text(writer.path() + ".metrics");
    CHECK(metric_value(sidecar, "metrics_version") == "2");
    CHECK(metric_value(sidecar, "profile") == "balanced");
    CHECK(metric_value(sidecar, "return") == "0x42");
    CHECK(metric_value(sidecar, "instructions") == "400");
    CHECK(metric_value(sidecar, "elapsed_ms") == "7");
    CHECK(metric_value(sidecar, "encoded_bytes") == std::to_string(decoded_stream.size()));
    CHECK(metric_value(sidecar, "compressed_bytes") == std::to_string(compressed.size()));
    CHECK(metric_value(sidecar, "effective_buffer_bytes") == "8192");
    CHECK(metric_value(sidecar, "raw_bytes").empty());
    CHECK(std::stoull(metric_value(sidecar, "buffer_swaps")) > 1);
    for (std::string_view key : {"instructions_per_second", "encoded_bytes_per_second",
                                 "disk_bytes_per_second", "compression_ratio", "cache_hits",
                                 "cache_misses", "cache_collisions", "cache_hit_rate",
                                 "buffer_swaps", "producer_waits", "producer_wait_ns"}) {
        CHECK(!metric_value(sidecar, key).empty());
    }

    CHECK(::unlink((writer.path() + ".metrics").c_str()) == 0);
    CHECK(::unlink(writer.path().c_str()) == 0);
    CHECK(::rmdir(directory.c_str()) == 0);
}

void uncompressed_stream_uses_binary_suffix_and_exact_byte_counts() {
    const std::string directory = temporary_directory();
    TraceOptions options{};
    options.compression_enabled = false;
    options.auto_buffer_size = false;
    options.buffer_bytes = 4096;
    TraceMetrics metrics{};
    BinaryTraceWriter writer(options, &metrics);
    const TraceContext context = context_for(directory);

    CHECK(writer.open(context));
    CHECK(writer.begin(context));
    CHECK(writer.call("jni", "short", "fits a 4 KiB buffer"));
    CHECK(writer.rule("short", "also fits"));
    CHECK(writer.end(0, true, 0));
    CHECK(writer.close());
    CHECK(writer.path().ends_with(".trace.bin"));
    const std::vector<uint8_t> bytes = read_bytes(writer.path());
    CHECK(metrics.encoded_bytes == bytes.size());
    CHECK(metrics.compressed_bytes == bytes.size());
    CHECK(record_types(bytes).back() == BinaryRecordType::TraceEnd);
    const std::string sidecar = read_text(writer.path() + ".metrics");
    CHECK(metric_value(sidecar, "encoded_bytes") == std::to_string(bytes.size()));
    CHECK(metric_value(sidecar, "compressed_bytes") == std::to_string(bytes.size()));

    CHECK(::unlink((writer.path() + ".metrics").c_str()) == 0);
    CHECK(::unlink(writer.path().c_str()) == 0);
    CHECK(::rmdir(directory.c_str()) == 0);
}

void encoding_failure_latches_and_does_no_later_event_work() {
    const std::string directory = temporary_directory();
    TraceOptions options{};
    options.compression_enabled = false;
    options.auto_buffer_size = false;
    options.buffer_bytes = 8192;
    TraceMetrics metrics{};
    CountingBackend backend;
    BinaryTraceWriter writer(options, &metrics, &backend);
    const TraceContext context = context_for(directory);

    CHECK(writer.open(context));
    CHECK(writer.begin(context));
    const uint64_t bytes_before = metrics.encoded_bytes;
    CHECK(!writer.call("category", "name", std::string(kBinaryMaxEventDetailBytes + 1, 'x')));
    CHECK(writer.failed());
    const int first_error = writer.error_code();
    CHECK(first_error != 0);
    CHECK(metrics.encoded_bytes == bytes_before);
    CHECK(!writer.rule("later", "later"));
    CHECK(!writer.error("later"));
    CHECK(metrics.encoded_bytes == bytes_before);
    CHECK(writer.error_code() == first_error);
    CHECK(!writer.end(91, false, 3));
    CHECK(!writer.close());
    CHECK(!writer.close());
    CHECK(backend.open_calls == 1);
    CHECK(backend.close_calls == 1);
    CHECK(::access((writer.path() + ".metrics").c_str(), F_OK) != 0);
    CHECK(::rmdir(directory.c_str()) == 0);
}

void failed_definition_is_not_committed() {
    const std::string directory = temporary_directory();
    TraceOptions options{};
    options.compression_enabled = false;
    options.auto_buffer_size = false;
    options.buffer_bytes = 4096;
    TraceMetrics metrics{};
    BinaryTraceWriter writer(options, &metrics);
    const TraceContext context = context_for(directory);
    CachedInstruction decoded{};
    decoded.opcode = 0x14000001U;
    decoded.read_gpr_mask = 1ULL << 34U;
    InstructionRecord record = instruction(1, &decoded);

    CHECK(writer.open(context));
    CHECK(writer.begin(context));
    const uint64_t bytes_before = metrics.encoded_bytes;
    CHECK(!writer.instruction(context, record));
    CHECK(metrics.encoded_bytes == bytes_before);
    CHECK(writer.failed());
    CHECK(!writer.instruction(context, record));
    CHECK(metrics.encoded_bytes == bytes_before);
    CHECK(!writer.close());
    CHECK(::access((writer.path() + ".metrics").c_str(), F_OK) != 0);
    CHECK(::unlink(writer.path().c_str()) == 0);
    CHECK(::rmdir(directory.c_str()) == 0);
}

void async_write_error_preserves_first_error_and_suppresses_metrics() {
    const std::string directory = temporary_directory();
    TraceOptions options{};
    options.compression_enabled = false;
    options.auto_buffer_size = false;
    options.buffer_bytes = 4096;
    TraceMetrics metrics{};
    CountingBackend backend;
    backend.write_error = ENOSPC;
    BinaryTraceWriter writer(options, &metrics, &backend);
    const TraceContext context = context_for(directory);

    CHECK(writer.open(context));
    CHECK(writer.begin(context));
    CHECK(writer.end(0x1234, true, 5));
    CHECK(!writer.close());
    CHECK(!writer.close());
    CHECK(writer.failed());
    CHECK(writer.error_code() == ENOSPC);
    CHECK(backend.write_calls == 1);
    CHECK(backend.close_calls == 1);
    CHECK(::access((writer.path() + ".metrics").c_str(), F_OK) != 0);
    CHECK(::rmdir(directory.c_str()) == 0);
}

void sidecar_error_removes_partial_metrics_and_close_is_idempotent() {
    const std::string directory = temporary_directory();
    TraceOptions options{};
    options.compression_enabled = false;
    options.auto_buffer_size = false;
    options.buffer_bytes = 4096;
    TraceMetrics metrics{};
    PointFaults faults;
    faults.selected = FailurePoint::MetricsSidecar;
    faults.error_code = EIO;
    BinaryTraceWriter writer(options, &metrics, nullptr, &faults);
    const TraceContext context = context_for(directory);

    CHECK(writer.open(context));
    CHECK(writer.begin(context));
    CHECK(writer.end(0x55, true, 1));
    CHECK(!writer.close());
    CHECK(!writer.close());
    CHECK(writer.error_code() == EIO);
    CHECK(::access((writer.path() + ".metrics").c_str(), F_OK) != 0);
    CHECK(::unlink(writer.path().c_str()) == 0);
    CHECK(::rmdir(directory.c_str()) == 0);
}

} // namespace

int main() {
    compressed_stream_definitions_footer_and_metrics_v2_are_consistent();
    uncompressed_stream_uses_binary_suffix_and_exact_byte_counts();
    encoding_failure_latches_and_does_no_later_event_work();
    failed_definition_is_not_committed();
    async_write_error_preserves_first_error_and_suppresses_metrics();
    sidecar_error_removes_partial_metrics_and_close_is_idempotent();
}
