#include "core/instruction_cache.h"
#include "events/binary_trace_format.h"
#include "events/binary_trace_writer.h"
#include "lz4frame.h"

#include <algorithm>
#include <cerrno>
#include <atomic>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <string_view>
#include <condition_variable>
#include <mutex>
#include <thread>
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

class BlockingBackend final : public TraceWriterBackend {
public:
    int open_file(const char *, int, unsigned int) noexcept override { return 92; }

    ssize_t write_file(int, const void *, size_t size) noexcept override {
        std::unique_lock<std::mutex> lock(mutex);
        entered = true;
        changed.notify_all();
        changed.wait(lock, [&] { return released; });
        bytes += size;
        return static_cast<ssize_t>(size);
    }

    int close_file(int) noexcept override { return 0; }

    void wait_until_entered() {
        std::unique_lock<std::mutex> lock(mutex);
        CHECK(changed.wait_for(lock, std::chrono::seconds(5), [&] { return entered; }));
    }

    void release() {
        std::lock_guard<std::mutex> lock(mutex);
        released = true;
        changed.notify_all();
    }

    uint64_t bytes = 0;

private:
    std::mutex mutex;
    std::condition_variable changed;
    bool entered = false;
    bool released = false;
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

class Lz4FrameMeasurer {
public:
    Lz4FrameMeasurer() {
        preferences.frameInfo.contentSize = kBinaryTraceEndRecordBytes;
        CHECK(!LZ4F_isError(LZ4F_createCompressionContext(&context, LZ4F_VERSION)));
        const size_t bound = LZ4F_compressBound(kBinaryTraceEndRecordBytes, &preferences);
        scratch.resize(std::max(bound, static_cast<size_t>(LZ4F_HEADER_SIZE_MAX)));
    }

    ~Lz4FrameMeasurer() { LZ4F_freeCompressionContext(context); }

    size_t measure(const std::array<uint8_t, kBinaryTraceEndRecordBytes> &footer) {
        size_t total = LZ4F_compressBegin(context, scratch.data(), scratch.size(), &preferences);
        CHECK(!LZ4F_isError(total));
        size_t produced = LZ4F_compressUpdate(context, scratch.data(), scratch.size(),
                                              footer.data(), footer.size(), nullptr);
        CHECK(!LZ4F_isError(produced));
        total += produced;
        produced = LZ4F_compressEnd(context, scratch.data(), scratch.size(), nullptr);
        CHECK(!LZ4F_isError(produced));
        return total + produced;
    }

    size_t bound() const {
        return LZ4F_compressFrameBound(kBinaryTraceEndRecordBytes, &preferences);
    }

private:
    LZ4F_cctx *context = nullptr;
    LZ4F_preferences_t preferences{};
    std::vector<uint8_t> scratch;
};

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

std::string artifact_path(const BinaryTraceWriter &writer) {
    return std::string(writer.path());
}

std::string sidecar_path(const BinaryTraceWriter &writer) {
    return artifact_path(writer) + ".metrics";
}

void check_footer_matches_sidecar(const std::vector<uint8_t> &stream,
                                  const std::string &sidecar) {
    const size_t payload = stream.size() - kBinaryTraceEndRecordBytes + kBinaryRecordHeaderBytes;
    struct Field {
        size_t offset;
        const char *name;
    };
    for (const Field field : {Field{9, "elapsed_ms"}, Field{17, "instructions"},
                              Field{25, "encoded_bytes"}, Field{33, "compressed_bytes"},
                              Field{41, "cache_hits"}, Field{49, "cache_misses"},
                              Field{57, "cache_collisions"}, Field{65, "buffer_swaps"},
                              Field{73, "producer_waits"}, Field{81, "producer_wait_ns"},
                              Field{89, "effective_buffer_bytes"}}) {
        CHECK(u64(stream, payload + field.offset) ==
              std::stoull(metric_value(sidecar, field.name)));
    }
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
    const std::vector<uint8_t> compressed = read_bytes(artifact_path(writer));
    const std::array<uint8_t, 4> skippable_magic{0x50, 0x2a, 0x4d, 0x18};
    const auto padding = std::find_end(compressed.begin(), compressed.end(),
                                       skippable_magic.begin(), skippable_magic.end());
    CHECK(padding != compressed.end());
    const size_t padding_offset = static_cast<size_t>(padding - compressed.begin());
    CHECK(compressed.size() - padding_offset >= 8);
    CHECK(u32(compressed, padding_offset + 4) == compressed.size() - padding_offset - 8);
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
    CHECK(u64(decoded_stream, footer_offset + kBinaryRecordHeaderBytes + 33) ==
          compressed.size());

    const std::string sidecar = read_text(sidecar_path(writer));
    check_footer_matches_sidecar(decoded_stream, sidecar);
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

    CHECK(::unlink(sidecar_path(writer).c_str()) == 0);
    CHECK(::unlink(artifact_path(writer).c_str()) == 0);
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
    const std::vector<uint8_t> bytes = read_bytes(artifact_path(writer));
    CHECK(metrics.encoded_bytes == bytes.size());
    CHECK(metrics.compressed_bytes == bytes.size());
    CHECK(record_types(bytes).back() == BinaryRecordType::TraceEnd);
    const size_t footer_offset = bytes.size() - kBinaryTraceEndRecordBytes;
    CHECK(u64(bytes, footer_offset + kBinaryRecordHeaderBytes + 25) == bytes.size());
    CHECK(u64(bytes, footer_offset + kBinaryRecordHeaderBytes + 33) == bytes.size());
    const std::string sidecar = read_text(sidecar_path(writer));
    check_footer_matches_sidecar(bytes, sidecar);
    CHECK(metric_value(sidecar, "encoded_bytes") == std::to_string(bytes.size()));
    CHECK(metric_value(sidecar, "compressed_bytes") == std::to_string(bytes.size()));

    CHECK(::unlink(sidecar_path(writer).c_str()) == 0);
    CHECK(::unlink(artifact_path(writer).c_str()) == 0);
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
    CHECK(::access(sidecar_path(writer).c_str(), F_OK) != 0);
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
    CHECK(::access(sidecar_path(writer).c_str(), F_OK) != 0);
    CHECK(::unlink(artifact_path(writer).c_str()) == 0);
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
    CHECK(!writer.end(0x1234, true, 5));
    CHECK(!writer.close());
    CHECK(!writer.close());
    CHECK(writer.failed());
    CHECK(writer.error_code() == ENOSPC);
    CHECK(backend.write_calls == 1);
    CHECK(backend.close_calls == 1);
    CHECK(::access(sidecar_path(writer).c_str(), F_OK) != 0);
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
    CHECK(::access(sidecar_path(writer).c_str(), F_OK) != 0);
    CHECK(::unlink(artifact_path(writer).c_str()) == 0);
    CHECK(::rmdir(directory.c_str()) == 0);
}

void setup_allocation_failure_latches_enomem_without_artifacts() {
    const std::string directory = temporary_directory();
    TraceOptions options{};
    TraceMetrics metrics{};
    PointFaults faults;
    faults.selected = FailurePoint::PathSetup;
    faults.error_code = ENOMEM;
    BinaryTraceWriter writer(options, &metrics, nullptr, &faults);
    const TraceContext context = context_for(directory);

    CHECK(!writer.prepare(context));
    CHECK(writer.failed());
    CHECK(writer.error_code() == ENOMEM);
    CHECK(!writer.open_prepared());
    CHECK(!writer.begin(context));
    CHECK(writer.path().empty());
    CHECK(::rmdir(directory.c_str()) == 0);
}

void directory_creation_failure_preserves_errno() {
    TraceOptions options{};
    TraceMetrics metrics{};
    PointFaults faults;
    faults.selected = FailurePoint::DirectoryCreation;
    faults.error_code = EACCES;
    BinaryTraceWriter writer(options, &metrics, nullptr, &faults);
    const TraceContext context = context_for("/not-created/qbdi");

    CHECK(!writer.prepare(context));
    CHECK(writer.failed());
    CHECK(writer.error_code() == EACCES);
    CHECK(writer.path().empty());
}

void real_mkdir_failure_preserves_enotdir() {
    TraceOptions options{};
    TraceMetrics metrics{};
    BinaryTraceWriter writer(options, &metrics);
    const TraceContext context = context_for("/dev/null/qbdi-traces");

    CHECK(!writer.prepare(context));
    CHECK(writer.failed());
    CHECK(writer.error_code() == ENOTDIR);
    CHECK(writer.path().empty());
}

void end_waits_for_consumer_before_snapshotting_compressed_bytes() {
    const std::string directory = temporary_directory();
    TraceOptions options{};
    options.compression_enabled = false;
    options.auto_buffer_size = false;
    options.buffer_bytes = 4096;
    TraceMetrics metrics{};
    BlockingBackend backend;
    BinaryTraceWriter writer(options, &metrics, &backend);
    const TraceContext context = context_for(directory);
    CachedInstruction decoded{};
    decoded.opcode = 0xd503201fU;

    CHECK(writer.open(context));
    CHECK(writer.begin(context));
    for (uint64_t sequence = 1; sequence <= 150; ++sequence)
        CHECK(writer.instruction(context, instruction(sequence, &decoded)));
    backend.wait_until_entered();
    std::atomic<bool> end_returned{false};
    std::thread ending([&] {
        CHECK(writer.end(0x88, true, 9));
        end_returned.store(true, std::memory_order_release);
    });
    CHECK(!end_returned.load(std::memory_order_acquire));
    backend.release();
    ending.join();
    CHECK(writer.close());
    CHECK(backend.bytes == metrics.compressed_bytes);
    CHECK(::unlink((std::string(writer.path()) + ".metrics").c_str()) == 0);
    CHECK(::rmdir(directory.c_str()) == 0);
}

void padded_footer_is_total_for_exact_cycle_and_adversarial_prefixes() {
    BinaryTraceEncoder encoder;
    Lz4FrameMeasurer measurer;
    TraceMetrics metrics{};
    metrics.instructions = 400;
    metrics.encoded_bytes = 14000;
    metrics.cache_hits = 390;
    metrics.cache_misses = 10;
    metrics.buffer_swaps = 4;
    metrics.effective_buffer_bytes = 8192;
    std::array<uint8_t, kBinaryTraceEndRecordBytes> footer{};
    bool exact_cycle_found = false;
    for (uint64_t nonce = 0; nonce < 1000000 && !exact_cycle_found; ++nonce) {
        metrics.producer_wait_ns = nonce;
        metrics.compressed_bytes = 175;
        CHECK(encoder.encode_end(footer.data(), footer.size(), true, 0x42, 7, metrics).ok);
        const size_t from_175 = measurer.measure(footer);
        metrics.compressed_bytes = 176;
        CHECK(encoder.encode_end(footer.data(), footer.size(), true, 0x42, 7, metrics).ok);
        const size_t from_176 = measurer.measure(footer);
        exact_cycle_found = from_175 == 90 && from_176 == 89;
    }
    CHECK(exact_cycle_found);
    CHECK(86 + 90 == 176);
    CHECK(86 + 89 == 175);

    const uint64_t prefixes[] = {0, 1, 2, 85, 86, 87, 999, 4096, 65535, 999999};
    for (const uint64_t prefix : prefixes) {
        const uint64_t target = prefix + measurer.bound() + 8;
        metrics.compressed_bytes = target;
        CHECK(encoder.encode_end(footer.data(), footer.size(), true, 0x42, 7, metrics).ok);
        const size_t actual = measurer.measure(footer);
        CHECK(actual <= measurer.bound());
        const uint64_t padding_bytes = target - prefix - actual;
        CHECK(padding_bytes >= 8);
        CHECK(prefix + actual + padding_bytes == target);
    }
    uint64_t state = 0x9e3779b97f4a7c15ULL;
    for (size_t sample = 0; sample < 10000; ++sample) {
        state = state * 6364136223846793005ULL + 1;
        const uint64_t prefix = state % 1000000;
        const uint64_t target = prefix + measurer.bound() + 8;
        metrics.compressed_bytes = target;
        CHECK(encoder.encode_end(footer.data(), footer.size(), true, 0x42, 7, metrics).ok);
        const size_t actual = measurer.measure(footer);
        CHECK(actual <= measurer.bound());
        CHECK(target - prefix - actual >= 8);
        CHECK(prefix + actual + (target - prefix - actual) == target);
    }
}

} // namespace

int main() {
    compressed_stream_definitions_footer_and_metrics_v2_are_consistent();
    uncompressed_stream_uses_binary_suffix_and_exact_byte_counts();
    encoding_failure_latches_and_does_no_later_event_work();
    failed_definition_is_not_committed();
    async_write_error_preserves_first_error_and_suppresses_metrics();
    sidecar_error_removes_partial_metrics_and_close_is_idempotent();
    setup_allocation_failure_latches_enomem_without_artifacts();
    directory_creation_failure_preserves_errno();
    real_mkdir_failure_preserves_enotdir();
    end_waits_for_consumer_before_snapshotting_compressed_bytes();
    padded_footer_is_total_for_exact_cycle_and_adversarial_prefixes();
}
