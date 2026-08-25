#include "core/instruction_cache.h"
#include "events/binary_trace_format.h"
#include "events/binary_trace_writer.h"
#include "lz4frame.h"

#include <algorithm>
#include <cerrno>
#include <atomic>
#include <array>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <string_view>
#include <condition_variable>
#include <mutex>
#include <new>
#include <thread>
#include <unistd.h>
#include <vector>

namespace {

enum class IoFaultMode : int {
    None,
    SidecarInterruptedAndPartial,
    SidecarWriteError,
};

std::atomic<IoFaultMode> g_io_fault_mode{IoFaultMode::None};
std::atomic<int> g_sidecar_fd{-1};
std::atomic<unsigned int> g_fault_write_calls{0};
std::atomic<size_t> g_allocations{0};

bool has_suffix(const char *path, std::string_view suffix) {
    return path != nullptr && std::string_view(path).ends_with(suffix);
}

void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

} // namespace

void *operator new(size_t size) {
    g_allocations.fetch_add(1, std::memory_order_relaxed);
    void *allocation = std::malloc(size);
    if (allocation == nullptr) std::abort();
    return allocation;
}

void *operator new[](size_t size) { return ::operator new(size); }

void *operator new(size_t size, const std::nothrow_t &) noexcept {
    g_allocations.fetch_add(1, std::memory_order_relaxed);
    return std::malloc(size);
}

void *operator new[](size_t size, const std::nothrow_t &tag) noexcept {
    return ::operator new(size, tag);
}

void operator delete(void *allocation) noexcept { std::free(allocation); }
void operator delete[](void *allocation) noexcept { ::operator delete(allocation); }
void operator delete(void *allocation, size_t) noexcept { std::free(allocation); }
void operator delete[](void *allocation, size_t) noexcept { ::operator delete(allocation); }
void operator delete(void *allocation, const std::nothrow_t &) noexcept {
    std::free(allocation);
}
void operator delete[](void *allocation, const std::nothrow_t &) noexcept {
    ::operator delete(allocation);
}

extern "C" int __real_open(const char *path, int flags, ...);
extern "C" ssize_t __real_write(int fd, const void *data, size_t size);
extern "C" int __real_close(int fd);

extern "C" int __wrap_open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if ((flags & O_CREAT) != 0) {
        va_list args;
        va_start(args, flags);
        mode = static_cast<mode_t>(va_arg(args, int));
        va_end(args);
    }
    const int fd = __real_open(path, flags, mode);
    if (fd >= 0 && has_suffix(path, ".metrics") &&
        g_io_fault_mode.load(std::memory_order_relaxed) != IoFaultMode::None) {
        g_sidecar_fd.store(fd, std::memory_order_relaxed);
    }
    return fd;
}

extern "C" ssize_t __wrap_write(int fd, const void *data, size_t size) {
    if (fd == g_sidecar_fd.load(std::memory_order_relaxed)) {
        const unsigned int call =
                g_fault_write_calls.fetch_add(1, std::memory_order_relaxed);
        const IoFaultMode mode = g_io_fault_mode.load(std::memory_order_relaxed);
        if (mode == IoFaultMode::SidecarInterruptedAndPartial) {
            if (call == 0) {
                errno = EINTR;
                return -1;
            }
            if (call == 1 && size > 1) return __real_write(fd, data, size / 2U);
        } else if (mode == IoFaultMode::SidecarWriteError) {
            if (call == 0 && size > 1) return __real_write(fd, data, size / 2U);
            errno = EIO;
            return -1;
        }
    }
    return __real_write(fd, data, size);
}

extern "C" int __wrap_close(int fd) { return __real_close(fd); }

namespace {

void set_io_fault(IoFaultMode mode) {
    g_sidecar_fd.store(-1, std::memory_order_relaxed);
    g_fault_write_calls.store(0, std::memory_order_relaxed);
    g_io_fault_mode.store(mode, std::memory_order_relaxed);
}

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

struct LogicalCall {
    std::string category;
    std::string name;
    std::string detail;
    uint64_t event_id = 0;
    uint32_t total_detail_bytes = 0;
    uint16_t chunk_count = 1;
    std::vector<size_t> fragment_sizes;
};

std::string read_wire_string(const std::vector<uint8_t> &bytes, size_t *offset,
                             size_t limit) {
    CHECK(*offset + 2 <= limit);
    const size_t size = u16(bytes, *offset);
    *offset += 2;
    CHECK(size <= limit - *offset);
    std::string value(reinterpret_cast<const char *>(bytes.data() + *offset), size);
    *offset += size;
    return value;
}

std::vector<LogicalCall> logical_calls(const std::vector<uint8_t> &bytes) {
    std::vector<LogicalCall> calls;
    size_t offset = kBinaryStreamHeaderBytes;
    while (offset < bytes.size()) {
        CHECK(bytes.size() - offset >= kBinaryRecordHeaderBytes);
        const auto type = static_cast<BinaryRecordType>(u16(bytes, offset));
        const uint16_t flags = u16(bytes, offset + 2);
        const size_t end = offset + kBinaryRecordHeaderBytes + u32(bytes, offset + 4);
        CHECK(end <= bytes.size());
        if (type != BinaryRecordType::Call) {
            offset = end;
            continue;
        }

        size_t cursor = offset + kBinaryRecordHeaderBytes;
        if (flags == 0) {
            LogicalCall call;
            call.category = read_wire_string(bytes, &cursor, end);
            call.name = read_wire_string(bytes, &cursor, end);
            call.detail = read_wire_string(bytes, &cursor, end);
            call.total_detail_bytes = static_cast<uint32_t>(call.detail.size());
            call.fragment_sizes.push_back(call.detail.size());
            CHECK(cursor == end);
            calls.push_back(std::move(call));
        } else {
            CHECK(flags == kBinaryCallChunkFlag);
            CHECK(cursor + kBinaryCallChunkMetadataBytes <= end);
            const uint64_t event_id = u64(bytes, cursor);
            const uint32_t total = u32(bytes, cursor + 8);
            const uint16_t chunk_index = u16(bytes, cursor + 12);
            const uint16_t chunk_count = u16(bytes, cursor + 14);
            cursor += kBinaryCallChunkMetadataBytes;
            const std::string category = read_wire_string(bytes, &cursor, end);
            const std::string name = read_wire_string(bytes, &cursor, end);
            const std::string fragment = read_wire_string(bytes, &cursor, end);
            CHECK(cursor == end);
            if (chunk_index == 0) {
                CHECK(event_id != 0);
                LogicalCall call;
                call.category = category;
                call.name = name;
                call.event_id = event_id;
                call.total_detail_bytes = total;
                call.chunk_count = chunk_count;
                calls.push_back(std::move(call));
            }
            CHECK(!calls.empty());
            LogicalCall &call = calls.back();
            CHECK(call.event_id == event_id);
            CHECK(call.category == category);
            CHECK(call.name == name);
            CHECK(call.total_detail_bytes == total);
            CHECK(call.chunk_count == chunk_count);
            CHECK(call.fragment_sizes.size() == chunk_index);
            call.fragment_sizes.push_back(fragment.size());
            call.detail.append(fragment);
            if (chunk_index + 1U == chunk_count) {
                CHECK(call.detail.size() == call.total_detail_bytes);
            }
        }
        offset = end;
    }
    return calls;
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

void check_stop_matches_sidecar(const std::vector<uint8_t> &stream,
                                const std::string &sidecar) {
    const size_t payload = stream.size() - kBinaryTraceStopRecordBytes + kBinaryRecordHeaderBytes;
    struct Field {
        size_t offset;
        const char *name;
    };
    for (const Field field : {Field{8, "elapsed_ms"}, Field{16, "instructions"},
                              Field{24, "encoded_bytes"}, Field{32, "compressed_bytes"},
                              Field{40, "cache_hits"}, Field{48, "cache_misses"},
                              Field{56, "cache_collisions"}, Field{64, "buffer_swaps"},
                              Field{72, "producer_waits"}, Field{80, "producer_wait_ns"},
                              Field{88, "effective_buffer_bytes"}}) {
        CHECK(u64(stream, payload + field.offset) ==
              std::stoull(metric_value(sidecar, field.name)));
    }
}

void compressed_stream_definitions_footer_and_metrics_v3_are_consistent() {
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
    CHECK(metric_value(sidecar, "metrics_version") == "3");
    CHECK(metric_value(sidecar, "termination") == "completed");
    CHECK(metric_value(sidecar, "return_valid") == "1");
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

void uncompressed_stopped_stream_has_one_terminal_and_v3_metrics() {
    const std::string directory = temporary_directory();
    TraceOptions options{};
    options.compression_enabled = false;
    options.auto_buffer_size = false;
    options.buffer_bytes = 4096;
    TraceMetrics metrics{};
    BinaryTraceWriter writer(options, &metrics);
    const TraceContext context = context_for(directory);
    CachedInstruction decoded{};
    decoded.opcode = 0xd503201fU;

    CHECK(writer.open(context));
    CHECK(writer.begin(context));
    CHECK(writer.instruction(context, instruction(1, &decoded)));
    CHECK(writer.stop(TraceStopReason::DurationElapsed, 17));
    CHECK(writer.stop(TraceStopReason::DurationElapsed, 17));
    CHECK(!writer.end(0x55, true, 18));
    CHECK(writer.close());

    const std::vector<uint8_t> bytes = read_bytes(artifact_path(writer));
    CHECK(count_type(record_types(bytes), BinaryRecordType::TraceStop) == 1);
    const std::string sidecar = read_text(sidecar_path(writer));
    check_stop_matches_sidecar(bytes, sidecar);
    CHECK(sidecar.find("metrics_version=3\n") != std::string::npos);
    CHECK(sidecar.find("termination=stopped\n") != std::string::npos);
    CHECK(sidecar.find("return_valid=0\nreturn=0x0\n") != std::string::npos);

    CHECK(::unlink(sidecar_path(writer).c_str()) == 0);
    CHECK(::unlink(artifact_path(writer).c_str()) == 0);
    CHECK(::rmdir(directory.c_str()) == 0);
}

void compressed_stopped_stream_has_one_terminal_and_v3_metrics() {
    const std::string directory = temporary_directory();
    TraceOptions options{};
    options.compression_enabled = true;
    options.auto_buffer_size = false;
    options.buffer_bytes = 4096;
    TraceMetrics metrics{};
    BinaryTraceWriter writer(options, &metrics);
    const TraceContext context = context_for(directory);
    CachedInstruction decoded{};
    decoded.opcode = 0xd503201fU;

    CHECK(writer.open(context));
    CHECK(writer.begin(context));
    CHECK(writer.instruction(context, instruction(1, &decoded)));
    CHECK(writer.stop(TraceStopReason::DurationElapsed, 17));
    CHECK(writer.stop(TraceStopReason::DurationElapsed, 17));
    CHECK(!writer.end(0x55, true, 18));
    CHECK(writer.close());

    size_t frames = 0;
    const std::vector<uint8_t> bytes =
            decompress_frames(read_bytes(artifact_path(writer)), &frames);
    CHECK(frames >= 1);
    CHECK(count_type(record_types(bytes), BinaryRecordType::TraceStop) == 1);
    const std::string sidecar = read_text(sidecar_path(writer));
    check_stop_matches_sidecar(bytes, sidecar);
    CHECK(sidecar.find("metrics_version=3\n") != std::string::npos);
    CHECK(sidecar.find("termination=stopped\n") != std::string::npos);
    CHECK(sidecar.find("return_valid=0\nreturn=0x0\n") != std::string::npos);

    CHECK(::unlink(sidecar_path(writer).c_str()) == 0);
    CHECK(::unlink(artifact_path(writer).c_str()) == 0);
    CHECK(::rmdir(directory.c_str()) == 0);
}

void maximum_rule_and_error_survive_four_kib_buffers_in_order() {
    const std::string directory = temporary_directory();
    TraceOptions options{};
    options.compression_enabled = false;
    options.auto_buffer_size = false;
    options.buffer_bytes = 4096;
    TraceMetrics metrics{};
    BinaryTraceWriter writer(options, &metrics);
    const TraceContext context = context_for(directory);
    const std::string name(kBinaryMaxEventNameBytes, 'n');
    const std::string utf8 = std::string(3071, 'a') + "\xe2\x82\xac" +
                             std::string(kBinaryMaxEventDetailBytes - 3074, 'b');
    const std::string raw = std::string(3071, 'r') + std::string("\x80\xff\0", 3) +
                            std::string(kBinaryMaxEventDetailBytes - 3074, 's');

    CHECK(writer.open(context));
    CHECK(writer.begin(context));
    CHECK(writer.rule(name, utf8));
    CHECK(writer.error(raw));
    CHECK(writer.end(0, true, 1));
    CHECK(writer.close());

    const std::vector<uint8_t> stream = read_bytes(artifact_path(writer));
    std::vector<BinaryRecordType> semantic_types;
    size_t offset = kBinaryStreamHeaderBytes;
    while (offset < stream.size()) {
        const auto type = static_cast<BinaryRecordType>(u16(stream, offset));
        const uint16_t flags = u16(stream, offset + 2);
        const size_t record_bytes = kBinaryRecordHeaderBytes + u32(stream, offset + 4);
        CHECK(record_bytes <= 4096);
        if (type == BinaryRecordType::Rule || type == BinaryRecordType::Error) {
            CHECK(flags == kBinaryEventChunkFlag);
            semantic_types.push_back(type);
        }
        offset += record_bytes;
    }
    CHECK((semantic_types == std::vector<BinaryRecordType>{
            BinaryRecordType::Rule, BinaryRecordType::Rule,
            BinaryRecordType::Error, BinaryRecordType::Error}));

    CHECK(::unlink(sidecar_path(writer).c_str()) == 0);
    CHECK(::unlink(artifact_path(writer).c_str()) == 0);
    CHECK(::rmdir(directory.c_str()) == 0);
}

void instruction_memory_and_continuations_keep_producer_order() {
    const std::string directory = temporary_directory();
    TraceOptions options{};
    options.profile = TraceProfile::Full;
    options.compression_enabled = false;
    options.auto_buffer_size = false;
    options.buffer_bytes = 4096;
    TraceMetrics metrics{};
    BinaryTraceWriter writer(options, &metrics);
    const TraceContext context = context_for(directory);
    CachedInstruction decoded{};
    decoded.opcode = 0xf9400020U;
    std::strcpy(decoded.mnemonic, "ldr");

    InstructionRecord record = instruction(1, &decoded);
    record.memory_count = 2;
    record.memory[0].kind = MemoryAccessKind::Read;
    record.memory[0].metadata_available = true;
    record.memory[0].address = 0x2000;
    record.memory[0].size = 8;
    record.memory[0].value = 0x11;
    record.memory[1] = record.memory[0];
    record.memory[1].address = 0x2008;
    record.memory[1].value = 0x22;
    MemoryRecord continuation = record.memory[0];
    continuation.address = 0x2010;
    continuation.value = 0x33;

    CHECK(writer.open(context));
    CHECK(writer.begin(context));
    CHECK(writer.instruction(context, record));
    CHECK(writer.memory(context, record.pc, continuation));
    CHECK(writer.end(0x44, true, 2));
    CHECK(writer.close());

    const std::vector<uint8_t> stream = read_bytes(artifact_path(writer));
    CHECK(stream[8] == static_cast<uint8_t>(TraceProfile::Full));
    const std::vector<BinaryRecordType> types = record_types(stream);
    const auto instruction_position =
            std::find(types.begin(), types.end(), BinaryRecordType::Instruction);
    CHECK(instruction_position != types.end());
    CHECK(static_cast<size_t>(types.end() - instruction_position) >= 5);
    CHECK(instruction_position[1] == BinaryRecordType::Memory);
    CHECK(instruction_position[2] == BinaryRecordType::Memory);
    CHECK(instruction_position[3] == BinaryRecordType::Memory);
    CHECK(instruction_position[4] == BinaryRecordType::TraceEnd);

    CHECK(::unlink(sidecar_path(writer).c_str()) == 0);
    CHECK(::unlink(artifact_path(writer).c_str()) == 0);
    CHECK(::rmdir(directory.c_str()) == 0);
}

void sidecar_retries_eintr_and_partial_writes() {
    const std::string directory = temporary_directory();
    TraceOptions options{};
    options.compression_enabled = false;
    options.auto_buffer_size = false;
    options.buffer_bytes = 4096;
    TraceMetrics metrics{};
    BinaryTraceWriter writer(options, &metrics);
    const TraceContext context = context_for(directory);

    set_io_fault(IoFaultMode::SidecarInterruptedAndPartial);
    CHECK(writer.open(context));
    CHECK(writer.begin(context));
    CHECK(writer.end(0, true, 3));
    CHECK(writer.close());
    CHECK(g_fault_write_calls.load(std::memory_order_relaxed) >= 3);
    set_io_fault(IoFaultMode::None);
    CHECK(metric_value(read_text(sidecar_path(writer)), "elapsed_ms") == "3");

    CHECK(::unlink(sidecar_path(writer).c_str()) == 0);
    CHECK(::unlink(artifact_path(writer).c_str()) == 0);
    CHECK(::rmdir(directory.c_str()) == 0);
}

void sidecar_write_error_removes_partial_file() {
    const std::string directory = temporary_directory();
    TraceOptions options{};
    options.compression_enabled = false;
    options.auto_buffer_size = false;
    options.buffer_bytes = 4096;
    TraceMetrics metrics{};
    BinaryTraceWriter writer(options, &metrics);
    const TraceContext context = context_for(directory);

    set_io_fault(IoFaultMode::SidecarWriteError);
    CHECK(writer.open(context));
    CHECK(writer.begin(context));
    CHECK(writer.end(0, true, 3));
    CHECK(!writer.close());
    CHECK(!writer.close());
    CHECK(writer.error_code() == EIO);
    set_io_fault(IoFaultMode::None);
    CHECK(::access(sidecar_path(writer).c_str(), F_OK) != 0);

    CHECK(::unlink(artifact_path(writer).c_str()) == 0);
    CHECK(::rmdir(directory.c_str()) == 0);
}

void invalid_lifecycle_transitions_fail_closed() {
    TraceOptions options{};
    options.compression_enabled = false;
    options.auto_buffer_size = false;
    options.buffer_bytes = 4096;
    TraceMetrics metrics{};
    BinaryTraceWriter unopened(options, &metrics);
    CHECK(!unopened.end(0, false, 1));
    CHECK(!unopened.close());
    CHECK(!unopened.close());

    TraceContext bad_context = context_for("/dev/null/not-a-directory");
    BinaryTraceWriter failed_open(options, &metrics);
    CHECK(!failed_open.open(bad_context));
    CHECK(!failed_open.begin(bad_context));
    CHECK(!failed_open.end(0, false, 1));
    CHECK(!failed_open.close());
    CHECK(!failed_open.close());

    const std::string directory = temporary_directory();
    const TraceContext context = context_for(directory);
    BinaryTraceWriter incomplete(options, &metrics);
    CHECK(incomplete.open(context));
    const std::string path(incomplete.path());
    CHECK(!incomplete.close());
    CHECK(!incomplete.end(0, false, 1));
    CHECK(!incomplete.begin(context));
    CHECK(::access((path + ".metrics").c_str(), F_OK) != 0);
    CHECK(::unlink(path.c_str()) == 0);
    CHECK(::rmdir(directory.c_str()) == 0);
}

void instruction_and_memory_hot_path_allocate_nothing() {
    const std::string directory = temporary_directory();
    TraceOptions options{};
    options.profile = TraceProfile::Full;
    options.compression_enabled = false;
    options.auto_buffer_size = false;
    options.buffer_bytes = 8192;
    TraceMetrics metrics{};
    BinaryTraceWriter writer(options, &metrics);
    const TraceContext context = context_for(directory);
    CachedInstruction decoded{};
    decoded.opcode = 0xf9400020U;
    decoded.read_gpr_mask = 1U;
    decoded.read_gpr_widths[0] = 8;
    std::strcpy(decoded.read_register_names[0], "X0");
    InstructionRecord record = instruction(1, &decoded);
    record.reads.count = 1;
    record.reads.values[0] = 0x1234;
    record.memory_count = 1;
    record.memory[0].kind = MemoryAccessKind::Read;
    record.memory[0].address = 0x2000;
    record.memory[0].size = 8;

    CHECK(writer.open(context));
    CHECK(writer.begin(context));
    const size_t allocations_before = g_allocations.load(std::memory_order_relaxed);
    CHECK(writer.instruction(context, record));
    CHECK(writer.memory(context, record.pc, record.memory[0]));
    CHECK(g_allocations.load(std::memory_order_relaxed) == allocations_before);
    CHECK(writer.end(0, true, 1));
    CHECK(writer.close());

    CHECK(::unlink(sidecar_path(writer).c_str()) == 0);
    CHECK(::unlink(artifact_path(writer).c_str()) == 0);
    CHECK(::rmdir(directory.c_str()) == 0);
}

void chunked_calls_round_trip_utf8_identity_and_maximum_order() {
    const std::string directory = temporary_directory();
    TraceOptions options{};
    options.compression_enabled = false;
    options.auto_buffer_size = false;
    options.buffer_bytes = 8192;
    TraceMetrics metrics{};
    BinaryTraceWriter writer(options, &metrics);
    const TraceContext context = context_for(directory);
    const std::string euro("\xe2\x82\xac", 3);
    const std::string crossing = std::string(3071, 'a') + euro + std::string(5000, 'b');
    const std::string arbitrary = std::string(3071, 'q') +
                                  std::string("\x80\xff\x00", 3) +
                                  std::string(4000, 'r');
    const std::string maximum(kBinaryMaxLogicalCallDetailBytes, 'z');

    CHECK(writer.open(context));
    CHECK(writer.begin(context));
    CHECK(writer.call("jni-enter", "same", crossing));
    CHECK(writer.call("jni-enter", "same", "second"));
    CHECK(writer.call("jni-enter", "same", ""));
    CHECK(writer.call("jni-enter", "same", arbitrary));
    CHECK(writer.call("jni-enter", "same", maximum));
    CHECK(writer.end(0, true, 1));
    CHECK(writer.close());

    const std::vector<LogicalCall> calls = logical_calls(read_bytes(artifact_path(writer)));
    CHECK(calls.size() == 5);
    CHECK(calls[0].detail == crossing);
    CHECK(calls[0].chunk_count == 3);
    CHECK(calls[0].fragment_sizes.size() == 3);
    CHECK(calls[0].fragment_sizes[0] == 3071);
    CHECK(calls[0].event_id != 0);
    CHECK(calls[1].detail == "second");
    CHECK(calls[1].event_id == 0);
    CHECK(calls[2].detail.empty());
    CHECK(calls[2].event_id == 0);
    CHECK(calls[3].detail == arbitrary);
    CHECK(calls[3].event_id != 0);
    CHECK(calls[3].event_id != calls[0].event_id);
    CHECK(calls[4].detail == maximum);
    CHECK(calls[4].event_id != 0);
    CHECK(calls[4].event_id != calls[3].event_id);
    CHECK(calls[4].chunk_count ==
          (kBinaryMaxLogicalCallDetailBytes + 3071U) / 3072U);
    CHECK(calls[4].fragment_sizes.size() == calls[4].chunk_count);

    CHECK(::unlink(sidecar_path(writer).c_str()) == 0);
    CHECK(::unlink(artifact_path(writer).c_str()) == 0);
    CHECK(::rmdir(directory.c_str()) == 0);
}

void oversized_logical_call_fails_before_writing_any_fragment() {
    const std::string directory = temporary_directory();
    TraceOptions options{};
    options.compression_enabled = false;
    options.auto_buffer_size = false;
    options.buffer_bytes = 8192;
    TraceMetrics metrics{};
    BinaryTraceWriter writer(options, &metrics);
    const TraceContext context = context_for(directory);
    const std::string oversized(kBinaryMaxLogicalCallDetailBytes + 1U, 'x');

    CHECK(writer.open(context));
    CHECK(writer.begin(context));
    const uint64_t encoded_before = metrics.encoded_bytes;
    CHECK(!writer.call("jni", "oversized", oversized));
    CHECK(writer.failed());
    CHECK(metrics.encoded_bytes == encoded_before);
    CHECK(!writer.close());

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
    CHECK(!writer.call("category", "name",
                       std::string(kBinaryMaxLogicalCallDetailBytes + 1U, 'x')));
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

void metadata_dictionary_boundary_finalizes_65536_and_rejects_65537() {
    const std::string directory = temporary_directory();
    TraceOptions options{};
    options.compression_enabled = false;
    options.auto_buffer_size = false;
    options.buffer_bytes = 64 * 1024;
    const TraceContext context = context_for(directory);
    std::string successful_path;
    {
        TraceMetrics metrics{};
        BinaryTraceWriter writer(options, &metrics);
        CachedInstruction decoded{};
        CHECK(writer.open(context));
        CHECK(writer.begin(context));
        for (uint32_t opcode = 0; opcode < (1U << 16U); ++opcode) {
            decoded.opcode = opcode;
            CHECK(writer.instruction(context, instruction(opcode + 1ULL, &decoded)));
        }
        CHECK(writer.end(0x55, true, 1));
        CHECK(writer.close());
        CHECK(metrics.instructions == (1U << 16U));
        successful_path = artifact_path(writer);
        CHECK(record_types(read_bytes(successful_path)).back() == BinaryRecordType::TraceEnd);
        CHECK(::unlink(sidecar_path(writer).c_str()) == 0);
        CHECK(::unlink(successful_path.c_str()) == 0);
    }
    {
        TraceMetrics metrics{};
        BinaryTraceWriter writer(options, &metrics);
        CachedInstruction decoded{};
        CHECK(writer.open(context));
        CHECK(writer.begin(context));
        for (uint32_t opcode = 0; opcode < (1U << 16U); ++opcode) {
            decoded.opcode = opcode;
            CHECK(writer.instruction(context, instruction(opcode + 1ULL, &decoded)));
        }
        const uint64_t encoded_before = metrics.encoded_bytes;
        decoded.opcode = 1U << 16U;
        CHECK(!writer.instruction(context, instruction((1U << 16U) + 1ULL, &decoded)));
        CHECK(writer.error_code() == EOVERFLOW);
        CHECK(metrics.instructions == (1U << 16U));
        CHECK(metrics.encoded_bytes == encoded_before);
        const std::string failed_path = artifact_path(writer);
        CHECK(!writer.close());
        CHECK(::access((failed_path + ".metrics").c_str(), F_OK) != 0);
        CHECK(::unlink(failed_path.c_str()) == 0);
    }
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
    compressed_stream_definitions_footer_and_metrics_v3_are_consistent();
    uncompressed_stream_uses_binary_suffix_and_exact_byte_counts();
    uncompressed_stopped_stream_has_one_terminal_and_v3_metrics();
    compressed_stopped_stream_has_one_terminal_and_v3_metrics();
    maximum_rule_and_error_survive_four_kib_buffers_in_order();
    instruction_memory_and_continuations_keep_producer_order();
    sidecar_retries_eintr_and_partial_writes();
    sidecar_write_error_removes_partial_file();
    invalid_lifecycle_transitions_fail_closed();
    instruction_and_memory_hot_path_allocate_nothing();
    chunked_calls_round_trip_utf8_identity_and_maximum_order();
    oversized_logical_call_fails_before_writing_any_fragment();
    encoding_failure_latches_and_does_no_later_event_work();
    failed_definition_is_not_committed();
    metadata_dictionary_boundary_finalizes_65536_and_rejects_65537();
    async_write_error_preserves_first_error_and_suppresses_metrics();
    sidecar_error_removes_partial_metrics_and_close_is_idempotent();
    setup_allocation_failure_latches_enomem_without_artifacts();
    directory_creation_failure_preserves_errno();
    real_mkdir_failure_preserves_enotdir();
    end_waits_for_consumer_before_snapshotting_compressed_bytes();
    padded_footer_is_total_for_exact_cycle_and_adversarial_prefixes();
}
