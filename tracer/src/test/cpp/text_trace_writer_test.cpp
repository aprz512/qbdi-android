#include "events/text_trace_writer.h"
#include "lz4frame.h"

#include <cassert>
#include <atomic>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

namespace {

enum class IoFaultMode : int {
    None,
    SidecarInterruptedAndPartial,
    SidecarWriteError,
    TraceWriteError,
};

std::atomic<IoFaultMode> g_io_fault_mode{IoFaultMode::None};
std::atomic<int> g_sidecar_fd{-1};
std::atomic<int> g_trace_fd{-1};
std::atomic<unsigned int> g_fault_write_calls{0};

bool has_suffix(const char *path, std::string_view suffix) {
    return path != nullptr && std::string_view(path).ends_with(suffix);
}

} // namespace

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
    if (fd < 0) return fd;

    const IoFaultMode fault_mode = g_io_fault_mode.load(std::memory_order_relaxed);
    if (has_suffix(path, ".metrics") &&
        (fault_mode == IoFaultMode::SidecarInterruptedAndPartial ||
         fault_mode == IoFaultMode::SidecarWriteError)) {
        g_sidecar_fd.store(fd, std::memory_order_relaxed);
    } else if (!has_suffix(path, ".metrics") &&
               (has_suffix(path, ".trace.txt") || has_suffix(path, ".trace.txt.lz4")) &&
               fault_mode == IoFaultMode::TraceWriteError) {
        g_trace_fd.store(fd, std::memory_order_relaxed);
    }
    return fd;
}

extern "C" ssize_t __wrap_write(int fd, const void *data, size_t size) {
    const IoFaultMode fault_mode = g_io_fault_mode.load(std::memory_order_relaxed);
    if (fd == g_trace_fd.load(std::memory_order_relaxed) &&
        fault_mode == IoFaultMode::TraceWriteError) {
        ++g_fault_write_calls;
        errno = ENOSPC;
        return -1;
    }
    if (fd == g_sidecar_fd.load(std::memory_order_relaxed)) {
        const unsigned int call = g_fault_write_calls.fetch_add(1, std::memory_order_relaxed);
        if (fault_mode == IoFaultMode::SidecarInterruptedAndPartial) {
            if (call == 0) {
                errno = EINTR;
                return -1;
            }
            if (call == 1 && size > 1) return __real_write(fd, data, size / 2U);
        } else if (fault_mode == IoFaultMode::SidecarWriteError) {
            if (call == 0 && size > 1) return __real_write(fd, data, size / 2U);
            errno = EIO;
            return -1;
        }
    }
    return __real_write(fd, data, size);
}

extern "C" int __wrap_close(int fd) {
    return __real_close(fd);
}

namespace {

void set_io_fault(IoFaultMode mode) {
    g_sidecar_fd.store(-1, std::memory_order_relaxed);
    g_trace_fd.store(-1, std::memory_order_relaxed);
    g_fault_write_calls.store(0, std::memory_order_relaxed);
    g_io_fault_mode.store(mode, std::memory_order_relaxed);
}

std::string make_temporary_directory() {
    char path[] = "/tmp/qtrace-text-writer-XXXXXX";
    char *created = mkdtemp(path);
    assert(created != nullptr);
    return created;
}

std::vector<char> read_file(const std::string &path) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    assert(fd >= 0);
    std::vector<char> bytes;
    char buffer[4096];
    for (;;) {
        const ssize_t result = ::read(fd, buffer, sizeof(buffer));
        if (result == 0) break;
        assert(result > 0);
        bytes.insert(bytes.end(), buffer, buffer + result);
    }
    assert(::close(fd) == 0);
    return bytes;
}

std::string read_text_file(const std::string &path) {
    const std::vector<char> bytes = read_file(path);
    return {bytes.begin(), bytes.end()};
}

std::string metric_value(const std::string &metrics, std::string_view key) {
    const std::string prefix = std::string(key) + "=";
    const size_t begin = metrics.find(prefix);
    assert(begin != std::string::npos);
    const size_t value_begin = begin + prefix.size();
    const size_t end = metrics.find('\n', value_begin);
    assert(end != std::string::npos);
    return metrics.substr(value_begin, end - value_begin);
}

std::string decompress_concatenated_frames(const std::vector<char> &compressed) {
    std::string decoded;
    size_t input_offset = 0;
    while (input_offset < compressed.size()) {
        LZ4F_dctx *context = nullptr;
        assert(!LZ4F_isError(LZ4F_createDecompressionContext(&context, LZ4F_VERSION)));
        size_t result = 1;
        while (result != 0) {
            char output[4096];
            size_t input_size = compressed.size() - input_offset;
            size_t output_size = sizeof(output);
            result = LZ4F_decompress(context, output, &output_size,
                                     compressed.data() + input_offset, &input_size, nullptr);
            assert(!LZ4F_isError(result));
            assert(input_size != 0 || output_size != 0 || result == 0);
            input_offset += input_size;
            decoded.append(output, output_size);
        }
        LZ4F_freeDecompressionContext(context);
    }
    return decoded;
}

TraceContext trace_context(const std::string &directory) {
    TraceContext context{};
    context.output_directory = directory;
    context.package_name = "com.example.demo";
    context.scene_name = "facade";
    context.target_so = "libdemo_target.so";
    context.module_base = 0x1000;
    context.target_offset = 0x10;
    context.target_address = 0x1010;
    context.pid = 12;
    context.tid = 34;
    return context;
}

InstructionRecord instruction_record() {
    static CachedInstruction decoded{};
    std::strcpy(decoded.mnemonic, "nop");
    InstructionRecord record{};
    record.sequence = 1;
    record.pc = 0x1010;
    record.module_base = 0x1000;
    record.decoded = &decoded;
    return record;
}

void emits_ordered_compressed_trace_and_closes_idempotently() {
    const std::string directory = make_temporary_directory();
    TraceOptions options{};
    options.compression_enabled = true;
    options.auto_buffer_size = false;
    options.buffer_bytes = 4096;
    TraceMetrics metrics{};
    TextTraceWriter writer(options, &metrics);
    const TraceContext context = trace_context(directory);

    assert(writer.open(context));
    assert(!writer.open(context));
    assert(writer.begin(context));
    assert(!writer.begin(context));
    assert(writer.instruction(context, instruction_record()));
    assert(writer.call("libc", "memcpy", "target=0x2000"));
    const std::string cold_semantic_payload = "JNI " + std::string(10 * 1024, 'x') + "\n";
    assert(writer.write_raw_line(cold_semantic_payload));
    assert(writer.rule("force_tbnz", "taken=1"));
    assert(writer.end(0x42, true, 7));
    assert(!writer.end(0x42, true, 7));
    assert(writer.close());
    assert(writer.close());
    assert(!writer.end(0x42, true, 7));
    assert(writer.path().ends_with(".trace.txt.lz4"));

    const std::string text = decompress_concatenated_frames(read_file(writer.path()));
    assert(text.find("TRACE_BEGIN") < text.find("1 libdemo_target.so+0x10"));
    assert(text.find("CALL libc.memcpy") < text.find(cold_semantic_payload));
    assert(text.find(cold_semantic_payload) < text.find("RULE force_tbnz"));
    assert(text.find("RULE force_tbnz") < text.find("TRACE_END status=ok"));
    const std::string sidecar = read_text_file(writer.path() + ".metrics");
    assert(text.find("producer_waits=" + metric_value(sidecar, "producer_waits") + " ") !=
           std::string::npos);
    assert(text.find("producer_wait_ns=" + metric_value(sidecar, "producer_wait_ns") + "\n") !=
           std::string::npos);

    assert(::unlink((writer.path() + ".metrics").c_str()) == 0);
    assert(::unlink(writer.path().c_str()) == 0);
    assert(::rmdir(directory.c_str()) == 0);
}

void emits_decodable_uncompressed_trace_with_consistent_final_metrics() {
    const std::string directory = make_temporary_directory();
    TraceOptions options{};
    options.compression_enabled = false;
    options.auto_buffer_size = false;
    options.buffer_bytes = 4096;
    TraceMetrics metrics{};
    TextTraceWriter writer(options, &metrics);
    const TraceContext context = trace_context(directory);

    assert(writer.open(context));
    assert(writer.begin(context));
    assert(writer.instruction(context, instruction_record()));
    assert(writer.end(0, true, 0));
    assert(writer.close());
    assert(writer.path().ends_with(".trace.txt"));
    assert(!writer.path().ends_with(".trace.txt.lz4"));

    const std::string text = read_text_file(writer.path());
    assert(text.starts_with("TRACE_BEGIN"));
    assert(text.ends_with("\n"));
    const std::string sidecar = read_text_file(writer.path() + ".metrics");
    const std::string raw_bytes = metric_value(sidecar, "raw_bytes");
    assert(text.find("raw_bytes=" + raw_bytes + " ") != std::string::npos);
    assert(metric_value(sidecar, "instructions") == "1");
    assert(metric_value(sidecar, "elapsed_ms") == "0");
    assert(metric_value(sidecar, "instructions_per_second") == "0.000000");
    assert(metric_value(sidecar, "compressed_bytes") == raw_bytes);
    assert(metric_value(sidecar, "compression_ratio") == "1.000000");
    for (std::string_view key : {"cache_hits", "cache_misses", "buffer_swaps",
                                 "producer_waits", "producer_wait_ns"}) {
        assert(!metric_value(sidecar, key).empty());
    }

    assert(::unlink((writer.path() + ".metrics").c_str()) == 0);
    assert(::unlink(writer.path().c_str()) == 0);
    assert(::rmdir(directory.c_str()) == 0);
}

void rejects_invalid_lifecycle_transitions_and_open_failures() {
    TraceOptions options{};
    options.auto_buffer_size = false;
    options.buffer_bytes = 4096;
    TraceMetrics metrics{};
    TextTraceWriter unopened(options, &metrics);
    assert(!unopened.end(0, false, 1));
    assert(!unopened.close());
    assert(!unopened.close());

    TraceContext bad_context = trace_context("/dev/null/not-a-directory");
    TextTraceWriter failed_open(options, &metrics);
    assert(!failed_open.open(bad_context));
    assert(!failed_open.begin(bad_context));
    assert(!failed_open.end(0, false, 1));
    assert(!failed_open.close());
    assert(!failed_open.close());

    const std::string directory = make_temporary_directory();
    const TraceContext context = trace_context(directory);
    TextTraceWriter incomplete(options, &metrics);
    assert(incomplete.open(context));
    assert(!incomplete.close());
    assert(!incomplete.end(0, false, 1));
    assert(!incomplete.begin(context));
    assert(::access((incomplete.path() + ".metrics").c_str(), F_OK) != 0);
    assert(::unlink(incomplete.path().c_str()) == 0);
    assert(::rmdir(directory.c_str()) == 0);
}

void retries_interrupted_and_partial_sidecar_writes() {
    const std::string directory = make_temporary_directory();
    TraceOptions options{};
    options.compression_enabled = false;
    options.auto_buffer_size = false;
    options.buffer_bytes = 4096;
    TraceMetrics metrics{};
    TextTraceWriter writer(options, &metrics);
    const TraceContext context = trace_context(directory);

    set_io_fault(IoFaultMode::SidecarInterruptedAndPartial);
    assert(writer.open(context));
    assert(writer.begin(context));
    assert(writer.end(0, true, 3));
    assert(writer.close());
    assert(g_fault_write_calls.load(std::memory_order_relaxed) >= 3);
    set_io_fault(IoFaultMode::None);
    assert(metric_value(read_text_file(writer.path() + ".metrics"), "elapsed_ms") == "3");

    assert(::unlink((writer.path() + ".metrics").c_str()) == 0);
    assert(::unlink(writer.path().c_str()) == 0);
    assert(::rmdir(directory.c_str()) == 0);
}

void removes_partial_sidecar_after_write_error() {
    const std::string directory = make_temporary_directory();
    TraceOptions options{};
    options.compression_enabled = false;
    options.auto_buffer_size = false;
    options.buffer_bytes = 4096;
    TraceMetrics metrics{};
    TextTraceWriter writer(options, &metrics);
    const TraceContext context = trace_context(directory);

    set_io_fault(IoFaultMode::SidecarWriteError);
    assert(writer.open(context));
    assert(writer.begin(context));
    assert(writer.end(0, true, 3));
    assert(!writer.close());
    assert(!writer.close());
    set_io_fault(IoFaultMode::None);
    assert(::access((writer.path() + ".metrics").c_str(), F_OK) != 0);

    assert(::unlink(writer.path().c_str()) == 0);
    assert(::rmdir(directory.c_str()) == 0);
}

void reports_async_trace_write_failure_without_publishing_metrics() {
    const std::string directory = make_temporary_directory();
    TraceOptions options{};
    options.compression_enabled = true;
    options.auto_buffer_size = false;
    options.buffer_bytes = 4096;
    TraceMetrics metrics{};
    TextTraceWriter writer(options, &metrics);
    const TraceContext context = trace_context(directory);

    set_io_fault(IoFaultMode::TraceWriteError);
    assert(writer.open(context));
    assert(writer.begin(context));
    assert(writer.instruction(context, instruction_record()));
    assert(writer.end(0, false, 4));
    assert(!writer.close());
    assert(!writer.close());
    set_io_fault(IoFaultMode::None);
    assert(::access((writer.path() + ".metrics").c_str(), F_OK) != 0);

    assert(::unlink(writer.path().c_str()) == 0);
    assert(::rmdir(directory.c_str()) == 0);
}

void latches_facade_encoding_failures_for_semantic_callers() {
    const std::string directory = make_temporary_directory();
    TraceOptions options{};
    options.compression_enabled = false;
    options.auto_buffer_size = false;
    options.buffer_bytes = 4096;
    TraceMetrics metrics{};
    TextTraceWriter writer(options, &metrics);
    TraceContext context = trace_context(directory);

    assert(writer.open(context));
    assert(writer.begin(context));
    context.target_so = std::string(kMaxInstructionLineBytes, 'm');
    assert(!writer.instruction(context, instruction_record()));
    assert(writer.failed());
    assert(!writer.close());
    assert(::access((writer.path() + ".metrics").c_str(), F_OK) != 0);

    assert(::unlink(writer.path().c_str()) == 0);
    assert(::rmdir(directory.c_str()) == 0);
}

} // namespace

int main() {
    emits_ordered_compressed_trace_and_closes_idempotently();
    emits_decodable_uncompressed_trace_with_consistent_final_metrics();
    rejects_invalid_lifecycle_transitions_and_open_failures();
    retries_interrupted_and_partial_sidecar_writes();
    removes_partial_sidecar_after_write_error();
    reports_async_trace_write_failure_without_publishing_metrics();
    latches_facade_encoding_failures_for_semantic_callers();
}
