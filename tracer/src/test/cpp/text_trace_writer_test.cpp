#include "core/instruction_cache.h"
#include "events/text_trace_writer.h"
#include "core/trace_run_session.h"
#include "lz4frame.h"

#include <atomic>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <new>
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
std::atomic<size_t> g_allocations{0};

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
        bytes_written += size;
        return static_cast<ssize_t>(size);
    }

    int close_file(int) noexcept override {
        ++close_calls;
        return 0;
    }

    std::atomic<unsigned int> open_calls{0};
    std::atomic<unsigned int> write_calls{0};
    std::atomic<unsigned int> close_calls{0};
    std::atomic<uint64_t> bytes_written{0};
};

bool has_suffix(const char *path, std::string_view suffix) {
    return path != nullptr && std::string_view(path).ends_with(suffix);
}

} // namespace

void *operator new(size_t size) {
    g_allocations.fetch_add(1, std::memory_order_relaxed);
    if (void *allocation = std::malloc(size)) return allocation;
    throw std::bad_alloc();
}

void *operator new[](size_t size) {
    return ::operator new(size);
}

void *operator new(size_t size, const std::nothrow_t &) noexcept {
    g_allocations.fetch_add(1, std::memory_order_relaxed);
    return std::malloc(size);
}

void *operator new[](size_t size, const std::nothrow_t &tag) noexcept {
    return ::operator new(size, tag);
}

void operator delete(void *allocation) noexcept {
    std::free(allocation);
}

void operator delete[](void *allocation) noexcept {
    ::operator delete(allocation);
}

void operator delete(void *allocation, size_t) noexcept {
    std::free(allocation);
}

void operator delete[](void *allocation, size_t) noexcept {
    ::operator delete(allocation);
}

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
    CHECK(created != nullptr);
    return created;
}

std::vector<char> read_file(const std::string &path) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0);
    std::vector<char> bytes;
    char buffer[4096];
    for (;;) {
        const ssize_t result = ::read(fd, buffer, sizeof(buffer));
        if (result == 0) break;
        CHECK(result > 0);
        bytes.insert(bytes.end(), buffer, buffer + result);
    }
    CHECK(::close(fd) == 0);
    return bytes;
}

std::string read_text_file(const std::string &path) {
    const std::vector<char> bytes = read_file(path);
    return {bytes.begin(), bytes.end()};
}

std::string metric_value(const std::string &metrics, std::string_view key) {
    const std::string prefix = std::string(key) + "=";
    const size_t begin = metrics.find(prefix);
    CHECK(begin != std::string::npos);
    const size_t value_begin = begin + prefix.size();
    const size_t end = metrics.find('\n', value_begin);
    CHECK(end != std::string::npos);
    return metrics.substr(value_begin, end - value_begin);
}

std::string decompress_concatenated_frames(const std::vector<char> &compressed) {
    std::string decoded;
    size_t input_offset = 0;
    while (input_offset < compressed.size()) {
        LZ4F_dctx *context = nullptr;
        CHECK(!LZ4F_isError(LZ4F_createDecompressionContext(&context, LZ4F_VERSION)));
        size_t result = 1;
        while (result != 0) {
            char output[4096];
            size_t input_size = compressed.size() - input_offset;
            size_t output_size = sizeof(output);
            result = LZ4F_decompress(context, output, &output_size,
                                     compressed.data() + input_offset, &input_size, nullptr);
            CHECK(!LZ4F_isError(result));
            CHECK(input_size != 0 || output_size != 0 || result == 0);
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

    CHECK(writer.open(context));
    CHECK(!writer.open(context));
    CHECK(writer.begin(context));
    CHECK(!writer.begin(context));
    CHECK(writer.instruction(context, instruction_record()));
    CHECK(writer.call("libc", "memcpy", "target=0x2000"));
    const std::string cold_semantic_payload = "JNI " + std::string(10 * 1024, 'x') + "\n";
    CHECK(writer.write_raw_line(cold_semantic_payload));
    CHECK(writer.rule("force_tbnz", "taken=1"));
    CHECK(writer.end(0x42, true, 7));
    CHECK(!writer.end(0x42, true, 7));
    CHECK(writer.close());
    CHECK(writer.close());
    CHECK(!writer.end(0x42, true, 7));
    CHECK(writer.path().ends_with(".trace.txt.lz4"));

    const std::string text = decompress_concatenated_frames(read_file(writer.path()));
    CHECK(text.find("TRACE_BEGIN") < text.find("1 libdemo_target.so+0x10"));
    CHECK(text.find("CALL libc.memcpy") < text.find(cold_semantic_payload));
    CHECK(text.find(cold_semantic_payload) < text.find("RULE force_tbnz"));
    CHECK(text.find("RULE force_tbnz") < text.find("TRACE_END status=ok"));
    const std::string sidecar = read_text_file(writer.path() + ".metrics");
    const std::string buffer_swaps = metric_value(sidecar, "buffer_swaps");
    CHECK(std::stoull(buffer_swaps) > 1);
    CHECK(text.find("buffer_swaps=" + buffer_swaps + " ") != std::string::npos);
    CHECK(text.find("producer_waits=" + metric_value(sidecar, "producer_waits") + " ") !=
           std::string::npos);
    CHECK(text.find("producer_wait_ns=" + metric_value(sidecar, "producer_wait_ns") + "\n") !=
           std::string::npos);

    CHECK(::unlink((writer.path() + ".metrics").c_str()) == 0);
    CHECK(::unlink(writer.path().c_str()) == 0);
    CHECK(::rmdir(directory.c_str()) == 0);
}

void emits_decodable_uncompressed_trace_with_consistent_final_metrics() {
    const std::string directory = make_temporary_directory();
    TraceOptions options{};
    options.compression_enabled = false;
    options.auto_buffer_size = false;
    options.buffer_bytes = 8192;
    TraceMetrics metrics{};
    TextTraceWriter writer(options, &metrics);
    const TraceContext context = trace_context(directory);

    CHECK(writer.open(context));
    CHECK(writer.begin(context));
    CHECK(writer.instruction(context, instruction_record()));
    CHECK(writer.end(0, true, 0));
    CHECK(writer.close());
    CHECK(writer.path().ends_with(".trace.txt"));
    CHECK(!writer.path().ends_with(".trace.txt.lz4"));

    const std::string text = read_text_file(writer.path());
    CHECK(text.starts_with("TRACE_BEGIN"));
    CHECK(text.ends_with("\n"));
    const std::string sidecar = read_text_file(writer.path() + ".metrics");
    const std::string raw_bytes = metric_value(sidecar, "raw_bytes");
    CHECK(text.find("raw_bytes=" + raw_bytes + " ") != std::string::npos);
    CHECK(metric_value(sidecar, "instructions") == "1");
    CHECK(metric_value(sidecar, "elapsed_ms") == "0");
    CHECK(metric_value(sidecar, "instructions_per_second") == "0.000000");
    CHECK(metric_value(sidecar, "compressed_bytes") == raw_bytes);
    CHECK(metric_value(sidecar, "compression_ratio") == "1.000000");
    CHECK(metric_value(sidecar, "buffer_swaps") == "1");
    CHECK(text.find("buffer_swaps=1 ") != std::string::npos);
    for (std::string_view key : {"cache_hits", "cache_misses", "buffer_swaps",
                                 "producer_waits", "producer_wait_ns"}) {
        CHECK(!metric_value(sidecar, key).empty());
    }

    CHECK(::unlink((writer.path() + ".metrics").c_str()) == 0);
    CHECK(::unlink(writer.path().c_str()) == 0);
    CHECK(::rmdir(directory.c_str()) == 0);
}

void emits_memory_without_hot_path_allocations() {
    const std::string directory = make_temporary_directory();
    TraceOptions options{};
    options.compression_enabled = false;
    options.auto_buffer_size = false;
    options.buffer_bytes = 8192;
    TraceMetrics metrics{};
    TextTraceWriter writer(options, &metrics);
    const TraceContext context = trace_context(directory);
    MemoryRecord memory{};
    memory.kind = MemoryAccessKind::Write;
    memory.address = 0x2000;
    memory.size = 8;
    memory.value = 0x42;

    CHECK(writer.open(context));
    CHECK(writer.begin(context));
    const size_t allocations_before = g_allocations.load(std::memory_order_relaxed);
    CHECK(writer.memory(context, context.module_base + 0x10, memory));
    CHECK(g_allocations.load(std::memory_order_relaxed) == allocations_before);
    CHECK(writer.end(0, true, 1));
    CHECK(writer.close());

    const std::string text = read_text_file(writer.path());
    CHECK(text.find("MEM libdemo_target.so+0x10 type=w addr=0x2000 size=8 value=0x42\n") !=
           std::string::npos);
    CHECK(::unlink((writer.path() + ".metrics").c_str()) == 0);
    CHECK(::unlink(writer.path().c_str()) == 0);
    CHECK(::rmdir(directory.c_str()) == 0);
}

void rejects_invalid_lifecycle_transitions_and_open_failures() {
    TraceOptions options{};
    options.auto_buffer_size = false;
    options.buffer_bytes = 4096;
    TraceMetrics metrics{};
    TextTraceWriter unopened(options, &metrics);
    CHECK(!unopened.end(0, false, 1));
    CHECK(!unopened.close());
    CHECK(!unopened.close());

    TraceContext bad_context = trace_context("/dev/null/not-a-directory");
    TextTraceWriter failed_open(options, &metrics);
    CHECK(!failed_open.open(bad_context));
    CHECK(!failed_open.begin(bad_context));
    CHECK(!failed_open.end(0, false, 1));
    CHECK(!failed_open.close());
    CHECK(!failed_open.close());

    const std::string directory = make_temporary_directory();
    const TraceContext context = trace_context(directory);
    TextTraceWriter incomplete(options, &metrics);
    CHECK(incomplete.open(context));
    CHECK(!incomplete.close());
    CHECK(!incomplete.end(0, false, 1));
    CHECK(!incomplete.begin(context));
    CHECK(::access((incomplete.path() + ".metrics").c_str(), F_OK) != 0);
    CHECK(::unlink(incomplete.path().c_str()) == 0);
    CHECK(::rmdir(directory.c_str()) == 0);
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
    CHECK(writer.open(context));
    CHECK(writer.begin(context));
    CHECK(writer.end(0, true, 3));
    CHECK(writer.close());
    CHECK(g_fault_write_calls.load(std::memory_order_relaxed) >= 3);
    set_io_fault(IoFaultMode::None);
    CHECK(metric_value(read_text_file(writer.path() + ".metrics"), "elapsed_ms") == "3");

    CHECK(::unlink((writer.path() + ".metrics").c_str()) == 0);
    CHECK(::unlink(writer.path().c_str()) == 0);
    CHECK(::rmdir(directory.c_str()) == 0);
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
    CHECK(writer.open(context));
    CHECK(writer.begin(context));
    CHECK(writer.end(0, true, 3));
    CHECK(!writer.close());
    CHECK(!writer.close());
    set_io_fault(IoFaultMode::None);
    CHECK(::access((writer.path() + ".metrics").c_str(), F_OK) != 0);

    CHECK(::unlink(writer.path().c_str()) == 0);
    CHECK(::rmdir(directory.c_str()) == 0);
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
    CHECK(writer.open(context));
    CHECK(writer.begin(context));
    CHECK(writer.instruction(context, instruction_record()));
    CHECK(writer.end(0, false, 4));
    CHECK(!writer.close());
    CHECK(!writer.close());
    set_io_fault(IoFaultMode::None);
    CHECK(::access((writer.path() + ".metrics").c_str(), F_OK) != 0);

    CHECK(::unlink(writer.path().c_str()) == 0);
    CHECK(::rmdir(directory.c_str()) == 0);
}

void finalizes_early_setup_failure_without_running_target() {
    const std::string directory = make_temporary_directory();
    TraceOptions options{};
    options.compression_enabled = false;
    options.auto_buffer_size = false;
    options.buffer_bytes = 4096;
    TraceMetrics metrics{};
    TextTraceWriter writer(options, &metrics);
    const TraceContext context = trace_context(directory);
    TraceRunSessionOutcome session;

    CHECK(writer.open(context));
    CHECK(writer.begin(context));
    session.observe_trace_setup(true);
    session.observe_execution_setup(false);
    bool target_ran = false;
    if (session.target_should_run()) target_ran = true;
    session.observe_target_call({target_ran, false, 99}, writer.failed());
    const TraceRunFinalization finalization = session.finalize(writer, 4);

    CHECK(!target_ran);
    CHECK(!finalization.target_ran);
    CHECK(!finalization.footer_success);
    CHECK(!finalization.completion_success);
    CHECK(!finalization.should_log_success);
    CHECK(finalization.outward_return_value == 0);
    CHECK(::access((writer.path() + ".metrics").c_str(), F_OK) != 0);
    const std::string text = read_text_file(writer.path());
    CHECK(text.find("TRACE_END status=failed ret=0x0") != std::string::npos);

    CHECK(::unlink(writer.path().c_str()) == 0);
    CHECK(::rmdir(directory.c_str()) == 0);
}

void finalizes_registration_failure_after_running_target() {
    const std::string directory = make_temporary_directory();
    TraceOptions options{};
    options.compression_enabled = false;
    options.auto_buffer_size = false;
    options.buffer_bytes = 4096;
    TraceMetrics metrics{};
    TextTraceWriter writer(options, &metrics);
    const TraceContext context = trace_context(directory);
    TraceRunSessionOutcome session;

    CHECK(writer.open(context));
    CHECK(writer.begin(context));
    session.observe_trace_setup(true);
    session.observe_execution_setup(true);
    session.observe_memory_instrumentation(true, false, false);
    bool target_ran = false;
    const auto run_target = [&] {
        target_ran = true;
        return uint64_t{73};
    };
    CHECK(session.target_should_run());
    const uint64_t target_retval = run_target();
    CHECK(target_ran);
    session.observe_target_call({target_ran, true, target_retval}, writer.failed());
    const TraceRunFinalization finalization = session.finalize(writer, 4);
    CHECK(finalization.target_ran);
    CHECK(!finalization.footer_success);
    CHECK(!finalization.completion_success);
    CHECK(!finalization.should_log_success);
    CHECK(finalization.outward_return_value == 73);
    CHECK(::access((writer.path() + ".metrics").c_str(), F_OK) != 0);
    const std::string text = read_text_file(writer.path());
    CHECK(text.find("TRACE_END status=failed ret=0x49") != std::string::npos);

    CHECK(::unlink(writer.path().c_str()) == 0);
    CHECK(::rmdir(directory.c_str()) == 0);
}

void finalizes_success_with_one_authoritative_result() {
    const std::string directory = make_temporary_directory();
    TraceOptions options{};
    options.compression_enabled = false;
    options.auto_buffer_size = false;
    options.buffer_bytes = 4096;
    TraceMetrics metrics{};
    TextTraceWriter writer(options, &metrics);
    const TraceContext context = trace_context(directory);
    TraceRunSessionOutcome session;

    CHECK(writer.open(context));
    CHECK(writer.begin(context));
    session.observe_trace_setup(true);
    session.observe_execution_setup(true);
    session.observe_memory_instrumentation(true, true, true);
    CHECK(session.target_should_run());
    session.observe_target_call({true, true, 91}, writer.failed());
    const TraceRunFinalization finalization = session.finalize(writer, 6);

    CHECK(finalization.target_ran);
    CHECK(finalization.footer_success);
    CHECK(finalization.completion_success);
    CHECK(finalization.should_log_success);
    CHECK(finalization.outward_return_value == 91);
    CHECK(::access((writer.path() + ".metrics").c_str(), F_OK) == 0);
    const std::string text = read_text_file(writer.path());
    CHECK(text.find("TRACE_END status=ok ret=0x5b") != std::string::npos);

    CHECK(::unlink((writer.path() + ".metrics").c_str()) == 0);
    CHECK(::unlink(writer.path().c_str()) == 0);
    CHECK(::rmdir(directory.c_str()) == 0);
}

void latches_facade_encoding_failures_for_semantic_callers() {
    const std::string directory = make_temporary_directory();
    TraceOptions options{};
    options.compression_enabled = false;
    options.auto_buffer_size = false;
    options.buffer_bytes = 4096;
    TraceMetrics metrics{};
    CountingBackend backend;
    TextTraceWriter writer(options, &metrics, &backend);
    TraceContext context = trace_context(directory);

    CHECK(writer.open(context));
    CHECK(writer.begin(context));
    context.target_so = std::string(kMaxInstructionLineBytes, 'm');
    CHECK(!writer.instruction(context, instruction_record()));
    CHECK(writer.failed());
    const uint64_t raw_bytes_after_failure = metrics.raw_bytes;
    const size_t allocations_after_failure = g_allocations.load(std::memory_order_relaxed);
    context.target_so = "libdemo_target.so";
    MemoryRecord memory{};
    constexpr char long_category[] =
        "category-long-enough-to-require-qualified-name-allocation-after-the-latch";
    CHECK(!writer.instruction(context, instruction_record()));
    CHECK(!writer.memory(context, context.target_address, memory));
    CHECK(!writer.call(long_category, "later", "detail"));
    CHECK(!writer.rule("later", "detail"));
    CHECK(!writer.error("later"));
    CHECK(!writer.write_raw_line("LATER"));
    CHECK(metrics.raw_bytes == raw_bytes_after_failure);
    CHECK(g_allocations.load(std::memory_order_relaxed) == allocations_after_failure);
    CHECK(!writer.end(0, false, 5));
    CHECK(!writer.close());
    CHECK(!writer.close());
    CHECK(backend.open_calls.load(std::memory_order_relaxed) == 1);
    CHECK(backend.write_calls.load(std::memory_order_relaxed) == 1);
    CHECK(backend.bytes_written.load(std::memory_order_relaxed) == raw_bytes_after_failure);
    CHECK(backend.close_calls.load(std::memory_order_relaxed) == 1);
    CHECK(::access((writer.path() + ".metrics").c_str(), F_OK) != 0);

    CHECK(::rmdir(directory.c_str()) == 0);
}

} // namespace

int main() {
    emits_ordered_compressed_trace_and_closes_idempotently();
    emits_decodable_uncompressed_trace_with_consistent_final_metrics();
    emits_memory_without_hot_path_allocations();
    rejects_invalid_lifecycle_transitions_and_open_failures();
    retries_interrupted_and_partial_sidecar_writes();
    removes_partial_sidecar_after_write_error();
    reports_async_trace_write_failure_without_publishing_metrics();
    finalizes_early_setup_failure_without_running_target();
    finalizes_registration_failure_after_running_target();
    finalizes_success_with_one_authoritative_result();
    latches_facade_encoding_failures_for_semantic_callers();
}
