#include "core/qbdi_runner_lifecycle.h"
#include "events/binary_trace_format.h"
#include "events/binary_trace_writer.h"
#include "lz4frame.h"
#include "third_party/nlohmann/json.hpp"

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <memory>
#include <string>
#include <string_view>
#include <sys/wait.h>
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

class ConsumerGate final : public TraceFaultInjector {
public:
    bool fail_buffer_allocation(size_t bytes) noexcept override {
        return bytes != 4096;
    }

    bool fail_lz4_operation() noexcept override {
        entered.store(true, std::memory_order_release);
        while (!released.load(std::memory_order_acquire)) std::this_thread::yield();
        return false;
    }

    void wait_until_entered() const {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!entered.load(std::memory_order_acquire) &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::yield();
        }
        CHECK(entered.load(std::memory_order_acquire));
    }

    std::atomic<bool> entered{false};
    std::atomic<bool> released{false};
};

class RecordingPosixBackend final : public TraceWriterBackend {
public:
    int open_file(const char *path, int flags, unsigned int mode) noexcept override {
        opened_fd = TraceWriterBackend::open_file(path, flags, mode);
        return opened_fd;
    }

    int opened_fd = -1;
};

struct ForkingCall {
    pid_t child = -1;
    int inherited_trace_fd = -1;
    bool reuse_trace_fd_before_return = false;
    bool fork_again_in_child = false;
};

int reuse_fd_with_dev_null(int fd) noexcept {
    (void)::close(fd);
    int replacement = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (replacement < 0) return -1;
    if (replacement != fd) {
        if (::dup2(replacement, fd) != fd) {
            (void)::close(replacement);
            return -1;
        }
        (void)::close(replacement);
        replacement = fd;
    }
    return replacement;
}

bool fork_inside_traced_call(void *opaque, uint64_t *return_value) noexcept {
    auto *call = static_cast<ForkingCall *>(opaque);
    const pid_t child = ::fork();
    if (child < 0) return false;
    if (child == 0) {
        if (call->reuse_trace_fd_before_return &&
            reuse_fd_with_dev_null(call->inherited_trace_fd) != call->inherited_trace_fd) {
            _exit(80);
        }
        if (call->fork_again_in_child) {
            const pid_t grandchild = ::fork();
            if (grandchild < 0) _exit(79);
            if (grandchild == 0) {
                _exit(::fcntl(call->inherited_trace_fd, F_GETFD) >= 0 ? 0 : 78);
            }
            int status = -1;
            if (::waitpid(grandchild, &status, 0) != grandchild || !WIFEXITED(status) ||
                WEXITSTATUS(status) != 0) {
                _exit(77);
            }
        }
        *return_value = 0xcafe;
        return true;
    }
    call->child = child;
    *return_value = 0xbeef;
    return true;
}

bool wait_for_child(pid_t child, int *status) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline) {
        const pid_t result = ::waitpid(child, status, WNOHANG);
        if (result == child) return true;
        if (result < 0) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    (void)::kill(child, SIGKILL);
    (void)::waitpid(child, status, 0);
    return false;
}

std::vector<char> read_file(const std::string &path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

std::string decompress_frames(const std::vector<char> &compressed) {
    LZ4F_dctx *context = nullptr;
    CHECK(!LZ4F_isError(LZ4F_createDecompressionContext(&context, LZ4F_VERSION)));
    std::string decoded;
    size_t input_offset = 0;
    while (input_offset < compressed.size()) {
        char output[4096];
        size_t output_size = sizeof(output);
        size_t input_size = compressed.size() - input_offset;
        const size_t result = LZ4F_decompress(
                context, output, &output_size, compressed.data() + input_offset,
                &input_size, nullptr);
        CHECK(!LZ4F_isError(result));
        CHECK(input_size != 0);
        input_offset += input_size;
        decoded.append(output, output_size);
    }
    LZ4F_freeDecompressionContext(context);
    return decoded;
}

uint16_t read_u16(const std::string &bytes, size_t offset) {
    CHECK(offset + 2 <= bytes.size());
    return static_cast<uint16_t>(static_cast<uint8_t>(bytes[offset])) |
           static_cast<uint16_t>(static_cast<uint8_t>(bytes[offset + 1])) << 8U;
}

uint32_t read_u32(const std::string &bytes, size_t offset) {
    CHECK(offset + 4 <= bytes.size());
    return static_cast<uint32_t>(static_cast<uint8_t>(bytes[offset])) |
           static_cast<uint32_t>(static_cast<uint8_t>(bytes[offset + 1])) << 8U |
           static_cast<uint32_t>(static_cast<uint8_t>(bytes[offset + 2])) << 16U |
           static_cast<uint32_t>(static_cast<uint8_t>(bytes[offset + 3])) << 24U;
}

uint64_t read_u64(const std::string &bytes, size_t offset) {
    CHECK(offset + 8 <= bytes.size());
    uint64_t value = 0;
    for (size_t byte = 0; byte < 8; ++byte) {
        value |= static_cast<uint64_t>(
                         static_cast<uint8_t>(bytes[offset + byte]))
                 << (byte * 8U);
    }
    return value;
}

size_t find_record(const std::string &stream, BinaryRecordType expected) {
    if (stream.size() < kBinaryStreamHeaderBytes ||
        stream.compare(0, 4, "QTRB") != 0) {
        return std::string::npos;
    }
    size_t offset = kBinaryStreamHeaderBytes;
    while (offset + kBinaryRecordHeaderBytes <= stream.size()) {
        const auto type = static_cast<BinaryRecordType>(read_u16(stream, offset));
        const size_t payload = read_u32(stream, offset + 4);
        if (payload > stream.size() - offset - kBinaryRecordHeaderBytes) {
            return std::string::npos;
        }
        if (type == expected) return offset;
        offset += kBinaryRecordHeaderBytes + payload;
    }
    return std::string::npos;
}

bool contains_record(const std::string &stream, BinaryRecordType expected) {
    if (stream.size() < kBinaryStreamHeaderBytes || stream.compare(0, 4, "QTRB") != 0)
        return false;
    size_t offset = kBinaryStreamHeaderBytes;
    while (offset + kBinaryRecordHeaderBytes <= stream.size()) {
        const auto type = static_cast<BinaryRecordType>(read_u16(stream, offset));
        const size_t payload = read_u32(stream, offset + 4);
        if (payload > stream.size() - offset - kBinaryRecordHeaderBytes) return false;
        if (type == expected) return true;
        offset += kBinaryRecordHeaderBytes + payload;
    }
    return false;
}

std::string basename_of(std::string_view path) {
    const size_t slash = path.find_last_of('/');
    return std::string(path.substr(slash == std::string_view::npos ? 0 : slash + 1));
}

void normal_writer_publishes_created_artifact_and_stable_error_to_status() {
    char directory_template[] = "/tmp/qtrace-runner-status-XXXXXX";
    char *directory = ::mkdtemp(directory_template);
    CHECK(directory != nullptr);

    TraceConfig config{};
    config.package_name = "com.example.runner";
    config.session.id = "7d5807cf-cf09-4f21-92de-1ad92802610a";
    TraceGenerationStatusOptions status_options{};
    status_options.config = config;
    status_options.output_directory = directory;
    auto runtime = TraceGenerationRuntime::create(
            73, config.session, TraceGenerationLimits{}, DeadlineWait{},
            std::move(status_options));
    CHECK(runtime != nullptr);
    CHECK(runtime->arm());

    TraceOptions options{};
    options.compression_enabled = false;
    options.auto_buffer_size = false;
    options.buffer_bytes = 4096;
    TraceMetrics metrics{};
    TraceContext context{};
    context.scene_name = "status";
    context.target_so = "libtarget.so";
    context.module_base = 0x1000;
    context.target_address = 0x1010;
    context.target_offset = 0x10;
    context.pid = ::getpid();
    context.tid = ::getpid();
    context.output_directory = directory;
    BinaryTraceWriter writer(options, &metrics);
    CHECK(writer.prepare(context));
    CHECK(writer.open_prepared());
    CHECK(writer.begin(context));
    const std::string artifact_path(writer.path());
    CHECK(record_qbdi_normal_artifact(runtime, artifact_path));
    record_qbdi_normal_error(runtime, QbdiNormalError::SessionCreate);
    record_qbdi_normal_error(runtime, QbdiNormalError::SessionCreate);

    const std::string status_path = std::string(directory) + "/session-" +
                                    config.session.id + ".status.json";
    nlohmann::json published;
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline) {
        const std::vector<char> bytes = read_file(status_path);
        if (!bytes.empty()) {
            published = nlohmann::json::parse(bytes.begin(), bytes.end(), nullptr,
                                               false);
            if (!published.is_discarded() &&
                published.at("artifacts").size() == 1 &&
                published.at("errors").size() == 1) {
                break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    CHECK(!published.is_discarded());
    CHECK(published.at("errors").size() == 1);
    CHECK(published.at("artifacts").at(0) == basename_of(artifact_path));
    CHECK(published.at("errors").at(0).at("code") ==
          "QBDI_SESSION_CREATE_FAILED");

    CHECK(writer.end(0, true, 1));
    CHECK(writer.close());
    runtime.reset();
    CHECK(::unlink(artifact_path.c_str()) == 0);
    CHECK(::unlink((artifact_path + ".metrics").c_str()) == 0);
    CHECK(::unlink(status_path.c_str()) == 0);
    (void)::unlink((status_path + ".backup").c_str());
    (void)::unlink((status_path + ".restore").c_str());
    (void)::unlink((status_path + ".rollback").c_str());
    (void)::unlink((status_path + ".commit").c_str());
    CHECK(::rmdir(directory) == 0);
}

void stopped_writer_closes_without_a_completed_terminal() {
    char directory_template[] = "/tmp/qtrace-runner-stop-XXXXXX";
    char *directory = ::mkdtemp(directory_template);
    CHECK(directory != nullptr);

    TraceOptions options{};
    options.compression_enabled = false;
    options.auto_buffer_size = false;
    options.buffer_bytes = 4096;
    TraceMetrics metrics{};
    TraceContext context{};
    context.scene_name = "stopped";
    context.target_so = "libtarget.so";
    context.module_base = 0x1000;
    context.target_address = 0x1010;
    context.target_offset = 0x10;
    context.pid = ::getpid();
    context.tid = ::getpid();
    context.output_directory = directory;

    BinaryTraceWriter writer(options, &metrics);
    CHECK(writer.open(context));
    const std::string path(writer.path());
    CHECK(writer.begin(context));
    CHECK(writer.stop(TraceStopReason::DurationElapsed, 17));
    CHECK(!writer.end(0x44, true, 18));
    CHECK(writer.close());

    const std::vector<char> bytes = read_file(path);
    const std::string trace(bytes.begin(), bytes.end());
    CHECK(contains_record(trace, BinaryRecordType::TraceStop));
    CHECK(!contains_record(trace, BinaryRecordType::TraceEnd));
    CHECK(::unlink(path.c_str()) == 0);
    CHECK(::unlink((path + ".metrics").c_str()) == 0);
    CHECK(::rmdir(directory) == 0);
}

struct RunnerDeadline {
    std::atomic<bool> entered{false};
    std::atomic<bool> release{false};

    static void wait_until(void *opaque, uint64_t,
                           const std::atomic<bool> *stop) noexcept {
        auto *deadline = static_cast<RunnerDeadline *>(opaque);
        deadline->entered.store(true, std::memory_order_release);
        while (!deadline->release.load(std::memory_order_acquire) &&
               !stop->load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
    }

    void request_stop(const std::shared_ptr<TraceGenerationRuntime> &runtime) {
        while (!entered.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
        release.store(true, std::memory_order_release);
        runtime->join_deadline_for_test();
        CHECK(runtime->stop_token().requested());
    }
};

long fixed_elapsed(void *opaque) noexcept {
    return *static_cast<long *>(opaque);
}

SessionOptions runner_timed_session() {
    SessionOptions session{};
    session.id = "runner-stop";
    session.duration_ms = 60000;
    return session;
}

TraceAdmission admit_runner(
        const std::shared_ptr<TraceGenerationRuntime> &runtime,
        uint64_t generation, size_t scene_index, uint32_t tid) {
    const TraceAdmissionResult result = runtime->try_begin_call(
            generation, scene_index, tid);
    CHECK(result.status == TraceAdmissionStatus::Admitted);
    return result.admission;
}

void normal_stop_lifecycle_seals_and_acknowledges_the_exact_admission_once() {
    RunnerDeadline deadline;
    auto runtime = TraceGenerationRuntime::create(
            71, runner_timed_session(),
            DeadlineWait{&deadline, &RunnerDeadline::wait_until});
    CHECK(runtime != nullptr);
    CHECK(runtime->arm());
    const TraceAdmission admission = admit_runner(runtime, 71, 4, 101);
    CHECK(admission.generation == 71);
    CHECK(admission.scene_index == 4);
    CHECK(admission.tid == 101);
    CHECK(admission.serial != 0);
    deadline.request_stop(runtime);

    char directory_template[] = "/tmp/qtrace-runner-runtime-stop-XXXXXX";
    char *directory = ::mkdtemp(directory_template);
    CHECK(directory != nullptr);
    TraceOptions options{};
    options.compression_enabled = false;
    options.auto_buffer_size = false;
    options.buffer_bytes = 4096;
    TraceMetrics metrics{};
    TraceContext context{};
    context.scene_name = "runtime-stop";
    context.target_so = "libtarget.so";
    context.module_base = 0x1000;
    context.target_address = 0x1010;
    context.target_offset = 0x10;
    context.pid = ::getpid();
    context.tid = ::getpid();
    context.output_directory = directory;
    BinaryTraceWriter writer(options, &metrics);
    CHECK(writer.open(context));
    const std::string path(writer.path());
    CHECK(writer.begin(context));
    long elapsed_ms = 37;
    QbdiNormalStopLifecycle lifecycle(
            &writer, runtime, admission, &elapsed_ms, fixed_elapsed);
    CHECK(lifecycle.enabled());
    CHECK(lifecycle.token() == &runtime->stop_token());

    CHECK(lifecycle.seal(TraceStopReason::DurationElapsed));
    CHECK(lifecycle.seal(TraceStopReason::DurationElapsed));
    lifecycle.acknowledge(true);
    lifecycle.acknowledge(true);

    CHECK(lifecycle.stop_observed());
    CHECK(lifecycle.sealed());
    CHECK(lifecycle.seal_calls() == 1);
    CHECK(lifecycle.acknowledge_calls() == 1);
    CHECK(runtime->snapshot().phase == TraceGenerationPhase::Sealed);
    CHECK(!writer.end(0x44, true, 38));
    CHECK(writer.close());
    const std::vector<char> bytes = read_file(path);
    const std::string trace(bytes.begin(), bytes.end());
    const size_t stop = find_record(trace, BinaryRecordType::TraceStop);
    CHECK(stop != std::string::npos);
    CHECK(static_cast<uint8_t>(trace[stop + kBinaryRecordHeaderBytes]) ==
          static_cast<uint8_t>(TraceStopReason::DurationElapsed));
    CHECK(read_u64(trace, stop + kBinaryRecordHeaderBytes + 8) == 37);
    CHECK(!contains_record(trace, BinaryRecordType::TraceEnd));
    CHECK(::unlink(path.c_str()) == 0);
    CHECK(::unlink((path + ".metrics").c_str()) == 0);
    CHECK(::rmdir(directory) == 0);
}

void normal_stop_lifecycle_reports_a_failed_seal_once() {
    RunnerDeadline deadline;
    auto runtime = TraceGenerationRuntime::create(
            72, runner_timed_session(),
            DeadlineWait{&deadline, &RunnerDeadline::wait_until});
    CHECK(runtime != nullptr);
    CHECK(runtime->arm());
    const TraceAdmission admission = admit_runner(runtime, 72, 5, 202);
    deadline.request_stop(runtime);

    char directory_template[] = "/tmp/qtrace-runner-runtime-fail-XXXXXX";
    char *directory = ::mkdtemp(directory_template);
    CHECK(directory != nullptr);
    TraceOptions options{};
    options.compression_enabled = false;
    options.auto_buffer_size = false;
    options.buffer_bytes = 4096;
    TraceMetrics metrics{};
    TraceContext context{};
    context.scene_name = "runtime-fail";
    context.target_so = "libtarget.so";
    context.module_base = 0x1000;
    context.target_address = 0x1010;
    context.target_offset = 0x10;
    context.pid = ::getpid();
    context.tid = ::getpid();
    context.output_directory = directory;
    BinaryTraceWriter writer(options, &metrics);
    CHECK(writer.open(context));
    const std::string path(writer.path());
    CHECK(writer.begin(context));
    CHECK(!writer.end(0, false, 1));
    long elapsed_ms = 41;
    QbdiNormalStopLifecycle lifecycle(
            &writer, runtime, admission, &elapsed_ms, fixed_elapsed);

    CHECK(!lifecycle.seal(TraceStopReason::DurationElapsed));
    CHECK(!lifecycle.seal(TraceStopReason::DurationElapsed));
    lifecycle.acknowledge(false);
    lifecycle.acknowledge(false);

    CHECK(lifecycle.stop_observed());
    CHECK(!lifecycle.sealed());
    CHECK(lifecycle.seal_calls() == 1);
    CHECK(lifecycle.acknowledge_calls() == 1);
    CHECK(runtime->snapshot().phase == TraceGenerationPhase::StopIncomplete);
    CHECK(!writer.close());
    CHECK(::unlink(path.c_str()) == 0);
    CHECK(::rmdir(directory) == 0);
}

void traced_fork_child_detaches_writer_and_parent_completes_artifact() {
    char directory_template[] = "/tmp/qtrace-runner-fork-XXXXXX";
    char *directory = ::mkdtemp(directory_template);
    CHECK(directory != nullptr);

    TraceOptions options{};
    options.auto_buffer_size = false;
    options.buffer_bytes = 4096;
    TraceMetrics metrics{};
    ConsumerGate gate;
    TraceContext context{};
    context.scene_name = "fork";
    context.target_so = "libtarget.so";
    context.module_base = 0x1000;
    context.target_address = 0x1010;
    context.target_offset = 0x10;
    context.pid = ::getpid();
    context.tid = ::getpid();
    context.output_directory = directory;

    RecordingPosixBackend backend;
    BinaryTraceWriter writer(options, &metrics, &backend, &gate);
    CHECK(writer.prepare(context));
    const std::string path(writer.path());
    CHECK(writer.open_prepared());
    CHECK(backend.opened_fd >= 0);
    CHECK(writer.begin(context));
    CHECK(writer.call("stress", "publication-a", std::string(3000, 'g')));
    CHECK(writer.call("stress", "publication-b", std::string(1000, 'h')));
    gate.wait_until_entered();

    TraceMetrics secondary_metrics{};
    TraceContext secondary_context = context;
    secondary_context.scene_name = "fork-secondary";
    RecordingPosixBackend secondary_backend;
    BinaryTraceWriter secondary_writer(options, &secondary_metrics, &secondary_backend);
    CHECK(secondary_writer.prepare(secondary_context));
    const std::string secondary_path(secondary_writer.path());
    CHECK(secondary_writer.open_prepared());
    CHECK(secondary_backend.opened_fd >= 0);
    CHECK(secondary_writer.begin(secondary_context));

    ForkingCall call{-1, backend.opened_fd, false, false};
    const QbdiTargetCallResult result =
            run_qbdi_target_call(fork_inside_traced_call, &call, &writer);
    if (result.child_detached) {
        if (!result.succeeded || result.return_value != 0xcafe) _exit(81);
        errno = 0;
        if (::fcntl(backend.opened_fd, F_GETFD) != -1 || errno != EBADF) _exit(82);
        errno = 0;
        if (::fcntl(secondary_backend.opened_fd, F_GETFD) != -1 || errno != EBADF) _exit(88);
        const int reused = reuse_fd_with_dev_null(backend.opened_fd);
        if (reused != backend.opened_fd) _exit(83);
        secondary_writer.~BinaryTraceWriter();
        writer.~BinaryTraceWriter();
        if (::fcntl(reused, F_GETFD) < 0) _exit(84);
        (void)::close(reused);
        _exit(0);
    }

    CHECK(result.succeeded);
    CHECK(result.return_value == 0xbeef);
    CHECK(call.child > 0);

    ForkingCall reused_call{-1, backend.opened_fd, true, true};
    const QbdiTargetCallResult reused_result =
            run_qbdi_target_call(fork_inside_traced_call, &reused_call, &writer);
    if (reused_result.child_detached) {
        if (!reused_result.succeeded || reused_result.return_value != 0xcafe) _exit(85);
        if (::fcntl(backend.opened_fd, F_GETFD) < 0) _exit(86);
        errno = 0;
        if (::fcntl(secondary_backend.opened_fd, F_GETFD) != -1 || errno != EBADF) _exit(89);
        secondary_writer.~BinaryTraceWriter();
        writer.~BinaryTraceWriter();
        if (::fcntl(backend.opened_fd, F_GETFD) < 0) _exit(87);
        (void)::close(backend.opened_fd);
        _exit(0);
    }
    CHECK(reused_result.succeeded);
    CHECK(reused_result.return_value == 0xbeef);
    CHECK(reused_call.child > 0);

    gate.released.store(true, std::memory_order_release);
    CHECK(writer.end(result.return_value, true, 1));
    CHECK(writer.close());
    CHECK(secondary_writer.end(result.return_value, true, 1));
    CHECK(secondary_writer.close());

    int child_status = -1;
    CHECK(wait_for_child(call.child, &child_status));
    CHECK(WIFEXITED(child_status));
    CHECK(WEXITSTATUS(child_status) == 0);
    CHECK(wait_for_child(reused_call.child, &child_status));
    CHECK(WIFEXITED(child_status));
    CHECK(WEXITSTATUS(child_status) == 0);
    const std::string trace = decompress_frames(read_file(path));
    const std::string secondary_trace = decompress_frames(read_file(secondary_path));
    CHECK(std::string_view(path).ends_with(".trace.bin.lz4"));
    CHECK(std::string_view(secondary_path).ends_with(".trace.bin.lz4"));
    CHECK(trace.compare(0, 4, "QTRB") == 0);
    CHECK(secondary_trace.compare(0, 4, "QTRB") == 0);
    CHECK(contains_record(trace, BinaryRecordType::TraceBegin));
    CHECK(contains_record(trace, BinaryRecordType::Call));
    CHECK(contains_record(trace, BinaryRecordType::TraceEnd));
    CHECK(contains_record(secondary_trace, BinaryRecordType::TraceEnd));
    CHECK(::access((path + ".metrics").c_str(), F_OK) == 0);
    CHECK(::access((secondary_path + ".metrics").c_str(), F_OK) == 0);

    CHECK(::unlink(path.c_str()) == 0);
    CHECK(::unlink((path + ".metrics").c_str()) == 0);
    CHECK(::unlink(secondary_path.c_str()) == 0);
    CHECK(::unlink((secondary_path + ".metrics").c_str()) == 0);
    CHECK(::rmdir(directory) == 0);
}

} // namespace

int main() {
    normal_writer_publishes_created_artifact_and_stable_error_to_status();
    stopped_writer_closes_without_a_completed_terminal();
    normal_stop_lifecycle_seals_and_acknowledges_the_exact_admission_once();
    normal_stop_lifecycle_reports_a_failed_seal_once();
    traced_fork_child_detaches_writer_and_parent_completes_artifact();
}
