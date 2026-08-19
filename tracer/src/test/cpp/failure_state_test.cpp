#include "core/crash_marker.h"
#include "core/qbdi_runner.h"
#include "events/async_trace_writer.h"
#include "events/text_trace_writer.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

volatile sig_atomic_t g_forwarded_signals = 0;

void forwarding_handler(int) {
    g_forwarded_signals = static_cast<sig_atomic_t>(g_forwarded_signals + 1);
}

void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

class MemoryBackend final : public TraceWriterBackend {
public:
    int open_file(const char *, int, unsigned int) noexcept override { return 41; }
    ssize_t write_file(int, const void *, size_t size) noexcept override {
        return static_cast<ssize_t>(size);
    }
    int close_file(int) noexcept override { return 0; }
};

class FakeFaultInjector final : public TraceFaultInjector {
public:
    FakeFaultInjector(FailurePoint selected, int selected_error) noexcept
        : selected_(selected), selected_error_(selected_error) {}

    int failure(FailurePoint point) noexcept override {
        return point == selected_ ? selected_error_ : 0;
    }

private:
    FailurePoint selected_;
    int selected_error_;
};

TraceOptions options() {
    TraceOptions result{};
    result.compression_enabled = true;
    result.auto_buffer_size = false;
    result.buffer_bytes = 4096;
    return result;
}

TraceContext context(const std::string &directory) {
    TraceContext result{};
    result.output_directory = directory;
    result.package_name = "com.example.failure";
    result.scene_name = "failure";
    result.target_so = "libfailure.so";
    result.target_offset = 0x10;
    result.target_address = 0x1010;
    result.pid = 12;
    result.tid = 34;
    return result;
}

void setup_failures_latch_their_code_and_finish_is_idempotent() {
    for (FailurePoint point : {FailurePoint::Allocation, FailurePoint::Synchronization,
                               FailurePoint::ThreadCreation,
                               FailurePoint::CompressionAllocation}) {
        MemoryBackend backend;
        FakeFaultInjector faults(point, EAGAIN);
        TraceMetrics metrics{};
        AsyncTraceWriter writer(&backend, &faults);
        CHECK(!writer.open("memory", options(), &metrics));
        CHECK(!writer.finish());
        CHECK(!writer.finish());
        CHECK(writer.error_code() == EAGAIN);
    }
}

void runtime_failures_preserve_the_first_code_and_finish_is_idempotent() {
    for (FailurePoint point : {FailurePoint::Compression, FailurePoint::FirstWrite,
                               FailurePoint::FinalWrite}) {
        MemoryBackend backend;
        FakeFaultInjector faults(point, ENOSPC);
        TraceMetrics metrics{};
        AsyncTraceWriter writer(&backend, &faults);
        CHECK(writer.open("memory", options(), &metrics));
        CHECK(writer.append("payload"));
        CHECK(!writer.finish());
        CHECK(!writer.finish());
        CHECK(writer.error_code() == ENOSPC);
    }
}

void metrics_sidecar_failure_is_stable_and_close_is_idempotent() {
    char path[] = "/tmp/qtrace-failure-state-XXXXXX";
    char *directory = mkdtemp(path);
    CHECK(directory != nullptr);

    MemoryBackend backend;
    FakeFaultInjector faults(FailurePoint::MetricsSidecar, EDQUOT);
    TraceMetrics metrics{};
    TextTraceWriter writer(options(), &metrics, &backend, &faults);
    const TraceContext trace = context(directory);
    CHECK(writer.open(trace));
    CHECK(writer.begin(trace));
    CHECK(writer.end(7, true, 1));
    CHECK(!writer.close());
    CHECK(!writer.close());
    CHECK(writer.error_code() == EDQUOT);
    CHECK(::rmdir(directory) == 0);
}

void setup_failure_is_distinct_from_a_legitimate_zero_return() {
    const TraceRunResult setup_failure{false, 0};
    const TraceRunResult legitimate_zero{true, 0};
    CHECK(!setup_failure.target_executed);
    CHECK(legitimate_zero.target_executed);
    CHECK(setup_failure.value == legitimate_zero.value);
}

void successful_run_removes_its_empty_crash_marker_and_restores_handlers() {
    char path[] = "/tmp/qtrace-crash-state-XXXXXX";
    char *directory = mkdtemp(path);
    CHECK(directory != nullptr);
    const std::string trace_path = std::string(directory) + "/trace";
    struct sigaction before{};
    CHECK(sigaction(SIGABRT, nullptr, &before) == 0);

    CrashMarkerSession session;
    CHECK(session.open(trace_path));
    CHECK(::access((trace_path + ".crash").c_str(), F_OK) == 0);
    CHECK(session.finish());
    CHECK(session.finish());
    CHECK(::access((trace_path + ".crash").c_str(), F_OK) != 0);

    struct sigaction after{};
    CHECK(sigaction(SIGABRT, nullptr, &after) == 0);
    CHECK(after.sa_handler == before.sa_handler);
    CHECK(::rmdir(directory) == 0);
}

void signal_writes_one_valid_fixed_size_marker_and_reraises() {
    char path[] = "/tmp/qtrace-crash-signal-XXXXXX";
    char *directory = mkdtemp(path);
    CHECK(directory != nullptr);
    const std::string trace_path = std::string(directory) + "/trace";
    const std::string marker_path = trace_path + ".crash";

    const pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        const rlimit no_core{0, 0};
        (void)setrlimit(RLIMIT_CORE, &no_core);
        CrashMarkerSession session;
        if (!session.open(trace_path)) _exit(101);
        raise(SIGABRT);
        _exit(102);
    }

    int status = 0;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFSIGNALED(status));
    CHECK(WTERMSIG(status) == SIGABRT);
    const int fd = ::open(marker_path.c_str(), O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0);
    CrashMarker marker{};
    CHECK(::read(fd, &marker, sizeof(marker)) == static_cast<ssize_t>(sizeof(marker)));
    char extra = 0;
    CHECK(::read(fd, &extra, 1) == 0);
    CHECK(::close(fd) == 0);
    CHECK(valid_crash_marker(marker));
    CHECK(marker.signal == SIGABRT);
    CHECK(marker.tid > 0);
    CHECK(::unlink(marker_path.c_str()) == 0);
    CHECK(::rmdir(directory) == 0);
}

void concurrent_session_is_rejected_and_multiple_signals_write_once() {
    char path[] = "/tmp/qtrace-crash-multiple-XXXXXX";
    char *directory = mkdtemp(path);
    CHECK(directory != nullptr);
    const std::string first_path = std::string(directory) + "/first";
    const std::string second_path = std::string(directory) + "/second";

    struct sigaction forwarding{};
    forwarding.sa_handler = forwarding_handler;
    sigemptyset(&forwarding.sa_mask);
    struct sigaction old_abort{};
    struct sigaction old_ill{};
    CHECK(sigaction(SIGABRT, &forwarding, &old_abort) == 0);
    CHECK(sigaction(SIGILL, &forwarding, &old_ill) == 0);

    CrashMarkerSession first;
    CrashMarkerSession second;
    CHECK(first.open(first_path));
    CHECK(!second.open(second_path));
    CHECK(second.error_code() == EBUSY);
    CHECK(::access((second_path + ".crash").c_str(), F_OK) != 0);
    g_forwarded_signals = 0;
    CHECK(raise(SIGABRT) == 0);
    CHECK(raise(SIGILL) == 0);
    CHECK(g_forwarded_signals == 2);
    CHECK(first.finish());

    const int fd = ::open((first_path + ".crash").c_str(), O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0);
    CrashMarker marker{};
    CHECK(::read(fd, &marker, sizeof(marker)) == static_cast<ssize_t>(sizeof(marker)));
    char extra = 0;
    CHECK(::read(fd, &extra, 1) == 0);
    CHECK(::close(fd) == 0);
    CHECK(marker.signal == SIGABRT);
    CHECK(sigaction(SIGABRT, &old_abort, nullptr) == 0);
    CHECK(sigaction(SIGILL, &old_ill, nullptr) == 0);
    CHECK(::unlink((first_path + ".crash").c_str()) == 0);
    CHECK(::rmdir(directory) == 0);
}

void delayed_handler_from_a_finished_run_cannot_touch_the_next_run() {
    char path[] = "/tmp/qtrace-crash-generation-XXXXXX";
    char *directory = mkdtemp(path);
    CHECK(directory != nullptr);
    const std::string first_path = std::string(directory) + "/first";
    const std::string second_path = std::string(directory) + "/second";

    struct sigaction forwarding{};
    forwarding.sa_handler = forwarding_handler;
    sigemptyset(&forwarding.sa_mask);
    struct sigaction old_abort{};
    CHECK(sigaction(SIGABRT, &forwarding, &old_abort) == 0);

    CrashMarkerSession first;
    CHECK(first.open(first_path));
    struct sigaction first_action{};
    CHECK(sigaction(SIGABRT, nullptr, &first_action) == 0);
    CHECK((first_action.sa_flags & SA_SIGINFO) != 0);
    CHECK(first.finish());

    CrashMarkerSession second;
    CHECK(second.open(second_path));
    struct sigaction second_action{};
    CHECK(sigaction(SIGABRT, nullptr, &second_action) == 0);
    CHECK((second_action.sa_flags & SA_SIGINFO) != 0);
    CHECK(first_action.sa_sigaction != second_action.sa_sigaction);

    g_forwarded_signals = 0;
    first_action.sa_sigaction(SIGABRT, nullptr, nullptr);
    CHECK(g_forwarded_signals == 1);
    struct stat marker_status{};
    CHECK(::stat((second_path + ".crash").c_str(), &marker_status) == 0);
    CHECK(marker_status.st_size == 0);
    struct sigaction still_second{};
    CHECK(sigaction(SIGABRT, nullptr, &still_second) == 0);
    CHECK(still_second.sa_sigaction == second_action.sa_sigaction);

    CHECK(second.finish());
    CHECK(sigaction(SIGABRT, &old_abort, nullptr) == 0);
    CHECK(::rmdir(directory) == 0);
}

} // namespace

int main() {
    setup_failures_latch_their_code_and_finish_is_idempotent();
    runtime_failures_preserve_the_first_code_and_finish_is_idempotent();
    metrics_sidecar_failure_is_stable_and_close_is_idempotent();
    setup_failure_is_distinct_from_a_legitimate_zero_return();
    successful_run_removes_its_empty_crash_marker_and_restores_handlers();
    signal_writes_one_valid_fixed_size_marker_and_reraises();
    concurrent_session_is_rejected_and_multiple_signals_write_once();
    delayed_handler_from_a_finished_run_cannot_touch_the_next_run();
    return 0;
}
