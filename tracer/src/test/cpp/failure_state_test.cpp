#include "core/crash_marker.h"
#include "core/qbdi_runner.h"
#include "events/async_trace_writer.h"
#include "events/text_trace_writer.h"

#include <cerrno>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <future>
#include <string>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

using CrashHandlerTestGate = void (*)();
void crash_marker_test_set_handler_gate(CrashHandlerTestGate gate);
void crash_marker_test_force_forward_failure(bool enabled);

namespace {

volatile sig_atomic_t g_forwarded_signals = 0;
volatile sig_atomic_t g_mask_result = 0;
volatile sig_atomic_t g_siginfo_result = 0;
std::atomic<bool> g_handler_gate_entered{false};
std::atomic<bool> g_release_handler_gate{false};
std::atomic<bool> g_blocking_handler_entered{false};
std::atomic<bool> g_release_blocking_handler{false};

void forwarding_handler(int) {
    g_forwarded_signals = static_cast<sig_atomic_t>(g_forwarded_signals + 1);
}

void mask_handler(int signal_number) {
    sigset_t current{};
    if (sigprocmask(SIG_SETMASK, nullptr, &current) != 0) {
        g_mask_result = -1;
        return;
    }
    const bool self_blocked = sigismember(&current, signal_number) == 1;
    const bool extra_blocked = sigismember(&current, SIGUSR1) == 1;
    g_mask_result = self_blocked && extra_blocked ? 1 : -1;
}

void nodefer_mask_handler(int signal_number) {
    sigset_t current{};
    if (sigprocmask(SIG_SETMASK, nullptr, &current) != 0) {
        g_mask_result = -1;
        return;
    }
    const bool self_blocked = sigismember(&current, signal_number) == 1;
    const bool extra_blocked = sigismember(&current, SIGUSR1) == 1;
    g_mask_result = !self_blocked && extra_blocked ? 1 : -1;
}

void siginfo_handler(int signal_number, siginfo_t *info, void *) {
    g_siginfo_result = signal_number == SIGABRT && info != nullptr ? 1 : -1;
}

void handler_entry_gate() {
    g_handler_gate_entered = true;
    while (!g_release_handler_gate.load()) std::this_thread::yield();
}

void blocking_handler(int) {
    g_blocking_handler_entered = true;
    while (!g_release_blocking_handler.load()) std::this_thread::yield();
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

void failed_tagged_forward_uses_old_semantics_without_consuming_the_new_marker() {
    char path[] = "/tmp/qtrace-crash-forward-fail-XXXXXX";
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
    struct sigaction old_tracer{};
    CHECK(sigaction(SIGABRT, nullptr, &old_tracer) == 0);
    CHECK(first.finish());
    CrashMarkerSession second;
    CHECK(second.open(second_path));

    g_forwarded_signals = 0;
    crash_marker_test_force_forward_failure(true);
    old_tracer.sa_sigaction(SIGABRT, nullptr, nullptr);
    crash_marker_test_force_forward_failure(false);
    CHECK(g_forwarded_signals == 1);
    struct stat marker_status{};
    CHECK(::stat((second_path + ".crash").c_str(), &marker_status) == 0);
    CHECK(marker_status.st_size == 0);

    CHECK(second.finish());
    CHECK(sigaction(SIGABRT, &old_abort, nullptr) == 0);
    CHECK(::rmdir(directory) == 0);
}

void failed_tagged_forward_preserves_stale_nodefer_mask() {
    char path[] = "/tmp/qtrace-crash-forward-nodefer-XXXXXX";
    char *directory = mkdtemp(path);
    CHECK(directory != nullptr);
    const std::string first_path = std::string(directory) + "/first";
    const std::string second_path = std::string(directory) + "/second";

    struct sigaction nodefer{};
    nodefer.sa_handler = nodefer_mask_handler;
    sigemptyset(&nodefer.sa_mask);
    sigaddset(&nodefer.sa_mask, SIGUSR1);
    nodefer.sa_flags = SA_NODEFER;
    struct sigaction old_abort{};
    CHECK(sigaction(SIGABRT, &nodefer, &old_abort) == 0);
    CrashMarkerSession first;
    CHECK(first.open(first_path));
    struct sigaction old_tracer{};
    CHECK(sigaction(SIGABRT, nullptr, &old_tracer) == 0);
    CHECK(first.finish());
    CrashMarkerSession second;
    CHECK(second.open(second_path));

    g_mask_result = 0;
    crash_marker_test_force_forward_failure(true);
    old_tracer.sa_sigaction(SIGABRT, nullptr, nullptr);
    crash_marker_test_force_forward_failure(false);
    CHECK(g_mask_result == 1);
    struct stat marker_status{};
    CHECK(::stat((second_path + ".crash").c_str(), &marker_status) == 0);
    CHECK(marker_status.st_size == 0);

    CHECK(second.finish());
    CHECK(sigaction(SIGABRT, &old_abort, nullptr) == 0);
    CHECK(::rmdir(directory) == 0);
}

void stale_default_action_still_terminates_by_the_original_signal() {
    char path[] = "/tmp/qtrace-crash-default-XXXXXX";
    char *directory = mkdtemp(path);
    CHECK(directory != nullptr);
    const std::string first_path = std::string(directory) + "/first";
    const std::string second_path = std::string(directory) + "/second";

    const pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        const rlimit no_core{0, 0};
        (void)setrlimit(RLIMIT_CORE, &no_core);
        struct sigaction defaults{};
        defaults.sa_handler = SIG_DFL;
        sigemptyset(&defaults.sa_mask);
        if (sigaction(SIGABRT, &defaults, nullptr) != 0) _exit(101);
        CrashMarkerSession first;
        if (!first.open(first_path)) _exit(102);
        struct sigaction old_handler{};
        if (sigaction(SIGABRT, nullptr, &old_handler) != 0) _exit(103);
        if (!first.finish()) _exit(104);
        CrashMarkerSession second;
        if (!second.open(second_path)) _exit(105);
        crash_marker_test_force_forward_failure(true);
        old_handler.sa_sigaction(SIGABRT, nullptr, nullptr);
        _exit(106);
    }

    int status = 0;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFSIGNALED(status));
    CHECK(WTERMSIG(status) == SIGABRT);
    struct stat second_marker{};
    CHECK(::stat((second_path + ".crash").c_str(), &second_marker) == 0);
    CHECK(second_marker.st_size == 0);
    CHECK(::unlink((second_path + ".crash").c_str()) == 0);
    CHECK(::rmdir(directory) == 0);
}

void stale_forwarding_preserves_mask_and_one_shot_reset_behavior() {
    char path[] = "/tmp/qtrace-crash-stale-reset-XXXXXX";
    char *directory = mkdtemp(path);
    CHECK(directory != nullptr);
    const std::string first_path = std::string(directory) + "/first";
    const std::string second_path = std::string(directory) + "/second";

    const pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        const rlimit no_core{0, 0};
        (void)setrlimit(RLIMIT_CORE, &no_core);
        CrashMarkerSession first;
        if (!first.open(first_path)) _exit(111);
        struct sigaction old_handler{};
        if (sigaction(SIGABRT, nullptr, &old_handler) != 0) _exit(112);
        if (!first.finish()) _exit(113);

        struct sigaction masked{};
        masked.sa_handler = mask_handler;
        sigemptyset(&masked.sa_mask);
        sigaddset(&masked.sa_mask, SIGUSR1);
        masked.sa_flags = SA_RESETHAND;
        if (sigaction(SIGABRT, &masked, nullptr) != 0) _exit(114);
        CrashMarkerSession second;
        if (!second.open(second_path)) _exit(115);
        struct sigaction second_handler{};
        if (sigaction(SIGABRT, nullptr, &second_handler) != 0) _exit(116);

        g_mask_result = 0;
        old_handler.sa_sigaction(SIGABRT, nullptr, nullptr);
        if (g_mask_result != 1) _exit(117);
        struct sigaction still_second{};
        if (sigaction(SIGABRT, nullptr, &still_second) != 0 ||
            still_second.sa_sigaction != second_handler.sa_sigaction) {
            _exit(118);
        }
        old_handler.sa_sigaction(SIGABRT, nullptr, nullptr);
        _exit(119);
    }

    int status = 0;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFSIGNALED(status));
    CHECK(WTERMSIG(status) == SIGABRT);
    struct stat second_marker{};
    CHECK(::stat((second_path + ".crash").c_str(), &second_marker) == 0);
    CHECK(second_marker.st_size == 0);
    CHECK(::unlink((second_path + ".crash").c_str()) == 0);
    CHECK(::rmdir(directory) == 0);
}

void forwarded_handlers_keep_masks_nodefer_ignore_and_reset_semantics() {
    char path[] = "/tmp/qtrace-crash-flags-XXXXXX";
    char *directory = mkdtemp(path);
    CHECK(directory != nullptr);

    struct sigaction old_abort{};
    struct sigaction masked{};
    masked.sa_handler = mask_handler;
    sigemptyset(&masked.sa_mask);
    sigaddset(&masked.sa_mask, SIGUSR1);
    masked.sa_flags = SA_RESETHAND;
    CHECK(sigaction(SIGABRT, &masked, &old_abort) == 0);
    g_mask_result = 0;
    errno = E2BIG;
    {
        CrashMarkerSession session;
        const std::string trace_path = std::string(directory) + "/masked";
        CHECK(session.open(trace_path));
        CHECK(raise(SIGABRT) == 0);
        CHECK(g_mask_result == 1);
        CHECK(errno == E2BIG);
        struct sigaction reset{};
        CHECK(sigaction(SIGABRT, nullptr, &reset) == 0);
        CHECK(reset.sa_handler == SIG_DFL);
        CHECK(session.finish());
        CHECK(::unlink((trace_path + ".crash").c_str()) == 0);
    }

    struct sigaction nodefer{};
    nodefer.sa_handler = nodefer_mask_handler;
    sigemptyset(&nodefer.sa_mask);
    sigaddset(&nodefer.sa_mask, SIGUSR1);
    nodefer.sa_flags = SA_NODEFER;
    CHECK(sigaction(SIGABRT, &nodefer, nullptr) == 0);
    g_mask_result = 0;
    {
        CrashMarkerSession session;
        const std::string trace_path = std::string(directory) + "/nodefer";
        CHECK(session.open(trace_path));
        CHECK(raise(SIGABRT) == 0);
        CHECK(g_mask_result == 1);
        CHECK(session.finish());
        CHECK(::unlink((trace_path + ".crash").c_str()) == 0);
    }


    struct sigaction with_info{};
    with_info.sa_sigaction = siginfo_handler;
    sigemptyset(&with_info.sa_mask);
    with_info.sa_flags = SA_SIGINFO;
    CHECK(sigaction(SIGABRT, &with_info, nullptr) == 0);
    g_siginfo_result = 0;
    {
        CrashMarkerSession session;
        const std::string trace_path = std::string(directory) + "/siginfo";
        CHECK(session.open(trace_path));
        CHECK(raise(SIGABRT) == 0);
        CHECK(g_siginfo_result == 1);
        CHECK(session.finish());
        CHECK(::unlink((trace_path + ".crash").c_str()) == 0);
    }

    struct sigaction ignored{};
    ignored.sa_handler = SIG_IGN;
    sigemptyset(&ignored.sa_mask);
    CHECK(sigaction(SIGABRT, &ignored, nullptr) == 0);
    {
        CrashMarkerSession session;
        const std::string trace_path = std::string(directory) + "/ignored";
        CHECK(session.open(trace_path));
        CHECK(raise(SIGABRT) == 0);
        struct sigaction current{};
        CHECK(sigaction(SIGABRT, nullptr, &current) == 0);
        CHECK(current.sa_handler == SIG_IGN);
        CHECK(session.finish());
        CHECK(::unlink((trace_path + ".crash").c_str()) == 0);
    }
    CHECK(sigaction(SIGABRT, &old_abort, nullptr) == 0);
    CHECK(::rmdir(directory) == 0);
}

void finish_does_not_wait_for_a_stale_blocking_prior_handler() {
    char path[] = "/tmp/qtrace-crash-bounded-XXXXXX";
    char *directory = mkdtemp(path);
    CHECK(directory != nullptr);
    const std::string trace_path = std::string(directory) + "/trace";

    struct sigaction blocking{};
    blocking.sa_handler = blocking_handler;
    sigemptyset(&blocking.sa_mask);
    struct sigaction old_abort{};
    CHECK(sigaction(SIGABRT, &blocking, &old_abort) == 0);
    CrashMarkerSession session;
    CHECK(session.open(trace_path));
    struct sigaction installed{};
    CHECK(sigaction(SIGABRT, nullptr, &installed) == 0);

    g_handler_gate_entered = false;
    g_release_handler_gate = false;
    g_blocking_handler_entered = false;
    g_release_blocking_handler = false;
    crash_marker_test_set_handler_gate(handler_entry_gate);
    std::thread delayed([&] { installed.sa_sigaction(SIGABRT, nullptr, nullptr); });
    while (!g_handler_gate_entered.load()) std::this_thread::yield();

    auto finishing = std::async(std::launch::async, [&] { return session.finish(); });
    const bool bounded = finishing.wait_for(std::chrono::milliseconds(100)) ==
                         std::future_status::ready;
    if (!bounded) g_release_handler_gate = true;
    CHECK(bounded);
    CHECK(finishing.get());

    g_release_handler_gate = true;
    while (!g_blocking_handler_entered.load()) std::this_thread::yield();
    g_release_blocking_handler = true;
    delayed.join();
    crash_marker_test_set_handler_gate(nullptr);
    CHECK(sigaction(SIGABRT, &old_abort, nullptr) == 0);
    CHECK(::unlink((trace_path + ".crash").c_str()) == 0);
    CHECK(::rmdir(directory) == 0);
}

void retired_forwarder_cannot_reinstall_after_a_blocking_custom_handler() {
    char path[] = "/tmp/qtrace-crash-no-reinstall-XXXXXX";
    char *directory = mkdtemp(path);
    CHECK(directory != nullptr);
    const std::string first_path = std::string(directory) + "/first";
    const std::string second_path = std::string(directory) + "/second";

    struct sigaction blocking{};
    blocking.sa_handler = blocking_handler;
    sigemptyset(&blocking.sa_mask);
    struct sigaction old_abort{};
    CHECK(sigaction(SIGABRT, &blocking, &old_abort) == 0);

    CrashMarkerSession first;
    CHECK(first.open(first_path));
    struct sigaction old_tracer{};
    CHECK(sigaction(SIGABRT, nullptr, &old_tracer) == 0);
    CHECK(first.finish());

    CrashMarkerSession second;
    CHECK(second.open(second_path));
    g_blocking_handler_entered = false;
    g_release_blocking_handler = false;
    std::thread forwarded([&] { old_tracer.sa_sigaction(SIGABRT, nullptr, nullptr); });
    while (!g_blocking_handler_entered.load()) std::this_thread::yield();

    auto finishing = std::async(std::launch::async, [&] { return second.finish(); });
    CHECK(finishing.wait_for(std::chrono::milliseconds(100)) == std::future_status::ready);
    CHECK(finishing.get());
    struct sigaction after_finish{};
    CHECK(sigaction(SIGABRT, nullptr, &after_finish) == 0);
    CHECK(after_finish.sa_handler == blocking_handler);

    g_release_blocking_handler = true;
    forwarded.join();
    struct sigaction after_return{};
    CHECK(sigaction(SIGABRT, nullptr, &after_return) == 0);
    CHECK(after_return.sa_handler == blocking_handler);
    CHECK(sigaction(SIGABRT, &old_abort, nullptr) == 0);
    CHECK(::access((second_path + ".crash").c_str(), F_OK) != 0);
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
    failed_tagged_forward_uses_old_semantics_without_consuming_the_new_marker();
    failed_tagged_forward_preserves_stale_nodefer_mask();
    stale_default_action_still_terminates_by_the_original_signal();
    stale_forwarding_preserves_mask_and_one_shot_reset_behavior();
    forwarded_handlers_keep_masks_nodefer_ignore_and_reset_semantics();
    finish_does_not_wait_for_a_stale_blocking_prior_handler();
    retired_forwarder_cannot_reinstall_after_a_blocking_custom_handler();
    return 0;
}
