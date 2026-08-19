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
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <thread>
#include <ucontext.h>
#include <unistd.h>

using CrashHandlerTestGate = void (*)();
void crash_marker_test_set_handler_gate(CrashHandlerTestGate gate);
void crash_marker_test_set_session_gate(CrashHandlerTestGate gate);

namespace {

volatile sig_atomic_t g_forwarded_signals = 0;
volatile sig_atomic_t g_mask_result = 0;
volatile sig_atomic_t g_siginfo_result = 0;
volatile sig_atomic_t g_exact_siginfo_result = 0;
siginfo_t *g_expected_siginfo = nullptr;
void *g_expected_context = nullptr;
int g_fault_pipe_fd = -1;
std::atomic<bool> g_handler_gate_entered{false};
std::atomic<bool> g_release_handler_gate{false};
std::atomic<bool> g_blocking_handler_entered{false};
std::atomic<bool> g_release_blocking_handler{false};
std::atomic<bool> g_session_gate_entered{false};
std::atomic<bool> g_release_session_gate{false};

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

void exact_siginfo_handler(int signal_number, siginfo_t *info, void *context) {
    g_exact_siginfo_result =
            signal_number == SIGSEGV && info == g_expected_siginfo &&
                            context == g_expected_context && info != nullptr &&
                            info->si_code == SEGV_MAPERR &&
                            info->si_addr == reinterpret_cast<void *>(0x12345000)
                    ? 1
                    : -1;
}

struct FaultPayload {
    int signal_number;
    int code;
    uintptr_t address;
    int context_present;
};

void fault_payload_handler(int signal_number, siginfo_t *info, void *context) {
    const FaultPayload payload{signal_number, info == nullptr ? 0 : info->si_code,
                               info == nullptr
                                       ? 0
                                       : reinterpret_cast<uintptr_t>(info->si_addr),
                               context == nullptr ? 0 : 1};
    if (g_fault_pipe_fd >= 0) {
        const ssize_t write_result = ::write(g_fault_pipe_fd, &payload, sizeof(payload));
        (void)write_result;
    }
    _exit(0);
}

void handler_entry_gate() {
    g_handler_gate_entered = true;
    while (!g_release_handler_gate.load()) std::this_thread::yield();
}

void blocking_handler(int) {
    g_blocking_handler_entered = true;
    while (!g_release_blocking_handler.load()) std::this_thread::yield();
}

void session_lock_gate() {
    g_session_gate_entered = true;
    while (!g_release_session_gate.load()) std::this_thread::yield();
}

void selected_old_default_reaches_new_handler_without_overwriting_it() {
    const pid_t child = ::fork();
    if (child < 0) std::abort();
    if (child == 0) {
        char path[] = "/tmp/qtrace-crash-default-race-XXXXXX";
        char *directory = mkdtemp(path);
        if (directory == nullptr) _exit(141);
        const std::string first_path = std::string(directory) + "/first";
        const std::string cleanup_path = std::string(directory) + "/cleanup";
        struct sigaction defaults{};
        defaults.sa_handler = SIG_DFL;
        sigemptyset(&defaults.sa_mask);
        struct sigaction old_abort{};
        if (::sigaction(SIGABRT, &defaults, &old_abort) != 0) _exit(142);
        CrashMarkerSession first;
        if (!first.open(first_path)) _exit(143);
        g_handler_gate_entered = false;
        g_release_handler_gate = false;
        crash_marker_test_set_handler_gate(handler_entry_gate);
        std::thread selected([] { (void)::raise(SIGABRT); });
        while (!g_handler_gate_entered.load()) std::this_thread::yield();
        if (!first.finish()) _exit(144);

        struct sigaction replacement{};
        replacement.sa_handler = forwarding_handler;
        sigemptyset(&replacement.sa_mask);
        if (::sigaction(SIGABRT, &replacement, nullptr) != 0) _exit(145);
        g_forwarded_signals = 0;
        g_release_handler_gate = true;
        selected.join();
        crash_marker_test_set_handler_gate(nullptr);
        if (g_forwarded_signals != 1) _exit(146);
        struct sigaction after{};
        if (::sigaction(SIGABRT, nullptr, &after) != 0 ||
            after.sa_handler != forwarding_handler) {
            _exit(147);
        }
        CrashMarkerSession cleanup;
        if (!cleanup.open(cleanup_path) || !cleanup.finish()) _exit(148);
        (void)::sigaction(SIGABRT, &old_abort, nullptr);
        (void)::unlink((first_path + ".crash").c_str());
        (void)::rmdir(directory);
        _exit(0);
    }
    int status = 0;
    if (::waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0) {
        std::abort();
    }
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

int find_open_fd_for_path(const std::string &path) {
    struct stat expected{};
    if (::stat(path.c_str(), &expected) != 0) return -1;
    const long open_max = ::sysconf(_SC_OPEN_MAX);
    const int limit = open_max > 0 && open_max < 65536 ? static_cast<int>(open_max) : 4096;
    for (int fd = 0; fd < limit; ++fd) {
        struct stat candidate{};
        if (::fstat(fd, &candidate) == 0 && candidate.st_dev == expected.st_dev &&
            candidate.st_ino == expected.st_ino) {
            return fd;
        }
    }
    return -1;
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

void delayed_custom_handler_uses_old_semantics_without_consuming_the_new_marker() {
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
    old_tracer.sa_sigaction(SIGABRT, nullptr, nullptr);
    CHECK(g_forwarded_signals == 1);
    struct stat marker_status{};
    CHECK(::stat((second_path + ".crash").c_str(), &marker_status) == 0);
    CHECK(marker_status.st_size == 0);

    CHECK(second.finish());
    CHECK(sigaction(SIGABRT, &old_abort, nullptr) == 0);
    CHECK(::rmdir(directory) == 0);
}

void delayed_custom_handler_preserves_stale_nodefer_mask() {
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
    old_tracer.sa_sigaction(SIGABRT, nullptr, nullptr);
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
        old_handler.sa_sigaction(SIGABRT, nullptr, nullptr);
        _exit(106);
    }

    int status = 0;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFSIGNALED(status));
    CHECK(WTERMSIG(status) == SIGABRT);
    struct stat second_marker{};
    CHECK(::stat((second_path + ".crash").c_str(), &second_marker) == 0);
    // The stale thunk only re-raises. The currently installed second generation
    // owns that delivery and records it before its own saved default terminates.
    CHECK(second_marker.st_size == static_cast<off_t>(sizeof(CrashMarker)));
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
        g_mask_result = 0;
        old_handler.sa_sigaction(SIGABRT, nullptr, nullptr);
        if (g_mask_result != 1) _exit(117);
        struct sigaction still_second{};
        if (sigaction(SIGABRT, nullptr, &still_second) != 0 ||
            still_second.sa_handler != SIG_DFL) {
            _exit(118);
        }
        (void)raise(SIGABRT);
        _exit(119);
    }

    int status = 0;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFSIGNALED(status));
    CHECK(WTERMSIG(status) == SIGABRT);
    struct stat second_marker{};
    CHECK(::stat((second_path + ".crash").c_str(), &second_marker) == 0);
    CHECK(second_marker.st_size == static_cast<off_t>(sizeof(CrashMarker)));
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

void custom_siginfo_receives_the_original_payload_and_context() {
    char path[] = "/tmp/qtrace-crash-context-XXXXXX";
    char *directory = mkdtemp(path);
    CHECK(directory != nullptr);
    const std::string trace_path = std::string(directory) + "/trace";

    struct sigaction exact{};
    exact.sa_sigaction = exact_siginfo_handler;
    sigemptyset(&exact.sa_mask);
    exact.sa_flags = SA_SIGINFO;
    struct sigaction old_segv{};
    CHECK(sigaction(SIGSEGV, &exact, &old_segv) == 0);

    CrashMarkerSession session;
    CHECK(session.open(trace_path));
    struct sigaction installed{};
    CHECK(sigaction(SIGSEGV, nullptr, &installed) == 0);
    siginfo_t info{};
    info.si_signo = SIGSEGV;
    info.si_code = SEGV_MAPERR;
    info.si_addr = reinterpret_cast<void *>(0x12345000);
    ucontext_t context{};
    g_expected_siginfo = &info;
    g_expected_context = &context;
    g_exact_siginfo_result = 0;
    installed.sa_sigaction(SIGSEGV, &info, &context);
    CHECK(g_exact_siginfo_result == 1);
    CHECK(session.finish());

    CHECK(sigaction(SIGSEGV, &old_segv, nullptr) == 0);
    CHECK(::unlink((trace_path + ".crash").c_str()) == 0);
    CHECK(::rmdir(directory) == 0);
}

void retired_handler_blocks_new_sessions_and_same_path_reuse() {
    char path[] = "/tmp/qtrace-crash-retired-path-XXXXXX";
    char *directory = mkdtemp(path);
    CHECK(directory != nullptr);
    const std::string trace_path = std::string(directory) + "/trace";
    const std::string later_path = std::string(directory) + "/later";

    struct sigaction blocking{};
    blocking.sa_handler = blocking_handler;
    sigemptyset(&blocking.sa_mask);
    struct sigaction old_abort{};
    CHECK(sigaction(SIGABRT, &blocking, &old_abort) == 0);
    CrashMarkerSession first;
    CHECK(first.open(trace_path));
    struct sigaction installed{};
    CHECK(sigaction(SIGABRT, nullptr, &installed) == 0);

    g_handler_gate_entered = false;
    g_release_handler_gate = false;
    g_blocking_handler_entered = false;
    g_release_blocking_handler = false;
    crash_marker_test_set_handler_gate(handler_entry_gate);
    std::thread delayed([&] { installed.sa_sigaction(SIGABRT, nullptr, nullptr); });
    while (!g_handler_gate_entered.load()) std::this_thread::yield();
    struct stat before{};
    CHECK(::stat((trace_path + ".crash").c_str(), &before) == 0);
    CHECK(first.finish());

    CrashMarkerSession blocked;
    CHECK(!blocked.open(trace_path));
    CHECK(blocked.error_code() == EBUSY);
    struct stat during{};
    CHECK(::stat((trace_path + ".crash").c_str(), &during) == 0);
    CHECK(during.st_dev == before.st_dev);
    CHECK(during.st_ino == before.st_ino);

    g_release_handler_gate = true;
    while (!g_blocking_handler_entered.load()) std::this_thread::yield();
    g_release_blocking_handler = true;
    delayed.join();
    crash_marker_test_set_handler_gate(nullptr);

    CrashMarkerSession same_path;
    CHECK(!same_path.open(trace_path));
    CHECK(same_path.error_code() == EEXIST);
    CrashMarkerSession later;
    CHECK(later.open(later_path));
    CHECK(later.finish());
    CHECK(sigaction(SIGABRT, &old_abort, nullptr) == 0);
    CHECK(::unlink((trace_path + ".crash").c_str()) == 0);
    CHECK(::rmdir(directory) == 0);
}

void real_fault_preserves_siginfo_code_address_and_context() {
    char path[] = "/tmp/qtrace-crash-real-context-XXXXXX";
    char *directory = mkdtemp(path);
    CHECK(directory != nullptr);
    const std::string trace_path = std::string(directory) + "/trace";
    int payload_pipe[2]{};
    CHECK(::pipe(payload_pipe) == 0);

    const pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        (void)::close(payload_pipe[0]);
        g_fault_pipe_fd = payload_pipe[1];
        struct sigaction prior{};
        prior.sa_sigaction = fault_payload_handler;
        sigemptyset(&prior.sa_mask);
        prior.sa_flags = SA_SIGINFO;
        if (::sigaction(SIGSEGV, &prior, nullptr) != 0) _exit(121);
        CrashMarkerSession session;
        if (!session.open(trace_path)) _exit(122);
        const long page_size = ::sysconf(_SC_PAGESIZE);
        if (page_size <= 0) _exit(123);
        void *page = ::mmap(nullptr, static_cast<size_t>(page_size), PROT_NONE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (page == MAP_FAILED) _exit(124);
        const uintptr_t expected_address = reinterpret_cast<uintptr_t>(page);
        if (::write(payload_pipe[1], &expected_address, sizeof(expected_address)) !=
            static_cast<ssize_t>(sizeof(expected_address))) {
            _exit(126);
        }
        *static_cast<volatile uint8_t *>(page) = 1;
        _exit(125);
    }

    (void)::close(payload_pipe[1]);
    uintptr_t expected_address = 0;
    CHECK(::read(payload_pipe[0], &expected_address, sizeof(expected_address)) ==
          static_cast<ssize_t>(sizeof(expected_address)));
    FaultPayload payload{};
    CHECK(::read(payload_pipe[0], &payload, sizeof(payload)) ==
          static_cast<ssize_t>(sizeof(payload)));
    (void)::close(payload_pipe[0]);
    int status = 0;
    CHECK(::waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status));
    CHECK(WEXITSTATUS(status) == 0);
    CHECK(payload.signal_number == SIGSEGV);
    CHECK(payload.code == SEGV_ACCERR);
    CHECK(payload.address == expected_address);
    CHECK(payload.context_present == 1);
    CHECK(::unlink((trace_path + ".crash").c_str()) == 0);
    CHECK(::rmdir(directory) == 0);
}

void delayed_old_reset_handler_cannot_clobber_a_new_generation() {
    char path[] = "/tmp/qtrace-crash-reset-generation-XXXXXX";
    char *directory = mkdtemp(path);
    CHECK(directory != nullptr);
    const std::string first_path = std::string(directory) + "/first";
    const std::string second_path = std::string(directory) + "/second";

    struct sigaction reset{};
    reset.sa_handler = forwarding_handler;
    sigemptyset(&reset.sa_mask);
    reset.sa_flags = SA_RESETHAND | SA_NODEFER;
    struct sigaction old_abort{};
    CHECK(sigaction(SIGABRT, &reset, &old_abort) == 0);
    CrashMarkerSession first;
    CHECK(first.open(first_path));
    struct sigaction old_thunk{};
    CHECK(sigaction(SIGABRT, nullptr, &old_thunk) == 0);
    CHECK((old_thunk.sa_flags & SA_RESETHAND) != 0);
    CHECK((old_thunk.sa_flags & SA_NODEFER) != 0);
    CHECK(first.finish());

    CrashMarkerSession second;
    CHECK(second.open(second_path));
    struct sigaction new_thunk{};
    CHECK(sigaction(SIGABRT, nullptr, &new_thunk) == 0);
    g_forwarded_signals = 0;
    old_thunk.sa_sigaction(SIGABRT, nullptr, nullptr);
    CHECK(g_forwarded_signals == 1);
    struct sigaction after_old{};
    CHECK(sigaction(SIGABRT, nullptr, &after_old) == 0);
    CHECK(after_old.sa_sigaction == new_thunk.sa_sigaction);
    CHECK(second.finish());
    CHECK(sigaction(SIGABRT, &old_abort, nullptr) == 0);
    CHECK(::rmdir(directory) == 0);
}

void fork_detaches_inherited_crash_session_without_touching_parent_artifact() {
    char path[] = "/tmp/qtrace-crash-atfork-XXXXXX";
    char *directory = mkdtemp(path);
    CHECK(directory != nullptr);
    const std::string parent_path = std::string(directory) + "/parent";
    const std::string child_path = std::string(directory) + "/child";
    CrashMarkerSession parent;
    bool parent_opened = false;
    g_session_gate_entered = false;
    g_release_session_gate = false;
    crash_marker_test_set_session_gate(session_lock_gate);
    std::thread opening([&] { parent_opened = parent.open(parent_path); });
    while (!g_session_gate_entered.load()) std::this_thread::yield();
    std::atomic<bool> fork_started{false};
    int status = -1;
    std::thread forking([&] {
        fork_started = true;
        const pid_t child = ::fork();
        if (child == 0) {
            if (!parent.finish()) _exit(90);
            CrashMarkerSession child_session;
            if (child_session.open(child_path)) _exit(91);
            if (child_session.error_code() != ECHILD) _exit(92);
            if (::access((child_path + ".crash").c_str(), F_OK) == 0) _exit(93);
            _exit(0);
        }
        if (child < 0 || ::waitpid(child, &status, 0) != child) status = -1;
    });
    while (!fork_started.load()) std::this_thread::yield();
    g_release_session_gate = true;
    opening.join();
    crash_marker_test_set_session_gate(nullptr);
    forking.join();
    CHECK(parent_opened);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    struct stat before{};
    CHECK(::stat((parent_path + ".crash").c_str(), &before) == 0);
    struct stat after{};
    CHECK(::stat((parent_path + ".crash").c_str(), &after) == 0);
    CHECK(after.st_dev == before.st_dev && after.st_ino == before.st_ino);
    CHECK(after.st_size == 0);
    CHECK(parent.finish());
    CHECK(::rmdir(directory) == 0);
}

void fork_child_closes_marker_fd_already_claimed_by_live_handler() {
    char path[] = "/tmp/qtrace-crash-claimed-fd-XXXXXX";
    char *directory = mkdtemp(path);
    CHECK(directory != nullptr);
    const std::string trace_path = std::string(directory) + "/trace";
    const std::string marker_path = trace_path + ".crash";

    struct sigaction forwarding{};
    forwarding.sa_handler = forwarding_handler;
    sigemptyset(&forwarding.sa_mask);
    struct sigaction old_abort{};
    CHECK(::sigaction(SIGABRT, &forwarding, &old_abort) == 0);
    CrashMarkerSession session;
    CHECK(session.open(trace_path));
    const int marker_fd = find_open_fd_for_path(marker_path);
    CHECK(marker_fd >= 0);

    g_handler_gate_entered = false;
    g_release_handler_gate = false;
    crash_marker_test_set_handler_gate(handler_entry_gate);
    std::thread handling([] { (void)::raise(SIGABRT); });
    while (!g_handler_gate_entered.load()) std::this_thread::yield();

    const pid_t child = ::fork();
    CHECK(child >= 0);
    if (child == 0) {
        errno = 0;
        const int result = ::fcntl(marker_fd, F_GETFD);
        _exit(result == -1 && errno == EBADF ? 0 : 77);
    }
    int status = 0;
    CHECK(::waitpid(child, &status, 0) == child);
    const bool child_closed_fd = WIFEXITED(status) && WEXITSTATUS(status) == 0;

    g_release_handler_gate = true;
    handling.join();
    crash_marker_test_set_handler_gate(nullptr);
    CHECK(session.finish());
    CHECK(::sigaction(SIGABRT, &old_abort, nullptr) == 0);
    CHECK(::unlink(marker_path.c_str()) == 0);
    CHECK(::rmdir(directory) == 0);
    CHECK(child_closed_fd);
}

void fork_child_does_not_close_fd_reused_after_marker_finish() {
    char path[] = "/tmp/qtrace-crash-reused-fd-XXXXXX";
    char *directory = mkdtemp(path);
    CHECK(directory != nullptr);
    const std::string trace_path = std::string(directory) + "/trace";
    const std::string marker_path = trace_path + ".crash";
    CrashMarkerSession session;
    CHECK(session.open(trace_path));
    const int marker_fd = find_open_fd_for_path(marker_path);
    CHECK(marker_fd >= 3);
    CHECK(session.finish());

    int reused_fd = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
    CHECK(reused_fd >= 0);
    if (reused_fd != marker_fd) {
        CHECK(::dup2(reused_fd, marker_fd) == marker_fd);
        CHECK(::close(reused_fd) == 0);
        reused_fd = marker_fd;
    }
    const pid_t child = ::fork();
    CHECK(child >= 0);
    if (child == 0) {
        _exit(::fcntl(reused_fd, F_GETFD) >= 0 ? 0 : 78);
    }
    int status = 0;
    CHECK(::waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(::close(reused_fd) == 0);
    CHECK(::rmdir(directory) == 0);
}

void artifact_names_are_unique_before_exclusive_trace_creation() {
    char path[] = "/tmp/qtrace-artifact-pair-XXXXXX";
    char *directory = mkdtemp(path);
    CHECK(directory != nullptr);
    TraceOptions trace_options = options();
    trace_options.compression_enabled = false;
    TraceMetrics first_metrics{};
    TextTraceWriter first(trace_options, &first_metrics);
    CHECK(first.prepare(context(directory)));
    CrashMarkerSession first_marker;
    CHECK(first_marker.open(first.path()));
    CHECK(first.open_prepared());
    CHECK(first.begin(context(directory)));
    CHECK(first.end(7, true, 1));
    CHECK(first.close());
    CHECK(first_marker.finish());
    struct stat before{};
    CHECK(::stat(first.path().c_str(), &before) == 0);

    TraceMetrics second_metrics{};
    TextTraceWriter second(trace_options, &second_metrics);
    CHECK(second.prepare(context(directory)));
    CHECK(second.path() != first.path());
    CrashMarkerSession second_marker;
    CHECK(second_marker.open(second.path()));
    CHECK(second.open_prepared());
    CHECK(second.begin(context(directory)));
    CHECK(second.end(8, true, 1));
    CHECK(second.close());
    CHECK(second_marker.finish());
    struct stat after{};
    CHECK(::stat(first.path().c_str(), &after) == 0);
    CHECK(after.st_dev == before.st_dev && after.st_ino == before.st_ino &&
          after.st_size == before.st_size);
    CHECK(::unlink(first.path().c_str()) == 0);
    CHECK(::unlink(second.path().c_str()) == 0);
    CHECK(::unlink((first.path() + ".metrics").c_str()) == 0);
    if (::unlink((second.path() + ".metrics").c_str()) != 0) CHECK(errno == ENOENT);
    CHECK(::rmdir(directory) == 0);
}

} // namespace

int main() {
    setup_failures_latch_their_code_and_finish_is_idempotent();
    runtime_failures_preserve_the_first_code_and_finish_is_idempotent();
    metrics_sidecar_failure_is_stable_and_close_is_idempotent();
    setup_failure_is_distinct_from_a_legitimate_zero_return();
    // These subprocesses must establish their own crash session before this
    // process installs its atfork lifecycle. Once installed, a fork child is
    // intentionally detached and new trace setup fails safely.
    selected_old_default_reaches_new_handler_without_overwriting_it();
    signal_writes_one_valid_fixed_size_marker_and_reraises();
    stale_default_action_still_terminates_by_the_original_signal();
    stale_forwarding_preserves_mask_and_one_shot_reset_behavior();
    real_fault_preserves_siginfo_code_address_and_context();
    successful_run_removes_its_empty_crash_marker_and_restores_handlers();
    concurrent_session_is_rejected_and_multiple_signals_write_once();
    delayed_handler_from_a_finished_run_cannot_touch_the_next_run();
    delayed_custom_handler_uses_old_semantics_without_consuming_the_new_marker();
    delayed_custom_handler_preserves_stale_nodefer_mask();
    forwarded_handlers_keep_masks_nodefer_ignore_and_reset_semantics();
    finish_does_not_wait_for_a_stale_blocking_prior_handler();
    retired_forwarder_cannot_reinstall_after_a_blocking_custom_handler();
    custom_siginfo_receives_the_original_payload_and_context();
    retired_handler_blocks_new_sessions_and_same_path_reuse();
    delayed_old_reset_handler_cannot_clobber_a_new_generation();
    fork_detaches_inherited_crash_session_without_touching_parent_artifact();
    fork_child_closes_marker_fd_already_claimed_by_live_handler();
    fork_child_does_not_close_fd_reused_after_marker_finish();
    artifact_names_are_unique_before_exclusive_trace_creation();
    return 0;
}
