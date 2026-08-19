#include "core/crash_marker.h"

#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <mutex>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>
#include <utility>

namespace {

constexpr int kCrashSignals[] = {SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGFPE};
static_assert(sizeof(kCrashSignals) / sizeof(kCrashSignals[0]) == 5);

std::mutex g_session_mutex;
bool g_session_owned = false;

// A handler address can already have been selected by the kernel when finish() replaces
// the sigaction. Give every run a distinct handler/state slot and never reuse it: a delayed
// old handler can then touch only its old, cleared fd and immutable prior actions. Exhaustion
// is a stable setup failure, so target execution can fall back without tracing.
constexpr size_t kMaxHandlerGenerations = 1024;

struct CrashHandlerState {
    int active_fd = -1;
    int active_handlers = 0;
    int retired_fd = -1;
    std::string retired_path;
    int reset_consumed[5]{};
    struct sigaction previous[5]{};
};

using CrashSignalHandler = void (*)(int, siginfo_t *, void *);
CrashHandlerState g_handler_states[kMaxHandlerGenerations]{};
size_t g_next_handler_generation = 0;
constexpr int kForwardedSignalMagic = 0x51434657;

#if defined(QTRACE_HOST_TEST)
using CrashHandlerTestGate = void (*)();
CrashHandlerTestGate g_handler_test_gate = nullptr;
bool g_force_forward_failure = false;
#endif

size_t signal_index(int signal_number) noexcept {
    for (size_t index = 0; index < 5; ++index) {
        if (kCrashSignals[index] == signal_number) return index;
    }
    return 5;
}

bool handler_is_ours(const struct sigaction &action,
                     CrashSignalHandler expected) noexcept {
    return (action.sa_flags & SA_SIGINFO) != 0 && action.sa_sigaction == expected;
}

bool is_forwarded_signal(const siginfo_t *info) noexcept {
    return info != nullptr && info->si_code == SI_QUEUE &&
           info->si_value.sival_int == kForwardedSignalMagic &&
           info->si_pid == static_cast<pid_t>(syscall(SYS_getpid));
}

bool queue_forwarded_signal(int signal_number) noexcept {
#if defined(QTRACE_HOST_TEST)
    if (g_force_forward_failure) return false;
#endif
    siginfo_t forwarded{};
    forwarded.si_signo = signal_number;
    forwarded.si_code = SI_QUEUE;
    forwarded.si_pid = static_cast<pid_t>(syscall(SYS_getpid));
    forwarded.si_uid = static_cast<uid_t>(syscall(SYS_getuid));
    forwarded.si_value.sival_int = kForwardedSignalMagic;
    long result = -1;
    do {
        result = syscall(SYS_rt_tgsigqueueinfo, forwarded.si_pid,
                         static_cast<pid_t>(syscall(SYS_gettid)), signal_number,
                         &forwarded);
    } while (result != 0 && errno == EINTR);
    // Never fall back to an untagged signal: a newer generation would mistake it for a
    // real crash and consume its marker fd. Failure leaves the immutable old generation
    // retired without perturbing the active run.
    return result == 0;
}

struct sigaction effective_previous(CrashHandlerState &state, size_t index) noexcept {
    if (__atomic_load_n(&state.reset_consumed[index], __ATOMIC_ACQUIRE) == 0) {
        return state.previous[index];
    }
    struct sigaction defaults{};
    defaults.sa_handler = SIG_DFL;
    sigemptyset(&defaults.sa_mask);
    return defaults;
}

void invoke_previous_preserving_semantics(CrashHandlerState &state, size_t index,
                                          int signal_number, siginfo_t *info,
                                          void *context) noexcept {
    const struct sigaction previous = effective_previous(state, index);
    if (previous.sa_handler == SIG_IGN) return;

    if (previous.sa_handler == SIG_DFL) {
        // Default behavior cannot be emulated with _exit: install the true default and
        // re-raise so wait status/core semantics remain kernel-defined. This path does not
        // return, so it cannot reinstall a retired tracer action.
        if (::sigaction(signal_number, &previous, nullptr) == 0) {
            sigset_t delivery_mask{};
            if (context != nullptr) {
                delivery_mask = static_cast<ucontext_t *>(context)->uc_sigmask;
            } else {
                (void)::sigprocmask(SIG_SETMASK, nullptr, &delivery_mask);
                sigdelset(&delivery_mask, signal_number);
            }
            (void)::raise(signal_number);
            (void)::sigprocmask(SIG_SETMASK, &delivery_mask, nullptr);
        }
        return;
    }

    if ((previous.sa_flags & SA_RESETHAND) != 0) {
        int expected = 0;
        if (!__atomic_compare_exchange_n(&state.reset_consumed[index], &expected, 1, false,
                                         __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            invoke_previous_preserving_semantics(state, index, signal_number, info, context);
            return;
        }
    }

    sigset_t saved_mask{};
    (void)::sigprocmask(SIG_SETMASK, nullptr, &saved_mask);
    sigset_t handler_mask = context != nullptr
                                    ? static_cast<ucontext_t *>(context)->uc_sigmask
                                    : saved_mask;
    for (int masked_signal = 1; masked_signal < NSIG; ++masked_signal) {
        if (sigismember(&previous.sa_mask, masked_signal) == 1) {
            sigaddset(&handler_mask, masked_signal);
        }
    }
    if ((previous.sa_flags & SA_NODEFER) == 0) {
        sigaddset(&handler_mask, signal_number);
    } else if (context == nullptr) {
        // A test/manual stale entry has no pre-delivery ucontext; remove the tracer
        // handler's automatic self-block to reproduce SA_NODEFER.
        sigdelset(&handler_mask, signal_number);
    }
    (void)::sigprocmask(SIG_SETMASK, &handler_mask, nullptr);
    if ((previous.sa_flags & SA_SIGINFO) != 0) {
        previous.sa_sigaction(signal_number, info, context);
    } else {
        previous.sa_handler(signal_number);
    }
    (void)::sigprocmask(SIG_SETMASK, &saved_mask, nullptr);
}

void crash_marker_handler_for_generation(size_t generation, int signal_number,
                                         siginfo_t *info, void *context,
                                         CrashSignalHandler self) noexcept {
    const int saved_errno = errno;
    CrashHandlerState &state = g_handler_states[generation];
    static_assert(__atomic_always_lock_free(sizeof(int), nullptr));
    (void)__atomic_add_fetch(&state.active_handlers, 1, __ATOMIC_ACQ_REL);
    const bool forwarded = is_forwarded_signal(info);
    const int fd = forwarded
                           ? -1
                           : __atomic_exchange_n(&state.active_fd, -1, __ATOMIC_ACQ_REL);
    if (fd >= 0) {
        const CrashMarker marker{kCrashMarkerMagic, signal_number,
                                 static_cast<int32_t>(syscall(SYS_gettid))};
        // Exactly one attempt. EINTR, zero, or a short write remains invalid and is never
        // retried in signal context; readers accept only one complete fixed-size record.
        const ssize_t write_result = ::write(fd, &marker, sizeof(marker));
        (void)write_result;
    }
#if defined(QTRACE_HOST_TEST)
    if (g_handler_test_gate != nullptr) g_handler_test_gate();
#endif
    const size_t index = signal_index(signal_number);
    if (index < 5) {
        struct sigaction current{};
        const bool still_installed =
                ::sigaction(signal_number, nullptr, &current) == 0 &&
                handler_is_ours(current, self);
        if (still_installed && forwarded) {
            invoke_previous_preserving_semantics(state, index, signal_number, info, context);
        } else if (still_installed) {
            const struct sigaction previous = effective_previous(state, index);
            if (::sigaction(signal_number, &previous, nullptr) == 0) {
                (void)::raise(signal_number);
            } else {
                if (!queue_forwarded_signal(signal_number)) {
                    invoke_previous_preserving_semantics(state, index, signal_number,
                                                         info, context);
                }
            }
        } else {
            // Re-enter the currently installed action through the kernel so SIG_DFL, SIG_IGN,
            // masks, SA_NODEFER, SA_RESETHAND, and SA_SIGINFO are applied normally. A newer
            // tracer handler recognizes this token and skips its fd before forwarding again.
            if (!queue_forwarded_signal(signal_number)) {
                invoke_previous_preserving_semantics(state, index, signal_number,
                                                     info, context);
            }
        }
    }
    errno = saved_errno;
    (void)__atomic_sub_fetch(&state.active_handlers, 1, __ATOMIC_ACQ_REL);
}

template <size_t Generation>
void crash_marker_handler(int signal_number, siginfo_t *info, void *context) noexcept {
    crash_marker_handler_for_generation(Generation, signal_number, info, context,
                                        crash_marker_handler<Generation>);
}

template <size_t... Generations>
constexpr auto make_handler_table(std::index_sequence<Generations...>) {
    return std::array<CrashSignalHandler, sizeof...(Generations)>{
            crash_marker_handler<Generations>...};
}

constexpr auto g_handler_table =
        make_handler_table(std::make_index_sequence<kMaxHandlerGenerations>{});

void latch_error(int *destination, int value) noexcept {
    if (*destination == 0) *destination = value == 0 ? EIO : value;
}

bool finish_marker_file(int fd, const std::string &path, int *error_code) noexcept {
    bool ok = true;
    struct stat status{};
    bool retain = false;
    if (::fstat(fd, &status) != 0) {
        latch_error(error_code, errno);
        ok = false;
    } else if (status.st_size == static_cast<off_t>(sizeof(CrashMarker))) {
        CrashMarker marker{};
        retain = ::pread(fd, &marker, sizeof(marker), 0) ==
                         static_cast<ssize_t>(sizeof(marker)) &&
                 valid_crash_marker(marker);
    }
    if (::close(fd) != 0) {
        latch_error(error_code, errno);
        ok = false;
    }
    if (!retain && ::unlink(path.c_str()) != 0 && errno != ENOENT) {
        latch_error(error_code, errno);
        ok = false;
    }
    return ok;
}

void reap_retired_generations() noexcept {
    for (size_t generation = 0; generation < g_next_handler_generation; ++generation) {
        CrashHandlerState &state = g_handler_states[generation];
        if (state.retired_fd < 0 ||
            __atomic_load_n(&state.active_handlers, __ATOMIC_ACQUIRE) != 0) {
            continue;
        }
        const int fd = state.retired_fd;
        state.retired_fd = -1;
        int ignored_error = 0;
        (void)finish_marker_file(fd, state.retired_path, &ignored_error);
    }
}

} // namespace

#if defined(QTRACE_HOST_TEST)
void crash_marker_test_set_handler_gate(CrashHandlerTestGate gate) {
    g_handler_test_gate = gate;
}

void crash_marker_test_force_forward_failure(bool enabled) {
    g_force_forward_failure = enabled;
}
#endif

bool valid_crash_marker(const CrashMarker &marker) noexcept {
    return marker.magic == kCrashMarkerMagic && marker.tid > 0 &&
           signal_index(marker.signal) < 5;
}

CrashMarkerSession::~CrashMarkerSession() {
    finish();
}

bool CrashMarkerSession::open(const std::string &trace_path) noexcept {
    if (opened_ || finish_called_ || trace_path.empty()) {
        latch_error(&error_code_, EINVAL);
        return false;
    }

    std::lock_guard<std::mutex> lock(g_session_mutex);
    reap_retired_generations();
    if (g_session_owned) {
        latch_error(&error_code_, EBUSY);
        finish_called_ = true;
        return false;
    }
    g_session_owned = true;

    path_ = trace_path + ".crash";
    fd_ = ::open(path_.c_str(), O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC | O_APPEND, 0644);
    if (fd_ < 0) {
        latch_error(&error_code_, errno);
        g_session_owned = false;
        finish_called_ = true;
        return false;
    }
    if (g_next_handler_generation >= kMaxHandlerGenerations) {
        latch_error(&error_code_, ENOSPC);
        (void)::close(fd_);
        fd_ = -1;
        (void)::unlink(path_.c_str());
        g_session_owned = false;
        finish_called_ = true;
        return false;
    }
    handler_slot_ = g_next_handler_generation++;
    CrashHandlerState &handler_state = g_handler_states[handler_slot_];
    __atomic_store_n(&handler_state.active_fd, fd_, __ATOMIC_RELEASE);

    struct sigaction replacement{};
    replacement.sa_sigaction = g_handler_table[handler_slot_];
    sigemptyset(&replacement.sa_mask);
    for (size_t index = 0; index < kSignalCount; ++index) {
        if (::sigaction(kCrashSignals[index], nullptr, &previous_[index]) != 0) {
            latch_error(&error_code_, errno);
            for (size_t prior = 0; prior < index; ++prior) {
                (void)::sigaction(kCrashSignals[prior], &previous_[prior], nullptr);
            }
            __atomic_store_n(&handler_state.active_fd, -1, __ATOMIC_RELEASE);
            (void)::close(fd_);
            fd_ = -1;
            (void)::unlink(path_.c_str());
            g_session_owned = false;
            finish_called_ = true;
            return false;
        }
        handler_state.previous[index] = previous_[index];
        replacement.sa_flags = SA_SIGINFO |
                               (previous_[index].sa_flags & (SA_RESTART | SA_ONSTACK));
        if (::sigaction(kCrashSignals[index], &replacement, nullptr) != 0) {
            latch_error(&error_code_, errno);
            for (size_t prior = 0; prior < index; ++prior) {
                (void)::sigaction(kCrashSignals[prior], &previous_[prior], nullptr);
            }
            __atomic_store_n(&handler_state.active_fd, -1, __ATOMIC_RELEASE);
            (void)::close(fd_);
            fd_ = -1;
            (void)::unlink(path_.c_str());
            g_session_owned = false;
            finish_called_ = true;
            return false;
        }
        installed_[index] = true;
    }

    opened_ = true;
    return true;
}

bool CrashMarkerSession::finish() noexcept {
    if (finish_called_) return finish_result_;
    finish_called_ = true;
    if (!opened_) return false;

    std::lock_guard<std::mutex> lock(g_session_mutex);
    CrashHandlerState &handler_state = g_handler_states[handler_slot_];
    int expected_fd = fd_;
    const bool fd_unclaimed = __atomic_compare_exchange_n(
            &handler_state.active_fd, &expected_fd, -1, false, __ATOMIC_ACQ_REL,
            __ATOMIC_ACQUIRE);

    bool ok = true;
    for (size_t index = 0; index < kSignalCount; ++index) {
        if (!installed_[index]) continue;
        struct sigaction current{};
        if (::sigaction(kCrashSignals[index], nullptr, &current) != 0) {
            latch_error(&error_code_, errno);
            ok = false;
        } else if (handler_is_ours(current, g_handler_table[handler_slot_])) {
            const struct sigaction previous = effective_previous(handler_state, index);
            if (::sigaction(kCrashSignals[index], &previous, nullptr) != 0) {
                latch_error(&error_code_, errno);
                ok = false;
            }
        }
        installed_[index] = false;
    }
    if (fd_unclaimed ||
        __atomic_load_n(&handler_state.active_handlers, __ATOMIC_ACQUIRE) == 0) {
        ok = finish_marker_file(fd_, path_, &error_code_) && ok;
    } else {
        // The handler owns this descriptor. Retire it without waiting; immutable generation
        // state remains valid forever and a later non-signal operation reaps it after exit.
        handler_state.retired_fd = fd_;
        handler_state.retired_path = path_;
    }
    fd_ = -1;

    opened_ = false;
    g_session_owned = false;
    finish_result_ = ok;
    return finish_result_;
}
