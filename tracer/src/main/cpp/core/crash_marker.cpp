#include "core/crash_marker.h"

#include <atomic>
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <mutex>
#include <pthread.h>
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
size_t g_owner_generation = static_cast<size_t>(-1);

// A handler address can already have been selected by the kernel when finish() replaces
// the sigaction. Give every run a distinct handler/state slot and never reuse it: a delayed
// old handler can then touch only its old, cleared fd and immutable prior actions. Exhaustion
// is a stable setup failure, so target execution can fall back without tracing.
constexpr size_t kMaxHandlerGenerations = 1024;

struct CrashHandlerState {
    // Authoritative identity of the still-open descriptor for this generation.
    // active_fd only controls the handler's one-write claim; retired_fd only
    // controls deferred normal-context cleanup. Neither may erase ownership.
    int owned_fd = -1;
    int active_fd = -1;
    int active_handlers = 0;
    int owns_disposition[5]{};
    int retired_fd = -1;
    std::string retired_path;
    bool retired = false;
    int reset_consumed[5]{};
    struct sigaction previous[5]{};
};

using CrashSignalHandler = void (*)(int, siginfo_t *, void *);
CrashHandlerState g_handler_states[kMaxHandlerGenerations]{};
size_t g_next_handler_generation = 0;
pthread_once_t g_atfork_once = PTHREAD_ONCE_INIT;
std::atomic<int> g_atfork_error{EAGAIN};
volatile sig_atomic_t g_crash_child_detached = 0;
volatile sig_atomic_t g_crash_prepare_locked = 0;

#if defined(QTRACE_HOST_TEST)
using CrashHandlerTestGate = void (*)();
CrashHandlerTestGate g_handler_test_gate = nullptr;
CrashHandlerTestGate g_session_test_gate = nullptr;
#endif

void register_atfork() noexcept {
    g_atfork_error.store(
            ::pthread_atfork(crash_marker_atfork_prepare, crash_marker_atfork_parent,
                             crash_marker_atfork_child),
            std::memory_order_release);
}

bool install_atfork_once() noexcept {
    const int once_error = ::pthread_once(&g_atfork_once, register_atfork);
    if (once_error != 0) {
        g_atfork_error.store(once_error, std::memory_order_release);
    }
    return g_atfork_error.load(std::memory_order_acquire) == 0;
}

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
        // The wrapper was installed with SA_RESETHAND, so the kernel reset its
        // disposition before selecting this thunk. Re-raise only: if another owner
        // installed meanwhile, the pending delivery reaches that current owner.
        (void)::raise(signal_number);
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
    const int fd = __atomic_exchange_n(&state.active_fd, -1, __ATOMIC_ACQ_REL);
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
        const bool owns_disposition = __atomic_exchange_n(
                &state.owns_disposition[index], 0, __ATOMIC_ACQ_REL) != 0;
        if (owns_disposition) {
            struct sigaction current{};
            const struct sigaction previous = effective_previous(state, index);
            if (::sigaction(signal_number, nullptr, &current) == 0 &&
                handler_is_ours(current, self) && previous.sa_handler != SIG_DFL) {
                (void)::sigaction(signal_number, &previous, nullptr);
            }
        }
        // Custom prior actions receive the exact kernel-provided objects. No synthetic
        // signal is queued and no later generation is consulted.
        invoke_previous_preserving_semantics(state, index, signal_number, info, context);
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
    bool have_identity = false;
    bool retain = false;
    if (::fstat(fd, &status) != 0) {
        latch_error(error_code, errno);
        ok = false;
    } else {
        have_identity = true;
        if (status.st_size == static_cast<off_t>(sizeof(CrashMarker))) {
            CrashMarker marker{};
            retain = ::pread(fd, &marker, sizeof(marker), 0) ==
                             static_cast<ssize_t>(sizeof(marker)) &&
                     valid_crash_marker(marker);
        }
    }
    if (::close(fd) != 0) {
        latch_error(error_code, errno);
        ok = false;
    }
    if (!retain && have_identity) {
        struct stat path_status{};
        if (::lstat(path.c_str(), &path_status) == 0) {
            if (path_status.st_dev == status.st_dev && path_status.st_ino == status.st_ino &&
                ::unlink(path.c_str()) != 0 && errno != ENOENT) {
                latch_error(error_code, errno);
                ok = false;
            }
        } else if (errno != ENOENT) {
            latch_error(error_code, errno);
            ok = false;
        }
    }
    return ok;
}

void reap_retired_generation() noexcept {
    if (!g_session_owned || g_owner_generation >= g_next_handler_generation) return;
    CrashHandlerState &state = g_handler_states[g_owner_generation];
    if (!state.retired || state.retired_fd < 0 ||
        __atomic_load_n(&state.active_handlers, __ATOMIC_ACQUIRE) != 0) {
        return;
    }
    const int fd = state.retired_fd;
    state.retired_fd = -1;
    state.retired = false;
    (void)__atomic_exchange_n(&state.owned_fd, -1, __ATOMIC_ACQ_REL);
    int ignored_error = 0;
    (void)finish_marker_file(fd, state.retired_path, &ignored_error);
    g_session_owned = false;
    g_owner_generation = static_cast<size_t>(-1);
}

} // namespace

#if defined(QTRACE_HOST_TEST)
void crash_marker_test_set_handler_gate(CrashHandlerTestGate gate) {
    g_handler_test_gate = gate;
}

void crash_marker_test_set_session_gate(CrashHandlerTestGate gate) {
    g_session_test_gate = gate;
}

void crash_marker_test_force_atfork_error(int error_code) noexcept {
    g_atfork_error.store(error_code == 0 ? EIO : error_code,
                         std::memory_order_release);
}

#endif

bool valid_crash_marker(const CrashMarker &marker) noexcept {
    return marker.magic == kCrashMarkerMagic && marker.tid > 0 &&
           signal_index(marker.signal) < 5;
}

void crash_marker_atfork_prepare() noexcept {
    if (g_crash_child_detached != 0) return;
    g_session_mutex.lock();
    g_crash_prepare_locked = 1;
}

void crash_marker_atfork_parent() noexcept {
    if (g_crash_prepare_locked == 0) return;
    g_crash_prepare_locked = 0;
    g_session_mutex.unlock();
}

void crash_marker_atfork_child() noexcept {
    if (g_crash_prepare_locked == 0) return;
    g_crash_child_detached = 1;
    g_crash_prepare_locked = 0;
    for (size_t generation = 0; generation < g_next_handler_generation; ++generation) {
        CrashHandlerState &state = g_handler_states[generation];
        for (size_t index = 0; index < 5; ++index) {
            struct sigaction current{};
            if (__atomic_load_n(&state.owns_disposition[index], __ATOMIC_ACQUIRE) != 0 &&
                ::sigaction(kCrashSignals[index], nullptr, &current) == 0 &&
                handler_is_ours(current, g_handler_table[generation])) {
                (void)::sigaction(kCrashSignals[index], &state.previous[index], nullptr);
            }
            __atomic_store_n(&state.owns_disposition[index], 0, __ATOMIC_RELEASE);
        }
        // owned_fd remains stable across the handler's active_fd claim and
        // finish's retired_fd transition, so exactly one close covers every
        // live ownership state without risking a second close after fd reuse.
        const int owned_fd = __atomic_exchange_n(&state.owned_fd, -1, __ATOMIC_ACQ_REL);
        (void)__atomic_exchange_n(&state.active_fd, -1, __ATOMIC_ACQ_REL);
        if (owned_fd >= 0) (void)::close(owned_fd);
    }
}

CrashMarkerSession::~CrashMarkerSession() {
    finish();
}

bool CrashMarkerSession::open(const std::string &trace_path) noexcept {
    if (g_crash_child_detached != 0) {
        latch_error(&error_code_, ECHILD);
        finish_called_ = true;
        return false;
    }
    if (!install_atfork_once()) {
        latch_error(&error_code_, g_atfork_error.load(std::memory_order_acquire));
        finish_called_ = true;
        return false;
    }
    if (opened_ || finish_called_ || trace_path.empty()) {
        latch_error(&error_code_, EINVAL);
        return false;
    }

    std::lock_guard<std::mutex> lock(g_session_mutex);
#if defined(QTRACE_HOST_TEST)
    if (g_session_test_gate != nullptr) g_session_test_gate();
#endif
    reap_retired_generation();
    if (g_session_owned) {
        latch_error(&error_code_, EBUSY);
        finish_called_ = true;
        return false;
    }
    g_session_owned = true;

    path_ = trace_path + ".crash";
    fd_ = ::open(path_.c_str(), O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_APPEND, 0644);
    if (fd_ < 0) {
        latch_error(&error_code_, errno);
        g_session_owned = false;
        g_owner_generation = static_cast<size_t>(-1);
        finish_called_ = true;
        return false;
    }
    if (g_next_handler_generation >= kMaxHandlerGenerations) {
        latch_error(&error_code_, ENOSPC);
        (void)::close(fd_);
        fd_ = -1;
        (void)::unlink(path_.c_str());
        g_session_owned = false;
        g_owner_generation = static_cast<size_t>(-1);
        finish_called_ = true;
        return false;
    }
    handler_slot_ = g_next_handler_generation++;
    g_owner_generation = handler_slot_;
    CrashHandlerState &handler_state = g_handler_states[handler_slot_];
    __atomic_store_n(&handler_state.owned_fd, fd_, __ATOMIC_RELEASE);
    __atomic_store_n(&handler_state.active_fd, fd_, __ATOMIC_RELEASE);

    struct sigaction replacement{};
    replacement.sa_sigaction = g_handler_table[handler_slot_];
    for (size_t index = 0; index < kSignalCount; ++index) {
        if (::sigaction(kCrashSignals[index], nullptr, &previous_[index]) != 0) {
            latch_error(&error_code_, errno);
            for (size_t prior = 0; prior < index; ++prior) {
                (void)::sigaction(kCrashSignals[prior], &previous_[prior], nullptr);
            }
            __atomic_store_n(&handler_state.active_fd, -1, __ATOMIC_RELEASE);
            __atomic_store_n(&handler_state.owned_fd, -1, __ATOMIC_RELEASE);
            for (size_t prior = 0; prior < index; ++prior) {
                __atomic_store_n(&handler_state.owns_disposition[prior], 0,
                                 __ATOMIC_RELEASE);
            }
            (void)::close(fd_);
            fd_ = -1;
            (void)::unlink(path_.c_str());
            g_session_owned = false;
            g_owner_generation = static_cast<size_t>(-1);
            finish_called_ = true;
            return false;
        }
        handler_state.previous[index] = previous_[index];
        replacement.sa_mask = previous_[index].sa_mask;
        replacement.sa_flags = SA_SIGINFO |
                               (previous_[index].sa_flags &
                                (SA_RESTART | SA_ONSTACK | SA_NODEFER | SA_RESETHAND));
        if (previous_[index].sa_handler == SIG_DFL) {
            replacement.sa_flags |= SA_RESETHAND;
        }
        if (::sigaction(kCrashSignals[index], &replacement, nullptr) != 0) {
            latch_error(&error_code_, errno);
            for (size_t prior = 0; prior < index; ++prior) {
                (void)::sigaction(kCrashSignals[prior], &previous_[prior], nullptr);
            }
            __atomic_store_n(&handler_state.active_fd, -1, __ATOMIC_RELEASE);
            __atomic_store_n(&handler_state.owned_fd, -1, __ATOMIC_RELEASE);
            for (size_t prior = 0; prior < index; ++prior) {
                __atomic_store_n(&handler_state.owns_disposition[prior], 0,
                                 __ATOMIC_RELEASE);
            }
            (void)::close(fd_);
            fd_ = -1;
            (void)::unlink(path_.c_str());
            g_session_owned = false;
            g_owner_generation = static_cast<size_t>(-1);
            finish_called_ = true;
            return false;
        }
        installed_[index] = true;
        __atomic_store_n(&handler_state.owns_disposition[index], 1, __ATOMIC_RELEASE);
    }

    opened_ = true;
    owner_pid_ = ::getpid();
    return true;
}

bool CrashMarkerSession::finish() noexcept {
    if (finish_called_) return finish_result_;
    finish_called_ = true;
    if (!opened_) return false;
    if (owner_pid_ != ::getpid()) {
        // The atfork child callback already detached and closed the duplicated fd.
        // Never let a copied parent session close a child fd that reused its number.
        fd_ = -1;
        opened_ = false;
        finish_result_ = true;
        return true;
    }

    std::lock_guard<std::mutex> lock(g_session_mutex);
    CrashHandlerState &handler_state = g_handler_states[handler_slot_];
    int expected_fd = fd_;
    const bool fd_unclaimed = __atomic_compare_exchange_n(
            &handler_state.active_fd, &expected_fd, -1, false, __ATOMIC_ACQ_REL,
            __ATOMIC_ACQUIRE);

    bool ok = true;
    for (size_t index = 0; index < kSignalCount; ++index) {
        if (!installed_[index]) continue;
        const bool owns_disposition = __atomic_exchange_n(
                &handler_state.owns_disposition[index], 0, __ATOMIC_ACQ_REL) != 0;
        struct sigaction current{};
        if (::sigaction(kCrashSignals[index], nullptr, &current) != 0) {
            latch_error(&error_code_, errno);
            ok = false;
        } else if (owns_disposition &&
                   handler_is_ours(current, g_handler_table[handler_slot_])) {
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
        (void)__atomic_exchange_n(&handler_state.owned_fd, -1, __ATOMIC_ACQ_REL);
        ok = finish_marker_file(fd_, path_, &error_code_) && ok;
    } else {
        // The handler owns this descriptor. Retire it without waiting; immutable generation
        // state remains valid forever and a later non-signal operation reaps it after exit.
        handler_state.retired_fd = fd_;
        handler_state.retired_path = path_;
        handler_state.retired = true;
    }
    fd_ = -1;

    opened_ = false;
    if (!handler_state.retired) {
        g_session_owned = false;
        g_owner_generation = static_cast<size_t>(-1);
    }
    finish_result_ = ok;
    return finish_result_;
}
