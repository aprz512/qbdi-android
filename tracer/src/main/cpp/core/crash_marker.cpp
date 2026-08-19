#include "core/crash_marker.h"

#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <mutex>
#include <sys/stat.h>
#include <sys/syscall.h>
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
    struct sigaction previous[5]{};
};

using CrashSignalHandler = void (*)(int, siginfo_t *, void *);
CrashHandlerState g_handler_states[kMaxHandlerGenerations]{};
size_t g_next_handler_generation = 0;

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

void forward_to_previous(const struct sigaction &previous, int signal_number,
                         siginfo_t *info, void *context) noexcept {
    if (previous.sa_handler == SIG_IGN) return;
    if (previous.sa_handler == SIG_DFL) {
        // A stale, already-selected handler cannot temporarily install SIG_DFL without
        // clobbering a newer run. Preserve fail-stop behavior without touching sigaction.
        _exit(128 + signal_number);
    }
    if ((previous.sa_flags & SA_SIGINFO) != 0) {
        previous.sa_sigaction(signal_number, info, context);
    } else {
        previous.sa_handler(signal_number);
    }
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
    const size_t index = signal_index(signal_number);
    if (index < 5) {
        struct sigaction current{};
        const bool still_installed =
                ::sigaction(signal_number, nullptr, &current) == 0 &&
                handler_is_ours(current, self);
        if (still_installed &&
            ::sigaction(signal_number, &state.previous[index], nullptr) == 0) {
            (void)::raise(signal_number);
        } else {
            // The delivery selected an older generation before teardown. Do not restore
            // over a newer/external action and do not read any newer generation's state.
            forward_to_previous(state.previous[index], signal_number, info, context);
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

} // namespace

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
    replacement.sa_flags = SA_SIGINFO;
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
    (void)__atomic_compare_exchange_n(&handler_state.active_fd, &expected_fd, -1, false,
                                      __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);

    bool ok = true;
    for (size_t index = 0; index < kSignalCount; ++index) {
        if (!installed_[index]) continue;
        struct sigaction current{};
        if (::sigaction(kCrashSignals[index], nullptr, &current) != 0) {
            latch_error(&error_code_, errno);
            ok = false;
        } else if (handler_is_ours(current, g_handler_table[handler_slot_]) &&
                   ::sigaction(kCrashSignals[index], &previous_[index], nullptr) != 0) {
            latch_error(&error_code_, errno);
            ok = false;
        }
        installed_[index] = false;
    }
    while (__atomic_load_n(&handler_state.active_handlers, __ATOMIC_ACQUIRE) != 0) {}

    struct stat status{};
    bool retain = false;
    if (::fstat(fd_, &status) != 0) {
        latch_error(&error_code_, errno);
        ok = false;
    } else if (status.st_size == static_cast<off_t>(sizeof(CrashMarker))) {
        CrashMarker marker{};
        retain = ::pread(fd_, &marker, sizeof(marker), 0) ==
                         static_cast<ssize_t>(sizeof(marker)) &&
                 valid_crash_marker(marker);
    }
    if (::close(fd_) != 0) {
        latch_error(&error_code_, errno);
        ok = false;
    }
    fd_ = -1;
    if (!retain && ::unlink(path_.c_str()) != 0 && errno != ENOENT) {
        latch_error(&error_code_, errno);
        ok = false;
    }

    opened_ = false;
    g_session_owned = false;
    finish_result_ = ok;
    return finish_result_;
}
