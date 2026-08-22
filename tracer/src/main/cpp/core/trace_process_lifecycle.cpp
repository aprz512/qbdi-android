#include "core/trace_process_lifecycle.h"

#if !defined(QTRACE_HOST_TEST)
#include "core/signal_broker.h"
#endif

#include <array>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <pthread.h>
#include <unistd.h>

namespace {

volatile sig_atomic_t g_trace_child_detached = 0;
volatile sig_atomic_t g_trace_writer_prepare_locked = 0;
pthread_once_t g_trace_lifecycle_once = PTHREAD_ONCE_INIT;
std::atomic<int> g_trace_lifecycle_error{EAGAIN};
pthread_mutex_t g_trace_writer_fd_registry_mutex = PTHREAD_MUTEX_INITIALIZER;
constexpr size_t kMaxActiveTraceWriterFds = 1024;
std::array<std::atomic<int>, kMaxActiveTraceWriterFds> g_trace_writer_fds{};
static_assert(std::atomic<int>::is_always_lock_free);

void trace_process_atfork_prepare() noexcept {
    if (g_trace_child_detached != 0) return;
    (void)::pthread_mutex_lock(&g_trace_writer_fd_registry_mutex);
    g_trace_writer_prepare_locked = 1;
}

void trace_process_atfork_parent() noexcept {
    if (g_trace_writer_prepare_locked == 0) return;
    g_trace_writer_prepare_locked = 0;
    (void)::pthread_mutex_unlock(&g_trace_writer_fd_registry_mutex);
}

void trace_process_atfork_child() noexcept {
    trace_process_mark_child_detached();
#if !defined(QTRACE_HOST_TEST)
    detach_process_signal_broker_after_fork_child();
#endif
    g_trace_writer_prepare_locked = 0;
    for (std::atomic<int> &slot : g_trace_writer_fds) {
        const int fd_plus_one = slot.exchange(0, std::memory_order_relaxed);
        if (fd_plus_one > 0) (void)::close(fd_plus_one - 1);
    }
}

void install_atfork() noexcept {
    g_trace_lifecycle_error.store(
            ::pthread_atfork(trace_process_atfork_prepare, trace_process_atfork_parent,
                             trace_process_atfork_child),
            std::memory_order_release);
}

} // namespace

bool trace_process_child_detached() noexcept {
    return g_trace_child_detached != 0;
}

void trace_process_mark_child_detached() noexcept {
    g_trace_child_detached = 1;
}

bool install_trace_process_lifecycle() noexcept {
    const int once_error = ::pthread_once(&g_trace_lifecycle_once, install_atfork);
    if (once_error != 0) {
        g_trace_lifecycle_error.store(once_error, std::memory_order_release);
    }
    return trace_process_lifecycle_ready();
}

bool trace_process_lifecycle_ready() noexcept {
    return g_trace_lifecycle_error.load(std::memory_order_acquire) == 0;
}

int trace_process_lifecycle_error() noexcept {
    return g_trace_lifecycle_error.load(std::memory_order_acquire);
}

#if defined(QTRACE_HOST_TEST)
void trace_process_test_force_lifecycle_error(int error_code) noexcept {
    g_trace_lifecycle_error.store(error_code == 0 ? EIO : error_code,
                                  std::memory_order_release);
}
#endif

void trace_writer_fd_registry_lock() noexcept {
    (void)::pthread_mutex_lock(&g_trace_writer_fd_registry_mutex);
}

void trace_writer_fd_registry_unlock() noexcept {
    (void)::pthread_mutex_unlock(&g_trace_writer_fd_registry_mutex);
}

size_t trace_writer_fd_register_locked(int fd) noexcept {
    if (fd < 0) return kInvalidTraceWriterFdSlot;
    const int fd_plus_one = fd + 1;
    if (fd_plus_one <= 0) return kInvalidTraceWriterFdSlot;
    for (size_t index = 0; index < g_trace_writer_fds.size(); ++index) {
        int empty = 0;
        if (g_trace_writer_fds[index].compare_exchange_strong(
                    empty, fd_plus_one, std::memory_order_relaxed,
                    std::memory_order_relaxed)) {
            return index;
        }
    }
    return kInvalidTraceWriterFdSlot;
}

void trace_writer_fd_unregister_locked(size_t slot, int fd) noexcept {
    if (slot >= g_trace_writer_fds.size()) return;
    int owned = fd + 1;
    (void)g_trace_writer_fds[slot].compare_exchange_strong(
            owned, 0, std::memory_order_relaxed, std::memory_order_relaxed);
}
