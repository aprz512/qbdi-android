#pragma once

#include <cstddef>

constexpr size_t kInvalidTraceWriterFdSlot = static_cast<size_t>(-1);

bool trace_process_child_detached() noexcept;
void trace_process_mark_child_detached() noexcept;
bool install_trace_process_lifecycle() noexcept;
bool trace_process_lifecycle_ready() noexcept;
int trace_process_lifecycle_error() noexcept;

#if defined(QTRACE_HOST_TEST)
void trace_process_test_force_lifecycle_error(int error_code) noexcept;
#endif

// Normal-process ownership transitions hold this registry lock across both the
// descriptor syscall and slot publication. The atfork child never unlocks or
// otherwise touches the inherited pthread object.
void trace_writer_fd_registry_lock() noexcept;
void trace_writer_fd_registry_unlock() noexcept;
size_t trace_writer_fd_register_locked(int fd) noexcept;
void trace_writer_fd_unregister_locked(size_t slot, int fd) noexcept;
