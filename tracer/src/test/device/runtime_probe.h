#pragma once
#include <cstdint>

struct RuntimeSyscallResult {
    const char *name = nullptr;
    uint64_t number = 0;
    uint64_t args[6]{};
    uint64_t raw_return = 0;
    int errno_before = 0;
    int errno_after = 0;
};

struct RuntimeProbeInput {
    volatile uint64_t values[16];
    uint64_t observed_pid = 0;
    int wait_status = -1;
    int receipt_fd = -1;
    RuntimeSyscallResult syscalls[8]{};
    uint32_t syscall_count = 0;
    uint32_t signal_count = 0;
    uint32_t signal_order = 0;
};
using RuntimeProbeTarget = uint64_t (*)(int, RuntimeProbeInput *);
