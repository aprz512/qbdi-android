#pragma once
#include <cstdint>

struct RuntimeProbeInput {
    volatile uint64_t values[16];
    uint64_t observed_pid = 0;
    int wait_status = -1;
    int receipt_fd = -1;
};
using RuntimeProbeTarget = uint64_t (*)(int, RuntimeProbeInput *);
