#pragma once

#include <cstdint>

class BinaryTraceWriter;

using QbdiTargetCall = bool (*)(void *opaque, uint64_t *return_value);

struct QbdiTargetCallResult {
    bool succeeded = false;
    uint64_t return_value = 0;
    bool child_detached = false;
};

QbdiTargetCallResult run_qbdi_target_call(QbdiTargetCall call, void *opaque,
                                          BinaryTraceWriter *writer) noexcept;
