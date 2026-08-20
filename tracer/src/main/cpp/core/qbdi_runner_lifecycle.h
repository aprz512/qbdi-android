#pragma once

#include <cstdint>

class BinaryTraceWriter;

using QbdiTargetCall = bool (*)(void *opaque, uint64_t *return_value);

struct QbdiTargetCallResult {
    bool succeeded = false;
    uint64_t return_value = 0;
    bool child_detached = false;
};

using QbdiRegisterCallback = uint32_t (*)(void *opaque) noexcept;

// Type-erased production seam for the three callbacks required before vm.call. All requested
// registrars are invoked even after an earlier failure, matching QBDI runner setup ordering.
struct QbdiCallbackRegistration {
    void *opaque = nullptr;
    QbdiRegisterCallback add_pre = nullptr;
    QbdiRegisterCallback add_post = nullptr;
    QbdiRegisterCallback add_exec_transfer = nullptr;
    uint32_t invalid_event_id = 0;
    bool requires_post = false;
};

bool register_qbdi_callbacks(const QbdiCallbackRegistration &) noexcept;

QbdiTargetCallResult run_qbdi_target_call(QbdiTargetCall call, void *opaque,
                                          BinaryTraceWriter *writer) noexcept;
