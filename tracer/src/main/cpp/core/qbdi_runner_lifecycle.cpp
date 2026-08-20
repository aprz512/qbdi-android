#include "core/qbdi_runner_lifecycle.h"

#include "core/trace_process_lifecycle.h"
#include "events/binary_trace_writer.h"

bool register_qbdi_callbacks(const QbdiCallbackRegistration &registration) noexcept {
    bool succeeded = registration.add_pre != nullptr &&
                     registration.add_pre(registration.opaque) !=
                             registration.invalid_event_id;
    if (registration.requires_post) {
        const bool post_succeeded = registration.add_post != nullptr &&
                                    registration.add_post(registration.opaque) !=
                                            registration.invalid_event_id;
        succeeded = post_succeeded && succeeded;
    }
    const bool exec_succeeded = registration.add_exec_transfer != nullptr &&
                                registration.add_exec_transfer(registration.opaque) !=
                                        registration.invalid_event_id;
    return exec_succeeded && succeeded;
}

QbdiTargetCallResult run_qbdi_target_call(QbdiTargetCall call, void *opaque,
                                          BinaryTraceWriter *writer) noexcept {
    QbdiTargetCallResult result{};
    if (call != nullptr) result.succeeded = call(opaque, &result.return_value);
    result.child_detached = trace_process_child_detached();
    if (result.child_detached && writer != nullptr) writer->detach_after_fork_child();
    return result;
}
