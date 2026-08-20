#include "core/qbdi_runner_lifecycle.h"

#include "core/trace_process_lifecycle.h"
#include "events/text_trace_writer.h"

QbdiTargetCallResult run_qbdi_target_call(QbdiTargetCall call, void *opaque,
                                          TextTraceWriter *writer) noexcept {
    QbdiTargetCallResult result{};
    if (call != nullptr) result.succeeded = call(opaque, &result.return_value);
    result.child_detached = trace_process_child_detached();
    if (result.child_detached && writer != nullptr) writer->detach_after_fork_child();
    return result;
}
