#pragma once

#include "events/trace_sink.h"

#include <QBDI.h>
#include <QBDI/Callback.h>

#include <cstdint>
#include <string>
#include <vector>

struct PendingExecTransfer {
    uintptr_t target = 0;
    std::string category;
    std::string name;
};

struct ExecTransferMonitor {
    std::vector<PendingExecTransfer> pending;
};

void emit_exec_transfer_event(ExecTransferMonitor *monitor, const QBDI::VMState *vm_state,
                              QBDI::GPRState *state, TraceSink *sink);

// 设置 JNI 回溯配置（需在 emit_exec_transfer_event 之前调用）
void set_jni_backtrace_funcs(const std::vector<std::string> &funcs);
