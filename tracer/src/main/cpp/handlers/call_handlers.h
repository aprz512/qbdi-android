#pragma once

#include "events/trace_sink.h"

#include <QBDI.h>
#include <QBDI/Callback.h>

#include <cstdint>
#include <array>
#include <string>
#include <vector>

struct JniFuncInfo;

struct JniCallSnapshot {
    const JniFuncInfo *func = nullptr;
    std::array<uint64_t, 8> args{};
    int tid = 0;
    long enter_ms = 0;
};

struct PendingExecTransfer {
    uintptr_t target = 0;
    std::string category;
    std::string name;
    JniCallSnapshot jni;
};

struct ExecTransferMonitor {
    std::vector<PendingExecTransfer> pending;
};

void emit_exec_transfer_event(ExecTransferMonitor *monitor, const QBDI::VMState *vm_state,
                              QBDI::GPRState *state, TraceSink *sink,
                              const QBDI::FPRState *floating = nullptr);

// 设置 JNI 回溯配置（需在 emit_exec_transfer_event 之前调用）
void set_jni_backtrace_funcs(const std::vector<std::string> &funcs);
