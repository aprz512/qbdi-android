#pragma once

#include "core/memory_trace_policy.h"
#include "core/pending_instruction.h"
#include "core/qbdi_instruction_decoder.h"
#include "core/trace_config.h"
#include "core/arm64_syscall.h"

#include <QBDI.h>

#include <array>

class CodeRuleEngine;
class SignalBroker;
struct SignalBrokerThreadState;
class TraceCallbackGate;
class TraceSink;
struct TraceContext;

class InstructionCollector final : public PendingInstructionSink {
public:
    InstructionCollector(InstructionCache *cache, TraceSink *writer,
                         CodeRuleEngine *code_rules, const TraceContext *trace,
                         TraceCallbackGate *trace_gate,
                         const TraceOptions &options,
                         const ModuleRange &retained_module,
                         SignalBroker *signal_broker = nullptr,
                         SignalBrokerThreadState *signal_thread = nullptr) noexcept;

    QBDI::VMAction on_pre(QBDI::VM *vm, QBDI::GPRState *gpr, QBDI::FPRState *fpr);
    QBDI::VMAction on_memory(QBDI::VM *vm, QBDI::GPRState *gpr);
    QBDI::VMAction on_post(QBDI::VM *vm, QBDI::GPRState *gpr, QBDI::FPRState *fpr);
    void finish_last(const QBDI::GPRState &gpr) noexcept;

    static QBDI::VMAction pre_callback(QBDI::VM *vm, QBDI::GPRState *gpr,
                                       QBDI::FPRState *fpr, void *data);
    static QBDI::VMAction memory_callback(QBDI::VM *vm, QBDI::GPRState *gpr,
                                          QBDI::FPRState *fpr, void *data);
    static QBDI::VMAction post_callback(QBDI::VM *vm, QBDI::GPRState *gpr,
                                        QBDI::FPRState *fpr, void *data);

    bool emit(const InstructionRecord &record,
              const RegisterSnapshot &post_registers) override;
    bool emit_memory_continuation(uintptr_t pc,
                                  const MemoryRecord &record) override;

private:
    InstructionView resolve(QBDI::VM *vm, const QBDI::GPRState *gpr) noexcept;
    static RegisterSnapshot snapshot(const QBDI::GPRState &gpr, uint64_t mask) noexcept;
    void capture_pre_memory(QBDI::VM *vm) noexcept;
    void begin_syscall(const Arm64SyscallSnapshot &call, uint64_t signal_epoch) noexcept;
    void end_syscall(bool observed, uint64_t raw, const char *reason) noexcept;

    InstructionCache *cache_ = nullptr;
    TraceSink *writer_ = nullptr;
    CodeRuleEngine *code_rules_ = nullptr;
    const TraceContext *trace_ = nullptr;
    TraceCallbackGate *trace_gate_ = nullptr;
    TraceProfile profile_ = TraceProfile::Fast;
    size_t hexdump_limit_ = 0;
    bool decode_memory_ = false;
    bool calls_only_ = false;
    bool syscall_details_ = false;
    uint64_t syscall_id_ = 0;
    uint64_t syscall_signal_epoch_ = 0;
    Arm64SyscallSnapshot syscall_pending_{};
    Arm64InstructionResolver resolver_{ModuleRange{}};
    CachedInstruction uncached_{};
    InstructionView current_view_{};
    MemoryTracePolicy memory_policy_{};
    PendingInstructionCollector pending_;
    SignalBroker *signal_broker_ = nullptr;
    SignalBrokerThreadState *signal_thread_ = nullptr;
};
