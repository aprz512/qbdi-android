#include "core/qbdi_thread_session.h"

#include "core/trace_process_lifecycle.h"

#include <new>

#if !defined(QTRACE_HOST_TEST)
#include "core/instruction_cache.h"
#include "core/instruction_collector.h"
#include "core/flight_transfer_event.h"
#include "core/logging.h"
#include "core/module_maps.h"
#include "core/qbdi_runner_lifecycle.h"
#include "core/trace_callback_gate.h"
#include "core/trace_config.h"
#include "events/binary_trace_writer.h"
#include "events/trace_sink.h"
#include "flight/flight_artifact.h"
#include "flight/flight_chunk_writer.h"
#include "flight/flight_trace_sink.h"
#include "handlers/call_handlers.h"
#include "rules/code_rule.h"

#include <QBDI.h>
#include <QBDI/State.h>

#include <array>
#include <cstdio>
#include <cstring>
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace {

thread_local QbdiThreadSession *g_current_qbdi_thread_session = nullptr;

} // namespace

#if defined(QTRACE_HOST_TEST)
struct QbdiThreadSession::Impl {};
#else

struct QbdiThreadSession::Impl {
    Impl(const TraceConfig &source_config, const TraceInvocation &invocation,
         TraceContext *external_context, TraceSink *external_sink,
         TraceCallbackGate *external_gate, BinaryTraceWriter *writer) noexcept
            : config(&source_config), module(invocation.module), scene(invocation.scene),
              context(external_context), sink(external_sink), gate(external_gate),
              normal_writer(writer), trace_options(source_config.trace) {
        initialize_collector();
    }

    Impl(const TraceConfig &source_config, const ModuleRange &retained_module,
         const SceneConfig &entry_scene, uint32_t thread_id,
         FlightArtifact *flight_artifact) noexcept
            : config(&source_config), module(&retained_module), scene(&entry_scene),
              context(&owned_context), sink(&flight_sink), gate(&owned_gate),
              artifact(flight_artifact), trace_options(source_config.trace),
              flight(true) {
        trace_options.profile = TraceProfile::Full;
        owned_context.module_base = module->start;
        owned_context.target_offset = scene->offset;
        (void)module_offset_address(*module, scene->offset, false,
                                    &owned_context.target_address);
        owned_context.pid = ::getpid();
        owned_context.tid = static_cast<int>(thread_id);
        if (artifact == nullptr ||
            !artifact->register_thread(thread_id, &registration) ||
            !chunk_writer.initialize(artifact, registration)) {
            return;
        }
        initialize_collector();
    }

    ~Impl() {
        delete collector;
        collector = nullptr;
        if (flight) {
            (void)chunk_writer.seal();
            chunk_writer.detach();
        }
        if (fakestack != nullptr) QBDI::alignedFree(fakestack);
    }

    void initialize_collector() noexcept {
        if (context == nullptr || sink == nullptr || gate == nullptr ||
            config == nullptr || module == nullptr || scene == nullptr ||
            module->start >= module->end) {
            return;
        }
        register_user_code_rules(code_rules);
        collector = new (std::nothrow) InstructionCollector(
                &instruction_cache, sink, &code_rules, context, gate,
                trace_options, *module);
        ready = collector != nullptr;
    }

    bool fail_setup(const char *message) noexcept {
        if (sink != nullptr && message != nullptr) (void)sink->error(message);
        if (gate != nullptr) gate->observe_failure(true);
        return false;
    }

    bool instrument(uintptr_t entry, uintptr_t execution_entry,
                    size_t execution_bytes) noexcept {
        if (flight) {
            if (execution_bytes == 0 ||
                execution_entry > UINTPTR_MAX - execution_bytes) {
                return fail_setup("retained gateway extent is invalid");
            }
            vm.addInstrumentedRange(execution_entry,
                                    execution_entry + execution_bytes);
            if (module->readable_executable_range_count != 0) {
                for (size_t index = 0;
                     index < module->readable_executable_range_count; ++index) {
                    const AddressRange range =
                            module->readable_executable_ranges[index];
                    if (range.start >= range.end || range.start < module->start ||
                        range.end > module->end) {
                        return fail_setup("retained module executable range is invalid");
                    }
                    vm.addInstrumentedRange(range.start, range.end);
                }
                return true;
            }
            if (!vm.addInstrumentedModuleFromAddr(entry)) {
                return fail_setup("addInstrumentedModuleFromAddr failed");
            }
            return true;
        }

        if (scene->end_offset > 0) {
            uintptr_t range_start = 0;
            uintptr_t range_end = 0;
            if (!module_offset_address(*module, scene->offset, false, &range_start) ||
                !module_offset_address(*module, scene->end_offset, true, &range_end) ||
                range_end <= range_start) {
                return fail_setup(
                        "scene instrumentation range is outside retained module");
            }
            vm.addInstrumentedRange(range_start, range_end);
            return true;
        }
        const uintptr_t logical_address = context != nullptr
                                                  ? context->target_address
                                                  : entry;
        if (!vm.addInstrumentedModuleFromAddr(logical_address)) {
            char message[128];
            const int count = std::snprintf(
                    message, sizeof(message),
                    "addInstrumentedModuleFromAddr failed address=0x%llx",
                    static_cast<unsigned long long>(logical_address));
            return count > 0 && static_cast<size_t>(count) < sizeof(message)
                           ? fail_setup(message)
                           : fail_setup("addInstrumentedModuleFromAddr failed");
        }
        return true;
    }

    static uint32_t add_pre(void *opaque) noexcept {
        auto *self = static_cast<Impl *>(opaque);
        if (self->flight) return self->add_target_code_callbacks(QBDI::PREINST);
        return self->vm.addCodeCB(QBDI::PREINST,
                                  InstructionCollector::pre_callback,
                                  self->collector);
    }

    static uint32_t add_post(void *opaque) noexcept {
        auto *self = static_cast<Impl *>(opaque);
        if (self->flight) return self->add_target_code_callbacks(QBDI::POSTINST);
        return self->vm.addCodeCB(QBDI::POSTINST,
                                  InstructionCollector::post_callback,
                                  self->collector);
    }

    static QBDI::VMAction on_target_pre(QBDI::VM *vm, QBDI::GPRState *gpr,
                                        QBDI::FPRState *fpr, void *opaque) {
        auto *self = static_cast<Impl *>(opaque);
        if (gpr != nullptr) self->last_target_pc = gpr->pc;
        return InstructionCollector::pre_callback(vm, gpr, fpr, self->collector);
    }

    static QBDI::VMAction on_target_post(QBDI::VM *vm, QBDI::GPRState *gpr,
                                         QBDI::FPRState *fpr, void *opaque) {
        auto *self = static_cast<Impl *>(opaque);
        return InstructionCollector::post_callback(vm, gpr, fpr, self->collector);
    }

    uint32_t add_target_code_callbacks(QBDI::InstPosition position) noexcept {
        const size_t count = module->readable_executable_range_count;
        uint32_t first = QBDI::INVALID_EVENTID;
        for (size_t index = 0; index < (count == 0 ? 1U : count); ++index) {
            const AddressRange range = count == 0
                                               ? AddressRange{module->start, module->end}
                                               : module->readable_executable_ranges[index];
            const uint32_t id = vm.addCodeRangeCB(
                    range.start, range.end, position,
                    position == QBDI::PREINST ? on_target_pre : on_target_post,
                    this);
            if (id == QBDI::INVALID_EVENTID) return id;
            if (first == QBDI::INVALID_EVENTID) first = id;
        }
        return first;
    }

    static QBDI::VMAction on_exec_transfer(QBDI::VM *,
                                           const QBDI::VMState *vm_state,
                                           QBDI::GPRState *gpr,
                                           QBDI::FPRState *, void *opaque) {
        if (trace_process_child_detached()) return QBDI::CONTINUE;
        auto *self = static_cast<Impl *>(opaque);
        self->gate->observe_failure(self->sink->failed());
        return self->gate->trace(QBDI::CONTINUE, [&] {
            if (self->flight &&
                !emit_flight_transfer_event(&self->flight_transfer,
                                            self->last_target_pc, vm_state,
                                            gpr, self->sink)) {
                return false;
            }
            emit_exec_transfer_event(&self->exec_transfer, vm_state, gpr,
                                     self->sink);
            return !self->sink->failed();
        });
    }

    static uint32_t add_exec(void *opaque) noexcept {
        auto *self = static_cast<Impl *>(opaque);
        return self->vm.addVMEventCB(
                QBDI::EXEC_TRANSFER_CALL | QBDI::EXEC_TRANSFER_RETURN,
                on_exec_transfer, self);
    }

    bool initialize_execution(uintptr_t logical_entry, uintptr_t execution_entry,
                              size_t execution_bytes, const uint64_t args[8],
                              uint64_t indirect_result) noexcept {
        QBDI::GPRState *gpr = vm.getGPRState();
        if (gpr == nullptr) return fail_setup("QBDI GPR state unavailable");
        if (fakestack == nullptr) {
            constexpr uint32_t kVirtualStackSize = 0x1000000;
            if (!QBDI::allocateVirtualStack(gpr, kVirtualStackSize,
                                            &fakestack)) {
                return fail_setup("allocateVirtualStack failed");
            }
            initial_sp = gpr->sp;
        }
        for (size_t index = 0; index < call_arguments.size(); ++index) {
            call_arguments[index] = static_cast<QBDI::rword>(args[index]);
            QBDI_GPR_SET(gpr, index, args[index]);
        }
        gpr->x8 = indirect_result;
        gpr->sp = initial_sp;
        gpr->pc = execution_entry;
        last_target_pc = logical_entry;
        if (flight && context != nullptr) {
            context->target_address = logical_entry;
            context->target_offset = logical_entry >= module->start
                                             ? logical_entry - module->start
                                             : 0;
        }

        if (setup_attempted) return setup_succeeded;
        setup_attempted = true;
        if (!instrument(logical_entry, execution_entry, execution_bytes)) return false;
        const FlightTraceContextView flight_context{
                scene->name, config->target_so, context->module_base,
                context->target_offset, context->target_address,
                static_cast<uint32_t>(context->pid),
                static_cast<uint32_t>(context->tid)};
        if (flight && !flight_sink.initialize(&chunk_writer, TraceProfile::Full,
                                              flight_context, gpr)) {
            return fail_setup("flight trace sink initialization failed");
        }

        const QbdiCallbackRegistration registration_callbacks{
                this, add_pre, add_post, add_exec,
                static_cast<uint32_t>(QBDI::INVALID_EVENTID),
                code_rules.requires_immediate_post()};
        if (!register_qbdi_callbacks(registration_callbacks)) {
            return fail_setup("QBDI callback registration failed");
        }
        if (trace_options.memory_enabled()) {
            const bool recording =
                    vm.recordMemoryAccess(QBDI::MEMORY_READ_WRITE);
            const uint32_t callback =
                    recording
                            ? vm.addMemAccessCB(
                                      QBDI::MEMORY_READ_WRITE,
                                      InstructionCollector::memory_callback,
                                      collector)
                            : QBDI::INVALID_EVENTID;
            if (!recording || callback == QBDI::INVALID_EVENTID) {
                return fail_setup("QBDI memory instrumentation unavailable");
            }
        }
        setup_succeeded = true;
        return true;
    }

    TraceRunResult call(uintptr_t logical_entry, uintptr_t execution_entry,
                        size_t execution_bytes,
                        const uint64_t args[8],
                        uint64_t indirect_result) noexcept {
        if (!ready || !initialize_execution(logical_entry, execution_entry,
                                            execution_bytes, args,
                                            indirect_result)) {
            return {};
        }
        QBDI::rword value = 0;
        const bool succeeded = vm.callA(&value, execution_entry,
                                        static_cast<uint32_t>(call_arguments.size()),
                                        call_arguments.data());
        if (trace_process_child_detached()) {
            return {succeeded, static_cast<uint64_t>(value)};
        }
        if (succeeded) {
            QBDI::GPRState *gpr = vm.getGPRState();
            if (gpr != nullptr) collector->finish_last(*gpr);
        }
        return {succeeded, static_cast<uint64_t>(value)};
    }

    const TraceConfig *config = nullptr;
    const ModuleRange *module = nullptr;
    const SceneConfig *scene = nullptr;
    TraceContext owned_context;
    TraceContext *context = nullptr;
    TraceSink *sink = nullptr;
    TraceCallbackGate owned_gate;
    TraceCallbackGate *gate = nullptr;
    BinaryTraceWriter *normal_writer = nullptr;
    FlightArtifact *artifact = nullptr;
    TraceOptions trace_options{};
    FlightThreadRegistration registration{};
    FlightChunkWriter chunk_writer;
    FlightTraceSink flight_sink;
    InstructionCache instruction_cache;
    CodeRuleEngine code_rules;
    ExecTransferMonitor exec_transfer;
    FlightTransferMonitor flight_transfer;
    QBDI::VM vm;
    InstructionCollector *collector = nullptr;
    std::array<QBDI::rword, 8> call_arguments{};
    uint8_t *fakestack = nullptr;
    QBDI::rword initial_sp = 0;
    uintptr_t last_target_pc = 0;
    bool flight = false;
    bool ready = false;
    bool setup_attempted = false;
    bool setup_succeeded = false;
};
#endif

QbdiThreadSession *current_qbdi_thread_session() noexcept {
    return g_current_qbdi_thread_session;
}

QbdiThreadSession::QbdiThreadSession(uint32_t tid,
                                     uint32_t module_generation) noexcept
        : tid_(tid), module_generation_(module_generation) {}

QbdiThreadSession::~QbdiThreadSession() {
    if (trace_process_child_detached()) return;
    if (g_current_qbdi_thread_session == this) g_current_qbdi_thread_session = nullptr;
    delete impl_;
}

bool QbdiThreadSession::try_enter() noexcept {
    if (!ready_ || entered_ || vm_running_ ||
        (g_current_qbdi_thread_session != nullptr &&
         g_current_qbdi_thread_session != this)) {
        return false;
    }
    entered_ = true;
    g_current_qbdi_thread_session = this;
    return true;
}

void QbdiThreadSession::leave() noexcept {
    if (trace_process_child_detached() || !entered_ || vm_running_) return;
    entered_ = false;
    if (g_current_qbdi_thread_session == this) g_current_qbdi_thread_session = nullptr;
}

void QbdiThreadSession::mark_coverage_gap(uintptr_t pc) noexcept {
    if (trace_process_child_detached()) return;
    incomplete_ = true;
    if (gap_reporter_ != nullptr) gap_reporter_(gap_opaque_, tid_, pc);
}

void QbdiThreadSession::set_gap_reporter(
        QbdiThreadSessionGapReporter gap_reporter, void *gap_opaque) noexcept {
    gap_reporter_ = gap_reporter;
    gap_opaque_ = gap_opaque;
}

void QbdiThreadSession::copy_cache_metrics(TraceMetrics *metrics) const noexcept {
#if defined(QTRACE_HOST_TEST)
    (void)metrics;
#else
    if (metrics == nullptr || impl_ == nullptr) return;
    const InstructionCacheMetrics cache = impl_->instruction_cache.metrics();
    metrics->cache_hits = cache.hits;
    metrics->cache_misses = cache.misses;
    metrics->cache_collisions = cache.collisions;
#endif
}

TraceRunResult QbdiThreadSession::call(uintptr_t entry, const uint64_t args[8],
                                       uint64_t indirect_result) noexcept {
    return call_gateway(entry, entry, 0, args, indirect_result);
}

TraceRunResult QbdiThreadSession::call_gateway(
        uintptr_t logical_entry, uintptr_t execution_entry,
        size_t execution_bytes,
        const uint64_t args[8], uint64_t indirect_result) noexcept {
    if (!ready_ || logical_entry == 0 || execution_entry == 0 ||
        args == nullptr || vm_running_) {
        mark_coverage_gap(logical_entry);
        return {};
    }

    bool entered_here = false;
    if (!entered_) {
        if (!try_enter()) {
            mark_coverage_gap(logical_entry);
            return {};
        }
        entered_here = true;
    } else if (g_current_qbdi_thread_session != this) {
        mark_coverage_gap(logical_entry);
        return {};
    }

    vm_running_ = true;
    const TraceRunResult result = execute(logical_entry, execution_entry,
                                          execution_bytes, args,
                                          indirect_result);
    if (trace_process_child_detached()) return result;
    vm_running_ = false;
    if (!result.target_executed) mark_coverage_gap(logical_entry);
    if (entered_here) leave();
    return result;
}

#if defined(QTRACE_HOST_TEST)

QbdiThreadSession *QbdiThreadSession::create_for_test(
        uint32_t tid, uint32_t module_generation,
        QbdiThreadSessionTestExecutor executor, void *executor_opaque,
        QbdiThreadSessionGapReporter gap_reporter, void *gap_opaque) noexcept {
    if (tid == 0 || module_generation == 0 || executor == nullptr) return nullptr;
    auto *session = new (std::nothrow) QbdiThreadSession(tid, module_generation);
    if (session == nullptr) return nullptr;
    session->test_executor_ = executor;
    session->test_executor_opaque_ = executor_opaque;
    session->gap_reporter_ = gap_reporter;
    session->gap_opaque_ = gap_opaque;
    session->ready_ = true;
    return session;
}

TraceRunResult QbdiThreadSession::execute(uintptr_t, uintptr_t execution_entry,
                                          size_t,
                                          const uint64_t args[8],
                                          uint64_t indirect_result) noexcept {
    if (test_executor_ == nullptr) return {};
    return test_executor_(test_executor_opaque_, this, execution_entry, args,
                          indirect_result);
}

QbdiThreadSession *QbdiThreadSession::create_normal(
        const TraceConfig &, const TraceInvocation &, TraceContext *, TraceSink *,
        TraceCallbackGate *, BinaryTraceWriter *) noexcept {
    return nullptr;
}

QbdiThreadSession *QbdiThreadSession::create_flight(
        const TraceConfig &, const ModuleRange &, const SceneConfig &, uint32_t,
        uint32_t, FlightArtifact *) noexcept {
    return nullptr;
}

#else

QbdiThreadSession *QbdiThreadSession::create_normal(
        const TraceConfig &config, const TraceInvocation &invocation,
        TraceContext *context, TraceSink *sink, TraceCallbackGate *callback_gate,
        BinaryTraceWriter *normal_writer) noexcept {
    if (invocation.scene == nullptr || invocation.module == nullptr ||
        context == nullptr || sink == nullptr || callback_gate == nullptr) {
        return nullptr;
    }
    const uint32_t tid = static_cast<uint32_t>(context->tid);
    auto *session = new (std::nothrow) QbdiThreadSession(tid, 1);
    if (session == nullptr) return nullptr;
    session->impl_ = new (std::nothrow) Impl(
            config, invocation, context, sink, callback_gate, normal_writer);
    session->ready_ = session->impl_ != nullptr && session->impl_->ready;
    if (!session->ready_) {
        delete session;
        return nullptr;
    }
    return session;
}

QbdiThreadSession *QbdiThreadSession::create_flight(
        const TraceConfig &config, const ModuleRange &module,
        const SceneConfig &scene, uint32_t tid, uint32_t module_generation,
        FlightArtifact *artifact) noexcept {
    if (tid == 0 || module_generation == 0 || artifact == nullptr) return nullptr;
    auto *session = new (std::nothrow)
            QbdiThreadSession(tid, module_generation);
    if (session == nullptr) return nullptr;
    session->impl_ = new (std::nothrow)
            Impl(config, module, scene, tid, artifact);
    session->ready_ = session->impl_ != nullptr && session->impl_->ready;
    if (!session->ready_) {
        delete session;
        return nullptr;
    }
    return session;
}

TraceRunResult QbdiThreadSession::execute(uintptr_t logical_entry,
                                          uintptr_t execution_entry,
                                          size_t execution_bytes,
                                          const uint64_t args[8],
                                          uint64_t indirect_result) noexcept {
    if (impl_ == nullptr) return {};
    const TraceRunResult result = impl_->call(logical_entry, execution_entry,
                                              execution_bytes, args,
                                              indirect_result);
    if (result.target_executed && !trace_process_child_detached() &&
        (impl_->sink->failed() || !impl_->gate->enabled())) {
        mark_coverage_gap(logical_entry);
    }
    return result;
}

#endif
