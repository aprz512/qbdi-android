#include "core/qbdi_thread_session.h"

#include "core/capture_coordinator.h"
#include "core/signal_broker.h"
#include "core/trace_process_lifecycle.h"

#include <new>
#include <pthread.h>
#include <sched.h>

#if defined(QTRACE_HOST_TEST)
#define QTRACE_SESSION_CALL_NOEXCEPT
#else
#define QTRACE_SESSION_CALL_NOEXCEPT noexcept
#endif

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
#include <QBDI/Memory.hpp>
#include <QBDI/State.h>

#include <array>
#include <cstdio>
#include <cstring>
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace {

thread_local QbdiThreadSession *g_current_qbdi_thread_session = nullptr;

#if defined(QTRACE_HOST_TEST)
bool accept_test_control_extent(void *, uintptr_t, uintptr_t) noexcept {
    return true;
}
#endif

} // namespace

bool recognize_deferred_pthread_exit(uintptr_t destination,
                                     uintptr_t pthread_exit_destination,
                                     uint64_t exit_value,
                                     TraceRunResult *result) noexcept {
    if (destination == 0 || pthread_exit_destination == 0 ||
        destination != pthread_exit_destination || result == nullptr) {
        return false;
    }
    *result = {true, false, true, exit_value};
    return true;
}

bool needs_thread_begin_publication(bool pending, bool published) noexcept {
    return pending && !published;
}

QBDI::VMAction classify_deferred_pthread_exit_event(
        const QBDI::VMState *vm_state, const QBDI::GPRState *gpr,
        uintptr_t pthread_exit_destination, TraceRunResult *result) noexcept {
    if (vm_state == nullptr || gpr == nullptr || result == nullptr) {
        return QBDI::CONTINUE;
    }
    uintptr_t destination = 0;
    if ((vm_state->event & QBDI::EXEC_TRANSFER_CALL) != 0) {
        destination = vm_state->basicBlockStart;
    } else if ((vm_state->event &
                (QBDI::BASIC_BLOCK_EXIT | QBDI::SEQUENCE_EXIT)) != 0) {
        destination = gpr->pc;
    }
    return recognize_deferred_pthread_exit(
                   destination, pthread_exit_destination,
                   QBDI_GPR_GET(gpr, 0), result)
                   ? QBDI::STOP
                   : QBDI::CONTINUE;
}

bool make_pthread_exit_control_hole(uintptr_t pthread_exit_destination,
                                    AddressRange *hole) noexcept {
    if (pthread_exit_destination == 0 || hole == nullptr ||
        pthread_exit_destination > UINTPTR_MAX - sizeof(uint32_t)) {
        return false;
    }
    *hole = {pthread_exit_destination,
             pthread_exit_destination + sizeof(uint32_t)};
    return true;
}

void observe_qbdi_vm_target_post(
        const QbdiVmExecutionLifecycle &signal_execution,
        const QBDI::GPRState *gpr, uintptr_t return_address) noexcept {
    signal_execution.observe_target_post(gpr, return_address);
}

#if defined(QTRACE_HOST_TEST)
struct QbdiThreadSession::Impl {};
#else

namespace {

uint64_t activate_signal_execution(void *opaque,
                                   QBDI::GPRState *gpr) noexcept {
    return static_cast<SignalBrokerThreadState *>(opaque)
            ->activate_execution(gpr);
}

void clear_signal_execution(void *opaque) noexcept {
    static_cast<SignalBrokerThreadState *>(opaque)->deactivate_execution();
}

void observe_signal_target_post(void *opaque, const QBDI::GPRState *gpr,
                                uintptr_t return_address) noexcept {
    static_cast<SignalBrokerThreadState *>(opaque)
            ->observe_target_post(gpr, return_address);
}

}  // namespace

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
        signal_broker = &SignalBroker::process();
        if (!signal_thread.initialize(thread_id, artifact, registration,
                                      vm.getGPRState()) ||
            !signal_broker->register_thread(&signal_thread)) {
            return;
        }
        signal_registered = true;
        signal_execution = {&signal_thread, activate_signal_execution,
                            clear_signal_execution,
                            observe_signal_target_post};
        initialize_collector();
    }

    ~Impl() {
        if (signal_registered && signal_broker != nullptr) {
            signal_broker->unregister_thread(&signal_thread);
            signal_registered = false;
        }
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
                trace_options, *module, signal_broker,
                signal_registered ? &signal_thread : nullptr);
        ready = collector != nullptr;
    }

    bool fail_setup(const char *message) noexcept {
        if (sink != nullptr && message != nullptr) (void)sink->error(message);
        if (gate != nullptr) gate->observe_failure(true);
        return false;
    }

    bool is_target_address(uintptr_t address) const noexcept {
        if (module == nullptr || address == 0) return false;
        const size_t count = module->readable_executable_range_count;
        for (size_t index = 0; index < (count == 0 ? 1U : count); ++index) {
            const AddressRange range = count == 0
                                               ? AddressRange{module->start, module->end}
                                               : module->readable_executable_ranges[index];
            if (range.start < range.end && address >= range.start &&
                address < range.end) {
                return true;
            }
        }
        return false;
    }

    void exclude_native_pthread_exit() noexcept {
        const uintptr_t entry = reinterpret_cast<uintptr_t>(pthread_exit);
        AddressRange hole{};
        if (make_pthread_exit_control_hole(entry, &hole)) {
            vm.removeInstrumentedRange(hole.start, hole.end);
        }
    }

    bool instrument_target(uintptr_t entry) noexcept {
        if (flight) {
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
                exclude_native_pthread_exit();
                return true;
            }
            if (!vm.addInstrumentedModuleFromAddr(entry)) {
                return fail_setup("addInstrumentedModuleFromAddr failed");
            }
            exclude_native_pthread_exit();
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

    static bool add_control_range(void *opaque, uintptr_t start,
                                  uintptr_t end) noexcept {
        auto *self = static_cast<Impl *>(opaque);
        self->vm.addInstrumentedRange(start, end);
        return true;
    }

    static bool add_control_observer(void *opaque, uintptr_t start,
                                     uintptr_t end) noexcept {
        auto *self = static_cast<Impl *>(opaque);
        return self->vm.addCodeRangeCB(start, end, QBDI::PREINST,
                                       on_control_pre, self) !=
               QBDI::INVALID_EVENTID;
    }

    QbdiControlExtentRegistration control_registration() noexcept {
        return {this, add_control_range, add_control_observer};
    }

    bool fail_control_extent(QbdiControlExtentResult result) noexcept {
        switch (result) {
            case QbdiControlExtentResult::Invalid:
                return fail_setup("retained gateway extent is invalid");
            case QbdiControlExtentResult::CapacityExceeded:
                return fail_setup("retained gateway extent capacity exhausted");
            case QbdiControlExtentResult::InstrumentationFailed:
                return fail_setup("control-only instrumentation unavailable");
            case QbdiControlExtentResult::ObserverFailed:
                return fail_setup("control-only execution observer unavailable");
            case QbdiControlExtentResult::Added:
            case QbdiControlExtentResult::AlreadyPresent:
                return true;
        }
        return fail_setup("retained gateway extent setup failed");
    }

    bool copy_execution_state(QbdiExecutionState *state) noexcept {
        if (state == nullptr) return false;
        const QBDI::GPRState *gpr = vm.getGPRState();
        if (gpr == nullptr) return false;
        static_assert(QBDI::REG_PC + 1 == 34);
        for (size_t index = 0; index <= QBDI::REG_PC; ++index) {
            state->words[index] = QBDI_GPR_GET(gpr, index);
        }
        state->words[34] = gpr->localMonitor.addr;
        state->words[35] = gpr->localMonitor.enable;
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
        if (gpr != nullptr) {
            self->target_execution_observed = true;
            self->last_target_pc = self->control_only ? 0 : gpr->pc;
        }
        if (self->control_only) return QBDI::CONTINUE;
        return InstructionCollector::pre_callback(vm, gpr, fpr, self->collector);
    }

    static QBDI::VMAction on_control_pre(QBDI::VM *, QBDI::GPRState *,
                                         QBDI::FPRState *, void *opaque) {
        static_cast<Impl *>(opaque)->target_execution_observed = true;
        return QBDI::CONTINUE;
    }

    static QBDI::VMAction on_target_post(QBDI::VM *vm, QBDI::GPRState *gpr,
                                         QBDI::FPRState *fpr, void *opaque) {
        auto *self = static_cast<Impl *>(opaque);
        observe_qbdi_vm_target_post(self->signal_execution, gpr,
                                    kReturnAddress);
        if (self->control_only) return QBDI::CONTINUE;
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
        TraceRunResult deferred_exit{};
        const QBDI::VMAction deferred_action = self->flight
                ? classify_deferred_pthread_exit_event(
                          vm_state, gpr,
                          reinterpret_cast<uintptr_t>(pthread_exit),
                          &deferred_exit)
                : QBDI::CONTINUE;
        const bool requests_exit = deferred_action == QBDI::STOP;
        if (requests_exit) {
            self->thread_exit_requested = true;
            self->thread_exit_value = deferred_exit.value;
        }
        if (vm_state == nullptr ||
            (vm_state->event & (QBDI::EXEC_TRANSFER_CALL |
                                QBDI::EXEC_TRANSFER_RETURN)) == 0) {
            return deferred_action;
        }
        self->gate->observe_failure(self->sink->failed());
        const QBDI::VMAction action = self->gate->trace(
                deferred_action, [&] {
                    if (self->flight &&
                        !emit_flight_transfer_event(
                                &self->flight_transfer,
                                !self->control_only &&
                                                self->is_target_address(
                                                        self->last_target_pc)
                                        ? self->last_target_pc
                                        : 0,
                                vm_state, gpr, self->sink,
                                !self->control_only)) {
                        return false;
                    }
                    if (!self->control_only &&
                        (!self->flight ||
                         self->flight_transfer.last_published)) {
                        emit_exec_transfer_event(&self->exec_transfer,
                                                 vm_state, gpr, self->sink);
                    }
                    return !self->sink->failed();
                });
        if ((vm_state->event & QBDI::EXEC_TRANSFER_CALL) != 0) {
            self->last_target_pc = 0;
        }
        return action;
    }

    static uint32_t add_exec(void *opaque) noexcept {
        auto *self = static_cast<Impl *>(opaque);
        return self->vm.addVMEventCB(
                QBDI::BASIC_BLOCK_EXIT | QBDI::SEQUENCE_EXIT |
                        QBDI::EXEC_TRANSFER_CALL |
                        QBDI::EXEC_TRANSFER_RETURN,
                on_exec_transfer, self);
    }

    bool initialize_execution(uintptr_t logical_entry, uintptr_t execution_entry,
                              const uint64_t args[8],
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
        last_target_pc = is_target_address(logical_entry) ? logical_entry : 0;
        if (flight && context != nullptr && is_target_address(logical_entry)) {
            context->target_address = logical_entry;
            context->target_offset = logical_entry >= module->start
                                             ? logical_entry - module->start
                                             : 0;
        }

        if (setup_attempted) return setup_succeeded;
        setup_attempted = true;
        if (!instrument_target(logical_entry)) {
            return false;
        }
        const FlightTraceContextView flight_context{
                scene->name, config->target_so, context->module_base,
                context->target_offset, context->target_address,
                static_cast<uint32_t>(context->pid),
                static_cast<uint32_t>(context->tid)};
        if (flight && !flight_sink.ensure_initialized(
                              &chunk_writer, TraceProfile::Full,
                              flight_context, gpr)) {
            return fail_setup("flight trace sink initialization failed");
        }
        if (flight &&
            needs_thread_begin_publication(thread_lifecycle_pending,
                                           thread_lifecycle_published) &&
            !publish_thread_begin()) {
            return fail_setup("flight thread-begin publication failed");
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
                        const uint64_t args[8],
                        uint64_t indirect_result) noexcept {
        if (!ready || !initialize_execution(logical_entry, execution_entry,
                                            args, indirect_result)) {
            return {};
        }
        QBDI::GPRState *gpr = vm.getGPRState();
        if (gpr == nullptr) return {};
        QBDI::simulateCallA(gpr, kReturnAddress,
                            static_cast<uint32_t>(call_arguments.size()),
                            call_arguments.data());
        if (flight && !flight_sink.sync_registers(*gpr)) return {};
        thread_exit_requested = false;
        thread_exit_value = 0;
        target_execution_observed = false;
        control_only = false;
        if (!signal_execution.activate(gpr)) return {};
        const bool executed = vm.run(execution_entry, kReturnAddress);
        signal_execution.clear();
        const bool returned = executed && gpr->pc == kReturnAddress;
        const bool target_executed = executed || target_execution_observed;
        const uint64_t value = QBDI_GPR_GET(gpr, 0);
        if (trace_process_child_detached()) {
            return {target_executed, returned, value};
        }
        if (target_executed || thread_exit_requested) collector->finish_last(*gpr);
        if (thread_exit_requested) {
            return {true, false, true, thread_exit_value};
        }
        return {target_executed, returned, value};
    }

    TraceRunResult continue_control_only() noexcept {
        QBDI::GPRState *gpr = vm.getGPRState();
        if (!ready || gpr == nullptr || gpr->pc == 0 ||
            gpr->pc == kReturnAddress) {
            return {};
        }
        control_only = true;
        const uintptr_t continuation = gpr->pc;
        if (!signal_execution.activate(gpr)) return {};
        const bool executed = vm.run(continuation, kReturnAddress);
        signal_execution.clear();
        const bool returned = executed && gpr->pc == kReturnAddress;
        if (thread_exit_requested) {
            return {true, false, true, thread_exit_value};
        }
        return {true, returned, QBDI_GPR_GET(gpr, 0)};
    }

    bool begin_thread(uint32_t creator_tid, uintptr_t start_routine,
                      uint32_t module_generation) noexcept {
        if (!flight || thread_lifecycle_pending || thread_lifecycle_published ||
            creator_tid == 0 || start_routine == 0 || module_generation == 0) {
            return false;
        }
        thread_creator_tid = creator_tid;
        thread_start_routine = start_routine;
        thread_module_generation = module_generation;
        thread_lifecycle_pending = true;
        return true;
    }

    bool publish_thread_begin() noexcept {
        if (!thread_lifecycle_pending || thread_lifecycle_published ||
            !flight_sink.thread_begin(
                    thread_creator_tid, static_cast<uint32_t>(context->tid),
                    thread_start_routine, thread_module_generation)) {
            return false;
        }
        thread_lifecycle_published = true;
        return true;
    }

    bool publish_native_thread_begin() noexcept {
        if (!flight || !thread_lifecycle_pending ||
            thread_lifecycle_published) {
            return false;
        }
        QBDI::GPRState *gpr = vm.getGPRState();
        if (gpr == nullptr || context == nullptr) return false;
        const FlightTraceContextView flight_context{
                scene->name, config->target_so, context->module_base,
                context->target_offset, context->target_address,
                static_cast<uint32_t>(context->pid),
                static_cast<uint32_t>(context->tid)};
        return flight_sink.ensure_initialized(
                       &chunk_writer, TraceProfile::Full, flight_context, gpr) &&
               publish_thread_begin();
    }

    bool end_thread() noexcept {
        if (!thread_lifecycle_pending || thread_lifecycle_ended) return false;
        thread_lifecycle_ended = true;
        if (!thread_lifecycle_published) return false;
        const bool emitted =
                flight_sink.thread_end(static_cast<uint32_t>(context->tid));
        const bool sealed = chunk_writer.seal();
        return emitted && sealed;
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
    SignalBroker *signal_broker = nullptr;
    SignalBrokerThreadState signal_thread{};
    QbdiVmExecutionLifecycle signal_execution{};
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
    uintptr_t thread_start_routine = 0;
    uint32_t thread_creator_tid = 0;
    uint32_t thread_module_generation = 0;
    bool flight = false;
    bool signal_registered = false;
    bool ready = false;
    bool setup_attempted = false;
    bool setup_succeeded = false;
    bool thread_lifecycle_pending = false;
    bool thread_lifecycle_published = false;
    bool thread_lifecycle_ended = false;
    bool thread_exit_requested = false;
    uint64_t thread_exit_value = 0;
    static constexpr QBDI::rword kReturnAddress = 42;
    bool target_execution_observed = false;
    bool control_only = false;
};
#endif

QbdiThreadSession *current_qbdi_thread_session() noexcept {
    return g_current_qbdi_thread_session;
}

std::shared_ptr<CaptureCoordinator> current_capture_coordinator() noexcept {
    return g_current_qbdi_thread_session == nullptr
                   ? std::shared_ptr<CaptureCoordinator>{}
                   : g_current_qbdi_thread_session->active_capture_owner_;
}

QbdiThreadSession::QbdiThreadSession(uint32_t tid,
                                     uint32_t module_generation) noexcept
        : tid_(tid), module_generation_(module_generation) {}

QbdiThreadSession::~QbdiThreadSession() {
    if (g_current_qbdi_thread_session == this) {
        g_current_qbdi_thread_session = nullptr;
    }
    if (trace_process_child_detached()) {
        new (&capture_owner_) std::weak_ptr<CaptureCoordinator>();
        new (&active_capture_owner_) std::shared_ptr<CaptureCoordinator>();
        return;
    }
    active_capture_owner_.reset();
    delete impl_;
}

bool QbdiThreadSession::try_enter() noexcept {
    if (!ready_ || entered_ || vm_running_ ||
        (g_current_qbdi_thread_session != nullptr &&
         g_current_qbdi_thread_session != this)) {
        return false;
    }
    active_capture_owner_ = capture_owner_.lock();
    if (capture_owner_required_ && active_capture_owner_ == nullptr) {
        return false;
    }
    entered_ = true;
    g_current_qbdi_thread_session = this;
    return true;
}

void QbdiThreadSession::leave() noexcept {
    if (!entered_ || vm_running_) return;
    entered_ = false;
    if (g_current_qbdi_thread_session == this) {
        g_current_qbdi_thread_session = nullptr;
    }
    if (trace_process_child_detached()) return;
    active_capture_owner_.reset();
}

bool QbdiThreadSession::begin_thread(uint32_t creator_tid,
                                     uintptr_t start_routine) noexcept {
    if (!ready_ || thread_begun_ || thread_ended_ || creator_tid == 0 ||
        start_routine == 0) {
        return false;
    }
#if defined(QTRACE_HOST_TEST)
    if (lifecycle_reporter_ != nullptr &&
        !lifecycle_reporter_(lifecycle_opaque_, tid_, true, creator_tid,
                             start_routine)) {
        return false;
    }
#else
    if (impl_ == nullptr ||
        !impl_->begin_thread(creator_tid, start_routine, module_generation_)) {
        return false;
    }
#endif
    creator_tid_ = creator_tid;
    thread_entry_ = start_routine;
    thread_begun_ = true;
    return true;
}

bool QbdiThreadSession::publish_native_thread_begin() noexcept {
    if (!thread_begun_ || thread_ended_) return false;
#if defined(QTRACE_HOST_TEST)
    return true;
#else
    return impl_ != nullptr && impl_->publish_native_thread_begin();
#endif
}

bool QbdiThreadSession::end_thread() noexcept {
    if (!thread_begun_ || thread_ended_) return false;
#if defined(QTRACE_HOST_TEST)
    const bool ended = lifecycle_reporter_ == nullptr ||
                       lifecycle_reporter_(lifecycle_opaque_, tid_, false,
                                           creator_tid_, thread_entry_);
#else
    const bool ended = impl_ != nullptr && impl_->end_thread();
#endif
    thread_ended_ = true;
    return ended;
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

void QbdiThreadSession::set_capture_owner(
        const std::weak_ptr<CaptureCoordinator> &owner) noexcept {
    capture_owner_ = owner;
    capture_owner_required_ = !owner.expired();
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
                                       uint64_t indirect_result)
        QTRACE_SESSION_CALL_NOEXCEPT {
    return call_gateway(entry, entry, entry, 0, args, indirect_result);
}

TraceRunResult QbdiThreadSession::call_gateway(
        uintptr_t logical_entry, uintptr_t execution_entry,
        uintptr_t control_start, size_t execution_bytes,
        const uint64_t args[8], uint64_t indirect_result)
        QTRACE_SESSION_CALL_NOEXCEPT {
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
    TraceRunResult result = execute(logical_entry, execution_entry,
                                    control_start, execution_bytes, args,
                                    indirect_result);
    if (trace_process_child_detached()) return result;
    bool execution_observed = result.target_executed;
    QbdiNoProgressTracker no_progress;
    QbdiExecutionState execution_state{};
    bool state_available = copy_execution_state(&execution_state);
    if (state_available) (void)no_progress.observe(execution_state);
    size_t state_unavailable_attempts = 0;
    // Once QBDI has executed on its virtual stack, restarting the native entry
    // repeats side effects and returning an invented value breaks the pthread or
    // scene ABI. Exact no-progress therefore stays in control-only fail-stop and
    // yields periodically until QBDI can reach the real return/deferred exit.
    while (execution_observed &&
           !result.target_returned && !result.exit_requested) {
        if (!incomplete_) mark_coverage_gap(logical_entry);
        result = continue_execution();
        result.target_executed = result.target_executed || execution_observed;
        execution_observed = result.target_executed;
        if (trace_process_child_detached()) return result;
        bool repeated_state = false;
        if (state_available) {
            state_available = copy_execution_state(&execution_state);
            if (state_available) {
                repeated_state = no_progress.observe(execution_state);
            }
        }
        if (repeated_state ||
            (!state_available &&
             ++state_unavailable_attempts ==
                     QbdiNoProgressTracker::kRepeatedStateYieldInterval)) {
            (void)::sched_yield();
            state_unavailable_attempts = 0;
        }
    }
    vm_running_ = false;
    if (!result.target_returned && !result.exit_requested && !incomplete_) {
        mark_coverage_gap(logical_entry);
    }
    if (entered_here) leave();
    return result;
}

#if defined(QTRACE_HOST_TEST)

QbdiThreadSession *QbdiThreadSession::create_for_test(
        uint32_t tid, uint32_t module_generation,
        QbdiThreadSessionTestExecutor executor, void *executor_opaque,
        QbdiThreadSessionGapReporter gap_reporter, void *gap_opaque,
        QbdiThreadSessionLifecycleReporter lifecycle_reporter,
        void *lifecycle_opaque,
        QbdiThreadSessionTestContinuation continuation,
        QbdiControlExtentRegistration control_registration,
        QbdiVmExecutionLifecycle signal_execution) noexcept {
    if (tid == 0 || module_generation == 0 || executor == nullptr) return nullptr;
    auto *session = new (std::nothrow) QbdiThreadSession(tid, module_generation);
    if (session == nullptr) return nullptr;
    session->test_executor_ = executor;
    session->test_executor_opaque_ = executor_opaque;
    session->gap_reporter_ = gap_reporter;
    session->gap_opaque_ = gap_opaque;
    session->lifecycle_reporter_ = lifecycle_reporter;
    session->lifecycle_opaque_ = lifecycle_opaque;
    session->test_continuation_ = continuation;
    session->test_control_registration_ = control_registration;
    session->test_signal_execution_ = signal_execution;
    session->ready_ = true;
    return session;
}

TraceRunResult QbdiThreadSession::continue_execution()
        QTRACE_SESSION_CALL_NOEXCEPT {
    if (test_continuation_ == nullptr) return {};
    if (!test_signal_execution_.activate(nullptr)) return {};
    const TraceRunResult result =
            test_continuation_(test_executor_opaque_, this);
    test_signal_execution_.clear();
    return result;
}

TraceRunResult QbdiThreadSession::execute(uintptr_t, uintptr_t execution_entry,
                                          uintptr_t control_start,
                                          size_t execution_bytes,
                                          const uint64_t args[8],
                                          uint64_t indirect_result)
        QTRACE_SESSION_CALL_NOEXCEPT {
    if (test_executor_ == nullptr ||
        !ensure_control_extent(execution_entry, control_start, execution_bytes)) {
        return {};
    }
    if (!test_signal_execution_.activate(nullptr)) return {};
    const TraceRunResult result = test_executor_(
            test_executor_opaque_, this, execution_entry, control_start,
            execution_bytes, args, indirect_result);
    test_signal_execution_.clear();
    return result;
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
                                          uintptr_t control_start,
                                          size_t execution_bytes,
                                          const uint64_t args[8],
                                          uint64_t indirect_result)
        QTRACE_SESSION_CALL_NOEXCEPT {
    if (impl_ == nullptr ||
        !ensure_control_extent(execution_entry, control_start, execution_bytes)) {
        return {};
    }
    const TraceRunResult result = impl_->call(logical_entry, execution_entry,
                                              args, indirect_result);
    if (result.target_executed && !trace_process_child_detached() &&
        (impl_->sink->failed() || !impl_->gate->enabled())) {
        mark_coverage_gap(logical_entry);
    }
    return result;
}

TraceRunResult QbdiThreadSession::continue_execution()
        QTRACE_SESSION_CALL_NOEXCEPT {
    return impl_ != nullptr ? impl_->continue_control_only() : TraceRunResult{};
}

#endif

bool QbdiThreadSession::ensure_control_extent(
        uintptr_t execution_entry, uintptr_t control_start,
        size_t execution_bytes) noexcept {
    if (execution_bytes == 0) return true;
    if (control_start > UINTPTR_MAX - execution_bytes) {
#if !defined(QTRACE_HOST_TEST)
        if (impl_ != nullptr) {
            (void)impl_->fail_control_extent(QbdiControlExtentResult::Invalid);
        }
#endif
        return false;
    }
    const uintptr_t control_end = control_start + execution_bytes;
    if (execution_entry < control_start || execution_entry >= control_end) {
#if !defined(QTRACE_HOST_TEST)
        if (impl_ != nullptr) {
            (void)impl_->fail_control_extent(QbdiControlExtentResult::Invalid);
        }
#endif
        return false;
    }

#if defined(QTRACE_HOST_TEST)
    QbdiControlExtentRegistration registration = test_control_registration_;
    if (registration.add_instrumented_range == nullptr &&
        registration.add_pre_observer == nullptr) {
        registration = {nullptr, accept_test_control_extent,
                         accept_test_control_extent};
    }
#else
    if (impl_ == nullptr) return false;
    const QbdiControlExtentRegistration registration =
            impl_->control_registration();
#endif
    const QbdiControlExtentResult result = control_extents_.ensure(
            {control_start, control_end}, registration);
    if (result == QbdiControlExtentResult::Added ||
        result == QbdiControlExtentResult::AlreadyPresent) {
        return true;
    }
#if !defined(QTRACE_HOST_TEST)
    (void)impl_->fail_control_extent(result);
#endif
    return false;
}

bool QbdiThreadSession::copy_execution_state(
        QbdiExecutionState *state) const noexcept {
#if defined(QTRACE_HOST_TEST)
    (void)state;
    return false;
#else
    return impl_ != nullptr && impl_->copy_execution_state(state);
#endif
}

#undef QTRACE_SESSION_CALL_NOEXCEPT
