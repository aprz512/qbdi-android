#include "core/capture_coordinator.h"
#include "core/qbdi_thread_session.h"
#include "core/trace_generation_runtime.h"
#include "core/trace_process_lifecycle.h"

#include <array>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include "third_party/nlohmann/json.hpp"
#include <string>
#include <string_view>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace {

void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

void default_flight_path_uses_the_android_uid_user() {
    char output[1024]{};
    CHECK(capture_coordinator_test_default_flight_path(
            "com.example.capture", "libtarget.so", 10905, 17, 42,
            output, sizeof(output)));
    CHECK(std::string(output) ==
          "/data/user/0/com.example.capture/files/qbdi-traces/17_42_libtarget.so.flight.bin");
    CHECK(capture_coordinator_test_default_flight_path(
            "com.example.capture", "libtarget.so", 1010905, 17, 42,
            output, sizeof(output)));
    CHECK(std::string(output) ==
          "/data/user/10/com.example.capture/files/qbdi-traces/17_42_libtarget.so.flight.bin");
}

template <typename Predicate>
void wait_until(Predicate predicate) {
    for (size_t attempt = 0; attempt < 5000000; ++attempt) {
        if (predicate()) return;
        if ((attempt & 1023U) == 0) std::this_thread::yield();
    }
    CHECK(false);
}

struct FakeFlightWriter {
    TraceGenerationRuntime *runtime = nullptr;
    uint32_t tid = 0;
    std::atomic<bool> committed{true};
    std::atomic<bool> sealed{false};
    std::atomic<bool> fail_seal{false};
    std::atomic<bool> block_seal{false};
    std::atomic<bool> release_seal{false};
    std::atomic<size_t> seal_calls{0};
    std::atomic<pid_t> seal_tid{0};
};

struct FakeFactory {
    size_t artifact_creates = 0;
    size_t artifact_destroys = 0;
    size_t session_creates = 0;
    size_t session_destroys = 0;
    size_t coverage_gaps = 0;
    uint64_t run_id = 0;
    uint32_t pid = 0;
    uint32_t artifact_module_generation = 0;
    uint32_t session_module_generation = 0;
    uint32_t last_gap_tid = 0;
    uintptr_t last_gap_pc = 0;
    std::string session_scene;
    uintptr_t session_scene_offset = 0;
    CoverageGapReason last_gap_reason = CoverageGapReason::SessionFailure;
    std::string target;
    std::string path;
    bool session_reports_gap = false;
    bool artifact_create_fails = false;
    std::shared_ptr<TraceGenerationRuntime> runtime;
    std::array<FakeFlightWriter, 4> flight_writers{};
    std::atomic<bool> block_session_create{false};
    std::atomic<bool> session_create_entered{false};
    std::atomic<bool> release_session_create{false};
};

bool g_fail_on_child_artifact_mutation = false;

void *create_artifact(void *opaque, const char *path, const FlightOptions &,
                      const FlightArtifactIdentityView &identity) noexcept {
    auto *factory = static_cast<FakeFactory *>(opaque);
    ++factory->artifact_creates;
    factory->run_id = identity.run_id;
    factory->pid = identity.pid;
    factory->artifact_module_generation = identity.module_generation;
    factory->target.assign(identity.target_name, identity.target_name_bytes);
    factory->path = path;
    return factory->artifact_create_fails ? nullptr : factory;
}

void destroy_artifact(void *opaque, void *) noexcept {
    if (g_fail_on_child_artifact_mutation) _exit(91);
    ++static_cast<FakeFactory *>(opaque)->artifact_destroys;
}

TraceRunResult no_op_execution(void *opaque, QbdiThreadSession *session, uintptr_t entry,
                               uintptr_t, size_t,
                               const uint64_t[8], uint64_t) noexcept {
    auto *factory = static_cast<FakeFactory *>(opaque);
    if (factory->session_reports_gap) session->mark_coverage_gap(entry);
    return {true, 7};
}

QbdiExecutionResult stop_aware_execution(
        void *opaque, QbdiThreadSession *, uintptr_t, uintptr_t, size_t,
        const uint64_t[8], uint64_t) noexcept {
    auto *writer = static_cast<FakeFlightWriter *>(opaque);
    if (trace_process_child_detached() || writer->runtime == nullptr ||
        !writer->runtime->stop_token().requested()) {
        return {{true, true, writer->tid}, false, {}};
    }
    return {{true, false, writer->tid}, true,
            writer->runtime->stop_token().reason()};
}

TraceRunResult finish_control_only(void *opaque, QbdiThreadSession *) noexcept {
    const auto *writer = static_cast<FakeFlightWriter *>(opaque);
    return {true, true, writer->tid};
}

bool seal_fake_flight_writer(void *opaque, TraceStopReason) noexcept {
    auto *writer = static_cast<FakeFlightWriter *>(opaque);
    writer->seal_calls.fetch_add(1, std::memory_order_relaxed);
    writer->seal_tid.store(static_cast<pid_t>(::syscall(SYS_gettid)),
                           std::memory_order_release);
    while (writer->block_seal.load(std::memory_order_acquire) &&
           !writer->release_seal.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }
    const bool sealed = !writer->fail_seal.load(std::memory_order_acquire);
    writer->sealed.store(sealed, std::memory_order_release);
    return sealed;
}

bool fake_flight_committed(void *opaque) noexcept {
    return static_cast<FakeFlightWriter *>(opaque)->committed.load(
            std::memory_order_acquire);
}

bool fake_flight_sealed(void *opaque) noexcept {
    return static_cast<FakeFlightWriter *>(opaque)->sealed.load(
            std::memory_order_acquire);
}

std::string_view fake_flight_basename(void *) noexcept {
    return "cooperative.flight.bin";
}

QbdiThreadSession *create_session(void *opaque, void *, const TraceConfig &,
                                  const ModuleRange &, const SceneConfig &scene, uint32_t tid,
                                  uint32_t module_generation) noexcept {
    auto *factory = static_cast<FakeFactory *>(opaque);
    ++factory->session_creates;
    factory->session_module_generation = module_generation;
    factory->session_scene = scene.name;
    factory->session_scene_offset = scene.offset;
    if (factory->block_session_create.load(std::memory_order_acquire)) {
        factory->session_create_entered.store(true, std::memory_order_release);
        while (!factory->release_session_create.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
    }
    if (factory->runtime != nullptr) {
        CHECK(factory->session_creates <= factory->flight_writers.size());
        FakeFlightWriter *writer =
                &factory->flight_writers[factory->session_creates - 1U];
        writer->runtime = factory->runtime.get();
        writer->tid = tid;
        return QbdiThreadSession::create_for_test(
                tid, module_generation, stop_aware_execution, writer,
                nullptr, nullptr, nullptr, nullptr, finish_control_only,
                {}, {}, {},
                QbdiFlightWriterControl{
                        writer, seal_fake_flight_writer,
                        fake_flight_committed, fake_flight_sealed,
                        fake_flight_basename});
    }
    return QbdiThreadSession::create_for_test(tid, module_generation,
                                              no_op_execution, factory);
}

void destroy_session(void *opaque, QbdiThreadSession *session) noexcept {
    if (g_fail_on_child_artifact_mutation) _exit(92);
    ++static_cast<FakeFactory *>(opaque)->session_destroys;
    delete session;
}

void mark_gap(void *opaque, void *, uint32_t tid, uintptr_t pc,
              CoverageGapReason reason) noexcept {
    if (g_fail_on_child_artifact_mutation) _exit(93);
    auto *factory = static_cast<FakeFactory *>(opaque);
    ++factory->coverage_gaps;
    factory->last_gap_tid = tid;
    factory->last_gap_pc = pc;
    factory->last_gap_reason = reason;
}

CaptureCoordinatorFactories factories(FakeFactory *factory) {
    return {factory, create_artifact, destroy_artifact, create_session,
            destroy_session, mark_gap};
}

TraceConfig flight_config() {
    TraceConfig config = default_trace_config();
    config.package_name = "com.example.capture";
    config.target_so = "libcapture_target.so";
    config.flight.enabled = true;
    config.flight.max_threads = 4;
    config.flight.capacity_bytes = 64ULL * 1024ULL * 1024ULL;
    config.flight.chunk_bytes = 64U * 1024U;
    config.flight.protected_chunks = 1;
    config.flight.entry_scene = "init";
    config.scenes[0].offset = 0x100;
    return config;
}

ModuleRange retained_module() {
    ModuleRange module;
    module.start = 0x71000000;
    module.end = 0x71010000;
    module.path = "/data/app/libcapture_target.so";
    module.permissions = "r-xp";
    module.readable_executable_ranges[0] = {module.start, module.end};
    module.readable_executable_range_count = 1;
    return module;
}

std::shared_ptr<TraceGenerationRuntime> running_runtime(uint64_t generation) {
    SessionOptions session;
    session.id = "7d5807cf-cf09-4f21-92de-1ad92802610a";
    auto runtime = TraceGenerationRuntime::create(generation, session);
    CHECK(runtime != nullptr);
    CHECK(runtime->arm());
    return runtime;
}

FakeFlightWriter *writer_for(FakeFactory *factory, uint32_t tid) {
    for (FakeFlightWriter &writer : factory->flight_writers) {
        if (writer.tid == tid) return &writer;
    }
    return nullptr;
}

bool read_status_json(const std::string &path, nlohmann::json *status) {
    if (status == nullptr) return false;
    FILE *file = std::fopen(path.c_str(), "rb");
    if (file == nullptr) return false;
    std::array<char, 65536> bytes{};
    const size_t size = std::fread(bytes.data(), 1, bytes.size(), file);
    const bool complete = std::feof(file) != 0;
    (void)std::fclose(file);
    if (!complete || size == 0 || size == bytes.size()) return false;
    *status = nlohmann::json::parse(
            bytes.data(), bytes.data() + size, nullptr, false);
    return !status->is_discarded();
}

bool status_lists_one_artifact(const std::string &path,
                               std::string_view artifact) {
    nlohmann::json status;
    return read_status_json(path, &status) &&
           status.value("state", "") == "sealed" &&
           status.contains("artifacts") && status["artifacts"].is_array() &&
           status["artifacts"].size() == 1 &&
           status["artifacts"][0] == artifact &&
           status.contains("stopAcknowledged") &&
           status["stopAcknowledged"].is_boolean() &&
           status["stopAcknowledged"] == true;
}

bool status_reports_stop_acknowledged(const std::string &path,
                                      std::string_view state,
                                      bool acknowledged) {
    nlohmann::json status;
    return read_status_json(path, &status) &&
           status.value("state", "") == state &&
           status.contains("stopAcknowledged") &&
           status["stopAcknowledged"].is_boolean() &&
           status["stopAcknowledged"] == acknowledged;
}

bool status_has_state(const std::string &path, std::string_view state) {
    nlohmann::json status;
    return read_status_json(path, &status) && status.value("state", "") == state;
}

struct WorkerCall {
    CaptureCoordinator *coordinator = nullptr;
    const SceneConfig *scene = nullptr;
    uint32_t tid = 0;
    std::atomic<bool> entered{false};
    std::atomic<bool> invoke{false};
    std::atomic<bool> done{false};
    std::atomic<pid_t> owner_tid{0};
    QbdiThreadSession *session = nullptr;
};

void run_worker_call(WorkerCall *worker) {
    worker->owner_tid.store(static_cast<pid_t>(::syscall(SYS_gettid)),
                            std::memory_order_release);
    worker->session = worker->coordinator->enter(worker->tid, *worker->scene);
    CHECK(worker->session != nullptr);
    worker->entered.store(true, std::memory_order_release);
    while (!worker->invoke.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }
    const uint64_t args[8]{};
    const TraceRunResult result = worker->session->call(0x71000100, args, 0);
    CHECK(result.target_returned);
    worker->coordinator->leave(worker->session);
    worker->done.store(true, std::memory_order_release);
}

void creates_one_identified_artifact_and_keeps_module_generation_stable() {
    FakeFactory factory;
    CaptureCoordinator coordinator(factories(&factory));
    const TraceConfig config = flight_config();
    const ModuleRange module = retained_module();

    CHECK(coordinator.start(config, module, 47));
    CHECK(!coordinator.start(config, module, 48));
    CHECK(factory.artifact_creates == 1);
    CHECK(factory.run_id != 0);
    CHECK(factory.pid == static_cast<uint32_t>(::getpid()));
    CHECK(factory.artifact_module_generation == 47);
    CHECK(factory.target == "libcapture_target.so");
    const std::string expected_suffix =
            std::to_string(factory.run_id) + "_" + std::to_string(::getpid()) +
            "_libcapture_target.so.flight.bin";
    CHECK(std::string_view(factory.path).ends_with(expected_suffix));
    CHECK(coordinator.module_generation() == 47);
    ModuleRange module_snapshot;
    CHECK(coordinator.copy_module(&module_snapshot));
    CHECK(module_snapshot.start == module.start);
    CHECK(module_snapshot.end == module.end);
    CHECK(module_snapshot.path == module.path);
    CHECK(coordinator.matches_module(module));
    ModuleRange other_module = module;
    other_module.start += 0x20000;
    other_module.end += 0x20000;
    other_module.readable_executable_ranges[0] = {
            other_module.start, other_module.end};
    CHECK(!coordinator.matches_module(other_module));

    QbdiThreadSession *session = coordinator.enter(101, config.scenes[0]);
    CHECK(session != nullptr);
    CHECK(session->module_generation() == 47);
    CHECK(factory.session_module_generation == 47);
    coordinator.leave(session);
}

void reuses_only_same_tid_and_latches_recursive_gap_and_leave() {
    FakeFactory factory;
    CaptureCoordinator coordinator(factories(&factory));
    const TraceConfig config = flight_config();
    CHECK(coordinator.start(config, retained_module(), 9));

    QbdiThreadSession *first = coordinator.enter(111, config.scenes[0]);
    CHECK(first != nullptr);
    CHECK(current_qbdi_thread_session() == first);
    CHECK(coordinator.enter(111, config.scenes[0]) == nullptr);
    CHECK(factory.coverage_gaps == 1);
    CHECK(factory.last_gap_tid == 111);
    CHECK(factory.last_gap_pc == retained_module().start + config.scenes[0].offset);
    CHECK(coordinator.incomplete());
    coordinator.leave(first);
    coordinator.leave(first);
    CHECK(current_qbdi_thread_session() == nullptr);

    QbdiThreadSession *reused = coordinator.enter(111, config.scenes[0]);
    CHECK(reused == first);
    coordinator.leave(reused);
    QbdiThreadSession *other = coordinator.enter(222, config.scenes[0]);
    CHECK(other != nullptr);
    CHECK(other != first);
    coordinator.leave(other);
    CHECK(factory.session_creates == 2);

    coordinator.mark_coverage_gap(222, 0x71000444);
    CHECK(factory.coverage_gaps == 2);
    coordinator.mark_coverage_gap(333, 0x71000555,
                                  CoverageGapReason::HookSetup);
    CHECK(factory.coverage_gaps == 3);
    CHECK(coordinator.dropped_gap_count() == 2);
    CHECK(coordinator.incomplete());
}

void child_detach_never_destroys_or_marks_inherited_state() {
    FakeFactory factory;
    auto *coordinator = new CaptureCoordinator(factories(&factory));
    const TraceConfig config = flight_config();
    CHECK(coordinator->start(config, retained_module(), 12));
    QbdiThreadSession *session = coordinator->enter(333, config.scenes[0]);
    CHECK(session != nullptr);
    coordinator->leave(session);

    const pid_t child = ::fork();
    CHECK(child >= 0);
    if (child == 0) {
        g_fail_on_child_artifact_mutation = true;
        coordinator->detach_after_fork_child();
        coordinator->mark_coverage_gap(333, 0x71000500);
        delete coordinator;
        _exit(0);
    }
    int status = -1;
    CHECK(::waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status));
    CHECK(WEXITSTATUS(status) == 0);
    CHECK(factory.coverage_gaps == 0);
    delete coordinator;
    CHECK(factory.session_destroys == 1);
    CHECK(factory.artifact_destroys == 1);
}

void session_gap_latches_the_coordinator_incomplete() {
    FakeFactory factory;
    factory.session_reports_gap = true;
    CaptureCoordinator coordinator(factories(&factory));
    const TraceConfig config = flight_config();
    CHECK(coordinator.start(config, retained_module(), 13));
    QbdiThreadSession *session = coordinator.enter(444, config.scenes[0]);
    CHECK(session != nullptr);

    const uint64_t args[8]{};
    const TraceRunResult result = session->call(0x71000100, args, 0);
    coordinator.leave(session);

    CHECK(result.target_executed);
    CHECK(factory.coverage_gaps == 1);
    CHECK(factory.last_gap_tid == 444);
    CHECK(factory.last_gap_pc == 0x71000100);
    CHECK(coordinator.incomplete());
}

void failed_artifact_start_is_permanent_and_not_retried() {
    FakeFactory factory;
    factory.artifact_create_fails = true;
    CaptureCoordinator coordinator(factories(&factory));
    const TraceConfig config = flight_config();

    CHECK(!coordinator.start(config, retained_module(), 14));
    CHECK(!coordinator.start(config, retained_module(), 14));
    CHECK(factory.artifact_creates == 1);
    CHECK(coordinator.incomplete());
}

void thread_entry_uses_the_explicit_flight_entry_scene() {
    FakeFactory factory;
    CaptureCoordinator coordinator(factories(&factory));
    TraceConfig config = flight_config();
    config.flight.entry_scene = "boot";
    config.scenes = {
            {0, "worker", 0x100},
            {1, "boot", 0x200},
    };
    CHECK(coordinator.start(config, retained_module(), 15));

    QbdiThreadSession *session = coordinator.enter_thread(555, 0x71000200);
    CHECK(session != nullptr);
    CHECK(factory.session_scene == "boot");
    CHECK(factory.session_scene_offset == 0x200);
    coordinator.leave(session);
}

void cooperative_stop_rejects_new_entries_and_seals_on_each_owner() {
    FakeFactory factory;
    factory.runtime = running_runtime(47);
    CaptureCoordinator coordinator(factories(&factory));
    const TraceConfig config = flight_config();
    CHECK(coordinator.start(config, retained_module(), 47, factory.runtime));

    WorkerCall first{&coordinator, &config.scenes[0], 101};
    WorkerCall second{&coordinator, &config.scenes[0], 202};
    std::thread first_thread(run_worker_call, &first);
    std::thread second_thread(run_worker_call, &second);
    wait_until([&] {
        return first.entered.load(std::memory_order_acquire) &&
               second.entered.load(std::memory_order_acquire);
    });
    FakeFlightWriter *second_writer = writer_for(&factory, 202);
    CHECK(second_writer != nullptr);
    second_writer->block_seal.store(true, std::memory_order_release);

    CHECK(coordinator.request_stop(TraceStopReason::DurationElapsed));
    CHECK(coordinator.enter(303, config.scenes[0]) == nullptr);
    first.invoke.store(true, std::memory_order_release);
    second.invoke.store(true, std::memory_order_release);
    wait_until([&] {
        return first.done.load(std::memory_order_acquire) &&
               second_writer->seal_calls.load(std::memory_order_acquire) == 1;
    });
    CHECK(factory.runtime->snapshot().phase == TraceGenerationPhase::Stopping);
    CHECK(factory.runtime->snapshot().active_calls == 1);
    CHECK(coordinator.request_stop(TraceStopReason::DurationElapsed));

    second_writer->release_seal.store(true, std::memory_order_release);
    first_thread.join();
    second_thread.join();
    CHECK(factory.runtime->snapshot().phase == TraceGenerationPhase::Sealed);
    CHECK(factory.runtime->snapshot().active_calls == 0);
    FakeFlightWriter *first_writer = writer_for(&factory, 101);
    CHECK(first_writer != nullptr);
    CHECK(first_writer->seal_calls.load(std::memory_order_acquire) == 1);
    CHECK(second_writer->seal_calls.load(std::memory_order_acquire) == 1);
    CHECK(first_writer->seal_tid.load(std::memory_order_acquire) ==
          first.owner_tid.load(std::memory_order_acquire));
    CHECK(second_writer->seal_tid.load(std::memory_order_acquire) ==
          second.owner_tid.load(std::memory_order_acquire));
}

void owning_thread_seal_failure_finishes_stop_incomplete() {
    FakeFactory factory;
    factory.runtime = running_runtime(51);
    CaptureCoordinator coordinator(factories(&factory));
    const TraceConfig config = flight_config();
    CHECK(coordinator.start(config, retained_module(), 51, factory.runtime));

    WorkerCall worker{&coordinator, &config.scenes[0], 202};
    std::thread thread(run_worker_call, &worker);
    wait_until([&] { return worker.entered.load(std::memory_order_acquire); });
    FakeFlightWriter *writer = writer_for(&factory, 202);
    CHECK(writer != nullptr);
    writer->fail_seal.store(true, std::memory_order_release);
    CHECK(coordinator.request_stop(TraceStopReason::DurationElapsed));
    worker.invoke.store(true, std::memory_order_release);
    thread.join();

    CHECK(writer->seal_calls.load(std::memory_order_acquire) == 1);
    CHECK(!writer->sealed.load(std::memory_order_acquire));
    CHECK(factory.runtime->snapshot().phase ==
          TraceGenerationPhase::StopIncomplete);
    CHECK(coordinator.incomplete());
}

void missing_ack_is_reported_without_touching_the_live_writer() {
    FakeFactory factory;
    factory.runtime = running_runtime(52);
    CaptureCoordinator coordinator(factories(&factory));
    const TraceConfig config = flight_config();
    CHECK(coordinator.start(config, retained_module(), 52, factory.runtime));

    WorkerCall acknowledged{&coordinator, &config.scenes[0], 101};
    WorkerCall missing{&coordinator, &config.scenes[0], 202};
    std::thread acknowledged_thread(run_worker_call, &acknowledged);
    std::thread missing_thread(run_worker_call, &missing);
    wait_until([&] {
        return acknowledged.entered.load(std::memory_order_acquire) &&
               missing.entered.load(std::memory_order_acquire);
    });
    CHECK(coordinator.request_stop(TraceStopReason::DurationElapsed));
    acknowledged.invoke.store(true, std::memory_order_release);
    acknowledged_thread.join();
    CHECK(factory.runtime->snapshot().phase == TraceGenerationPhase::Stopping);

    FakeFlightWriter *live_writer = writer_for(&factory, 202);
    CHECK(live_writer != nullptr);
    CHECK(live_writer->committed.load(std::memory_order_acquire));
    CHECK(live_writer->seal_calls.load(std::memory_order_acquire) == 0);
    CHECK(coordinator.report_stop_incomplete());
    CHECK(factory.runtime->snapshot().phase ==
          TraceGenerationPhase::StopIncomplete);
    CHECK(factory.runtime->snapshot().active_calls == 0);
    CHECK(factory.session_destroys == 0);
    CHECK(factory.artifact_destroys == 0);
    CHECK(live_writer->seal_calls.load(std::memory_order_acquire) == 0);
    CHECK(live_writer->committed.load(std::memory_order_acquire));

    missing.invoke.store(true, std::memory_order_release);
    missing_thread.join();
    CHECK(live_writer->seal_calls.load(std::memory_order_acquire) == 1);
    CHECK(factory.runtime->snapshot().phase ==
          TraceGenerationPhase::StopIncomplete);
    CHECK(!coordinator.report_stop_incomplete());
}

// Catches a failed first enter leaving a persistent slot whose generation
// admission was already retired. Reusing that slot would let stop become
// Sealed before the live owner acknowledges it.
void first_enter_tls_conflict_rolls_back_slot_and_exact_admission() {
    FakeFactory factory;
    factory.runtime = running_runtime(56);
    CaptureCoordinator coordinator(factories(&factory));
    const TraceConfig config = flight_config();
    CHECK(coordinator.start(config, retained_module(), 56, factory.runtime));

    QbdiThreadSession *old_generation = QbdiThreadSession::create_for_test(
            101, 55, no_op_execution, &factory);
    CHECK(old_generation != nullptr);
    CHECK(old_generation->try_enter());

    CHECK(coordinator.enter(101, config.scenes[0]) == nullptr);
    CHECK(factory.session_creates == 1);
    CHECK(factory.session_destroys == 1);
    CHECK(factory.coverage_gaps == 1);
    CHECK(factory.runtime->snapshot().active_calls == 0);

    old_generation->leave();
    delete old_generation;
    QbdiThreadSession *replacement = coordinator.enter(101, config.scenes[0]);
    CHECK(replacement != nullptr);
    CHECK(factory.session_creates == 2);
    CHECK(factory.session_destroys == 1);
    CHECK(factory.runtime->snapshot().active_calls == 1);

    CHECK(coordinator.request_stop(TraceStopReason::DurationElapsed));
    CHECK(factory.runtime->snapshot().phase ==
          TraceGenerationPhase::StopRequested);
    const uint64_t args[8]{};
    CHECK(replacement->call(0x71000100, args, 0).target_returned);
    CHECK(factory.runtime->snapshot().phase == TraceGenerationPhase::Sealed);
    CHECK(factory.runtime->snapshot().active_calls == 0);
    coordinator.leave(replacement);
}

void stop_and_slot_creation_have_one_mutex_linearization_order() {
    FakeFactory factory;
    factory.runtime = running_runtime(53);
    factory.block_session_create.store(true, std::memory_order_release);
    CaptureCoordinator coordinator(factories(&factory));
    const TraceConfig config = flight_config();
    CHECK(coordinator.start(config, retained_module(), 53, factory.runtime));

    WorkerCall worker{&coordinator, &config.scenes[0], 101};
    std::thread owner(run_worker_call, &worker);
    wait_until([&] {
        return factory.session_create_entered.load(std::memory_order_acquire);
    });
    std::atomic<bool> stop_returned{false};
    std::thread stopper([&] {
        CHECK(coordinator.request_stop(TraceStopReason::DurationElapsed));
        stop_returned.store(true, std::memory_order_release);
    });
    CHECK(!stop_returned.load(std::memory_order_acquire));
    factory.release_session_create.store(true, std::memory_order_release);
    wait_until([&] { return worker.entered.load(std::memory_order_acquire); });
    stopper.join();
    CHECK(stop_returned.load(std::memory_order_acquire));
    CHECK(coordinator.enter(303, config.scenes[0]) == nullptr);
    worker.invoke.store(true, std::memory_order_release);
    owner.join();
    CHECK(factory.runtime->snapshot().phase == TraceGenerationPhase::Sealed);
}

void fork_child_never_seals_or_acknowledges_inherited_slots() {
    CHECK(install_trace_process_lifecycle());
    FakeFactory factory;
    factory.runtime = running_runtime(54);
    auto coordinator = std::make_shared<CaptureCoordinator>(factories(&factory));
    const TraceConfig config = flight_config();
    CHECK(coordinator->start(config, retained_module(), 54, factory.runtime));
    QbdiThreadSession *session = coordinator->enter(101, config.scenes[0]);
    CHECK(session != nullptr);
    FakeFlightWriter *writer = writer_for(&factory, 101);
    CHECK(writer != nullptr);
    CHECK(coordinator->request_stop(TraceStopReason::DurationElapsed));

    const pid_t child = ::fork();
    CHECK(child >= 0);
    if (child == 0) {
        coordinator->detach_after_fork_child();
        const uint64_t args[8]{};
        (void)session->call(0x71000100, args, 0);
        if (writer->seal_calls.load(std::memory_order_acquire) != 0) _exit(81);
        if (factory.runtime->snapshot().active_calls != 1) _exit(82);
        _exit(0);
    }
    int status = -1;
    CHECK(::waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status));
    CHECK(WEXITSTATUS(status) == 0);
    CHECK(writer->seal_calls.load(std::memory_order_acquire) == 0);

    const uint64_t args[8]{};
    CHECK(session->call(0x71000100, args, 0).target_returned);
    coordinator->leave(session);
    CHECK(factory.runtime->snapshot().phase == TraceGenerationPhase::Sealed);
}

void committed_flight_artifact_is_published_once_to_session_status() {
    char directory_template[] = "/tmp/qtrace-flight-status-XXXXXX";
    char *created = ::mkdtemp(directory_template);
    CHECK(created != nullptr);
    const std::string directory = created;
    const std::string session_id =
            "7d5807cf-cf09-4f21-92de-1ad92802610a";
    const std::string status_path = directory + "/session-" + session_id +
                                    ".status.json";
    {
        TraceConfig config = flight_config();
        config.session.id = session_id;
        TraceGenerationStatusOptions status_options;
        status_options.config = config;
        status_options.output_directory = directory;
        FakeFactory factory;
        factory.runtime = TraceGenerationRuntime::create(
                55, config.session,
                TraceGenerationLimits{config.scenes.size(),
                                      config.flight.max_threads},
                {}, std::move(status_options));
        CHECK(factory.runtime != nullptr);
        CHECK(factory.runtime->arm());
        CaptureCoordinator coordinator(factories(&factory));
        CHECK(coordinator.start(config, retained_module(), 55,
                                factory.runtime));

        WorkerCall first{&coordinator, &config.scenes[0], 101};
        WorkerCall second{&coordinator, &config.scenes[0], 202};
        std::thread first_thread(run_worker_call, &first);
        std::thread second_thread(run_worker_call, &second);
        wait_until([&] {
            return first.entered.load(std::memory_order_acquire) &&
                   second.entered.load(std::memory_order_acquire);
        });
        CHECK(coordinator.request_stop(TraceStopReason::DurationElapsed));
        first.invoke.store(true, std::memory_order_release);
        second.invoke.store(true, std::memory_order_release);
        first_thread.join();
        second_thread.join();
        wait_until([&] {
            return status_lists_one_artifact(
                    status_path, "cooperative.flight.bin");
        });
    }
    CHECK(::unlink(status_path.c_str()) == 0);
    const std::string commit_path = status_path + ".commit";
    CHECK(::unlink(commit_path.c_str()) == 0);
    CHECK(::rmdir(directory.c_str()) == 0);
}

// Catches StopIncomplete being serialized as if every target owner had sealed
// and acknowledged its current Flight chunk.
void missing_ack_status_json_reports_stop_not_acknowledged() {
    char directory_template[] = "/tmp/qtrace-flight-incomplete-status-XXXXXX";
    char *created = ::mkdtemp(directory_template);
    CHECK(created != nullptr);
    const std::string directory = created;
    const std::string session_id =
            "7d5807cf-cf09-4f21-92de-1ad92802610a";
    const std::string status_path = directory + "/session-" + session_id +
                                    ".status.json";
    {
        TraceConfig config = flight_config();
        config.session.id = session_id;
        TraceGenerationStatusOptions status_options;
        status_options.config = config;
        status_options.output_directory = directory;
        FakeFactory factory;
        factory.runtime = TraceGenerationRuntime::create(
                57, config.session,
                TraceGenerationLimits{config.scenes.size(),
                                      config.flight.max_threads},
                {}, std::move(status_options));
        CHECK(factory.runtime != nullptr);
        CHECK(factory.runtime->arm());
        CaptureCoordinator coordinator(factories(&factory));
        CHECK(coordinator.start(config, retained_module(), 57,
                                factory.runtime));

        WorkerCall missing{&coordinator, &config.scenes[0], 202};
        std::thread missing_thread(run_worker_call, &missing);
        wait_until([&] { return missing.entered.load(std::memory_order_acquire); });
        CHECK(coordinator.request_stop(TraceStopReason::DurationElapsed));
        CHECK(coordinator.report_stop_incomplete());
        CHECK(factory.runtime->snapshot().phase ==
              TraceGenerationPhase::StopIncomplete);
        wait_until([&] {
            return status_has_state(status_path, "stop_incomplete");
        });
        CHECK(status_reports_stop_acknowledged(
                status_path, "stop_incomplete", false));

        missing.invoke.store(true, std::memory_order_release);
        missing_thread.join();
        CHECK(factory.runtime->snapshot().phase ==
              TraceGenerationPhase::StopIncomplete);
    }
    CHECK(::unlink(status_path.c_str()) == 0);
    const std::string commit_path = status_path + ".commit";
    CHECK(::unlink(commit_path.c_str()) == 0);
    CHECK(::rmdir(directory.c_str()) == 0);
}

} // namespace

int main() {
    default_flight_path_uses_the_android_uid_user();
    creates_one_identified_artifact_and_keeps_module_generation_stable();
    reuses_only_same_tid_and_latches_recursive_gap_and_leave();
    child_detach_never_destroys_or_marks_inherited_state();
    session_gap_latches_the_coordinator_incomplete();
    failed_artifact_start_is_permanent_and_not_retried();
    thread_entry_uses_the_explicit_flight_entry_scene();
    cooperative_stop_rejects_new_entries_and_seals_on_each_owner();
    owning_thread_seal_failure_finishes_stop_incomplete();
    missing_ack_is_reported_without_touching_the_live_writer();
    missing_ack_status_json_reports_stop_not_acknowledged();
    first_enter_tls_conflict_rolls_back_slot_and_exact_admission();
    stop_and_slot_creation_have_one_mutex_linearization_order();
    fork_child_never_seals_or_acknowledges_inherited_slots();
    committed_flight_artifact_is_published_once_to_session_status();
}
