#include "core/capture_coordinator.h"
#include "core/qbdi_thread_session.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <sys/wait.h>
#include <unistd.h>

namespace {

void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

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
    CoverageGapReason last_gap_reason = CoverageGapReason::SessionFailure;
    std::string target;
    std::string path;
    bool session_reports_gap = false;
    bool artifact_create_fails = false;
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
                               const uint64_t[8], uint64_t) noexcept {
    auto *factory = static_cast<FakeFactory *>(opaque);
    if (factory->session_reports_gap) session->mark_coverage_gap(entry);
    return {true, 7};
}

QbdiThreadSession *create_session(void *opaque, void *, const TraceConfig &,
                                  const ModuleRange &, const SceneConfig &, uint32_t tid,
                                  uint32_t module_generation) noexcept {
    auto *factory = static_cast<FakeFactory *>(opaque);
    ++factory->session_creates;
    factory->session_module_generation = module_generation;
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

} // namespace

int main() {
    creates_one_identified_artifact_and_keeps_module_generation_stable();
    reuses_only_same_tid_and_latches_recursive_gap_and_leave();
    child_detach_never_destroys_or_marks_inherited_state();
    session_gap_latches_the_coordinator_incomplete();
    failed_artifact_start_is_permanent_and_not_retried();
}
