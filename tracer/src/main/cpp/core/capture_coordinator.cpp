#include "core/capture_coordinator.h"

#include "core/qbdi_thread_session.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <new>
#include <string>
#include <string_view>
#include <utility>
#include <unistd.h>

#if !defined(QTRACE_HOST_TEST)
#include "core/trace_process_lifecycle.h"
#include "flight/flight_artifact.h"

#include <cerrno>
#include <sys/stat.h>
#endif

namespace {

std::atomic<uint64_t> g_capture_run_sequence{1};

uint64_t next_run_id() noexcept {
    const uint64_t sequence =
            g_capture_run_sequence.fetch_add(1, std::memory_order_relaxed);
    const uint64_t ticks = static_cast<uint64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count());
    const uint64_t mixed = ticks ^ (static_cast<uint64_t>(::getpid()) << 32U) ^ sequence;
    return mixed == 0 ? sequence : mixed;
}

bool factories_valid(const CaptureCoordinatorFactories &factories) noexcept {
    return factories.create_artifact != nullptr &&
           factories.destroy_artifact != nullptr &&
           factories.create_session != nullptr &&
           factories.destroy_session != nullptr &&
           factories.mark_coverage_gap != nullptr;
}

bool same_module_generation(const ModuleRange &left,
                            const ModuleRange &right) noexcept {
    if (left.readable_executable_range_count >
                left.readable_executable_ranges.size() ||
        right.readable_executable_range_count >
                right.readable_executable_ranges.size()) {
        return false;
    }
    if (left.start != right.start || left.end != right.end ||
        left.file_offset != right.file_offset || left.path != right.path ||
        left.permissions != right.permissions ||
        left.readable_executable_range_count !=
                right.readable_executable_range_count) {
        return false;
    }
    for (size_t index = 0; index < left.readable_executable_range_count;
         ++index) {
        if (left.readable_executable_ranges[index].start !=
                    right.readable_executable_ranges[index].start ||
            left.readable_executable_ranges[index].end !=
                    right.readable_executable_ranges[index].end) {
            return false;
        }
    }
    return true;
}

std::string_view basename_view(std::string_view path) noexcept {
    const size_t slash = path.find_last_of('/');
    return slash == std::string_view::npos ? path : path.substr(slash + 1U);
}

#if !defined(QTRACE_HOST_TEST)
struct ProductionArtifact {
    FlightArtifact artifact;
    uint32_t global_emergency_slot = 0;
    size_t fd_registry_slot = kInvalidTraceWriterFdSlot;
    int registered_fd = -1;
};

bool mkdirs(char *path) noexcept {
    if (path == nullptr || path[0] == '\0') return false;
    for (char *cursor = path + 1; *cursor != '\0'; ++cursor) {
        if (*cursor != '/') continue;
        *cursor = '\0';
        if (::mkdir(path, 0755) != 0 && errno != EEXIST) {
            *cursor = '/';
            return false;
        }
        *cursor = '/';
    }
    return ::mkdir(path, 0755) == 0 || errno == EEXIST;
}

void *create_production_artifact(
        void *, const char *path, const FlightOptions &options,
        const FlightArtifactIdentityView &identity) noexcept {
    if (path == nullptr) return nullptr;
    char directory[4096];
    const size_t length = std::strlen(path);
    if (length >= sizeof(directory)) return nullptr;
    std::memcpy(directory, path, length + 1U);
    char *slash = std::strrchr(directory, '/');
    if (slash == nullptr || slash == directory) return nullptr;
    *slash = '\0';
    if (!mkdirs(directory)) return nullptr;

    auto *artifact = new (std::nothrow) ProductionArtifact();
    if (artifact == nullptr) return nullptr;
    artifact->global_emergency_slot = options.max_threads;
    if (!artifact->artifact.create(path, options, identity)) {
        delete artifact;
        return nullptr;
    }
    artifact->registered_fd = artifact->artifact.fd();
    trace_writer_fd_registry_lock();
    artifact->fd_registry_slot =
            trace_writer_fd_register_locked(artifact->registered_fd);
    trace_writer_fd_registry_unlock();
    if (artifact->fd_registry_slot == kInvalidTraceWriterFdSlot) {
        artifact->artifact.mark_incomplete(FlightIncompleteReason::WriterFailure);
        delete artifact;
        return nullptr;
    }
    return artifact;
}

void destroy_production_artifact(void *, void *opaque) noexcept {
    auto *artifact = static_cast<ProductionArtifact *>(opaque);
    if (artifact == nullptr) return;
    trace_writer_fd_registry_lock();
    trace_writer_fd_unregister_locked(artifact->fd_registry_slot,
                                      artifact->registered_fd);
    trace_writer_fd_registry_unlock();
    delete artifact;
}

QbdiThreadSession *create_production_session(
        void *, void *opaque, const TraceConfig &config,
        const ModuleRange &module, const SceneConfig &scene, uint32_t tid,
        uint32_t module_generation) noexcept {
    auto *artifact = static_cast<ProductionArtifact *>(opaque);
    if (artifact == nullptr) return nullptr;
    return QbdiThreadSession::create_flight(
            config, module, scene, tid, module_generation,
            &artifact->artifact);
}

void destroy_production_session(void *, QbdiThreadSession *session) noexcept {
    delete session;
}

void mark_production_gap(void *, void *opaque, uint32_t tid,
                         uintptr_t pc, CoverageGapReason reason) noexcept {
    auto *artifact = static_cast<ProductionArtifact *>(opaque);
    if (artifact == nullptr) return;
    artifact->artifact.mark_incomplete(FlightIncompleteReason::WriterFailure);
    FlightEmergencyRecord record{};
    record.type = static_cast<uint32_t>(FlightRecordType::CoverageGap);
    record.tid = tid;
    record.sequence = artifact->artifact.next_sequence();
    record.pc = pc;
    record.flags = static_cast<uint32_t>(reason);
    (void)artifact->artifact.write_emergency(
            artifact->global_emergency_slot, record);
}

CaptureCoordinatorFactories production_factories() noexcept {
    return {nullptr, create_production_artifact, destroy_production_artifact,
            create_production_session, destroy_production_session,
            mark_production_gap};
}
#endif

} // namespace

CaptureCoordinator::CaptureCoordinator(CaptureCoordinatorFactories factories) noexcept
        : factories_(factories) {
#if !defined(QTRACE_HOST_TEST)
    if (!factories_valid(factories_)) factories_ = production_factories();
#endif
}

CaptureCoordinator::~CaptureCoordinator() {
    if (detached()) return;
    if (slots_ != nullptr) {
        for (size_t index = 0; index < slot_count_; ++index) {
            if (slots_[index].session != nullptr) {
                factories_.destroy_session(factories_.opaque,
                                           slots_[index].session);
            }
        }
        delete[] slots_;
    }
    if (artifact_ != nullptr) {
        factories_.destroy_artifact(factories_.opaque, artifact_);
    }
}

bool CaptureCoordinator::start(TraceConfig config, ModuleRange module,
                               uint32_t module_generation) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (started_.load(std::memory_order_relaxed) || start_attempted_ || detached() ||
        !factories_valid(factories_) ||
        !config.flight.enabled || config.flight.max_threads == 0 ||
        module_generation == 0 || module.start >= module.end) {
        return false;
    }
    start_attempted_ = true;

    const std::string_view target = basename_view(config.target_so);
    if (target.empty() || target.size() > kFlightTargetNameBytes) {
        incomplete_.store(true, std::memory_order_release);
        return false;
    }
    auto *slots = new (std::nothrow) ThreadSlot[config.flight.max_threads];
    if (slots == nullptr) {
        incomplete_.store(true, std::memory_order_release);
        return false;
    }

    const uint64_t run_id = next_run_id();
    const uint32_t pid = static_cast<uint32_t>(::getpid());
    char path[4096];
    const int count = std::snprintf(
            path, sizeof(path), "/data/data/%s/files/qbdi-traces/%llu_%u_%.*s.flight.bin",
            config.package_name.c_str(), static_cast<unsigned long long>(run_id), pid,
            static_cast<int>(target.size()), target.data());
    if (count < 0 || static_cast<size_t>(count) >= sizeof(path)) {
        delete[] slots;
        incomplete_.store(true, std::memory_order_release);
        return false;
    }
    const FlightArtifactIdentityView identity{
            run_id, pid, module_generation, target.data(),
            static_cast<uint16_t>(target.size())};
    void *artifact = factories_.create_artifact(
            factories_.opaque, path, config.flight, identity);
    if (artifact == nullptr) {
        delete[] slots;
        incomplete_.store(true, std::memory_order_release);
        return false;
    }

    config_ = std::move(config);
    module_ = std::move(module);
    slots_ = slots;
    artifact_ = artifact;
    slot_count_ = config_.flight.max_threads;
    run_id_.store(run_id, std::memory_order_relaxed);
    module_generation_.store(module_generation, std::memory_order_relaxed);
    started_.store(true, std::memory_order_release);
    return true;
}

bool CaptureCoordinator::copy_module(ModuleRange *module) const {
    if (module == nullptr) return false;
    std::lock_guard<std::mutex> guard(mutex_);
    if (!started_.load(std::memory_order_relaxed)) return false;
    *module = module_;
    return true;
}

bool CaptureCoordinator::matches_module(const ModuleRange &module) const noexcept {
    std::lock_guard<std::mutex> guard(mutex_);
    return started_.load(std::memory_order_relaxed) &&
           same_module_generation(module_, module);
}

CaptureCoordinator::ThreadSlot *CaptureCoordinator::find_slot_locked(
        uint32_t tid) noexcept {
    if (tid == 0 || slots_ == nullptr) return nullptr;
    for (size_t index = 0; index < slot_count_; ++index) {
        if (slots_[index].tid == tid) return &slots_[index];
    }
    return nullptr;
}

void CaptureCoordinator::mark_coverage_gap_locked(uint32_t tid,
                                                  uintptr_t pc,
                                                  CoverageGapReason reason) noexcept {
    incomplete_.store(true, std::memory_order_release);
    factories_.mark_coverage_gap(factories_.opaque, artifact_, tid, pc, reason);
}

void CaptureCoordinator::report_session_gap(void *opaque, uint32_t tid,
                                            uintptr_t pc) noexcept {
    if (opaque == nullptr) return;
    static_cast<CaptureCoordinator *>(opaque)->mark_coverage_gap(
            tid, pc, CoverageGapReason::SessionFailure);
}

QbdiThreadSession *CaptureCoordinator::enter(uint32_t tid,
                                             const SceneConfig &scene) noexcept {
    if (detached()) return nullptr;
    std::lock_guard<std::mutex> guard(mutex_);
    if (!started_.load(std::memory_order_relaxed) || detached() || tid == 0) {
        return nullptr;
    }
    uintptr_t pc = 0;
    (void)module_offset_address(module_, scene.offset, false, &pc);
    if (scene.index >= config_.scenes.size()) {
        mark_coverage_gap_locked(tid, pc, CoverageGapReason::SessionFailure);
        return nullptr;
    }
    const SceneConfig &retained_scene = config_.scenes[scene.index];
    if (retained_scene.offset != scene.offset ||
        retained_scene.end_offset != scene.end_offset) {
        mark_coverage_gap_locked(tid, pc, CoverageGapReason::SessionFailure);
        return nullptr;
    }

    ThreadSlot *slot = find_slot_locked(tid);
    if (slot != nullptr) {
        if (!slot->session->try_enter()) {
            mark_coverage_gap_locked(tid, pc, CoverageGapReason::SessionFailure);
            return nullptr;
        }
        return slot->session;
    }

    for (size_t index = 0; index < slot_count_; ++index) {
        if (slots_[index].tid != 0) continue;
        QbdiThreadSession *session = factories_.create_session(
                factories_.opaque, artifact_, config_, module_, retained_scene, tid,
                module_generation_.load(std::memory_order_relaxed));
        if (session == nullptr || !session->ready()) {
            if (session != nullptr) {
                factories_.destroy_session(factories_.opaque, session);
            }
            mark_coverage_gap_locked(tid, pc, CoverageGapReason::SessionFailure);
            return nullptr;
        }
        session->set_gap_reporter(report_session_gap, this);
        slots_[index].tid = tid;
        slots_[index].session = session;
        if (!session->try_enter()) {
            mark_coverage_gap_locked(tid, pc, CoverageGapReason::SessionFailure);
            return nullptr;
        }
        return session;
    }
    mark_coverage_gap_locked(tid, pc, CoverageGapReason::SessionFailure);
    return nullptr;
}

void CaptureCoordinator::leave(QbdiThreadSession *session) noexcept {
    if (detached() || session == nullptr) return;
    std::lock_guard<std::mutex> guard(mutex_);
    if (detached()) return;
    for (size_t index = 0; index < slot_count_; ++index) {
        if (slots_[index].session != session) continue;
        session->leave();
        return;
    }
}

void CaptureCoordinator::mark_coverage_gap(uint32_t tid, uintptr_t pc,
                                           CoverageGapReason reason) noexcept {
    if (detached()) return;
    std::lock_guard<std::mutex> guard(mutex_);
    if (!started_.load(std::memory_order_relaxed) || detached()) return;
    mark_coverage_gap_locked(tid, pc, reason);
}

void CaptureCoordinator::detach_after_fork_child() noexcept {
    detached_.store(true, std::memory_order_release);
}
