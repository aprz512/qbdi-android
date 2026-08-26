#pragma once

#include "core/trace_config.h"
#include "core/tracer_configuration.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

struct ResolvedSceneStatus {
    std::string name;
    uint64_t start_offset = 0;
    uint64_t end_offset = 0;
};

struct SessionActiveScene {
    size_t scene_index = 0;
    uint32_t tid = 0;
    bool sealed = false;
};

struct SessionStatusSnapshot {
    uint32_t schema_version = 1;
    std::string session_id;
    uint64_t generation = 0;
    std::string package;
    uint32_t pid = 0;
    std::string state;
    std::string reason;
    uint64_t transition_monotonic_ns = 0;
    std::vector<ResolvedSceneStatus> normalized_scenes;
    std::vector<SessionActiveScene> active_scenes;
    std::vector<std::string> artifacts;
    bool stop_acknowledged = false;
    std::vector<ConfigurationIssue> warnings;
    std::vector<ConfigurationIssue> errors;
};

#if defined(QTRACE_HOST_TEST)
enum class SessionStatusFaultPoint : uint8_t {
    None,
    PartialWrite,
    FileFsync,
    Rename,
    DirectoryFsync,
    RollbackRename,
    RollbackUnlink,
    RollbackDirFsync,
    MarkerFileFsync,
    MarkerPrepareDirFsync,
    MarkerCommitRename,
    MarkerCommitDirFsync,
    MarkerCleanupUnlink,
    MarkerCleanupDirFsync,
    MarkerRecreateOpen,
    MarkerRecreateFileFsync,
    BackupPrepareDirFsync,
    BackupCleanupDirFsync,
};

void session_status_test_inject_fault(SessionStatusFaultPoint point, int error) noexcept;
void session_status_test_inject_followup_fault(SessionStatusFaultPoint point, int error) noexcept;
#endif

bool session_status_artifact_basename_is_valid(std::string_view value) noexcept;
bool session_status_string_is_valid_utf8(std::string_view value) noexcept;

class SessionStatusPublisher final {
public:
    bool open(const TraceConfig &, uint64_t generation,
              std::string_view output_directory = {}) noexcept;
    bool publish(const SessionStatusSnapshot &) noexcept;
    std::string_view path() const noexcept;
    int error_code() const noexcept;
    int recovery_error() const noexcept;
    std::string_view backup_path() const noexcept;

private:
    static constexpr size_t kPathCapacity = 4096;

    void record_error(int error) noexcept;
    void record_recovery_error(int error) noexcept;
    bool recover_pending_transaction() noexcept;

    char output_directory_[kPathCapacity]{};
    char path_[kPathCapacity]{};
    char backup_path_[kPathCapacity]{};
    char restore_path_[kPathCapacity]{};
    char rollback_path_[kPathCapacity]{};
    char commit_path_[kPathCapacity]{};
    char package_[513]{};
    char session_id_[37]{};
    uint64_t generation_ = 0;
    size_t path_size_ = 0;
    size_t backup_path_size_ = 0;
    int first_error_ = 0;
    int recovery_error_ = 0;
    bool opened_ = false;
};
