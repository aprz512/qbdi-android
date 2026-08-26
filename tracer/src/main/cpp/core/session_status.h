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
};

void session_status_test_inject_fault(SessionStatusFaultPoint point, int error) noexcept;
#endif

class SessionStatusPublisher final {
public:
    bool open(const TraceConfig &, uint64_t generation,
              std::string_view output_directory = {}) noexcept;
    bool publish(const SessionStatusSnapshot &) noexcept;
    std::string_view path() const noexcept;
    int error_code() const noexcept;

private:
    static constexpr size_t kPathCapacity = 4096;

    void record_error(int error) noexcept;

    char output_directory_[kPathCapacity]{};
    char path_[kPathCapacity]{};
    char backup_path_[kPathCapacity]{};
    char package_[513]{};
    char session_id_[37]{};
    uint64_t generation_ = 0;
    size_t path_size_ = 0;
    int first_error_ = 0;
    bool opened_ = false;
};
