#pragma once

#include "core/module_maps.h"
#include "core/trace_config.h"

#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

constexpr int32_t QTRACE_JSON_OK = 0;
constexpr int32_t QTRACE_JSON_RESPONSE_TOO_SMALL = 1;
constexpr int32_t QTRACE_JSON_INVALID_ARGUMENT = 2;

struct ConfigurationIssue {
    std::string code;
    std::string path;
    std::string message;
};

struct PreparedConfiguration {
    TraceConfig config;
    ConfigurationIssue error;

    bool accepted() const noexcept { return error.code.empty(); }
};

enum class ConfigurationState {
    WaitingForModule,
    Installing,
    Installed,
    HookFailed,
    RollbackFailed,
    Superseded,
};

enum class SceneConfigurationState {
    Pending,
    Installing,
    Installed,
    HookFailed,
    RolledBack,
    RollbackFailed,
};

struct SceneConfigurationStatus {
    std::string name;
    uintptr_t offset = 0;
    uintptr_t runtime_address = 0;
    uintptr_t runtime_end = 0;
    SceneConfigurationState state = SceneConfigurationState::Pending;
    std::vector<ConfigurationIssue> warnings;
    std::string error_code;
    int hook_error = 0;
};

struct JsonCallResult {
    int32_t transport_code = 0;
    uint64_t required_size = 0;
    std::string payload;
};

class TracerConfiguration {
public:
    JsonCallResult configure(std::string_view request,
                             uint64_t response_capacity);
    JsonCallResult status(uint64_t generation,
                          uint64_t response_capacity) const;
    bool current(uint64_t *generation, TraceConfig *config) const;
    void mark_installing(uint64_t generation,
                         const ModuleRange &module,
                         const std::vector<SceneAddressDiagnostics> &diagnostics);
    void finish_install(uint64_t generation,
                        ConfigurationState state,
                        std::vector<SceneConfigurationStatus> scenes);

private:
    struct GenerationSnapshot {
        uint64_t generation = 0;
        TraceConfig config;
        ConfigurationState state = ConfigurationState::WaitingForModule;
        ModuleRange module;
        bool has_module = false;
        std::vector<SceneConfigurationStatus> scenes;
    };

    mutable std::mutex mutex_;
    uint64_t next_generation_ = 1;
    std::vector<GenerationSnapshot> generations_;
};

PreparedConfiguration prepare_tracer_configuration(std::string_view request);
std::string serialize_configure_rejection(const ConfigurationIssue &issue);
