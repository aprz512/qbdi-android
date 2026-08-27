#include "core/capture_coordinator.h"
#include "core/module_maps.h"
#include "core/native_fallback_arm64.h"
#include "core/qbdi_runner.h"
#include "core/qbdi_thread_session.h"
#include "core/trace_process_lifecycle.h"
#include "core/trace_config.h"
#include "core/tracer_configuration.h"
#include "handlers/call_handlers.h"
#include "hooks/inline_hook_adapter.h"
#include "hooks/thread_create_gateway.h"
#include "third_party/nlohmann/json.hpp"

#include <atomic>
#include <condition_variable>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <chrono>
#include <cerrno>
#include <climits>
#include <fcntl.h>
#include <fstream>
#include <mutex>
#include <new>
#include <memory>
#include <link.h>
#include <spawn.h>
#include <string>
#include <thread>
#include <sys/wait.h>
#include <unistd.h>

extern "C" uint64_t trace_proxy_dispatch(size_t index, const uint64_t args[8],
                                          uint64_t indirect_result);
extern "C" int32_t qbdi_tracer_configure_json(
        const char *, uint64_t, char *, uint64_t, uint64_t *);
extern "C" int32_t qbdi_tracer_get_status_json(
        uint64_t, char *, uint64_t, uint64_t *);
extern "C" void qbdi_tracer_install_module(
        const char *, uintptr_t, uintptr_t);
extern "C" void qbdi_tracer_configure(const char *) __attribute__((weak));
extern "C" {
char trace_proxy_stubs[32768]{};
}

using RegistrationGate = void (*)();
void trace_proxy_test_reset(const TraceConfig &config);
bool trace_proxy_test_update(const TraceConfig &config, const SceneConfig &scene,
                             const ModuleRange &module);
bool trace_proxy_test_repeat_current_install(const SceneConfig &scene,
                                             const ModuleRange &module);
void trace_proxy_test_set_registration_gate(RegistrationGate gate);
void trace_proxy_test_set_atfork_prepare_gate(RegistrationGate gate);
void trace_proxy_test_set_stub_entry_gate(RegistrationGate gate);
void trace_proxy_test_set_installed_status_gate(RegistrationGate gate);
void trace_proxy_test_set_hook_commit_gate(RegistrationGate gate);
void trace_proxy_test_set_registry_transition_gate(RegistrationGate gate);
void trace_proxy_test_set_status_output_directory(const char *directory);
size_t trace_proxy_test_generation(size_t scene_index);
void trace_proxy_test_set_coordinator(
        const std::shared_ptr<CaptureCoordinator> &coordinator);
CaptureCoordinator *trace_proxy_test_hook_coordinator(size_t generation);
std::shared_ptr<TraceGenerationRuntime> trace_proxy_test_current_runtime();
std::shared_ptr<TraceGenerationRuntime> trace_proxy_test_hook_runtime(
        size_t generation);
void trace_proxy_test_install_loading_module(const ModuleRange &module);
void trace_proxy_test_module_fini(uintptr_t module_base,
                                  const char *module_path);
bool trace_proxy_test_generation_retired(size_t generation);
bool trace_proxy_test_generation_installed(size_t generation);
bool trace_proxy_test_finish_module_observation_failure(uint64_t generation);
bool trace_proxy_test_current_configuration(uint64_t *generation,
                                            TraceConfig *config);
CaptureCoordinator *trace_proxy_test_current_coordinator();
void trace_proxy_test_throw_during_configuration_apply();
bool trace_proxy_test_generation_locks_available(size_t generation);

void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

volatile sig_atomic_t g_fail_on_child_delete = 0;
volatile sig_atomic_t g_fail_next_nothrow_allocation = 0;
std::atomic<size_t> g_throwing_allocation_calls{0};
bool g_fail_inline_hook_init = false;

extern char **environ;

std::string json_abi_request(std::string package_name,
                             std::string target_module,
                             bool flight_enabled = false,
                             std::string entry_scene = {},
                             nlohmann::json scenes = nlohmann::json::array()) {
    return nlohmann::json({
            {"schemaVersion", 1},
            {"packageName", std::move(package_name)},
            {"targetModule", std::move(target_module)},
            {"trace", {
                    {"profile", "fast"},
                    {"compression", true},
                    {"lz4Level", 2},
                    {"autoBuffer", true},
                    {"bufferMb", 0},
                    {"hexdumpLimit", 32},
            }},
            {"flight", {
                    {"enabled", flight_enabled},
                    {"entryScene", std::move(entry_scene)},
                    {"capacityMb", 512},
                    {"chunkKb", 256},
                    {"maxThreads", 256},
                    {"protectedChunks", 4},
            }},
            {"scenes", std::move(scenes)},
    }).dump();
}

nlohmann::json call_json_configure(const std::string &request) {
    std::vector<char> response(64U * 1024U);
    uint64_t response_size = 0;
    CHECK(qbdi_tracer_configure_json(request.data(), request.size(), response.data(),
                                     response.size(), &response_size) == QTRACE_JSON_OK);
    CHECK(response_size > 1);
    CHECK(response.at(response_size - 1) == '\0');
    return nlohmann::json::parse(response.data());
}

nlohmann::json call_json_status(uint64_t generation) {
    std::vector<char> response(64U * 1024U);
    uint64_t response_size = 0;
    CHECK(qbdi_tracer_get_status_json(generation, response.data(), response.size(),
                                      &response_size) == QTRACE_JSON_OK);
    CHECK(response_size > 1);
    CHECK(response.at(response_size - 1) == '\0');
    return nlohmann::json::parse(response.data());
}

void json_configuration_abi_is_transactional_and_nul_terminated() {
    const std::string request = json_abi_request(
            "com.aprz.qbdiandroid",
            "libqtrace-json-abi-test-never-loaded.so");
    char small_response[] = {'x'};
    uint64_t response_size = 99;

    CHECK(qbdi_tracer_configure_json(nullptr, 0, small_response,
                                     sizeof(small_response), &response_size) ==
          QTRACE_JSON_INVALID_ARGUMENT);
    CHECK(qbdi_tracer_configure_json(request.data(), request.size(), nullptr,
                                     sizeof(small_response), &response_size) ==
          QTRACE_JSON_INVALID_ARGUMENT);
    CHECK(qbdi_tracer_configure_json(request.data(), request.size(), small_response,
                                     sizeof(small_response), nullptr) ==
          QTRACE_JSON_INVALID_ARGUMENT);
    CHECK(qbdi_tracer_get_status_json(1, nullptr, sizeof(small_response),
                                      &response_size) == QTRACE_JSON_INVALID_ARGUMENT);
    CHECK(qbdi_tracer_get_status_json(1, small_response, sizeof(small_response),
                                      nullptr) == QTRACE_JSON_INVALID_ARGUMENT);

    std::string embedded_nul = request;
    embedded_nul.insert(embedded_nul.size() / 2, 1, '\0');
    std::vector<char> rejection_buffer(64U * 1024U);
    CHECK(qbdi_tracer_configure_json(
                  embedded_nul.data(), embedded_nul.size(), rejection_buffer.data(),
                  rejection_buffer.size(), &response_size) == QTRACE_JSON_OK);
    CHECK(response_size > 1);
    CHECK(rejection_buffer.at(response_size - 1) == '\0');
    const nlohmann::json rejection = nlohmann::json::parse(rejection_buffer.data());
    CHECK(rejection.at("ok") == false);
    CHECK(rejection.at("error").at("code") == "MALFORMED_JSON");

    small_response[0] = 'x';
    CHECK(qbdi_tracer_configure_json(
                  request.data(), request.size(), small_response,
                  sizeof(small_response), &response_size) ==
          QTRACE_JSON_RESPONSE_TOO_SMALL);
    CHECK(response_size > sizeof(small_response));
    CHECK(small_response[0] == 'x');
    uint64_t active_generation = 0;
    TraceConfig active_config;
    CHECK(!trace_proxy_test_current_configuration(&active_generation,
                                                  &active_config));

    uint64_t missing_size = 0;
    std::vector<char> missing_buffer(64U * 1024U);
    CHECK(qbdi_tracer_get_status_json(1, missing_buffer.data(), missing_buffer.size(),
                                      &missing_size) == QTRACE_JSON_OK);
    const nlohmann::json missing = nlohmann::json::parse(missing_buffer.data());
    CHECK(missing.at("ok") == false);
    CHECK(missing.at("error").at("code") == "GENERATION_NOT_FOUND");

    std::vector<char> response(response_size);
    CHECK(qbdi_tracer_configure_json(request.data(), request.size(), response.data(),
                                     response.size(), &response_size) == QTRACE_JSON_OK);
    CHECK(response_size == response.size());
    CHECK(response.at(response_size - 1) == '\0');
    CHECK(std::strlen(response.data()) + 1 == response_size);
    const nlohmann::json accepted = nlohmann::json::parse(response.data());
    CHECK(accepted.at("ok") == true);
    CHECK(accepted.at("generation") == 1);
    CHECK(trace_proxy_test_current_configuration(&active_generation,
                                                 &active_config));
    CHECK(active_generation == 1);
    CHECK(active_config.package_name == "com.aprz.qbdiandroid");
    CHECK(active_config.target_so ==
          "libqtrace-json-abi-test-never-loaded.so");

    small_response[0] = 'y';
    CHECK(qbdi_tracer_get_status_json(1, small_response, sizeof(small_response),
                                      &response_size) ==
          QTRACE_JSON_RESPONSE_TOO_SMALL);
    CHECK(small_response[0] == 'y');
    std::vector<char> status_response(response_size);
    CHECK(qbdi_tracer_get_status_json(1, status_response.data(),
                                      status_response.size(), &response_size) ==
          QTRACE_JSON_OK);
    CHECK(status_response.at(response_size - 1) == '\0');
    const nlohmann::json status = nlohmann::json::parse(status_response.data());
    CHECK(status.at("ok") == true);
    CHECK(status.at("generation") == 1);
    CHECK(status.at("state") == "waiting_for_module");

    CHECK(qbdi_tracer_configure == nullptr);
}

void rejected_configuration_preserves_the_active_runtime_snapshot() {
    uint64_t before_generation = 0;
    TraceConfig before_config;
    CHECK(trace_proxy_test_current_configuration(&before_generation,
                                                 &before_config));

    const nlohmann::json rejected = call_json_configure("{]");
    CHECK(rejected.at("ok") == false);
    CHECK(rejected.at("error").at("code") == "MALFORMED_JSON");

    uint64_t after_generation = 0;
    TraceConfig after_config;
    CHECK(trace_proxy_test_current_configuration(&after_generation,
                                                 &after_config));
    CHECK(after_generation == before_generation);
    CHECK(after_config.package_name == before_config.package_name);
    CHECK(after_config.target_so == before_config.target_so);
}

void accepted_configuration_is_active_when_inline_setup_fails() {
    g_fail_inline_hook_init = true;
    const nlohmann::json accepted = call_json_configure(json_abi_request(
            "com.example.setup-failure",
            "libqtrace-setup-failure-never-loaded.so", false, {},
            nlohmann::json::array({
                    {{"name", "setup"},
                     {"location", {{"offset", "0x100"}}}},
            })));
    CHECK(accepted.at("ok") == true);

    uint64_t active_generation = 0;
    TraceConfig active_config;
    CHECK(trace_proxy_test_current_configuration(&active_generation,
                                                 &active_config));
    CHECK(active_generation == accepted.at("generation").get<uint64_t>());
    CHECK(active_config.package_name == "com.example.setup-failure");
    CHECK(active_config.target_so == "libqtrace-setup-failure-never-loaded.so");
    CHECK(!g_fail_inline_hook_init);
    const nlohmann::json status = call_json_status(active_generation);
    CHECK(status.at("state") == "hook_failed");
    CHECK(status.at("scenes").at(0).at("state") == "hook_failed");
    CHECK(status.at("scenes").at(0).at("error").at("code") ==
          "HOOK_INITIALIZATION_FAILED");
}

void nonflight_configuration_waits_beyond_the_old_timeout_boundary() {
    const nlohmann::json accepted = call_json_configure(json_abi_request(
            "com.example.no-module-timeout",
            "libqtrace-no-module-timeout-never-loaded.so", false, {},
            nlohmann::json::array({
                    {{"name", "late"},
                     {"location", {{"offset", "0x100"}}}},
            })));
    CHECK(accepted.at("ok") == true);
    const uint64_t generation = accepted.at("generation").get<uint64_t>();

    std::this_thread::sleep_for(std::chrono::milliseconds(10'250));

    const nlohmann::json status = call_json_status(generation);
    CHECK(status.at("state") == "waiting_for_module");
    CHECK(status.at("scenes").at(0).at("state") == "pending");
}

void flight_configuration_activates_its_explicit_entry_scene() {
    const nlohmann::json scenes = nlohmann::json::array({
            {{"name", "worker"}, {"location", {{"offset", "0x100"}}}},
            {{"name", "boot"}, {"location", {{"offset", "0x200"}}}},
    });
    const nlohmann::json accepted = call_json_configure(json_abi_request(
            "com.example.flight-entry",
            "libqtrace-flight-entry-never-loaded.so", true, "boot", scenes));
    CHECK(accepted.at("ok") == true);

    uint64_t active_generation = 0;
    TraceConfig active_config;
    CHECK(trace_proxy_test_current_configuration(&active_generation,
                                                 &active_config));
    CHECK(active_generation == accepted.at("generation").get<uint64_t>());
    CHECK(active_config.flight.entry_scene == "boot");
    CHECK(active_config.scenes.at(0).name == "worker");
    CHECK(active_config.scenes.at(1).name == "boot");
    CHECK(trace_proxy_test_current_coordinator() != nullptr);
}

void configuration_abi_catches_publication_and_status_exceptions() {
    const nlohmann::json baseline = call_json_configure(json_abi_request(
            "com.example.exception-baseline",
            "libexception-baseline-never-loaded.so"));
    CHECK(baseline.at("ok") == true);
    const uint64_t baseline_generation =
            baseline.at("generation").get<uint64_t>();
    uint64_t active_generation = 0;
    TraceConfig active_config;
    CHECK(trace_proxy_test_current_configuration(&active_generation,
                                                 &active_config));
    CHECK(active_generation == baseline_generation);

    const std::string replacement = json_abi_request(
            "com.example.exception-replacement",
            "libexception-replacement-never-loaded.so", false, {},
            nlohmann::json::array({
                    {{"name", "replacement"},
                     {"location", {{"offset", "0x100"}}}},
            }));
    const TracerConfigurationFaultPoint configure_faults[] = {
            TracerConfigurationFaultPoint::ParsePrepared,
            TracerConfigurationFaultPoint::SnapshotPrepared,
            TracerConfigurationFaultPoint::ResponsePrepared,
            TracerConfigurationFaultPoint::ReplacementPrepared,
    };
    for (const TracerConfigurationFaultPoint fault: configure_faults) {
        tracer_configuration_test_throw_at(fault);
        std::vector<char> response(64U * 1024U);
        uint64_t response_size = 0;
        CHECK(qbdi_tracer_configure_json(
                      replacement.data(), replacement.size(), response.data(),
                      response.size(), &response_size) == QTRACE_JSON_OK);
        CHECK(response_size > 1);
        CHECK(response.at(response_size - 1) == '\0');
        const nlohmann::json failure = nlohmann::json::parse(response.data());
        CHECK(failure.at("ok") == false);
        CHECK(failure.at("error").at("code") == "INTERNAL_ERROR");
        CHECK(trace_proxy_test_current_configuration(&active_generation,
                                                     &active_config));
        CHECK(active_generation == baseline_generation);
        CHECK(active_config.package_name == "com.example.exception-baseline");
        CHECK(call_json_status(baseline_generation).at("ok") == true);
    }

    tracer_configuration_test_throw_at(
            TracerConfigurationFaultPoint::StatusSerialization);
    std::vector<char> response(64U * 1024U);
    uint64_t response_size = 0;
    CHECK(qbdi_tracer_get_status_json(
                  baseline_generation, response.data(), response.size(),
                  &response_size) == QTRACE_JSON_OK);
    CHECK(response.at(response_size - 1) == '\0');
    const nlohmann::json status_failure =
            nlohmann::json::parse(response.data());
    CHECK(status_failure.at("ok") == false);
    CHECK(status_failure.at("error").at("code") == "INTERNAL_ERROR");
    CHECK(trace_proxy_test_current_configuration(&active_generation,
                                                 &active_config));
    CHECK(active_generation == baseline_generation);

    trace_proxy_test_throw_during_configuration_apply();
    const nlohmann::json accepted_with_apply_failure =
            call_json_configure(replacement);
    CHECK(accepted_with_apply_failure.at("ok") == true);
    const uint64_t failed_generation =
            accepted_with_apply_failure.at("generation").get<uint64_t>();
    CHECK(failed_generation == baseline_generation + 1);
    CHECK(trace_proxy_test_current_configuration(&active_generation,
                                                 &active_config));
    CHECK(active_generation == failed_generation);
    CHECK(active_config.package_name ==
          "com.example.exception-replacement");
    const nlohmann::json failed_status =
            call_json_status(failed_generation);
    CHECK(failed_status.at("state") == "hook_failed");
    CHECK(failed_status.at("scenes").at(0).at("error").at("code") ==
          "CONFIGURATION_APPLY_EXCEPTION");
}

extern "C" void *__real__Znwm(std::size_t);
extern "C" void *__wrap__Znwm(std::size_t size) {
    g_throwing_allocation_calls.fetch_add(1, std::memory_order_relaxed);
    return __real__Znwm(size);
}

extern "C" void *__real__ZnwmRKSt9nothrow_t(std::size_t, const std::nothrow_t &);
extern "C" void *__wrap__ZnwmRKSt9nothrow_t(
        std::size_t size, const std::nothrow_t &tag) {
    if (g_fail_next_nothrow_allocation != 0) {
        g_fail_next_nothrow_allocation = 0;
        return nullptr;
    }
    return __real__ZnwmRKSt9nothrow_t(size, tag);
}

extern "C" void __real__ZdlPv(void *);
extern "C" void __wrap__ZdlPv(void *pointer) {
    if (g_fail_on_child_delete != 0) _exit(96);
    __real__ZdlPv(pointer);
}

extern "C" void __real__ZdlPvm(void *, std::size_t);
extern "C" void __wrap__ZdlPvm(void *pointer, std::size_t size) {
    if (g_fail_on_child_delete != 0) _exit(96);
    __real__ZdlPvm(pointer, size);
}

extern "C" void __real__ZdaPv(void *);
extern "C" void __wrap__ZdaPv(void *pointer) {
    if (g_fail_on_child_delete != 0) _exit(96);
    __real__ZdaPv(pointer);
}

extern "C" void __real__ZdaPvm(void *, std::size_t);
extern "C" void __wrap__ZdaPvm(void *pointer, std::size_t size) {
    if (g_fail_on_child_delete != 0) _exit(96);
    __real__ZdaPvm(pointer, size);
}

namespace {

std::mutex g_fake_mutex;
TraceInvocation g_seen_invocation;
TraceConfig g_seen_config;
size_t g_runner_calls = 0;
size_t g_allocations_at_runner_entry = 0;
size_t g_bridge_calls = 0;
size_t g_hook_calls = 0;
size_t g_unhook_calls = 0;
bool g_fail_unhook = false;
size_t g_fail_unhook_call = 0;
std::vector<size_t> g_fail_unhook_calls;
bool g_fail_next_hook = false;
size_t g_fail_hook_call = 0;
int g_hook_failure_error = 0;
int g_unhook_failure_error = 0;
bool g_install_residual_hook = false;
uintptr_t g_original_override = 0;
std::vector<uintptr_t> g_hook_targets;
std::atomic<size_t> g_old_calls{0};
std::atomic<size_t> g_new_calls{0};
std::atomic<size_t> g_admission_completion_calls{0};
int g_nested_fork_status = -1;
bool g_runner_forks = false;
pid_t g_runner_fork_child = -1;
bool g_runner_acknowledges_stop = false;
std::vector<ModuleRange> g_fake_maps;

std::mutex g_gate_mutex;
std::condition_variable g_gate_condition;
std::mutex g_fake_linker_mutex;
bool g_block_hook_on_linker = false;
bool g_hook_waiting_for_linker = false;
bool g_registration_entered = false;
bool g_release_registration = false;
bool g_atfork_prepare_entered = false;
int g_fork_transition_phase_fd = -1;
bool g_stub_entry_entered = false;
bool g_release_stub_entry = false;
bool g_installed_status_entered = false;
bool g_release_installed_status = false;
bool g_hook_commit_entered = false;
bool g_release_hook_commit = false;
bool g_block_unhook_return = false;
bool g_unhook_return_entered = false;
bool g_release_unhook_return = false;
bool g_registry_transition_entered = false;
bool g_release_registry_transition = false;
bool g_use_runner_gate = false;
bool g_runner_entered = false;
bool g_release_runner = false;
bool g_use_bridge_gate = false;
size_t g_bridge_gate_entries = 0;
bool g_release_bridge = false;

struct RuntimeReleaseLockProbe {
    static void before_worker_join(void *opaque) noexcept {
        auto *probe = static_cast<RuntimeReleaseLockProbe *>(opaque);
        probe->requested.store(true, std::memory_order_release);
        while (!probe->checked.load(std::memory_order_acquire)) {
            ::sched_yield();
        }
    }

    size_t hook_generation = 0;
    std::atomic<bool> requested{false};
    std::atomic<bool> checked{false};
    std::atomic<bool> locks_available{false};
};

struct FlightProxyFactory {
    std::atomic<size_t> artifact_creates{0};
    std::atomic<size_t> session_creates{0};
    std::atomic<size_t> session_calls{0};
    std::atomic<size_t> coverage_gaps{0};
    std::atomic<uintptr_t> last_gap_pc{0};
    std::atomic<CoverageGapReason> last_gap_reason{
            CoverageGapReason::SessionFailure};
    std::atomic<uintptr_t> last_execution_entry{0};
    std::atomic<size_t> last_execution_bytes{0};
    std::atomic<bool> defer_thread_exit{false};
    std::atomic<bool> partial_execution{false};
    std::atomic<size_t> continuation_failures_remaining{0};
    std::atomic<size_t> continuation_stops_remaining{0};
    std::atomic<size_t> continuation_calls{0};
    std::atomic<uint64_t> last_argument{0};
    std::mutex gate_mutex;
    std::condition_variable gate_condition;
    size_t blocked_entries = 0;
    bool block_sessions = false;
    bool release_sessions = false;
};

FlightProxyFactory g_flight_factory;

uint64_t old_target(uint64_t value, uint64_t, uint64_t, uint64_t,
                    uint64_t, uint64_t, uint64_t, uint64_t) {
    ++g_old_calls;
    return value + 0x100;
}

uint64_t new_target(uint64_t value, uint64_t, uint64_t, uint64_t,
                    uint64_t, uint64_t, uint64_t, uint64_t) {
    ++g_new_calls;
    return value + 0x200;
}

uint64_t forking_target(uint64_t, uint64_t, uint64_t, uint64_t,
                        uint64_t, uint64_t, uint64_t, uint64_t) {
    const pid_t child = ::fork();
    if (child == 0) return 0xCAFE;
    if (child < 0 || ::waitpid(child, &g_nested_fork_status, 0) != child) return 0;
    return 0xBEEF;
}

void registration_gate() {
    std::unique_lock<std::mutex> lock(g_gate_mutex);
    g_registration_entered = true;
    g_gate_condition.notify_all();
    g_gate_condition.wait(lock, [] { return g_release_registration; });
}

void report_fork_transition_phase(char phase) {
    if (g_fork_transition_phase_fd < 0) return;
    ssize_t written = 0;
    do {
        written = ::write(g_fork_transition_phase_fd, &phase, 1);
    } while (written < 0 && errno == EINTR);
}

void atfork_prepare_gate() {
    {
        std::lock_guard<std::mutex> lock(g_gate_mutex);
        g_atfork_prepare_entered = true;
    }
    report_fork_transition_phase('P');
    g_gate_condition.notify_all();
}

void stub_entry_gate() {
    std::unique_lock<std::mutex> lock(g_gate_mutex);
    g_stub_entry_entered = true;
    g_gate_condition.notify_all();
    g_gate_condition.wait(lock, [] { return g_release_stub_entry; });
}

void installed_status_gate() {
    std::unique_lock<std::mutex> lock(g_gate_mutex);
    g_installed_status_entered = true;
    g_gate_condition.notify_all();
    g_gate_condition.wait(lock, [] { return g_release_installed_status; });
}

void hook_commit_gate() {
    std::unique_lock<std::mutex> lock(g_gate_mutex);
    g_hook_commit_entered = true;
    g_gate_condition.notify_all();
    g_gate_condition.wait(lock, [] { return g_release_hook_commit; });
}

void registry_transition_gate() {
    std::unique_lock<std::mutex> lock(g_gate_mutex);
    g_registry_transition_entered = true;
    g_gate_condition.notify_all();
    g_gate_condition.wait(lock, [] { return g_release_registry_transition; });
}

void count_admission_completion(void *) noexcept {
    g_admission_completion_calls.fetch_add(1, std::memory_order_relaxed);
}

void reset_fakes() {
    std::lock_guard<std::mutex> lock(g_fake_mutex);
    g_seen_invocation = {};
    g_seen_config = {};
    g_runner_calls = 0;
    g_allocations_at_runner_entry = 0;
    g_bridge_calls = 0;
    g_hook_calls = 0;
    g_unhook_calls = 0;
    g_fail_unhook = false;
    g_fail_unhook_call = 0;
    g_fail_unhook_calls.clear();
    g_fail_next_hook = false;
    g_fail_hook_call = 0;
    g_hook_failure_error = 0;
    g_unhook_failure_error = 0;
    g_install_residual_hook = false;
    g_original_override = 0;
    g_hook_targets.clear();
    g_runner_forks = false;
    g_runner_fork_child = -1;
    g_runner_acknowledges_stop = false;
    g_fail_on_child_delete = 0;
    g_fail_next_nothrow_allocation = 0;
    g_throwing_allocation_calls.store(0, std::memory_order_relaxed);
    g_old_calls = 0;
    g_new_calls = 0;
    g_admission_completion_calls.store(0, std::memory_order_relaxed);
    g_fake_maps.clear();
    g_flight_factory.artifact_creates.store(0, std::memory_order_relaxed);
    g_flight_factory.session_creates.store(0, std::memory_order_relaxed);
    g_flight_factory.session_calls.store(0, std::memory_order_relaxed);
    g_flight_factory.coverage_gaps.store(0, std::memory_order_relaxed);
    g_flight_factory.last_gap_pc.store(0, std::memory_order_relaxed);
    g_flight_factory.last_gap_reason.store(CoverageGapReason::SessionFailure,
                                           std::memory_order_relaxed);
    g_flight_factory.last_execution_entry.store(0, std::memory_order_relaxed);
    g_flight_factory.last_execution_bytes.store(0, std::memory_order_relaxed);
    g_flight_factory.defer_thread_exit.store(false, std::memory_order_relaxed);
    g_flight_factory.partial_execution.store(false, std::memory_order_relaxed);
    g_flight_factory.continuation_failures_remaining.store(
            0, std::memory_order_relaxed);
    g_flight_factory.continuation_stops_remaining.store(
            0, std::memory_order_relaxed);
    g_flight_factory.continuation_calls.store(0, std::memory_order_relaxed);
    g_flight_factory.last_argument.store(0, std::memory_order_relaxed);
    {
        std::lock_guard<std::mutex> flight_lock(g_flight_factory.gate_mutex);
        g_flight_factory.blocked_entries = 0;
        g_flight_factory.block_sessions = false;
        g_flight_factory.release_sessions = false;
    }
    {
        std::lock_guard<std::mutex> gate_lock(g_gate_mutex);
        g_registration_entered = false;
        g_release_registration = false;
        g_atfork_prepare_entered = false;
        g_stub_entry_entered = false;
        g_release_stub_entry = false;
        g_installed_status_entered = false;
        g_release_installed_status = false;
        g_hook_commit_entered = false;
        g_release_hook_commit = false;
        g_block_unhook_return = false;
        g_unhook_return_entered = false;
        g_release_unhook_return = false;
        g_registry_transition_entered = false;
        g_release_registry_transition = false;
        g_use_runner_gate = false;
        g_runner_entered = false;
        g_release_runner = false;
        g_use_bridge_gate = false;
        g_bridge_gate_entries = 0;
        g_release_bridge = false;
        g_block_hook_on_linker = false;
        g_hook_waiting_for_linker = false;
    }
}

TraceConfig config_named(const char *name) {
    TraceConfig config = default_trace_config();
    config.package_name = name;
    config.scenes.clear();
    return config;
}

SceneConfig scene_named(const char *name, uintptr_t target, size_t index = 0) {
    SceneConfig scene;
    scene.index = index;
    scene.name = name;
    scene.offset = target;
    scene.end_offset = target + 4;
    return scene;
}

ModuleRange module_named(const char *path, uintptr_t end = UINTPTR_MAX - 1U) {
    ModuleRange module;
    module.start = 0;
    module.end = end;
    module.permissions = "r-xp";
    module.path = path;
    return module;
}

void *create_flight_proxy_artifact(
        void *opaque, const char *, const FlightOptions &,
        const FlightArtifactIdentityView &) noexcept {
    auto *factory = static_cast<FlightProxyFactory *>(opaque);
    factory->artifact_creates.fetch_add(1, std::memory_order_relaxed);
    return factory;
}

void destroy_flight_proxy_artifact(void *, void *) noexcept {}

TraceRunResult execute_flight_proxy_session(
        void *opaque, QbdiThreadSession *, uintptr_t entry,
        uintptr_t, size_t execution_bytes,
        const uint64_t args[8], uint64_t indirect_result) noexcept {
    auto *factory = static_cast<FlightProxyFactory *>(opaque);
    factory->session_calls.fetch_add(1, std::memory_order_relaxed);
    factory->last_execution_entry.store(entry, std::memory_order_relaxed);
    factory->last_execution_bytes.store(execution_bytes,
                                        std::memory_order_relaxed);
    factory->last_argument.store(args[0], std::memory_order_relaxed);
    {
        std::unique_lock<std::mutex> lock(factory->gate_mutex);
        if (factory->block_sessions) {
            ++factory->blocked_entries;
            factory->gate_condition.notify_all();
            factory->gate_condition.wait(lock, [&] {
                return factory->release_sessions;
            });
        }
    }
    if (factory->defer_thread_exit.load(std::memory_order_relaxed)) {
        return {true, false, true, args[0]};
    }
    if (factory->partial_execution.load(std::memory_order_relaxed)) {
        return {true, false, 0xbad};
    }
    return {true, call_target_arm64(entry, args, indirect_result)};
}

TraceRunResult continue_flight_proxy_session(
        void *opaque, QbdiThreadSession *) noexcept {
    auto *factory = static_cast<FlightProxyFactory *>(opaque);
    factory->continuation_calls.fetch_add(1, std::memory_order_relaxed);
    size_t failures = factory->continuation_failures_remaining.load(
            std::memory_order_relaxed);
    while (failures != 0 &&
           !factory->continuation_failures_remaining.compare_exchange_weak(
                   failures, failures - 1U, std::memory_order_relaxed,
                   std::memory_order_relaxed)) {
    }
    if (failures != 0) return {};
    size_t stops = factory->continuation_stops_remaining.load(
            std::memory_order_relaxed);
    while (stops != 0 &&
           !factory->continuation_stops_remaining.compare_exchange_weak(
                   stops, stops - 1U, std::memory_order_relaxed,
                   std::memory_order_relaxed)) {
    }
    if (stops != 0) return {true, false, 0xbeef};
    uint64_t args[8]{factory->last_argument.load(std::memory_order_relaxed)};
    return {true, true,
            call_target_arm64(
                    factory->last_execution_entry.load(std::memory_order_relaxed),
                    args, 0)};
}

QbdiThreadSession *create_flight_proxy_session(
        void *opaque, void *, const TraceConfig &, const ModuleRange &,
        const SceneConfig &, uint32_t tid,
        uint32_t module_generation) noexcept {
    auto *factory = static_cast<FlightProxyFactory *>(opaque);
    factory->session_creates.fetch_add(1, std::memory_order_relaxed);
    return QbdiThreadSession::create_for_test(
            tid, module_generation, execute_flight_proxy_session, factory,
            nullptr, nullptr, nullptr, nullptr,
            continue_flight_proxy_session);
}

void destroy_flight_proxy_session(void *, QbdiThreadSession *session) noexcept {
    delete session;
}

void mark_flight_proxy_gap(void *opaque, void *, uint32_t,
                           uintptr_t pc, CoverageGapReason reason) noexcept {
    auto *factory = static_cast<FlightProxyFactory *>(opaque);
    factory->coverage_gaps.fetch_add(1, std::memory_order_relaxed);
    factory->last_gap_pc.store(pc, std::memory_order_relaxed);
    factory->last_gap_reason.store(reason, std::memory_order_relaxed);
}

CaptureCoordinatorFactories flight_proxy_factories() {
    return {&g_flight_factory, create_flight_proxy_artifact,
            destroy_flight_proxy_artifact, create_flight_proxy_session,
            destroy_flight_proxy_session, mark_flight_proxy_gap};
}

TraceConfig flight_proxy_config(const SceneConfig &scene) {
    TraceConfig config = config_named("flight-proxy");
    config.target_so = "libflight-proxy.so";
    config.flight.enabled = true;
    config.flight.max_threads = 4;
    config.flight.capacity_bytes = 64ULL * 1024ULL * 1024ULL;
    config.flight.chunk_bytes = 64U * 1024U;
    config.flight.protected_chunks = 1;
    config.flight.entry_scene = scene.name;
    config.scenes.push_back(scene);
    return config;
}

std::shared_ptr<CaptureCoordinator> start_flight_proxy_coordinator(
        const TraceConfig &config, const ModuleRange &module) {
    const std::shared_ptr<CaptureCoordinator> coordinator(
            new CaptureCoordinator(flight_proxy_factories()));
    CHECK(coordinator != nullptr);
    CHECK(coordinator->start(config, module, 77));
    trace_proxy_test_set_coordinator(coordinator);
    return coordinator;
}

void flight_gateway_install_never_holds_the_registry_across_shadowhook() {
    reset_fakes();
    const SceneConfig scene = scene_named(
            "flight-linker-lock-order", reinterpret_cast<uintptr_t>(new_target));
    const TraceConfig config = flight_proxy_config(scene);
    const ModuleRange target = module_named("/data/app/libflight-proxy.so");
    trace_proxy_test_reset(config);
    const std::shared_ptr<CaptureCoordinator> coordinator =
            start_flight_proxy_coordinator(config, target);

    std::unique_lock<std::mutex> linker_lock(g_fake_linker_mutex);
    {
        std::lock_guard<std::mutex> gate_lock(g_gate_mutex);
        g_block_hook_on_linker = true;
    }
    ::alarm(3);
    std::thread installer([&] {
        trace_proxy_test_install_loading_module(target);
    });
    {
        std::unique_lock<std::mutex> gate_lock(g_gate_mutex);
        g_gate_condition.wait(gate_lock, [] {
            return g_hook_waiting_for_linker;
        });
    }

    trace_proxy_test_install_loading_module(
            module_named("/data/app/libunrelated-flight-callback.so"));
    linker_lock.unlock();
    installer.join();
    ::alarm(0);

    CHECK(coordinator->started());
    CHECK(process_thread_create_gateway().should_capture(
            reinterpret_cast<PthreadStartRoutine>(old_target)));
    const size_t generation = trace_proxy_test_generation(scene.index);
    CHECK(generation != 4096);
    CHECK(trace_proxy_test_generation_installed(generation));
    CHECK(g_hook_calls == 2);
}

void accepted_nonflight_generation_deactivates_the_flight_gateway() {
    reset_fakes();
    trace_proxy_test_reset(config_named("flight-gateway-transition-reset"));
    const ModuleRange module = module_named(
            "/data/app/libflight-gateway-transition.so");
    const nlohmann::json flight_accepted = call_json_configure(
            json_abi_request(
                    "com.example.flight-gateway-transition",
                    "libflight-gateway-transition.so", true, "flight-entry",
                    nlohmann::json::array({
                            {{"name", "flight-entry"},
                             {"location", {{"offset", "0x40"}}}},
                    })));
    const uint64_t flight_generation =
            flight_accepted.at("generation").get<uint64_t>();
    uint64_t active_generation = 0;
    TraceConfig flight_config;
    CHECK(trace_proxy_test_current_configuration(&active_generation,
                                                 &flight_config));
    CHECK(active_generation == flight_generation);
    const std::shared_ptr<CaptureCoordinator> coordinator =
            start_flight_proxy_coordinator(flight_config, module);
    trace_proxy_test_install_loading_module(module);
    CHECK(call_json_status(flight_generation).at("state") == "installed");
    CHECK(process_thread_create_gateway().should_capture(
            reinterpret_cast<PthreadStartRoutine>(old_target)));

    CHECK(call_json_configure(json_abi_request(
                  "com.example.nonflight-gateway-transition",
                  "libnonflight-gateway-transition-never-loaded.so"))
                  .at("ok") == true);

    CHECK(!process_thread_create_gateway().should_capture(
            reinterpret_cast<PthreadStartRoutine>(old_target)));
    CHECK(coordinator->started());

    const nlohmann::json failing_flight_accepted = call_json_configure(
            json_abi_request(
                    "com.example.failed-flight-gateway-transition",
                    "libflight-gateway-transition.so", true, "replacement",
                    nlohmann::json::array({
                            {{"name", "replacement"},
                             {"location", {{"offset", "0x80"}}}},
                    })));
    const uint64_t failing_generation =
            failing_flight_accepted.at("generation").get<uint64_t>();
    TraceConfig failing_flight_config;
    CHECK(trace_proxy_test_current_configuration(&active_generation,
                                                 &failing_flight_config));
    const std::shared_ptr<CaptureCoordinator> failing_coordinator =
            start_flight_proxy_coordinator(failing_flight_config, module);

    trace_proxy_test_install_loading_module(module);

    const nlohmann::json failed = call_json_status(failing_generation);
    CHECK(failed.at("state") == "hook_failed");
    CHECK(!process_thread_create_gateway().should_capture(
            reinterpret_cast<PthreadStartRoutine>(old_target)));
    CHECK(failing_coordinator->incomplete());
}

void invalid_target_module_observation_finishes_with_a_stable_code() {
    reset_fakes();
    trace_proxy_test_reset(config_named("module-observation-reset"));
    const nlohmann::json accepted = call_json_configure(json_abi_request(
            "com.example.module-observation", "libmodule-observation.so",
            false, {}, nlohmann::json::array({
                    {{"name", "entry"},
                     {"location", {{"offset", "0x100"}}}},
            })));
    const uint64_t generation = accepted.at("generation").get<uint64_t>();

    qbdi_tracer_install_module("/data/app/libmodule-observation.so", 1, 1);

    const nlohmann::json status = call_json_status(generation);
    CHECK(status.at("state") == "hook_failed");
    CHECK(status.at("scenes").at(0).at("error").at("code") ==
          "MODULE_OBSERVATION_FAILED");
}

void callback_registration_failure_preserves_the_shadowhook_error() {
    reset_fakes();
    trace_proxy_test_reset(config_named("callback-registration-reset"));
    const nlohmann::json accepted = call_json_configure(json_abi_request(
            "com.example.callback-registration", "libcallback-registration.so",
            true, "boot", nlohmann::json::array({
                    {{"name", "boot"},
                     {"location", {{"offset", "0x100"}}}},
            })));
    const uint64_t generation = accepted.at("generation").get<uint64_t>();
    uint64_t active_generation = 0;
    TraceConfig config;
    CHECK(trace_proxy_test_current_configuration(&active_generation, &config));
    CHECK(active_generation == generation);
    ModuleRange module;
    module.start = 0x75000000;
    module.end = module.start + 0x1000;
    module.permissions = "r-xp";
    module.path = "/data/app/libcallback-registration.so";
    const std::shared_ptr<CaptureCoordinator> coordinator(
            new CaptureCoordinator(flight_proxy_factories()));
    CHECK(coordinator->start(config, module,
                             static_cast<uint32_t>(generation)));
    trace_proxy_test_set_coordinator(coordinator);
    g_fail_hook_call = 1;
    g_hook_failure_error = 87;

    trace_proxy_test_install_loading_module(module);

    const nlohmann::json status = call_json_status(generation);
    CHECK(status.at("state") == "hook_failed");
    CHECK(status.at("scenes").at(0).at("error").at("code") ==
          "CALLBACK_REGISTRATION_FAILED");
    CHECK(status.at("scenes").at(0).at("error").at("hookError") == 87);
}

void branch_before_registry_that_is_retired_never_enters_qbdi() {
    reset_fakes();
    const TraceConfig old_config = config_named("old-generation");
    const SceneConfig old_scene = scene_named("old-generation",
                                              reinterpret_cast<uintptr_t>(old_target));
    trace_proxy_test_reset(old_config);
    CHECK(trace_proxy_test_update(old_config, old_scene, module_named("old-module")));
    const size_t old_generation = trace_proxy_test_generation(old_scene.index);
    const std::shared_ptr<TraceGenerationRuntime> old_runtime =
            trace_proxy_test_hook_runtime(old_generation);
    CHECK(old_runtime != nullptr);
    trace_proxy_test_set_stub_entry_gate(stub_entry_gate);

    uint64_t args[8]{5};
    uint64_t old_result = 0;
    std::thread delayed([&] {
        old_result = trace_proxy_dispatch(old_generation, args, 0x66);
    });
    {
        std::unique_lock<std::mutex> lock(g_gate_mutex);
        g_gate_condition.wait(lock, [] { return g_stub_entry_entered; });
    }

    const TraceConfig new_config = config_named("new-generation");
    SceneConfig new_scene = scene_named("new-generation",
                                        reinterpret_cast<uintptr_t>(old_target));
    new_scene.end_offset += 0x20;
    CHECK(trace_proxy_test_update(new_config, new_scene, module_named("new-module")));
    const size_t new_generation = trace_proxy_test_generation(new_scene.index);
    CHECK(new_generation != old_generation);
    CHECK(trace_proxy_test_hook_runtime(old_generation) == nullptr);
    CHECK(old_runtime->request_stop(TraceStopReason::DurationElapsed));

    {
        std::lock_guard<std::mutex> lock(g_gate_mutex);
        g_release_stub_entry = true;
    }
    g_gate_condition.notify_all();
    delayed.join();
    trace_proxy_test_set_stub_entry_gate(nullptr);

    CHECK(old_result == 0x105);
    CHECK(g_runner_calls == 0);
    CHECK(old_runtime->snapshot().active_calls == 0);
    CHECK(old_runtime->snapshot().phase == TraceGenerationPhase::Sealed);
    CHECK(trace_proxy_dispatch(new_generation, args, 0x77) == 0x105);
    CHECK(g_runner_calls == 1);
    CHECK(g_seen_config.package_name == "new-generation");
    CHECK(g_seen_invocation.scene->name == "new-generation");
    CHECK(g_seen_invocation.module->path == "new-module");
}

void entrant_registration_and_snapshot_are_atomic_with_install() {
    reset_fakes();
    const TraceConfig old_config = config_named("old-config");
    const SceneConfig old_scene = scene_named("old-scene",
                                              reinterpret_cast<uintptr_t>(old_target));
    trace_proxy_test_reset(old_config);
    CHECK(trace_proxy_test_update(old_config, old_scene, module_named("old-module")));
    trace_proxy_test_set_registration_gate(registration_gate);
    {
        std::lock_guard<std::mutex> lock(g_gate_mutex);
        g_use_runner_gate = true;
    }

    uint64_t args[8]{7};
    uint64_t result = 0;
    std::thread entrant([&] { result = trace_proxy_dispatch(0, args, 0x88); });
    {
        std::unique_lock<std::mutex> lock(g_gate_mutex);
        g_gate_condition.wait(lock, [] { return g_registration_entered; });
    }

    TraceConfig new_config = config_named("new-config");
    SceneConfig new_scene = scene_named("new-scene",
                                        reinterpret_cast<uintptr_t>(new_target));
    new_scene.end_offset += 8;
    const ModuleRange new_module = module_named("new-module", UINTPTR_MAX);
    std::atomic<bool> installer_started{false};
    std::atomic<bool> installer_finished{false};
    std::thread installer([&] {
        installer_started = true;
        CHECK(trace_proxy_test_update(new_config, new_scene, new_module));
        installer_finished = true;
    });
    while (!installer_started.load()) std::this_thread::yield();
    CHECK(!installer_finished.load());

    {
        std::lock_guard<std::mutex> lock(g_gate_mutex);
        g_release_registration = true;
    }
    g_gate_condition.notify_all();
    {
        std::unique_lock<std::mutex> lock(g_gate_mutex);
        g_gate_condition.wait(lock, [] { return g_runner_entered; });
    }
    installer.join();
    CHECK(installer_finished.load());
    {
        std::lock_guard<std::mutex> lock(g_gate_mutex);
        g_release_runner = true;
    }
    g_gate_condition.notify_all();
    entrant.join();
    trace_proxy_test_set_registration_gate(nullptr);

    CHECK(result == 0x107);
    CHECK(g_old_calls == 1);
    CHECK(g_new_calls == 0);
    CHECK(g_seen_config.package_name == "old-config");
    CHECK(g_seen_invocation.scene->name == "old-scene");
    CHECK(g_seen_invocation.module->path == "old-module");

    CHECK(trace_proxy_dispatch(trace_proxy_test_generation(new_scene.index), args, 0x99) ==
          0x207);
    CHECK(g_new_calls == 1);
    CHECK(g_seen_config.package_name == "new-config");
    CHECK(g_seen_invocation.scene->name == "new-scene");
    CHECK(g_seen_invocation.scene->end_offset == new_scene.end_offset);
    CHECK(g_seen_invocation.module->path == "new-module");
}

void stopped_generation_proxy_bypasses_qbdi_before_allocation() {
    reset_fakes();
    trace_proxy_test_reset(config_named("stopped-runtime-reset"));
    char offset[2 * sizeof(uintptr_t) + 3]{};
    std::snprintf(offset, sizeof(offset), "0x%lx",
                  static_cast<unsigned long>(
                          reinterpret_cast<uintptr_t>(new_target)));
    const nlohmann::json accepted = call_json_configure(json_abi_request(
            "com.example.stopped.runtime", "libstopped-runtime.so", false,
            {}, nlohmann::json::array({
                        {{"name", "entry"},
                         {"location", {{"offset", offset}}}},
                })));
    CHECK(accepted.at("ok") == true);
    g_original_override = reinterpret_cast<uintptr_t>(old_target);
    trace_proxy_test_install_loading_module(
            module_named("/data/app/libstopped-runtime.so"));
    CHECK(call_json_status(
                  accepted.at("generation").get<uint64_t>()).at("state") ==
          "installed");

    uint64_t args[8]{3};
    size_t proxy_generation = trace_proxy_test_generation(0);
    CHECK(trace_proxy_dispatch(proxy_generation, args, 0) == 0x203);
    const std::shared_ptr<TraceGenerationRuntime> runtime =
            g_seen_invocation.runtime;
    CHECK(runtime != nullptr);
    CHECK(runtime->snapshot().phase == TraceGenerationPhase::Running);
    CHECK(runtime->request_stop(TraceStopReason::DurationElapsed));
    CHECK(runtime->snapshot().phase == TraceGenerationPhase::Sealed);

    const size_t runner_calls_before = g_runner_calls;
    proxy_generation = trace_proxy_test_generation(0);
    CHECK(trace_proxy_dispatch(proxy_generation, args, 0) == 0x103);
    CHECK(g_runner_calls == runner_calls_before);
    CHECK(g_old_calls == 1);
    CHECK(runtime->snapshot().active_calls == 0);
}

void failed_hook_batch_never_arms_its_generation_deadline() {
    reset_fakes();
    trace_proxy_test_reset(config_named("failed-runtime-batch-reset"));
    nlohmann::json request = nlohmann::json::parse(json_abi_request(
            "com.example.failed.runtime", "libfailed-runtime.so", false, {},
            nlohmann::json::array({
                    {{"name", "first"},
                     {"location", {{"offset", "0x40"}}}},
                    {{"name", "second"},
                     {"location", {{"offset", "0x80"}}}},
            })));
    request["session"] = {
            {"id", "1c4da924-8281-4e53-8e2c-1e912aa0ee3d"},
            {"durationMs", 100},
    };
    const nlohmann::json accepted = call_json_configure(request.dump());
    CHECK(accepted.at("ok") == true);
    const std::shared_ptr<TraceGenerationRuntime> runtime =
            trace_proxy_test_current_runtime();
    CHECK(runtime != nullptr);
    CHECK(runtime->snapshot().phase == TraceGenerationPhase::Waiting);
    g_fail_hook_call = 2;
    trace_proxy_test_install_loading_module(
            module_named("/data/app/libfailed-runtime.so"));
    CHECK(call_json_status(
                  accepted.at("generation").get<uint64_t>()).at("state") ==
          "hook_failed");

    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    CHECK(runtime->snapshot().phase == TraceGenerationPhase::Waiting);
    CHECK(!runtime->stop_token().requested());
}

void successful_hook_batch_shares_one_runtime_and_then_arms_it() {
    reset_fakes();
    trace_proxy_test_reset(config_named("shared-runtime-batch-reset"));
    const nlohmann::json accepted = call_json_configure(json_abi_request(
            "com.example.shared.runtime", "libshared-runtime.so", false, {},
            nlohmann::json::array({
                    {{"name", "first"},
                     {"location", {{"offset", "0x40"}}}},
                    {{"name", "second"},
                     {"location", {{"offset", "0x80"}}}},
            })));
    const std::shared_ptr<TraceGenerationRuntime> runtime =
            trace_proxy_test_current_runtime();
    CHECK(runtime != nullptr);
    CHECK(runtime->snapshot().phase == TraceGenerationPhase::Waiting);
    trace_proxy_test_install_loading_module(
            module_named("/data/app/libshared-runtime.so"));

    CHECK(call_json_status(
                  accepted.at("generation").get<uint64_t>()).at("state") ==
          "installed");
    CHECK(trace_proxy_test_hook_runtime(
                  trace_proxy_test_generation(0)) == runtime);
    CHECK(trace_proxy_test_hook_runtime(
                  trace_proxy_test_generation(1)) == runtime);
    CHECK(runtime->snapshot().phase == TraceGenerationPhase::Running);
}

void stop_racing_proxy_registration_uses_dormant_passthrough() {
    reset_fakes();
    const TraceConfig config = config_named("registration-stop");
    const SceneConfig scene = scene_named(
            "registration-stop", reinterpret_cast<uintptr_t>(new_target));
    trace_proxy_test_reset(config);
    g_original_override = reinterpret_cast<uintptr_t>(old_target);
    CHECK(trace_proxy_test_update(config, scene, module_named("module")));
    const size_t generation = trace_proxy_test_generation(scene.index);
    const std::shared_ptr<TraceGenerationRuntime> runtime =
            trace_proxy_test_hook_runtime(generation);
    CHECK(runtime != nullptr);
    trace_proxy_test_set_registration_gate(registration_gate);

    uint64_t args[8]{11};
    uint64_t result = 0;
    std::thread entrant([&] {
        result = trace_proxy_dispatch(generation, args, 0);
    });
    {
        std::unique_lock<std::mutex> lock(g_gate_mutex);
        g_gate_condition.wait(lock, [] { return g_registration_entered; });
    }
    CHECK(runtime->request_stop(TraceStopReason::DurationElapsed));
    {
        std::lock_guard<std::mutex> lock(g_gate_mutex);
        g_release_registration = true;
    }
    g_gate_condition.notify_all();
    entrant.join();
    trace_proxy_test_set_registration_gate(nullptr);

    CHECK(result == 0x10B);
    CHECK(g_runner_calls == 0);
    CHECK(g_unhook_calls == 0);
    CHECK(runtime->snapshot().active_calls == 0);
    CHECK(runtime->snapshot().phase == TraceGenerationPhase::Sealed);
}

void active_proxy_acknowledges_the_exact_generation_admission() {
    reset_fakes();
    const TraceConfig config = config_named("active-stop");
    const SceneConfig scene = scene_named(
            "active-stop", reinterpret_cast<uintptr_t>(new_target));
    trace_proxy_test_reset(config);
    CHECK(trace_proxy_test_update(config, scene, module_named("module")));
    const size_t generation = trace_proxy_test_generation(scene.index);
    const std::shared_ptr<TraceGenerationRuntime> runtime =
            trace_proxy_test_hook_runtime(generation);
    CHECK(runtime != nullptr);
    runtime->set_test_hooks(TraceGenerationTestHooks{
            .before_admission_completion = &count_admission_completion,
    });
    {
        std::lock_guard<std::mutex> lock(g_gate_mutex);
        g_use_runner_gate = true;
    }
    g_runner_acknowledges_stop = true;

    uint64_t args[8]{13};
    uint64_t result = 0;
    std::thread entrant([&] {
        result = trace_proxy_dispatch(generation, args, 0);
    });
    {
        std::unique_lock<std::mutex> lock(g_gate_mutex);
        g_gate_condition.wait(lock, [] { return g_runner_entered; });
    }
    CHECK(runtime->snapshot().active_calls == 1);
    CHECK(runtime->request_stop(TraceStopReason::DurationElapsed));
    {
        std::lock_guard<std::mutex> lock(g_gate_mutex);
        g_release_runner = true;
    }
    g_gate_condition.notify_all();
    entrant.join();

    CHECK(result == 0x20D);
    CHECK(runtime->snapshot().active_calls == 0);
    CHECK(runtime->snapshot().phase == TraceGenerationPhase::Sealed);
    CHECK(g_admission_completion_calls.load(std::memory_order_relaxed) == 1);
}

void stopped_dormant_hook_never_attempts_a_failing_unhook() {
    reset_fakes();
    const TraceConfig config = config_named("dormant-unhook");
    const SceneConfig scene = scene_named(
            "dormant-unhook", reinterpret_cast<uintptr_t>(new_target));
    trace_proxy_test_reset(config);
    g_original_override = reinterpret_cast<uintptr_t>(old_target);
    CHECK(trace_proxy_test_update(config, scene, module_named("module")));
    const size_t generation = trace_proxy_test_generation(scene.index);
    const std::shared_ptr<TraceGenerationRuntime> runtime =
            trace_proxy_test_hook_runtime(generation);
    CHECK(runtime->request_stop(TraceStopReason::DurationElapsed));
    g_fail_unhook = true;

    uint64_t args[8]{17};
    CHECK(trace_proxy_dispatch(generation, args, 0) == 0x111);
    CHECK(g_runner_calls == 0);
    CHECK(g_unhook_calls == 0);
    CHECK(runtime->snapshot().active_calls == 0);
}

void old_generation_deadline_cannot_stop_a_newer_generation() {
    reset_fakes();
    TraceConfig old_config = config_named("old-timed-generation");
    old_config.session.id = "2d865e2f-c3ee-4186-8703-92b5c125b545";
    old_config.session.duration_ms = 25;
    const SceneConfig old_scene = scene_named(
            "old-timed-generation", reinterpret_cast<uintptr_t>(old_target));
    trace_proxy_test_reset(config_named("timer-isolation-reset"));
    CHECK(trace_proxy_test_update(old_config, old_scene,
                                  module_named("old-module")));
    const std::shared_ptr<TraceGenerationRuntime> old_runtime =
            trace_proxy_test_hook_runtime(
                    trace_proxy_test_generation(old_scene.index));
    CHECK(old_runtime != nullptr);

    TraceConfig new_config = config_named("new-monitor-generation");
    const SceneConfig new_scene = scene_named(
            "new-monitor-generation", reinterpret_cast<uintptr_t>(new_target));
    CHECK(trace_proxy_test_update(new_config, new_scene,
                                  module_named("new-module")));
    const size_t new_generation = trace_proxy_test_generation(new_scene.index);
    const std::shared_ptr<TraceGenerationRuntime> new_runtime =
            trace_proxy_test_hook_runtime(new_generation);
    CHECK(new_runtime != nullptr);
    CHECK(new_runtime != old_runtime);

    old_runtime->join_deadline_for_test();
    CHECK(old_runtime->stop_token().requested());
    CHECK(old_runtime->snapshot().phase == TraceGenerationPhase::Sealed);
    CHECK(new_runtime->snapshot().phase == TraceGenerationPhase::Running);
    uint64_t args[8]{19};
    CHECK(trace_proxy_dispatch(new_generation, args, 0) == 0x213);
    CHECK(g_runner_calls == 1);
    CHECK(new_runtime->snapshot().phase == TraceGenerationPhase::Running);
}

void unhook_failure_uses_the_saved_original_exactly_once() {
    reset_fakes();
    const TraceConfig config = config_named("unhook-failure");
    const SceneConfig scene = scene_named("unhook-failure",
                                          reinterpret_cast<uintptr_t>(old_target));
    trace_proxy_test_reset(config);
    CHECK(trace_proxy_test_update(config, scene, module_named("module")));
    g_fail_unhook = true;

    uint64_t args[8]{9};
    CHECK(trace_proxy_dispatch(0, args, 0x1234) == 0x109);
    CHECK(g_old_calls == 1);
    CHECK(g_bridge_calls == 1);
    CHECK(g_runner_calls == 0);
    CHECK(g_unhook_calls == 1);
}

void rehook_failure_leaves_a_coherent_direct_execution_state() {
    reset_fakes();
    const TraceConfig config = config_named("rehook-failure");
    const SceneConfig scene = scene_named("rehook-failure",
                                          reinterpret_cast<uintptr_t>(old_target));
    trace_proxy_test_reset(config);
    CHECK(trace_proxy_test_update(config, scene, module_named("module")));
    g_fail_next_hook = true;

    uint64_t args[8]{11};
    CHECK(trace_proxy_dispatch(0, args, 0) == 0x10b);
    CHECK(g_old_calls == 1);
    CHECK(trace_proxy_dispatch(0, args, 0) == 0x10b);
    CHECK(g_old_calls == 2);
    CHECK(g_new_calls == 0);
}

void every_physical_rehook_gets_a_new_proxy_identity() {
    reset_fakes();
    const TraceConfig config = config_named("physical-rehook-generation");
    const SceneConfig scene = scene_named("physical-rehook-generation",
                                          reinterpret_cast<uintptr_t>(old_target));
    trace_proxy_test_reset(config);
    CHECK(trace_proxy_test_update(config, scene, module_named("module")));
    const size_t first_generation = trace_proxy_test_generation(scene.index);
    const std::shared_ptr<TraceGenerationRuntime> runtime =
            trace_proxy_test_hook_runtime(first_generation);
    CHECK(runtime != nullptr);
    uint64_t args[8]{19};
    CHECK(trace_proxy_dispatch(first_generation, args, 0) == 0x113);
    const size_t second_generation = trace_proxy_test_generation(scene.index);
    CHECK(second_generation != first_generation);
    CHECK(g_hook_calls == 2);
    CHECK(trace_proxy_test_hook_runtime(first_generation) == nullptr);
    CHECK(trace_proxy_test_hook_runtime(second_generation) == runtime);

    // A delayed call already carrying the first identity remains valid and cannot
    // resolve the second generation.
    CHECK(trace_proxy_dispatch(first_generation, args, 0) == 0x113);
    CHECK(g_seen_config.package_name == "physical-rehook-generation");
}

void hook_install_never_waits_for_the_linker_while_holding_the_registry() {
    reset_fakes();
    TraceConfig config = config_named("linker-lock-order");
    config.target_so = "liblinker-lock-order.so";
    const SceneConfig scene = scene_named(
            "linker-lock-order", reinterpret_cast<uintptr_t>(old_target));
    config.scenes.push_back(scene);
    trace_proxy_test_reset(config);
    const ModuleRange target = module_named(
            "/data/app/liblinker-lock-order.so");

    std::unique_lock<std::mutex> linker_lock(g_fake_linker_mutex);
    {
        std::lock_guard<std::mutex> gate_lock(g_gate_mutex);
        g_block_hook_on_linker = true;
    }
    ::alarm(3);
    std::thread installer([&] {
        trace_proxy_test_install_loading_module(target);
    });
    {
        std::unique_lock<std::mutex> gate_lock(g_gate_mutex);
        g_gate_condition.wait(gate_lock, [] {
            return g_hook_waiting_for_linker;
        });
    }

    // Model a constructor callback running under bionic's linker lock. It must
    // be able to inspect an unrelated module so the hook installer can finish
    // its linker operation; waiting for the registry here creates AB-BA.
    trace_proxy_test_install_loading_module(
            module_named("/data/app/libunrelated.so"));
    linker_lock.unlock();
    installer.join();
    ::alarm(0);

    CHECK(g_hook_calls == 1);
    const size_t generation = trace_proxy_test_generation(scene.index);
    CHECK(generation != 4096);
    CHECK(trace_proxy_test_generation_installed(generation));
}

void module_fini_before_hook_commit_rolls_back_the_unpublished_gateway() {
    reset_fakes();
    trace_proxy_test_reset(config_named("hook-commit-retirement-reset"));
    char offset[2 * sizeof(uintptr_t) + 3]{};
    std::snprintf(offset, sizeof(offset), "0x%lx",
                  static_cast<unsigned long>(
                          reinterpret_cast<uintptr_t>(new_target)));
    const nlohmann::json accepted = call_json_configure(json_abi_request(
            "com.example.hook.commit.retirement",
            "libhook-commit-retirement.so", false, {},
            nlohmann::json::array({
                    {{"name", "entry"},
                     {"location", {{"offset", offset}}}},
            })));
    CHECK(accepted.at("ok") == true);
    const uint64_t configuration_generation =
            accepted.at("generation").get<uint64_t>();
    const ModuleRange module =
            module_named("/data/app/libhook-commit-retirement.so");
    g_original_override = reinterpret_cast<uintptr_t>(old_target);
    trace_proxy_test_set_hook_commit_gate(hook_commit_gate);

    ::alarm(3);
    std::thread installer([&] {
        trace_proxy_test_install_loading_module(module);
    });
    {
        std::unique_lock<std::mutex> lock(g_gate_mutex);
        g_gate_condition.wait(lock, [] { return g_hook_commit_entered; });
    }
    const size_t proxy_generation = trace_proxy_test_generation(0);
    CHECK(proxy_generation != 4096);

    // Model the exact loader ordering: the DSO is retired after the physical
    // ShadowHook succeeds but before the installer can commit that gateway to
    // the authoritative registry/status snapshot.
    trace_proxy_test_module_fini(module.start, module.path.c_str());
    {
        std::lock_guard<std::mutex> lock(g_gate_mutex);
        g_release_hook_commit = true;
    }
    g_gate_condition.notify_all();
    installer.join();
    trace_proxy_test_set_hook_commit_gate(nullptr);
    ::alarm(0);

    CHECK(call_json_status(configuration_generation).at("state") ==
          "hook_failed");
    CHECK(trace_proxy_test_generation_retired(proxy_generation));
    CHECK(!trace_proxy_test_generation_installed(proxy_generation));
    CHECK(g_hook_calls == 1);
    CHECK(g_unhook_calls == 1);
    uint64_t args[8]{23};
    CHECK(trace_proxy_dispatch(proxy_generation, args, 0) == 0x117);
    CHECK(g_runner_calls == 0);
}

void stale_rollback_failure_stays_authoritative_until_cleanup_succeeds() {
    reset_fakes();
    trace_proxy_test_reset(config_named("stale-residual-reset"));
    char offset[2 * sizeof(uintptr_t) + 3]{};
    std::snprintf(offset, sizeof(offset), "0x%lx",
                  static_cast<unsigned long>(
                          reinterpret_cast<uintptr_t>(new_target)));
    const nlohmann::json accepted = call_json_configure(json_abi_request(
            "com.example.stale.residual", "libstale-residual.so", false, {},
            nlohmann::json::array({
                    {{"name", "entry"},
                     {"location", {{"offset", offset}}}},
            })));
    const uint64_t failed_configuration =
            accepted.at("generation").get<uint64_t>();
    const ModuleRange module =
            module_named("/data/app/libstale-residual.so");
    g_original_override = reinterpret_cast<uintptr_t>(old_target);
    trace_proxy_test_set_hook_commit_gate(hook_commit_gate);

    std::thread installer([&] {
        trace_proxy_test_install_loading_module(module);
    });
    {
        std::unique_lock<std::mutex> lock(g_gate_mutex);
        g_gate_condition.wait(lock, [] { return g_hook_commit_entered; });
    }
    const size_t residual_generation = trace_proxy_test_generation(0);
    CHECK(residual_generation != 4096);
    trace_proxy_test_module_fini(module.start, module.path.c_str());
    g_fail_unhook = true;
    g_unhook_failure_error = 91;
    {
        std::lock_guard<std::mutex> lock(g_gate_mutex);
        g_block_unhook_return = true;
        g_release_hook_commit = true;
    }
    g_gate_condition.notify_all();
    {
        std::unique_lock<std::mutex> lock(g_gate_mutex);
        g_gate_condition.wait(lock, [] { return g_unhook_return_entered; });
    }

    // The stale slot remains the sole physical owner while ShadowHook is
    // unlocked. A loader retry must neither install nor publish a terminal.
    std::thread reentrant_loader([&] {
        trace_proxy_test_install_loading_module(module);
    });
    reentrant_loader.join();
    CHECK(g_hook_calls == 1);
    CHECK(call_json_status(failed_configuration).at("state") == "installing");
    {
        std::lock_guard<std::mutex> lock(g_gate_mutex);
        g_release_unhook_return = true;
    }
    g_gate_condition.notify_all();
    installer.join();
    trace_proxy_test_set_hook_commit_gate(nullptr);

    const nlohmann::json failed = call_json_status(failed_configuration);
    CHECK(failed.at("state") == "rollback_failed");
    CHECK(failed.at("scenes").at(0).at("state") == "rollback_failed");
    CHECK(failed.at("scenes").at(0).at("error").at("code") ==
          "HOOK_ROLLBACK_FAILED");
    CHECK(failed.at("scenes").at(0).at("error").at("hookError") == 91);
    CHECK(trace_proxy_test_generation_retired(residual_generation));
    CHECK(trace_proxy_test_generation_installed(residual_generation));
    uint64_t args[8]{31};
    CHECK(trace_proxy_dispatch(residual_generation, args, 0) == 0x11f);
    CHECK(g_runner_calls == 0);

    const pid_t child = ::fork();
    CHECK(child >= 0);
    if (child == 0) {
        const uint64_t child_result =
                trace_proxy_dispatch(residual_generation, args, 0);
        ::_exit(child_result == 0x11f ? 0 : 1);
    }
    int child_status = 0;
    CHECK(::waitpid(child, &child_status, 0) == child);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);

    // A loader retry must retry residual cleanup, never install a second
    // physical gateway while the first handle is still owned.
    trace_proxy_test_install_loading_module(module);
    CHECK(g_unhook_calls == 2);
    CHECK(g_hook_calls == 1);
    CHECK(trace_proxy_test_generation_installed(residual_generation));

    g_fail_inline_hook_init = true;
    const nlohmann::json replacement = call_json_configure(json_abi_request(
            "com.example.stale.residual.replacement", "libstale-residual.so",
            false, {}, nlohmann::json::array({
                    {{"name", "replacement"},
                     {"location", {{"offset", offset}}}},
            })));
    const uint64_t replacement_generation =
            replacement.at("generation").get<uint64_t>();
    const nlohmann::json replacement_status =
            call_json_status(replacement_generation);
    CHECK(replacement_status.at("state") == "rollback_failed");
    CHECK(replacement_status.at("scenes").at(0).at("state") ==
          "rollback_failed");
    CHECK(replacement_status.at("scenes").at(0).at("error").at("code") ==
          "HOOK_ROLLBACK_FAILED");
    CHECK(g_unhook_calls == 3);
    CHECK(g_hook_calls == 1);

    g_fail_unhook = false;
    trace_proxy_test_install_loading_module(module);
    CHECK(call_json_status(replacement_generation).at("state") ==
          "rollback_failed");
    CHECK(g_unhook_calls == 4);
    CHECK(g_hook_calls == 1);

    const nlohmann::json recovered = call_json_configure(json_abi_request(
            "com.example.stale.residual.recovered", "libstale-residual.so",
            false, {}, nlohmann::json::array({
                    {{"name", "recovered"},
                     {"location", {{"offset", offset}}}},
            })));
    const uint64_t recovered_generation =
            recovered.at("generation").get<uint64_t>();
    trace_proxy_test_install_loading_module(module);
    CHECK(call_json_status(recovered_generation).at("state") == "installed");
    CHECK(g_unhook_calls == 4);
    CHECK(g_hook_calls == 2);
    CHECK(!trace_proxy_test_generation_installed(residual_generation));
    CHECK(trace_proxy_test_generation_installed(
            trace_proxy_test_generation(0)));
}

void stale_rollback_lock_order_child() {
    ::alarm(3);
    reset_fakes();
    trace_proxy_test_reset(config_named("stale-rollback-lock-order-reset"));
    char offset[2 * sizeof(uintptr_t) + 3]{};
    std::snprintf(offset, sizeof(offset), "0x%lx",
                  static_cast<unsigned long>(
                          reinterpret_cast<uintptr_t>(new_target)));
    const nlohmann::json accepted = call_json_configure(json_abi_request(
            "com.example.stale.rollback.lock.order",
            "libstale-rollback-lock-order.so", false, {},
            nlohmann::json::array({
                    {{"name", "entry"},
                     {"location", {{"offset", offset}}}},
            })));
    CHECK(accepted.at("ok") == true);
    const ModuleRange module =
            module_named("/data/app/libstale-rollback-lock-order.so");
    g_original_override = reinterpret_cast<uintptr_t>(old_target);
    trace_proxy_test_set_hook_commit_gate(hook_commit_gate);

    std::thread installer([&] {
        trace_proxy_test_install_loading_module(module);
    });
    {
        std::unique_lock<std::mutex> lock(g_gate_mutex);
        g_gate_condition.wait(lock, [] { return g_hook_commit_entered; });
    }
    const size_t proxy_generation = trace_proxy_test_generation(0);
    CHECK(proxy_generation != 4096);
    trace_proxy_test_module_fini(module.start, module.path.c_str());
    trace_proxy_test_set_registry_transition_gate(registry_transition_gate);
    {
        std::lock_guard<std::mutex> lock(g_gate_mutex);
        g_block_unhook_return = true;
        g_release_hook_commit = true;
    }
    g_gate_condition.notify_all();
    {
        std::unique_lock<std::mutex> lock(g_gate_mutex);
        g_gate_condition.wait(lock, [] { return g_unhook_return_entered; });
    }

    // The callback owns g_lock before it waits for the stale slot's
    // transition. Releasing both deterministic barriers recreates the old
    // transition->g_lock / g_lock->transition cycle without sleeps.
    std::thread callback([&] {
        trace_proxy_test_module_fini(module.start, module.path.c_str());
    });
    {
        std::unique_lock<std::mutex> lock(g_gate_mutex);
        g_gate_condition.wait(lock, [] {
            return g_registry_transition_entered;
        });
        g_release_unhook_return = true;
        g_release_registry_transition = true;
    }
    g_gate_condition.notify_all();
    installer.join();
    callback.join();
    trace_proxy_test_set_registry_transition_gate(nullptr);
    trace_proxy_test_set_hook_commit_gate(nullptr);
    CHECK(g_unhook_calls == 1);
    CHECK(trace_proxy_test_generation_retired(proxy_generation));
    CHECK(!trace_proxy_test_generation_installed(proxy_generation));
    uint64_t args[8]{29};
    CHECK(trace_proxy_dispatch(proxy_generation, args, 0) == 0x11d);
    CHECK(g_runner_calls == 0);
    ::alarm(0);
}

void stale_rollback_never_inverts_registry_and_transition_locks() {
    const pid_t child = ::fork();
    CHECK(child >= 0);
    if (child == 0) {
        ::execl("/proc/self/exe", "tracer_entry_proxy_test",
                "stale-rollback-lock-order-child", nullptr);
        ::_exit(127);
    }

    int status = 0;
    CHECK(::waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

void physical_rehook_keeps_its_original_capture_coordinator() {
    reset_fakes();
    const TraceConfig config = config_named("coordinator-generation");
    const SceneConfig scene = scene_named(
            "coordinator-generation", reinterpret_cast<uintptr_t>(old_target));
    trace_proxy_test_reset(config);
    const std::shared_ptr<CaptureCoordinator> original =
            std::make_shared<CaptureCoordinator>();
    const std::shared_ptr<CaptureCoordinator> replacement =
            std::make_shared<CaptureCoordinator>();
    trace_proxy_test_set_coordinator(original);
    CHECK(trace_proxy_test_update(config, scene, module_named("module")));
    const size_t first_generation = trace_proxy_test_generation(scene.index);
    CHECK(trace_proxy_test_hook_coordinator(first_generation) == original.get());

    trace_proxy_test_set_coordinator(replacement);
    uint64_t args[8]{41};
    CHECK(trace_proxy_dispatch(first_generation, args, 0) == 0x129);
    const size_t second_generation = trace_proxy_test_generation(scene.index);

    CHECK(second_generation != first_generation);
    CHECK(trace_proxy_test_hook_coordinator(first_generation) == nullptr);
    CHECK(trace_proxy_test_hook_coordinator(second_generation) == original.get());
}

void concurrent_unhook_failures_keep_the_original_bypass_alive() {
    reset_fakes();
    const TraceConfig config = config_named("concurrent-unhook-failure");
    const SceneConfig scene = scene_named("concurrent-unhook-failure",
                                          reinterpret_cast<uintptr_t>(old_target));
    trace_proxy_test_reset(config);
    CHECK(trace_proxy_test_update(config, scene, module_named("module")));
    g_fail_unhook = true;
    {
        std::lock_guard<std::mutex> lock(g_gate_mutex);
        g_use_bridge_gate = true;
    }

    uint64_t args[8]{13};
    uint64_t first_result = 0;
    uint64_t second_result = 0;
    std::thread first([&] { first_result = trace_proxy_dispatch(0, args, 0); });
    {
        std::unique_lock<std::mutex> lock(g_gate_mutex);
        g_gate_condition.wait(lock, [] { return g_bridge_gate_entries == 1; });
    }
    std::thread second([&] { second_result = trace_proxy_dispatch(0, args, 0); });
    {
        std::unique_lock<std::mutex> lock(g_gate_mutex);
        g_gate_condition.wait(lock, [] { return g_bridge_gate_entries == 2; });
    }
    {
        std::lock_guard<std::mutex> lock(g_fake_mutex);
        CHECK(g_unhook_calls == 1);
    }
    {
        std::lock_guard<std::mutex> lock(g_gate_mutex);
        g_release_bridge = true;
    }
    g_gate_condition.notify_all();
    first.join();
    second.join();
    CHECK(first_result == 0x10d);
    CHECK(second_result == 0x10d);
    CHECK(g_old_calls == 2);
}

void same_address_updates_replace_all_metadata_and_hook_generation() {
    reset_fakes();
    TraceConfig first_config = config_named("first-config");
    SceneConfig first_scene = scene_named("first", reinterpret_cast<uintptr_t>(old_target));
    trace_proxy_test_reset(first_config);
    CHECK(trace_proxy_test_update(first_config, first_scene, module_named("first-module")));
    const size_t initial_hook_calls = g_hook_calls;

    TraceConfig second_config = config_named("second-config");
    SceneConfig second_scene = scene_named("second", reinterpret_cast<uintptr_t>(old_target));
    second_scene.end_offset += 0x40;
    CHECK(trace_proxy_test_update(second_config, second_scene,
                                   module_named("reloaded-module", UINTPTR_MAX)));
    CHECK(g_hook_calls == initial_hook_calls + 1);
    CHECK(g_unhook_calls == 1);

    uint64_t args[8]{3};
    CHECK(trace_proxy_dispatch(trace_proxy_test_generation(second_scene.index), args, 0) ==
          0x103);
    CHECK(g_seen_config.package_name == "second-config");
    CHECK(g_seen_invocation.scene->name == "second");
    CHECK(g_seen_invocation.scene->end_offset == second_scene.end_offset);
    CHECK(g_seen_invocation.module->path == "reloaded-module");
    CHECK(g_seen_invocation.module->end == UINTPTR_MAX);
}

void duplicate_install_for_one_configuration_generation_is_idempotent() {
    reset_fakes();
    const TraceConfig config = config_named("one-generation");
    const SceneConfig scene = scene_named("one-generation",
                                          reinterpret_cast<uintptr_t>(old_target));
    const ModuleRange module = module_named("same-module");
    trace_proxy_test_reset(config);

    CHECK(trace_proxy_test_repeat_current_install(scene, module));
    const size_t generation = trace_proxy_test_generation(scene.index);
    CHECK(trace_proxy_test_repeat_current_install(scene, module));

    CHECK(trace_proxy_test_generation(scene.index) == generation);
    CHECK(g_hook_calls == 1);
    CHECK(g_unhook_calls == 0);
}

void failed_same_generation_install_is_retried() {
    reset_fakes();
    const TraceConfig config = config_named("retry-generation");
    const SceneConfig scene = scene_named("retry-generation",
                                          reinterpret_cast<uintptr_t>(old_target));
    const ModuleRange module = module_named("retry-module");
    trace_proxy_test_reset(config);
    g_fail_next_hook = true;

    CHECK(!trace_proxy_test_repeat_current_install(scene, module));
    const size_t failed_generation = trace_proxy_test_generation(scene.index);
    CHECK(trace_proxy_test_repeat_current_install(scene, module));

    CHECK(g_hook_calls == 2);
    CHECK(trace_proxy_test_generation(scene.index) != failed_generation);
}

void duplicate_during_an_active_call_schedules_only_the_required_rehook() {
    reset_fakes();
    const TraceConfig config = config_named("active-duplicate");
    const SceneConfig scene = scene_named("active-duplicate",
                                          reinterpret_cast<uintptr_t>(old_target));
    const ModuleRange module = module_named("active-module");
    trace_proxy_test_reset(config);
    CHECK(trace_proxy_test_repeat_current_install(scene, module));
    const size_t first_generation = trace_proxy_test_generation(scene.index);
    {
        std::lock_guard<std::mutex> lock(g_gate_mutex);
        g_use_runner_gate = true;
    }

    uint64_t args[8]{23};
    uint64_t result = 0;
    std::thread active([&] { result = trace_proxy_dispatch(first_generation, args, 0); });
    {
        std::unique_lock<std::mutex> lock(g_gate_mutex);
        g_gate_condition.wait(lock, [] { return g_runner_entered; });
    }
    CHECK(trace_proxy_test_repeat_current_install(scene, module));
    {
        std::lock_guard<std::mutex> lock(g_gate_mutex);
        g_release_runner = true;
    }
    g_gate_condition.notify_all();
    active.join();

    CHECK(result == 0x117);
    CHECK(g_hook_calls == 2);
    CHECK(g_unhook_calls == 1);
    CHECK(trace_proxy_test_generation(scene.index) != first_generation);
}

void batch_reconfiguration_stays_installing_until_pending_rehook_succeeds() {
    reset_fakes();
    TraceConfig old_config = config_named("active-batch-old");
    old_config.target_so = "libactive-batch.so";
    const SceneConfig old_scene = scene_named(
            "entry", reinterpret_cast<uintptr_t>(old_target));
    const ModuleRange module = module_named("/data/app/libactive-batch.so");
    trace_proxy_test_reset(old_config);
    CHECK(trace_proxy_test_update(old_config, old_scene, module));
    const size_t old_generation = trace_proxy_test_generation(old_scene.index);
    const std::shared_ptr<TraceGenerationRuntime> old_runtime =
            trace_proxy_test_hook_runtime(old_generation);
    {
        std::lock_guard<std::mutex> lock(g_gate_mutex);
        g_use_runner_gate = true;
    }

    uint64_t args[8]{29};
    uint64_t result = 0;
    std::thread active([&] {
        result = trace_proxy_dispatch(old_generation, args, 0);
    });
    {
        std::unique_lock<std::mutex> lock(g_gate_mutex);
        g_gate_condition.wait(lock, [] { return g_runner_entered; });
    }

    char offset[2 * sizeof(uintptr_t) + 3]{};
    std::snprintf(offset, sizeof(offset), "0x%lx",
                  static_cast<unsigned long>(
                          reinterpret_cast<uintptr_t>(old_target)));
    const nlohmann::json accepted = call_json_configure(json_abi_request(
            "com.example.active-batch", "libactive-batch.so", false, {},
            nlohmann::json::array({
                    {{"name", "entry"},
                     {"location", {{"offset", offset}}}},
            })));
    const uint64_t config_generation =
            accepted.at("generation").get<uint64_t>();
    const std::shared_ptr<TraceGenerationRuntime> pending_runtime =
            trace_proxy_test_current_runtime();
    CHECK(pending_runtime != nullptr);
    CHECK(pending_runtime != old_runtime);
    trace_proxy_test_install_loading_module(module);

    CHECK(call_json_status(config_generation).at("state") == "installing");

    {
        std::lock_guard<std::mutex> lock(g_gate_mutex);
        g_release_runner = true;
    }
    g_gate_condition.notify_all();
    active.join();

    CHECK(result == 0x11d);
    CHECK(call_json_status(config_generation).at("state") == "installed");
    CHECK(trace_proxy_test_hook_runtime(old_generation) == nullptr);
    CHECK(trace_proxy_test_hook_runtime(
                  trace_proxy_test_generation(old_scene.index)) ==
          pending_runtime);
    CHECK(g_hook_calls == 2);
    CHECK(g_unhook_calls == 1);
}

void superseded_pending_runtime_is_destroyed_outside_generation_locks() {
    reset_fakes();
    TraceConfig old_config = config_named("pending-release-old");
    old_config.target_so = "libpending-release-old.so";
    const SceneConfig old_scene = scene_named(
            "entry", reinterpret_cast<uintptr_t>(old_target));
    const ModuleRange old_module = module_named(
            "/data/app/libpending-release-old.so");
    trace_proxy_test_reset(old_config);
    CHECK(trace_proxy_test_update(old_config, old_scene, old_module));
    const size_t old_generation = trace_proxy_test_generation(old_scene.index);
    {
        std::lock_guard<std::mutex> lock(g_gate_mutex);
        g_use_runner_gate = true;
    }
    uint64_t args[8]{31};
    std::thread active([&] {
        CHECK(trace_proxy_dispatch(old_generation, args, 0) == 0x11f);
    });
    {
        std::unique_lock<std::mutex> lock(g_gate_mutex);
        g_gate_condition.wait(lock, [] { return g_runner_entered; });
    }

    nlohmann::json request_a = nlohmann::json::parse(json_abi_request(
            "com.example.pending-a", "libpending-release-a.so", false, {},
            nlohmann::json::array({
                    {{"name", "entry"},
                     {"location", {{"offset", "0x40"}}}},
            })));
    request_a["session"] = {
            {"id", "7d5807cf-cf09-4f21-92de-1ad92802610a"},
            {"durationMs", 60000},
    };
    const uint64_t generation_a = call_json_configure(request_a.dump())
                                          .at("generation")
                                          .get<uint64_t>();
    trace_proxy_test_install_loading_module(module_named(
            "/data/app/libpending-release-a.so"));
    CHECK(call_json_status(generation_a).at("state") == "installing");
    std::shared_ptr<TraceGenerationRuntime> runtime_a =
            trace_proxy_test_current_runtime();
    CHECK(runtime_a != nullptr);
    CHECK(runtime_a->snapshot().phase == TraceGenerationPhase::Waiting);
    RuntimeReleaseLockProbe probe{};
    probe.hook_generation = old_generation;
    runtime_a->set_test_hooks(TraceGenerationTestHooks{
            .opaque = &probe,
            .before_worker_join = &RuntimeReleaseLockProbe::before_worker_join,
    });
    CHECK(runtime_a->arm());
    std::weak_ptr<TraceGenerationRuntime> weak_runtime_a = runtime_a;

    const nlohmann::json accepted_b = call_json_configure(json_abi_request(
            "com.example.pending-b", "libpending-release-b-never-loaded.so",
            false, {}, nlohmann::json::array({
                    {{"name", "entry"},
                     {"location", {{"offset", "0x80"}}}},
            })));
    const uint64_t generation_b =
            accepted_b.at("generation").get<uint64_t>();
    runtime_a.reset();
    uint64_t current_generation = 0;
    TraceConfig current_config;
    CHECK(trace_proxy_test_current_configuration(&current_generation,
                                                 &current_config));
    CHECK(current_generation == generation_b);

    std::thread lock_checker([&] {
        while (!probe.requested.load(std::memory_order_acquire)) {
            ::sched_yield();
        }
        probe.locks_available.store(
                trace_proxy_test_generation_locks_available(
                        probe.hook_generation),
                std::memory_order_release);
        probe.checked.store(true, std::memory_order_release);
    });
    {
        std::lock_guard<std::mutex> lock(g_gate_mutex);
        g_release_runner = true;
    }
    g_gate_condition.notify_all();
    active.join();
    lock_checker.join();

    CHECK(probe.locks_available.load(std::memory_order_acquire));
    CHECK(weak_runtime_a.expired());
    CHECK(g_hook_calls == 1);
    CHECK(trace_proxy_test_current_configuration(&current_generation,
                                                 &current_config));
    CHECK(current_generation == generation_b);
    CHECK(call_json_status(generation_b).at("state") ==
          "waiting_for_module");
}

void observer_module_is_normalized_to_load_bias_and_exact_readable_exec_map() {
    reset_fakes();
    ModuleRange read_only;
    read_only.start = 0x70000000;
    read_only.end = 0x70001000;
    read_only.file_offset = 0;
    read_only.permissions = "r--p";
    read_only.path = "/data/app/libtarget.so";
    ModuleRange execute_only;
    execute_only.start = 0x70001000;
    execute_only.end = 0x70002000;
    execute_only.file_offset = 0x1000;
    execute_only.permissions = "--xp";
    execute_only.path = read_only.path;
    ModuleRange executable;
    executable.start = 0x70002000;
    executable.end = 0x70004000;
    executable.file_offset = 0x2000;
    executable.permissions = "r-xp";
    executable.path = read_only.path;
    g_fake_maps = {read_only, execute_only, executable};

    ModuleRange normalized;
    CHECK(normalize_module_ranges(g_fake_maps, executable.path, 0x70000000, 0x4000,
                                  &normalized));
    CHECK(normalized.start == 0x70000000);
    CHECK(normalized.end == 0x70004000);
    CHECK(normalized.readable_executable_range_count == 1);
    CHECK(normalized.readable_executable_ranges[0].start == 0x70002000);
    CHECK(normalized.readable_executable_ranges[0].end == 0x70004000);
    CHECK(normalized.path == executable.path);

    ModuleRange detached;
    CHECK(normalize_module_ranges(g_fake_maps, "libtarget.so", 0, 0, &detached));
    CHECK(detached.start == normalized.start);
    CHECK(detached.end == normalized.end);
    CHECK(detached.readable_executable_range_count ==
          normalized.readable_executable_range_count);

    // Android's loader may include a trailing anonymous BSS page in
    // Module.size. Observer hints validate the mapping, but must not change
    // the retained generation identity compared with /proc/self/maps polling.
    ModuleRange observer_with_anonymous_tail;
    CHECK(normalize_module_ranges(g_fake_maps, executable.path, 0x70000000, 0x5000,
                                  &observer_with_anonymous_tail));
    CHECK(observer_with_anonymous_tail.end == detached.end);

    CHECK(!normalize_module_ranges(g_fake_maps, executable.path, UINTPTR_MAX - 1U, 4,
                                   &normalized));

    ModuleRange outside_observer = executable;
    outside_observer.start = 0x70004000;
    outside_observer.end = 0x70005000;
    outside_observer.file_offset = 0x4000;
    g_fake_maps.push_back(outside_observer);
    CHECK(!normalize_module_ranges(g_fake_maps, executable.path, 0x70000000, 0x4000,
                                   &normalized));
    g_fake_maps.pop_back();

    ModuleRange duplicate = executable;
    duplicate.start = 0x71002000;
    duplicate.end = 0x71004000;
    duplicate.path = "/other/libtarget.so";
    g_fake_maps.push_back(duplicate);
    CHECK(!normalize_module_ranges(g_fake_maps, "libtarget.so", 0, 0, &normalized));
}

void constructor_phdr_range_uses_load_bias_and_preserves_executable_segments() {
    const std::array<ElfW(Phdr), 3> headers{{
            {.p_type = PT_LOAD, .p_flags = PF_R, .p_offset = 0,
             .p_vaddr = 0, .p_paddr = 0, .p_filesz = 0,
             .p_memsz = 0x800, .p_align = 0},
            {.p_type = PT_LOAD, .p_flags = PF_R | PF_X, .p_offset = 0x1000,
             .p_vaddr = 0x3000, .p_paddr = 0, .p_filesz = 0,
             .p_memsz = 0x801, .p_align = 0},
            {.p_type = PT_LOAD, .p_flags = PF_X, .p_offset = 0x2000,
             .p_vaddr = 0x6000, .p_paddr = 0, .p_filesz = 0,
             .p_memsz = 0x1001, .p_align = 0},
    }};
    dl_phdr_info info{};
    info.dlpi_addr = 0x71000000;
    info.dlpi_name = "/data/app/example/libflight-proxy.so";
    info.dlpi_phdr = headers.data();
    info.dlpi_phnum = headers.size();

    ModuleRange module;
    CHECK(module_range_from_phdr(info, &module));
    CHECK(module.start == 0x71000000);
    CHECK(module.end == 0x71008000);
    CHECK(module.path == info.dlpi_name);
    CHECK(module.readable_executable_range_count == 2);
    CHECK(module.readable_executable_ranges[0].start == 0x71003000);
    CHECK(module.readable_executable_ranges[0].end == 0x71003801);
    CHECK(module.readable_executable_ranges[1].start == 0x71006000);
    CHECK(module.readable_executable_ranges[1].end == 0x71007001);
}

void constructor_phdr_range_rejects_invalid_or_unrepresentable_loads() {
    dl_phdr_info info{};
    info.dlpi_addr = 0x71000000;
    info.dlpi_name = "/data/app/example/libflight-proxy.so";
    ModuleRange module;

    const std::array<ElfW(Phdr), 1> missing{{
            {.p_type = PT_NOTE, .p_flags = 0, .p_offset = 0,
             .p_vaddr = 0, .p_paddr = 0, .p_filesz = 0,
             .p_memsz = 0x100, .p_align = 0},
    }};
    info.dlpi_phdr = missing.data();
    info.dlpi_phnum = missing.size();
    CHECK(!module_range_from_phdr(info, &module));

    const std::array<ElfW(Phdr), 1> segment_overflow{{
            {.p_type = PT_LOAD, .p_flags = PF_X,
             .p_offset = 0, .p_vaddr = UINTPTR_MAX - 0x80U,
             .p_paddr = 0, .p_filesz = 0, .p_memsz = 0x100,
             .p_align = 0},
    }};
    info.dlpi_phdr = segment_overflow.data();
    info.dlpi_phnum = segment_overflow.size();
    CHECK(!module_range_from_phdr(info, &module));

    const std::array<ElfW(Phdr), 1> base_overflow{{
            {.p_type = PT_LOAD, .p_flags = PF_X,
             .p_offset = 0, .p_vaddr = 0x1000, .p_paddr = 0,
             .p_filesz = 0, .p_memsz = 0x1000, .p_align = 0},
    }};
    info.dlpi_addr = UINTPTR_MAX - 0x1000U;
    info.dlpi_phdr = base_overflow.data();
    info.dlpi_phnum = base_overflow.size();
    CHECK(!module_range_from_phdr(info, &module));

    std::array<ElfW(Phdr), 9> executable{};
    for (size_t index = 0; index < executable.size(); ++index) {
        executable[index].p_type = PT_LOAD;
        executable[index].p_flags = PF_X;
        executable[index].p_vaddr = index * 0x1000;
        executable[index].p_memsz = 0x800;
    }
    info.dlpi_addr = 0x71000000;
    info.dlpi_phdr = executable.data();
    info.dlpi_phnum = executable.size();
    CHECK(!module_range_from_phdr(info, &module));
}

void outside_scene_warning_does_not_block_hook_installation() {
    reset_fakes();
    trace_proxy_test_reset(config_named("outside-warning-reset"));
    char directory_template[] = "/tmp/qtrace-install-warning-XXXXXX";
    char *directory = ::mkdtemp(directory_template);
    CHECK(directory != nullptr);
    trace_proxy_test_set_status_output_directory(directory);
    nlohmann::json request = nlohmann::json::parse(json_abi_request(
            "com.example.outsidewarning", "liboutside-warning.so", false, {},
            nlohmann::json::array({
                    {{"name", "outside"},
                     {"location", {{"offset", "0x200"}}}},
            })));
    request["session"] = {
            {"id", "7d5807cf-cf09-4f21-92de-1ad92802610a"},
            {"durationMs", 60000},
    };
    const nlohmann::json accepted = call_json_configure(request.dump());
    CHECK(accepted.at("ok") == true);
    CHECK(accepted.at("session").at("id") ==
          "7d5807cf-cf09-4f21-92de-1ad92802610a");
    const uint64_t generation = accepted.at("generation").get<uint64_t>();
    ModuleRange module;
    module.start = 0x71000000;
    module.end = module.start + 0x100;
    module.permissions = "r-xp";
    module.path = "/data/app/liboutside-warning.so";

    trace_proxy_test_install_loading_module(module);
    std::shared_ptr<TraceGenerationRuntime> runtime =
            trace_proxy_test_current_runtime();
    CHECK(runtime != nullptr);
    CHECK(runtime->snapshot().phase == TraceGenerationPhase::Running);
    CHECK(runtime->snapshot().status_error == 0);

    const nlohmann::json snapshot = call_json_status(generation);
    CHECK(g_hook_calls == 1);
    CHECK(g_hook_targets.at(0) == module.start + 0x200);
    CHECK(snapshot.at("state") == "installed");
    CHECK(snapshot.at("scenes").at(0).at("state") == "installed");
    CHECK(snapshot.at("scenes").at(0).at("runtimeAddress") == "0x71000200");
    bool found_outside_warning = false;
    for (const auto &warning : snapshot.at("scenes").at(0).at("warnings")) {
        if (warning.at("code") == "ADDRESS_OUTSIDE_TARGET_MODULE") {
            found_outside_warning = true;
        }
    }
    CHECK(found_outside_warning);

    const std::string status_path =
            std::string(directory) +
            "/session-7d5807cf-cf09-4f21-92de-1ad92802610a.status.json";
    nlohmann::json authoritative;
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline) {
        std::ifstream input(status_path);
        if (input) {
            const std::string text{std::istreambuf_iterator<char>(input),
                                   std::istreambuf_iterator<char>()};
            authoritative = nlohmann::json::parse(text, nullptr, false);
            if (authoritative.is_object() &&
                !authoritative.at("warnings").empty()) {
                break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    CHECK(authoritative.is_object());
    CHECK(authoritative.at("warnings").at(0).at("code") ==
          "ADDRESS_OUTSIDE_TARGET_MODULE");
    CHECK(authoritative.at("warnings").at(0).at("path") ==
          "$.scenes[0].location");

    trace_proxy_test_set_status_output_directory(nullptr);
    trace_proxy_test_reset(config_named("outside-warning-cleanup"));
    runtime.reset();
    CHECK(::unlink(status_path.c_str()) == 0);
    (void)::unlink((status_path + ".backup").c_str());
    (void)::unlink((status_path + ".restore").c_str());
    (void)::unlink((status_path + ".rollback").c_str());
    (void)::unlink((status_path + ".commit").c_str());
    CHECK(::rmdir(directory) == 0);
}

void authoritative_status_observes_installed_before_running() {
    reset_fakes();
    trace_proxy_test_reset(config_named("installed-status-order-reset"));
    char directory_template[] = "/tmp/qtrace-installed-order-XXXXXX";
    char *directory = ::mkdtemp(directory_template);
    CHECK(directory != nullptr);
    trace_proxy_test_set_status_output_directory(directory);
    trace_proxy_test_set_installed_status_gate(installed_status_gate);
    nlohmann::json request = nlohmann::json::parse(json_abi_request(
            "com.example.installedorder", "libinstalled-order.so", false,
            {}, nlohmann::json::array({
                        {{"name", "entry"},
                         {"location", {{"offset", "0x40"}}}},
                })));
    request["session"] = {
            {"id", "6f238851-b45e-4b89-9167-38cc7ef707f3"},
            {"durationMs", 60000},
    };
    const uint64_t generation = call_json_configure(request.dump())
                                        .at("generation")
                                        .get<uint64_t>();
    const ModuleRange module = module_named(
            "/data/app/libinstalled-order.so");
    std::thread installer([&] {
        trace_proxy_test_install_loading_module(module);
    });
    {
        std::unique_lock<std::mutex> lock(g_gate_mutex);
        g_gate_condition.wait(lock, [] { return g_installed_status_entered; });
    }
    const std::string path = std::string(directory) +
            "/session-6f238851-b45e-4b89-9167-38cc7ef707f3.status.json";
    {
        std::ifstream input(path);
        CHECK(input.good());
        const nlohmann::json installed = nlohmann::json::parse(input);
        CHECK(installed.at("generation") == generation);
        CHECK(installed.at("state") == "installed");
    }
    {
        std::lock_guard<std::mutex> lock(g_gate_mutex);
        g_release_installed_status = true;
    }
    g_gate_condition.notify_all();
    installer.join();

    nlohmann::json running;
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline) {
        std::ifstream input(path);
        if (input) {
            running = nlohmann::json::parse(input, nullptr, false);
            if (running.is_object() && running.at("state") == "running") {
                break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    CHECK(running.is_object());
    CHECK(running.at("state") == "running");

    trace_proxy_test_set_installed_status_gate(nullptr);
    trace_proxy_test_set_status_output_directory(nullptr);
    trace_proxy_test_reset(config_named("installed-status-order-cleanup"));
    CHECK(::unlink(path.c_str()) == 0);
    (void)::unlink((path + ".backup").c_str());
    (void)::unlink((path + ".restore").c_str());
    (void)::unlink((path + ".rollback").c_str());
    (void)::unlink((path + ".commit").c_str());
    CHECK(::rmdir(directory) == 0);
}

void second_hook_failure_rolls_back_the_batch_in_reverse() {
    reset_fakes();
    trace_proxy_test_reset(config_named("batch-failure-reset"));
    const nlohmann::json accepted = call_json_configure(json_abi_request(
            "com.example.batch-failure", "libbatch-failure.so", false, {},
            nlohmann::json::array({
                    {{"name", "first"}, {"location", {{"offset", "0x40"}}}},
                    {{"name", "second"}, {"location", {{"offset", "0x80"}}}},
            })));
    const uint64_t generation = accepted.at("generation").get<uint64_t>();
    g_fail_hook_call = 2;
    g_hook_failure_error = 73;
    ModuleRange module;
    module.start = 0x72000000;
    module.end = module.start + 0x1000;
    module.permissions = "r-xp";
    module.path = "/data/app/libbatch-failure.so";

    trace_proxy_test_install_loading_module(module);

    const nlohmann::json snapshot = call_json_status(generation);
    CHECK(snapshot.at("state") == "hook_failed");
    CHECK(snapshot.at("scenes").at(0).at("state") == "rolled_back");
    CHECK(snapshot.at("scenes").at(1).at("state") == "hook_failed");
    CHECK(snapshot.at("scenes").at(1).at("error").at("code") ==
          "HOOK_INSTALL_FAILED");
    CHECK(snapshot.at("scenes").at(1).at("error").at("hookError") == 73);
    CHECK(g_hook_calls == 2);
    CHECK(g_unhook_calls == 1);
    CHECK(!trace_proxy_test_generation_installed(
            trace_proxy_test_generation(0)));
}

void rollback_failure_reports_and_retains_the_residual_hook() {
    reset_fakes();
    trace_proxy_test_reset(config_named("rollback-failure-reset"));
    const nlohmann::json accepted = call_json_configure(json_abi_request(
            "com.example.rollback-failure", "librollback-failure.so", false, {},
            nlohmann::json::array({
                    {{"name", "first"}, {"location", {{"offset", "0x40"}}}},
                    {{"name", "second"}, {"location", {{"offset", "0x80"}}}},
            })));
    const uint64_t generation = accepted.at("generation").get<uint64_t>();
    g_fail_hook_call = 2;
    g_hook_failure_error = 73;
    g_fail_unhook = true;
    g_unhook_failure_error = 91;
    ModuleRange module;
    module.start = 0x73000000;
    module.end = module.start + 0x1000;
    module.permissions = "r-xp";
    module.path = "/data/app/librollback-failure.so";

    trace_proxy_test_install_loading_module(module);

    const nlohmann::json snapshot = call_json_status(generation);
    CHECK(snapshot.at("state") == "rollback_failed");
    CHECK(snapshot.at("scenes").at(0).at("state") == "rollback_failed");
    CHECK(snapshot.at("scenes").at(0).at("error").at("code") ==
          "HOOK_ROLLBACK_FAILED");
    CHECK(snapshot.at("scenes").at(0).at("error").at("hookError") == 91);
    CHECK(snapshot.at("scenes").at(1).at("state") == "hook_failed");
    CHECK(g_unhook_calls == 1);
    CHECK(trace_proxy_test_generation_installed(
            trace_proxy_test_generation(0)));
}

void failed_replacement_batch_removes_unattempted_prior_generation_hooks() {
    reset_fakes();
    trace_proxy_test_reset(config_named("replacement-cleanup-reset"));
    char old_offset[2 * sizeof(uintptr_t) + 3]{};
    char new_offset[2 * sizeof(uintptr_t) + 3]{};
    std::snprintf(old_offset, sizeof(old_offset), "0x%lx",
                  static_cast<unsigned long>(
                          reinterpret_cast<uintptr_t>(old_target)));
    std::snprintf(new_offset, sizeof(new_offset), "0x%lx",
                  static_cast<unsigned long>(
                          reinterpret_cast<uintptr_t>(new_target)));
    const nlohmann::json old_accepted = call_json_configure(json_abi_request(
            "com.example.replacement-old", "libreplacement-cleanup.so", false, {},
            nlohmann::json::array({
                    {{"name", "first"}, {"location", {{"offset", old_offset}}}},
                    {{"name", "second"}, {"location", {{"offset", old_offset}}}},
                    {{"name", "third"}, {"location", {{"offset", old_offset}}}},
            })));
    CHECK(old_accepted.at("ok") == true);
    const ModuleRange module = module_named(
            "/data/app/libreplacement-cleanup.so");
    trace_proxy_test_install_loading_module(module);
    const size_t old_third_generation = trace_proxy_test_generation(2);
    CHECK(trace_proxy_test_generation_installed(old_third_generation));
    {
        std::lock_guard<std::mutex> lock(g_gate_mutex);
        g_use_runner_gate = true;
    }
    uint64_t args[8]{31};
    uint64_t active_result = 0;
    std::thread active([&] {
        active_result = trace_proxy_dispatch(old_third_generation, args, 0);
    });
    {
        std::unique_lock<std::mutex> lock(g_gate_mutex);
        g_gate_condition.wait(lock, [] { return g_runner_entered; });
    }

    const nlohmann::json accepted = call_json_configure(json_abi_request(
            "com.example.replacement-new", "libreplacement-cleanup.so", false, {},
            nlohmann::json::array({
                    {{"name", "first"}, {"location", {{"offset", new_offset}}}},
                    {{"name", "second"}, {"location", {{"offset", new_offset}}}},
                    {{"name", "third"}, {"location", {{"offset", new_offset}}}},
            })));
    const uint64_t generation = accepted.at("generation").get<uint64_t>();
    g_fail_hook_call = g_hook_calls + 2;
    g_hook_failure_error = 73;

    trace_proxy_test_install_loading_module(module);

    const nlohmann::json snapshot = call_json_status(generation);
    CHECK(snapshot.at("state") == "hook_failed");
    CHECK(snapshot.at("scenes").at(0).at("state") == "rolled_back");
    CHECK(snapshot.at("scenes").at(1).at("state") == "hook_failed");
    CHECK(!trace_proxy_test_generation_installed(old_third_generation));
    CHECK(g_unhook_calls == 4);
    const size_t hook_calls_before_release = g_hook_calls;
    {
        std::lock_guard<std::mutex> lock(g_gate_mutex);
        g_release_runner = true;
    }
    g_gate_condition.notify_all();
    active.join();
    CHECK(active_result == 0x11f);
    CHECK(g_hook_calls == hook_calls_before_release);
}

void removed_prior_scene_residual_is_appended_to_rollback_status() {
    reset_fakes();
    trace_proxy_test_reset(config_named("removed-residual-reset"));
    char old_offset[2 * sizeof(uintptr_t) + 3]{};
    char new_offset[2 * sizeof(uintptr_t) + 3]{};
    std::snprintf(old_offset, sizeof(old_offset), "0x%lx",
                  static_cast<unsigned long>(
                          reinterpret_cast<uintptr_t>(old_target)));
    std::snprintf(new_offset, sizeof(new_offset), "0x%lx",
                  static_cast<unsigned long>(
                          reinterpret_cast<uintptr_t>(new_target)));
    const ModuleRange module = module_named(
            "/data/app/libremoved-residual.so");
    CHECK(call_json_configure(json_abi_request(
                  "com.example.removed-residual-old", "libremoved-residual.so",
                  false, {}, nlohmann::json::array({
                          {{"name", "old-first"},
                           {"location", {{"offset", old_offset}}}},
                          {{"name", "old-removed"},
                           {"location", {{"offset", old_offset}}}},
                  }))).at("ok") == true);
    trace_proxy_test_install_loading_module(module);

    const nlohmann::json accepted = call_json_configure(json_abi_request(
            "com.example.removed-residual-new", "libremoved-residual.so",
            false, {}, nlohmann::json::array({
                    {{"name", "new-only"},
                     {"location", {{"offset", new_offset}}}},
            })));
    const uint64_t generation = accepted.at("generation").get<uint64_t>();
    g_fail_unhook = true;
    g_unhook_failure_error = 91;

    trace_proxy_test_install_loading_module(module);

    const nlohmann::json snapshot = call_json_status(generation);
    CHECK(snapshot.at("state") == "rollback_failed");
    CHECK(snapshot.at("scenes").size() == 2);
    CHECK(snapshot.at("scenes").at(0).at("name") == "old-first");
    CHECK(snapshot.at("scenes").at(0).at("offset") == old_offset);
    CHECK(snapshot.at("scenes").at(0).at("runtimeAddress") == old_offset);
    CHECK(snapshot.at("scenes").at(0).at("state") == "rollback_failed");
    CHECK(snapshot.at("scenes").at(1).at("name") == "old-removed");
    CHECK(snapshot.at("scenes").at(1).at("state") == "rollback_failed");
    CHECK(snapshot.at("scenes").at(1).at("error").at("code") ==
          "HOOK_ROLLBACK_FAILED");
    CHECK(snapshot.at("scenes").at(1).at("error").at("hookError") == 91);
}

void successful_scene_removal_retires_the_old_hook_before_installed() {
    reset_fakes();
    trace_proxy_test_reset(config_named("successful-removal-reset"));
    const ModuleRange module = module_named(
            "/data/app/libsuccessful-removal.so");
    CHECK(call_json_configure(json_abi_request(
                  "com.example.successful-removal-old",
                  "libsuccessful-removal.so", false, {},
                  nlohmann::json::array({
                          {{"name", "kept"},
                           {"location", {{"offset", "0x40"}}}},
                          {{"name", "removed"},
                           {"location", {{"offset", "0x80"}}}},
                  }))).at("ok") == true);
    trace_proxy_test_install_loading_module(module);
    const size_t removed_generation = trace_proxy_test_generation(1);
    CHECK(trace_proxy_test_generation_installed(removed_generation));

    const nlohmann::json accepted = call_json_configure(json_abi_request(
            "com.example.successful-removal-new", "libsuccessful-removal.so",
            false, {}, nlohmann::json::array({
                    {{"name", "kept"},
                     {"location", {{"offset", "0xc0"}}}},
            })));
    const uint64_t generation = accepted.at("generation").get<uint64_t>();
    trace_proxy_test_install_loading_module(module);

    const nlohmann::json snapshot = call_json_status(generation);
    CHECK(snapshot.at("state") == "installed");
    CHECK(snapshot.at("scenes").size() == 1);
    CHECK(!trace_proxy_test_generation_installed(removed_generation));
    CHECK(trace_proxy_test_generation_retired(removed_generation));
    CHECK(g_unhook_calls == 2);
}

void failed_scene_retirement_rolls_back_the_new_batch() {
    reset_fakes();
    trace_proxy_test_reset(config_named("retirement-rollback-reset"));
    const ModuleRange module = module_named(
            "/data/app/libretirement-rollback.so");
    CHECK(call_json_configure(json_abi_request(
                  "com.example.retirement-rollback-old",
                  "libretirement-rollback.so", false, {},
                  nlohmann::json::array({
                          {{"name", "old-kept"},
                           {"location", {{"offset", "0x40"}}}},
                          {{"name", "old-removed"},
                           {"location", {{"offset", "0x80"}}}},
                  }))).at("ok") == true);
    trace_proxy_test_install_loading_module(module);
    const size_t removed_generation = trace_proxy_test_generation(1);

    const nlohmann::json accepted = call_json_configure(json_abi_request(
            "com.example.retirement-rollback-new",
            "libretirement-rollback.so", false, {}, nlohmann::json::array({
                    {{"name", "new-kept"},
                     {"location", {{"offset", "0xc0"}}}},
            })));
    const uint64_t generation = accepted.at("generation").get<uint64_t>();
    g_fail_unhook_call = 2;
    g_unhook_failure_error = 91;
    trace_proxy_test_install_loading_module(module);

    const nlohmann::json snapshot = call_json_status(generation);
    CHECK(snapshot.at("state") == "rollback_failed");
    CHECK(snapshot.at("scenes").at(0).at("state") == "rolled_back");
    CHECK(snapshot.at("scenes").at(1).at("name") == "old-removed");
    CHECK(snapshot.at("scenes").at(1).at("state") == "rollback_failed");
    CHECK(snapshot.at("scenes").at(1).at("error").at("code") ==
          "HOOK_ROLLBACK_FAILED");
    CHECK(snapshot.at("scenes").at(1).at("error").at("hookError") == 91);
    CHECK(!trace_proxy_test_generation_installed(2));
    CHECK(trace_proxy_test_generation_retired(2));
    CHECK(trace_proxy_test_generation_installed(removed_generation));
    CHECK(g_unhook_calls == 3);
}

void reordered_scene_residuals_are_tracked_by_physical_hook() {
    reset_fakes();
    trace_proxy_test_reset(config_named("physical-residual-reset"));
    const ModuleRange module = module_named(
            "/data/app/libphysical-residual.so");
    CHECK(call_json_configure(json_abi_request(
                  "com.example.physical-residual-old",
                  "libphysical-residual.so", false, {},
                  nlohmann::json::array({
                          {{"name", "old-zero"},
                           {"location", {{"offset", "0x80"}}}},
                          {{"name", "old-one"},
                           {"location", {{"offset", "0x100"}}}},
                          {{"name", "shared"},
                           {"location", {{"offset", "0x40"}}}},
                  }))).at("ok") == true);
    trace_proxy_test_install_loading_module(module);
    const size_t prior_shared_generation = trace_proxy_test_generation(2);

    const nlohmann::json accepted = call_json_configure(json_abi_request(
            "com.example.physical-residual-new", "libphysical-residual.so",
            false, {}, nlohmann::json::array({
                    {{"name", "shared"},
                     {"location", {{"offset", "0x40"}}}},
                    {{"name", "new-fail"},
                     {"location", {{"offset", "0x180"}}}},
            })));
    const uint64_t generation = accepted.at("generation").get<uint64_t>();
    g_fail_hook_call = g_hook_calls + 2;
    g_hook_failure_error = 73;
    g_fail_unhook_calls = {3, 4};
    g_unhook_failure_error = 91;
    trace_proxy_test_install_loading_module(module);

    const nlohmann::json snapshot = call_json_status(generation);
    CHECK(snapshot.at("state") == "rollback_failed");
    CHECK(g_unhook_calls == 4);
    CHECK(snapshot.at("scenes").size() == 3);
    size_t shared_residuals = 0;
    for (const auto &scene : snapshot.at("scenes")) {
        if (scene.at("name") == "shared" &&
            scene.at("state") == "rollback_failed") {
            CHECK(scene.at("error").at("code") == "HOOK_ROLLBACK_FAILED");
            CHECK(scene.at("error").at("hookError") == 91);
            ++shared_residuals;
        }
    }
    CHECK(shared_residuals == 2);
    CHECK(trace_proxy_test_generation_installed(prior_shared_generation));
    CHECK(trace_proxy_test_generation_installed(3));
}

void residual_same_generation_retry_never_becomes_installed() {
    reset_fakes();
    trace_proxy_test_reset(config_named("residual-retry-reset"));
    const ModuleRange module = module_named(
            "/data/app/libresidual-retry.so");
    const nlohmann::json accepted = call_json_configure(json_abi_request(
            "com.example.residual-retry", "libresidual-retry.so", false, {},
            nlohmann::json::array({
                    {{"name", "entry"},
                     {"location", {{"offset", "0x40"}}}},
            })));
    const uint64_t generation = accepted.at("generation").get<uint64_t>();
    g_install_residual_hook = true;
    g_hook_failure_error = 73;
    trace_proxy_test_install_loading_module(module);
    CHECK(call_json_status(generation).at("state") == "rollback_failed");
    const size_t proxy_generation = trace_proxy_test_generation(0);
    CHECK(trace_proxy_test_generation_installed(proxy_generation));

    g_fail_unhook = true;
    g_unhook_failure_error = 91;
    trace_proxy_test_install_loading_module(module);

    const nlohmann::json snapshot = call_json_status(generation);
    CHECK(snapshot.at("state") == "rollback_failed");
    CHECK(snapshot.at("scenes").at(0).at("state") == "rollback_failed");
    CHECK(snapshot.at("scenes").at(0).at("error").at("code") ==
          "HOOK_INSTALL_RESIDUAL");
    // The first terminal snapshot remains authoritative; a late retry must not
    // rewrite its stable installation error.
    CHECK(snapshot.at("scenes").at(0).at("error").at("hookError") == 73);
    CHECK(g_hook_calls == 1);
}

void flight_residual_same_generation_retry_is_not_idempotent() {
    reset_fakes();
    const SceneConfig scene = scene_named(
            "flight-residual-retry",
            reinterpret_cast<uintptr_t>(old_target));
    const TraceConfig config = flight_proxy_config(scene);
    const ModuleRange module = module_named(
            "/data/app/libflight-proxy.so");
    trace_proxy_test_reset(config);
    const std::shared_ptr<CaptureCoordinator> coordinator(
            new CaptureCoordinator(flight_proxy_factories()));
    CHECK(coordinator->start(config, module, 77));
    trace_proxy_test_set_coordinator(coordinator);
    g_install_residual_hook = true;
    g_hook_failure_error = 73;
    CHECK(!trace_proxy_test_update(config, scene, module));

    g_fail_unhook = true;
    g_unhook_failure_error = 91;
    CHECK(!trace_proxy_test_repeat_current_install(scene, module));
    CHECK(g_hook_calls == 1);
    CHECK(g_unhook_calls == 1);
}

void setup_failure_retires_prior_generation_hooks() {
    reset_fakes();
    trace_proxy_test_reset(config_named("setup-cleanup-reset"));
    const ModuleRange module = module_named(
            "/data/app/libsetup-cleanup.so");
    CHECK(call_json_configure(json_abi_request(
                  "com.example.setup-cleanup-old", "libsetup-cleanup.so",
                  false, {}, nlohmann::json::array({
                          {{"name", "old"},
                           {"location", {{"offset", "0x40"}}}},
                  }))).at("ok") == true);
    trace_proxy_test_install_loading_module(module);
    const size_t old_generation = trace_proxy_test_generation(0);
    CHECK(trace_proxy_test_generation_installed(old_generation));

    g_fail_inline_hook_init = true;
    const nlohmann::json accepted = call_json_configure(json_abi_request(
            "com.example.setup-cleanup-new", "libsetup-cleanup.so", false, {},
            nlohmann::json::array({
                    {{"name", "new"},
                     {"location", {{"offset", "0x80"}}}},
            })));
    const uint64_t generation = accepted.at("generation").get<uint64_t>();

    const nlohmann::json snapshot = call_json_status(generation);
    CHECK(snapshot.at("state") == "hook_failed");
    CHECK(snapshot.at("scenes").at(0).at("error").at("code") ==
          "HOOK_INITIALIZATION_FAILED");
    CHECK(!trace_proxy_test_generation_installed(old_generation));
    CHECK(trace_proxy_test_generation_retired(old_generation));
    CHECK(g_unhook_calls == 1);
}

void setup_failure_reports_every_prior_residual_hook() {
    reset_fakes();
    trace_proxy_test_reset(config_named("setup-residual-reset"));
    const ModuleRange module = module_named(
            "/data/app/libsetup-residual.so");
    CHECK(call_json_configure(json_abi_request(
                  "com.example.setup-residual-old", "libsetup-residual.so",
                  false, {}, nlohmann::json::array({
                          {{"name", "old-zero"},
                           {"location", {{"offset", "0x40"}}}},
                          {{"name", "old-one"},
                           {"location", {{"offset", "0x80"}}}},
                          {{"name", "old-two"},
                           {"location", {{"offset", "0xc0"}}}},
                  }))).at("ok") == true);
    trace_proxy_test_install_loading_module(module);

    g_fail_inline_hook_init = true;
    g_fail_unhook = true;
    g_unhook_failure_error = 91;
    const nlohmann::json accepted = call_json_configure(json_abi_request(
            "com.example.setup-residual-new", "libsetup-residual.so", false,
            {}, nlohmann::json::array({
                    {{"name", "new"},
                     {"location", {{"offset", "0x100"}}}},
            })));
    const uint64_t generation = accepted.at("generation").get<uint64_t>();

    const nlohmann::json snapshot = call_json_status(generation);
    CHECK(snapshot.at("state") == "rollback_failed");
    CHECK(snapshot.at("scenes").size() == 4);
    std::vector<std::string> residual_names;
    for (const auto &scene : snapshot.at("scenes")) {
        if (scene.at("state") == "rollback_failed") {
            CHECK(scene.at("error").at("code") == "HOOK_ROLLBACK_FAILED");
            CHECK(scene.at("error").at("hookError") == 91);
            residual_names.push_back(scene.at("name").get<std::string>());
        }
    }
    std::sort(residual_names.begin(), residual_names.end());
    CHECK(residual_names == std::vector<std::string>(
            {"old-one", "old-two", "old-zero"}));
}

void superseded_module_waiter_emits_no_terminal_outcome() {
    reset_fakes();
    trace_proxy_test_reset(config_named("superseded-waiter-reset"));
    const TraceConfig stale_config = [] {
        TraceConfig config = config_named("superseded-waiter-old");
        config.target_so = "libsuperseded-waiter-old.so";
        config.scenes.push_back(scene_named("old", 0x40));
        return config;
    }();
    const nlohmann::json stale_accepted = call_json_configure(
            json_abi_request("com.example.superseded-waiter-old",
                             stale_config.target_so, false, {},
                             nlohmann::json::array({
                                     {{"name", "old"},
                                      {"location", {{"offset", "0x40"}}}},
                             })));
    const uint64_t stale_generation =
            stale_accepted.at("generation").get<uint64_t>();
    CHECK(call_json_configure(json_abi_request(
                  "com.example.superseded-waiter-new",
                  "libsuperseded-waiter-new.so", false, {},
                  nlohmann::json::array({
                          {{"name", "new"},
                           {"location", {{"offset", "0x80"}}}},
                  }))).at("ok") == true);

    CHECK(!trace_proxy_test_finish_module_observation_failure(
            stale_generation));
    CHECK(call_json_status(stale_generation).at("state") == "superseded");
}

void scene_indices_outside_the_stub_region_are_rejected() {
    reset_fakes();
    const TraceConfig config = config_named("bounds");
    const SceneConfig scene = scene_named("bounds", reinterpret_cast<uintptr_t>(old_target),
                                          256);
    trace_proxy_test_reset(config);
    CHECK(!trace_proxy_test_update(config, scene, module_named("module")));
    CHECK(g_hook_calls == 0);
}

void proxy_generation_identities_are_never_reused_and_exhaust_safely() {
    reset_fakes();
    const TraceConfig config = config_named("generation-capacity");
    const SceneConfig scene = scene_named("generation-capacity",
                                          reinterpret_cast<uintptr_t>(old_target));
    trace_proxy_test_reset(config);
    for (size_t generation = 0; generation < 4096; ++generation) {
        CHECK(trace_proxy_test_update(config, scene, module_named("module")));
        CHECK(trace_proxy_test_generation(scene.index) == generation);
    }
    CHECK(!trace_proxy_test_update(config, scene, module_named("module")));
    CHECK(g_hook_calls == 4096);
}

void residual_hook_without_an_original_never_branches_to_null() {
    reset_fakes();
    const TraceConfig config = config_named("residual");
    const SceneConfig scene = scene_named("residual", reinterpret_cast<uintptr_t>(old_target));
    trace_proxy_test_reset(config);
    g_install_residual_hook = true;
    CHECK(!trace_proxy_test_update(config, scene, module_named("module")));
    g_fail_unhook = true;

    uint64_t args[8]{17};
    CHECK(trace_proxy_dispatch(0, args, 0) == 0);
    CHECK(g_bridge_calls == 0);
    CHECK(g_runner_calls == 0);
    CHECK(g_old_calls == 0);
    CHECK(g_unhook_calls == 1);
}

void fork_transition_child_case() {
    report_fork_transition_phase('S');
    reset_fakes();
    const TraceConfig config = config_named("fork-generation");
    const SceneConfig scene = scene_named("fork-generation",
                                          reinterpret_cast<uintptr_t>(old_target));
    trace_proxy_test_reset(config);
    CHECK(trace_proxy_test_update(config, scene, module_named("fork-module")));
    trace_proxy_test_set_registration_gate(registration_gate);
    trace_proxy_test_set_atfork_prepare_gate(atfork_prepare_gate);

    uint64_t args[8]{9};
    std::thread entrant([&] { (void)trace_proxy_dispatch(0, args, 0); });
    {
        std::unique_lock<std::mutex> lock(g_gate_mutex);
        g_gate_condition.wait(lock, [] { return g_registration_entered; });
    }
    report_fork_transition_phase('R');
    int child_status = -1;
    std::thread forker([&] {
        const pid_t child = ::fork();
        if (child == 0) {
            const size_t runner_before = g_runner_calls;
            const uint64_t value = trace_proxy_dispatch(0, args, 0);
            _exit(value == 0x109 && g_runner_calls == runner_before ? 0 : 93);
        }
        if (child < 0 || ::waitpid(child, &child_status, 0) != child) child_status = -1;
    });
    {
        std::unique_lock<std::mutex> lock(g_gate_mutex);
        g_gate_condition.wait(lock, [] { return g_atfork_prepare_entered; });
        g_release_registration = true;
    }
    report_fork_transition_phase('L');
    g_gate_condition.notify_all();
    entrant.join();
    forker.join();
    trace_proxy_test_set_atfork_prepare_gate(nullptr);
    trace_proxy_test_set_registration_gate(nullptr);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    report_fork_transition_phase('C');
}

const char *fork_transition_phase_name(char phase) {
    switch (phase) {
        case 'S': return "setup";
        case 'R': return "registration-held";
        case 'P': return "atfork-prepare-before-registry";
        case 'L': return "registration-released";
        case 'C': return "complete";
        default: return "not-started";
    }
}

void drain_fork_transition_phase(int fd, char *phase) {
    char observed[32]{};
    for (;;) {
        const ssize_t size = ::read(fd, observed, sizeof(observed));
        if (size > 0) {
            *phase = observed[size - 1];
            continue;
        }
        if (size < 0 && errno == EINTR) continue;
        CHECK(size == 0 || (errno == EAGAIN || errno == EWOULDBLOCK));
        return;
    }
}

void fork_waits_for_transition_and_child_uses_inherited_bypass_without_deadlock() {
    int phase_pipe[2]{-1, -1};
    CHECK(::pipe(phase_pipe) == 0);
    const int read_flags = ::fcntl(phase_pipe[0], F_GETFL, 0);
    CHECK(read_flags >= 0);
    CHECK(::fcntl(phase_pipe[0], F_SETFL, read_flags | O_NONBLOCK) == 0);

    posix_spawn_file_actions_t actions{};
    CHECK(::posix_spawn_file_actions_init(&actions) == 0);
    CHECK(::posix_spawn_file_actions_addclose(&actions, phase_pipe[0]) == 0);
    char phase_fd[32]{};
    std::snprintf(phase_fd, sizeof(phase_fd), "%d", phase_pipe[1]);
    char executable[] = "/proc/self/exe";
    char selected[] = "fork-transition-child";
    char *const arguments[]{executable, selected, phase_fd, nullptr};
    pid_t child = -1;
    const int spawn_error = ::posix_spawn(
            &child, executable, &actions, nullptr, arguments, environ);
    CHECK(::posix_spawn_file_actions_destroy(&actions) == 0);
    CHECK(::close(phase_pipe[1]) == 0);
    phase_pipe[1] = -1;
    CHECK(spawn_error == 0 && child > 0);

    const auto started = std::chrono::steady_clock::now();
    const auto operation_deadline = started + std::chrono::seconds(4);
    const auto cleanup_deadline = started + std::chrono::seconds(5);
    char phase = 0;
    int status = -1;
    pid_t waited = 0;
    while (std::chrono::steady_clock::now() < operation_deadline) {
        drain_fork_transition_phase(phase_pipe[0], &phase);
        waited = ::waitpid(child, &status, WNOHANG);
        if (waited == child) break;
        if (waited < 0 && errno == EINTR) continue;
        CHECK(waited == 0);
        (void)::usleep(1000);
    }
    if (waited == 0) {
        drain_fork_transition_phase(phase_pipe[0], &phase);
        std::fprintf(stderr,
                     "fork transition subprocess timeout pid=%ld phase=%s\n",
                     static_cast<long>(child),
                     fork_transition_phase_name(phase));
        (void)::kill(child, SIGKILL);
        while (std::chrono::steady_clock::now() < cleanup_deadline) {
            waited = ::waitpid(child, &status, WNOHANG);
            if (waited == child) break;
            if (waited < 0 && errno == EINTR) continue;
            CHECK(waited == 0);
            (void)::usleep(1000);
        }
        if (waited == 0) {
            std::fprintf(stderr,
                         "fork transition subprocess unreaped pid=%ld phase=%s\n",
                         static_cast<long>(child),
                         fork_transition_phase_name(phase));
        }
    }
    CHECK(::close(phase_pipe[0]) == 0);
    CHECK(waited == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

void target_fork_child_skips_inherited_proxy_postamble() {
    reset_fakes();
    g_nested_fork_status = -1;
    const TraceConfig config = config_named("target-fork");
    const SceneConfig scene = scene_named("target-fork",
                                          reinterpret_cast<uintptr_t>(forking_target));
    trace_proxy_test_reset(config);
    CHECK(trace_proxy_test_update(config, scene, module_named("fork-module")));
    uint64_t args[8]{};
    const uint64_t result = trace_proxy_dispatch(0, args, 0);
    if (result == 0xCAFE) _exit(0);
    CHECK(result == 0xBEEF);
    CHECK(WIFEXITED(g_nested_fork_status) && WEXITSTATUS(g_nested_fork_status) == 0);
}

void traced_runner_fork_child_performs_no_proxy_deallocation() {
    reset_fakes();
    const TraceConfig config = config_named(
            "traced-runner-fork-with-non-small-string-storage");
    const SceneConfig scene = scene_named(
            "traced-runner-fork-with-non-small-string-storage",
            reinterpret_cast<uintptr_t>(old_target));
    trace_proxy_test_reset(config);
    CHECK(trace_proxy_test_update(config, scene, module_named(
            "traced-runner-fork-module-with-non-small-string-storage")));
    g_runner_forks = true;

    uint64_t args[8]{};
    const uint64_t result = trace_proxy_dispatch(0, args, 0);
    if (result == 0xCAFE) _exit(0);
    CHECK(result == 0xBEEF);

    int status = -1;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    pid_t waited = 0;
    while ((waited = ::waitpid(g_runner_fork_child, &status, WNOHANG)) == 0 &&
           std::chrono::steady_clock::now() < deadline) {
        ::usleep(1000);
    }
    if (waited == 0) {
        (void)::kill(g_runner_fork_child, SIGKILL);
        waited = ::waitpid(g_runner_fork_child, &status, 0);
    }
    CHECK(waited == g_runner_fork_child);
    CHECK(WIFEXITED(status));
    if (WEXITSTATUS(status) != 0) {
        std::fprintf(stderr, "traced runner child exit=%d\n", WEXITSTATUS(status));
    }
    CHECK(WEXITSTATUS(status) == 0);
}

void proxy_runtime_allocation_failure_executes_the_target_once() {
    reset_fakes();
    const TraceConfig config = config_named("proxy-runtime-allocation-failure");
    const SceneConfig scene = scene_named(
            "proxy-runtime-allocation-failure",
            reinterpret_cast<uintptr_t>(old_target));
    trace_proxy_test_reset(config);
    CHECK(trace_proxy_test_update(config, scene, module_named("allocation-failure-module")));

    uint64_t args[8]{29};
    g_fail_next_nothrow_allocation = 1;
    CHECK(trace_proxy_dispatch(0, args, 0x1234) == 0x11D);
    CHECK(g_old_calls == 1);
    CHECK(g_runner_calls == 0);
}

void proxy_runtime_snapshot_performs_no_throwing_allocation() {
    reset_fakes();
    const TraceConfig config = config_named(
            "proxy-runtime-zero-copy-snapshot-with-long-storage");
    const SceneConfig scene = scene_named(
            "proxy-runtime-zero-copy-snapshot-with-long-storage",
            reinterpret_cast<uintptr_t>(old_target));
    trace_proxy_test_reset(config);
    CHECK(trace_proxy_test_update(config, scene, module_named(
            "proxy-runtime-zero-copy-module-with-long-storage")));

    uint64_t args[8]{31};
    g_throwing_allocation_calls.store(0, std::memory_order_relaxed);
    CHECK(trace_proxy_dispatch(0, args, 0) == 0x11F);
    CHECK(g_allocations_at_runner_entry == 0);
    CHECK(g_old_calls == 1);
}

void atfork_install_failure_bypasses_tracing_and_executes_target_once() {
    reset_fakes();
    const TraceConfig config = config_named("atfork-registration-failure");
    const SceneConfig scene = scene_named(
            "atfork-registration-failure", reinterpret_cast<uintptr_t>(old_target));
    trace_proxy_test_reset(config);
    CHECK(trace_proxy_test_update(config, scene, module_named("atfork-failure-module")));

    trace_process_test_force_lifecycle_error(ENOMEM);
    uint64_t args[8]{37};
    CHECK(trace_proxy_dispatch(0, args, 0) == 0x125);
    CHECK(g_old_calls == 1);
    CHECK(g_runner_calls == 0);
    CHECK(!trace_proxy_test_update(config, scene, module_named("must-not-install")));
}

void flight_hook_install_failure_latches_a_specific_gap() {
    reset_fakes();
    const SceneConfig scene = scene_named(
            "flight-install-failure", reinterpret_cast<uintptr_t>(new_target));
    const TraceConfig config = flight_proxy_config(scene);
    const ModuleRange module = module_named("/data/app/libflight-proxy.so");
    trace_proxy_test_reset(config);
    const std::shared_ptr<CaptureCoordinator> coordinator =
            start_flight_proxy_coordinator(config, module);
    g_fail_next_hook = true;

    CHECK(!trace_proxy_test_update(config, scene, module));
    CHECK(coordinator->incomplete());
    CHECK(g_flight_factory.coverage_gaps.load(std::memory_order_relaxed) == 1);
    CHECK(g_flight_factory.last_gap_pc.load(std::memory_order_relaxed) ==
          reinterpret_cast<uintptr_t>(new_target));
    CHECK(g_flight_factory.last_gap_reason.load(std::memory_order_relaxed) ==
          CoverageGapReason::HookSetup);
}

void concurrent_flight_gateway_keeps_the_hook_persistent() {
    reset_fakes();
    const SceneConfig scene = scene_named(
            "persistent-flight", reinterpret_cast<uintptr_t>(new_target));
    const TraceConfig config = flight_proxy_config(scene);
    const ModuleRange module = module_named("/data/app/libflight-proxy.so");
    trace_proxy_test_reset(config);
    const std::shared_ptr<CaptureCoordinator> coordinator =
            start_flight_proxy_coordinator(config, module);
    (void)coordinator;
    g_original_override = reinterpret_cast<uintptr_t>(old_target);
    CHECK(trace_proxy_test_update(config, scene, module));
    const size_t generation = trace_proxy_test_generation(scene.index);
    {
        std::lock_guard<std::mutex> lock(g_flight_factory.gate_mutex);
        g_flight_factory.block_sessions = true;
    }

    uint64_t first_args[8]{51};
    uint64_t second_args[8]{52};
    uint64_t first_result = 0;
    uint64_t second_result = 0;
    std::thread first([&] {
        first_result = trace_proxy_dispatch(generation, first_args, 0);
    });
    std::thread second([&] {
        second_result = trace_proxy_dispatch(generation, second_args, 0);
    });
    {
        std::unique_lock<std::mutex> lock(g_flight_factory.gate_mutex);
        g_flight_factory.gate_condition.wait(lock, [] {
            return g_flight_factory.blocked_entries == 2;
        });
        g_flight_factory.release_sessions = true;
    }
    g_flight_factory.gate_condition.notify_all();
    first.join();
    second.join();

    CHECK(first_result == 0x133);
    CHECK(second_result == 0x134);
    CHECK(g_unhook_calls == 0);
    CHECK(g_hook_calls == 1);
    CHECK(g_flight_factory.session_creates.load(std::memory_order_relaxed) == 2);
    CHECK(g_flight_factory.session_calls.load(std::memory_order_relaxed) == 2);
    CHECK(g_flight_factory.last_execution_entry.load(std::memory_order_relaxed) ==
          reinterpret_cast<uintptr_t>(old_target));
    CHECK(g_flight_factory.last_execution_bytes.load(std::memory_order_relaxed) == 64);
    CHECK(!coordinator->incomplete());
}

struct ProxyExitCall {
    size_t generation = 0;
    void *value = nullptr;
    std::atomic<bool> returned{false};
};

void *dispatch_deferred_exit(void *opaque) {
    auto *call = static_cast<ProxyExitCall *>(opaque);
    uint64_t args[8]{reinterpret_cast<uint64_t>(call->value)};
    (void)trace_proxy_dispatch(call->generation, args, 0);
    call->returned.store(true, std::memory_order_release);
    return reinterpret_cast<void *>(0xdead);
}

void flight_proxy_defers_pthread_exit_until_after_proxy_cleanup() {
    reset_fakes();
    const SceneConfig scene = scene_named(
            "flight-deferred-exit", reinterpret_cast<uintptr_t>(new_target));
    const TraceConfig config = flight_proxy_config(scene);
    const ModuleRange module = module_named("/data/app/libflight-proxy.so");
    trace_proxy_test_reset(config);
    const std::shared_ptr<CaptureCoordinator> coordinator =
            start_flight_proxy_coordinator(config, module);
    (void)coordinator;
    g_original_override = reinterpret_cast<uintptr_t>(old_target);
    CHECK(trace_proxy_test_update(config, scene, module));
    g_flight_factory.defer_thread_exit.store(true, std::memory_order_relaxed);

    int token = 83;
    ProxyExitCall call{trace_proxy_test_generation(scene.index), &token};
    pthread_t thread{};
    CHECK(::pthread_create(&thread, nullptr, dispatch_deferred_exit, &call) == 0);
    void *result = nullptr;
    CHECK(::pthread_join(thread, &result) == 0);
    CHECK(result == &token);
    CHECK(!call.returned.load(std::memory_order_acquire));
    CHECK(g_flight_factory.session_calls.load(std::memory_order_relaxed) == 1);
}

void flight_proxy_continues_partial_execution_without_entry_restart() {
    reset_fakes();
    const SceneConfig scene = scene_named(
            "flight-partial", reinterpret_cast<uintptr_t>(new_target));
    const TraceConfig config = flight_proxy_config(scene);
    const ModuleRange module = module_named("/data/app/libflight-proxy.so");
    trace_proxy_test_reset(config);
    const std::shared_ptr<CaptureCoordinator> coordinator =
            start_flight_proxy_coordinator(config, module);
    g_original_override = reinterpret_cast<uintptr_t>(old_target);
    CHECK(trace_proxy_test_update(config, scene, module));
    g_flight_factory.partial_execution.store(true, std::memory_order_relaxed);
    g_flight_factory.continuation_failures_remaining.store(
            1, std::memory_order_relaxed);
    g_flight_factory.continuation_stops_remaining.store(
            1, std::memory_order_relaxed);

    uint64_t args[8]{89};
    CHECK(trace_proxy_dispatch(trace_proxy_test_generation(scene.index),
                               args, 0) == 0x159);
    CHECK(g_old_calls.load(std::memory_order_relaxed) == 1);
    CHECK(g_flight_factory.session_calls.load(std::memory_order_relaxed) == 1);
    CHECK(g_flight_factory.continuation_calls.load(
                  std::memory_order_relaxed) == 3);
    CHECK(coordinator->incomplete());
}

void flight_rejects_a_different_same_basename_mapping() {
    reset_fakes();
    SceneConfig scene = scene_named("module-generation", 0x100);
    const TraceConfig config = flight_proxy_config(scene);
    ModuleRange retained = module_named("/data/app/a/libflight-proxy.so", 0x71010000);
    retained.start = 0x71000000;
    retained.readable_executable_ranges[0] = {retained.start, retained.end};
    retained.readable_executable_range_count = 1;
    ModuleRange replacement = retained;
    replacement.start = 0x72000000;
    replacement.end = 0x72010000;
    replacement.path = "/data/app/b/libflight-proxy.so";
    replacement.readable_executable_ranges[0] = {replacement.start, replacement.end};
    trace_proxy_test_reset(config);
    const std::shared_ptr<CaptureCoordinator> coordinator =
            start_flight_proxy_coordinator(config, retained);

    CHECK(!trace_proxy_test_update(config, scene, replacement));
    CHECK(g_hook_calls == 0);
    CHECK(coordinator->incomplete());
    CHECK(g_flight_factory.coverage_gaps.load(std::memory_order_relaxed) == 1);
    CHECK(g_flight_factory.last_gap_pc.load(std::memory_order_relaxed) ==
          replacement.start + scene.offset);
}

void flight_native_bypass_latches_a_coverage_gap() {
    reset_fakes();
    const SceneConfig scene = scene_named(
            "flight-native-bypass", reinterpret_cast<uintptr_t>(new_target));
    const TraceConfig config = flight_proxy_config(scene);
    const ModuleRange module = module_named("/data/app/libflight-proxy.so");
    trace_proxy_test_reset(config);
    const std::shared_ptr<CaptureCoordinator> coordinator =
            start_flight_proxy_coordinator(config, module);
    g_original_override = reinterpret_cast<uintptr_t>(old_target);
    CHECK(trace_proxy_test_update(config, scene, module));
    const size_t generation = trace_proxy_test_generation(scene.index);

    uint64_t args[8]{61};
    g_fail_next_nothrow_allocation = 1;
    CHECK(trace_proxy_dispatch(generation, args, 0) == 0x13D);
    CHECK(g_old_calls == 1);
    CHECK(g_flight_factory.session_calls.load(std::memory_order_relaxed) == 0);
    CHECK(coordinator->incomplete());
    CHECK(g_flight_factory.coverage_gaps.load(std::memory_order_relaxed) == 1);
    CHECK(g_flight_factory.last_gap_pc.load(std::memory_order_relaxed) ==
          reinterpret_cast<uintptr_t>(new_target));
    CHECK(g_flight_factory.last_gap_reason.load(std::memory_order_relaxed) ==
          CoverageGapReason::NativeBypass);
}

void persistent_flight_proxy_leaves_admission_to_the_coordinator() {
    reset_fakes();
    trace_proxy_test_reset(config_named("flight-admission-reset"));
    char offset[2 * sizeof(uintptr_t) + 3]{};
    std::snprintf(offset, sizeof(offset), "0x%lx",
                  static_cast<unsigned long>(
                          reinterpret_cast<uintptr_t>(new_target)));
    const nlohmann::json accepted = call_json_configure(json_abi_request(
            "com.example.flight.admission", "libflight-admission.so", true,
            "entry", nlohmann::json::array({
                             {{"name", "entry"},
                              {"location", {{"offset", offset}}}},
                     })));
    CHECK(accepted.at("ok") == true);
    const uint64_t config_generation =
            accepted.at("generation").get<uint64_t>();
    uint64_t active_generation = 0;
    TraceConfig config;
    CHECK(trace_proxy_test_current_configuration(&active_generation, &config));
    CHECK(active_generation == config_generation);
    const std::shared_ptr<TraceGenerationRuntime> runtime =
            trace_proxy_test_current_runtime();
    CHECK(runtime != nullptr);
    const ModuleRange module =
            module_named("/data/app/libflight-admission.so");
    const std::shared_ptr<CaptureCoordinator> coordinator(
            new CaptureCoordinator(flight_proxy_factories()));
    CHECK(coordinator != nullptr);
    CHECK(coordinator->start(config, module,
                             static_cast<uint32_t>(config_generation),
                             runtime));
    trace_proxy_test_set_coordinator(coordinator);
    g_original_override = reinterpret_cast<uintptr_t>(old_target);
    trace_proxy_test_install_loading_module(module);
    CHECK(runtime->snapshot().phase == TraceGenerationPhase::Running);

    uint64_t args[8]{23};
    CHECK(trace_proxy_dispatch(trace_proxy_test_generation(0), args, 0) ==
          0x117);
    CHECK(g_runner_calls == 0);
    CHECK(g_flight_factory.session_creates.load(std::memory_order_relaxed) ==
          1);
    CHECK(g_flight_factory.session_calls.load(std::memory_order_relaxed) == 1);
    CHECK(runtime->snapshot().active_calls == 1);
    CHECK(coordinator->request_stop(TraceStopReason::DurationElapsed));
    CHECK(coordinator->report_stop_incomplete());
    CHECK(runtime->snapshot().phase == TraceGenerationPhase::StopIncomplete);
}

void active_flight_reconfiguration_is_rejected_as_incomplete() {
    reset_fakes();
    const SceneConfig scene = scene_named(
            "active-flight-reconfigure", reinterpret_cast<uintptr_t>(new_target));
    const TraceConfig first_config = flight_proxy_config(scene);
    const ModuleRange module = module_named("/data/app/libflight-proxy.so");
    trace_proxy_test_reset(first_config);
    const std::shared_ptr<CaptureCoordinator> first_coordinator =
            start_flight_proxy_coordinator(first_config, module);
    (void)first_coordinator;
    g_original_override = reinterpret_cast<uintptr_t>(old_target);
    CHECK(trace_proxy_test_update(first_config, scene, module));
    const size_t generation = trace_proxy_test_generation(scene.index);
    {
        std::lock_guard<std::mutex> lock(g_flight_factory.gate_mutex);
        g_flight_factory.block_sessions = true;
    }
    uint64_t args[8]{71};
    uint64_t result = 0;
    std::thread active([&] { result = trace_proxy_dispatch(generation, args, 0); });
    {
        std::unique_lock<std::mutex> lock(g_flight_factory.gate_mutex);
        g_flight_factory.gate_condition.wait(lock, [] {
            return g_flight_factory.blocked_entries == 1;
        });
    }

    TraceConfig replacement_config = first_config;
    replacement_config.package_name = "replacement-flight";
    const std::shared_ptr<CaptureCoordinator> replacement_coordinator =
            start_flight_proxy_coordinator(replacement_config, module);
    CHECK(!trace_proxy_test_update(replacement_config, scene, module));
    CHECK(replacement_coordinator->incomplete());
    CHECK(g_unhook_calls == 0);
    CHECK(g_hook_calls == 1);
    ThreadExecutionControl control{};
    const size_t allocations_before =
            g_throwing_allocation_calls.load(std::memory_order_relaxed);
    CHECK(replacement_coordinator->resolve_thread_start(
            reinterpret_cast<uintptr_t>(new_target), &control));
    CHECK(g_throwing_allocation_calls.load(std::memory_order_relaxed) ==
          allocations_before);
    CHECK(control.execution_entry == reinterpret_cast<uintptr_t>(old_target));
    CHECK(control.owner != nullptr);

    {
        std::lock_guard<std::mutex> lock(g_flight_factory.gate_mutex);
        g_flight_factory.release_sessions = true;
    }
    g_flight_factory.gate_condition.notify_all();
    active.join();
    CHECK(result == 0x147);
}

void fini_retires_only_the_exact_loading_generation_and_marks_a_gap() {
    reset_fakes();
    const SceneConfig scene = scene_named("init", 0x100);
    const TraceConfig config = flight_proxy_config(scene);
    ModuleRange module;
    module.start = 0x71000000;
    module.end = 0x71004000;
    module.permissions = "r-xp";
    module.path = "/data/app/example/libflight-proxy.so";
    trace_proxy_test_reset(config);
    const std::shared_ptr<CaptureCoordinator> coordinator(
            new CaptureCoordinator(flight_proxy_factories()));
    CHECK(coordinator != nullptr);
    trace_proxy_test_set_coordinator(coordinator);
    g_original_override = reinterpret_cast<uintptr_t>(old_target);

    trace_proxy_test_install_loading_module(module);
    const size_t generation = trace_proxy_test_generation(scene.index);
    const std::shared_ptr<TraceGenerationRuntime> runtime =
            trace_proxy_test_hook_runtime(generation);
    CHECK(generation != 4096);
    CHECK(coordinator->started());
    CHECK(!trace_proxy_test_generation_retired(generation));

    trace_proxy_test_module_fini(module.start + 0x1000, module.path.c_str());
    trace_proxy_test_module_fini(module.start, "/other/libflight-proxy.so");
    CHECK(!trace_proxy_test_generation_retired(generation));
    CHECK(g_flight_factory.coverage_gaps.load(std::memory_order_relaxed) == 0);

    trace_proxy_test_module_fini(module.start, module.path.c_str());
    CHECK(trace_proxy_test_generation_retired(generation));
    CHECK(trace_proxy_test_hook_runtime(generation) == nullptr);
    CHECK(trace_proxy_test_hook_coordinator(generation) == nullptr);
    CHECK(trace_proxy_test_current_runtime() == runtime);
    CHECK(trace_proxy_test_current_coordinator() == coordinator.get());
    CHECK(coordinator->incomplete());
    CHECK(g_flight_factory.coverage_gaps.load(std::memory_order_relaxed) == 1);
    CHECK(g_flight_factory.last_gap_pc.load(std::memory_order_relaxed) ==
          module.start);
    CHECK(g_flight_factory.last_gap_reason.load(std::memory_order_relaxed) ==
          CoverageGapReason::ModuleGeneration);
}

} // namespace

bool init_inline_hook() {
    if (!g_fail_inline_hook_init) return true;
    g_fail_inline_hook_init = false;
    return false;
}

bool configure_inline_hook_dl_init_helper_path(const char *) { return true; }

bool register_inline_hook_dl_init_callback(InlineHookDlInitCallback,
                                           void *) {
    return true;
}

bool register_inline_hook_dl_fini_callback(InlineHookDlInitCallback,
                                           void *) {
    return true;
}

bool hook_function_address(uintptr_t target, void *, HookHandle *handle) {
    {
        std::unique_lock<std::mutex> gate_lock(g_gate_mutex);
        if (g_block_hook_on_linker) {
            g_hook_waiting_for_linker = true;
            g_gate_condition.notify_all();
            gate_lock.unlock();
            std::lock_guard<std::mutex> linker_lock(g_fake_linker_mutex);
        }
    }
    std::lock_guard<std::mutex> lock(g_fake_mutex);
    ++g_hook_calls;
    g_hook_targets.push_back(target);
    handle->hook_error = 0;
    handle->unhook_error = 0;
    if (g_install_residual_hook) {
        g_install_residual_hook = false;
        handle->target = target;
        handle->original = nullptr;
        handle->retained_original = nullptr;
        handle->stub = reinterpret_cast<void *>(g_hook_calls + 1);
        handle->hook_error = g_hook_failure_error;
        handle->residual_hook = true;
        return false;
    }
    if (g_fail_next_hook ||
        (g_fail_hook_call != 0 && g_hook_calls == g_fail_hook_call)) {
        g_fail_next_hook = false;
        handle->hook_error = g_hook_failure_error;
        return false;
    }
    handle->target = target;
    handle->original = reinterpret_cast<void *>(
            g_original_override != 0 ? g_original_override : target);
    handle->retained_original = handle->original;
    handle->retained_original_bytes = kShadowHookArm64OriginalSlotBytes;
    handle->stub = reinterpret_cast<void *>(g_hook_calls + 1);
    return true;
}

bool hook_symbol_address(uintptr_t target, void *replacement,
                         HookHandle *handle) {
    return hook_function_address(target, replacement, handle);
}

bool unhook_function(HookHandle *handle) {
    bool succeeded = true;
    {
        std::lock_guard<std::mutex> lock(g_fake_mutex);
        ++g_unhook_calls;
        handle->unhook_error = 0;
        if (g_fail_unhook ||
            (g_fail_unhook_call != 0 &&
             g_unhook_calls == g_fail_unhook_call) ||
            std::find(g_fail_unhook_calls.begin(), g_fail_unhook_calls.end(),
                      g_unhook_calls) != g_fail_unhook_calls.end()) {
            handle->unhook_error = g_unhook_failure_error;
            succeeded = false;
        } else {
            handle->stub = nullptr;
            handle->original = reinterpret_cast<void *>(new_target);
        }
    }
    {
        std::unique_lock<std::mutex> lock(g_gate_mutex);
        if (g_block_unhook_return) {
            g_unhook_return_entered = true;
            g_gate_condition.notify_all();
            g_gate_condition.wait(lock, [] { return g_release_unhook_return; });
        }
    }
    return succeeded;
}

TraceRunResult run_with_qbdi(const TraceConfig &config, const TraceInvocation &invocation) {
    {
        std::lock_guard<std::mutex> lock(g_fake_mutex);
        ++g_runner_calls;
        g_allocations_at_runner_entry =
                g_throwing_allocation_calls.load(std::memory_order_relaxed);
        g_seen_config = config;
        g_seen_invocation = invocation;
    }
    if (g_runner_forks) {
        const pid_t child = ::fork();
        if (child == 0) {
            g_fail_on_child_delete = 1;
            return {true, 0xCAFE};
        }
        if (child < 0) return {true, 0};
        g_runner_fork_child = child;
        return {true, 0xBEEF};
    }
    std::unique_lock<std::mutex> gate_lock(g_gate_mutex);
    if (g_use_runner_gate) {
        g_runner_entered = true;
        g_gate_condition.notify_all();
        g_gate_condition.wait(gate_lock, [] { return g_release_runner; });
        g_use_runner_gate = false;
    }
    bool admission_finished = false;
    if (g_runner_acknowledges_stop && invocation.runtime != nullptr &&
        invocation.runtime->stop_token().requested()) {
        invocation.runtime->acknowledge_sealed(invocation.admission);
        admission_finished = true;
    }
    TraceRunResult result{false, 0};
    result.admission_finished = admission_finished;
    return result;
}

extern "C" uint64_t call_target_arm64(uintptr_t target, const uint64_t args[8], uint64_t) {
    {
        std::lock_guard<std::mutex> lock(g_fake_mutex);
        ++g_bridge_calls;
    }
    std::unique_lock<std::mutex> gate_lock(g_gate_mutex);
    if (g_use_bridge_gate) {
        ++g_bridge_gate_entries;
        g_gate_condition.notify_all();
        g_gate_condition.wait(gate_lock, [] { return g_release_bridge; });
    }
    gate_lock.unlock();
    const auto function = reinterpret_cast<GenericTargetFn>(target);
    return function(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);
}

void set_jni_backtrace_funcs(const std::vector<std::string> &) {}

int main(int argc, char **argv) {
    if (argc == 3 && std::string_view(argv[1]) == "fork-transition-child") {
        char *end = nullptr;
        const long phase_fd = std::strtol(argv[2], &end, 10);
        CHECK(end != argv[2] && end != nullptr && *end == '\0' &&
              phase_fd >= 0 && phase_fd <= INT_MAX);
        g_fork_transition_phase_fd = static_cast<int>(phase_fd);
        fork_transition_child_case();
        return 0;
    }
    if (argc == 2) {
        const std::string_view selected(argv[1]);
        if (selected == "flight-hook-failure") {
            flight_hook_install_failure_latches_a_specific_gap();
            return 0;
        }
        if (selected == "persistent-flight") {
            concurrent_flight_gateway_keeps_the_hook_persistent();
            return 0;
        }
        if (selected == "module-generation") {
            flight_rejects_a_different_same_basename_mapping();
            return 0;
        }
        if (selected == "flight-native-bypass") {
            flight_native_bypass_latches_a_coverage_gap();
            return 0;
        }
        if (selected == "flight-active-reconfigure") {
            active_flight_reconfiguration_is_rejected_as_incomplete();
            return 0;
        }
        if (selected == "gateway-deactivation") {
            accepted_nonflight_generation_deactivates_the_flight_gateway();
            return 0;
        }
        if (selected == "config-exception-safety") {
            configuration_abi_catches_publication_and_status_exceptions();
            return 0;
        }
        if (selected == "pending-runtime-release") {
            superseded_pending_runtime_is_destroyed_outside_generation_locks();
            return 0;
        }
        if (selected == "installed-status-order") {
            authoritative_status_observes_installed_before_running();
            return 0;
        }
        if (selected == "admission-exact-once") {
            active_proxy_acknowledges_the_exact_generation_admission();
            return 0;
        }
        if (selected == "linker-lock-order") {
            hook_install_never_waits_for_the_linker_while_holding_the_registry();
            return 0;
        }
        if (selected == "flight-linker-lock-order") {
            flight_gateway_install_never_holds_the_registry_across_shadowhook();
            return 0;
        }
        if (selected == "hook-commit-retirement") {
            module_fini_before_hook_commit_rolls_back_the_unpublished_gateway();
            return 0;
        }
        if (selected == "stale-rollback-residual") {
            stale_rollback_failure_stays_authoritative_until_cleanup_succeeds();
            return 0;
        }
        if (selected == "stale-rollback-lock-order") {
            stale_rollback_never_inverts_registry_and_transition_locks();
            return 0;
        }
        if (selected == "stale-rollback-lock-order-child") {
            stale_rollback_lock_order_child();
            return 0;
        }
        return 2;
    }
    json_configuration_abi_is_transactional_and_nul_terminated();
    rejected_configuration_preserves_the_active_runtime_snapshot();
    accepted_configuration_is_active_when_inline_setup_fails();
    nonflight_configuration_waits_beyond_the_old_timeout_boundary();
    flight_configuration_activates_its_explicit_entry_scene();
    configuration_abi_catches_publication_and_status_exceptions();
    invalid_target_module_observation_finishes_with_a_stable_code();
    callback_registration_failure_preserves_the_shadowhook_error();
    flight_gateway_install_never_holds_the_registry_across_shadowhook();
    accepted_nonflight_generation_deactivates_the_flight_gateway();
    branch_before_registry_that_is_retired_never_enters_qbdi();
    entrant_registration_and_snapshot_are_atomic_with_install();
    stopped_generation_proxy_bypasses_qbdi_before_allocation();
    failed_hook_batch_never_arms_its_generation_deadline();
    successful_hook_batch_shares_one_runtime_and_then_arms_it();
    stop_racing_proxy_registration_uses_dormant_passthrough();
    active_proxy_acknowledges_the_exact_generation_admission();
    stopped_dormant_hook_never_attempts_a_failing_unhook();
    old_generation_deadline_cannot_stop_a_newer_generation();
    unhook_failure_uses_the_saved_original_exactly_once();
    rehook_failure_leaves_a_coherent_direct_execution_state();
    every_physical_rehook_gets_a_new_proxy_identity();
    hook_install_never_waits_for_the_linker_while_holding_the_registry();
    module_fini_before_hook_commit_rolls_back_the_unpublished_gateway();
    stale_rollback_failure_stays_authoritative_until_cleanup_succeeds();
    stale_rollback_never_inverts_registry_and_transition_locks();
    physical_rehook_keeps_its_original_capture_coordinator();
    concurrent_unhook_failures_keep_the_original_bypass_alive();
    same_address_updates_replace_all_metadata_and_hook_generation();
    duplicate_install_for_one_configuration_generation_is_idempotent();
    failed_same_generation_install_is_retried();
    duplicate_during_an_active_call_schedules_only_the_required_rehook();
    batch_reconfiguration_stays_installing_until_pending_rehook_succeeds();
    superseded_pending_runtime_is_destroyed_outside_generation_locks();
    observer_module_is_normalized_to_load_bias_and_exact_readable_exec_map();
    constructor_phdr_range_uses_load_bias_and_preserves_executable_segments();
    constructor_phdr_range_rejects_invalid_or_unrepresentable_loads();
    outside_scene_warning_does_not_block_hook_installation();
    authoritative_status_observes_installed_before_running();
    second_hook_failure_rolls_back_the_batch_in_reverse();
    rollback_failure_reports_and_retains_the_residual_hook();
    failed_replacement_batch_removes_unattempted_prior_generation_hooks();
    removed_prior_scene_residual_is_appended_to_rollback_status();
    successful_scene_removal_retires_the_old_hook_before_installed();
    failed_scene_retirement_rolls_back_the_new_batch();
    reordered_scene_residuals_are_tracked_by_physical_hook();
    residual_same_generation_retry_never_becomes_installed();
    flight_residual_same_generation_retry_is_not_idempotent();
    setup_failure_retires_prior_generation_hooks();
    setup_failure_reports_every_prior_residual_hook();
    superseded_module_waiter_emits_no_terminal_outcome();
    scene_indices_outside_the_stub_region_are_rejected();
    proxy_generation_identities_are_never_reused_and_exhaust_safely();
    residual_hook_without_an_original_never_branches_to_null();
    fork_waits_for_transition_and_child_uses_inherited_bypass_without_deadlock();
    target_fork_child_skips_inherited_proxy_postamble();
    traced_runner_fork_child_performs_no_proxy_deallocation();
    proxy_runtime_allocation_failure_executes_the_target_once();
    proxy_runtime_snapshot_performs_no_throwing_allocation();
    flight_hook_install_failure_latches_a_specific_gap();
    concurrent_flight_gateway_keeps_the_hook_persistent();
    flight_proxy_defers_pthread_exit_until_after_proxy_cleanup();
    flight_proxy_continues_partial_execution_without_entry_restart();
    flight_rejects_a_different_same_basename_mapping();
    flight_native_bypass_latches_a_coverage_gap();
    persistent_flight_proxy_leaves_admission_to_the_coordinator();
    active_flight_reconfiguration_is_rejected_as_incomplete();
    fini_retires_only_the_exact_loading_generation_and_marks_a_gap();
    atfork_install_failure_bypasses_tracing_and_executes_target_once();
    return 0;
}
