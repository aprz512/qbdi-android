#include "core/tracer_configuration.h"

#include "third_party/nlohmann/json.hpp"

#include <charconv>
#include <initializer_list>
#include <limits>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>

namespace {

using nlohmann::json;

constexpr size_t kMaximumRequestBytes = 1024U * 1024U;
constexpr size_t kMaximumScenes = 256;

const char *configuration_state_name(ConfigurationState state) noexcept {
    switch (state) {
        case ConfigurationState::WaitingForModule:
            return "waiting_for_module";
        case ConfigurationState::Installing:
            return "installing";
        case ConfigurationState::Installed:
            return "installed";
        case ConfigurationState::HookFailed:
            return "hook_failed";
        case ConfigurationState::RollbackFailed:
            return "rollback_failed";
        case ConfigurationState::Superseded:
            return "superseded";
    }
    return "hook_failed";
}

const char *scene_configuration_state_name(SceneConfigurationState state) noexcept {
    switch (state) {
        case SceneConfigurationState::Pending:
            return "pending";
        case SceneConfigurationState::Installing:
            return "installing";
        case SceneConfigurationState::Installed:
            return "installed";
        case SceneConfigurationState::HookFailed:
            return "hook_failed";
        case SceneConfigurationState::RolledBack:
            return "rolled_back";
        case SceneConfigurationState::RollbackFailed:
            return "rollback_failed";
    }
    return "hook_failed";
}

std::string hexadecimal(uintptr_t value) {
    char digits[2 * sizeof(uintptr_t) + 1]{};
    const auto converted = std::to_chars(digits, digits + sizeof(digits), value, 16);
    return "0x" + std::string(digits, converted.ptr);
}

json serialize_warnings(const std::vector<ConfigurationIssue> &warnings) {
    json serialized = json::array();
    for (const ConfigurationIssue &warning: warnings) {
        serialized.push_back({{"code", warning.code}, {"message", warning.message}});
    }
    return serialized;
}

JsonCallResult sized_result(std::string payload, uint64_t response_capacity) {
    JsonCallResult result;
    result.required_size = static_cast<uint64_t>(payload.size()) + 1;
    result.payload = std::move(payload);
    result.transport_code = result.required_size > response_capacity
                            ? QTRACE_JSON_RESPONSE_TOO_SMALL
                            : QTRACE_JSON_OK;
    return result;
}

json serialize_normalized_scenes(const TraceConfig &config) {
    json scenes = json::array();
    for (const SceneConfig &scene: config.scenes) {
        scenes.push_back({
                {"name", scene.name},
                {"offset", hexadecimal(scene.offset)},
                {"endOffset", scene.end_offset == 0 ? json(nullptr)
                                                      : json(hexadecimal(scene.end_offset))},
        });
    }
    return scenes;
}

std::vector<SceneConfigurationStatus> pending_scene_statuses(
        const TraceConfig &config) {
    std::vector<SceneConfigurationStatus> scenes;
    scenes.reserve(config.scenes.size());
    for (const SceneConfig &scene: config.scenes) {
        SceneConfigurationStatus status;
        status.name = scene.name;
        status.offset = scene.offset;
        scenes.push_back(std::move(status));
    }
    return scenes;
}

PreparedConfiguration reject(std::string code, std::string path, std::string message) {
    PreparedConfiguration prepared;
    prepared.error = {std::move(code), std::move(path), std::move(message)};
    return prepared;
}

bool valid_utf8(std::string_view text) noexcept {
    for (size_t index = 0; index < text.size();) {
        const auto first = static_cast<unsigned char>(text[index]);
        if (first < 0x80) {
            ++index;
            continue;
        }

        size_t length = 0;
        if (first >= 0xC2 && first <= 0xDF) length = 2;
        if (first >= 0xE0 && first <= 0xEF) length = 3;
        if (first >= 0xF0 && first <= 0xF4) length = 4;
        if (length == 0 || index + length > text.size()) return false;
        for (size_t continuation = 1; continuation < length; ++continuation) {
            if ((static_cast<unsigned char>(text[index + continuation]) & 0xC0) != 0x80) {
                return false;
            }
        }
        const auto second = static_cast<unsigned char>(text[index + 1]);
        if ((first == 0xE0 && second < 0xA0) || (first == 0xED && second > 0x9F) ||
            (first == 0xF0 && second < 0x90) || (first == 0xF4 && second > 0x8F)) {
            return false;
        }
        index += length;
    }
    return true;
}

bool hex_address_overflows(const std::string &text) noexcept {
    const size_t start = text.size() >= 2 && text[0] == '0' &&
                                 (text[1] == 'x' || text[1] == 'X')
                         ? 2
                         : 0;
    if (start == text.size()) return false;
    unsigned long long parsed = 0;
    const auto conversion = std::from_chars(text.data() + start,
                                            text.data() + text.size(), parsed, 16);
    return conversion.ec == std::errc::result_out_of_range;
}

bool parse_hex_address(const std::string &text, uintptr_t *value) noexcept {
    if (text.empty()) return false;
    const size_t start = text.size() >= 2 && text[0] == '0' &&
                                 (text[1] == 'x' || text[1] == 'X')
                         ? 2
                         : 0;
    if (start == text.size()) return false;
    unsigned long long parsed = 0;
    const auto conversion = std::from_chars(text.data() + start,
                                            text.data() + text.size(), parsed, 16);
    if (conversion.ec != std::errc() || conversion.ptr != text.data() + text.size() ||
        parsed > static_cast<unsigned long long>(std::numeric_limits<uintptr_t>::max())) {
        return false;
    }
    *value = static_cast<uintptr_t>(parsed);
    return true;
}

bool exact_keys(const json &object, std::initializer_list<std::string_view> allowed,
                ConfigurationIssue *issue, std::string_view path) {
    for (const auto &entry: object.items()) {
        bool found = false;
        for (const std::string_view key: allowed) {
            if (entry.key() == key) {
                found = true;
                break;
            }
        }
        if (!found) {
            *issue = {"UNKNOWN_FIELD", std::string(path) + "." + entry.key(),
                      "unknown configuration field '" + entry.key() + "'"};
            return false;
        }
    }
    return true;
}

const json *required_member(const json &object, std::string_view name,
                            ConfigurationIssue *issue, std::string_view path) {
    const std::string key(name);
    if (!object.contains(key)) {
        *issue = {"MISSING_FIELD", std::string(path) + "." + key,
                  "required configuration field is missing"};
        return nullptr;
    }
    return &object.at(key);
}

bool string_member(const json &object, std::string_view name, std::string *value,
                   ConfigurationIssue *issue, std::string_view path,
                   bool nonempty = true, size_t maximum_bytes = 512) {
    const json *member = required_member(object, name, issue, path);
    const std::string member_path = std::string(path) + "." + std::string(name);
    if (member == nullptr) return false;
    if (!member->is_string()) {
        *issue = {"TYPE_MISMATCH", member_path, "configuration field must be a string"};
        return false;
    }
    *value = member->get<std::string>();
    if ((nonempty && value->empty()) || value->size() > maximum_bytes ||
        value->find('\0') != std::string::npos) {
        *issue = {"INVALID_STRING", member_path, "configuration string is invalid"};
        return false;
    }
    return true;
}

bool boolean_member(const json &object, std::string_view name, bool *value,
                    ConfigurationIssue *issue, std::string_view path) {
    const json *member = required_member(object, name, issue, path);
    if (member == nullptr) return false;
    if (!member->is_boolean()) {
        *issue = {"TYPE_MISMATCH", std::string(path) + "." + std::string(name),
                  "configuration field must be a boolean"};
        return false;
    }
    *value = member->get<bool>();
    return true;
}

bool unsigned_member(const json &object, std::string_view name, uint64_t *value,
                     ConfigurationIssue *issue, std::string_view path) {
    const json *member = required_member(object, name, issue, path);
    if (member == nullptr) return false;
    if (!member->is_number_unsigned()) {
        *issue = {"TYPE_MISMATCH", std::string(path) + "." + std::string(name),
                  "configuration field must be an unsigned integer"};
        return false;
    }
    *value = member->get<uint64_t>();
    return true;
}

bool is_power_of_two(uint64_t value) noexcept {
    return value != 0 && (value & (value - 1)) == 0;
}

bool parse_address(const json &object, std::string_view name, uintptr_t *value,
                   ConfigurationIssue *issue, std::string_view path) {
    std::string text;
    if (!string_member(object, name, &text, issue, path)) return false;
    if (parse_hex_address(text, value)) return true;
    *issue = {hex_address_overflows(text) ? "ADDRESS_OVERFLOW" : "INVALID_HEX_ADDRESS",
              std::string(path) + "." + std::string(name),
              "configuration address must be a hexadecimal uintptr_t value"};
    return false;
}

bool parse_trace(const json &trace, TraceOptions *options, ConfigurationIssue *issue) {
    if (!trace.is_object()) {
        *issue = {"TYPE_MISMATCH", "$.trace", "trace must be an object"};
        return false;
    }
    if (!exact_keys(trace, {"profile", "compression", "lz4Level", "autoBuffer", "bufferMb",
                            "hexdumpLimit"}, issue, "$.trace")) return false;
    std::string profile;
    bool compression = false;
    bool auto_buffer = false;
    uint64_t level = 0;
    uint64_t buffer_mb = 0;
    uint64_t hexdump_limit = 0;
    if (!string_member(trace, "profile", &profile, issue, "$.trace") ||
        !boolean_member(trace, "compression", &compression, issue, "$.trace") ||
        !unsigned_member(trace, "lz4Level", &level, issue, "$.trace") ||
        !boolean_member(trace, "autoBuffer", &auto_buffer, issue, "$.trace") ||
        !unsigned_member(trace, "bufferMb", &buffer_mb, issue, "$.trace") ||
        !unsigned_member(trace, "hexdumpLimit", &hexdump_limit, issue, "$.trace")) {
        return false;
    }
    if (profile == "fast") options->profile = TraceProfile::Fast;
    else if (profile == "balanced") options->profile = TraceProfile::Balanced;
    else if (profile == "full") options->profile = TraceProfile::Full;
    else {
        *issue = {"INVALID_TRACE_OPTIONS", "$.trace.profile", "unknown trace profile"};
        return false;
    }
    if (level > 12) {
        *issue = {"INVALID_TRACE_OPTIONS", "$.trace.lz4Level", "lz4Level must be at most 12"};
        return false;
    }
    if (buffer_mb != 0 && (buffer_mb < 8 || buffer_mb > 128)) {
        *issue = {"INVALID_TRACE_OPTIONS", "$.trace.bufferMb", "bufferMb must be 0 or 8 through 128"};
        return false;
    }
    if ((auto_buffer && buffer_mb != 0) || (!auto_buffer && buffer_mb == 0)) {
        *issue = {"INVALID_TRACE_OPTIONS", "$.trace.autoBuffer", "autoBuffer and bufferMb conflict"};
        return false;
    }
    if (hexdump_limit > 64) {
        *issue = {"INVALID_TRACE_OPTIONS", "$.trace.hexdumpLimit", "hexdumpLimit must be at most 64"};
        return false;
    }
    options->compression_enabled = compression;
    options->lz4_level = static_cast<int>(level);
    options->auto_buffer_size = auto_buffer;
    options->buffer_bytes = static_cast<size_t>(buffer_mb * 1024ULL * 1024ULL);
    options->hexdump_limit = static_cast<size_t>(hexdump_limit);
    return true;
}

bool parse_flight(const json &flight, FlightOptions *options, ConfigurationIssue *issue) {
    if (!flight.is_object()) {
        *issue = {"TYPE_MISMATCH", "$.flight", "flight must be an object"};
        return false;
    }
    if (!exact_keys(flight, {"enabled", "entryScene", "capacityMb", "chunkKb", "maxThreads",
                             "protectedChunks"}, issue, "$.flight")) return false;
    uint64_t capacity_mb = 0;
    uint64_t chunk_kb = 0;
    uint64_t max_threads = 0;
    uint64_t protected_chunks = 0;
    if (!boolean_member(flight, "enabled", &options->enabled, issue, "$.flight")) return false;
    const json *entry_scene = required_member(flight, "entryScene", issue, "$.flight");
    if (entry_scene == nullptr) {
        if (options->enabled) {
            *issue = {"INVALID_FLIGHT_ENTRY_SCENE", "$.flight.entryScene",
                      "enabled flight recorder requires entryScene"};
        }
        return false;
    }
    if (!entry_scene->is_string()) {
        *issue = {"TYPE_MISMATCH", "$.flight.entryScene", "entryScene must be a string"};
        return false;
    }
    options->entry_scene = entry_scene->get<std::string>();
    if (options->entry_scene.size() > 128 || options->entry_scene.find('\0') != std::string::npos ||
        (options->enabled && options->entry_scene.empty())) {
        *issue = {"INVALID_FLIGHT_ENTRY_SCENE", "$.flight.entryScene", "entryScene is invalid"};
        return false;
    }
    if (!unsigned_member(flight, "capacityMb", &capacity_mb, issue, "$.flight") ||
        !unsigned_member(flight, "chunkKb", &chunk_kb, issue, "$.flight") ||
        !unsigned_member(flight, "maxThreads", &max_threads, issue, "$.flight") ||
        !unsigned_member(flight, "protectedChunks", &protected_chunks, issue, "$.flight")) {
        return false;
    }
    if (capacity_mb < 64 || capacity_mb > 2048) {
        *issue = {"INVALID_FLIGHT_OPTIONS", "$.flight.capacityMb", "capacityMb must be 64 through 2048"};
        return false;
    }
    if (chunk_kb < 64 || chunk_kb > 1024 || !is_power_of_two(chunk_kb)) {
        *issue = {"INVALID_FLIGHT_OPTIONS", "$.flight.chunkKb", "chunkKb must be a power of two from 64 through 1024"};
        return false;
    }
    if (max_threads == 0 || max_threads > 1024) {
        *issue = {"INVALID_FLIGHT_OPTIONS", "$.flight.maxThreads", "maxThreads must be 1 through 1024"};
        return false;
    }
    if (protected_chunks == 0 || protected_chunks > UINT32_MAX) {
        *issue = {"INVALID_FLIGHT_OPTIONS", "$.flight.protectedChunks", "protectedChunks is out of range"};
        return false;
    }
    options->capacity_bytes = capacity_mb * 1024ULL * 1024ULL;
    options->chunk_bytes = static_cast<uint32_t>(chunk_kb * 1024ULL);
    options->max_threads = static_cast<uint32_t>(max_threads);
    options->protected_chunks = static_cast<uint32_t>(protected_chunks);
    if (static_cast<uint64_t>(options->protected_chunks) * options->chunk_bytes >
        options->capacity_bytes) {
        *issue = {"INVALID_FLIGHT_OPTIONS", "$.flight.protectedChunks",
                  "flight protected reservation exceeds capacity"};
        return false;
    }
    return true;
}

bool parse_scenes(const json &scenes, std::vector<SceneConfig> *parsed,
                  ConfigurationIssue *issue) {
    if (!scenes.is_array()) {
        *issue = {"TYPE_MISMATCH", "$.scenes", "scenes must be an array"};
        return false;
    }
    if (scenes.size() > kMaximumScenes) {
        *issue = {"TOO_MANY_SCENES", "$.scenes", "at most 256 scenes are allowed"};
        return false;
    }
    std::unordered_set<std::string> names;
    parsed->clear();
    parsed->reserve(scenes.size());
    for (size_t index = 0; index < scenes.size(); ++index) {
        const std::string scene_path = "$.scenes[" + std::to_string(index) + "]";
        const json &scene = scenes.at(index);
        if (!scene.is_object()) {
            *issue = {"TYPE_MISMATCH", scene_path, "scene must be an object"};
            return false;
        }
        if (!exact_keys(scene, {"name", "location"}, issue, scene_path)) return false;
        std::string name;
        if (!string_member(scene, "name", &name, issue, scene_path, true, 128)) return false;
        if (!names.insert(name).second) {
            *issue = {"DUPLICATE_SCENE", scene_path + ".name", "scene names must be unique"};
            return false;
        }
        const json *location = required_member(scene, "location", issue, scene_path);
        if (location == nullptr) return false;
        const std::string location_path = scene_path + ".location";
        if (!location->is_object()) {
            *issue = {"TYPE_MISMATCH", location_path, "location must be an object"};
            return false;
        }
        if (!exact_keys(*location, {"offset", "endOffset", "imageBase", "address", "endAddress"},
                        issue, location_path)) return false;
        const bool has_offset = location->contains("offset");
        const bool has_ida = location->contains("imageBase") || location->contains("address") ||
                             location->contains("endAddress");
        if (has_offset == has_ida) {
            *issue = {"CONFLICTING_LOCATION", location_path,
                      "location must use exactly one supported locator form"};
            return false;
        }
        uintptr_t offset = 0;
        uintptr_t end_offset = 0;
        bool has_end = false;
        if (has_offset) {
            if (!parse_address(*location, "offset", &offset, issue, location_path)) return false;
            has_end = location->contains("endOffset");
            if (has_end && !parse_address(*location, "endOffset", &end_offset, issue, location_path)) {
                return false;
            }
        } else {
            if (!location->contains("imageBase") || !location->contains("address") ||
                location->contains("endOffset")) {
                *issue = {"CONFLICTING_LOCATION", location_path,
                          "IDA/Ghidra locations require imageBase and address"};
                return false;
            }
            uintptr_t image_base = 0;
            uintptr_t address = 0;
            if (!parse_address(*location, "imageBase", &image_base, issue, location_path) ||
                !parse_address(*location, "address", &address, issue, location_path)) return false;
            if (address < image_base) {
                *issue = {"ADDRESS_BELOW_IMAGE_BASE", location_path + ".address",
                          "address is below imageBase"};
                return false;
            }
            offset = address - image_base;
            has_end = location->contains("endAddress");
            if (has_end) {
                uintptr_t end_address = 0;
                if (!parse_address(*location, "endAddress", &end_address, issue, location_path)) return false;
                if (end_address < image_base) {
                    *issue = {"ADDRESS_BELOW_IMAGE_BASE", location_path + ".endAddress",
                              "endAddress is below imageBase"};
                    return false;
                }
                end_offset = end_address - image_base;
            }
        }
        if (has_end && end_offset <= offset) {
            *issue = {"INVALID_RANGE", location_path +
                      (has_offset ? ".endOffset" : ".endAddress"),
                      "end address must be greater than start address"};
            return false;
        }
        parsed->push_back({index, std::move(name), offset, end_offset});
    }
    return true;
}

}  // namespace

PreparedConfiguration prepare_tracer_configuration(std::string_view request) {
    if (request.empty() || request.size() > kMaximumRequestBytes) {
        return reject("INVALID_REQUEST_SIZE", "$", "request must contain 1 byte through 1 MiB");
    }
    if (request.find('\0') != std::string_view::npos) {
        return reject("MALFORMED_JSON", "$", "request must not contain embedded NUL bytes");
    }
    if (!valid_utf8(request)) return reject("INVALID_UTF8", "$", "request is not valid UTF-8");

    try {
        const json root = json::parse(request.begin(), request.end());
        if (!root.is_object()) return reject("TYPE_MISMATCH", "$", "request root must be an object");
        ConfigurationIssue issue;
#ifndef NDEBUG
        if (!exact_keys(root, {"schemaVersion", "packageName", "targetModule", "trace", "flight",
                               "scenes", "debug"}, &issue, "$")) {
#else
        if (!exact_keys(root, {"schemaVersion", "packageName", "targetModule", "trace", "flight",
                               "scenes"}, &issue, "$")) {
#endif
            PreparedConfiguration prepared;
            prepared.error = std::move(issue);
            return prepared;
        }

        uint64_t schema_version = 0;
        if (!unsigned_member(root, "schemaVersion", &schema_version, &issue, "$")) {
            PreparedConfiguration prepared;
            prepared.error = std::move(issue);
            return prepared;
        }
        if (schema_version != 1) {
            return reject("UNSUPPORTED_SCHEMA_VERSION", "$.schemaVersion",
                          "schemaVersion must be 1");
        }

        TraceConfig config;
        if (!string_member(root, "packageName", &config.package_name, &issue, "$", true, 512) ||
            !string_member(root, "targetModule", &config.target_so, &issue, "$", true, 512)) {
            PreparedConfiguration prepared;
            prepared.error = std::move(issue);
            return prepared;
        }
        const json *trace = required_member(root, "trace", &issue, "$");
        if (trace == nullptr || !parse_trace(*trace, &config.trace, &issue)) {
            PreparedConfiguration prepared;
            prepared.error = std::move(issue);
            return prepared;
        }
        const json *flight = required_member(root, "flight", &issue, "$");
        if (flight == nullptr || !parse_flight(*flight, &config.flight, &issue)) {
            PreparedConfiguration prepared;
            prepared.error = std::move(issue);
            return prepared;
        }
        const json *scenes = required_member(root, "scenes", &issue, "$");
        if (scenes == nullptr || !parse_scenes(*scenes, &config.scenes, &issue)) {
            PreparedConfiguration prepared;
            prepared.error = std::move(issue);
            return prepared;
        }
        if (config.flight.enabled) {
            if (config.flight.entry_scene.empty()) {
                return reject("INVALID_FLIGHT_ENTRY_SCENE", "$.flight.entryScene",
                              "enabled flight recorder requires entryScene");
            }
            bool found = false;
            for (const SceneConfig &scene: config.scenes) {
                if (scene.name == config.flight.entry_scene) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                return reject("INVALID_FLIGHT_ENTRY_SCENE", "$.flight.entryScene",
                              "entryScene must name a configured scene");
            }
        }
#ifndef NDEBUG
        if (root.contains("debug")) {
            const json &debug = root.at("debug");
            if (!debug.is_object()) return reject("TYPE_MISMATCH", "$.debug", "debug must be an object");
            if (!exact_keys(debug, {"bufferBytes", "failSetup"}, &issue, "$.debug")) {
                PreparedConfiguration prepared;
                prepared.error = std::move(issue);
                return prepared;
            }
            if (debug.contains("bufferBytes")) {
                uint64_t buffer_bytes = 0;
                if (!unsigned_member(debug, "bufferBytes", &buffer_bytes, &issue, "$.debug")) {
                    PreparedConfiguration prepared;
                    prepared.error = std::move(issue);
                    return prepared;
                }
                if (buffer_bytes != 4096) return reject("INVALID_TRACE_OPTIONS", "$.debug.bufferBytes", "bufferBytes must be 4096");
                config.trace.auto_buffer_size = false;
                config.trace.buffer_bytes = static_cast<size_t>(buffer_bytes);
            }
            if (debug.contains("failSetup")) {
                if (!debug.at("failSetup").is_boolean()) {
                    return reject("TYPE_MISMATCH", "$.debug.failSetup", "failSetup must be a boolean");
                }
                config.test_fail_setup = debug.at("failSetup").get<bool>();
            }
        }
#endif
        PreparedConfiguration prepared;
        prepared.config = std::move(config);
        return prepared;
    } catch (const json::exception &) {
        return reject("MALFORMED_JSON", "$", "request is not valid JSON");
    } catch (...) {
        return reject("MALFORMED_JSON", "$", "request could not be parsed");
    }
}

std::string serialize_configure_rejection(const ConfigurationIssue &issue) {
    const json response = {
            {"responseSchemaVersion", 1},
            {"ok", false},
            {"error", {{"code", issue.code}, {"path", issue.path}, {"message", issue.message}}},
    };
    return response.dump();
}

JsonCallResult TracerConfiguration::configure(std::string_view request,
                                              uint64_t response_capacity) {
    PreparedConfiguration prepared = prepare_tracer_configuration(request);
    if (!prepared.accepted()) {
        return sized_result(serialize_configure_rejection(prepared.error),
                            response_capacity);
    }

    std::lock_guard<std::mutex> guard(mutex_);
    const uint64_t generation = next_generation_;
    const json response = {
            {"responseSchemaVersion", 1},
            {"ok", true},
            {"generation", generation},
            {"state", "waiting_for_module"},
            {"targetModule", prepared.config.target_so},
            {"scenes", serialize_normalized_scenes(prepared.config)},
            {"warnings", json::array()},
    };
    JsonCallResult result = sized_result(response.dump(), response_capacity);
    if (result.transport_code != QTRACE_JSON_OK) return result;

    if (!generations_.empty()) {
        generations_.back().state = ConfigurationState::Superseded;
    }
    GenerationSnapshot snapshot;
    snapshot.generation = generation;
    snapshot.config = std::move(prepared.config);
    snapshot.scenes = pending_scene_statuses(snapshot.config);
    generations_.push_back(std::move(snapshot));
    if (generations_.size() > 2) generations_.erase(generations_.begin());
    ++next_generation_;
    return result;
}

JsonCallResult TracerConfiguration::status(uint64_t generation,
                                           uint64_t response_capacity) const {
    std::lock_guard<std::mutex> guard(mutex_);
    const GenerationSnapshot *snapshot = nullptr;
    for (const GenerationSnapshot &candidate: generations_) {
        if (candidate.generation == generation) {
            snapshot = &candidate;
            break;
        }
    }
    if (snapshot == nullptr) {
        return sized_result(serialize_configure_rejection({
                                    "GENERATION_NOT_FOUND", "$.generation",
                                    "configuration generation is not retained"}),
                            response_capacity);
    }

    json scenes = json::array();
    for (const SceneConfigurationStatus &scene: snapshot->scenes) {
        json serialized = {
                {"name", scene.name},
                {"offset", hexadecimal(scene.offset)},
                {"runtimeAddress", scene.runtime_address == 0
                                           ? json(nullptr)
                                           : json(hexadecimal(scene.runtime_address))},
                {"state", scene_configuration_state_name(scene.state)},
                {"warnings", serialize_warnings(scene.warnings)},
        };
        if (!scene.error_code.empty()) {
            serialized["error"] = {
                    {"code", scene.error_code},
                    {"hookError", scene.hook_error},
            };
        }
        scenes.push_back(std::move(serialized));
    }
    const json response = {
            {"responseSchemaVersion", 1},
            {"ok", true},
            {"generation", snapshot->generation},
            {"state", configuration_state_name(snapshot->state)},
            {"targetModule", snapshot->config.target_so},
            {"moduleBase", snapshot->has_module
                                   ? json(hexadecimal(snapshot->module.start))
                                   : json(nullptr)},
            {"scenes", std::move(scenes)},
            {"warnings", json::array()},
    };
    return sized_result(response.dump(), response_capacity);
}

bool TracerConfiguration::current(uint64_t *generation,
                                  TraceConfig *config) const {
    if (generation == nullptr || config == nullptr) return false;
    std::lock_guard<std::mutex> guard(mutex_);
    if (generations_.empty()) return false;
    *generation = generations_.back().generation;
    *config = generations_.back().config;
    return true;
}

void TracerConfiguration::mark_installing(
        uint64_t generation, const ModuleRange &module,
        std::vector<SceneConfigurationStatus> scenes) {
    std::lock_guard<std::mutex> guard(mutex_);
    for (GenerationSnapshot &snapshot: generations_) {
        if (snapshot.generation != generation ||
            snapshot.state == ConfigurationState::Superseded) {
            continue;
        }
        snapshot.module = module;
        snapshot.has_module = true;
        snapshot.state = ConfigurationState::Installing;
        snapshot.scenes = std::move(scenes);
        return;
    }
}

void TracerConfiguration::finish_install(
        uint64_t generation, ConfigurationState state,
        std::vector<SceneConfigurationStatus> scenes) {
    std::lock_guard<std::mutex> guard(mutex_);
    for (GenerationSnapshot &snapshot: generations_) {
        if (snapshot.generation != generation ||
            snapshot.state == ConfigurationState::Superseded) {
            continue;
        }
        snapshot.state = state;
        snapshot.scenes = std::move(scenes);
        return;
    }
}
