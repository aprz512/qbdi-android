#include "core/tracer_configuration.h"
#include "third_party/nlohmann/json.hpp"

#include <cstdio>
#include <cstdlib>
#include <new>
#include <string>
#include <string_view>

static void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}
#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

static void expect_rejection(std::string_view request,
                             const char *code, const char *path) {
    PreparedConfiguration prepared = prepare_tracer_configuration(request);
    CHECK(!prepared.accepted());
    CHECK(prepared.error.code == code);
    CHECK(prepared.error.path == path);
    CHECK(!prepared.error.message.empty());

    const nlohmann::json response = nlohmann::json::parse(
            serialize_configure_rejection(prepared.error));
    CHECK(response.at("responseSchemaVersion") == 1);
    CHECK(response.at("ok") == false);
    CHECK(response.at("error").at("code") == code);
    CHECK(response.at("error").at("path") == path);
    CHECK(response.at("error").at("message") == prepared.error.message);
}

static std::string document_with_scenes(std::string_view scenes) {
    return std::string(R"json({
      "schemaVersion": 1,
      "packageName": "com.aprz.qbdiandroid",
      "targetModule": "libdemo_target.so",
      "trace": {
        "profile": "fast", "compression": true, "lz4Level": 2,
        "autoBuffer": true, "bufferMb": 0, "hexdumpLimit": 32
      },
      "flight": {
        "enabled": false, "entryScene": "", "capacityMb": 512,
        "chunkKb": 256, "maxThreads": 256, "protectedChunks": 4
      },
      "scenes": )json") + std::string(scenes) + "}";
}

static std::string replace_once(std::string value, std::string_view from,
                                std::string_view to) {
    const size_t position = value.find(from);
    CHECK(position != std::string::npos);
    value.replace(position, from.size(), to);
    return value;
}

static std::string document_with_session(std::string_view session) {
    return replace_once(document_with_scenes("[]"), "\"scenes\": []",
                        "\"scenes\": [], \"session\": " + std::string(session));
}

static nlohmann::json parse_payload(const JsonCallResult &result) {
    CHECK(result.transport_code == QTRACE_JSON_OK);
    CHECK(result.required_size == result.payload.size() + 1);
    return nlohmann::json::parse(result.payload);
}

static void generation_registry_is_transactional_and_retains_two_generations() {
    TracerConfiguration configuration;
    const std::string first_request = document_with_scenes(
            R"json([{"name":"first","location":{"offset":"0x10"}}])json");

    uint64_t generation = 0;
    TraceConfig current_config;
    CHECK(!configuration.current(&generation, &current_config));

    const JsonCallResult no_fit = configuration.configure(first_request, 1);
    CHECK(no_fit.transport_code == QTRACE_JSON_RESPONSE_TOO_SMALL);
    CHECK(no_fit.required_size > 1);
    CHECK(!configuration.current(&generation, &current_config));

    const JsonCallResult first = configuration.configure(first_request,
                                                          no_fit.required_size);
    const nlohmann::json first_response = parse_payload(first);
    CHECK(first_response.at("ok") == true);
    CHECK(first_response.at("generation") == 1);
    CHECK(first_response.at("state") == "waiting_for_module");
    CHECK(first_response.at("scenes").at(0).at("offset") == "0x10");
    CHECK(configuration.current(&generation, &current_config));
    CHECK(generation == 1);
    CHECK(current_config.scenes.at(0).name == "first");

    const nlohmann::json rejection = parse_payload(
            configuration.configure("{]", 64U * 1024U));
    CHECK(rejection.at("ok") == false);
    CHECK(rejection.at("error").at("code") == "MALFORMED_JSON");
    CHECK(configuration.current(&generation, &current_config));
    CHECK(generation == 1);

    const std::string second_request = document_with_scenes(
            R"json([{"name":"second","location":{"offset":"0x20"}}])json");
    const nlohmann::json second = parse_payload(
            configuration.configure(second_request, 64U * 1024U));
    CHECK(second.at("generation") == 2);
    CHECK(configuration.current(&generation, &current_config));
    CHECK(generation == 2);
    CHECK(current_config.scenes.at(0).name == "second");

    const nlohmann::json superseded = parse_payload(
            configuration.status(1, 64U * 1024U));
    CHECK(superseded.at("ok") == true);
    CHECK(superseded.at("generation") == 1);
    CHECK(superseded.at("state") == "superseded");

    const std::string third_request = document_with_scenes(
            R"json([{"name":"third","location":{"offset":"0x30","endOffset":"0x50"}}])json");
    const nlohmann::json third = parse_payload(
            configuration.configure(third_request, 64U * 1024U));
    CHECK(third.at("generation") == 3);

    ModuleRange module;
    module.start = 0x70000000;
    module.end = 0x70010000;
    module.path = "/data/app/libdemo_target.so";
    SceneAddressDiagnostics installing_scene;
    installing_scene.valid = true;
    installing_scene.runtime_address = 0x70000030;
    installing_scene.runtime_end = 0x70000050;
    installing_scene.warnings = {
            {"ADDRESS_OUTSIDE_TARGET_MODULE", "runtime address is outside the target module mapping"},
            {"ADDRESS_IN_RUNTIME_MAPPING", "runtime address is in an anonymous or runtime-generated mapping"},
    };
    configuration.mark_installing(3, module, {installing_scene});
    const nlohmann::json installing = parse_payload(
            configuration.status(3, 64U * 1024U));
    CHECK(installing.at("state") == "installing");
    CHECK(installing.at("moduleBase") == "0x70000000");
    CHECK(installing.at("scenes").at(0).at("state") == "installing");
    CHECK(installing.at("scenes").at(0).at("offset") == "0x30");
    CHECK(installing.at("scenes").at(0).at("runtimeAddress") == "0x70000030");
    CHECK(installing.at("scenes").at(0).at("runtimeEnd") == "0x70000050");
    CHECK(installing.at("scenes").at(0).at("warnings").at(0).at("code") ==
          "ADDRESS_OUTSIDE_TARGET_MODULE");
    CHECK(installing.at("scenes").at(0).at("warnings").at(0).at("message") ==
          "runtime address is outside the target module mapping");
    CHECK(installing.at("scenes").at(0).at("warnings").at(1).at("code") ==
          "ADDRESS_IN_RUNTIME_MAPPING");

    SceneConfigurationStatus installed_scene;
    installed_scene.name = "third";
    installed_scene.offset = 0x30;
    installed_scene.runtime_address = 0x70000030;
    installed_scene.runtime_end = 0x70000050;
    installed_scene.state = SceneConfigurationState::Installed;
    installed_scene.warnings = {
            {"ADDRESS_OUTSIDE_TARGET_MODULE", "$.scenes[0].location",
             "runtime address is outside the target module mapping"},
            {"ADDRESS_IN_RUNTIME_MAPPING", "$.scenes[0].location",
             "runtime address is in an anonymous or runtime-generated mapping"},
    };
    configuration.finish_install(3, ConfigurationState::Installed,
                                 {installed_scene});
    const nlohmann::json installed = parse_payload(
            configuration.status(3, 64U * 1024U));
    CHECK(installed.at("state") == "installed");
    CHECK(installed.at("scenes").at(0).at("state") == "installed");
    CHECK(installed.at("scenes").at(0).at("warnings").size() == 2);

    const nlohmann::json expired = parse_payload(
            configuration.status(1, 64U * 1024U));
    CHECK(expired.at("ok") == false);
    CHECK(expired.at("error").at("code") == "GENERATION_NOT_FOUND");
}

static void configure_and_status_serialize_normalized_session() {
    TracerConfiguration configuration;
    const std::string request = document_with_session(
            R"json({"id":"7d5807cf-cf09-4f21-92de-1ad92802610a","durationMs":60000})json");

    const nlohmann::json configured = parse_payload(
            configuration.configure(request, 64U * 1024U));
    CHECK(configured.at("session").at("id") == "7d5807cf-cf09-4f21-92de-1ad92802610a");
    CHECK(configured.at("session").at("durationMs") == 60000);

    const nlohmann::json status = parse_payload(
            configuration.status(configured.at("generation").get<uint64_t>(), 64U * 1024U));
    CHECK(status.at("session").at("id") == "7d5807cf-cf09-4f21-92de-1ad92802610a");
    CHECK(status.at("session").at("durationMs") == 60000);

    TracerConfiguration legacy_configuration;
    const nlohmann::json legacy_configured = parse_payload(
            legacy_configuration.configure(document_with_scenes("[]"), 64U * 1024U));
    CHECK(legacy_configured.at("session").at("id") == "");
    CHECK(legacy_configured.at("session").at("durationMs") == 0);
    const nlohmann::json legacy_status = parse_payload(
            legacy_configuration.status(
                    legacy_configured.at("generation").get<uint64_t>(), 64U * 1024U));
    CHECK(legacy_status.at("session").at("id") == "");
    CHECK(legacy_status.at("session").at("durationMs") == 0);
}

static void terminal_generations_ignore_late_install_callbacks() {
    TracerConfiguration configuration;
    const std::string request = document_with_scenes(
            R"json([{"name":"terminal","location":{"offset":"0x10"}}])json");
    ModuleRange module;
    module.start = 0x71000000;
    module.end = 0x71001000;
    module.path = "/data/app/libdemo_target.so";
    SceneAddressDiagnostics diagnostics;
    diagnostics.valid = true;
    diagnostics.runtime_address = module.start + 0x10;
    SceneConfigurationStatus scene;
    scene.name = "terminal";
    scene.offset = 0x10;
    scene.runtime_address = diagnostics.runtime_address;
    scene.state = SceneConfigurationState::Installed;

    const struct TerminalCase {
        ConfigurationState state;
        const char *name;
    } cases[] = {
            {ConfigurationState::Installed, "installed"},
            {ConfigurationState::HookFailed, "hook_failed"},
            {ConfigurationState::RollbackFailed, "rollback_failed"},
    };
    uint64_t previous_generation = 0;
    for (const TerminalCase &test_case: cases) {
        const nlohmann::json accepted = parse_payload(
                configuration.configure(request, 64U * 1024U));
        const uint64_t generation = accepted.at("generation").get<uint64_t>();
        configuration.mark_installing(generation, module, {diagnostics});
        configuration.finish_install(generation, test_case.state, {scene});

        configuration.mark_installing(generation, module, {diagnostics});
        configuration.finish_install(
                generation, ConfigurationState::Installed, {scene});
        CHECK(parse_payload(configuration.status(generation, 64U * 1024U))
                      .at("state") == test_case.name);

        if (previous_generation != 0) {
            configuration.mark_installing(previous_generation, module,
                                           {diagnostics});
            configuration.finish_install(
                    previous_generation, ConfigurationState::Installed,
                    {scene});
            CHECK(parse_payload(configuration.status(
                                      previous_generation, 64U * 1024U))
                          .at("state") == "superseded");
        }
        previous_generation = generation;
    }

    (void)parse_payload(configuration.configure(request, 64U * 1024U));
    configuration.mark_installing(previous_generation, module, {diagnostics});
    configuration.finish_install(previous_generation,
                                 ConfigurationState::Installed, {scene});
    CHECK(parse_payload(configuration.status(previous_generation,
                                             64U * 1024U))
                  .at("state") == "superseded");
}

static void publication_faults_preserve_the_prior_generation() {
    TracerConfiguration configuration;
    const std::string first_request = document_with_scenes(
            R"json([{"name":"first","location":{"offset":"0x10"}}])json");
    const std::string second_request = document_with_scenes(
            R"json([{"name":"second","location":{"offset":"0x20"}}])json");
    const nlohmann::json first = parse_payload(
            configuration.configure(first_request, 64U * 1024U));
    CHECK(first.at("generation") == 1);
    SceneConfigurationStatus installed;
    installed.name = "first";
    installed.offset = 0x10;
    installed.state = SceneConfigurationState::Installed;
    configuration.finish_install(1, ConfigurationState::Installed,
                                 {installed});

    const TracerConfigurationFaultPoint fault_points[] = {
            TracerConfigurationFaultPoint::ParsePrepared,
            TracerConfigurationFaultPoint::SnapshotPrepared,
            TracerConfigurationFaultPoint::ResponsePrepared,
            TracerConfigurationFaultPoint::ReplacementPrepared,
    };
    for (const TracerConfigurationFaultPoint fault_point: fault_points) {
        tracer_configuration_test_throw_at(fault_point);
        bool threw = false;
        try {
            (void)configuration.configure(second_request, 64U * 1024U);
        } catch (const std::bad_alloc &) {
            threw = true;
        }
        CHECK(threw);
        uint64_t generation = 0;
        TraceConfig config;
        CHECK(configuration.current(&generation, &config));
        CHECK(generation == 1);
        CHECK(config.scenes.at(0).name == "first");
        CHECK(parse_payload(configuration.status(1, 64U * 1024U))
                      .at("state") == "installed");
    }

    const nlohmann::json second = parse_payload(
            configuration.configure(second_request, 64U * 1024U));
    CHECK(second.at("generation") == 2);
}

int main() {
    const char request[] = R"json({
      "schemaVersion": 1,
      "packageName": "com.aprz.qbdiandroid",
      "targetModule": "libdemo_target.so",
      "trace": {
        "profile": "fast", "compression": true, "lz4Level": 2,
        "autoBuffer": true, "bufferMb": 0, "hexdumpLimit": 32
      },
      "flight": {
        "enabled": true, "entryScene": "init", "capacityMb": 512,
        "chunkKb": 256, "maxThreads": 256, "protectedChunks": 4
      },
      "scenes": [
        {"name": "init", "location": {"offset": "0x6ac90"}},
        {"name": "algorithm", "location": {
          "imageBase": "0x10000", "address": "0x7db38",
          "endAddress": "0x7dc00"
        }}
      ]
    })json";
    PreparedConfiguration prepared = prepare_tracer_configuration(request);
    CHECK(prepared.accepted());
    CHECK(prepared.config.scenes.size() == 2);
    CHECK(prepared.config.scenes[0].name == "init");
    CHECK(prepared.config.scenes[0].offset == 0x6ac90);
    CHECK(prepared.config.scenes[1].offset == 0x6db38);
    CHECK(prepared.config.scenes[1].end_offset == 0x6dc00);
    CHECK(prepared.config.flight.entry_scene == "init");

    const auto timed_session = prepare_tracer_configuration(document_with_session(
            R"json({"id":"7d5807cf-cf09-4f21-92de-1ad92802610a","durationMs":60000})json"));
    CHECK(timed_session.accepted());
    CHECK(timed_session.config.session.id == "7d5807cf-cf09-4f21-92de-1ad92802610a");
    CHECK(timed_session.config.session.duration_ms == 60000);
    CHECK(timed_session.config.session.enabled());
    CHECK(timed_session.config.session.timed());

    const auto minimum_duration_session = prepare_tracer_configuration(document_with_session(
            R"json({"id":"7d5807cf-cf09-4f21-92de-1ad92802610a","durationMs":100})json"));
    CHECK(minimum_duration_session.accepted());
    const auto maximum_duration_session = prepare_tracer_configuration(document_with_session(
            R"json({"id":"7d5807cf-cf09-4f21-92de-1ad92802610a","durationMs":86400000})json"));
    CHECK(maximum_duration_session.accepted());

    const auto monitor_session = prepare_tracer_configuration(document_with_session(
            R"json({"id":"7d5807cf-cf09-4f21-92de-1ad92802610a"})json"));
    CHECK(monitor_session.accepted());
    CHECK(monitor_session.config.session.duration_ms == 0);
    CHECK(monitor_session.config.session.enabled());
    CHECK(!monitor_session.config.session.timed());
    const auto legacy_session = prepare_tracer_configuration(document_with_scenes("[]"));
    CHECK(legacy_session.accepted());
    CHECK(!legacy_session.config.session.enabled());
    CHECK(legacy_session.config.session.duration_ms == 0);

    expect_rejection(document_with_session(
                             R"json({"id":"7D5807CF-CF09-4F21-92DE-1AD92802610A"})json"),
                     "INVALID_SESSION_ID", "$.session.id");
    expect_rejection(document_with_session(
                             R"json({"id":"7d5807cfcf094f2192de1ad92802610a"})json"),
                     "INVALID_SESSION_ID", "$.session.id");
    expect_rejection(document_with_session(
                             R"json({"id":"00000000-0000-0000-0000-000000000000"})json"),
                     "INVALID_SESSION_ID", "$.session.id");
    expect_rejection(document_with_session(R"json({"durationMs":60000})json"),
                     "MISSING_FIELD", "$.session.id");
    expect_rejection(document_with_session(
                             R"json({"id":"7d5807cf-cf09-4f21-92de-1ad92802610a","durationMs":99})json"),
                     "INVALID_SESSION_DURATION", "$.session.durationMs");
    expect_rejection(document_with_session(
                             R"json({"id":"7d5807cf-cf09-4f21-92de-1ad92802610a","durationMs":86400001})json"),
                     "INVALID_SESSION_DURATION", "$.session.durationMs");
    expect_rejection(document_with_session(
                             R"json({"id":"7d5807cf-cf09-4f21-92de-1ad92802610a","unexpected":true})json"),
                     "UNKNOWN_FIELD", "$.session.unexpected");

    expect_rejection("{]", "MALFORMED_JSON", "$");
    const std::string embedded_nul = std::string("{\"schemaVersion\":1}") + '\0';
    expect_rejection(embedded_nul, "MALFORMED_JSON", "$");
    const std::string invalid_utf8 =
            "{\"schemaVersion\":1,\"packageName\":\"\xC3\","
            "\"targetModule\":\"libdemo_target.so\",\"trace\":{},"
            "\"flight\":{},\"scenes\":[]}";
    expect_rejection(invalid_utf8, "INVALID_UTF8", "$");

    expect_rejection(replace_once(document_with_scenes("[]"), "\"schemaVersion\": 1",
                                  "\"schemaVersion\": 2"),
                     "UNSUPPORTED_SCHEMA_VERSION", "$.schemaVersion");
    expect_rejection(replace_once(document_with_scenes("[]"), "\"schemaVersion\": 1",
                                  "\"schemaVersion\": \"1\""),
                     "TYPE_MISMATCH", "$.schemaVersion");
    expect_rejection(replace_once(document_with_scenes("[]"), "\"scenes\": []",
                                  "\"scenes\": [], \"unexpected\": true"),
                     "UNKNOWN_FIELD", "$.unexpected");
    expect_rejection(replace_once(document_with_scenes("[]"), "\"hexdumpLimit\": 32",
                                  "\"hexdumpLimit\": 32, \"unexpected\": true"),
                     "UNKNOWN_FIELD", "$.trace.unexpected");
    expect_rejection(replace_once(document_with_scenes("[]"), "\"protectedChunks\": 4",
                                  "\"protectedChunks\": 4, \"unexpected\": true"),
                     "UNKNOWN_FIELD", "$.flight.unexpected");
    expect_rejection(document_with_scenes(R"json([{"name":"one","location":{"offset":"0x1"},"unexpected":true}])json"),
                     "UNKNOWN_FIELD", "$.scenes[0].unexpected");
    expect_rejection(document_with_scenes(R"json([{"name":"one","location":{"offset":"0x1","unexpected":true}}])json"),
                     "UNKNOWN_FIELD", "$.scenes[0].location.unexpected");

    expect_rejection(document_with_scenes(R"json([{"name":"one","location":{"offset":1}}])json"),
                     "TYPE_MISMATCH", "$.scenes[0].location.offset");
    expect_rejection(document_with_scenes(R"json([{"name":"one","location":{"offset":"0x1"}},{"name":"one","location":{"offset":"0x2"}}])json"),
                     "DUPLICATE_SCENE", "$.scenes[1].name");
    expect_rejection(document_with_scenes(R"json([{"name":"one","location":{"offset":"g"}}])json"),
                     "INVALID_HEX_ADDRESS", "$.scenes[0].location.offset");
    expect_rejection(document_with_scenes(R"json([{"name":"one","location":{"offset":"0x1","address":"0x1","imageBase":"0x0"}}])json"),
                     "CONFLICTING_LOCATION", "$.scenes[0].location");
    expect_rejection(document_with_scenes(R"json([{"name":"one","location":{"imageBase":"0x0"}}])json"),
                     "CONFLICTING_LOCATION", "$.scenes[0].location");
    expect_rejection(document_with_scenes(R"json([{"name":"one","location":{"imageBase":"0x100","address":"0xff"}}])json"),
                     "ADDRESS_BELOW_IMAGE_BASE", "$.scenes[0].location.address");
    expect_rejection(document_with_scenes(R"json([{"name":"one","location":{"offset":"0x10000000000000000"}}])json"),
                     "ADDRESS_OVERFLOW", "$.scenes[0].location.offset");
    expect_rejection(document_with_scenes(R"json([{"name":"one","location":{"offset":"0x10","endOffset":"0x10"}}])json"),
                     "INVALID_RANGE", "$.scenes[0].location.endOffset");
    expect_rejection(document_with_scenes(R"json([{"name":"one","location":{"offset":"0x10","endOffset":"0xf"}}])json"),
                     "INVALID_RANGE", "$.scenes[0].location.endOffset");
    expect_rejection(document_with_scenes(R"json([{"name":"one","location":{"imageBase":"0x100","address":"0x110","endAddress":"0xff"}}])json"),
                     "ADDRESS_BELOW_IMAGE_BASE", "$.scenes[0].location.endAddress");
    expect_rejection(document_with_scenes(R"json([{"name":"one","location":{"imageBase":"0x100","address":"0x110","endOffset":"0x20"}}])json"),
                     "CONFLICTING_LOCATION", "$.scenes[0].location");

    std::string too_many_scenes = "[";
    for (size_t index = 0; index != 257; ++index) {
        if (index != 0) too_many_scenes += ',';
        too_many_scenes += "{\"name\":\"scene" + std::to_string(index) +
                           "\",\"location\":{\"offset\":\"0x1\"}}";
    }
    too_many_scenes += ']';
    expect_rejection(document_with_scenes(too_many_scenes), "TOO_MANY_SCENES", "$.scenes");

    const std::string numeric_options = document_with_scenes("[]");
    struct RejectionCase {
        std::string_view from;
        std::string_view to;
        const char *code;
        const char *path;
    };
    const RejectionCase numeric_rejections[] = {
            {"\"lz4Level\": 2", "\"lz4Level\": 13", "INVALID_TRACE_OPTIONS", "$.trace.lz4Level"},
            {"\"bufferMb\": 0", "\"bufferMb\": 7", "INVALID_TRACE_OPTIONS", "$.trace.bufferMb"},
            {"\"bufferMb\": 0", "\"bufferMb\": 129", "INVALID_TRACE_OPTIONS", "$.trace.bufferMb"},
            {"\"autoBuffer\": true", "\"autoBuffer\": false", "INVALID_TRACE_OPTIONS", "$.trace.autoBuffer"},
            {"\"hexdumpLimit\": 32", "\"hexdumpLimit\": 65", "INVALID_TRACE_OPTIONS", "$.trace.hexdumpLimit"},
            {"\"capacityMb\": 512", "\"capacityMb\": 63", "INVALID_FLIGHT_OPTIONS", "$.flight.capacityMb"},
            {"\"capacityMb\": 512", "\"capacityMb\": 2049", "INVALID_FLIGHT_OPTIONS", "$.flight.capacityMb"},
            {"\"chunkKb\": 256", "\"chunkKb\": 63", "INVALID_FLIGHT_OPTIONS", "$.flight.chunkKb"},
            {"\"chunkKb\": 256", "\"chunkKb\": 96", "INVALID_FLIGHT_OPTIONS", "$.flight.chunkKb"},
            {"\"chunkKb\": 256", "\"chunkKb\": 1025", "INVALID_FLIGHT_OPTIONS", "$.flight.chunkKb"},
            {"\"maxThreads\": 256", "\"maxThreads\": 0", "INVALID_FLIGHT_OPTIONS", "$.flight.maxThreads"},
            {"\"maxThreads\": 256", "\"maxThreads\": 1025", "INVALID_FLIGHT_OPTIONS", "$.flight.maxThreads"},
            {"\"protectedChunks\": 4", "\"protectedChunks\": 0", "INVALID_FLIGHT_OPTIONS", "$.flight.protectedChunks"},
            {"\"protectedChunks\": 4", "\"protectedChunks\": 4294967296", "INVALID_FLIGHT_OPTIONS", "$.flight.protectedChunks"},
    };
    for (const RejectionCase &test_case: numeric_rejections) {
        expect_rejection(replace_once(numeric_options, test_case.from, test_case.to),
                         test_case.code, test_case.path);
    }
    expect_rejection(replace_once(numeric_options, "\"bufferMb\": 0", "\"bufferMb\": 8"),
                     "INVALID_TRACE_OPTIONS", "$.trace.autoBuffer");
    expect_rejection(replace_once(replace_once(replace_once(numeric_options,
                                                             "\"capacityMb\": 512", "\"capacityMb\": 64"),
                                                "\"chunkKb\": 256", "\"chunkKb\": 1024"),
                                      "\"protectedChunks\": 4", "\"protectedChunks\": 65"),
                     "INVALID_FLIGHT_OPTIONS", "$.flight.protectedChunks");

    const std::string accepted_numeric_boundaries[] = {
            replace_once(numeric_options, "\"lz4Level\": 2", "\"lz4Level\": 0"),
            replace_once(numeric_options, "\"lz4Level\": 2", "\"lz4Level\": 12"),
            replace_once(replace_once(numeric_options, "\"bufferMb\": 0", "\"bufferMb\": 8"),
                         "\"autoBuffer\": true", "\"autoBuffer\": false"),
            replace_once(replace_once(numeric_options, "\"bufferMb\": 0", "\"bufferMb\": 128"),
                         "\"autoBuffer\": true", "\"autoBuffer\": false"),
            replace_once(numeric_options, "\"hexdumpLimit\": 32", "\"hexdumpLimit\": 0"),
            replace_once(numeric_options, "\"hexdumpLimit\": 32", "\"hexdumpLimit\": 64"),
            replace_once(numeric_options, "\"capacityMb\": 512", "\"capacityMb\": 64"),
            replace_once(numeric_options, "\"capacityMb\": 512", "\"capacityMb\": 2048"),
            replace_once(numeric_options, "\"chunkKb\": 256", "\"chunkKb\": 64"),
            replace_once(numeric_options, "\"chunkKb\": 256", "\"chunkKb\": 1024"),
            replace_once(numeric_options, "\"maxThreads\": 256", "\"maxThreads\": 1"),
            replace_once(numeric_options, "\"maxThreads\": 256", "\"maxThreads\": 1024"),
            replace_once(numeric_options, "\"protectedChunks\": 4", "\"protectedChunks\": 1"),
            replace_once(replace_once(replace_once(numeric_options,
                                                    "\"capacityMb\": 512", "\"capacityMb\": 2048"),
                                       "\"chunkKb\": 256", "\"chunkKb\": 64"),
                         "\"protectedChunks\": 4", "\"protectedChunks\": 32768"),
    };
    for (const std::string &boundary_request: accepted_numeric_boundaries) {
        CHECK(prepare_tracer_configuration(boundary_request).accepted());
    }

    expect_rejection("", "INVALID_REQUEST_SIZE", "$");
    expect_rejection("{", "MALFORMED_JSON", "$");
    std::string maximum_request = numeric_options;
    maximum_request.append(1024U * 1024U - maximum_request.size(), ' ');
    CHECK(maximum_request.size() == 1024U * 1024U);
    CHECK(prepare_tracer_configuration(maximum_request).accepted());
    maximum_request.push_back(' ');
    expect_rejection(maximum_request, "INVALID_REQUEST_SIZE", "$");

    expect_rejection(replace_once(request, "\"entryScene\": \"init\"",
                                  "\"entryScene\": \"missing\""),
                     "INVALID_FLIGHT_ENTRY_SCENE", "$.flight.entryScene");
    expect_rejection(replace_once(request, "\"enabled\": true, \"entryScene\": \"init\", ",
                                  "\"enabled\": true, "),
                     "INVALID_FLIGHT_ENTRY_SCENE", "$.flight.entryScene");

    PreparedConfiguration offset_form = prepare_tracer_configuration(document_with_scenes(
            R"json([{"name":"offset","location":{"offset":"0x6db38","endOffset":"0x6dc00"}}])json"));
    CHECK(offset_form.accepted());
    CHECK(offset_form.config.scenes[0].offset == 0x6db38);
    CHECK(offset_form.config.scenes[0].end_offset == 0x6dc00);

#ifndef NDEBUG
    PreparedConfiguration debug_controls = prepare_tracer_configuration(replace_once(
            document_with_scenes("[]"), "\"scenes\": []",
            "\"scenes\": [], \"debug\": {\"bufferBytes\": 4096, \"failSetup\": true}"));
    CHECK(debug_controls.accepted());
    CHECK(!debug_controls.config.trace.auto_buffer_size);
    CHECK(debug_controls.config.trace.buffer_bytes == 4096);
    CHECK(debug_controls.config.test_fail_setup);
    expect_rejection(replace_once(document_with_scenes("[]"), "\"scenes\": []",
                                  "\"scenes\": [], \"debug\": {\"unexpected\": true}"),
                     "UNKNOWN_FIELD", "$.debug.unexpected");
#else
    expect_rejection(replace_once(document_with_scenes("[]"), "\"scenes\": []",
                                  "\"scenes\": [], \"debug\": {}"),
                     "UNKNOWN_FIELD", "$.debug");
#endif
    generation_registry_is_transactional_and_retains_two_generations();
    configure_and_status_serialize_normalized_session();
    terminal_generations_ignore_late_install_callbacks();
    publication_faults_preserve_the_prior_generation();
}
