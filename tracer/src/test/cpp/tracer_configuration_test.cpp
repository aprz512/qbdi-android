#include "core/tracer_configuration.h"
#include "third_party/nlohmann/json.hpp"

#include <cstdio>
#include <cstdlib>
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
}
