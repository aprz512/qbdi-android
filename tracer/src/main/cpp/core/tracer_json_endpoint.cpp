#include "core/tracer_json_endpoint.h"

#include <cstring>
#include <limits>
#include <utility>

int32_t TracerJsonEndpoint::write_result(const JsonCallResult &result, char *response,
                                       uint64_t *response_size) noexcept {
    *response_size = result.required_size;
    if (result.transport_code != QTRACE_JSON_OK) return result.transport_code;
    if (result.required_size != result.payload.size() + 1) {
        *response_size = 0;
        return QTRACE_JSON_INVALID_ARGUMENT;
    }
    std::memcpy(response, result.payload.c_str(), result.payload.size() + 1);
    return QTRACE_JSON_OK;
}

int32_t TracerJsonEndpoint::write_internal_error(
        char *response, uint64_t response_capacity, uint64_t *response_size) noexcept {
    static constexpr char payload[] =
            R"json({"responseSchemaVersion":1,"ok":false,"error":{"code":"INTERNAL_ERROR","path":"$","message":"internal tracer configuration error"}})json";
    constexpr uint64_t required_size = sizeof(payload);
    *response_size = required_size;
    if (response_capacity < required_size) return QTRACE_JSON_RESPONSE_TOO_SMALL;
    std::memcpy(response, payload, sizeof(payload));
    return QTRACE_JSON_OK;
}

int32_t TracerJsonEndpoint::configure(const char *request, uint64_t request_size,
                                     char *response, uint64_t response_capacity,
                                     uint64_t *response_size) noexcept {
    if (response_size == nullptr) return QTRACE_JSON_INVALID_ARGUMENT;
    *response_size = 0;
    if (request == nullptr || response == nullptr ||
        request_size > std::numeric_limits<size_t>::max() ||
        response_capacity > std::numeric_limits<size_t>::max()) {
        return QTRACE_JSON_INVALID_ARGUMENT;
    }
    if (!ready_()) return QTRACE_JSON_INVALID_ARGUMENT;

    try {
        std::lock_guard<std::mutex> call_guard(call_mutex_);
        JsonCallResult result = configuration_.configure(
                std::string_view(request, static_cast<size_t>(request_size)),
                response_capacity);
        const int32_t transport_code = write_result(result, response, response_size);
        if (transport_code != QTRACE_JSON_OK) return transport_code;
        if (result.published()) {
            activate_(std::move(result.published_config), std::move(result.active_config),
                      result.published_generation);
        }
        return QTRACE_JSON_OK;
    } catch (...) {
        return write_internal_error(response, response_capacity, response_size);
    }
}

int32_t TracerJsonEndpoint::status(uint64_t generation, char *response,
                                  uint64_t response_capacity,
                                  uint64_t *response_size) noexcept {
    if (response_size == nullptr) return QTRACE_JSON_INVALID_ARGUMENT;
    *response_size = 0;
    if (response == nullptr || response_capacity > std::numeric_limits<size_t>::max()) {
        return QTRACE_JSON_INVALID_ARGUMENT;
    }
    if (!ready_()) return QTRACE_JSON_INVALID_ARGUMENT;
    try {
        return write_result(configuration_.status(generation, response_capacity),
                            response, response_size);
    } catch (...) {
        return write_internal_error(response, response_capacity, response_size);
    }
}
