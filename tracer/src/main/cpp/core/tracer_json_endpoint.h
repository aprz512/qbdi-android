#pragma once

#include "core/tracer_configuration.h"

#include <cstdint>
#include <mutex>

// Borrowed dependencies outlive the endpoint. The call mutex is shared with fork and
// configuration lifecycle transitions; activation runs after the accepted response is copied.
// This internal module owns transport validation and contains every exception at the JSON ABI.
class __attribute__((visibility("hidden"))) TracerJsonEndpoint {
public:
    using Ready = bool (*)() noexcept;
    using Activate = void (*)(TraceConfig, TraceConfig, uint64_t) noexcept;

    constexpr TracerJsonEndpoint(TracerConfiguration &configuration, std::mutex &call_mutex,
                                Ready ready, Activate activate) noexcept
        : configuration_(configuration), call_mutex_(call_mutex), ready_(ready),
          activate_(activate) {}

    int32_t configure(const char *request, uint64_t request_size, char *response,
                      uint64_t response_capacity, uint64_t *response_size) noexcept;
    int32_t status(uint64_t generation, char *response, uint64_t response_capacity,
                   uint64_t *response_size) noexcept;

private:
    static int32_t write_result(const JsonCallResult &, char *, uint64_t *) noexcept;
    static int32_t write_internal_error(char *, uint64_t, uint64_t *) noexcept;

    TracerConfiguration &configuration_;
    std::mutex &call_mutex_;
    Ready ready_;
    Activate activate_;
};
