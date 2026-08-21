#include "core/trace_config.h"

#include <charconv>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

static std::vector<std::string> split(const std::string &value, char delimiter) {
    std::vector<std::string> result;
    std::stringstream input(value);
    std::string item;
    while (std::getline(input, item, delimiter)) result.push_back(item);
    return result;
}

static bool parse_decimal(const std::string &value, unsigned long long *result) {
    if (value.empty()) return false;
    const char *first = value.data();
    const char *last = first + value.size();
    const auto parsed = std::from_chars(first, last, *result, 10);
    return parsed.ec == std::errc() && parsed.ptr == last;
}

static bool parse_hex(const std::string &value, uintptr_t *result) {
    if (value.empty()) return false;
    const size_t start = value.size() >= 2 && value[0] == '0' &&
                                 (value[1] == 'x' || value[1] == 'X')
                         ? 2
                         : 0;
    if (start == value.size()) return false;
    unsigned long long parsed = 0;
    const char *first = value.data() + start;
    const char *last = value.data() + value.size();
    const auto conversion = std::from_chars(first, last, parsed, 16);
    if (conversion.ec != std::errc() || conversion.ptr != last ||
        parsed > static_cast<unsigned long long>(UINTPTR_MAX)) {
        return false;
    }
    *result = static_cast<uintptr_t>(parsed);
    return true;
}

static bool is_power_of_two(unsigned long long value) {
    return value != 0 && (value & (value - 1)) == 0;
}

static TraceConfig invalid_config(TraceConfig config, std::string error) {
    config.valid = false;
    config.error = std::move(error);
    return config;
}

const char *trace_profile_name(TraceProfile profile) {
    switch (profile) {
        case TraceProfile::Fast:
            return "fast";
        case TraceProfile::Balanced:
            return "balanced";
        case TraceProfile::Full:
            return "full";
    }
    return "unknown";
}

TraceConfig default_trace_config() {
    TraceConfig config;
    config.scenes = {
            {0, "init",      0},
            {1, "jni",       0},
            {2, "libc",      0},
            {3, "algorithm", 0},
            {4, "integrity", 0},
            {5, "benchmark", 0},
    };
    return config;
}

TraceConfig parse_trace_config(const char *encoded_config) {
    TraceConfig config = default_trace_config();
    if (encoded_config == nullptr || encoded_config[0] == 0) return config;
    bool lz4_level_explicit = false;

    for (const std::string &part: split(encoded_config, ';')) {
        if (part.empty()) continue;
        if (part.rfind("package=", 0) == 0) {
            config.package_name = part.substr(8);
        } else if (part.rfind("target=", 0) == 0) {
            config.target_so = part.substr(7);
        } else if (part.rfind("scene=", 0) == 0) {
            std::vector<std::string> fields = split(part.substr(6), ',');
            if (fields.size() < 2 || fields.size() > 3 || fields[0].empty()) {
                return invalid_config(std::move(config), "invalid scene configuration: " + part);
            }
            uintptr_t offset = 0;
            if (!parse_hex(fields[1], &offset)) {
                return invalid_config(std::move(config), "invalid scene offset: " + fields[1]);
            }
            uintptr_t end_offset = 0;
            if (fields.size() == 3 && !parse_hex(fields[2], &end_offset)) {
                return invalid_config(std::move(config), "invalid scene end offset: " + fields[2]);
            }
            for (auto &scene: config.scenes) {
                if (scene.name != fields[0]) continue;
                scene.offset = offset;
                scene.end_offset = end_offset;
            }
        } else if (part.rfind("jni_bt=", 0) == 0) {
            config.jni_backtrace_funcs = split(part.substr(7), ',');
        } else if (part.rfind("profile=", 0) == 0) {
            const std::string value = part.substr(8);
            if (value == "fast") {
                config.trace.profile = TraceProfile::Fast;
            } else if (value == "balanced") {
                config.trace.profile = TraceProfile::Balanced;
            } else if (value == "full") {
                config.trace.profile = TraceProfile::Full;
            } else {
                return invalid_config(std::move(config), "unknown trace profile: " + value);
            }
        } else if (part.rfind("compression=", 0) == 0) {
            const std::string value = part.substr(12);
            if (value == "0") {
                config.trace.compression_enabled = false;
            } else if (value == "1") {
                config.trace.compression_enabled = true;
            } else {
                return invalid_config(std::move(config), "invalid compression setting: " + value);
            }
        } else if (part.rfind("lz4_level=", 0) == 0) {
            const std::string value = part.substr(10);
            unsigned long long level = 0;
            if (!parse_decimal(value, &level) || level > 12) {
                return invalid_config(std::move(config), "invalid lz4_level: " + value);
            }
            config.trace.lz4_level = static_cast<int>(level);
            lz4_level_explicit = true;
        } else if (part.rfind("auto_buffer=", 0) == 0) {
            const std::string value = part.substr(12);
            if (value == "0") {
                config.trace.auto_buffer_size = false;
            } else if (value == "1") {
                config.trace.auto_buffer_size = true;
            } else {
                return invalid_config(std::move(config), "invalid auto_buffer setting: " + value);
            }
        } else if (part.rfind("buffer_mb=", 0) == 0) {
            const std::string value = part.substr(10);
            unsigned long long megabytes = 0;
            if (!parse_decimal(value, &megabytes) || (megabytes != 0 &&
                                                       (megabytes < 8 || megabytes > 128))) {
                return invalid_config(std::move(config), "invalid buffer_mb: " + value);
            }
            config.trace.buffer_bytes = static_cast<size_t>(megabytes * 1024 * 1024);
            config.trace.auto_buffer_size = megabytes == 0;
        } else if (part.rfind("hexdump_limit=", 0) == 0) {
            const std::string value = part.substr(14);
            unsigned long long limit = 0;
            if (!parse_decimal(value, &limit) || limit > 64) {
                return invalid_config(std::move(config), "invalid hexdump_limit: " + value);
            }
            config.trace.hexdump_limit = static_cast<size_t>(limit);
        } else if (part.rfind("flight=", 0) == 0) {
            const std::string value = part.substr(7);
            if (value == "0") {
                config.flight.enabled = false;
            } else if (value == "1") {
                config.flight.enabled = true;
            } else {
                return invalid_config(std::move(config), "invalid flight setting: " + value);
            }
        } else if (part.rfind("flight_mb=", 0) == 0) {
            const std::string value = part.substr(10);
            unsigned long long megabytes = 0;
            if (!parse_decimal(value, &megabytes) || megabytes < 64 || megabytes > 2048) {
                return invalid_config(std::move(config), "invalid flight_mb: " + value);
            }
            config.flight.capacity_bytes = megabytes * 1024ULL * 1024ULL;
        } else if (part.rfind("flight_chunk_kb=", 0) == 0) {
            const std::string value = part.substr(16);
            unsigned long long kilobytes = 0;
            if (!parse_decimal(value, &kilobytes) || kilobytes < 64 || kilobytes > 1024 ||
                !is_power_of_two(kilobytes)) {
                return invalid_config(std::move(config), "invalid flight_chunk_kb: " + value);
            }
            config.flight.chunk_bytes = static_cast<uint32_t>(kilobytes * 1024ULL);
        } else if (part.rfind("flight_max_threads=", 0) == 0) {
            const std::string value = part.substr(19);
            unsigned long long threads = 0;
            if (!parse_decimal(value, &threads) || threads < 1 || threads > 1024) {
                return invalid_config(std::move(config), "invalid flight_max_threads: " + value);
            }
            config.flight.max_threads = static_cast<uint32_t>(threads);
        } else if (part.rfind("flight_protected_chunks=", 0) == 0) {
            const std::string value = part.substr(24);
            unsigned long long chunks = 0;
            if (!parse_decimal(value, &chunks) || chunks == 0 || chunks > UINT32_MAX) {
                return invalid_config(std::move(config), "invalid flight_protected_chunks: " + value);
            }
            config.flight.protected_chunks = static_cast<uint32_t>(chunks);
#ifndef NDEBUG
        } else if (part.rfind("test_buffer_bytes=", 0) == 0) {
            const std::string value = part.substr(18);
            unsigned long long bytes = 0;
            if (!parse_decimal(value, &bytes) || bytes != 4096) {
                return invalid_config(std::move(config), "invalid test_buffer_bytes: " + value);
            }
            config.trace.buffer_bytes = static_cast<size_t>(bytes);
            config.trace.auto_buffer_size = false;
        } else if (part == "test_fail_setup=1") {
            config.test_fail_setup = true;
#endif
        } else {
            return invalid_config(std::move(config), "unknown trace configuration field: " + part);
        }
    }
    if (!lz4_level_explicit && config.trace.profile != TraceProfile::Fast) {
        config.trace.lz4_level = 2;
    }
    if (static_cast<uint64_t>(config.flight.protected_chunks) * config.flight.chunk_bytes >
        config.flight.capacity_bytes) {
        return invalid_config(std::move(config), "flight protected reservation exceeds capacity");
    }
    return config;
}
