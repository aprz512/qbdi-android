#include "core/trace_config.h"

bool trace_session_id_is_uuid_v4(std::string_view value) noexcept {
    if (value.size() != 36 || value[8] != '-' || value[13] != '-' ||
        value[18] != '-' || value[23] != '-' || value[14] != '4' ||
        (value[19] != '8' && value[19] != '9' && value[19] != 'a' && value[19] != 'b')) {
        return false;
    }

    bool all_zero = true;
    for (size_t index = 0; index != value.size(); ++index) {
        if (index == 8 || index == 13 || index == 18 || index == 23) continue;
        const char character = value[index];
        if (!((character >= '0' && character <= '9') ||
              (character >= 'a' && character <= 'f'))) {
            return false;
        }
        all_zero = all_zero && character == '0';
    }
    return !all_zero;
}

bool trace_package_name_is_valid(std::string_view value) noexcept {
    if (value.empty() || value.size() > 512) return false;
    bool segment_start = true;
    for (char character : value) {
        if (character == '.') {
            if (segment_start) return false;
            segment_start = true;
            continue;
        }
        const bool alphabetic = (character >= 'a' && character <= 'z') ||
                                (character >= 'A' && character <= 'Z');
        const bool decimal = character >= '0' && character <= '9';
        if ((segment_start && !alphabetic) ||
            (!segment_start && !alphabetic && !decimal && character != '_')) return false;
        segment_start = false;
    }
    return !segment_start;
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
