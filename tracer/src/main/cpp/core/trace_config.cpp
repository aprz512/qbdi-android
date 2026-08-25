#include "core/trace_config.h"

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
