#include "core/trace_config.h"

#include <cstdlib>
#include <sstream>
#include <string>
#include <vector>

static std::vector<std::string> split(const std::string &value, char delimiter) {
    std::vector<std::string> result;
    std::stringstream input(value);
    std::string item;
    while (std::getline(input, item, delimiter)) result.push_back(item);
    return result;
}

TraceConfig default_trace_config() {
    TraceConfig config;
    config.scenes = {
            {0, "init",      0},
            {1, "jni",       0},
            {2, "libc",      0},
            {3, "algorithm", 0},
            {4, "integrity", 0},
    };
    return config;
}

TraceConfig parse_trace_config(const char *encoded_config) {
    TraceConfig config = default_trace_config();
    if (encoded_config == nullptr || encoded_config[0] == 0) return config;

    for (const std::string &part: split(encoded_config, ';')) {
        if (part.rfind("package=", 0) == 0) {
            config.package_name = part.substr(8);
        } else if (part.rfind("target=", 0) == 0) {
            config.target_so = part.substr(7);
        } else if (part.rfind("scene=", 0) == 0) {
            std::vector<std::string> fields = split(part.substr(6), ',');
            if (fields.size() < 2) continue;
            for (auto &scene: config.scenes) {
                if (scene.name != fields[0]) continue;
                scene.offset = strtoull(fields[1].c_str(), nullptr, 16);
                if (fields.size() >= 3) {
                    scene.end_offset = strtoull(fields[2].c_str(), nullptr, 16);
                }
            }
        } else if (part.rfind("jni_bt=", 0) == 0) {
            config.jni_backtrace_funcs = split(part.substr(7), ',');
        }
    }
    return config;
}
