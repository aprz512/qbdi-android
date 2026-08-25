#pragma once

#include "core/trace_config.h"

#include <string>
#include <string_view>

struct ConfigurationIssue {
    std::string code;
    std::string path;
    std::string message;
};

struct PreparedConfiguration {
    TraceConfig config;
    ConfigurationIssue error;

    bool accepted() const noexcept { return error.code.empty(); }
};

PreparedConfiguration prepare_tracer_configuration(std::string_view request);
std::string serialize_configure_rejection(const ConfigurationIssue &issue);
