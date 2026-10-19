#pragma once

#include <string_view>

#ifndef QTRACE_USER_RULES_SAMPLE_SHA256
#define QTRACE_USER_RULES_SAMPLE_SHA256 ""
#endif

inline bool user_rules_identity_matches(std::string_view sample_sha256) noexcept {
    constexpr std::string_view expected = QTRACE_USER_RULES_SAMPLE_SHA256;
    return expected.size() == 64 && sample_sha256 == expected;
}
