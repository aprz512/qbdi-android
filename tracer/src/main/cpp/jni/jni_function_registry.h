#pragma once

#include "jni/jni_function_table.h"

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

class JniFunctionRegistry {
public:
    JniFunctionRegistry();

    bool bind(std::string_view name, uintptr_t address);
    bool is_bound(std::string_view name) const;
    const JniFuncInfo *find(uintptr_t address) const;
    const std::vector<JniFuncInfo> &functions() const;
    size_t size() const;

private:
    std::vector<JniFuncInfo> functions_;
    JniAddressMap by_address_;
};
