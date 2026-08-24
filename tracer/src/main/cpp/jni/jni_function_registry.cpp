#include "jni/jni_function_registry.h"

#include <algorithm>

JniFunctionRegistry::JniFunctionRegistry()
        : functions_(build_jni_function_table()) {}

bool JniFunctionRegistry::bind(std::string_view name, uintptr_t address) {
    if (address == 0 || by_address_.find(address) != by_address_.end()) return false;

    auto function = std::find_if(functions_.begin(), functions_.end(), [name](const auto &entry) {
        return name == entry.name;
    });
    if (function == functions_.end() || function->address != 0) return false;

    function->address = address;
    by_address_.emplace(address, &*function);
    return true;
}

bool JniFunctionRegistry::is_bound(std::string_view name) const {
    const auto function = std::find_if(
            functions_.begin(), functions_.end(), [name](const auto &entry) {
                return name == entry.name;
            });
    return function != functions_.end() && function->address != 0;
}

const JniFuncInfo *JniFunctionRegistry::find(uintptr_t address) const {
    const auto function = by_address_.find(address);
    return function == by_address_.end() ? nullptr : function->second;
}

const std::vector<JniFuncInfo> &JniFunctionRegistry::functions() const {
    return functions_;
}

size_t JniFunctionRegistry::size() const {
    return by_address_.size();
}
