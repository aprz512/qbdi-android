#pragma once

#include "jni/jni_function_registry.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

class JniCallResolver {
public:
    using MemoryReader = std::function<bool(uintptr_t, void *, size_t)>;

    explicit JniCallResolver(MemoryReader memory_reader);
    JniCallResolver(const JniCallResolver &) = delete;
    JniCallResolver &operator=(const JniCallResolver &) = delete;

    const JniFuncInfo *resolve(uintptr_t receiver, uintptr_t target);

private:
    enum class InterfaceKind { Env, Vm };

    struct TableSnapshot {
        InterfaceKind kind = InterfaceKind::Env;
        std::vector<std::pair<std::string_view, uintptr_t>> entries;
    };

    bool read_word(uintptr_t address, uintptr_t *value) const;
    std::optional<TableSnapshot> inspect(uintptr_t receiver,
                                         uintptr_t target) const;
    static std::unique_ptr<JniFunctionRegistry>
    build_registry(const TableSnapshot &snapshot);

    MemoryReader memory_reader_;
    std::once_flag env_once_;
    std::once_flag vm_once_;
    std::unique_ptr<JniFunctionRegistry> env_storage_;
    std::unique_ptr<JniFunctionRegistry> vm_storage_;
    std::atomic<const JniFunctionRegistry *> env_registry_{nullptr};
    std::atomic<const JniFunctionRegistry *> vm_registry_{nullptr};
};
