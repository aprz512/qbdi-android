#include "jni/jni_call_resolver.h"

#include <array>
#include <cstring>
#include <limits>

namespace {

constexpr size_t kEnvReservedSlots = 4;
constexpr size_t kVmReservedSlots = 3;
constexpr uintptr_t kMinimumPointer = 0x1000;

const std::vector<JniFuncInfo> &jni_metadata() {
    static const std::vector<JniFuncInfo> metadata = build_jni_function_table();
    return metadata;
}

} // namespace

JniCallResolver::JniCallResolver(MemoryReader memory_reader)
        : memory_reader_(std::move(memory_reader)) {}

bool JniCallResolver::read_word(uintptr_t address, uintptr_t *value) const {
    return value != nullptr && address > kMinimumPointer && memory_reader_ &&
           memory_reader_(address, value, sizeof(*value));
}

std::optional<JniCallResolver::TableSnapshot>
JniCallResolver::inspect(uintptr_t receiver, uintptr_t target) const {
    if (receiver <= kMinimumPointer || target <= kMinimumPointer) return std::nullopt;

    uintptr_t vtable = 0;
    if (!read_word(receiver, &vtable) || vtable <= kMinimumPointer) {
        return std::nullopt;
    }

    std::array<uintptr_t, kEnvReservedSlots> leading_slots{};
    for (size_t slot = 0; slot < leading_slots.size(); ++slot) {
        if (slot > (std::numeric_limits<uintptr_t>::max() - vtable) /
                           sizeof(uintptr_t) ||
            !read_word(vtable + slot * sizeof(uintptr_t), &leading_slots[slot])) {
            return std::nullopt;
        }
    }
    if (leading_slots[0] != 0 || leading_slots[1] != 0 || leading_slots[2] != 0) {
        return std::nullopt;
    }

    InterfaceKind kind;
    if (leading_slots[3] == 0) {
        kind = InterfaceKind::Env;
    } else if (leading_slots[3] > kMinimumPointer) {
        kind = InterfaceKind::Vm;
    } else {
        return std::nullopt;
    }

    TableSnapshot snapshot;
    snapshot.kind = kind;
    const std::string_view expected_interface =
            kind == InterfaceKind::Env ? "JNIEnv" : "JavaVM";
    size_t slot = kind == InterfaceKind::Env ? kEnvReservedSlots : kVmReservedSlots;
    bool contains_target = false;
    for (const auto &function: jni_metadata()) {
        if (expected_interface != function.struct_name) continue;
        if (slot > (std::numeric_limits<uintptr_t>::max() - vtable) /
                           sizeof(uintptr_t)) {
            return std::nullopt;
        }
        uintptr_t address = 0;
        if (!read_word(vtable + slot * sizeof(uintptr_t), &address) ||
            address <= kMinimumPointer) {
            return std::nullopt;
        }
        snapshot.entries.emplace_back(function.name, address);
        contains_target = contains_target || address == target;
        ++slot;
    }
    if (!contains_target || snapshot.entries.empty()) return std::nullopt;
    return snapshot;
}

std::unique_ptr<JniFunctionRegistry>
JniCallResolver::build_registry(const TableSnapshot &snapshot) {
    auto registry = std::make_unique<JniFunctionRegistry>();
    for (const auto &[name, address]: snapshot.entries) {
        (void)registry->bind(name, address);
    }
    return registry;
}

const JniFuncInfo *JniCallResolver::resolve(uintptr_t receiver, uintptr_t target) {
    if (const auto *registry = env_registry_.load(std::memory_order_acquire)) {
        if (const JniFuncInfo *function = registry->find(target)) return function;
    }
    if (const auto *registry = vm_registry_.load(std::memory_order_acquire)) {
        if (const JniFuncInfo *function = registry->find(target)) return function;
    }

    auto snapshot = inspect(receiver, target);
    if (!snapshot) return nullptr;

    if (snapshot->kind == InterfaceKind::Env) {
        std::call_once(env_once_, [this, &snapshot] {
            env_storage_ = build_registry(*snapshot);
            env_registry_.store(env_storage_.get(), std::memory_order_release);
        });
        const auto *registry = env_registry_.load(std::memory_order_acquire);
        return registry != nullptr ? registry->find(target) : nullptr;
    }

    std::call_once(vm_once_, [this, &snapshot] {
        vm_storage_ = build_registry(*snapshot);
        vm_registry_.store(vm_storage_.get(), std::memory_order_release);
    });
    const auto *registry = vm_registry_.load(std::memory_order_acquire);
    return registry != nullptr ? registry->find(target) : nullptr;
}
