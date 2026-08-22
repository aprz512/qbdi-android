#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <pthread.h>

constexpr uint32_t kModuleRetentionPendingFlag = 1U << 4U;
constexpr size_t kModuleRetentionPathBytes = 4096;
constexpr size_t kModuleRetentionProbeNameBytes = 256;

enum class ModuleRetentionState : uint32_t {
    Empty = 0,
    Loading,
    PublishingPending,
    Pending,
    Binding,
    Bound,
    Failed,
    Detached,
};

struct ModuleRetentionIdentity {
    uintptr_t base = 0;
    uintptr_t end = 0;
    char path[kModuleRetentionPathBytes]{};
    uintptr_t probe_address = 0;
    char probe_name[kModuleRetentionProbeNameBytes]{};
};

using ModuleRetentionSymbolResolver = void *(*)(
        void *handle, const char *name, void *opaque) noexcept;
bool module_retention_handle_matches(
        void *handle, const ModuleRetentionIdentity &identity,
        ModuleRetentionSymbolResolver resolver, void *opaque) noexcept;

struct ModuleRetentionAdapter {
    void *opaque = nullptr;
    void *(*retain_exact)(void *opaque,
                         const ModuleRetentionIdentity &identity) noexcept = nullptr;
};

struct ModuleRetentionFailureSink {
    void *opaque = nullptr;
    void (*report)(void *opaque,
                   const ModuleRetentionIdentity &identity) noexcept = nullptr;
};

class ModuleRetentionLease final {
public:
    ModuleRetentionState state() const noexcept {
        return state_.load(std::memory_order_acquire);
    }
    void *handle() const noexcept {
        return handle_.load(std::memory_order_acquire);
    }
    const ModuleRetentionIdentity &identity() const noexcept { return identity_; }
    uint64_t generation() const noexcept { return generation_; }

private:
    friend class ModuleGenerationRetainer;
    std::atomic<ModuleRetentionState> state_{ModuleRetentionState::Empty};
    ModuleRetentionIdentity identity_{};
    uint32_t *artifact_flags_ = nullptr;
    std::atomic<void *> handle_{nullptr};
    uint64_t generation_ = 0;
    uint32_t retain_attempts_ = 0;
    ModuleRetentionFailureSink failure_sink_{};
    std::shared_ptr<const void> *owner_ = nullptr;
};

class ModuleGenerationRetainer final {
public:
    static constexpr size_t kMaximumLeases = 64;
    static constexpr uint32_t kMaximumRetainAttempts = 200;

    explicit ModuleGenerationRetainer(ModuleRetentionAdapter adapter) noexcept
            : adapter_(adapter) {}
    ~ModuleGenerationRetainer();

    ModuleGenerationRetainer(const ModuleGenerationRetainer &) = delete;
    ModuleGenerationRetainer &operator=(const ModuleGenerationRetainer &) = delete;

    ModuleRetentionLease *begin_loading(
            const ModuleRetentionIdentity &identity,
            uint32_t *artifact_flags,
            uint64_t generation,
            ModuleRetentionFailureSink failure_sink = {},
            std::shared_ptr<const void> owner = {}) noexcept;
    ModuleRetentionLease *retain_postloaded(
            const ModuleRetentionIdentity &identity,
            uint32_t *artifact_flags,
            uint64_t generation,
            ModuleRetentionFailureSink failure_sink = {},
            std::shared_ptr<const void> owner = {}) noexcept;

    // Safe for a dynamic-linker constructor callback: bounded fixed-slot scan,
    // bounded byte comparison, and lock-free atomic operations only.
    __attribute__((noinline)) bool notify_constructor_returned(
            uintptr_t base, const char *path) noexcept;

    bool process_one_pending() noexcept;
    bool start_worker() noexcept;
    void shutdown() noexcept;
    void detach_after_fork_child() noexcept;

private:
    static void *worker_entry(void *opaque) noexcept;
    ModuleRetentionLease *find_exact(
            const ModuleRetentionIdentity &identity,
            uint64_t generation) noexcept;
    ModuleRetentionLease *claim_slot(
            const ModuleRetentionIdentity &identity,
            uint32_t *artifact_flags,
            uint64_t generation,
            ModuleRetentionFailureSink failure_sink,
            std::shared_ptr<const void> owner,
            bool *created) noexcept;

    ModuleRetentionAdapter adapter_{};
    std::array<ModuleRetentionLease, kMaximumLeases> leases_{};
    std::atomic<size_t> published_leases_{0};
    std::atomic<bool> detached_{false};
    std::atomic<bool> stopping_{false};
    std::atomic<bool> fork_child_{false};
    std::atomic<bool> worker_started_{false};
    pthread_t worker_{};
    pthread_mutex_t allocation_mutex_ = PTHREAD_MUTEX_INITIALIZER;
};
