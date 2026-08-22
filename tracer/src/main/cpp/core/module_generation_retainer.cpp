#include "core/module_generation_retainer.h"

#include <cstring>
#include <new>
#include <utility>
#include <unistd.h>

namespace {

bool valid_identity(const ModuleRetentionIdentity &identity) noexcept {
    return identity.base != 0 && identity.end > identity.base &&
           identity.path[0] != '\0' &&
           std::memchr(identity.path, '\0', sizeof(identity.path)) != nullptr &&
           identity.probe_address >= identity.base &&
           identity.probe_address < identity.end &&
           identity.probe_name[0] != '\0' &&
           std::memchr(identity.probe_name, '\0',
                       sizeof(identity.probe_name)) != nullptr;
}

bool same_identity(const ModuleRetentionIdentity &left,
                   const ModuleRetentionIdentity &right) noexcept {
    return left.base == right.base && left.end == right.end &&
           left.probe_address == right.probe_address &&
           std::strncmp(left.path, right.path, sizeof(left.path)) == 0 &&
           std::strncmp(left.probe_name, right.probe_name,
                        sizeof(left.probe_name)) == 0;
}

__attribute__((always_inline)) inline bool bounded_path_equal(
        const char *left, const char *right) noexcept {
    if (left == nullptr || right == nullptr) return false;
    for (size_t index = 0; index < kModuleRetentionPathBytes; ++index) {
        const char l = left[index];
        const char r = right[index];
        if (l != r) return false;
        if (l == '\0') return true;
    }
    return false;
}

} // namespace

bool module_retention_handle_matches(
        void *handle, const ModuleRetentionIdentity &identity,
        ModuleRetentionSymbolResolver resolver, void *opaque) noexcept {
    if (handle == nullptr || resolver == nullptr ||
        identity.probe_address == 0 || identity.probe_name[0] == '\0') {
        return false;
    }
    return reinterpret_cast<uintptr_t>(
                   resolver(handle, identity.probe_name, opaque)) ==
           identity.probe_address;
}

ModuleRetentionLease *ModuleGenerationRetainer::find_exact(
        const ModuleRetentionIdentity &identity,
        uint64_t generation) noexcept {
    const size_t count = published_leases_.load(std::memory_order_acquire);
    for (size_t index = 0; index < count; ++index) {
        ModuleRetentionLease &lease = leases_[index];
        if (lease.generation_ == generation &&
            same_identity(lease.identity_, identity)) {
            return &lease;
        }
    }
    return nullptr;
}

ModuleRetentionLease *ModuleGenerationRetainer::claim_slot(
        const ModuleRetentionIdentity &identity,
        uint32_t *artifact_flags,
        uint64_t generation,
        ModuleRetentionFailureSink failure_sink,
        std::shared_ptr<const void> owner,
        bool *created) noexcept {
    if (created != nullptr) *created = false;
    if (detached_.load(std::memory_order_acquire) || !valid_identity(identity) ||
        artifact_flags == nullptr || generation == 0) {
        return nullptr;
    }
    if (::pthread_mutex_lock(&allocation_mutex_) != 0) return nullptr;
    ModuleRetentionLease *lease = find_exact(identity, generation);
    if (lease == nullptr) {
        const size_t published =
                published_leases_.load(std::memory_order_relaxed);
        for (size_t index = 0; index < published; ++index) {
            if (leases_[index].artifact_flags_ == artifact_flags) {
                (void)::pthread_mutex_unlock(&allocation_mutex_);
                return nullptr;
            }
        }
        const size_t index = published_leases_.load(std::memory_order_relaxed);
        if (index < leases_.size()) {
            auto *owner_cell = new (std::nothrow)
                    std::shared_ptr<const void>(std::move(owner));
            if (owner_cell == nullptr) {
                (void)::pthread_mutex_unlock(&allocation_mutex_);
                return nullptr;
            }
            lease = &leases_[index];
            lease->identity_ = identity;
            lease->artifact_flags_ = artifact_flags;
            lease->generation_ = generation;
            lease->retain_attempts_ = 0;
            lease->failure_sink_ = failure_sink;
            lease->owner_ = owner_cell;
            lease->handle_.store(nullptr, std::memory_order_relaxed);
            lease->state_.store(ModuleRetentionState::Loading,
                                std::memory_order_relaxed);
            published_leases_.store(index + 1U, std::memory_order_release);
            if (created != nullptr) *created = true;
        }
    }
    (void)::pthread_mutex_unlock(&allocation_mutex_);
    return lease;
}

ModuleRetentionLease *ModuleGenerationRetainer::begin_loading(
        const ModuleRetentionIdentity &identity,
        uint32_t *artifact_flags,
        uint64_t generation,
        ModuleRetentionFailureSink failure_sink,
        std::shared_ptr<const void> owner) noexcept {
    return claim_slot(identity, artifact_flags, generation, failure_sink,
                      std::move(owner), nullptr);
}

ModuleRetentionLease *ModuleGenerationRetainer::retain_postloaded(
        const ModuleRetentionIdentity &identity,
        uint32_t *artifact_flags,
        uint64_t generation,
        ModuleRetentionFailureSink failure_sink,
        std::shared_ptr<const void> owner) noexcept {
    bool created = false;
    ModuleRetentionLease *lease = claim_slot(
            identity, artifact_flags, generation, failure_sink,
            std::move(owner), &created);
    if (lease == nullptr) return nullptr;
    if (lease->state() == ModuleRetentionState::Bound) return lease;
    // A constructor-time install already owns this exact generation through
    // the active loader call. A postloaded API duplicate must not try dlopen
    // while that call still holds the linker lock.
    if (!created && lease->state() == ModuleRetentionState::Loading) {
        return lease;
    }
    ModuleRetentionState expected = ModuleRetentionState::Loading;
    if (!lease->state_.compare_exchange_strong(
                expected, ModuleRetentionState::Binding,
                std::memory_order_acq_rel, std::memory_order_acquire)) {
        return nullptr;
    }
    void *handle = adapter_.retain_exact == nullptr
                           ? nullptr
                           : adapter_.retain_exact(adapter_.opaque,
                                                   lease->identity_);
    if (handle == nullptr) {
        lease->state_.store(ModuleRetentionState::Failed,
                            std::memory_order_release);
        (void)__atomic_fetch_or(lease->artifact_flags_,
                                kModuleRetentionPendingFlag, __ATOMIC_RELEASE);
        if (lease->failure_sink_.report != nullptr) {
            lease->failure_sink_.report(lease->failure_sink_.opaque,
                                        lease->identity_);
        }
        return nullptr;
    }
    lease->handle_.store(handle, std::memory_order_release);
    lease->state_.store(ModuleRetentionState::Bound, std::memory_order_release);
    return lease;
}

bool ModuleGenerationRetainer::notify_constructor_returned(
        uintptr_t base, const char *path) noexcept {
    if (detached_.load(std::memory_order_acquire) || base == 0 || path == nullptr)
        return false;
    const size_t count = published_leases_.load(std::memory_order_acquire);
    for (size_t index = 0; index < count; ++index) {
        ModuleRetentionLease &lease = leases_[index];
        if (lease.identity_.base != base ||
            !bounded_path_equal(lease.identity_.path, path)) {
            continue;
        }
        ModuleRetentionState expected = ModuleRetentionState::Loading;
        if (!lease.state_.compare_exchange_strong(
                    expected, ModuleRetentionState::PublishingPending,
                    std::memory_order_acq_rel, std::memory_order_acquire)) {
            continue;
        }
        (void)__atomic_fetch_or(lease.artifact_flags_,
                                kModuleRetentionPendingFlag, __ATOMIC_RELEASE);
        lease.state_.store(ModuleRetentionState::Pending,
                           std::memory_order_release);
        return true;
    }
    return false;
}

bool ModuleGenerationRetainer::process_one_pending() noexcept {
    if (detached_.load(std::memory_order_acquire)) return false;
    const size_t count = published_leases_.load(std::memory_order_acquire);
    for (size_t index = 0; index < count; ++index) {
        ModuleRetentionLease &lease = leases_[index];
        ModuleRetentionState expected = ModuleRetentionState::Pending;
        if (!lease.state_.compare_exchange_strong(
                    expected, ModuleRetentionState::Binding,
                    std::memory_order_acq_rel, std::memory_order_acquire)) {
            continue;
        }
        ++lease.retain_attempts_;
        void *handle = adapter_.retain_exact == nullptr
                               ? nullptr
                               : adapter_.retain_exact(adapter_.opaque,
                                                       lease.identity_);
        if (handle == nullptr) {
            const bool exhausted =
                    lease.retain_attempts_ >= kMaximumRetainAttempts;
            lease.state_.store(exhausted ? ModuleRetentionState::Failed
                                         : ModuleRetentionState::Pending,
                               std::memory_order_release);
            if (exhausted && lease.failure_sink_.report != nullptr) {
                lease.failure_sink_.report(lease.failure_sink_.opaque,
                                           lease.identity_);
            }
            return true;
        }
        lease.handle_.store(handle, std::memory_order_release);
        lease.state_.store(ModuleRetentionState::Bound,
                           std::memory_order_release);
        (void)__atomic_fetch_and(lease.artifact_flags_,
                                 ~kModuleRetentionPendingFlag,
                                 __ATOMIC_RELEASE);
        return true;
    }
    return false;
}

void *ModuleGenerationRetainer::worker_entry(void *opaque) noexcept {
    auto *retainer = static_cast<ModuleGenerationRetainer *>(opaque);
    while (!retainer->stopping_.load(std::memory_order_acquire) &&
           !retainer->detached_.load(std::memory_order_acquire)) {
        (void)retainer->process_one_pending();
        (void)::usleep(10 * 1000);
    }
    return nullptr;
}

bool ModuleGenerationRetainer::start_worker() noexcept {
    bool expected = false;
    if (!worker_started_.compare_exchange_strong(
                expected, true, std::memory_order_acq_rel,
                std::memory_order_acquire)) {
        return true;
    }
    if (::pthread_create(&worker_, nullptr, worker_entry, this) != 0) {
        worker_started_.store(false, std::memory_order_release);
        return false;
    }
    return true;
}

ModuleGenerationRetainer::~ModuleGenerationRetainer() {
    shutdown();
}

void ModuleGenerationRetainer::shutdown() noexcept {
    if (fork_child_.load(std::memory_order_acquire)) return;
    stopping_.store(true, std::memory_order_release);
    if (worker_started_.exchange(false, std::memory_order_acq_rel)) {
        (void)::pthread_join(worker_, nullptr);
    }
    const size_t count = published_leases_.load(std::memory_order_acquire);
    for (size_t index = 0; index < count; ++index) {
        delete leases_[index].owner_;
        leases_[index].owner_ = nullptr;
    }
}

void ModuleGenerationRetainer::detach_after_fork_child() noexcept {
    fork_child_.store(true, std::memory_order_release);
    detached_.store(true, std::memory_order_release);
    worker_started_.store(false, std::memory_order_release);
    const size_t count = published_leases_.load(std::memory_order_acquire);
    for (size_t index = 0; index < count; ++index) {
        leases_[index].state_.store(ModuleRetentionState::Detached,
                                    std::memory_order_release);
    }
}
