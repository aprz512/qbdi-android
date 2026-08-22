#include "core/module_generation_retainer.h"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {

void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

struct FakeRetain {
    alignas(uint32_t) uint32_t flags = 0;
    int calls = 0;
    bool exact = true;
    void *handle = reinterpret_cast<void *>(0x1234);
    int failures = 0;
};

void *retain_exact(void *opaque, const ModuleRetentionIdentity &) noexcept {
    auto *fake = static_cast<FakeRetain *>(opaque);
    ++fake->calls;
    return fake->exact ? fake->handle : nullptr;
}

void report_failure(void *opaque,
                    const ModuleRetentionIdentity &) noexcept {
    ++static_cast<FakeRetain *>(opaque)->failures;
}

void *resolve_probe(void *, const char *, void *opaque) noexcept {
    return opaque;
}

ModuleRetentionIdentity identity(uintptr_t base = 0x70000000) {
    ModuleRetentionIdentity result{};
    result.base = base;
    result.end = base + 0x4000;
    std::strcpy(result.path, "/data/app/libtarget.so");
    result.probe_address = base + 0x100;
    std::strcpy(result.probe_name, "target_probe");
    return result;
}

void loading_is_complete_until_the_constructor_returns() {
    FakeRetain fake;
    ModuleGenerationRetainer retainer({&fake, retain_exact});
    ModuleRetentionLease *lease = retainer.begin_loading(
            identity(), &fake.flags, 1);
    CHECK(lease != nullptr);
    CHECK(lease->state() == ModuleRetentionState::Loading);
    CHECK(__atomic_load_n(&fake.flags, __ATOMIC_ACQUIRE) == 0);
    CHECK(fake.calls == 0);
}

void post_callback_publishes_incomplete_before_pending() {
    FakeRetain fake;
    ModuleGenerationRetainer retainer({&fake, retain_exact});
    ModuleRetentionLease *lease = retainer.begin_loading(
            identity(), &fake.flags, 1);
    CHECK(retainer.notify_constructor_returned(0x70000000,
                                               "/data/app/libtarget.so"));
    CHECK(lease->state() == ModuleRetentionState::Pending);
    CHECK((__atomic_load_n(&fake.flags, __ATOMIC_ACQUIRE) &
           kModuleRetentionPendingFlag) != 0);
    CHECK(fake.calls == 0);
}

void worker_binds_exact_generation_then_clears_only_transient_flag() {
    FakeRetain fake;
    __atomic_store_n(&fake.flags, kModuleRetentionPendingFlag | 0x4U,
                     __ATOMIC_RELEASE);
    ModuleGenerationRetainer retainer({&fake, retain_exact});
    ModuleRetentionLease *lease = retainer.begin_loading(
            identity(), &fake.flags, 1);
    CHECK(retainer.notify_constructor_returned(0x70000000,
                                               "/data/app/libtarget.so"));
    CHECK(retainer.process_one_pending());
    CHECK(lease->state() == ModuleRetentionState::Bound);
    CHECK(lease->handle() == fake.handle);
    CHECK(fake.calls == 1);
    CHECK(__atomic_load_n(&fake.flags, __ATOMIC_ACQUIRE) == 0x4U);
}

void mismatch_fails_permanently_without_clearing_pending() {
    FakeRetain fake;
    fake.exact = false;
    ModuleGenerationRetainer retainer({&fake, retain_exact});
    ModuleRetentionLease *lease = retainer.begin_loading(
            identity(), &fake.flags, 1, {&fake, report_failure});
    CHECK(retainer.notify_constructor_returned(0x70000000,
                                               "/data/app/libtarget.so"));
    for (uint32_t attempt = 0;
         attempt < ModuleGenerationRetainer::kMaximumRetainAttempts; ++attempt) {
        CHECK(retainer.process_one_pending());
    }
    CHECK(lease->state() == ModuleRetentionState::Failed);
    CHECK((__atomic_load_n(&fake.flags, __ATOMIC_ACQUIRE) &
           kModuleRetentionPendingFlag) != 0);
    CHECK(fake.failures == 1);
}

void exact_generation_is_shared_and_postloaded_install_is_synchronous() {
    FakeRetain fake;
    ModuleGenerationRetainer retainer({&fake, retain_exact});
    ModuleRetentionLease *first = retainer.begin_loading(
            identity(), &fake.flags, 7);
    ModuleRetentionLease *second = retainer.begin_loading(
            identity(), &fake.flags, 7);
    CHECK(first == second);
    CHECK(fake.calls == 0);
    CHECK(retainer.retain_postloaded(identity(), &fake.flags, 7) == first);
    CHECK(fake.calls == 0);
    CHECK(retainer.notify_constructor_returned(0x70000000,
                                               "/data/app/libtarget.so"));
    CHECK(retainer.process_one_pending());
    CHECK(first->state() == ModuleRetentionState::Bound);
    CHECK(fake.calls == 1);

    FakeRetain postloaded;
    ModuleGenerationRetainer postloaded_retainer({&postloaded, retain_exact});
    ModuleRetentionLease *bound = postloaded_retainer.retain_postloaded(
            identity(0x71000000), &postloaded.flags, 8);
    CHECK(bound != nullptr);
    CHECK(bound->state() == ModuleRetentionState::Bound);
    CHECK(postloaded.calls == 1);
}

void detached_registry_ignores_late_post_and_worker() {
    FakeRetain fake;
    ModuleGenerationRetainer retainer({&fake, retain_exact});
    ModuleRetentionLease *lease = retainer.begin_loading(
            identity(), &fake.flags, 1);
    retainer.detach_after_fork_child();
    CHECK(!retainer.notify_constructor_returned(0x70000000,
                                                "/data/app/libtarget.so"));
    CHECK(!retainer.process_one_pending());
    CHECK(lease->state() == ModuleRetentionState::Detached);
    CHECK(__atomic_load_n(&fake.flags, __ATOMIC_ACQUIRE) == 0);
    CHECK(fake.calls == 0);
}

void reconfiguration_keeps_each_artifact_owned_and_clears_its_own_flag() {
    FakeRetain fake;
    alignas(uint32_t) uint32_t second_flags = 0;
    auto first_owner = std::make_shared<int>(1);
    auto second_owner = std::make_shared<int>(2);
    std::weak_ptr<int> first_lifetime = first_owner;
    std::weak_ptr<int> second_lifetime = second_owner;
    ModuleGenerationRetainer retainer({&fake, retain_exact});
    CHECK(retainer.begin_loading(identity(), &fake.flags, 1, {},
                                 first_owner) != nullptr);
    CHECK(retainer.begin_loading(identity(0x71000000), &second_flags, 2, {},
                                 second_owner) != nullptr);
    first_owner.reset();
    second_owner.reset();
    CHECK(!first_lifetime.expired());
    CHECK(!second_lifetime.expired());
    CHECK(retainer.notify_constructor_returned(0x70000000,
                                               "/data/app/libtarget.so"));
    CHECK(retainer.notify_constructor_returned(0x71000000,
                                               "/data/app/libtarget.so"));
    CHECK(retainer.process_one_pending());
    CHECK(__atomic_load_n(&fake.flags, __ATOMIC_ACQUIRE) == 0);
    CHECK((__atomic_load_n(&second_flags, __ATOMIC_ACQUIRE) &
           kModuleRetentionPendingFlag) != 0);
    CHECK(retainer.process_one_pending());
    CHECK(__atomic_load_n(&second_flags, __ATOMIC_ACQUIRE) == 0);
    retainer.shutdown();
    CHECK(first_lifetime.expired());
    CHECK(second_lifetime.expired());
}

void returned_handle_must_resolve_the_exact_generation_probe() {
    ModuleRetentionIdentity target = identity();
    CHECK(module_retention_handle_matches(
            reinterpret_cast<void *>(0x1), target, resolve_probe,
            reinterpret_cast<void *>(target.probe_address)));
    CHECK(!module_retention_handle_matches(
            reinterpret_cast<void *>(0x1), target, resolve_probe,
            reinterpret_cast<void *>(target.probe_address + 4U)));
}

} // namespace

int main() {
    loading_is_complete_until_the_constructor_returns();
    post_callback_publishes_incomplete_before_pending();
    worker_binds_exact_generation_then_clears_only_transient_flag();
    mismatch_fails_permanently_without_clearing_pending();
    exact_generation_is_shared_and_postloaded_install_is_synchronous();
    detached_registry_ignores_late_post_and_worker();
    reconfiguration_keeps_each_artifact_owned_and_clears_its_own_flag();
    returned_handle_must_resolve_the_exact_generation_probe();
}
