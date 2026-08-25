#include "core/capture_coordinator.h"
#include "core/qbdi_thread_session.h"
#include "hooks/thread_create_gateway.h"

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <new>
#include <pthread.h>
#include <sched.h>
#include <string_view>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

extern "C" __attribute__((noinline, visibility("default")))
void *unrelated_start(void *argument) {
  return reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(argument) + 1U);
}

extern "C" __attribute__((noinline, visibility("default")))
void *nested_external_start(void *argument) {
  return argument;
}

namespace {

using StartRoutine = void *(*)(void *);

void check(bool condition, const char *expression, int line) {
  if (condition)
    return;
  std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
  std::abort();
}

#define CHECK(expression)                                                      \
  check(static_cast<bool>(expression), #expression, __LINE__)

std::atomic<bool> g_fail_next_nothrow_allocation{false};
std::atomic<bool> g_forbid_nothrow_allocation{false};

extern "C" void *__real__ZnwmRKSt9nothrow_t(std::size_t,
                                            const std::nothrow_t &);
extern "C" void *__wrap__ZnwmRKSt9nothrow_t(std::size_t size,
                                            const std::nothrow_t &tag) {
  if (g_forbid_nothrow_allocation.load(std::memory_order_relaxed))
    _exit(81);
  if (g_fail_next_nothrow_allocation.exchange(false,
                                              std::memory_order_relaxed)) {
    return nullptr;
  }
  return __real__ZnwmRKSt9nothrow_t(size, tag);
}

struct Factory {
  std::atomic<size_t> session_creates{0};
  std::atomic<size_t> session_destroys{0};
  std::atomic<size_t> executions{0};
  std::atomic<size_t> continuations{0};
  std::atomic<size_t> thread_begins{0};
  std::atomic<size_t> thread_ends{0};
  std::atomic<size_t> coverage_gaps{0};
  std::atomic<uint32_t> last_begin_tid{0};
  std::atomic<uint32_t> last_creator_tid{0};
  std::atomic<uintptr_t> last_start{0};
  std::atomic<uint32_t> last_gap_tid{0};
  std::atomic<uintptr_t> last_gap_pc{0};
  std::atomic<uintptr_t> last_execution_entry{0};
  std::atomic<uintptr_t> last_control_start{0};
  std::atomic<size_t> last_execution_bytes{0};
  std::atomic<uintptr_t> last_argument{0};
  std::atomic<CoverageGapReason> last_gap_reason{
      CoverageGapReason::SessionFailure};
  std::atomic<bool> execute_original{true};
  std::atomic<bool> partial_execution{false};
  std::atomic<size_t> continuation_stops_remaining{0};
  std::atomic<bool> defer_thread_exit{false};
  std::atomic<bool> saw_active_vm{false};
  std::atomic<bool> forbid_child_mutation{false};
  std::atomic<size_t> lifecycle_clock{0};
  std::atomic<size_t> begin_order{0};
  std::atomic<size_t> original_order{0};
  std::atomic<size_t> end_order{0};
  std::atomic<size_t> destroy_order{0};
};

void *create_artifact(void *opaque, const char *, const FlightOptions &,
                      const FlightArtifactIdentityView &) noexcept {
  return opaque;
}

void destroy_artifact(void *, void *) noexcept {}

TraceRunResult execute_start(void *opaque, QbdiThreadSession *session, uintptr_t entry,
                             uintptr_t control_start, size_t execution_bytes,
                             const uint64_t args[8],
                             uint64_t) {
  auto *factory = static_cast<Factory *>(opaque);
  factory->executions.fetch_add(1, std::memory_order_relaxed);
  factory->last_execution_entry.store(entry, std::memory_order_relaxed);
  factory->last_control_start.store(control_start, std::memory_order_relaxed);
  factory->last_execution_bytes.store(execution_bytes,
                                      std::memory_order_relaxed);
  factory->last_argument.store(static_cast<uintptr_t>(args[0]),
                               std::memory_order_relaxed);
  factory->saw_active_vm.store(session != nullptr && session->vm_active(),
                              std::memory_order_relaxed);
  if (factory->defer_thread_exit.load(std::memory_order_relaxed))
    return {true, false, true, args[0]};
  if (factory->partial_execution.load(std::memory_order_relaxed))
    return {true, false, 0xbad};
  if (!factory->execute_original.load(std::memory_order_relaxed))
    return {};
  factory->original_order.store(
      factory->lifecycle_clock.fetch_add(1, std::memory_order_relaxed) + 1U,
      std::memory_order_relaxed);
  const auto start = reinterpret_cast<StartRoutine>(entry);
  void *const result =
      start(reinterpret_cast<void *>(static_cast<uintptr_t>(args[0])));
  return {true, static_cast<uint64_t>(reinterpret_cast<uintptr_t>(result))};
}

TraceRunResult continue_start(void *opaque, QbdiThreadSession *session) noexcept {
  auto *factory = static_cast<Factory *>(opaque);
  factory->continuations.fetch_add(1, std::memory_order_relaxed);
  size_t remaining =
      factory->continuation_stops_remaining.load(std::memory_order_relaxed);
  while (remaining != 0 &&
         !factory->continuation_stops_remaining.compare_exchange_weak(
             remaining, remaining - 1U, std::memory_order_relaxed,
             std::memory_order_relaxed)) {
  }
  if (remaining != 0)
    return {true, false, 0};
  const auto start = reinterpret_cast<StartRoutine>(session->thread_entry());
  void *const result = start(reinterpret_cast<void *>(
      factory->last_argument.load(std::memory_order_relaxed)));
  return {true, true,
          static_cast<uint64_t>(reinterpret_cast<uintptr_t>(result))};
}

bool report_lifecycle(void *opaque, uint32_t tid, bool begin,
                      uint32_t creator_tid, uintptr_t start) noexcept {
  auto *factory = static_cast<Factory *>(opaque);
  if (factory->forbid_child_mutation.load(std::memory_order_relaxed))
    _exit(82);
  if (begin) {
    factory->begin_order.store(
        factory->lifecycle_clock.fetch_add(1, std::memory_order_relaxed) + 1U,
        std::memory_order_relaxed);
    factory->thread_begins.fetch_add(1, std::memory_order_relaxed);
    factory->last_begin_tid.store(tid, std::memory_order_relaxed);
    factory->last_creator_tid.store(creator_tid, std::memory_order_relaxed);
    factory->last_start.store(start, std::memory_order_relaxed);
  } else {
    factory->end_order.store(
        factory->lifecycle_clock.fetch_add(1, std::memory_order_relaxed) + 1U,
        std::memory_order_relaxed);
    factory->thread_ends.fetch_add(1, std::memory_order_relaxed);
  }
  return true;
}

QbdiThreadSession *create_session(void *opaque, void *, const TraceConfig &,
                                  const ModuleRange &, const SceneConfig &,
                                  uint32_t tid,
                                  uint32_t module_generation) noexcept {
  auto *factory = static_cast<Factory *>(opaque);
  if (factory->forbid_child_mutation.load(std::memory_order_relaxed))
    _exit(83);
  factory->session_creates.fetch_add(1, std::memory_order_relaxed);
  return QbdiThreadSession::create_for_test(tid, module_generation,
                                            execute_start, factory, nullptr,
                                            nullptr, report_lifecycle, factory,
                                            continue_start);
}

void destroy_session(void *opaque, QbdiThreadSession *session) noexcept {
  auto *factory = static_cast<Factory *>(opaque);
  if (factory->forbid_child_mutation.load(std::memory_order_relaxed))
    _exit(84);
  CHECK(!session->vm_active());
  factory->session_destroys.fetch_add(1, std::memory_order_relaxed);
  factory->destroy_order.store(
      factory->lifecycle_clock.fetch_add(1, std::memory_order_relaxed) + 1U,
      std::memory_order_relaxed);
  delete session;
}

void mark_gap(void *opaque, void *, uint32_t tid, uintptr_t pc,
              CoverageGapReason reason) noexcept {
  auto *factory = static_cast<Factory *>(opaque);
  if (factory->forbid_child_mutation.load(std::memory_order_relaxed))
    _exit(85);
  factory->coverage_gaps.fetch_add(1, std::memory_order_relaxed);
  factory->last_gap_tid.store(tid, std::memory_order_relaxed);
  factory->last_gap_pc.store(pc, std::memory_order_relaxed);
  factory->last_gap_reason.store(reason, std::memory_order_relaxed);
}

CaptureCoordinatorFactories factories(Factory *factory) noexcept {
  return {factory,        create_artifact, destroy_artifact,
          create_session, destroy_session, mark_gap};
}

TraceConfig flight_config(uint32_t max_threads = 16) {
  TraceConfig config;
  config.package_name = "com.example.thread-gateway";
  config.target_so = "libthread_gateway_target.so";
  config.flight.enabled = true;
  config.flight.max_threads = max_threads;
  config.flight.capacity_bytes = 64ULL * 1024ULL * 1024ULL;
  config.flight.chunk_bytes = 64U * 1024U;
  config.flight.protected_chunks = 1;
  config.flight.entry_scene = "init";
  config.scenes.push_back({0, "init", 0, 0});
  return config;
}

ModuleRange module_for(StartRoutine start, size_t bytes = 1) {
  const uintptr_t address = reinterpret_cast<uintptr_t>(start);
  ModuleRange module;
  module.start = address;
  module.end = address + bytes;
  module.path = "/data/app/libthread_gateway_target.so";
  module.permissions = "r-xp";
  module.readable_executable_ranges[0] = {module.start, module.end};
  module.readable_executable_range_count = 1;
  return module;
}

std::atomic<size_t> g_hook_calls{0};
std::atomic<bool> g_hook_fails{false};
std::atomic<bool> g_hook_failure_leaves_residual{false};
std::atomic<uintptr_t> g_hook_target{0};
std::atomic<void *> g_hook_replacement{nullptr};
std::atomic<const pthread_attr_t *> g_last_attr{nullptr};
std::atomic<StartRoutine> g_last_created_start{nullptr};
std::atomic<void *> g_last_created_argument{nullptr};
std::atomic<size_t> g_retained_create_calls{0};
std::atomic<size_t> g_wrapped_create_calls{0};
std::atomic<int> g_create_error{0};
std::atomic<bool> g_synchronous_create{false};
std::atomic<void *> g_synchronous_result{nullptr};
std::atomic<bool> g_probe_global_proxy_window{false};
std::atomic<int> g_global_proxy_status{-1};
std::atomic<void *> g_global_proxy_result{nullptr};
std::atomic<StartRoutine> g_global_proxy_start{nullptr};
std::atomic<void *> g_global_proxy_argument{nullptr};
CaptureCoordinator *g_lifecycle_reentry_coordinator = nullptr;
SceneConfig g_lifecycle_reentry_scene;
std::atomic<bool> g_lifecycle_reentry_succeeded{false};

bool fake_deferred_hook(uintptr_t target, void *replacement,
                        HookHandle *handle);

int recording_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                             StartRoutine start, void *argument) {
  g_retained_create_calls.fetch_add(1, std::memory_order_relaxed);
  g_last_attr.store(attr, std::memory_order_relaxed);
  g_last_created_start.store(start, std::memory_order_relaxed);
  g_last_created_argument.store(argument, std::memory_order_relaxed);
  const int error = g_create_error.load(std::memory_order_relaxed);
  if (error != 0)
    return error;
  if (g_synchronous_create.load(std::memory_order_relaxed)) {
    if (thread != nullptr)
      *thread = ::pthread_self();
    g_synchronous_result.store(start(argument), std::memory_order_relaxed);
    return 0;
  }
  return ::pthread_create(thread, attr, start, argument);
}

bool fake_hook_symbol_address(uintptr_t target, void *replacement,
                              HookHandle *handle) {
  g_hook_calls.fetch_add(1, std::memory_order_relaxed);
  g_hook_target.store(target, std::memory_order_relaxed);
  g_hook_replacement.store(replacement, std::memory_order_relaxed);
  if (g_hook_fails.load(std::memory_order_relaxed)) {
    if (g_hook_failure_leaves_residual.load(std::memory_order_relaxed)) {
      CHECK(handle->published_original != nullptr);
      __atomic_store_n(handle->published_original,
                       reinterpret_cast<void *>(recording_pthread_create),
                       __ATOMIC_RELEASE);
      handle->retained_original =
          reinterpret_cast<void *>(recording_pthread_create);
      handle->retained_original_bytes = 64;
      handle->residual_hook = true;
    }
    return false;
  }
  CHECK(handle->published_original != nullptr);
  __atomic_store_n(handle->published_original,
                   reinterpret_cast<void *>(recording_pthread_create),
                   __ATOMIC_RELEASE);
  if (g_probe_global_proxy_window.exchange(false,
                                           std::memory_order_relaxed)) {
    pthread_t thread{};
    g_global_proxy_status.store(
        trace_pthread_create_proxy(
            &thread, nullptr,
            g_global_proxy_start.load(std::memory_order_relaxed),
            g_global_proxy_argument.load(std::memory_order_relaxed)),
        std::memory_order_relaxed);
    g_global_proxy_result.store(
        g_synchronous_result.load(std::memory_order_relaxed),
        std::memory_order_relaxed);
  }
  handle->stub = reinterpret_cast<void *>(0x44);
  handle->target = target;
  handle->original = reinterpret_cast<void *>(recording_pthread_create);
  handle->retained_original = handle->original;
  handle->retained_original_bytes = 64;
  return true;
}

void reset_runtime() {
  g_hook_calls.store(0, std::memory_order_relaxed);
  g_hook_fails.store(false, std::memory_order_relaxed);
  g_hook_failure_leaves_residual.store(false, std::memory_order_relaxed);
  g_hook_target.store(0, std::memory_order_relaxed);
  g_hook_replacement.store(nullptr, std::memory_order_relaxed);
  g_last_attr.store(nullptr, std::memory_order_relaxed);
  g_last_created_start.store(nullptr, std::memory_order_relaxed);
  g_last_created_argument.store(nullptr, std::memory_order_relaxed);
  g_retained_create_calls.store(0, std::memory_order_relaxed);
  g_wrapped_create_calls.store(0, std::memory_order_relaxed);
  g_create_error.store(0, std::memory_order_relaxed);
  g_synchronous_create.store(false, std::memory_order_relaxed);
  g_synchronous_result.store(nullptr, std::memory_order_relaxed);
  g_probe_global_proxy_window.store(false, std::memory_order_relaxed);
  g_global_proxy_status.store(-1, std::memory_order_relaxed);
  g_global_proxy_result.store(nullptr, std::memory_order_relaxed);
  g_global_proxy_start.store(nullptr, std::memory_order_relaxed);
  g_global_proxy_argument.store(nullptr, std::memory_order_relaxed);
  g_lifecycle_reentry_coordinator = nullptr;
  g_lifecycle_reentry_scene = {};
  g_lifecycle_reentry_succeeded.store(false, std::memory_order_relaxed);
  g_fail_next_nothrow_allocation.store(false, std::memory_order_relaxed);
  g_forbid_nothrow_allocation.store(false, std::memory_order_relaxed);
}

struct Fixture {
  Factory factory;
  std::shared_ptr<CaptureCoordinator> coordinator_owner;
  CaptureCoordinator &coordinator;
  ThreadCreateGateway gateway;
  TraceConfig config;

  explicit Fixture(const ModuleRange &module, uint32_t max_threads = 16,
                   size_t retirement_budget = 64)
      : coordinator_owner(
            std::make_shared<CaptureCoordinator>(factories(&factory))),
        coordinator(*coordinator_owner),
        gateway(fake_hook_symbol_address, retirement_budget),
        config(flight_config(max_threads)) {
    CHECK(coordinator.start(config, module, 37));
    CHECK(gateway.install(coordinator_owner));
  }
};

std::atomic<uint32_t> g_worker_tid{0};

__attribute__((noinline)) void *identity_start(void *argument) {
  g_worker_tid.store(static_cast<uint32_t>(::syscall(SYS_gettid)),
                     std::memory_order_relaxed);
  return argument;
}

__attribute__((noinline)) void *lifecycle_reentry_start(void *argument) {
  if (g_lifecycle_reentry_coordinator == nullptr)
    return nullptr;
  const uint32_t tid = static_cast<uint32_t>(::syscall(SYS_gettid));
  QbdiThreadSession *session =
      g_lifecycle_reentry_coordinator->enter(tid, g_lifecycle_reentry_scene);
  if (session == nullptr)
    return nullptr;
  const uint64_t args[8]{
      static_cast<uint64_t>(reinterpret_cast<uintptr_t>(argument))};
  const TraceRunResult traced = session->call(
      reinterpret_cast<uintptr_t>(identity_start), args, 0);
  g_lifecycle_reentry_coordinator->leave(session);
  if (!traced.target_returned)
    return nullptr;
  g_lifecycle_reentry_succeeded.store(true, std::memory_order_relaxed);
  return reinterpret_cast<void *>(static_cast<uintptr_t>(traced.value));
}

void process_global_proxy_has_a_bypass_before_the_hook_is_live() {
  reset_runtime();
  static Factory factory;
  static auto coordinator =
      std::make_shared<CaptureCoordinator>(factories(&factory));
  TraceConfig config = flight_config();
  CHECK(coordinator->start(config, module_for(identity_start), 31));
  int token = 13;
  g_synchronous_create.store(true, std::memory_order_relaxed);
  g_global_proxy_start.store(identity_start, std::memory_order_relaxed);
  g_global_proxy_argument.store(&token, std::memory_order_relaxed);
  g_probe_global_proxy_window.store(true, std::memory_order_relaxed);
  CHECK(process_thread_create_gateway().install(coordinator));
  CHECK(g_global_proxy_status.load(std::memory_order_relaxed) == 0);
  CHECK(g_global_proxy_result.load(std::memory_order_relaxed) == &token);
  CHECK(g_last_created_start.load(std::memory_order_relaxed) == identity_start);
  CHECK(factory.session_creates.load(std::memory_order_relaxed) == 0);
}

void persistent_install_captures_every_new_flight_thread() {
  reset_runtime();
  Fixture fixture(module_for(identity_start));

  CHECK(g_hook_calls.load(std::memory_order_relaxed) == 1);
  CHECK(g_hook_target.load(std::memory_order_relaxed) ==
        reinterpret_cast<uintptr_t>(pthread_create));
  CHECK(g_hook_replacement.load(std::memory_order_relaxed) != nullptr);
  CHECK(fixture.gateway.install(fixture.coordinator_owner));
  CHECK(g_hook_calls.load(std::memory_order_relaxed) == 1);
  CHECK(fixture.gateway.should_capture(identity_start));
  CHECK(fixture.gateway.should_capture(unrelated_start));

  QbdiThreadSession *creator = fixture.coordinator.enter(
      static_cast<uint32_t>(::getpid()), fixture.config.scenes[0]);
  CHECK(creator != nullptr);
  CHECK(fixture.gateway.should_capture(unrelated_start));
  fixture.coordinator.leave(creator);
  CHECK(fixture.gateway.should_capture(unrelated_start));
}

void preserves_attributes_argument_return_for_all_flight_threads() {
  reset_runtime();
  Fixture fixture(module_for(identity_start));
  pthread_attr_t attr;
  CHECK(::pthread_attr_init(&attr) == 0);
  CHECK(::pthread_attr_setguardsize(&attr, 2U * 4096U) == 0);
  int token = 17;
  pthread_t thread{};
  g_worker_tid.store(0, std::memory_order_relaxed);
  const uint32_t creator_tid = static_cast<uint32_t>(::syscall(SYS_gettid));
  CHECK(fixture.gateway.create(&thread, &attr, identity_start, &token) == 0);
  void *result = nullptr;
  CHECK(::pthread_join(thread, &result) == 0);
  CHECK(result == &token);
  CHECK(g_last_attr.load(std::memory_order_relaxed) == &attr);
  CHECK(g_last_created_start.load(std::memory_order_relaxed) != identity_start);
  CHECK(fixture.factory.executions.load(std::memory_order_relaxed) == 1);
  CHECK(fixture.factory.thread_begins.load(std::memory_order_relaxed) == 1);
  CHECK(fixture.factory.thread_ends.load(std::memory_order_relaxed) == 1);
  CHECK(fixture.factory.last_start.load(std::memory_order_relaxed) ==
        reinterpret_cast<uintptr_t>(identity_start));
  CHECK(fixture.factory.last_begin_tid.load(std::memory_order_relaxed) ==
        g_worker_tid.load(std::memory_order_relaxed));
  CHECK(fixture.factory.last_creator_tid.load(std::memory_order_relaxed) ==
        creator_tid);
  CHECK(fixture.factory.session_creates.load(std::memory_order_relaxed) == 1);
  CHECK(fixture.factory.session_destroys.load(std::memory_order_relaxed) == 1);
  CHECK(fixture.factory.begin_order.load(std::memory_order_relaxed) <
        fixture.factory.original_order.load(std::memory_order_relaxed));
  CHECK(fixture.factory.original_order.load(std::memory_order_relaxed) <
        fixture.factory.end_order.load(std::memory_order_relaxed));
  CHECK(fixture.factory.end_order.load(std::memory_order_relaxed) <
        fixture.factory.destroy_order.load(std::memory_order_relaxed));

  CHECK(fixture.gateway.create(&thread, &attr, unrelated_start, &token) == 0);
  CHECK(::pthread_join(thread, &result) == 0);
  CHECK(result ==
        reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(&token) + 1U));
  CHECK(g_last_attr.load(std::memory_order_relaxed) == &attr);
  CHECK(g_last_created_start.load(std::memory_order_relaxed) != unrelated_start);
  CHECK(fixture.factory.last_start.load(std::memory_order_relaxed) ==
        reinterpret_cast<uintptr_t>(unrelated_start));
  CHECK(fixture.factory.executions.load(std::memory_order_relaxed) == 1);
  CHECK(fixture.factory.session_creates.load(std::memory_order_relaxed) == 2);
  CHECK(fixture.factory.session_destroys.load(std::memory_order_relaxed) == 2);
  CHECK(fixture.factory.thread_begins.load(std::memory_order_relaxed) == 2);
  CHECK(fixture.factory.thread_ends.load(std::memory_order_relaxed) == 2);
  CHECK(::pthread_attr_destroy(&attr) == 0);
}

void unrelated_native_lifecycle_releases_session_for_scene_reentry() {
  reset_runtime();
  Fixture fixture(module_for(identity_start));
  g_lifecycle_reentry_coordinator = &fixture.coordinator;
  g_lifecycle_reentry_scene = fixture.config.scenes[0];
  int token = 19;
  pthread_t thread{};

  CHECK(fixture.gateway.create(&thread, nullptr, lifecycle_reentry_start,
                               &token) == 0);
  void *result = nullptr;
  CHECK(::pthread_join(thread, &result) == 0);
  CHECK(result == &token);
  CHECK(g_lifecycle_reentry_succeeded.load(std::memory_order_relaxed));
  CHECK(fixture.factory.executions.load(std::memory_order_relaxed) == 1);
  CHECK(fixture.factory.thread_begins.load(std::memory_order_relaxed) == 1);
  CHECK(fixture.factory.thread_ends.load(std::memory_order_relaxed) == 1);
  CHECK(fixture.factory.session_creates.load(std::memory_order_relaxed) == 1);
  CHECK(fixture.factory.session_destroys.load(std::memory_order_relaxed) == 1);
  CHECK(fixture.factory.coverage_gaps.load(std::memory_order_relaxed) == 0);
  g_lifecycle_reentry_coordinator = nullptr;
}

__attribute__((noinline)) void *retained_identity_start(void *argument) {
  return argument;
}

std::atomic<size_t> g_patched_start_calls{0};

__attribute__((noinline)) void *patched_start(void *) {
  g_patched_start_calls.fetch_add(1, std::memory_order_relaxed);
  return reinterpret_cast<void *>(0xdead);
}

bool resolve_retained_start(void *, uintptr_t logical,
                            ThreadExecutionControl *control) noexcept {
  if (logical != reinterpret_cast<uintptr_t>(patched_start) ||
      control == nullptr) {
    return false;
  }
  const uintptr_t retained =
      reinterpret_cast<uintptr_t>(retained_identity_start);
  *control = {retained, retained, 64, nullptr};
  return true;
}

std::atomic<uintptr_t> g_retained_control_entry{
    reinterpret_cast<uintptr_t>(retained_identity_start)};

bool resolve_mutable_retained_start(void *, uintptr_t logical,
                                    ThreadExecutionControl *control) noexcept {
  if (logical != reinterpret_cast<uintptr_t>(patched_start) ||
      control == nullptr) {
    return false;
  }
  const uintptr_t retained =
      g_retained_control_entry.load(std::memory_order_relaxed);
  *control = {retained, retained, 64, nullptr};
  return true;
}

void queued_hooked_start_snapshots_creator_generation_control() {
  reset_runtime();
  Factory factory;
  auto coordinator =
      std::make_shared<CaptureCoordinator>(factories(&factory));
  CHECK(coordinator->start(flight_config(), module_for(patched_start), 39));
  coordinator->set_thread_start_resolver(resolve_mutable_retained_start,
                                         nullptr);
  ThreadCreateGateway gateway(fake_deferred_hook);
  CHECK(gateway.install(coordinator));
  g_retained_control_entry.store(
      reinterpret_cast<uintptr_t>(retained_identity_start),
      std::memory_order_relaxed);
  int token = 27;
  pthread_t thread{};
  CHECK(gateway.create(&thread, nullptr, patched_start, &token) == 0);
  const StartRoutine queued =
      g_last_created_start.load(std::memory_order_relaxed);
  void *const queued_argument =
      g_last_created_argument.load(std::memory_order_relaxed);
  CHECK(queued != nullptr && queued != patched_start);
  g_retained_control_entry.store(reinterpret_cast<uintptr_t>(patched_start),
                                 std::memory_order_relaxed);
  CHECK(queued(queued_argument) == &token);
  CHECK(factory.last_execution_entry.load(std::memory_order_relaxed) ==
        reinterpret_cast<uintptr_t>(retained_identity_start));
}

void hooked_scene_start_uses_the_retained_control_only_gateway() {
  reset_runtime();
  Fixture fixture(module_for(patched_start));
  fixture.coordinator.set_thread_start_resolver(resolve_retained_start,
                                                nullptr);
  g_patched_start_calls.store(0, std::memory_order_relaxed);
  int token = 23;
  pthread_t thread{};
  CHECK(fixture.gateway.create(&thread, nullptr, patched_start, &token) == 0);
  void *result = nullptr;
  CHECK(::pthread_join(thread, &result) == 0);
  CHECK(result == &token);
  CHECK(g_patched_start_calls.load(std::memory_order_relaxed) == 0);
  CHECK(fixture.factory.last_execution_entry.load(std::memory_order_relaxed) ==
        reinterpret_cast<uintptr_t>(retained_identity_start));
  CHECK(fixture.factory.last_control_start.load(std::memory_order_relaxed) ==
        reinterpret_cast<uintptr_t>(retained_identity_start));
  CHECK(fixture.factory.last_execution_bytes.load(std::memory_order_relaxed) ==
        64);
  CHECK(fixture.factory.last_start.load(std::memory_order_relaxed) ==
        reinterpret_cast<uintptr_t>(patched_start));
}

ThreadCreateGateway *g_nested_gateway = nullptr;

__attribute__((noinline)) void *nested_parent_start(void *argument) {
  pthread_t child{};
  if (g_nested_gateway == nullptr ||
      g_nested_gateway->create(&child, nullptr, nested_external_start,
                               argument) != 0) {
    return nullptr;
  }
  void *result = nullptr;
  if (::pthread_join(child, &result) != 0)
    return nullptr;
  return result;
}

void active_creator_tls_propagates_nested_ownership() {
  reset_runtime();
  Fixture fixture(module_for(nested_parent_start));
  g_nested_gateway = &fixture.gateway;
  int token = 29;
  pthread_t parent{};
  CHECK(fixture.gateway.create(&parent, nullptr, nested_parent_start, &token) ==
        0);
  void *result = nullptr;
  CHECK(::pthread_join(parent, &result) == 0);
  CHECK(result == &token);
  CHECK(fixture.factory.executions.load(std::memory_order_relaxed) == 2);
  CHECK(fixture.factory.session_creates.load(std::memory_order_relaxed) == 2);
  CHECK(fixture.factory.session_destroys.load(std::memory_order_relaxed) == 2);
  CHECK(fixture.factory.thread_begins.load(std::memory_order_relaxed) == 2);
  CHECK(fixture.factory.thread_ends.load(std::memory_order_relaxed) == 2);
  CHECK(fixture.factory.saw_active_vm.load(std::memory_order_relaxed));
  CHECK(g_retained_create_calls.load(std::memory_order_relaxed) == 2);
  const uintptr_t external =
      reinterpret_cast<uintptr_t>(nested_external_start);
  const uintptr_t control_start =
      fixture.factory.last_control_start.load(std::memory_order_relaxed);
  const size_t control_bytes =
      fixture.factory.last_execution_bytes.load(std::memory_order_relaxed);
  CHECK(control_start <= external);
  CHECK(control_start == external);
  CHECK(control_bytes > 0);
  CHECK(control_bytes > sizeof(uint32_t));
  g_nested_gateway = nullptr;
}

__attribute__((noinline)) void *exiting_start(void *argument) {
  ::pthread_exit(argument);
}

std::atomic<bool> g_cancel_entered{false};

__attribute__((noinline)) void *cancelable_start(void *) {
  g_cancel_entered.store(true, std::memory_order_release);
  for (;;) {
    ::pthread_testcancel();
    ::sched_yield();
  }
}

void cleanup_publishes_thread_end_for_pthread_exit_and_cancel() {
  reset_runtime();
  {
    Fixture fixture(module_for(exiting_start));
    fixture.factory.defer_thread_exit.store(true, std::memory_order_relaxed);
    int token = 41;
    pthread_t thread{};
    CHECK(fixture.gateway.create(&thread, nullptr, exiting_start, &token) == 0);
    void *result = nullptr;
    CHECK(::pthread_join(thread, &result) == 0);
    CHECK(result == &token);
    CHECK(fixture.factory.thread_begins.load(std::memory_order_relaxed) == 1);
    CHECK(fixture.factory.thread_ends.load(std::memory_order_relaxed) == 1);
    CHECK(fixture.factory.executions.load(std::memory_order_relaxed) == 1);
    CHECK(fixture.factory.session_destroys.load(std::memory_order_relaxed) ==
          1);
    CHECK(fixture.factory.coverage_gaps.load(std::memory_order_relaxed) == 0);
  }
  reset_runtime();
  {
    Fixture fixture(module_for(cancelable_start));
    g_cancel_entered.store(false, std::memory_order_relaxed);
    pthread_t thread{};
    CHECK(fixture.gateway.create(&thread, nullptr, cancelable_start, nullptr) ==
          0);
    while (!g_cancel_entered.load(std::memory_order_acquire))
      ::sched_yield();
    CHECK(::pthread_cancel(thread) == 0);
    void *result = nullptr;
    CHECK(::pthread_join(thread, &result) == 0);
    CHECK(result == PTHREAD_CANCELED);
    CHECK(fixture.factory.thread_begins.load(std::memory_order_relaxed) == 1);
    CHECK(fixture.factory.thread_ends.load(std::memory_order_relaxed) == 1);
    CHECK(fixture.factory.executions.load(std::memory_order_relaxed) == 1);
    CHECK(fixture.factory.session_destroys.load(std::memory_order_relaxed) ==
          0);
  }
}

void abnormal_session_retirement_is_bounded_and_exhaustion_fails_open() {
  reset_runtime();
  Fixture fixture(module_for(exiting_start), 2, 1);
  int first_token = 43;
  pthread_t first{};
  CHECK(fixture.gateway.create(&first, nullptr, exiting_start, &first_token) ==
        0);
  void *first_result = nullptr;
  CHECK(::pthread_join(first, &first_result) == 0);
  CHECK(first_result == &first_token);
  CHECK(fixture.factory.session_creates.load(std::memory_order_relaxed) == 1);
  CHECK(fixture.factory.session_destroys.load(std::memory_order_relaxed) == 0);
  CHECK(fixture.factory.last_gap_reason.load(std::memory_order_relaxed) ==
        CoverageGapReason::ThreadAbnormalExit);

  int second_token = 47;
  pthread_t second{};
  CHECK(fixture.gateway.create(&second, nullptr, exiting_start, &second_token) ==
        0);
  void *second_result = nullptr;
  CHECK(::pthread_join(second, &second_result) == 0);
  CHECK(second_result == &second_token);
  CHECK(fixture.factory.session_creates.load(std::memory_order_relaxed) == 1);
  CHECK(fixture.factory.session_destroys.load(std::memory_order_relaxed) == 0);
  CHECK(fixture.factory.thread_begins.load(std::memory_order_relaxed) == 1);
  CHECK(fixture.factory.coverage_gaps.load(std::memory_order_relaxed) == 2);
  CHECK(fixture.factory.last_gap_reason.load(std::memory_order_relaxed) ==
        CoverageGapReason::RetirementCapacity);
  CHECK(fixture.coordinator.dropped_gap_count() == 1);
}

void allocation_and_create_failure_fail_open_and_publish_sticky_gaps() {
  reset_runtime();
  Fixture fixture(module_for(identity_start));
  int token = 53;
  pthread_t thread{};

  g_fail_next_nothrow_allocation.store(true, std::memory_order_relaxed);
  CHECK(fixture.gateway.create(&thread, nullptr, identity_start, &token) == 0);
  void *result = nullptr;
  CHECK(::pthread_join(thread, &result) == 0);
  CHECK(result == &token);
  CHECK(g_last_created_start.load(std::memory_order_relaxed) == identity_start);
  CHECK(fixture.factory.session_creates.load(std::memory_order_relaxed) == 0);
  CHECK(fixture.factory.coverage_gaps.load(std::memory_order_relaxed) == 1);
  CHECK(fixture.factory.last_gap_reason.load(std::memory_order_relaxed) ==
        CoverageGapReason::ThreadStartAllocation);
  CHECK(fixture.coordinator.incomplete());

  g_create_error.store(EAGAIN, std::memory_order_relaxed);
  CHECK(fixture.gateway.create(&thread, nullptr, identity_start, &token) ==
        EAGAIN);
  CHECK(fixture.factory.coverage_gaps.load(std::memory_order_relaxed) == 2);
  CHECK(fixture.factory.last_gap_reason.load(std::memory_order_relaxed) ==
        CoverageGapReason::ThreadCreate);
  CHECK(fixture.coordinator.dropped_gap_count() == 1);
}

std::atomic<size_t> g_partial_start_calls{0};

__attribute__((noinline)) void *partial_start(void *argument) {
  g_partial_start_calls.fetch_add(1, std::memory_order_relaxed);
  return argument;
}

__attribute__((noinline)) void *unresolved_external_start(void *argument) {
  return argument;
}

void unrelated_external_start_keeps_native_lifecycle_without_a_gap() {
  reset_runtime();
  Fixture fixture(module_for(identity_start));
  int token = 57;
  pthread_t thread{};
  CHECK(fixture.gateway.create(&thread, nullptr, unresolved_external_start,
                               &token) == 0);
  void *result = nullptr;
  CHECK(::pthread_join(thread, &result) == 0);
  CHECK(result == &token);
  CHECK(fixture.factory.executions.load(std::memory_order_relaxed) == 0);
  CHECK(fixture.factory.thread_begins.load(std::memory_order_relaxed) == 1);
  CHECK(fixture.factory.thread_ends.load(std::memory_order_relaxed) == 1);
  CHECK(fixture.factory.session_destroys.load(std::memory_order_relaxed) == 1);
  CHECK(fixture.factory.coverage_gaps.load(std::memory_order_relaxed) == 0);
}

void partial_vm_execution_continues_control_only_without_restarting() {
  reset_runtime();
  Fixture fixture(module_for(partial_start));
  fixture.factory.partial_execution.store(true, std::memory_order_relaxed);
  fixture.factory.continuation_stops_remaining.store(
      2, std::memory_order_relaxed);
  g_partial_start_calls.store(0, std::memory_order_relaxed);
  int token = 59;
  pthread_t thread{};
  CHECK(fixture.gateway.create(&thread, nullptr, partial_start, &token) == 0);
  void *result = reinterpret_cast<void *>(0x1);
  CHECK(::pthread_join(thread, &result) == 0);
  CHECK(result == &token);
  CHECK(g_partial_start_calls.load(std::memory_order_relaxed) == 1);
  CHECK(fixture.factory.executions.load(std::memory_order_relaxed) == 1);
  CHECK(fixture.factory.continuations.load(std::memory_order_relaxed) == 3);
  CHECK(fixture.coordinator.incomplete());
  CHECK(fixture.factory.coverage_gaps.load(std::memory_order_relaxed) == 1);
}

void active_old_generation_owns_children_created_after_reconfiguration() {
  reset_runtime();
  Factory old_factory;
  Factory new_factory;
  auto old_owner =
      std::make_shared<CaptureCoordinator>(factories(&old_factory));
  auto new_owner =
      std::make_shared<CaptureCoordinator>(factories(&new_factory));
  CHECK(old_owner->start(flight_config(), module_for(identity_start), 81));
  CHECK(new_owner->start(flight_config(), module_for(unrelated_start), 82));
  ThreadCreateGateway gateway(fake_deferred_hook);
  CHECK(gateway.install(old_owner));
  QbdiThreadSession *old_session = old_owner->enter(
      static_cast<uint32_t>(::syscall(SYS_gettid)), flight_config().scenes[0]);
  CHECK(old_session != nullptr);
  CHECK(gateway.install(new_owner));

  int token = 83;
  pthread_t thread{};
  CHECK(gateway.create(&thread, nullptr, identity_start, &token) == 0);
  const StartRoutine queued =
      g_last_created_start.load(std::memory_order_relaxed);
  void *const queued_argument =
      g_last_created_argument.load(std::memory_order_relaxed);
  CHECK(queued != nullptr && queued != identity_start);
  old_owner->leave(old_session);
  CHECK(queued(queued_argument) == &token);
  CHECK(old_factory.session_creates.load(std::memory_order_relaxed) == 1);
  CHECK(old_factory.thread_begins.load(std::memory_order_relaxed) == 1);
  CHECK(new_factory.session_creates.load(std::memory_order_relaxed) == 0);
  CHECK(!old_owner->incomplete());
  CHECK(!new_owner->incomplete());
}

void hook_failure_marks_the_run_incomplete_without_a_residual_gateway() {
  reset_runtime();
  Factory factory;
  auto coordinator =
      std::make_shared<CaptureCoordinator>(factories(&factory));
  CHECK(coordinator->start(flight_config(), module_for(identity_start), 51));
  ThreadCreateGateway gateway(fake_hook_symbol_address);
  g_hook_fails.store(true, std::memory_order_relaxed);

  CHECK(!gateway.install(coordinator));
  CHECK(coordinator->incomplete());
  CHECK(factory.coverage_gaps.load(std::memory_order_relaxed) == 1);
  CHECK(factory.last_gap_reason.load(std::memory_order_relaxed) ==
        CoverageGapReason::HookSetup);
}

void residual_hook_failure_permanently_fails_open_through_retained_original() {
  reset_runtime();
  Factory factory;
  auto coordinator =
      std::make_shared<CaptureCoordinator>(factories(&factory));
  CHECK(coordinator->start(flight_config(), module_for(identity_start), 52));
  ThreadCreateGateway gateway(fake_hook_symbol_address);
  g_hook_fails.store(true, std::memory_order_relaxed);
  g_hook_failure_leaves_residual.store(true, std::memory_order_relaxed);

  CHECK(!gateway.install(coordinator));
  CHECK(coordinator->incomplete());
  g_synchronous_create.store(true, std::memory_order_relaxed);
  int token = 61;
  pthread_t thread{};
  CHECK(gateway.create(&thread, nullptr, identity_start, &token) == 0);
  CHECK(g_synchronous_result.load(std::memory_order_relaxed) == &token);
  CHECK(g_last_created_start.load(std::memory_order_relaxed) == identity_start);
  CHECK(factory.session_creates.load(std::memory_order_relaxed) == 0);
  CHECK(factory.thread_begins.load(std::memory_order_relaxed) == 0);
  CHECK(!gateway.install(coordinator));
  CHECK(g_hook_calls.load(std::memory_order_relaxed) == 1);
}

void child_detach_uses_only_the_inherited_original_path() {
  reset_runtime();
  Fixture fixture(module_for(identity_start));
  const pid_t child = ::fork();
  CHECK(child >= 0);
  if (child == 0) {
    fixture.factory.forbid_child_mutation.store(true,
                                                std::memory_order_relaxed);
    g_forbid_nothrow_allocation.store(true, std::memory_order_relaxed);
    g_synchronous_create.store(true, std::memory_order_relaxed);
    fixture.gateway.detach_after_fork_child();
    int token = 67;
    pthread_t thread{};
    if (fixture.gateway.create(&thread, nullptr, identity_start, &token) != 0) {
      _exit(86);
    }
    if (g_last_created_start.load(std::memory_order_relaxed) !=
            identity_start ||
        g_last_created_argument.load(std::memory_order_relaxed) != &token ||
        g_synchronous_result.load(std::memory_order_relaxed) != &token) {
      _exit(87);
    }
    _exit(0);
  }
  int status = -1;
  CHECK(::waitpid(child, &status, 0) == child);
  CHECK(WIFEXITED(status));
  CHECK(WEXITSTATUS(status) == 0);
}

int deferred_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                            StartRoutine start, void *argument) {
  g_retained_create_calls.fetch_add(1, std::memory_order_relaxed);
  g_last_attr.store(attr, std::memory_order_relaxed);
  g_last_created_start.store(start, std::memory_order_relaxed);
  g_last_created_argument.store(argument, std::memory_order_relaxed);
  if (thread != nullptr)
    *thread = ::pthread_self();
  return 0;
}

bool fake_deferred_hook(uintptr_t target, void *replacement,
                        HookHandle *handle) {
  g_hook_target.store(target, std::memory_order_relaxed);
  g_hook_replacement.store(replacement, std::memory_order_relaxed);
  CHECK(handle->published_original != nullptr);
  __atomic_store_n(handle->published_original,
                   reinterpret_cast<void *>(deferred_pthread_create),
                   __ATOMIC_RELEASE);
  handle->stub = reinterpret_cast<void *>(0x45);
  handle->original = reinterpret_cast<void *>(deferred_pthread_create);
  handle->retained_original = handle->original;
  handle->retained_original_bytes = 64;
  return true;
}

void queued_thread_start_keeps_its_coordinator_generation_alive() {
  reset_runtime();
  Factory factory;
  auto old_owner =
      std::make_shared<CaptureCoordinator>(factories(&factory));
  TraceConfig old_config = flight_config();
  CHECK(old_owner->start(old_config, module_for(identity_start), 61));
  std::weak_ptr<CaptureCoordinator> old_lifetime = old_owner;
  ThreadCreateGateway gateway(fake_deferred_hook);
  CHECK(gateway.install(old_owner));
  int token = 71;
  pthread_t thread{};
  CHECK(gateway.create(&thread, nullptr, identity_start, &token) == 0);
  const StartRoutine queued =
      g_last_created_start.load(std::memory_order_relaxed);
  void *const queued_argument =
      g_last_created_argument.load(std::memory_order_relaxed);
  CHECK(queued != nullptr && queued != identity_start);

  auto replacement =
      std::make_shared<CaptureCoordinator>(factories(&factory));
  TraceConfig replacement_config = flight_config();
  CHECK(replacement->start(replacement_config, module_for(identity_start), 62));
  CHECK(gateway.install(replacement));
  old_owner.reset();
  CHECK(!old_lifetime.expired());
  CHECK(queued(queued_argument) == &token);
  CHECK(old_lifetime.expired());
}

void deactivation_preserves_queued_owners_and_makes_new_calls_pass_through() {
  reset_runtime();
  Factory factory;
  auto coordinator =
      std::make_shared<CaptureCoordinator>(factories(&factory));
  const TraceConfig config = flight_config();
  CHECK(coordinator->start(config, module_for(identity_start), 64));
  ThreadCreateGateway gateway(fake_deferred_hook);
  CHECK(gateway.install(coordinator));

  int queued_token = 79;
  pthread_t thread{};
  CHECK(gateway.create(&thread, nullptr, identity_start, &queued_token) == 0);
  const StartRoutine queued =
      g_last_created_start.load(std::memory_order_relaxed);
  void *const queued_argument =
      g_last_created_argument.load(std::memory_order_relaxed);
  CHECK(queued != nullptr && queued != identity_start);

  gateway.deactivate();
  CHECK(!gateway.should_capture(identity_start));
  int passthrough_token = 80;
  CHECK(gateway.create(&thread, nullptr, identity_start,
                       &passthrough_token) == 0);
  CHECK(g_last_created_start.load(std::memory_order_relaxed) ==
        identity_start);
  CHECK(g_last_created_argument.load(std::memory_order_relaxed) ==
        &passthrough_token);

  CHECK(queued(queued_argument) == &queued_token);
  CHECK(factory.session_creates.load(std::memory_order_relaxed) == 1);
  CHECK(factory.thread_begins.load(std::memory_order_relaxed) == 1);
  CHECK(factory.thread_ends.load(std::memory_order_relaxed) == 1);
}

ThreadCreateGateway *g_installing_gateway = nullptr;
std::atomic<int> g_install_window_status{-1};
std::atomic<void *> g_install_window_result{nullptr};
int g_install_window_token = 0;

bool fake_hook_with_live_publication_window(uintptr_t target, void *replacement,
                                            HookHandle *handle) {
  CHECK(handle->published_original != nullptr);
  __atomic_store_n(handle->published_original,
                   reinterpret_cast<void *>(recording_pthread_create),
                   __ATOMIC_RELEASE);
  CHECK(g_installing_gateway != nullptr);
  pthread_t thread{};
  g_install_window_status.store(
      g_installing_gateway->create(&thread, nullptr, identity_start,
                                   &g_install_window_token),
      std::memory_order_relaxed);
  g_install_window_result.store(
      g_synchronous_result.load(std::memory_order_relaxed),
      std::memory_order_relaxed);
  handle->target = target;
  handle->stub = replacement;
  handle->original = reinterpret_cast<void *>(recording_pthread_create);
  handle->retained_original = handle->original;
  handle->retained_original_bytes = 64;
  return true;
}

void live_hook_publication_window_uses_the_exact_retained_bypass() {
  reset_runtime();
  Factory factory;
  auto coordinator =
      std::make_shared<CaptureCoordinator>(factories(&factory));
  TraceConfig config = flight_config();
  CHECK(coordinator->start(config, module_for(identity_start), 63));
  ThreadCreateGateway gateway(fake_hook_with_live_publication_window);
  g_installing_gateway = &gateway;
  g_install_window_token = 73;
  g_install_window_status.store(-1, std::memory_order_relaxed);
  g_install_window_result.store(nullptr, std::memory_order_relaxed);
  g_synchronous_create.store(true, std::memory_order_relaxed);
  CHECK(gateway.install(coordinator));
  CHECK(g_install_window_status.load(std::memory_order_relaxed) == 0);
  CHECK(g_install_window_result.load(std::memory_order_relaxed) ==
        &g_install_window_token);
  g_installing_gateway = nullptr;
}

__attribute__((noinline)) void *stress_start(void *argument) {
  return argument;
}

void persistent_gateway_survives_concurrent_create_stress() {
  reset_runtime();
  Fixture fixture(module_for(stress_start), 16);
  constexpr size_t kCreators = 4;
  constexpr size_t kIterations = 40;
  std::atomic<size_t> completed{0};
  std::thread creators[kCreators];
  for (size_t creator = 0; creator < kCreators; ++creator) {
    creators[creator] = std::thread([&] {
      for (size_t iteration = 0; iteration < kIterations; ++iteration) {
        pthread_t thread{};
        void *const token = reinterpret_cast<void *>(iteration + 1U);
        if (fixture.gateway.create(&thread, nullptr, stress_start, token) !=
            0) {
          continue;
        }
        void *result = nullptr;
        if (::pthread_join(thread, &result) == 0 && result == token) {
          completed.fetch_add(1, std::memory_order_relaxed);
        }
      }
    });
  }
  for (std::thread &creator : creators)
    creator.join();
  const size_t expected = kCreators * kIterations;
  CHECK(completed.load(std::memory_order_relaxed) == expected);
  CHECK(g_hook_calls.load(std::memory_order_relaxed) == 1);
  CHECK(fixture.factory.session_creates.load(std::memory_order_relaxed) ==
        expected);
  CHECK(fixture.factory.session_destroys.load(std::memory_order_relaxed) ==
        expected);
  CHECK(fixture.factory.thread_begins.load(std::memory_order_relaxed) ==
        expected);
  CHECK(fixture.factory.thread_ends.load(std::memory_order_relaxed) ==
        expected);
}

} // namespace

bool hook_symbol_address(uintptr_t target, void *replacement,
                         HookHandle *handle) {
  return fake_hook_symbol_address(target, replacement, handle);
}

int main() {
  process_global_proxy_has_a_bypass_before_the_hook_is_live();
  persistent_install_captures_every_new_flight_thread();
  preserves_attributes_argument_return_for_all_flight_threads();
  unrelated_native_lifecycle_releases_session_for_scene_reentry();
  hooked_scene_start_uses_the_retained_control_only_gateway();
  queued_hooked_start_snapshots_creator_generation_control();
  active_creator_tls_propagates_nested_ownership();
  cleanup_publishes_thread_end_for_pthread_exit_and_cancel();
  abnormal_session_retirement_is_bounded_and_exhaustion_fails_open();
  allocation_and_create_failure_fail_open_and_publish_sticky_gaps();
  partial_vm_execution_continues_control_only_without_restarting();
  unrelated_external_start_keeps_native_lifecycle_without_a_gap();
  active_old_generation_owns_children_created_after_reconfiguration();
  hook_failure_marks_the_run_incomplete_without_a_residual_gateway();
  residual_hook_failure_permanently_fails_open_through_retained_original();
  child_detach_uses_only_the_inherited_original_path();
  queued_thread_start_keeps_its_coordinator_generation_alive();
  deactivation_preserves_queued_owners_and_makes_new_calls_pass_through();
  live_hook_publication_window_uses_the_exact_retained_bypass();
  persistent_gateway_survives_concurrent_create_stress();
}
