#include "hooks/thread_create_gateway.h"

#include "core/capture_coordinator.h"
#include "core/qbdi_thread_session.h"
#include "core/trace_process_lifecycle.h"

#include <cerrno>
#include <cstdint>
#include <new>
#include <memory>
#include <sys/syscall.h>
#include <unistd.h>

namespace {

#if defined(QTRACE_HOST_TEST)
extern "C" void __lsan_ignore_object(const void *) __attribute__((weak));
#endif

struct ThreadStart {
  CaptureCoordinator *coordinator;
  PthreadStartRoutine original;
  void *argument;
  pid_t creator_tid;
  uint64_t module_generation;
  std::shared_ptr<CaptureCoordinator> owner;
  ThreadExecutionControl control;
  bool execute_with_qbdi;
  std::atomic<size_t> *retirement_reservations;
};

struct ThreadCleanup {
  ThreadStart *start = nullptr;
  QbdiThreadSession *session = nullptr;
};

pid_t current_tid() noexcept {
  return static_cast<pid_t>(::syscall(SYS_gettid));
}

void finish_thread(void *opaque) {
  auto *cleanup = static_cast<ThreadCleanup *>(opaque);
  if (cleanup == nullptr || cleanup->start == nullptr ||
      trace_process_child_detached()) {
    return;
  }
  if (cleanup->session != nullptr && cleanup->start->coordinator != nullptr &&
      !cleanup->start->coordinator->detached()) {
    const bool retain_active_session = cleanup->session->vm_active();
    if (retain_active_session) {
      cleanup->start->coordinator->mark_coverage_gap(
          cleanup->session->tid(), cleanup->session->thread_entry(),
          CoverageGapReason::ThreadAbnormalExit);
    }
    cleanup->start->coordinator->finish_thread(cleanup->session,
                                               retain_active_session);
    if (retain_active_session) {
#if defined(QTRACE_HOST_TEST)
      if (__lsan_ignore_object != nullptr) {
        __lsan_ignore_object(cleanup->start);
      }
#endif
      return;
    }
  }
  if (cleanup->start->retirement_reservations != nullptr) {
    cleanup->start->retirement_reservations->fetch_sub(
        1, std::memory_order_release);
  }
  delete cleanup->start;
  cleanup->start = nullptr;
  cleanup->session = nullptr;
}

void *thread_start_trampoline(void *opaque) {
  auto *start = static_cast<ThreadStart *>(opaque);
  if (start == nullptr || start->original == nullptr)
    return nullptr;
  void *result = nullptr;
  bool deferred_exit = false;
  void *deferred_exit_value = nullptr;
  ThreadCleanup cleanup{start, nullptr};
  pthread_cleanup_push(finish_thread, &cleanup);
  if (trace_process_child_detached() || start->coordinator == nullptr ||
      start->coordinator->detached()) {
    result = start->original(start->argument);
  } else {
    const uint32_t tid = static_cast<uint32_t>(current_tid());
    const uint32_t generation = start->coordinator->module_generation();
    if (generation == 0 || generation != start->module_generation) {
      start->coordinator->mark_coverage_gap(
          tid, reinterpret_cast<uintptr_t>(start->original),
          CoverageGapReason::ModuleGeneration);
      result = start->original(start->argument);
    } else {
      cleanup.session = start->coordinator->enter_thread(
          tid, reinterpret_cast<uintptr_t>(start->original));
      if (cleanup.session == nullptr ||
          !cleanup.session->begin_thread(
              static_cast<uint32_t>(start->creator_tid),
              reinterpret_cast<uintptr_t>(start->original))) {
        if (cleanup.session != nullptr) {
          start->coordinator->mark_coverage_gap(
              tid, reinterpret_cast<uintptr_t>(start->original),
              CoverageGapReason::SessionFailure);
        }
        result = start->original(start->argument);
      } else {
        const uint64_t arguments[8]{static_cast<uint64_t>(
            reinterpret_cast<uintptr_t>(start->argument))};
        const uintptr_t logical_entry =
            reinterpret_cast<uintptr_t>(start->original);
        if (!start->execute_with_qbdi ||
            start->control.execution_entry == 0) {
          if (start->execute_with_qbdi) {
            start->coordinator->mark_coverage_gap(
                tid, logical_entry, CoverageGapReason::GatewayUnavailable);
          }
          if (!cleanup.session->publish_native_thread_begin()) {
            start->coordinator->mark_coverage_gap(
                tid, logical_entry, CoverageGapReason::SessionFailure);
          }
          start->coordinator->leave(cleanup.session);
          result = start->original(start->argument);
        } else {
          const TraceRunResult traced = cleanup.session->call_gateway(
              logical_entry, start->control.execution_entry,
              start->control.control_start, start->control.control_bytes,
              arguments, 0);
          if (traced.target_returned) {
            result = reinterpret_cast<void *>(
                static_cast<uintptr_t>(traced.value));
          } else if (traced.exit_requested) {
            deferred_exit = true;
            deferred_exit_value = reinterpret_cast<void *>(
                static_cast<uintptr_t>(traced.value));
          } else if (!traced.target_executed) {
            result = start->original(start->argument);
          }
        }
      }
    }
  }
  pthread_cleanup_pop(1);
  if (deferred_exit) {
    ::pthread_exit(deferred_exit_value);
  }
  return result;
}

bool capture_flight_thread(CaptureCoordinator *coordinator,
                           PthreadStartRoutine start_routine) noexcept {
  if (coordinator == nullptr || start_routine == nullptr ||
      !coordinator->started() || coordinator->detached()) {
    return false;
  }
  return true;
}

ThreadCreateGateway g_process_thread_create_gateway;

} // namespace

ThreadCreateGateway::ThreadCreateGateway(
    ThreadCreateHookInstaller installer, size_t retirement_budget) noexcept
    : installer_(installer), retirement_budget_(retirement_budget) {}

bool ThreadCreateGateway::install(
    const std::shared_ptr<CaptureCoordinator> &coordinator) noexcept {
  std::lock_guard<std::mutex> install_guard(install_mutex_);
  if (coordinator == nullptr || !coordinator->started() ||
      coordinator->detached() ||
      child_detached_.load(std::memory_order_acquire)) {
    return false;
  }
  if (installed_.load(std::memory_order_acquire)) {
    std::lock_guard<std::mutex> guard(coordinator_mutex_);
    coordinator_ = coordinator;
    return true;
  }
  if (hook_.residual_hook)
    return false;
  const uintptr_t target = reinterpret_cast<uintptr_t>(pthread_create);
  hook_.published_original = &published_original_;
  if (installer_ == nullptr ||
      !installer_(target, reinterpret_cast<void *>(trace_pthread_create_proxy),
                  &hook_) ||
      hook_.retained_original == nullptr) {
    coordinator->mark_coverage_gap(static_cast<uint32_t>(current_tid()), target,
                                   CoverageGapReason::HookSetup);
    return false;
  }
  if (__atomic_load_n(&published_original_, __ATOMIC_ACQUIRE) == nullptr) {
    __atomic_store_n(&published_original_, hook_.retained_original,
                     __ATOMIC_RELEASE);
  }
  {
    std::lock_guard<std::mutex> guard(coordinator_mutex_);
    coordinator_ = coordinator;
  }
  installed_.store(true, std::memory_order_release);
  return true;
}

void ThreadCreateGateway::deactivate() noexcept {
  std::lock_guard<std::mutex> guard(coordinator_mutex_);
  coordinator_.reset();
}

void ThreadCreateGateway::deactivate_if(
    const std::shared_ptr<CaptureCoordinator> &coordinator) noexcept {
  std::lock_guard<std::mutex> guard(coordinator_mutex_);
  if (coordinator_ == coordinator)
    coordinator_.reset();
}

int ThreadCreateGateway::hook_error() const noexcept {
  std::lock_guard<std::mutex> install_guard(install_mutex_);
  return hook_.unhook_error != 0 ? hook_.unhook_error : hook_.hook_error;
}

void ThreadCreateGateway::prepare_for_fork() noexcept {
  install_mutex_.lock();
}

void ThreadCreateGateway::resume_after_fork_parent() noexcept {
  install_mutex_.unlock();
}

bool ThreadCreateGateway::should_capture(
    PthreadStartRoutine start_routine) const noexcept {
  if (!installed_.load(std::memory_order_acquire) ||
      child_detached_.load(std::memory_order_acquire) ||
      trace_process_child_detached()) {
    return false;
  }
  std::shared_ptr<CaptureCoordinator> coordinator =
      current_capture_coordinator();
  QbdiThreadSession *const active_session = current_qbdi_thread_session();
  if (coordinator == nullptr || active_session == nullptr ||
      active_session->module_generation() != coordinator->module_generation()) {
    std::lock_guard<std::mutex> guard(coordinator_mutex_);
    coordinator = coordinator_;
  }
  return capture_flight_thread(coordinator.get(), start_routine);
}

int ThreadCreateGateway::create(pthread_t *thread,
                                const pthread_attr_t *attributes,
                                PthreadStartRoutine start_routine,
                                void *argument) noexcept {
  PthreadCreateFunction original = reinterpret_cast<PthreadCreateFunction>(
      __atomic_load_n(&published_original_, __ATOMIC_ACQUIRE));
  if (original == nullptr)
    return EAGAIN;
  if (child_detached_.load(std::memory_order_acquire) ||
      trace_process_child_detached()) {
    return original(thread, attributes, start_routine, argument);
  }
  if (!installed_.load(std::memory_order_acquire))
    return original(thread, attributes, start_routine, argument);
  std::shared_ptr<CaptureCoordinator> coordinator =
      current_capture_coordinator();
  QbdiThreadSession *const active_session = current_qbdi_thread_session();
  const bool active_target_creator =
      coordinator != nullptr && active_session != nullptr &&
      active_session->vm_active() &&
      active_session->module_generation() == coordinator->module_generation();
  if (coordinator == nullptr || active_session == nullptr ||
      active_session->module_generation() != coordinator->module_generation()) {
    std::lock_guard<std::mutex> guard(coordinator_mutex_);
    coordinator = coordinator_;
  }
  if (!capture_flight_thread(coordinator.get(), start_routine))
    return original(thread, attributes, start_routine, argument);

  const pid_t creator_tid = current_tid();
  ThreadExecutionControl control{};
  const bool execute_with_qbdi =
      active_target_creator || coordinator->contains_target_address(
                                       reinterpret_cast<uintptr_t>(start_routine));
  if (execute_with_qbdi) {
    (void)coordinator->resolve_thread_start(
        reinterpret_cast<uintptr_t>(start_routine), &control);
  }
  size_t reservations = retirement_reservations_.load(std::memory_order_relaxed);
  while (reservations < retirement_budget_ &&
         !retirement_reservations_.compare_exchange_weak(
             reservations, reservations + 1U, std::memory_order_acq_rel,
             std::memory_order_relaxed)) {
  }
  if (reservations >= retirement_budget_) {
    coordinator->mark_coverage_gap(static_cast<uint32_t>(creator_tid),
                                   reinterpret_cast<uintptr_t>(start_routine),
                                   CoverageGapReason::RetirementCapacity);
    return original(thread, attributes, start_routine, argument);
  }
  auto *start = new (std::nothrow)
      ThreadStart{coordinator.get(), start_routine, argument, creator_tid,
                  coordinator->module_generation(), coordinator, control,
                  execute_with_qbdi, &retirement_reservations_};
  if (start == nullptr) {
    retirement_reservations_.fetch_sub(1, std::memory_order_release);
    coordinator->mark_coverage_gap(static_cast<uint32_t>(creator_tid),
                                   reinterpret_cast<uintptr_t>(start_routine),
                                   CoverageGapReason::ThreadStartAllocation);
    return original(thread, attributes, start_routine, argument);
  }

  const int result =
      original(thread, attributes, thread_start_trampoline, start);
  if (result != 0) {
    retirement_reservations_.fetch_sub(1, std::memory_order_release);
    delete start;
    coordinator->mark_coverage_gap(static_cast<uint32_t>(creator_tid),
                                   reinterpret_cast<uintptr_t>(start_routine),
                                   CoverageGapReason::ThreadCreate);
  }
  return result;
}

void ThreadCreateGateway::detach_after_fork_child() noexcept {
  child_detached_.store(true, std::memory_order_release);
}

ThreadCreateGateway &process_thread_create_gateway() noexcept {
  return g_process_thread_create_gateway;
}

extern "C" int trace_pthread_create_proxy(pthread_t *thread,
                                          const pthread_attr_t *attributes,
                                          PthreadStartRoutine start_routine,
                                          void *argument) noexcept {
  return process_thread_create_gateway().create(thread, attributes,
                                                start_routine, argument);
}
