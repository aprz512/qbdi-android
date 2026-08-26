#pragma once

#include "hooks/inline_hook_adapter.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <pthread.h>

class CaptureCoordinator;

using PthreadStartRoutine = void *(*)(void *);
using PthreadCreateFunction = int (*)(pthread_t *, const pthread_attr_t *,
                                      PthreadStartRoutine, void *);
using ThreadCreateHookInstaller = bool (*)(uintptr_t, void *, HookHandle *);

class ThreadCreateGateway final {
public:
  explicit ThreadCreateGateway(
      ThreadCreateHookInstaller installer = hook_symbol_address,
      size_t retirement_budget = 64) noexcept;

  ThreadCreateGateway(const ThreadCreateGateway &) = delete;
  ThreadCreateGateway &operator=(const ThreadCreateGateway &) = delete;

  bool install(const std::shared_ptr<CaptureCoordinator> &coordinator) noexcept;
  void deactivate() noexcept;
  void deactivate_if(
      const std::shared_ptr<CaptureCoordinator> &coordinator) noexcept;
  bool should_capture(PthreadStartRoutine start_routine) const noexcept;
  int create(pthread_t *thread, const pthread_attr_t *attributes,
             PthreadStartRoutine start_routine, void *argument) noexcept;
  void prepare_for_fork() noexcept;
  void resume_after_fork_parent() noexcept;
  void detach_after_fork_child() noexcept;

  bool installed() const noexcept {
    return installed_.load(std::memory_order_acquire);
  }

  int hook_error() const noexcept;

private:
  ThreadCreateHookInstaller installer_ = nullptr;
  HookHandle hook_{};
  mutable std::mutex install_mutex_;
  mutable std::mutex coordinator_mutex_;
  std::shared_ptr<CaptureCoordinator> coordinator_;
  void *published_original_ = nullptr;
  std::atomic<bool> installed_{false};
  std::atomic<bool> child_detached_{false};
  std::atomic<size_t> retirement_reservations_{0};
  size_t retirement_budget_ = 0;
};

ThreadCreateGateway &process_thread_create_gateway() noexcept;

extern "C" int trace_pthread_create_proxy(pthread_t *thread,
                                          const pthread_attr_t *attributes,
                                          PthreadStartRoutine start_routine,
                                          void *argument) noexcept;
