#pragma once

#include "core/trace_config.h"
#include "events/trace_metrics.h"

#include <cstddef>
#include <cstdint>
#include <pthread.h>
#include <string>
#include <string_view>
#include <sys/types.h>

enum class BufferState : uint8_t { Free, Filling, Ready, Writing };

enum class FailurePoint : uint8_t {
    None,
    PathSetup,
    DirectoryCreation,
    Allocation,
    Synchronization,
    ThreadCreation,
    CompressionAllocation,
    Compression,
    FirstWrite,
    FinalWrite,
    MetricsSidecar,
};

struct WritableSpan {
    char *data = nullptr;
    size_t capacity = 0;
};

class TraceWriterBackend {
public:
    virtual ~TraceWriterBackend() = default;

    virtual int open_file(const char *path, int flags, unsigned int mode) noexcept;
    virtual ssize_t write_file(int fd, const void *data, size_t size) noexcept;
    virtual int close_file(int fd) noexcept;
};

class TraceFaultInjector {
public:
    virtual ~TraceFaultInjector() = default;

    virtual int failure(FailurePoint point) noexcept;
    virtual bool fail_buffer_allocation(size_t per_buffer_bytes) noexcept;
    virtual bool fail_compression_allocation(size_t bytes) noexcept;
    virtual int create_consumer_thread(pthread_t *thread, void *(*entry)(void *),
                                       void *argument) noexcept;
    virtual int join_consumer_thread(pthread_t thread, void **result) noexcept;
    virtual bool fail_lz4_operation() noexcept;
    virtual void producer_waiting() noexcept;
    virtual void consumer_released_buffer() noexcept;
    virtual void consumer_thread_exited() noexcept;
};

size_t choose_trace_buffer_bytes(uint64_t physical_bytes, size_t requested_bytes,
                                 bool auto_size) noexcept;

struct AsyncTraceWriterImpl;

class AsyncTraceWriter {
public:
    explicit AsyncTraceWriter(TraceWriterBackend *backend = nullptr,
                              TraceFaultInjector *faults = nullptr) noexcept;
    ~AsyncTraceWriter();

    AsyncTraceWriter(const AsyncTraceWriter &) = delete;
    AsyncTraceWriter &operator=(const AsyncTraceWriter &) = delete;

    bool open(std::string_view path, const TraceOptions &options, TraceMetrics *metrics);
    WritableSpan reserve(size_t minimum);
    void commit(size_t bytes);
    bool append(std::string_view bytes);
    // Publishes all producer bytes and waits until the consumer has completed every prior frame.
    // A fresh empty producer buffer is acquired before returning.
    bool drain();
    // Requires a successful drain. Predicts the completed artifact size if final_record is the
    // next and final independently framed publication, without writing it.
    bool projected_file_bytes(std::string_view final_record, uint64_t *bytes);
    bool finish();
    void detach_after_fork_child() noexcept;
    bool failed() const;
    int error_code() const noexcept;
    size_t buffer_bytes() const noexcept;

private:
    AsyncTraceWriterImpl *impl_ = nullptr;
};
