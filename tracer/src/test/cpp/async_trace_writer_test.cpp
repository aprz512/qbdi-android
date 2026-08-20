#include "events/async_trace_writer.h"
#include "core/trace_process_lifecycle.h"
#include "lz4frame.h"

#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

using namespace std::chrono_literals;

void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

class MemoryBackend : public TraceWriterBackend {
public:
    int open_file(const char *, int, unsigned int) noexcept override {
        ++open_calls;
        return open_error == 0 ? 17 : (errno = open_error, -1);
    }

    ssize_t write_file(int, const void *data, size_t size) noexcept override {
        std::lock_guard<std::mutex> lock(mutex);
        ++write_calls;
        if (interrupt_once) {
            interrupt_once = false;
            errno = EINTR;
            return -1;
        }
        if (write_error != 0) {
            errno = write_error;
            return -1;
        }
        const size_t accepted = std::min(size, max_write_bytes);
        const auto *bytes = static_cast<const char *>(data);
        output.insert(output.end(), bytes, bytes + accepted);
        return static_cast<ssize_t>(accepted);
    }

    int close_file(int) noexcept override {
        ++close_calls;
        return 0;
    }

    std::vector<char> copy_output() const {
        std::lock_guard<std::mutex> lock(mutex);
        return output;
    }

    mutable std::mutex mutex;
    std::vector<char> output;
    int open_error = 0;
    int write_error = 0;
    bool interrupt_once = false;
    size_t max_write_bytes = static_cast<size_t>(-1);
    std::atomic<unsigned int> open_calls{0};
    std::atomic<unsigned int> write_calls{0};
    std::atomic<unsigned int> close_calls{0};
};

class BlockingErrorBackend final : public MemoryBackend {
public:
    ssize_t write_file(int, const void *, size_t) noexcept override {
        std::unique_lock<std::mutex> lock(gate_mutex);
        entered = true;
        gate_changed.notify_all();
        gate_changed.wait(lock, [&] { return released; });
        errno = ENOSPC;
        return -1;
    }

    void wait_until_entered() {
        std::unique_lock<std::mutex> lock(gate_mutex);
        CHECK(gate_changed.wait_for(lock, 5s, [&] { return entered; }));
    }

    void release() {
        std::lock_guard<std::mutex> lock(gate_mutex);
        released = true;
        gate_changed.notify_all();
    }

private:
    std::mutex gate_mutex;
    std::condition_variable gate_changed;
    bool entered = false;
    bool released = false;
};

class FirstWriteGateBackend final : public MemoryBackend {
public:
    ssize_t write_file(int fd, const void *data, size_t size) noexcept override {
        {
            std::unique_lock<std::mutex> lock(gate_mutex);
            if (first_write) {
                entered = true;
                changed.notify_all();
                changed.wait(lock, [&] { return released; });
                first_write = false;
            }
        }
        return MemoryBackend::write_file(fd, data, size);
    }

    void wait_until_entered() {
        std::unique_lock<std::mutex> lock(gate_mutex);
        CHECK(changed.wait_for(lock, 5s, [&] { return entered; }));
    }

    void release() {
        std::lock_guard<std::mutex> lock(gate_mutex);
        released = true;
        changed.notify_all();
    }

private:
    std::mutex gate_mutex;
    std::condition_variable changed;
    bool first_write = true;
    bool entered = false;
    bool released = false;
};

class WaitingFaults final : public TraceFaultInjector {
public:
    void producer_waiting() noexcept override {
        std::lock_guard<std::mutex> lock(mutex);
        waiting = true;
        changed.notify_all();
    }

    void wait_until_producer_waits() {
        std::unique_lock<std::mutex> lock(mutex);
        CHECK(changed.wait_for(lock, 5s, [&] { return waiting; }));
    }

private:
    std::mutex mutex;
    std::condition_variable changed;
    bool waiting = false;
};

class OrderingFaults final : public TraceFaultInjector {
public:
    void producer_waiting() noexcept override {
        std::lock_guard<std::mutex> lock(mutex);
        ++producer_wait_count;
        changed.notify_all();
    }

    void consumer_released_buffer() noexcept override {
        std::unique_lock<std::mutex> lock(mutex);
        if (!blocked_consumer_once) {
            blocked_consumer_once = true;
            changed.notify_all();
            changed.wait(lock, [&] { return consumer_can_continue; });
        }
    }

    void wait_for_producer_wait_count(unsigned int expected) {
        std::unique_lock<std::mutex> lock(mutex);
        CHECK(changed.wait_for(lock, 5s, [&] { return producer_wait_count >= expected; }));
    }

    void wait_until_consumer_is_blocked() {
        std::unique_lock<std::mutex> lock(mutex);
        CHECK(changed.wait_for(lock, 5s, [&] { return blocked_consumer_once; }));
    }

    void release_consumer() {
        std::lock_guard<std::mutex> lock(mutex);
        consumer_can_continue = true;
        changed.notify_all();
    }

private:
    std::mutex mutex;
    std::condition_variable changed;
    unsigned int producer_wait_count = 0;
    bool blocked_consumer_once = false;
    bool consumer_can_continue = false;
};

class SelectiveFaults final : public TraceFaultInjector {
public:
    bool fail_buffer_allocation(size_t per_buffer_bytes) noexcept override {
        allocation_attempts.push_back(per_buffer_bytes);
        return per_buffer_bytes != allowed_buffer_bytes;
    }

    bool fail_compression_allocation(size_t bytes) noexcept override {
        compression_allocation_bytes = bytes;
        return compression_allocation_fails;
    }

    int create_consumer_thread(pthread_t *thread, void *(*entry)(void *),
                               void *argument) noexcept override {
        if (thread_error != 0) return thread_error;
        return TraceFaultInjector::create_consumer_thread(thread, entry, argument);
    }

    int join_consumer_thread(pthread_t thread, void **result) noexcept override {
        {
            std::lock_guard<std::mutex> lock(lz4_mutex);
            ++join_attempts;
            lz4_changed.notify_all();
            if (join_failures_remaining != 0) {
                --join_failures_remaining;
                return EINVAL;
            }
        }
        return TraceFaultInjector::join_consumer_thread(thread, result);
    }

    bool fail_lz4_operation() noexcept override {
        std::unique_lock<std::mutex> lock(lz4_mutex);
        if (block_lz4) {
            lz4_entered = true;
            lz4_changed.notify_all();
            lz4_changed.wait(lock, [&] { return lz4_released; });
        }
        return lz4_fails;
    }

    void wait_until_lz4_entered() {
        std::unique_lock<std::mutex> lock(lz4_mutex);
        CHECK(lz4_changed.wait_for(lock, 5s, [&] { return lz4_entered; }));
    }

    void release_lz4() {
        std::lock_guard<std::mutex> lock(lz4_mutex);
        lz4_released = true;
        lz4_changed.notify_all();
    }

    void consumer_thread_exited() noexcept override {
        std::lock_guard<std::mutex> lock(lz4_mutex);
        consumer_exited = true;
        lz4_changed.notify_all();
    }

    void wait_until_consumer_exits() {
        std::unique_lock<std::mutex> lock(lz4_mutex);
        CHECK(lz4_changed.wait_for(lock, 5s, [&] { return consumer_exited; }));
    }

    void wait_for_join_attempts(unsigned int expected) {
        std::unique_lock<std::mutex> lock(lz4_mutex);
        CHECK(lz4_changed.wait_for(lock, 5s, [&] { return join_attempts >= expected; }));
    }

    size_t allowed_buffer_bytes = static_cast<size_t>(-1);
    bool compression_allocation_fails = false;
    bool lz4_fails = false;
    bool block_lz4 = false;
    int thread_error = 0;
    unsigned int join_failures_remaining = 0;
    size_t compression_allocation_bytes = 0;
    std::vector<size_t> allocation_attempts;

private:
    std::mutex lz4_mutex;
    std::condition_variable lz4_changed;
    bool lz4_entered = false;
    bool lz4_released = false;
    bool consumer_exited = false;
    unsigned int join_attempts = 0;
};

TraceOptions options_with_buffer(size_t bytes) {
    TraceOptions options;
    options.auto_buffer_size = false;
    options.buffer_bytes = bytes;
    options.compression_enabled = true;
    return options;
}

std::vector<char> decompress_concatenated_frames(const std::vector<char> &compressed,
                                                 size_t *frame_count) {
    std::vector<char> decoded;
    size_t input_offset = 0;
    *frame_count = 0;

    while (input_offset < compressed.size()) {
        LZ4F_dctx *context = nullptr;
        CHECK(!LZ4F_isError(LZ4F_createDecompressionContext(&context, LZ4F_VERSION)));
        size_t result = 1;
        while (result != 0) {
            char chunk[32768];
            size_t source_size = compressed.size() - input_offset;
            size_t destination_size = sizeof(chunk);
            result = LZ4F_decompress(context, chunk, &destination_size,
                                     compressed.data() + input_offset, &source_size, nullptr);
            CHECK(!LZ4F_isError(result));
            CHECK(source_size != 0 || destination_size != 0 || result == 0);
            input_offset += source_size;
            decoded.insert(decoded.end(), chunk, chunk + destination_size);
        }
        LZ4F_freeDecompressionContext(context);
        ++*frame_count;
    }
    return decoded;
}

void sizes_each_buffer_exactly() {
    CHECK(choose_trace_buffer_bytes(0, 0, true) == (64ULL << 20));
    CHECK(choose_trace_buffer_bytes(1ULL << 30, 0, true) == (64ULL << 20));
    CHECK(choose_trace_buffer_bytes(4ULL << 30, 0, true) == (64ULL << 20));
    CHECK(choose_trace_buffer_bytes(6ULL << 30, 0, true) == (64ULL << 20));
    CHECK(choose_trace_buffer_bytes((8ULL << 30) - 1, 0, true) == (64ULL << 20));
    CHECK(choose_trace_buffer_bytes(8ULL << 30, 0, true) == (128ULL << 20));
    CHECK(choose_trace_buffer_bytes(4ULL << 30, 32ULL << 20, false) == (32ULL << 20));

    MemoryBackend backend;
    TraceMetrics metrics{};
    AsyncTraceWriter writer(&backend);
    CHECK(writer.open("memory", options_with_buffer(4096), &metrics));
    WritableSpan first = writer.reserve(1);
    CHECK(first.data != nullptr);
    CHECK(first.capacity == 4096);
    std::memset(first.data, 'x', 17);
    writer.commit(17);
    WritableSpan second = writer.reserve(1);
    CHECK(second.data == first.data + 17);
    CHECK(second.capacity == 4096 - 17);
    writer.commit(0);
    CHECK(writer.finish());
}

void appends_large_payloads_as_exact_concatenated_frames() {
    MemoryBackend backend;
    TraceMetrics metrics{};
    AsyncTraceWriter writer(&backend);
    CHECK(writer.open("memory", options_with_buffer(4096), &metrics));

    std::string expected;
    for (char marker : {'A', 'B', 'C'}) {
        std::string payload(10 * 1024, marker);
        expected += payload;
        CHECK(writer.append(payload));
    }
    CHECK(writer.finish());

    size_t frames = 0;
    std::vector<char> decoded = decompress_concatenated_frames(backend.copy_output(), &frames);
    CHECK(std::string(decoded.begin(), decoded.end()) == expected);
    CHECK(frames >= 3);
    CHECK(metrics.buffer_swaps >= 2);
    CHECK(metrics.encoded_bytes == expected.size());
    CHECK(metrics.compressed_bytes > 0);
}

void retries_interrupted_writes() {
    MemoryBackend backend;
    backend.interrupt_once = true;
    TraceMetrics metrics{};
    AsyncTraceWriter writer(&backend);
    CHECK(writer.open("memory", options_with_buffer(4096), &metrics));
    CHECK(writer.append("retry me"));
    CHECK(writer.finish());
    CHECK(backend.write_calls >= 2);

    size_t frames = 0;
    const auto decoded = decompress_concatenated_frames(backend.copy_output(), &frames);
    CHECK(std::string(decoded.begin(), decoded.end()) == "retry me");
    CHECK(frames == 1);
}

void completes_short_writes_without_losing_bytes() {
    MemoryBackend backend;
    backend.max_write_bytes = 3;
    TraceMetrics metrics{};
    AsyncTraceWriter writer(&backend);
    CHECK(writer.open("memory", options_with_buffer(4096), &metrics));
    CHECK(writer.append("short writes remain ordered"));
    CHECK(writer.finish());
    CHECK(backend.write_calls > 1);

    size_t frames = 0;
    const auto decoded = decompress_concatenated_frames(backend.copy_output(), &frames);
    CHECK(std::string(decoded.begin(), decoded.end()) == "short writes remain ordered");
    CHECK(frames == 1);
    CHECK(metrics.encoded_bytes == 27);
}

void preserves_publication_order_when_buffer_zero_is_republished() {
    FirstWriteGateBackend backend;
    OrderingFaults faults;
    TraceMetrics metrics{};
    AsyncTraceWriter writer(&backend, &faults);
    CHECK(writer.open("memory", options_with_buffer(4096), &metrics));

    const std::string expected = std::string(4096, 'A') + std::string(4096, 'B') +
                                 std::string(4096, 'C') + "!";
    std::atomic<bool> producer_result{false};
    std::thread producer([&] {
        const bool bulk = writer.append(std::string_view(expected.data(), 3 * 4096));
        const bool tail = writer.append(std::string_view(expected.data() + 3 * 4096, 1));
        producer_result.store(bulk && tail, std::memory_order_release);
    });

    backend.wait_until_entered();
    faults.wait_for_producer_wait_count(1);
    backend.release();
    faults.wait_until_consumer_is_blocked();
    faults.wait_for_producer_wait_count(2);
    faults.release_consumer();
    producer.join();
    CHECK(producer_result.load(std::memory_order_acquire));
    CHECK(writer.finish());

    size_t frames = 0;
    const auto decoded = decompress_concatenated_frames(backend.copy_output(), &frames);
    CHECK(std::string(decoded.begin(), decoded.end()) == expected);
    CHECK(frames == 4);
}

void enospc_releases_a_waiting_producer() {
    BlockingErrorBackend backend;
    WaitingFaults faults;
    TraceMetrics metrics{};
    AsyncTraceWriter writer(&backend, &faults);
    CHECK(writer.open("memory", options_with_buffer(4096), &metrics));

    std::atomic<char *> reserve_result{reinterpret_cast<char *>(1)};
    std::thread producer([&] {
        CHECK(writer.append(std::string(2 * 4096, 'z')));
        reserve_result.store(writer.reserve(1).data, std::memory_order_release);
    });

    backend.wait_until_entered();
    faults.wait_until_producer_waits();
    backend.release();
    producer.join();
    CHECK(reserve_result.load(std::memory_order_acquire) == nullptr);
    CHECK(writer.failed());
    CHECK(!writer.finish());
    CHECK(!writer.finish());
    CHECK(writer.error_code() == ENOSPC);
    CHECK(metrics.producer_waits >= 1);
    CHECK(metrics.producer_wait_ns > 0);
    CHECK(metrics.encoded_bytes == 2 * 4096);
}

void allocation_falls_back_to_eight_mib_per_buffer() {
    MemoryBackend backend;
    SelectiveFaults faults;
    faults.allowed_buffer_bytes = 8ULL << 20;
    TraceMetrics metrics{};
    AsyncTraceWriter writer(&backend, &faults);
    CHECK(writer.open("memory", options_with_buffer(16ULL << 20), &metrics));
    CHECK(writer.buffer_bytes() == (8ULL << 20));
    WritableSpan span = writer.reserve(1);
    CHECK(span.capacity == (8ULL << 20));
    writer.commit(0);
    CHECK((faults.allocation_attempts ==
            std::vector<size_t>{16ULL << 20, 64ULL << 20, 32ULL << 20, 8ULL << 20}));
    CHECK(writer.finish());
}

void open_reports_allocation_thread_and_backend_failures() {
    TraceMetrics metrics{};
    MemoryBackend backend;

    SelectiveFaults allocation_faults;
    AsyncTraceWriter allocation_writer(&backend, &allocation_faults);
    CHECK(!allocation_writer.open("memory", options_with_buffer(4096), &metrics));
    CHECK(allocation_writer.failed());

    SelectiveFaults scratch_faults;
    scratch_faults.allowed_buffer_bytes = 4096;
    scratch_faults.compression_allocation_fails = true;
    AsyncTraceWriter scratch_writer(&backend, &scratch_faults);
    CHECK(!scratch_writer.open("memory", options_with_buffer(4096), &metrics));
    CHECK(scratch_writer.failed());
    CHECK(scratch_faults.compression_allocation_bytes > 0);
    CHECK(scratch_faults.compression_allocation_bytes < (2ULL << 20));

    SelectiveFaults thread_faults;
    thread_faults.allowed_buffer_bytes = 4096;
    thread_faults.thread_error = EAGAIN;
    AsyncTraceWriter thread_writer(&backend, &thread_faults);
    CHECK(!thread_writer.open("memory", options_with_buffer(4096), &metrics));
    CHECK(thread_writer.failed());

    MemoryBackend failing_backend;
    failing_backend.open_error = EACCES;
    AsyncTraceWriter backend_writer(&failing_backend);
    CHECK(!backend_writer.open("memory", options_with_buffer(4096), &metrics));
    CHECK(backend_writer.failed());
}

void lz4_failures_release_resources_and_reject_later_appends() {
    MemoryBackend backend;
    SelectiveFaults faults;
    faults.allowed_buffer_bytes = 4096;
    faults.lz4_fails = true;
    faults.block_lz4 = true;
    TraceMetrics metrics{};
    AsyncTraceWriter writer(&backend, &faults);
    CHECK(writer.open("memory", options_with_buffer(4096), &metrics));
    CHECK(writer.append(std::string(8192, 'q')));
    faults.wait_until_lz4_entered();
    faults.release_lz4();
    CHECK(!writer.finish());
    CHECK(writer.failed());
    CHECK(!writer.append("later"));
}

void failed_join_retains_resources_until_consumer_exit_is_observed() {
    MemoryBackend backend;
    SelectiveFaults faults;
    faults.allowed_buffer_bytes = 4096;
    faults.block_lz4 = true;
    faults.join_failures_remaining = 1;
    TraceMetrics metrics{};

    auto writer = std::make_unique<AsyncTraceWriter>(&backend, &faults);
    CHECK(writer->open("memory", options_with_buffer(4096), &metrics));
    CHECK(writer->append(std::string(8192, 'j')));
    faults.wait_until_lz4_entered();
    CHECK(!writer->finish());
    CHECK(writer->failed());
    CHECK(!writer->finish());
    CHECK(backend.close_calls.load() == 0);

    std::atomic<bool> destructor_returned{false};
    std::thread destroyer([&] {
        writer.reset();
        destructor_returned.store(true, std::memory_order_release);
    });
    faults.wait_for_join_attempts(2);
    CHECK(!destructor_returned.load(std::memory_order_acquire));
    faults.release_lz4();
    destroyer.join();
    CHECK(destructor_returned.load(std::memory_order_acquire));
    CHECK(backend.close_calls.load() == 1);
}

void finish_is_idempotent_and_invalid_calls_are_rejected() {
    MemoryBackend backend;
    TraceMetrics metrics{};
    AsyncTraceWriter unopened(&backend);
    CHECK(unopened.reserve(1).data == nullptr);
    CHECK(!unopened.append("x"));
    CHECK(!unopened.finish());

    AsyncTraceWriter writer(&backend);
    CHECK(writer.open("memory", options_with_buffer(4096), &metrics));
    CHECK(!writer.open("again", options_with_buffer(4096), &metrics));
    CHECK(writer.reserve(0).data == nullptr);
    CHECK(writer.append("done"));
    CHECK(writer.finish());
    CHECK(writer.finish());
    CHECK(!writer.append("too late"));
    CHECK(writer.reserve(1).data == nullptr);

    AsyncTraceWriter invalid_commit(&backend);
    CHECK(invalid_commit.open("memory", options_with_buffer(4096), &metrics));
    WritableSpan reserved = invalid_commit.reserve(4);
    CHECK(reserved.capacity >= 4);
    invalid_commit.commit(reserved.capacity + 1);
    CHECK(invalid_commit.failed());
    CHECK(!invalid_commit.finish());
}

void lifecycle_install_failure_prevents_opening_an_owned_fd() {
    trace_process_test_force_lifecycle_error(ENOMEM);
    MemoryBackend backend;
    TraceMetrics metrics{};
    AsyncTraceWriter writer(&backend);
    CHECK(!writer.open("memory", options_with_buffer(4096), &metrics));
    CHECK(writer.error_code() == ENOMEM);
    CHECK(backend.open_calls.load() == 0);
}

} // namespace

int main() {
    sizes_each_buffer_exactly();
    appends_large_payloads_as_exact_concatenated_frames();
    retries_interrupted_writes();
    completes_short_writes_without_losing_bytes();
    preserves_publication_order_when_buffer_zero_is_republished();
    enospc_releases_a_waiting_producer();
    allocation_falls_back_to_eight_mib_per_buffer();
    open_reports_allocation_thread_and_backend_failures();
    lz4_failures_release_resources_and_reject_later_appends();
    failed_join_retains_resources_until_consumer_exit_is_observed();
    finish_is_idempotent_and_invalid_calls_are_rejected();
    lifecycle_install_failure_prevents_opening_an_owned_fd();
    return 0;
}
