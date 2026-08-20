#include "events/async_trace_writer.h"

#include "core/trace_process_lifecycle.h"

#include "lz4frame.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <climits>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <new>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

namespace {

constexpr size_t kMiB = 1024ULL * 1024ULL;
constexpr size_t kCompressionChunkBytes = kMiB;
constexpr size_t kFallbackBufferBytes[] = {64ULL * kMiB, 32ULL * kMiB, 8ULL * kMiB};

uint64_t monotonic_nanoseconds() noexcept {
    timespec now{};
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return static_cast<uint64_t>(now.tv_sec) * 1000000000ULL +
           static_cast<uint64_t>(now.tv_nsec);
}

uint64_t physical_memory_bytes() noexcept {
    const long pages = sysconf(_SC_PHYS_PAGES);
    const long page_size = sysconf(_SC_PAGESIZE);
    if (pages <= 0 || page_size <= 0) return 0;
    const uint64_t page_count = static_cast<uint64_t>(pages);
    const uint64_t bytes_per_page = static_cast<uint64_t>(page_size);
    if (page_count > std::numeric_limits<uint64_t>::max() / bytes_per_page) return 0;
    return page_count * bytes_per_page;
}

class PosixTraceWriterBackend final : public TraceWriterBackend {};
class DefaultTraceFaultInjector final : public TraceFaultInjector {};

PosixTraceWriterBackend g_posix_backend;
DefaultTraceFaultInjector g_default_faults;

} // namespace

int TraceWriterBackend::open_file(const char *path, int flags, unsigned int mode) noexcept {
    return ::open(path, flags, static_cast<mode_t>(mode));
}

ssize_t TraceWriterBackend::write_file(int fd, const void *data, size_t size) noexcept {
    return ::write(fd, data, size);
}

int TraceWriterBackend::close_file(int fd) noexcept {
    return ::close(fd);
}

bool TraceFaultInjector::fail_buffer_allocation(size_t) noexcept {
    return false;
}

int TraceFaultInjector::failure(FailurePoint) noexcept {
    return 0;
}

bool TraceFaultInjector::fail_compression_allocation(size_t) noexcept {
    return false;
}

int TraceFaultInjector::create_consumer_thread(pthread_t *thread, void *(*entry)(void *),
                                               void *argument) noexcept {
    return pthread_create(thread, nullptr, entry, argument);
}

int TraceFaultInjector::join_consumer_thread(pthread_t thread, void **result) noexcept {
    return pthread_join(thread, result);
}

bool TraceFaultInjector::fail_lz4_operation() noexcept {
    return false;
}

void TraceFaultInjector::producer_waiting() noexcept {}

void TraceFaultInjector::consumer_released_buffer() noexcept {}

void TraceFaultInjector::consumer_thread_exited() noexcept {}

size_t choose_trace_buffer_bytes(uint64_t physical_bytes, size_t requested_bytes,
                                 bool auto_size) noexcept {
    if (!auto_size) return requested_bytes;
    return physical_bytes < (8ULL << 30) ? 64ULL * kMiB : 128ULL * kMiB;
}

struct AsyncTraceWriterImpl {
    struct Buffer {
        char *data = nullptr;
        size_t used = 0;
        uint64_t publication_sequence = 0;
        BufferState state = BufferState::Free;
    };

    explicit AsyncTraceWriterImpl(TraceWriterBackend *selected_backend,
                                  TraceFaultInjector *selected_faults) noexcept
        : backend(selected_backend != nullptr ? selected_backend : &g_posix_backend),
          faults(selected_faults != nullptr ? selected_faults : &g_default_faults) {
        synchronization_error = pthread_mutex_init(&mutex, nullptr);
        if (synchronization_error != 0) return;
        mutex_initialized = true;
        synchronization_error = pthread_cond_init(&ready_changed, nullptr);
        if (synchronization_error != 0) return;
        ready_changed_initialized = true;
        synchronization_error = pthread_cond_init(&free_changed, nullptr);
        if (synchronization_error == 0) free_changed_initialized = true;
        const int injected = faults->failure(FailurePoint::Synchronization);
        if (synchronization_error == 0 && injected != 0) synchronization_error = injected;
    }

    ~AsyncTraceWriterImpl() {
        if (free_changed_initialized) pthread_cond_destroy(&free_changed);
        if (ready_changed_initialized) pthread_cond_destroy(&ready_changed);
        if (mutex_initialized) pthread_mutex_destroy(&mutex);
    }

    TraceWriterBackend *backend;
    TraceFaultInjector *faults;
    TraceMetrics *metrics = nullptr;
    Buffer buffers[2];
    size_t buffer_bytes = 0;
    char *compression_scratch = nullptr;
    size_t compression_scratch_bytes = 0;
    LZ4F_cctx *compression_context = nullptr;
    LZ4F_preferences_t preferences{};
    int fd = -1;
    size_t fd_registry_slot = kInvalidTraceWriterFdSlot;
    pid_t owner_pid = -1;
    pthread_t consumer_thread{};
    bool consumer_started = false;
    std::atomic<bool> consumer_exited{false};
    bool opened = false;
    bool producer_done = false;
    bool finish_called = false;
    bool finish_result = false;
    bool resources_released = false;
    int join_error = 0;
    int active_buffer = -1;
    bool reservation_active = false;
    size_t reservation_capacity = 0;
    uint64_t next_publication_sequence = 1;
    std::atomic<int> error{0};
    std::atomic<uint64_t> compressed_bytes{0};
    bool first_write_attempted = false;
    int synchronization_error = 0;
    bool mutex_initialized = false;
    bool ready_changed_initialized = false;
    bool free_changed_initialized = false;
    pthread_mutex_t mutex{};
    pthread_cond_t ready_changed{};
    pthread_cond_t free_changed{};
};

namespace {

void latch_failure(AsyncTraceWriterImpl *impl, int error_code) noexcept {
    if (error_code == 0) error_code = EIO;
    int expected = 0;
    impl->error.compare_exchange_strong(expected, error_code, std::memory_order_release,
                                        std::memory_order_relaxed);
}

void unmap_region(void *region, size_t bytes) noexcept {
    if (region != nullptr && region != MAP_FAILED && bytes != 0) munmap(region, bytes);
}

void release_mappings(AsyncTraceWriterImpl *impl) noexcept {
    unmap_region(impl->compression_scratch, impl->compression_scratch_bytes);
    impl->compression_scratch = nullptr;
    impl->compression_scratch_bytes = 0;
    for (auto &buffer : impl->buffers) {
        unmap_region(buffer.data, impl->buffer_bytes);
        buffer.data = nullptr;
        buffer.used = 0;
        buffer.state = BufferState::Free;
    }
    impl->buffer_bytes = 0;
}

void close_backend(AsyncTraceWriterImpl *impl) noexcept {
    if (impl->fd < 0) return;
    trace_writer_fd_registry_lock();
    trace_writer_fd_unregister_locked(impl->fd_registry_slot, impl->fd);
    impl->fd_registry_slot = kInvalidTraceWriterFdSlot;
    if (impl->backend->close_file(impl->fd) != 0) {
        int close_error = errno == 0 ? EIO : errno;
        latch_failure(impl, close_error);
    }
    trace_writer_fd_registry_unlock();
    impl->fd = -1;
}

void release_consumer_resources(AsyncTraceWriterImpl *impl) noexcept {
    if (impl->resources_released) return;
    if (impl->compression_context != nullptr) {
        LZ4F_freeCompressionContext(impl->compression_context);
        impl->compression_context = nullptr;
    }
    release_mappings(impl);
    close_backend(impl);
    impl->resources_released = true;
}

void set_failure_locked(AsyncTraceWriterImpl *impl, int error_code) noexcept {
    if (error_code == 0) error_code = EIO;
    latch_failure(impl, error_code);
    for (auto &buffer : impl->buffers) buffer.state = BufferState::Free;
    pthread_cond_broadcast(&impl->free_changed);
    pthread_cond_broadcast(&impl->ready_changed);
}

void set_failure(AsyncTraceWriterImpl *impl, int error_code) noexcept {
    pthread_mutex_lock(&impl->mutex);
    set_failure_locked(impl, error_code);
    pthread_mutex_unlock(&impl->mutex);
}

bool write_all(AsyncTraceWriterImpl *impl, const char *data, size_t size,
               FailurePoint point = FailurePoint::None) noexcept {
    if (!impl->first_write_attempted) {
        impl->first_write_attempted = true;
        const int injected = impl->faults->failure(FailurePoint::FirstWrite);
        if (injected != 0) {
            errno = injected;
            return false;
        }
    }
    if (point != FailurePoint::None) {
        const int injected = impl->faults->failure(point);
        if (injected != 0) {
            errno = injected;
            return false;
        }
    }
    size_t written = 0;
    while (written < size) {
        const ssize_t result = impl->backend->write_file(impl->fd, data + written, size - written);
        if (result < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (result == 0) {
            errno = EIO;
            return false;
        }
        written += static_cast<size_t>(result);
        impl->compressed_bytes.fetch_add(static_cast<uint64_t>(result),
                                         std::memory_order_relaxed);
    }
    return true;
}

bool write_frame(AsyncTraceWriterImpl *impl, const char *data, size_t size) noexcept {
    impl->preferences.frameInfo.contentSize = static_cast<unsigned long long>(size);
    const int compression_error = impl->faults->failure(FailurePoint::Compression);
    if (compression_error != 0 || impl->faults->fail_lz4_operation()) {
        errno = compression_error != 0 ? compression_error : EIO;
        return false;
    }

    size_t produced = LZ4F_compressBegin(impl->compression_context, impl->compression_scratch,
                                         impl->compression_scratch_bytes, &impl->preferences);
    if (LZ4F_isError(produced) ||
        !write_all(impl, impl->compression_scratch, produced)) {
        if (errno == 0) errno = EIO;
        return false;
    }

    size_t offset = 0;
    while (offset < size) {
        const size_t input_bytes = std::min(kCompressionChunkBytes, size - offset);
        produced = LZ4F_compressUpdate(impl->compression_context, impl->compression_scratch,
                                       impl->compression_scratch_bytes, data + offset, input_bytes,
                                       nullptr);
        if (LZ4F_isError(produced) ||
            (produced != 0 && !write_all(impl, impl->compression_scratch, produced))) {
            if (errno == 0) errno = EIO;
            return false;
        }
        offset += input_bytes;
    }

    produced = LZ4F_compressEnd(impl->compression_context, impl->compression_scratch,
                                impl->compression_scratch_bytes, nullptr);
    if (LZ4F_isError(produced) ||
        !write_all(impl, impl->compression_scratch, produced, FailurePoint::FinalWrite)) {
        if (errno == 0) errno = EIO;
        return false;
    }
    return true;
}

bool measure_frame(AsyncTraceWriterImpl *impl, const char *data, size_t size,
                   uint64_t *measured) noexcept {
    if (measured == nullptr || impl->compression_context == nullptr ||
        impl->compression_scratch == nullptr) {
        errno = EINVAL;
        return false;
    }
    impl->preferences.frameInfo.contentSize = static_cast<unsigned long long>(size);
    uint64_t total = 0;
    size_t produced = LZ4F_compressBegin(impl->compression_context, impl->compression_scratch,
                                         impl->compression_scratch_bytes, &impl->preferences);
    if (LZ4F_isError(produced)) {
        errno = EIO;
        return false;
    }
    total += produced;
    size_t offset = 0;
    while (offset < size) {
        const size_t input_bytes = std::min(kCompressionChunkBytes, size - offset);
        produced = LZ4F_compressUpdate(impl->compression_context, impl->compression_scratch,
                                       impl->compression_scratch_bytes, data + offset, input_bytes,
                                       nullptr);
        if (LZ4F_isError(produced) || total > UINT64_MAX - produced) {
            errno = EIO;
            return false;
        }
        total += produced;
        offset += input_bytes;
    }
    produced = LZ4F_compressEnd(impl->compression_context, impl->compression_scratch,
                                impl->compression_scratch_bytes, nullptr);
    if (LZ4F_isError(produced) || total > UINT64_MAX - produced) {
        errno = EIO;
        return false;
    }
    *measured = total + produced;
    return true;
}

void *consumer_entry(void *argument) noexcept {
    auto *impl = static_cast<AsyncTraceWriterImpl *>(argument);
    TraceFaultInjector *faults = impl->faults;
    for (;;) {
        pthread_mutex_lock(&impl->mutex);
        int ready_index = -1;
        while (impl->error.load(std::memory_order_acquire) == 0 && ready_index < 0) {
            for (int index = 0; index < 2; ++index) {
                if (impl->buffers[index].state == BufferState::Ready &&
                    (ready_index < 0 ||
                     impl->buffers[index].publication_sequence <
                         impl->buffers[ready_index].publication_sequence)) {
                    ready_index = index;
                }
            }
            if (ready_index >= 0 || impl->producer_done) break;
            pthread_cond_wait(&impl->ready_changed, &impl->mutex);
        }

        if (impl->error.load(std::memory_order_acquire) != 0 || ready_index < 0) {
            pthread_mutex_unlock(&impl->mutex);
            break;
        }

        auto &buffer = impl->buffers[ready_index];
        buffer.state = BufferState::Writing;
        char *data = buffer.data;
        const size_t size = buffer.used;
        pthread_mutex_unlock(&impl->mutex);

        const bool ok = impl->preferences.compressionLevel == INT_MIN
                            ? write_all(impl, data, size)
                            : write_frame(impl, data, size);
        const int operation_error = errno == 0 ? EIO : errno;

        pthread_mutex_lock(&impl->mutex);
        buffer.used = 0;
        buffer.state = BufferState::Free;
        if (!ok) {
            set_failure_locked(impl, operation_error);
            pthread_mutex_unlock(&impl->mutex);
            break;
        }
        pthread_cond_broadcast(&impl->free_changed);
        pthread_mutex_unlock(&impl->mutex);
        faults->consumer_released_buffer();
    }
    faults->consumer_thread_exited();
    impl->consumer_exited.store(true, std::memory_order_release);
    return nullptr;
}

bool allocate_buffers(AsyncTraceWriterImpl *impl, size_t selected_bytes) noexcept {
    const int injected = impl->faults->failure(FailurePoint::Allocation);
    if (injected != 0) {
        errno = injected;
        return false;
    }
    size_t candidates[4] = {selected_bytes, kFallbackBufferBytes[0], kFallbackBufferBytes[1],
                            kFallbackBufferBytes[2]};
    for (size_t candidate_index = 0; candidate_index < 4; ++candidate_index) {
        const size_t capacity = candidates[candidate_index];
        if (capacity == 0) continue;
        bool duplicate = false;
        for (size_t previous = 0; previous < candidate_index; ++previous) {
            if (candidates[previous] == capacity) duplicate = true;
        }
        if (duplicate || impl->faults->fail_buffer_allocation(capacity)) continue;

        void *first = mmap(nullptr, capacity, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (first == MAP_FAILED) continue;
        void *second = mmap(nullptr, capacity, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (second == MAP_FAILED) {
            munmap(first, capacity);
            continue;
        }

        impl->buffer_bytes = capacity;
        impl->buffers[0].data = static_cast<char *>(first);
        impl->buffers[0].state = BufferState::Filling;
        impl->buffers[1].data = static_cast<char *>(second);
        impl->buffers[1].state = BufferState::Free;
        impl->active_buffer = 0;
        return true;
    }
    errno = ENOMEM;
    return false;
}

bool allocate_compression(AsyncTraceWriterImpl *impl, const TraceOptions &options) noexcept {
    if (!options.compression_enabled) {
        impl->preferences.compressionLevel = INT_MIN;
        return true;
    }

    const int injected = impl->faults->failure(FailurePoint::CompressionAllocation);
    if (injected != 0) {
        errno = injected;
        return false;
    }

    impl->preferences = {};
    impl->preferences.compressionLevel = options.lz4_level;
    impl->preferences.frameInfo.contentSize = 1;
    const size_t update_bound = LZ4F_compressBound(kCompressionChunkBytes, &impl->preferences);
    const size_t end_bound = LZ4F_compressBound(0, &impl->preferences);
    const size_t scratch_bytes = std::max({update_bound, end_bound,
                                           static_cast<size_t>(LZ4F_HEADER_SIZE_MAX)});
    if (LZ4F_isError(scratch_bytes) || scratch_bytes == 0 ||
        impl->faults->fail_compression_allocation(scratch_bytes)) {
        errno = ENOMEM;
        return false;
    }
    void *scratch = mmap(nullptr, scratch_bytes, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (scratch == MAP_FAILED) return false;
    impl->compression_scratch = static_cast<char *>(scratch);
    impl->compression_scratch_bytes = scratch_bytes;

    const size_t create_result =
        LZ4F_createCompressionContext(&impl->compression_context, LZ4F_VERSION);
    if (LZ4F_isError(create_result)) {
        errno = ENOMEM;
        return false;
    }
    return true;
}

bool publish_and_acquire(AsyncTraceWriterImpl *impl) noexcept {
    pthread_mutex_lock(&impl->mutex);
    if (impl->error.load(std::memory_order_acquire) != 0 || impl->active_buffer < 0) {
        pthread_mutex_unlock(&impl->mutex);
        return false;
    }

    auto &published = impl->buffers[impl->active_buffer];
    published.publication_sequence = impl->next_publication_sequence++;
    published.state = BufferState::Ready;
    if (impl->metrics != nullptr) ++impl->metrics->buffer_swaps;
    impl->active_buffer = -1;
    pthread_cond_signal(&impl->ready_changed);

    uint64_t wait_started = 0;
    bool counted_wait = false;
    for (;;) {
        if (impl->error.load(std::memory_order_acquire) != 0) {
            if (counted_wait && impl->metrics != nullptr) {
                const uint64_t wait_ended = monotonic_nanoseconds();
                if (wait_ended >= wait_started) {
                    impl->metrics->producer_wait_ns += wait_ended - wait_started;
                }
            }
            pthread_mutex_unlock(&impl->mutex);
            return false;
        }
        for (int index = 0; index < 2; ++index) {
            if (impl->buffers[index].state == BufferState::Free) {
                impl->buffers[index].used = 0;
                impl->buffers[index].state = BufferState::Filling;
                impl->active_buffer = index;
                if (counted_wait && impl->metrics != nullptr) {
                    const uint64_t wait_ended = monotonic_nanoseconds();
                    if (wait_ended >= wait_started) {
                        impl->metrics->producer_wait_ns += wait_ended - wait_started;
                    }
                }
                pthread_mutex_unlock(&impl->mutex);
                return true;
            }
        }
        if (!counted_wait) {
            counted_wait = true;
            wait_started = monotonic_nanoseconds();
            if (impl->metrics != nullptr) ++impl->metrics->producer_waits;
        }
        impl->faults->producer_waiting();
        pthread_cond_wait(&impl->free_changed, &impl->mutex);
    }
}

} // namespace

AsyncTraceWriter::AsyncTraceWriter(TraceWriterBackend *backend, TraceFaultInjector *faults) noexcept
    : impl_(new (std::nothrow) AsyncTraceWriterImpl(backend, faults)) {}

AsyncTraceWriter::~AsyncTraceWriter() {
    if (impl_ != nullptr) {
        if (trace_process_child_detached() ||
            (impl_->owner_pid > 0 && impl_->owner_pid != ::getpid())) {
            detach_after_fork_child();
            return;
        }
        if (impl_->opened && !impl_->finish_called) finish();
        if (impl_->consumer_started) {
            const int retry_result =
                impl_->faults->join_consumer_thread(impl_->consumer_thread, nullptr);
            if (retry_result != 0) {
                // A second unjoinable result still cannot let caller-owned seams or metrics die
                // under the consumer. Wait only for its terminal ownership publication, then
                // retain the complete implementation rather than risking resource UAF.
                while (!impl_->consumer_exited.load(std::memory_order_acquire)) {
                    timespec pause{0, 1000000};
                    while (nanosleep(&pause, &pause) != 0 && errno == EINTR) {}
                }
                impl_ = nullptr;
                return;
            }
            impl_->consumer_started = false;
            release_consumer_resources(impl_);
        }
        delete impl_;
    }
}

bool AsyncTraceWriter::open(std::string_view path, const TraceOptions &options,
                            TraceMetrics *metrics) {
    if (trace_process_child_detached()) {
        if (impl_ != nullptr) {
            latch_failure(impl_, ECHILD);
            impl_->finish_called = true;
        }
        return false;
    }
    if (!install_trace_process_lifecycle()) {
        if (impl_ != nullptr) {
            latch_failure(impl_, trace_process_lifecycle_error());
            impl_->finish_called = true;
        }
        return false;
    }
    if (impl_ == nullptr || impl_->opened || impl_->finish_called || metrics == nullptr ||
        path.empty()) {
        return false;
    }
    if (impl_->synchronization_error != 0) {
        latch_failure(impl_, impl_->synchronization_error);
        impl_->finish_called = true;
        return false;
    }

    constexpr size_t kMaxOpenPathBytes = 4095;
    if (path.size() > kMaxOpenPathBytes) {
        latch_failure(impl_, ENAMETOOLONG);
        impl_->finish_called = true;
        return false;
    }
    char open_path[kMaxOpenPathBytes + 1];
    std::memcpy(open_path, path.data(), path.size());
    open_path[path.size()] = '\0';

    impl_->metrics = metrics;
    impl_->compressed_bytes.store(0, std::memory_order_relaxed);
    impl_->owner_pid = ::getpid();
    trace_writer_fd_registry_lock();
    impl_->fd = impl_->backend->open_file(
            open_path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0644);
    if (impl_->fd >= 0) {
        impl_->fd_registry_slot = trace_writer_fd_register_locked(impl_->fd);
        if (impl_->fd_registry_slot == kInvalidTraceWriterFdSlot) {
            (void)impl_->backend->close_file(impl_->fd);
            impl_->fd = -1;
            errno = EMFILE;
        }
    }
    trace_writer_fd_registry_unlock();
    if (impl_->fd < 0) {
        latch_failure(impl_, errno == 0 ? EIO : errno);
        impl_->finish_called = true;
        return false;
    }

    const size_t selected = choose_trace_buffer_bytes(physical_memory_bytes(), options.buffer_bytes,
                                                      options.auto_buffer_size);
    if (!allocate_buffers(impl_, selected) || !allocate_compression(impl_, options)) {
        latch_failure(impl_, errno == 0 ? ENOMEM : errno);
        if (impl_->compression_context != nullptr) {
            LZ4F_freeCompressionContext(impl_->compression_context);
            impl_->compression_context = nullptr;
        }
        release_mappings(impl_);
        close_backend(impl_);
        impl_->finish_called = true;
        return false;
    }

    const int injected_thread_error = impl_->faults->failure(FailurePoint::ThreadCreation);
    const int thread_result = injected_thread_error != 0
                                      ? injected_thread_error
                                      : impl_->faults->create_consumer_thread(
                                                &impl_->consumer_thread, consumer_entry, impl_);
    if (thread_result != 0) {
        latch_failure(impl_, thread_result);
        if (impl_->compression_context != nullptr) {
            LZ4F_freeCompressionContext(impl_->compression_context);
            impl_->compression_context = nullptr;
        }
        release_mappings(impl_);
        close_backend(impl_);
        impl_->finish_called = true;
        return false;
    }

    impl_->consumer_started = true;
    impl_->opened = true;
    return true;
}

void AsyncTraceWriter::detach_after_fork_child() noexcept {
    if (impl_ == nullptr) return;
    impl_ = nullptr;
}

WritableSpan AsyncTraceWriter::reserve(size_t minimum) {
    if (impl_ == nullptr || !impl_->opened || impl_->finish_called || minimum == 0 ||
        impl_->reservation_active || impl_->error.load(std::memory_order_acquire) != 0 ||
        minimum > impl_->buffer_bytes || impl_->active_buffer < 0) {
        return {};
    }

    auto *buffer = &impl_->buffers[impl_->active_buffer];
    size_t remaining = impl_->buffer_bytes - buffer->used;
    if (remaining < minimum) {
        if (!publish_and_acquire(impl_)) return {};
        buffer = &impl_->buffers[impl_->active_buffer];
        remaining = impl_->buffer_bytes;
    }

    impl_->reservation_active = true;
    impl_->reservation_capacity = remaining;
    return {buffer->data + buffer->used, remaining};
}

void AsyncTraceWriter::commit(size_t bytes) {
    if (impl_ == nullptr || !impl_->opened || impl_->finish_called ||
        !impl_->reservation_active || bytes > impl_->reservation_capacity ||
        impl_->active_buffer < 0) {
        if (impl_ != nullptr && impl_->opened && !impl_->finish_called) set_failure(impl_, EINVAL);
        return;
    }

    impl_->buffers[impl_->active_buffer].used += bytes;
    if (impl_->metrics != nullptr) impl_->metrics->encoded_bytes += bytes;
    impl_->reservation_active = false;
    impl_->reservation_capacity = 0;
}

bool AsyncTraceWriter::append(std::string_view bytes) {
    if (impl_ == nullptr || !impl_->opened || impl_->finish_called ||
        impl_->error.load(std::memory_order_acquire) != 0) {
        return false;
    }
    size_t offset = 0;
    while (offset < bytes.size()) {
        WritableSpan span = reserve(1);
        if (span.data == nullptr) return false;
        const size_t chunk = std::min(span.capacity, bytes.size() - offset);
        std::memcpy(span.data, bytes.data() + offset, chunk);
        commit(chunk);
        if (impl_->error.load(std::memory_order_acquire) != 0) return false;
        offset += chunk;
    }
    return true;
}

bool AsyncTraceWriter::drain() {
    if (impl_ == nullptr || !impl_->opened || impl_->finish_called ||
        impl_->reservation_active || impl_->active_buffer < 0 ||
        impl_->error.load(std::memory_order_acquire) != 0) {
        return false;
    }

    pthread_mutex_lock(&impl_->mutex);
    auto &active = impl_->buffers[impl_->active_buffer];
    if (active.used != 0) {
        active.publication_sequence = impl_->next_publication_sequence++;
        active.state = BufferState::Ready;
        if (impl_->metrics != nullptr) ++impl_->metrics->buffer_swaps;
        pthread_cond_signal(&impl_->ready_changed);
    } else {
        active.state = BufferState::Free;
    }
    impl_->active_buffer = -1;

    bool counted_wait = false;
    uint64_t wait_started = 0;
    for (;;) {
        if (impl_->error.load(std::memory_order_acquire) != 0) {
            if (counted_wait && impl_->metrics != nullptr) {
                const uint64_t ended = monotonic_nanoseconds();
                if (ended >= wait_started) impl_->metrics->producer_wait_ns += ended - wait_started;
            }
            pthread_mutex_unlock(&impl_->mutex);
            return false;
        }
        bool all_free = true;
        for (const auto &buffer : impl_->buffers) {
            if (buffer.state != BufferState::Free) all_free = false;
        }
        if (all_free) break;
        if (!counted_wait) {
            counted_wait = true;
            wait_started = monotonic_nanoseconds();
            if (impl_->metrics != nullptr) ++impl_->metrics->producer_waits;
        }
        impl_->faults->producer_waiting();
        pthread_cond_wait(&impl_->free_changed, &impl_->mutex);
    }
    if (counted_wait && impl_->metrics != nullptr) {
        const uint64_t ended = monotonic_nanoseconds();
        if (ended >= wait_started) impl_->metrics->producer_wait_ns += ended - wait_started;
    }
    impl_->buffers[0].used = 0;
    impl_->buffers[0].state = BufferState::Filling;
    impl_->active_buffer = 0;
    pthread_mutex_unlock(&impl_->mutex);
    return true;
}

bool AsyncTraceWriter::projected_file_bytes(std::string_view final_record, uint64_t *bytes) {
    if (impl_ == nullptr || bytes == nullptr || final_record.empty() || !impl_->opened ||
        impl_->finish_called || impl_->reservation_active || impl_->active_buffer < 0 ||
        impl_->buffers[impl_->active_buffer].used != 0 ||
        impl_->error.load(std::memory_order_acquire) != 0) {
        return false;
    }
    for (int index = 0; index < 2; ++index) {
        if (index != impl_->active_buffer && impl_->buffers[index].state != BufferState::Free)
            return false;
    }
    const uint64_t prefix = impl_->compressed_bytes.load(std::memory_order_acquire);
    uint64_t final_bytes = final_record.size();
    if (impl_->preferences.compressionLevel != INT_MIN &&
        !measure_frame(impl_, final_record.data(), final_record.size(), &final_bytes)) {
        latch_failure(impl_, errno == 0 ? EIO : errno);
        return false;
    }
    if (prefix > UINT64_MAX - final_bytes) {
        latch_failure(impl_, EOVERFLOW);
        return false;
    }
    *bytes = prefix + final_bytes;
    return true;
}

bool AsyncTraceWriter::finish() {
    if (impl_ == nullptr) return false;
    if (impl_->finish_called) return impl_->finish_result;
    if (!impl_->opened) return false;

    if (impl_->reservation_active) set_failure(impl_, EINVAL);

    pthread_mutex_lock(&impl_->mutex);
    if (impl_->error.load(std::memory_order_acquire) == 0 && impl_->active_buffer >= 0) {
        auto &active = impl_->buffers[impl_->active_buffer];
        if (active.used != 0) {
            active.publication_sequence = impl_->next_publication_sequence++;
            active.state = BufferState::Ready;
            if (impl_->metrics != nullptr) ++impl_->metrics->buffer_swaps;
        } else {
            active.state = BufferState::Free;
        }
    }
    impl_->active_buffer = -1;
    impl_->producer_done = true;
    pthread_cond_broadcast(&impl_->ready_changed);
    pthread_cond_broadcast(&impl_->free_changed);
    pthread_mutex_unlock(&impl_->mutex);

    if (impl_->consumer_started) {
        const int join_result =
            impl_->faults->join_consumer_thread(impl_->consumer_thread, nullptr);
        if (join_result == 0) {
            impl_->consumer_started = false;
        } else {
            impl_->join_error = join_result;
            int expected = 0;
            impl_->error.compare_exchange_strong(expected, join_result, std::memory_order_release,
                                                 std::memory_order_relaxed);
            impl_->opened = false;
            impl_->finish_called = true;
            impl_->finish_result = false;
            return false;
        }
    }
    release_consumer_resources(impl_);

    if (impl_->metrics != nullptr) {
        impl_->metrics->compressed_bytes =
                impl_->compressed_bytes.load(std::memory_order_acquire);
    }

    impl_->opened = false;
    impl_->finish_called = true;
    impl_->finish_result = impl_->error.load(std::memory_order_acquire) == 0;
    return impl_->finish_result;
}

bool AsyncTraceWriter::failed() const {
    return impl_ == nullptr || impl_->error.load(std::memory_order_acquire) != 0;
}

int AsyncTraceWriter::error_code() const noexcept {
    return impl_ == nullptr ? ENOMEM : impl_->error.load(std::memory_order_acquire);
}

size_t AsyncTraceWriter::buffer_bytes() const noexcept {
    return impl_ != nullptr && impl_->opened && !impl_->finish_called ? impl_->buffer_bytes : 0;
}
