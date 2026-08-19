#include "events/async_trace_writer.h"

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

bool TraceFaultInjector::fail_compression_allocation(size_t) noexcept {
    return false;
}

int TraceFaultInjector::create_consumer_thread(pthread_t *thread, void *(*entry)(void *),
                                               void *argument) noexcept {
    return pthread_create(thread, nullptr, entry, argument);
}

bool TraceFaultInjector::fail_lz4_operation() noexcept {
    return false;
}

void TraceFaultInjector::producer_waiting() noexcept {}

void TraceFaultInjector::consumer_released_buffer() noexcept {}

size_t choose_trace_buffer_bytes(uint64_t physical_bytes, size_t requested_bytes,
                                 bool auto_size) noexcept {
    if (!auto_size) return requested_bytes;
    if (physical_bytes == 0) return 64ULL * kMiB;

    uint64_t selected = physical_bytes / 64;
    selected = std::max<uint64_t>(selected, 8ULL * kMiB);
    selected = std::min<uint64_t>(selected, 128ULL * kMiB);
    selected -= selected % kMiB;
    return static_cast<size_t>(selected);
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
    pthread_t consumer_thread{};
    bool consumer_started = false;
    bool opened = false;
    bool producer_done = false;
    bool finish_called = false;
    bool finish_result = false;
    int active_buffer = -1;
    bool reservation_active = false;
    size_t reservation_capacity = 0;
    uint64_t next_publication_sequence = 1;
    std::atomic<int> error{0};
    int synchronization_error = 0;
    bool mutex_initialized = false;
    bool ready_changed_initialized = false;
    bool free_changed_initialized = false;
    pthread_mutex_t mutex{};
    pthread_cond_t ready_changed{};
    pthread_cond_t free_changed{};
};

namespace {

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
    if (impl->backend->close_file(impl->fd) != 0) {
        int close_error = errno == 0 ? EIO : errno;
        int expected = 0;
        impl->error.compare_exchange_strong(expected, close_error, std::memory_order_relaxed);
    }
    impl->fd = -1;
}

void set_failure_locked(AsyncTraceWriterImpl *impl, int error_code) noexcept {
    if (error_code == 0) error_code = EIO;
    int expected = 0;
    impl->error.compare_exchange_strong(expected, error_code, std::memory_order_release,
                                        std::memory_order_relaxed);
    for (auto &buffer : impl->buffers) buffer.state = BufferState::Free;
    pthread_cond_broadcast(&impl->free_changed);
    pthread_cond_broadcast(&impl->ready_changed);
}

void set_failure(AsyncTraceWriterImpl *impl, int error_code) noexcept {
    pthread_mutex_lock(&impl->mutex);
    set_failure_locked(impl, error_code);
    pthread_mutex_unlock(&impl->mutex);
}

bool write_all(AsyncTraceWriterImpl *impl, const char *data, size_t size) noexcept {
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
        if (impl->metrics != nullptr) {
            impl->metrics->compressed_bytes += static_cast<uint64_t>(result);
        }
    }
    return true;
}

bool write_frame(AsyncTraceWriterImpl *impl, const char *data, size_t size) noexcept {
    impl->preferences.frameInfo.contentSize = static_cast<unsigned long long>(size);
    if (impl->faults->fail_lz4_operation()) {
        errno = EIO;
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
        !write_all(impl, impl->compression_scratch, produced)) {
        if (errno == 0) errno = EIO;
        return false;
    }
    return true;
}

void *consumer_entry(void *argument) noexcept {
    auto *impl = static_cast<AsyncTraceWriterImpl *>(argument);
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
        impl->faults->consumer_released_buffer();
    }
    return nullptr;
}

bool allocate_buffers(AsyncTraceWriterImpl *impl, size_t selected_bytes) noexcept {
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
        if (impl_->opened && !impl_->finish_called) finish();
        delete impl_;
    }
}

bool AsyncTraceWriter::open(const std::string &path, const TraceOptions &options,
                            TraceMetrics *metrics) {
    if (impl_ == nullptr || impl_->opened || impl_->finish_called || metrics == nullptr ||
        path.empty()) {
        return false;
    }
    if (impl_->synchronization_error != 0) {
        impl_->error.store(impl_->synchronization_error, std::memory_order_release);
        impl_->finish_called = true;
        return false;
    }

    impl_->metrics = metrics;
    impl_->fd = impl_->backend->open_file(path.c_str(), O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC,
                                         0644);
    if (impl_->fd < 0) {
        impl_->error.store(errno == 0 ? EIO : errno, std::memory_order_release);
        impl_->finish_called = true;
        return false;
    }

    const size_t selected = choose_trace_buffer_bytes(physical_memory_bytes(), options.buffer_bytes,
                                                      options.auto_buffer_size);
    if (!allocate_buffers(impl_, selected) || !allocate_compression(impl_, options)) {
        impl_->error.store(errno == 0 ? ENOMEM : errno, std::memory_order_release);
        if (impl_->compression_context != nullptr) {
            LZ4F_freeCompressionContext(impl_->compression_context);
            impl_->compression_context = nullptr;
        }
        release_mappings(impl_);
        close_backend(impl_);
        impl_->finish_called = true;
        return false;
    }

    const int thread_result = impl_->faults->create_consumer_thread(
        &impl_->consumer_thread, consumer_entry, impl_);
    if (thread_result != 0) {
        impl_->error.store(thread_result, std::memory_order_release);
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
    if (impl_->metrics != nullptr) impl_->metrics->raw_bytes += bytes;
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
        pthread_join(impl_->consumer_thread, nullptr);
        impl_->consumer_started = false;
    }
    if (impl_->compression_context != nullptr) {
        LZ4F_freeCompressionContext(impl_->compression_context);
        impl_->compression_context = nullptr;
    }
    release_mappings(impl_);
    close_backend(impl_);

    impl_->opened = false;
    impl_->finish_called = true;
    impl_->finish_result = impl_->error.load(std::memory_order_acquire) == 0;
    return impl_->finish_result;
}

bool AsyncTraceWriter::failed() const {
    return impl_ == nullptr || impl_->error.load(std::memory_order_acquire) != 0;
}
