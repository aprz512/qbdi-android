#include "flight/flight_artifact.h"

#include <bit>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {

static_assert(std::atomic_ref<uint32_t>::is_always_lock_free,
              "persistent publication requires lock-free 32-bit atomics");
constexpr size_t kFlightAtomicU32Alignment =
        std::atomic_ref<uint32_t>::required_alignment;
static_assert(kFlightSuperblockBytes % kFlightAtomicU32Alignment == 0);
static_assert(kFlightDirectoryEntryBytes % kFlightAtomicU32Alignment == 0);
static_assert(kFlightChunkHeaderBytes % kFlightAtomicU32Alignment == 0);
static_assert(kFlightRecordHeaderBytes % kFlightAtomicU32Alignment == 0);
static_assert(kFlightEmergencyRecordBytes % kFlightAtomicU32Alignment == 0);
static_assert(72U % kFlightAtomicU32Alignment == 0);
static_assert(20U % kFlightAtomicU32Alignment == 0);
static_assert(48U % kFlightAtomicU32Alignment == 0);

constexpr size_t kSuperblockFlagsOffset = 72;
constexpr size_t kDirectoryTidOffset = 0;
constexpr size_t kDirectoryStateOffset = 4;
constexpr size_t kDirectoryFirstSequenceOffset = 8;
constexpr size_t kDirectoryLastSequenceOffset = 16;
constexpr size_t kDirectoryChunkIndexOffset = 24;
constexpr size_t kDirectoryChunkGenerationOffset = 28;
constexpr size_t kChunkStateOffset = 12;
constexpr size_t kChunkTidOffset = 16;
constexpr size_t kChunkGenerationOffset = 20;
constexpr size_t kEmergencyFlagsOffset = 48;
constexpr size_t kEmergencyChecksumOffset = 52;
constexpr size_t kEmergencyChecksumInverseOffset = 56;
constexpr size_t kEmergencyVersionOffset = 60;
constexpr uint32_t kEmergencyChecksumOffsetBasis = 2166136261U;
constexpr uint32_t kEmergencyChecksumPrime = 16777619U;

uint32_t byte_swap_u32(uint32_t value) noexcept {
    return ((value & 0x000000ffU) << 24U) | ((value & 0x0000ff00U) << 8U) |
           ((value & 0x00ff0000U) >> 8U) | ((value & 0xff000000U) >> 24U);
}

uint32_t flight_u32_from_le(uint32_t value) noexcept {
    if constexpr (std::endian::native == std::endian::little) return value;
    return byte_swap_u32(value);
}

bool checked_add_u64(uint64_t left, uint64_t right, uint64_t *result) noexcept {
    if (result == nullptr || right > UINT64_MAX - left) return false;
    *result = left + right;
    return true;
}

bool checked_multiply_u64(uint64_t left, uint64_t right, uint64_t *result) noexcept {
    if (result == nullptr || (left != 0 && right > UINT64_MAX / left)) return false;
    *result = left * right;
    return true;
}

bool checked_align_u64(uint64_t value, uint64_t alignment, uint64_t *result) noexcept {
    if (alignment == 0 || (alignment & (alignment - 1U)) != 0) return false;
    const uint64_t mask = alignment - 1U;
    if (value > UINT64_MAX - mask) return false;
    *result = (value + mask) & ~mask;
    return true;
}

bool power_of_two(uint32_t value) noexcept {
    return value != 0 && (value & (value - 1U)) == 0;
}

bool valid_registration(const FlightThreadRegistration &registration,
                        uint32_t maximum) noexcept {
    return registration.tid != 0 && registration.directory_index < maximum;
}

uint32_t emergency_checksum(const FlightEmergencyRecord &record) noexcept {
    uint8_t encoded[52]{};
    flight_write_u32_le(encoded + 0, record.type);
    flight_write_u32_le(encoded + 4, record.tid);
    flight_write_u64_le(encoded + 8, record.sequence);
    flight_write_u64_le(encoded + 16, record.pc);
    flight_write_u64_le(encoded + 24, record.sp);
    flight_write_u64_le(encoded + 32, record.fault_address);
    flight_write_u32_le(encoded + 40, record.signal_number);
    flight_write_u32_le(encoded + 44, record.signal_code);
    flight_write_u32_le(encoded + 48, record.flags);
    uint32_t checksum = kEmergencyChecksumOffsetBasis;
    for (uint8_t byte : encoded) {
        checksum ^= byte;
        checksum *= kEmergencyChecksumPrime;
    }
    return checksum;
}

} // namespace

struct FlightArtifact::RuntimeChunkMetadata {
    uint64_t epoch;
    uint32_t next_protected;
    uint32_t protected_chunk;
};

struct FlightArtifact::RuntimeThreadMetadata {
    uint32_t newest_protected;
    uint32_t oldest_protected;
    uint32_t protected_count;
};

struct FlightArtifact::RuntimeEmergencyMetadata {
    uint32_t claim;
    uint32_t next_version;
};

uint32_t flight_u32_to_le(uint32_t value) noexcept {
    if constexpr (std::endian::native == std::endian::little) return value;
    return byte_swap_u32(value);
}

bool flight_atomic_u32_aligned(const uint8_t *address) noexcept {
    return address != nullptr &&
           reinterpret_cast<uintptr_t>(address) % kFlightAtomicU32Alignment == 0;
}

void flight_atomic_store_u32_le(uint8_t *destination, uint32_t value,
                                std::memory_order order) noexcept {
    if (!flight_atomic_u32_aligned(destination)) return;
    auto &native = *reinterpret_cast<uint32_t *>(destination);
    std::atomic_ref<uint32_t>(native).store(flight_u32_to_le(value), order);
}

uint32_t flight_atomic_load_u32_le(const uint8_t *source,
                                   std::memory_order order) noexcept {
    if (!flight_atomic_u32_aligned(source)) return 0;
    auto &native = *const_cast<uint32_t *>(reinterpret_cast<const uint32_t *>(source));
    return flight_u32_from_le(std::atomic_ref<uint32_t>(native).load(order));
}

uint32_t flight_atomic_fetch_or_u32_le(uint8_t *destination, uint32_t value,
                                       std::memory_order order) noexcept {
    if (!flight_atomic_u32_aligned(destination)) return 0;
    auto &native = *reinterpret_cast<uint32_t *>(destination);
    const uint32_t previous =
            std::atomic_ref<uint32_t>(native).fetch_or(flight_u32_to_le(value), order);
    return flight_u32_from_le(previous);
}

bool scan_flight_emergency(const uint8_t *bytes,
                           FlightEmergencyRecord *record) noexcept {
    if (bytes == nullptr || record == nullptr ||
        !flight_atomic_u32_aligned(bytes + kEmergencyFlagsOffset) ||
        !flight_atomic_u32_aligned(bytes + kEmergencyVersionOffset)) {
        return false;
    }
    const uint32_t published_flags = flight_atomic_load_u32_le(
            bytes + kEmergencyFlagsOffset, std::memory_order_acquire);
    if ((published_flags & kFlightEmergencyCommitted) == 0) return false;
    const uint32_t first_version = flight_atomic_load_u32_le(
            bytes + kEmergencyVersionOffset, std::memory_order_acquire);
    if (first_version == 0 || (first_version & 1U) != 0) return false;

    FlightEmergencyRecord decoded{};
    decoded.type = flight_atomic_load_u32_le(bytes + 0, std::memory_order_relaxed);
    decoded.tid = flight_atomic_load_u32_le(bytes + 4, std::memory_order_relaxed);
    decoded.sequence = flight_atomic_load_u32_le(bytes + 8, std::memory_order_relaxed);
    decoded.sequence |= static_cast<uint64_t>(flight_atomic_load_u32_le(
                                bytes + 12, std::memory_order_relaxed)) << 32U;
    decoded.pc = flight_atomic_load_u32_le(bytes + 16, std::memory_order_relaxed);
    decoded.pc |= static_cast<uint64_t>(flight_atomic_load_u32_le(
                          bytes + 20, std::memory_order_relaxed)) << 32U;
    decoded.sp = flight_atomic_load_u32_le(bytes + 24, std::memory_order_relaxed);
    decoded.sp |= static_cast<uint64_t>(flight_atomic_load_u32_le(
                          bytes + 28, std::memory_order_relaxed)) << 32U;
    decoded.fault_address = flight_atomic_load_u32_le(bytes + 32,
                                                      std::memory_order_relaxed);
    decoded.fault_address |= static_cast<uint64_t>(flight_atomic_load_u32_le(
                                     bytes + 36, std::memory_order_relaxed)) << 32U;
    decoded.signal_number = flight_atomic_load_u32_le(bytes + 40,
                                                      std::memory_order_relaxed);
    decoded.signal_code = flight_atomic_load_u32_le(bytes + 44,
                                                    std::memory_order_relaxed);
    decoded.flags = published_flags & ~kFlightEmergencyCommitted;
    const uint32_t checksum = flight_atomic_load_u32_le(
            bytes + kEmergencyChecksumOffset, std::memory_order_relaxed);
    const uint32_t inverse = flight_atomic_load_u32_le(
            bytes + kEmergencyChecksumInverseOffset, std::memory_order_relaxed);
    const uint32_t final_version = flight_atomic_load_u32_le(
            bytes + kEmergencyVersionOffset, std::memory_order_acquire);
    const uint32_t final_flags = flight_atomic_load_u32_le(
            bytes + kEmergencyFlagsOffset, std::memory_order_acquire);
    if (first_version != final_version || published_flags != final_flags ||
        inverse != ~checksum || checksum != emergency_checksum(decoded)) {
        return false;
    }
    *record = decoded;
    return true;
}

FlightArtifact::~FlightArtifact() {
    close();
}

bool FlightArtifact::create(const char *path, const FlightOptions &options) noexcept {
    if (valid() || path == nullptr || path[0] == '\0' || options.capacity_bytes > SIZE_MAX ||
        options.capacity_bytes > static_cast<uint64_t>(std::numeric_limits<off_t>::max()) ||
        options.max_threads == 0 || options.max_threads == UINT32_MAX ||
        options.protected_chunks == 0 ||
        !power_of_two(options.chunk_bytes) || options.chunk_bytes <= kFlightChunkHeaderBytes) {
        errno = EINVAL;
        return false;
    }

    uint64_t directory_bytes = 0;
    uint64_t emergency_bytes = 0;
    uint64_t directory_end = 0;
    uint64_t emergency_offset = 0;
    uint64_t emergency_end = 0;
    uint64_t chunk_offset = 0;
    const uint64_t emergency_record_count =
            static_cast<uint64_t>(options.max_threads) + 1U;
    if (!checked_multiply_u64(options.max_threads, kFlightDirectoryEntryBytes,
                              &directory_bytes) ||
        !checked_multiply_u64(emergency_record_count, kFlightEmergencyRecordBytes,
                              &emergency_bytes) ||
        !checked_add_u64(kFlightSuperblockBytes, directory_bytes, &directory_end) ||
        !checked_align_u64(directory_end, kFlightEmergencyRecordBytes, &emergency_offset) ||
        !checked_add_u64(emergency_offset, emergency_bytes, &emergency_end) ||
        !checked_align_u64(emergency_end, options.chunk_bytes, &chunk_offset) ||
        chunk_offset >= options.capacity_bytes) {
        errno = EOVERFLOW;
        return false;
    }
    const uint64_t chunk_count_64 =
            (options.capacity_bytes - chunk_offset) / options.chunk_bytes;
    if (chunk_count_64 == 0 || chunk_count_64 > UINT32_MAX) {
        errno = EOVERFLOW;
        return false;
    }
    const uint32_t chunk_count = static_cast<uint32_t>(chunk_count_64);

    uint64_t chunk_metadata_bytes = 0;
    uint64_t thread_metadata_bytes = 0;
    uint64_t emergency_metadata_bytes = 0;
    uint64_t runtime_bytes = 0;
    if (!checked_multiply_u64(chunk_count, sizeof(RuntimeChunkMetadata),
                              &chunk_metadata_bytes) ||
        !checked_multiply_u64(options.max_threads, sizeof(RuntimeThreadMetadata),
                              &thread_metadata_bytes) ||
        !checked_multiply_u64(emergency_record_count, sizeof(RuntimeEmergencyMetadata),
                              &emergency_metadata_bytes) ||
        !checked_add_u64(chunk_metadata_bytes, thread_metadata_bytes, &runtime_bytes) ||
        !checked_add_u64(runtime_bytes, emergency_metadata_bytes, &runtime_bytes) ||
        runtime_bytes > SIZE_MAX) {
        errno = EOVERFLOW;
        return false;
    }

    const int descriptor = ::open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    if (descriptor == -1) return false;
    if (::fchmod(descriptor, 0600) != 0 ||
        ::ftruncate(descriptor, static_cast<off_t>(options.capacity_bytes)) != 0) {
        const int error = errno;
        (void)::close(descriptor);
        (void)::unlink(path);
        errno = error;
        return false;
    }
    void *mapped = ::mmap(nullptr, static_cast<size_t>(options.capacity_bytes),
                          PROT_READ | PROT_WRITE, MAP_SHARED, descriptor, 0);
    if (mapped == MAP_FAILED) {
        const int error = errno;
        (void)::close(descriptor);
        (void)::unlink(path);
        errno = error;
        return false;
    }
    void *runtime = ::mmap(nullptr, static_cast<size_t>(runtime_bytes),
                           PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (runtime == MAP_FAILED) {
        const int error = errno;
        (void)::munmap(mapped, static_cast<size_t>(options.capacity_bytes));
        (void)::close(descriptor);
        (void)::unlink(path);
        errno = error;
        return false;
    }

    fd_ = descriptor;
    mapping_ = static_cast<uint8_t *>(mapped);
    mapping_size_ = static_cast<size_t>(options.capacity_bytes);
    runtime_mapping_ = runtime;
    runtime_mapping_size_ = static_cast<size_t>(runtime_bytes);
    chunk_metadata_ = static_cast<RuntimeChunkMetadata *>(runtime);
    thread_metadata_ = reinterpret_cast<RuntimeThreadMetadata *>(
            static_cast<uint8_t *>(runtime) + chunk_metadata_bytes);
    emergency_metadata_ = reinterpret_cast<RuntimeEmergencyMetadata *>(
            static_cast<uint8_t *>(runtime) + chunk_metadata_bytes +
            thread_metadata_bytes);
    options_ = options;
    directory_offset_ = kFlightSuperblockBytes;
    emergency_offset_ = emergency_offset;
    emergency_record_count_ = static_cast<uint32_t>(emergency_record_count);
    chunk_offset_ = chunk_offset;
    chunk_count_ = chunk_count;
    allocation_epoch_ = 0;
    sequence_allocator_.reset();

    std::memset(runtime_mapping_, 0, runtime_mapping_size_);
    for (uint32_t index = 0; index < chunk_count_; ++index) {
        chunk_metadata_[index].next_protected = kFlightInvalidIndex;
    }
    for (uint32_t index = 0; index < options_.max_threads; ++index) {
        thread_metadata_[index].newest_protected = kFlightInvalidIndex;
        thread_metadata_[index].oldest_protected = kFlightInvalidIndex;
    }
    for (uint32_t index = 0; index < emergency_record_count_; ++index) {
        emergency_metadata_[index].next_version = 2;
    }

    FlightSuperblock superblock{};
    superblock.magic = 0;
    superblock.version = kFlightVersion;
    superblock.byte_order = kFlightByteOrderLittleEndian;
    superblock.pointer_width = sizeof(uintptr_t) == 4 ? kFlightPointerWidth32
                                                      : kFlightPointerWidth64;
    superblock.header_bytes = kFlightSuperblockBytes;
    superblock.artifact_bytes = options.capacity_bytes;
    superblock.directory_offset = directory_offset_;
    superblock.directory_entry_bytes = kFlightDirectoryEntryBytes;
    superblock.directory_entries = options.max_threads;
    superblock.chunk_offset = chunk_offset_;
    superblock.chunk_bytes = options.chunk_bytes;
    superblock.chunk_count = chunk_count_;
    superblock.emergency_offset = emergency_offset_;
    superblock.emergency_record_bytes = kFlightEmergencyRecordBytes;
    superblock.emergency_record_count = emergency_record_count_;
    superblock.flags = 0;
    if (!encode_flight_superblock_le(superblock, mapping_, kFlightSuperblockBytes)) {
        const int error = EINVAL;
        close();
        (void)::unlink(path);
        errno = error;
        return false;
    }
    flight_atomic_store_u32_le(mapping_, kFlightMagic, std::memory_order_release);
    return true;
}

void FlightArtifact::close() noexcept {
    if (runtime_mapping_ != nullptr) {
        (void)::munmap(runtime_mapping_, runtime_mapping_size_);
    }
    if (mapping_ != nullptr) (void)::munmap(mapping_, mapping_size_);
    if (fd_ != -1) (void)::close(fd_);
    reset_state();
}

void FlightArtifact::detach_after_fork_child() noexcept {
    close();
}

uint32_t FlightArtifact::chunk_data_capacity() const noexcept {
    return options_.chunk_bytes > kFlightChunkHeaderBytes
                   ? options_.chunk_bytes - kFlightChunkHeaderBytes
                   : 0;
}

bool FlightArtifact::register_thread(uint32_t tid,
                                     FlightThreadRegistration *registration) noexcept {
    if (!valid() || tid == 0 || registration == nullptr) {
        errno = EINVAL;
        return false;
    }
    for (uint32_t index = 0; index < options_.max_threads; ++index) {
        uint8_t *entry = directory_entry(index);
        auto &native_tid = *reinterpret_cast<uint32_t *>(entry + kDirectoryTidOffset);
        std::atomic_ref<uint32_t> atomic_tid(native_tid);
        uint32_t observed =
                flight_u32_from_le(atomic_tid.load(std::memory_order_acquire));
        if (observed == tid) {
            while (flight_atomic_load_u32_le(entry + kDirectoryStateOffset,
                                             std::memory_order_acquire) ==
                   static_cast<uint32_t>(FlightDirectoryState::Free)) {
            }
            *registration = {index, tid};
            return true;
        }
        if (observed != 0) continue;
        uint32_t expected = flight_u32_to_le(0);
        if (!atomic_tid.compare_exchange_strong(expected, flight_u32_to_le(tid),
                                                std::memory_order_acq_rel,
                                                std::memory_order_acquire)) {
            if (flight_u32_from_le(expected) == tid) {
                while (flight_atomic_load_u32_le(entry + kDirectoryStateOffset,
                                                 std::memory_order_acquire) ==
                       static_cast<uint32_t>(FlightDirectoryState::Free)) {
                }
                *registration = {index, tid};
                return true;
            }
            continue;
        }
        flight_write_u64_le(entry + kDirectoryFirstSequenceOffset, 0);
        flight_write_u64_le(entry + kDirectoryLastSequenceOffset, 0);
        flight_write_u32_le(entry + kDirectoryChunkIndexOffset, kFlightInvalidIndex);
        flight_write_u32_le(entry + kDirectoryChunkGenerationOffset, 0);
        flight_atomic_store_u32_le(entry + kDirectoryStateOffset,
                                   static_cast<uint32_t>(FlightDirectoryState::Active),
                                   std::memory_order_release);
        *registration = {index, tid};
        return true;
    }
    publish_exhaustion(tid, options_.max_threads,
                       FlightIncompleteReason::DirectoryExhausted);
    errno = ENOSPC;
    return false;
}

bool FlightArtifact::acquire_chunk(const FlightThreadRegistration &registration,
                                   uint64_t first_sequence, FlightChunkLease *lease) noexcept {
    if (!valid() || lease == nullptr ||
        !valid_registration(registration, options_.max_threads)) {
        errno = EINVAL;
        return false;
    }
    const uint8_t *registered_entry = directory_entry(registration.directory_index);
    if (flight_atomic_load_u32_le(registered_entry + kDirectoryTidOffset,
                                  std::memory_order_acquire) != registration.tid) {
        errno = EINVAL;
        return false;
    }

    if (::pthread_mutex_lock(&rotation_mutex_) != 0) {
        publish_exhaustion(registration.tid, registration.directory_index,
                           FlightIncompleteReason::ChunkExhausted);
        errno = EBUSY;
        return false;
    }
    uint32_t selected = kFlightInvalidIndex;
    uint64_t oldest_epoch = UINT64_MAX;
    for (uint32_t index = 0; index < chunk_count_; ++index) {
        const uint32_t state = flight_atomic_load_u32_le(chunk(index) + kChunkStateOffset,
                                                        std::memory_order_acquire);
        if (state == static_cast<uint32_t>(FlightChunkState::Free)) {
            selected = index;
            break;
        }
        if (std::atomic_ref<uint32_t>(chunk_metadata_[index].protected_chunk)
                            .load(std::memory_order_relaxed) == 0 &&
            chunk_metadata_[index].epoch < oldest_epoch) {
            selected = index;
            oldest_epoch = chunk_metadata_[index].epoch;
        }
    }
    if (selected == kFlightInvalidIndex) {
        (void)::pthread_mutex_unlock(&rotation_mutex_);
        publish_exhaustion(registration.tid, registration.directory_index,
                           FlightIncompleteReason::ChunkExhausted);
        errno = ENOSPC;
        return false;
    }

    uint8_t *entry = directory_entry(registration.directory_index);
    uint8_t *selected_chunk = chunk(selected);
    const uint32_t previous_generation =
            flight_read_u32_le(selected_chunk + kChunkGenerationOffset);
    if (previous_generation == UINT32_MAX || allocation_epoch_ == UINT64_MAX) {
        (void)::pthread_mutex_unlock(&rotation_mutex_);
        publish_exhaustion(registration.tid, registration.directory_index,
                           FlightIncompleteReason::ChunkExhausted);
        errno = EOVERFLOW;
        return false;
    }
    const uint32_t generation = previous_generation + 1U;
    flight_atomic_store_u32_le(entry + kDirectoryStateOffset,
                               static_cast<uint32_t>(FlightDirectoryState::Rotating),
                               std::memory_order_release);
    // O_EXCL plus ftruncate guarantees zero-filled initial pages. On reuse only the
    // header must be cleared: committed_bytes bounds all recoverable data, and each
    // new record overwrites its complete aligned storage before publication.
    std::memset(selected_chunk, 0, kFlightChunkHeaderBytes);
    flight_write_u32_le(selected_chunk + 0, kFlightMagic);
    flight_write_u16_le(selected_chunk + 4, kFlightVersion);
    flight_write_u16_le(selected_chunk + 6, kFlightChunkHeaderBytes);
    flight_write_u32_le(selected_chunk + 8, selected);
    flight_write_u32_le(selected_chunk + kChunkTidOffset, registration.tid);
    flight_write_u32_le(selected_chunk + kChunkGenerationOffset, generation);
    flight_write_u64_le(selected_chunk + 24, first_sequence);
    flight_write_u64_le(selected_chunk + 32, first_sequence);
    flight_atomic_store_u32_le(selected_chunk + kChunkStateOffset,
                               static_cast<uint32_t>(FlightChunkState::Active),
                               std::memory_order_release);

    RuntimeThreadMetadata &thread = thread_metadata_[registration.directory_index];
    RuntimeChunkMetadata &metadata = chunk_metadata_[selected];
    metadata.epoch = ++allocation_epoch_;
    metadata.next_protected = kFlightInvalidIndex;
    std::atomic_ref<uint32_t>(metadata.protected_chunk)
            .store(1, std::memory_order_release);
    if (thread.newest_protected != kFlightInvalidIndex) {
        chunk_metadata_[thread.newest_protected].next_protected = selected;
    } else {
        thread.oldest_protected = selected;
    }
    thread.newest_protected = selected;
    ++thread.protected_count;
    if (thread.protected_count > options_.protected_chunks) {
        const uint32_t expired = thread.oldest_protected;
        thread.oldest_protected = chunk_metadata_[expired].next_protected;
        std::atomic_ref<uint32_t>(chunk_metadata_[expired].protected_chunk)
                .store(0, std::memory_order_release);
        --thread.protected_count;
    }

    if (flight_read_u64_le(entry + kDirectoryFirstSequenceOffset) == 0 && first_sequence != 0) {
        flight_write_u64_le(entry + kDirectoryFirstSequenceOffset, first_sequence);
    }
    flight_write_u64_le(entry + kDirectoryLastSequenceOffset, first_sequence);
    flight_write_u32_le(entry + kDirectoryChunkGenerationOffset, generation);
    flight_write_u32_le(entry + kDirectoryChunkIndexOffset, selected);
    flight_atomic_store_u32_le(entry + kDirectoryStateOffset,
                               static_cast<uint32_t>(FlightDirectoryState::Active),
                               std::memory_order_release);
    *lease = {selected, generation, registration.tid,
              selected_chunk + kFlightChunkHeaderBytes, chunk_data_capacity()};
    (void)::pthread_mutex_unlock(&rotation_mutex_);
    return true;
}

void FlightArtifact::mark_incomplete(FlightIncompleteReason reason) noexcept {
    if (!valid() || reason == FlightIncompleteReason::None) return;
    (void)flight_atomic_fetch_or_u32_le(mapping_ + kSuperblockFlagsOffset,
                                        static_cast<uint32_t>(reason),
                                        std::memory_order_release);
}

uint32_t FlightArtifact::flags() const noexcept {
    if (!valid()) return 0;
    return flight_atomic_load_u32_le(mapping_ + kSuperblockFlagsOffset,
                                     std::memory_order_acquire);
}

bool FlightArtifact::write_emergency(const FlightThreadRegistration &registration,
                                     const FlightEmergencyRecord &record) noexcept {
    if (!valid() || !valid_registration(registration, options_.max_threads) ||
        record.tid != registration.tid ||
        flight_atomic_load_u32_le(directory_entry(registration.directory_index) +
                                          kDirectoryTidOffset,
                                  std::memory_order_acquire) != registration.tid) {
        mark_incomplete(FlightIncompleteReason::EmergencyFailure);
        return false;
    }
    return write_emergency(registration.directory_index, record);
}

bool FlightArtifact::write_emergency(uint32_t slot_index,
                                     const FlightEmergencyRecord &record) noexcept {
    if (!valid() || slot_index >= emergency_record_count_ || record.tid == 0 ||
        (record.flags & kFlightEmergencyCommitted) != 0) {
        mark_incomplete(FlightIncompleteReason::EmergencyFailure);
        return false;
    }
    uint8_t *slot = mapping_ + emergency_offset_ +
                    static_cast<uint64_t>(slot_index) * kFlightEmergencyRecordBytes;
    RuntimeEmergencyMetadata &metadata = emergency_metadata_[slot_index];
    std::atomic_ref<uint32_t> claim(metadata.claim);
    uint32_t expected_claim = 0;
    if (!claim.compare_exchange_strong(expected_claim, 1U, std::memory_order_acq_rel,
                                       std::memory_order_acquire)) {
        mark_incomplete(FlightIncompleteReason::EmergencyFailure);
        return false;
    }
    FlightEmergencyRecord existing{};
    if (scan_flight_emergency(slot, &existing) &&
        existing.type == static_cast<uint32_t>(FlightRecordType::CoverageGap)) {
        claim.store(0, std::memory_order_release);
        return false;
    }
    std::atomic_ref<uint32_t> next_version(metadata.next_version);
    uint32_t version = next_version.load(std::memory_order_relaxed);
    while (version != 0 && version <= UINT32_MAX - 2U) {
        if (next_version.compare_exchange_weak(version, version + 2U,
                                               std::memory_order_relaxed,
                                               std::memory_order_relaxed)) {
            break;
        }
    }
    if (version == 0 || version > UINT32_MAX - 2U) {
        claim.store(0, std::memory_order_release);
        mark_incomplete(FlightIncompleteReason::EmergencyFailure);
        return false;
    }
    flight_atomic_store_u32_le(slot + kEmergencyVersionOffset, version | 1U,
                               std::memory_order_release);
    flight_atomic_store_u32_le(slot + kEmergencyFlagsOffset, 0,
                               std::memory_order_release);
    flight_atomic_store_u32_le(slot + 0, record.type, std::memory_order_relaxed);
    flight_atomic_store_u32_le(slot + 4, record.tid, std::memory_order_relaxed);
    flight_atomic_store_u32_le(slot + 8, static_cast<uint32_t>(record.sequence),
                               std::memory_order_relaxed);
    flight_atomic_store_u32_le(slot + 12, static_cast<uint32_t>(record.sequence >> 32U),
                               std::memory_order_relaxed);
    flight_atomic_store_u32_le(slot + 16, static_cast<uint32_t>(record.pc),
                               std::memory_order_relaxed);
    flight_atomic_store_u32_le(slot + 20, static_cast<uint32_t>(record.pc >> 32U),
                               std::memory_order_relaxed);
    flight_atomic_store_u32_le(slot + 24, static_cast<uint32_t>(record.sp),
                               std::memory_order_relaxed);
    flight_atomic_store_u32_le(slot + 28, static_cast<uint32_t>(record.sp >> 32U),
                               std::memory_order_relaxed);
    flight_atomic_store_u32_le(slot + 32, static_cast<uint32_t>(record.fault_address),
                               std::memory_order_relaxed);
    flight_atomic_store_u32_le(slot + 36, static_cast<uint32_t>(record.fault_address >> 32U),
                               std::memory_order_relaxed);
    flight_atomic_store_u32_le(slot + 40, record.signal_number, std::memory_order_relaxed);
    flight_atomic_store_u32_le(slot + 44, record.signal_code, std::memory_order_relaxed);
    const uint32_t checksum = emergency_checksum(record);
    flight_atomic_store_u32_le(slot + kEmergencyChecksumOffset, checksum,
                               std::memory_order_relaxed);
    flight_atomic_store_u32_le(slot + kEmergencyChecksumInverseOffset, ~checksum,
                               std::memory_order_relaxed);
    flight_atomic_store_u32_le(slot + kEmergencyVersionOffset, version,
                               std::memory_order_release);
    flight_atomic_store_u32_le(slot + kEmergencyFlagsOffset,
                               record.flags | kFlightEmergencyCommitted,
                               std::memory_order_release);
    claim.store(0, std::memory_order_release);
    return true;
}

const uint8_t *FlightArtifact::emergency_bytes(uint32_t directory_index) const noexcept {
    if (!valid() || directory_index >= emergency_record_count_) return nullptr;
    return mapping_ + emergency_offset_ +
           static_cast<uint64_t>(directory_index) * kFlightEmergencyRecordBytes;
}

const uint8_t *FlightArtifact::chunk_data(uint32_t chunk_index) const noexcept {
    const uint8_t *header = chunk(chunk_index);
    return header == nullptr ? nullptr : header + kFlightChunkHeaderBytes;
}

uint8_t *FlightArtifact::chunk_data(uint32_t chunk_index) noexcept {
    uint8_t *header = chunk(chunk_index);
    return header == nullptr ? nullptr : header + kFlightChunkHeaderBytes;
}

uint32_t FlightArtifact::chunk_generation(uint32_t chunk_index) const noexcept {
    const uint8_t *header = chunk(chunk_index);
    if (header == nullptr) return 0;
    (void)flight_atomic_load_u32_le(header + kChunkStateOffset, std::memory_order_acquire);
    return flight_read_u32_le(header + kChunkGenerationOffset);
}

uint32_t FlightArtifact::chunk_tid(uint32_t chunk_index) const noexcept {
    const uint8_t *header = chunk(chunk_index);
    if (header == nullptr) return 0;
    (void)flight_atomic_load_u32_le(header + kChunkStateOffset, std::memory_order_acquire);
    return flight_read_u32_le(header + kChunkTidOffset);
}

bool FlightArtifact::chunk_is_protected(uint32_t chunk_index) const noexcept {
    if (!valid() || chunk_index >= chunk_count_) return false;
    auto &value = const_cast<uint32_t &>(chunk_metadata_[chunk_index].protected_chunk);
    return std::atomic_ref<uint32_t>(value).load(std::memory_order_acquire) != 0;
}

bool FlightArtifact::read_chunk(uint32_t chunk_index, FlightChunkSnapshot *snapshot) const noexcept {
    const uint8_t *header = chunk(chunk_index);
    if (header == nullptr || snapshot == nullptr) return false;
    const uint32_t state = flight_atomic_load_u32_le(header + kChunkStateOffset,
                                                    std::memory_order_acquire);
    if (state != static_cast<uint32_t>(FlightChunkState::Active) &&
        state != static_cast<uint32_t>(FlightChunkState::Sealed)) {
        return false;
    }
    if (flight_read_u32_le(header + 0) != kFlightMagic ||
        flight_read_u16_le(header + 4) != kFlightVersion ||
        flight_read_u16_le(header + 6) != kFlightChunkHeaderBytes ||
        flight_read_u32_le(header + 8) != chunk_index) {
        return false;
    }
    snapshot->state = static_cast<FlightChunkState>(state);
    snapshot->chunk_index = chunk_index;
    snapshot->tid = flight_read_u32_le(header + 16);
    snapshot->generation = flight_read_u32_le(header + 20);
    snapshot->first_sequence = flight_read_u64_le(header + 24);
    snapshot->last_sequence = flight_read_u64_le(header + 32);
    snapshot->committed_bytes = flight_read_u32_le(header + 40);
    snapshot->record_count = flight_read_u32_le(header + 44);
    snapshot->checksum = flight_read_u32_le(header + 48);
    return true;
}

uint64_t FlightArtifact::next_sequence() noexcept {
    const uint64_t sequence = sequence_allocator_.next();
    if (sequence == 0) {
        mark_incomplete(FlightIncompleteReason::WriterFailure);
        return 0;
    }
    return sequence;
}

bool FlightArtifact::publish_thread_sequence(const FlightThreadRegistration &registration,
                                             const FlightChunkLease &lease,
                                             uint64_t first_sequence,
                                             uint64_t last_sequence) noexcept {
    if (!valid() || !valid_registration(registration, options_.max_threads) || !lease ||
        lease.tid != registration.tid || lease.chunk_index >= chunk_count_ ||
        chunk_generation(lease.chunk_index) != lease.generation ||
        chunk_tid(lease.chunk_index) != lease.tid) {
        return false;
    }
    uint8_t *entry = directory_entry(registration.directory_index);
    if (flight_read_u64_le(entry + kDirectoryFirstSequenceOffset) == 0) {
        flight_write_u64_le(entry + kDirectoryFirstSequenceOffset, first_sequence);
    }
    flight_write_u64_le(entry + kDirectoryLastSequenceOffset, last_sequence);
    return true;
}

bool FlightArtifact::seal_chunk(const FlightChunkLease &lease, uint64_t first_sequence,
                                uint64_t last_sequence, uint32_t committed_bytes,
                                uint32_t record_count, uint32_t checksum) noexcept {
    uint8_t *header = chunk(lease.chunk_index);
    if (header == nullptr || !lease || committed_bytes > chunk_data_capacity() ||
        flight_atomic_load_u32_le(header + kChunkStateOffset, std::memory_order_acquire) !=
                static_cast<uint32_t>(FlightChunkState::Active) ||
        flight_read_u32_le(header + kChunkTidOffset) != lease.tid ||
        flight_read_u32_le(header + kChunkGenerationOffset) != lease.generation) {
        return false;
    }
    flight_write_u64_le(header + 24, first_sequence);
    flight_write_u64_le(header + 32, last_sequence);
    flight_write_u32_le(header + 40, committed_bytes);
    flight_write_u32_le(header + 44, record_count);
    flight_write_u32_le(header + 48, checksum);
    flight_atomic_store_u32_le(header + kChunkStateOffset,
                               static_cast<uint32_t>(FlightChunkState::Sealed),
                               std::memory_order_release);
    return true;
}

uint8_t *FlightArtifact::directory_entry(uint32_t index) noexcept {
    if (!valid() || index >= options_.max_threads) return nullptr;
    return mapping_ + directory_offset_ +
           static_cast<uint64_t>(index) * kFlightDirectoryEntryBytes;
}

const uint8_t *FlightArtifact::directory_entry(uint32_t index) const noexcept {
    if (!valid() || index >= options_.max_threads) return nullptr;
    return mapping_ + directory_offset_ +
           static_cast<uint64_t>(index) * kFlightDirectoryEntryBytes;
}

uint8_t *FlightArtifact::chunk(uint32_t index) noexcept {
    if (!valid() || index >= chunk_count_) return nullptr;
    return mapping_ + chunk_offset_ + static_cast<uint64_t>(index) * options_.chunk_bytes;
}

const uint8_t *FlightArtifact::chunk(uint32_t index) const noexcept {
    if (!valid() || index >= chunk_count_) return nullptr;
    return mapping_ + chunk_offset_ + static_cast<uint64_t>(index) * options_.chunk_bytes;
}

void FlightArtifact::publish_exhaustion(uint32_t tid, uint32_t slot_index,
                                        FlightIncompleteReason reason) noexcept {
    mark_incomplete(reason);
    if (!valid() || tid == 0 || slot_index >= emergency_record_count_) return;
    FlightEmergencyRecord existing{};
    if (scan_flight_emergency(emergency_bytes(slot_index), &existing) &&
        existing.type == static_cast<uint32_t>(FlightRecordType::CoverageGap)) {
        return;
    }
    FlightEmergencyRecord record{};
    record.type = static_cast<uint32_t>(FlightRecordType::CoverageGap);
    record.tid = tid;
    record.sequence = next_sequence();
    record.flags = static_cast<uint32_t>(reason);
    (void)write_emergency(slot_index, record);
}

void FlightArtifact::reset_state() noexcept {
    fd_ = -1;
    mapping_ = nullptr;
    mapping_size_ = 0;
    runtime_mapping_ = nullptr;
    runtime_mapping_size_ = 0;
    chunk_metadata_ = nullptr;
    thread_metadata_ = nullptr;
    emergency_metadata_ = nullptr;
    options_ = {};
    directory_offset_ = 0;
    emergency_offset_ = 0;
    emergency_record_count_ = 0;
    chunk_offset_ = 0;
    chunk_count_ = 0;
    allocation_epoch_ = 0;
    sequence_allocator_.reset();
}
