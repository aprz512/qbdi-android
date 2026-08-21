#include "flight/flight_artifact.h"

#include <cerrno>
#include <array>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

extern "C" int __real_ftruncate(int descriptor, off_t length);
extern "C" void *__real_mmap(void *address, size_t length, int protection, int flags,
                              int descriptor, off_t offset);

namespace {

int g_file_operation_order = 0;
int g_ftruncate_order = 0;
int g_shared_mmap_order = 0;
bool g_fail_shared_mmap = false;

} // namespace

extern "C" int __wrap_ftruncate(int descriptor, off_t length) {
    g_ftruncate_order = ++g_file_operation_order;
    return __real_ftruncate(descriptor, length);
}

extern "C" void *__wrap_mmap(void *address, size_t length, int protection, int flags,
                              int descriptor, off_t offset) {
    if ((flags & MAP_SHARED) != 0 && descriptor >= 0) {
        g_shared_mmap_order = ++g_file_operation_order;
        if (g_fail_shared_mmap) {
            errno = ENOMEM;
            return MAP_FAILED;
        }
    }
    return __real_mmap(address, length, protection, flags, descriptor, offset);
}

namespace {

void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

struct TemporaryArtifact {
    TemporaryArtifact() {
        char directory_template[] = "/tmp/qtrace-flight-artifact-XXXXXX";
        char *created = ::mkdtemp(directory_template);
        CHECK(created != nullptr);
        directory = created;
        path = directory + "/artifact.flight.bin";
    }

    ~TemporaryArtifact() {
        (void)::unlink(path.c_str());
        (void)::rmdir(directory.c_str());
    }

    std::string directory;
    std::string path;
};

FlightOptions test_options() {
    FlightOptions options;
    options.enabled = true;
    options.capacity_bytes = 64ULL * 1024 * 1024;
    options.chunk_bytes = 1024U * 1024;
    options.max_threads = 8;
    options.protected_chunks = 4;
    return options;
}

void creates_checked_private_mapping_and_publishes_superblock_last() {
    TemporaryArtifact file;
    g_file_operation_order = 0;
    g_ftruncate_order = 0;
    g_shared_mmap_order = 0;
    FlightArtifact artifact;
    CHECK(artifact.create(file.path.c_str(), test_options()));
    CHECK(artifact.valid());
    CHECK(g_ftruncate_order > 0);
    CHECK(g_shared_mmap_order > g_ftruncate_order);

    struct stat status {};
    CHECK(::stat(file.path.c_str(), &status) == 0);
    CHECK((status.st_mode & 0777) == 0600);
    CHECK(static_cast<uint64_t>(status.st_size) == test_options().capacity_bytes);

    FlightSuperblock superblock{};
    CHECK(decode_flight_superblock_le(artifact.bytes(), kFlightSuperblockBytes, &superblock));
    CHECK(superblock.artifact_bytes == test_options().capacity_bytes);
    CHECK(superblock.directory_offset == kFlightSuperblockBytes);
    CHECK(superblock.directory_entries == test_options().max_threads);
    CHECK(superblock.directory_entry_bytes == kFlightDirectoryEntryBytes);
    CHECK(superblock.chunk_bytes == test_options().chunk_bytes);
    CHECK(superblock.chunk_count == artifact.chunk_count());
    CHECK(superblock.emergency_record_count == test_options().max_threads + 1U);
    CHECK(superblock.emergency_record_bytes == kFlightEmergencyRecordBytes);
    CHECK(superblock.directory_offset +
                  static_cast<uint64_t>(superblock.directory_entries) *
                          superblock.directory_entry_bytes <=
          superblock.emergency_offset);
    CHECK(superblock.emergency_offset +
                  static_cast<uint64_t>(superblock.emergency_record_count) *
                          superblock.emergency_record_bytes <=
          superblock.chunk_offset);
    CHECK(superblock.chunk_offset % test_options().chunk_bytes == 0);
    CHECK(superblock.chunk_offset +
                  static_cast<uint64_t>(superblock.chunk_count) * superblock.chunk_bytes <=
          superblock.artifact_bytes);

    FlightArtifact duplicate;
    CHECK(!duplicate.create(file.path.c_str(), test_options()));
    CHECK(artifact.valid());
}

void mmap_failure_closes_and_removes_the_partial_artifact() {
    TemporaryArtifact file;
    FlightArtifact artifact;
    g_fail_shared_mmap = true;
    CHECK(!artifact.create(file.path.c_str(), test_options()));
    g_fail_shared_mmap = false;
    CHECK(!artifact.valid());
    CHECK(::access(file.path.c_str(), F_OK) == -1);
    CHECK(errno == ENOENT);
}

void rejects_invalid_layout_without_leaving_a_file() {
    TemporaryArtifact file;
    FlightOptions options = test_options();
    options.capacity_bytes = 4096;
    options.max_threads = UINT32_MAX;

    FlightArtifact artifact;
    CHECK(!artifact.create(file.path.c_str(), options));
    CHECK(::access(file.path.c_str(), F_OK) == -1);
    CHECK(errno == ENOENT);
}

void sequence_allocation_saturates_permanently_before_wrap() {
    FlightSequenceAllocator allocator(UINT64_MAX - 1U);
    CHECK(allocator.next() == UINT64_MAX - 1U);
    CHECK(allocator.next() == 0);
    CHECK(allocator.next() == 0);
    CHECK(allocator.next() == 0);
}

void registers_unique_tids_and_marks_exhaustion_incomplete() {
    TemporaryArtifact file;
    FlightOptions options = test_options();
    options.max_threads = 2;
    FlightArtifact artifact;
    CHECK(artifact.create(file.path.c_str(), options));

    FlightThreadRegistration first{};
    FlightThreadRegistration duplicate{};
    FlightThreadRegistration second{};
    FlightThreadRegistration exhausted{};
    CHECK(artifact.register_thread(101, &first));
    CHECK(artifact.register_thread(101, &duplicate));
    CHECK(first.directory_index == duplicate.directory_index);
    CHECK(first.tid == 101);
    CHECK(artifact.register_thread(202, &second));
    CHECK(first.directory_index != second.directory_index);

    FlightEmergencyRecord first_evidence{};
    first_evidence.type = static_cast<uint32_t>(FlightRecordType::Error);
    first_evidence.tid = first.tid;
    first_evidence.sequence = 41;
    first_evidence.flags = static_cast<uint32_t>(FlightIncompleteReason::WriterFailure);
    CHECK(artifact.write_emergency(first, first_evidence));
    FlightEmergencyRecord second_evidence = first_evidence;
    second_evidence.tid = second.tid;
    second_evidence.sequence = 42;
    CHECK(artifact.write_emergency(second, second_evidence));
    CHECK(!artifact.register_thread(303, &exhausted));
    CHECK(artifact.incomplete());

    artifact.mark_incomplete(FlightIncompleteReason::WriterFailure);
    artifact.mark_incomplete(FlightIncompleteReason::None);
    CHECK(artifact.incomplete());
    CHECK((artifact.flags() & static_cast<uint32_t>(FlightIncompleteReason::DirectoryExhausted)) !=
          0);
    CHECK((artifact.flags() & static_cast<uint32_t>(FlightIncompleteReason::WriterFailure)) != 0);
    CHECK(flight_read_u32_le(artifact.emergency_bytes(first.directory_index) + 4) == first.tid);
    CHECK(flight_read_u64_le(artifact.emergency_bytes(first.directory_index) + 8) == 41);
    CHECK(flight_read_u32_le(artifact.emergency_bytes(second.directory_index) + 4) == second.tid);
    CHECK(flight_read_u64_le(artifact.emergency_bytes(second.directory_index) + 8) == 42);
    const uint8_t *emergency = artifact.emergency_bytes(options.max_threads);
    CHECK(flight_read_u32_le(emergency + 0) ==
          static_cast<uint32_t>(FlightRecordType::CoverageGap));
    CHECK(flight_read_u32_le(emergency + 4) == 303U);
    CHECK((flight_atomic_load_u32_le(emergency + 48, std::memory_order_acquire) &
           kFlightEmergencyCommitted) != 0);
    CHECK((flight_read_u32_le(emergency + 48) &
           static_cast<uint32_t>(FlightIncompleteReason::DirectoryExhausted)) != 0);
}

void protected_pool_exhaustion_publishes_the_affected_tid() {
    TemporaryArtifact file;
    FlightOptions options = test_options();
    options.max_threads = 2;
    options.protected_chunks = 63;
    FlightArtifact artifact;
    CHECK(artifact.create(file.path.c_str(), options));
    CHECK(artifact.chunk_count() == 63);
    FlightThreadRegistration thread{};
    FlightThreadRegistration neighbor{};
    CHECK(artifact.register_thread(3, &thread));
    CHECK(artifact.register_thread(4, &neighbor));
    CHECK(thread.directory_index == 0);
    CHECK(thread.tid % options.max_threads == neighbor.directory_index);
    FlightEmergencyRecord neighbor_evidence{};
    neighbor_evidence.type = static_cast<uint32_t>(FlightRecordType::Signal);
    neighbor_evidence.tid = neighbor.tid;
    neighbor_evidence.sequence = 77;
    CHECK(artifact.write_emergency(neighbor, neighbor_evidence));
    FlightChunkLease lease{};
    for (uint32_t index = 0; index < artifact.chunk_count(); ++index) {
        CHECK(artifact.acquire_chunk(thread, index + 1U, &lease));
    }
    CHECK(!artifact.acquire_chunk(thread, artifact.chunk_count() + 1U, &lease));
    const uint8_t *emergency = artifact.emergency_bytes(thread.directory_index);
    CHECK(flight_read_u32_le(emergency + 0) ==
          static_cast<uint32_t>(FlightRecordType::CoverageGap));
    CHECK(flight_read_u32_le(emergency + 4) == thread.tid);
    CHECK((flight_read_u32_le(emergency + 48) &
           static_cast<uint32_t>(FlightIncompleteReason::ChunkExhausted)) != 0);
    const uint64_t first_gap_sequence = flight_read_u64_le(emergency + 8);
    CHECK(!artifact.acquire_chunk(thread, artifact.chunk_count() + 2U, &lease));
    CHECK(flight_read_u64_le(emergency + 8) == first_gap_sequence);
    FlightEmergencyRecord later_signal{};
    later_signal.type = static_cast<uint32_t>(FlightRecordType::Signal);
    later_signal.tid = thread.tid;
    later_signal.sequence = 999;
    CHECK(!artifact.write_emergency(thread, later_signal));
    CHECK(flight_read_u32_le(emergency + 0) ==
          static_cast<uint32_t>(FlightRecordType::CoverageGap));
    CHECK(flight_read_u64_le(emergency + 8) == first_gap_sequence);
    CHECK(flight_read_u32_le(artifact.emergency_bytes(neighbor.directory_index) + 4) ==
          neighbor.tid);
    CHECK(flight_read_u64_le(artifact.emergency_bytes(neighbor.directory_index) + 8) == 77);
}

void emergency_slots_publish_complete_little_endian_records() {
    TemporaryArtifact file;
    FlightArtifact artifact;
    CHECK(artifact.create(file.path.c_str(), test_options()));
    FlightThreadRegistration thread{};
    CHECK(artifact.register_thread(0x11223344U, &thread));

    FlightEmergencyRecord record{};
    record.type = static_cast<uint32_t>(FlightRecordType::Signal);
    record.tid = thread.tid;
    record.sequence = 0x0102030405060708ULL;
    record.pc = 0x1112131415161718ULL;
    record.sp = 0x2122232425262728ULL;
    record.fault_address = 0x3132333435363738ULL;
    record.signal_number = 11;
    record.signal_code = 1;
    record.flags = 0x44;
    CHECK(artifact.write_emergency(thread, record));

    const uint8_t *bytes = artifact.emergency_bytes(thread.directory_index);
    CHECK(bytes != nullptr);
    CHECK(flight_read_u32_le(bytes + 0) == static_cast<uint32_t>(FlightRecordType::Signal));
    CHECK(flight_read_u32_le(bytes + 4) == 0x11223344U);
    CHECK(flight_read_u64_le(bytes + 8) == 0x0102030405060708ULL);
    CHECK(flight_read_u64_le(bytes + 16) == 0x1112131415161718ULL);
    CHECK(flight_read_u32_le(bytes + 40) == 11);
    CHECK(flight_read_u32_le(bytes + 48) == (0x44U | kFlightEmergencyCommitted));
    FlightEmergencyRecord decoded{};
    CHECK(scan_flight_emergency(bytes, &decoded));
    CHECK(decoded.tid == record.tid);
    CHECK(decoded.sequence == record.sequence);
    CHECK(decoded.pc == record.pc);
    CHECK(decoded.flags == record.flags);

    uint8_t *mutable_bytes = artifact.bytes() + (bytes - artifact.bytes());
    flight_atomic_store_u32_le(mutable_bytes + 16,
                               flight_read_u32_le(mutable_bytes + 16) ^ 1U,
                               std::memory_order_relaxed);
    CHECK(!scan_flight_emergency(bytes, &decoded));
}

void colliding_emergency_writers_never_publish_a_hybrid() {
    TemporaryArtifact file;
    FlightArtifact artifact;
    CHECK(artifact.create(file.path.c_str(), test_options()));
    FlightThreadRegistration thread{};
    CHECK(artifact.register_thread(900, &thread));

    auto patterned_record = [](uint32_t identity) {
        FlightEmergencyRecord record{};
        record.type = static_cast<uint32_t>(FlightRecordType::Signal);
        record.tid = 1000U + identity;
        record.sequence = 0x1100000000000000ULL | identity;
        record.pc = record.sequence ^ 0x1111111111111111ULL;
        record.sp = record.sequence ^ 0x2222222222222222ULL;
        record.fault_address = record.sequence ^ 0x3333333333333333ULL;
        record.signal_number = 4U + identity;
        record.signal_code = 40U + identity;
        record.flags = identity;
        return record;
    };
    CHECK(artifact.write_emergency(thread.directory_index, patterned_record(1)));

    std::atomic<bool> start{false};
    std::atomic<bool> stop_reader{false};
    std::atomic<bool> coherent{true};
    std::thread reader([&] {
        while (!stop_reader.load(std::memory_order_acquire)) {
            FlightEmergencyRecord decoded{};
            if (!scan_flight_emergency(
                        artifact.emergency_bytes(thread.directory_index), &decoded)) {
                continue;
            }
            const uint32_t identity = decoded.tid - 1000U;
            const uint64_t sequence = 0x1100000000000000ULL | identity;
            if (identity == 0 || identity > 8 || decoded.sequence != sequence ||
                decoded.pc != (sequence ^ 0x1111111111111111ULL) ||
                decoded.sp != (sequence ^ 0x2222222222222222ULL) ||
                decoded.fault_address != (sequence ^ 0x3333333333333333ULL) ||
                decoded.signal_number != 4U + identity ||
                decoded.signal_code != 40U + identity || decoded.flags != identity) {
                coherent.store(false, std::memory_order_relaxed);
                return;
            }
        }
    });
    std::array<std::thread, 8> writers;
    for (uint32_t index = 0; index < writers.size(); ++index) {
        writers[index] = std::thread([&, identity = index + 1U] {
            while (!start.load(std::memory_order_acquire)) {
            }
            const FlightEmergencyRecord record = patterned_record(identity);
            for (uint32_t iteration = 0; iteration < 2000; ++iteration) {
                (void)artifact.write_emergency(thread.directory_index, record);
            }
        });
    }
    start.store(true, std::memory_order_release);
    for (std::thread &writer : writers) writer.join();
    stop_reader.store(true, std::memory_order_release);
    reader.join();
    CHECK(coherent.load(std::memory_order_relaxed));
    FlightEmergencyRecord decoded{};
    CHECK(scan_flight_emergency(artifact.emergency_bytes(thread.directory_index), &decoded));
}

void concurrent_registration_keeps_duplicate_tids_unique_and_bounds_capacity() {
    TemporaryArtifact file;
    FlightArtifact artifact;
    CHECK(artifact.create(file.path.c_str(), test_options()));
    std::atomic<bool> start{false};
    std::array<FlightThreadRegistration, 8> duplicates{};
    std::array<std::thread, 8> duplicate_workers;
    for (size_t index = 0; index < duplicate_workers.size(); ++index) {
        duplicate_workers[index] = std::thread([&, index] {
            while (!start.load(std::memory_order_acquire)) {
            }
            CHECK(artifact.register_thread(777, &duplicates[index]));
        });
    }
    start.store(true, std::memory_order_release);
    for (std::thread &worker : duplicate_workers) worker.join();
    for (const FlightThreadRegistration &registration : duplicates) {
        CHECK(registration.directory_index == duplicates.front().directory_index);
    }

    start.store(false, std::memory_order_relaxed);
    std::array<bool, 14> registered{};
    std::array<FlightThreadRegistration, 14> registrations{};
    std::array<std::thread, 14> workers;
    for (size_t index = 0; index < workers.size(); ++index) {
        workers[index] = std::thread([&, index] {
            while (!start.load(std::memory_order_acquire)) {
            }
            registered[index] = artifact.register_thread(
                    static_cast<uint32_t>(1000 + index), &registrations[index]);
        });
    }
    start.store(true, std::memory_order_release);
    for (std::thread &worker : workers) worker.join();
    uint32_t successes = 0;
    for (bool result : registered) successes += result ? 1U : 0U;
    CHECK(successes == test_options().max_threads - 1U);
    for (size_t left = 0; left < registrations.size(); ++left) {
        if (!registered[left]) continue;
        for (size_t right = left + 1; right < registrations.size(); ++right) {
            if (registered[right]) {
                CHECK(registrations[left].directory_index !=
                      registrations[right].directory_index);
            }
        }
    }
    CHECK(artifact.incomplete());
}

void allocator_reclaims_global_oldest_without_stealing_reservations() {
    TemporaryArtifact file;
    FlightArtifact artifact;
    CHECK(artifact.create(file.path.c_str(), test_options()));
    FlightThreadRegistration busy{};
    FlightThreadRegistration quiet{};
    CHECK(artifact.register_thread(101, &busy));
    CHECK(artifact.register_thread(202, &quiet));

    std::vector<FlightChunkLease> busy_chunks;
    std::vector<FlightChunkLease> quiet_chunks;
    FlightChunkLease lease{};
    CHECK(artifact.acquire_chunk(busy, 1, &lease));
    busy_chunks.push_back(lease);
    CHECK(artifact.acquire_chunk(quiet, 2, &lease));
    quiet_chunks.push_back(lease);
    CHECK(artifact.acquire_chunk(quiet, 3, &lease));
    quiet_chunks.push_back(lease);
    CHECK(artifact.acquire_chunk(quiet, 4, &lease));
    quiet_chunks.push_back(lease);
    CHECK(artifact.acquire_chunk(quiet, 5, &lease));
    quiet_chunks.push_back(lease);
    uint64_t sequence = 6;
    while (busy_chunks.size() + quiet_chunks.size() < artifact.chunk_count()) {
        CHECK(artifact.acquire_chunk(busy, sequence++, &lease));
        busy_chunks.push_back(lease);
    }

    const FlightChunkLease oldest = busy_chunks.front();
    CHECK(artifact.acquire_chunk(quiet, sequence, &lease));
    CHECK(lease.chunk_index == oldest.chunk_index);
    CHECK(lease.generation == oldest.generation + 1U);
    for (const FlightChunkLease &protected_chunk : quiet_chunks) {
        CHECK(lease.chunk_index != protected_chunk.chunk_index);
        CHECK(artifact.chunk_generation(protected_chunk.chunk_index) ==
              protected_chunk.generation);
        CHECK(artifact.chunk_tid(protected_chunk.chunk_index) == quiet.tid);
    }
}

void fork_child_detach_releases_only_the_child_copy() {
    TemporaryArtifact file;
    FlightArtifact artifact;
    CHECK(artifact.create(file.path.c_str(), test_options()));
    const pid_t child = ::fork();
    CHECK(child >= 0);
    if (child == 0) {
        const int descriptor = artifact.fd();
        artifact.detach_after_fork_child();
        if (artifact.valid()) _exit(101);
        if (::fcntl(descriptor, F_GETFD) != -1 || errno != EBADF) _exit(102);
        _exit(0);
    }
    int child_status = 0;
    CHECK(::waitpid(child, &child_status, 0) == child);
    CHECK(WIFEXITED(child_status));
    CHECK(WEXITSTATUS(child_status) == 0);
    CHECK(artifact.valid());
    CHECK(::fcntl(artifact.fd(), F_GETFD) != -1);
}

} // namespace

int main() {
    creates_checked_private_mapping_and_publishes_superblock_last();
    mmap_failure_closes_and_removes_the_partial_artifact();
    rejects_invalid_layout_without_leaving_a_file();
    sequence_allocation_saturates_permanently_before_wrap();
    registers_unique_tids_and_marks_exhaustion_incomplete();
    protected_pool_exhaustion_publishes_the_affected_tid();
    emergency_slots_publish_complete_little_endian_records();
    colliding_emergency_writers_never_publish_a_hybrid();
    concurrent_registration_keeps_duplicate_tids_unique_and_bounds_capacity();
    allocator_reclaims_global_oldest_without_stealing_reservations();
    fork_child_detach_releases_only_the_child_copy();
}
