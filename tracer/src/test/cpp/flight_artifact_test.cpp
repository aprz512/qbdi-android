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

FlightArtifactIdentityView test_identity() {
    static constexpr char kTargetName[] = "libdemo_target.so";
    return {0x1020304050607080ULL, 4242, 17, kTargetName,
            static_cast<uint16_t>(sizeof(kTargetName) - 1U)};
}

void creates_checked_private_mapping_and_publishes_superblock_last() {
    TemporaryArtifact file;
    g_file_operation_order = 0;
    g_ftruncate_order = 0;
    g_shared_mmap_order = 0;
    FlightArtifact artifact;
    CHECK(artifact.create(file.path.c_str(), test_options(), test_identity()));
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
    CHECK(superblock.emergency_record_bytes == kFlightEmergencySlotBytes);
    CHECK(superblock.run_id == test_identity().run_id);
    CHECK(superblock.pid == test_identity().pid);
    CHECK(superblock.module_generation == test_identity().module_generation);
    CHECK(superblock.target_name_bytes == test_identity().target_name_bytes);
    CHECK(std::memcmp(superblock.target_name, test_identity().target_name,
                      superblock.target_name_bytes) == 0);
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
    CHECK(!duplicate.create(file.path.c_str(), test_options(), test_identity()));
    CHECK(artifact.valid());
}

void mmap_failure_closes_and_removes_the_partial_artifact() {
    TemporaryArtifact file;
    FlightArtifact artifact;
    g_fail_shared_mmap = true;
    CHECK(!artifact.create(file.path.c_str(), test_options(), test_identity()));
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
    CHECK(!artifact.create(file.path.c_str(), options, test_identity()));
    CHECK(::access(file.path.c_str(), F_OK) == -1);
    CHECK(errno == ENOENT);
}

void rejects_invalid_artifact_identity_without_leaving_a_file() {
    TemporaryArtifact file;
    FlightArtifactIdentityView identity = test_identity();
    identity.run_id = 0;
    FlightArtifact artifact;
    CHECK(!artifact.create(file.path.c_str(), test_options(), identity));
    CHECK(::access(file.path.c_str(), F_OK) == -1);
    CHECK(errno == ENOENT);

    identity = test_identity();
    identity.pid = 0;
    CHECK(!artifact.create(file.path.c_str(), test_options(), identity));
    identity = test_identity();
    identity.target_name_bytes = 0;
    CHECK(!artifact.create(file.path.c_str(), test_options(), identity));
    char long_name[kFlightTargetNameBytes + 1]{};
    for (size_t index = 0; index < sizeof(long_name); ++index) long_name[index] = 'x';
    identity = {test_identity().run_id, test_identity().pid, test_identity().module_generation,
                long_name, static_cast<uint16_t>(sizeof(long_name))};
    CHECK(!artifact.create(file.path.c_str(), test_options(), identity));
    char embedded_nul[] = {'a', '\0', 'b'};
    identity = {test_identity().run_id, test_identity().pid, test_identity().module_generation,
                embedded_nul, static_cast<uint16_t>(sizeof(embedded_nul))};
    CHECK(!artifact.create(file.path.c_str(), test_options(), identity));
    CHECK(::access(file.path.c_str(), F_OK) == -1);
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
    CHECK(artifact.create(file.path.c_str(), options, test_identity()));

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
    CHECK(artifact.create(file.path.c_str(), options, test_identity()));
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
    FlightEmergencyRecord repeated_gap{};
    CHECK(scan_flight_emergency(emergency, &repeated_gap));
    CHECK(flight_coverage_gap_dropped_count(repeated_gap) == 1);
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
    CHECK(artifact.create(file.path.c_str(), test_options(), test_identity()));
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

void emergency_overwrite_is_old_or_new_at_every_publication_phase() {
    for (uint32_t phase = 1; phase <= 7; ++phase) {
        TemporaryArtifact file;
        FlightArtifact artifact;
        CHECK(artifact.create(file.path.c_str(), test_options(), test_identity()));
        FlightThreadRegistration thread{};
        CHECK(artifact.register_thread(909, &thread));
        FlightEmergencyRecord old_record{};
        old_record.type = static_cast<uint32_t>(FlightRecordType::Signal);
        old_record.tid = thread.tid;
        old_record.sequence = 41;
        old_record.pc = 0x71000100U;
        CHECK(artifact.write_emergency(thread, old_record));
        FlightEmergencyRecord replacement = old_record;
        replacement.sequence = 42;
        replacement.pc = 0x71000200U;
        artifact.test_interrupt_emergency_publication(
                FlightRecordType::Signal, 0, phase);

        CHECK(!artifact.write_emergency(thread, replacement));

        FlightEmergencyRecord recovered{};
        CHECK(scan_flight_emergency(
                artifact.emergency_bytes(thread.directory_index), &recovered));
        CHECK(recovered.sequence == 41 || recovered.sequence == 42);
        CHECK(recovered.pc == (recovered.sequence == 41
                                       ? 0x71000100U
                                       : 0x71000200U));
    }
}

void coverage_gap_root_cause_is_sticky_and_counts_later_failures() {
    TemporaryArtifact file;
    FlightOptions options = test_options();
    FlightArtifact artifact;
    CHECK(artifact.create(file.path.c_str(), options, test_identity()));

    const uint32_t slot = options.max_threads;
    FlightEmergencyRecord first{};
    first.type = static_cast<uint32_t>(FlightRecordType::CoverageGap);
    first.tid = 101;
    first.sequence = 41;
    first.pc = 0x71000100;
    first.flags = 7;
    CHECK(artifact.write_emergency(slot, first));
    CHECK(artifact.increment_dropped_coverage_gap(slot));
    CHECK(artifact.increment_dropped_coverage_gap(slot));

    FlightEmergencyRecord decoded{};
    CHECK(scan_flight_emergency(artifact.emergency_bytes(slot), &decoded));
    CHECK(decoded.type == first.type);
    CHECK(decoded.tid == first.tid);
    CHECK(decoded.sequence == first.sequence);
    CHECK(decoded.pc == first.pc);
    CHECK(decoded.flags == first.flags);
    CHECK(flight_coverage_gap_dropped_count(decoded) == 2);
}

void dropped_gap_update_keeps_the_root_publication_immutable() {
    TemporaryArtifact file;
    FlightOptions options = test_options();
    FlightArtifact artifact;
    CHECK(artifact.create(file.path.c_str(), options, test_identity()));
    const uint32_t slot = options.max_threads;
    FlightEmergencyRecord root{};
    root.type = static_cast<uint32_t>(FlightRecordType::CoverageGap);
    root.tid = 202;
    root.sequence = 81;
    root.pc = 0x71000200;
    root.flags = 9;
    CHECK(artifact.write_emergency(slot, root));
    const uint8_t *bytes = artifact.emergency_bytes(slot);
    const uint32_t flags = flight_read_u32_le(bytes + 48);
    const uint32_t checksum = flight_read_u32_le(bytes + 52);
    const uint32_t checksum_inverse = flight_read_u32_le(bytes + 56);
    const uint32_t version = flight_read_u32_le(bytes + 60);

    CHECK(artifact.increment_dropped_coverage_gap(slot));

    CHECK(flight_read_u32_le(bytes + 48) == flags);
    CHECK(flight_read_u32_le(bytes + 52) == checksum);
    CHECK(flight_read_u32_le(bytes + 56) == checksum_inverse);
    CHECK(flight_read_u32_le(bytes + 60) == version);
    FlightEmergencyRecord decoded{};
    CHECK(scan_flight_emergency(bytes, &decoded));
    CHECK(decoded.tid == root.tid);
    CHECK(decoded.pc == root.pc);
    CHECK(flight_coverage_gap_dropped_count(decoded) == 1);
}

void colliding_emergency_writers_never_publish_a_hybrid() {
    TemporaryArtifact file;
    FlightArtifact artifact;
    CHECK(artifact.create(file.path.c_str(), test_options(), test_identity()));
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

void mixed_emergency_writers_preserve_one_gap_and_count_every_later_gap() {
    TemporaryArtifact file;
    FlightOptions options = test_options();
    FlightArtifact artifact;
    CHECK(artifact.create(file.path.c_str(), options, test_identity()));
    const uint32_t slot = options.max_threads;
    constexpr uint32_t kGapWriters = 4;
    constexpr uint32_t kAttempts = 500;
    std::atomic<bool> start{false};
    std::array<std::thread, kGapWriters * 2U> writers;
    for (uint32_t index = 0; index < kGapWriters; ++index) {
        writers[index] = std::thread([&, index] {
            while (!start.load(std::memory_order_acquire)) {
            }
            FlightEmergencyRecord record{};
            record.type = static_cast<uint32_t>(FlightRecordType::Signal);
            record.tid = 300U + index;
            for (uint32_t attempt = 0; attempt < kAttempts; ++attempt) {
                record.sequence = attempt + 1U;
                (void)artifact.write_emergency(slot, record);
            }
        });
        writers[kGapWriters + index] = std::thread([&, index] {
            while (!start.load(std::memory_order_acquire)) {
            }
            FlightEmergencyRecord record{};
            record.type = static_cast<uint32_t>(FlightRecordType::CoverageGap);
            record.tid = 400U + index;
            record.sequence = 100U + index;
            record.pc = 0x71001000U + index * 4U;
            record.flags = index + 1U;
            for (uint32_t attempt = 0; attempt < kAttempts; ++attempt) {
                CHECK(artifact.write_coverage_gap_sticky(slot, record));
            }
        });
    }
    start.store(true, std::memory_order_release);
    for (std::thread &writer : writers) writer.join();

    FlightEmergencyRecord decoded{};
    CHECK(scan_flight_emergency(artifact.emergency_bytes(slot), &decoded));
    CHECK(decoded.type == static_cast<uint32_t>(FlightRecordType::CoverageGap));
    CHECK(flight_coverage_gap_dropped_count(decoded) ==
          kGapWriters * kAttempts - 1U);
}

void abandoned_emergency_claim_fails_open_without_spinning_forever() {
    TemporaryArtifact file;
    FlightOptions options = test_options();
    FlightArtifact artifact;
    CHECK(artifact.create(file.path.c_str(), options, test_identity()));
    const uint32_t slot = options.max_threads;
    CHECK(artifact.test_claim_emergency_slot(slot));
    FlightEmergencyRecord record{};
    record.type = static_cast<uint32_t>(FlightRecordType::CoverageGap);
    record.tid = 501;
    record.sequence = 1;
    record.flags = 2;
    CHECK(!artifact.write_coverage_gap_sticky(slot, record));
    CHECK((artifact.flags() &
           static_cast<uint32_t>(FlightIncompleteReason::EmergencyFailure)) != 0);
    artifact.test_release_emergency_slot(slot);
}

void concurrent_registration_keeps_duplicate_tids_unique_and_bounds_capacity() {
    TemporaryArtifact file;
    FlightArtifact artifact;
    CHECK(artifact.create(file.path.c_str(), test_options(), test_identity()));
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
    FlightEmergencyRecord exhaustion{};
    CHECK(scan_flight_emergency(
            artifact.emergency_bytes(test_options().max_threads), &exhaustion));
    const uint32_t failures = static_cast<uint32_t>(registered.size()) - successes;
    CHECK(failures > 0);
    CHECK(flight_coverage_gap_dropped_count(exhaustion) == failures - 1U);
}

void allocator_reclaims_global_oldest_without_stealing_reservations() {
    TemporaryArtifact file;
    FlightArtifact artifact;
    CHECK(artifact.create(file.path.c_str(), test_options(), test_identity()));
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
    CHECK(artifact.create(file.path.c_str(), test_options(), test_identity()));
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
    rejects_invalid_artifact_identity_without_leaving_a_file();
    sequence_allocation_saturates_permanently_before_wrap();
    registers_unique_tids_and_marks_exhaustion_incomplete();
    protected_pool_exhaustion_publishes_the_affected_tid();
    emergency_slots_publish_complete_little_endian_records();
    emergency_overwrite_is_old_or_new_at_every_publication_phase();
    coverage_gap_root_cause_is_sticky_and_counts_later_failures();
    dropped_gap_update_keeps_the_root_publication_immutable();
    colliding_emergency_writers_never_publish_a_hybrid();
    mixed_emergency_writers_preserve_one_gap_and_count_every_later_gap();
    abandoned_emergency_claim_fails_open_without_spinning_forever();
    concurrent_registration_keeps_duplicate_tids_unique_and_bounds_capacity();
    allocator_reclaims_global_oldest_without_stealing_reservations();
    fork_child_detach_releases_only_the_child_copy();
}
