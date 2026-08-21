#include "flight/flight_artifact.h"
#include "flight/flight_chunk_writer.h"

#include <cstdio>
#include <atomic>
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>

namespace {

void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

FlightArtifactIdentityView test_identity() {
    static constexpr char kTargetName[] = "libdemo_target.so";
    return {0x1020304050607080ULL, 4242, 17, kTargetName,
            static_cast<uint16_t>(sizeof(kTargetName) - 1U)};
}

struct Fixture {
    Fixture() {
        char directory_template[] = "/tmp/qtrace-flight-writer-XXXXXX";
        char *created = ::mkdtemp(directory_template);
        CHECK(created != nullptr);
        directory = created;
        path = directory + "/artifact.flight.bin";
        FlightOptions options;
        options.enabled = true;
        options.capacity_bytes = 64ULL * 1024 * 1024;
        options.chunk_bytes = 64U * 1024;
        options.max_threads = 4;
        options.protected_chunks = 2;
        CHECK(artifact.create(path.c_str(), options, test_identity()));
        CHECK(artifact.register_thread(1234, &thread));
        CHECK(writer.initialize(&artifact, thread));
    }

    ~Fixture() {
        writer.detach();
        artifact.close();
        (void)::unlink(path.c_str());
        (void)::rmdir(directory.c_str());
    }

    std::string directory;
    std::string path;
    FlightArtifact artifact;
    FlightThreadRegistration thread{};
    FlightChunkWriter writer;
};

void appends_explicit_little_endian_records_with_valid_commit_and_checksum() {
    Fixture fixture;
    const uint8_t payload[] = {0xde, 0xad, 0xbe, 0xef, 0x55};
    CHECK(fixture.writer.append(FlightRecordType::Instruction,
                                {payload, sizeof(payload)}, 0x1234) ==
          FlightWriteResult::Written);

    FlightDecodedRecord decoded{};
    CHECK(scan_flight_record(fixture.writer.previous_record_bytes(),
                             fixture.writer.previous_record_size(),
                             fixture.writer.generation(), &decoded));
    CHECK(decoded.type == FlightRecordType::Instruction);
    CHECK(decoded.flags == 0x1234);
    CHECK(decoded.sequence == 1);
    CHECK(decoded.payload_bytes == sizeof(payload));
    CHECK(std::memcmp(decoded.payload, payload, sizeof(payload)) == 0);
    CHECK(flight_read_u16_le(fixture.writer.previous_record_bytes()) ==
          static_cast<uint16_t>(FlightRecordType::Instruction));
}

void distinguishes_written_no_space_and_writer_errors() {
    FlightChunkWriter inactive;
    const uint8_t byte = 1;
    CHECK(inactive.append(FlightRecordType::Instruction, {&byte, 1}) ==
          FlightWriteResult::Error);

    Fixture fixture;
    CHECK(fixture.writer.append(FlightRecordType::Instruction, {&byte, 1}) ==
          FlightWriteResult::Written);
    const uint32_t committed = fixture.writer.committed_bytes();
    std::vector<uint8_t> oversized(fixture.artifact.chunk_data_capacity(), 0xaa);
    CHECK(fixture.writer.append(FlightRecordType::Instruction, oversized) ==
          FlightWriteResult::NoSpace);
    CHECK(fixture.writer.committed_bytes() == committed);
}

void pair_append_preflights_both_records_before_publishing_either() {
    Fixture fixture;
    const size_t capacity = fixture.artifact.chunk_data_capacity();
    std::vector<uint8_t> padding(capacity - 72U, 0x55);
    CHECK(fixture.writer.append(FlightRecordType::Rule, padding) ==
          FlightWriteResult::Written);
    const uint32_t committed = fixture.writer.committed_bytes();
    const uint8_t metadata = 1;
    const uint8_t checkpoint = 2;
    const FlightRecordView first{FlightRecordType::ChunkBegin, {&metadata, 1}, 0};
    const FlightRecordView second{FlightRecordType::RegisterDelta, {&checkpoint, 1}, 1};
    CHECK(fixture.writer.append_pair(first, second) == FlightWriteResult::NoSpace);
    CHECK(fixture.writer.committed_bytes() == committed);
    CHECK(fixture.writer.record_count() == 1);
}

void rejects_bad_bounds_commit_checksum_and_generation() {
    Fixture fixture;
    const uint8_t payload[] = {1, 2, 3, 4};
    CHECK(fixture.writer.append(FlightRecordType::Memory, {payload, sizeof(payload)}) ==
          FlightWriteResult::Written);
    const uint8_t *record = fixture.writer.previous_record_bytes();
    const size_t size = fixture.writer.previous_record_size();
    FlightDecodedRecord decoded{};
    CHECK(!scan_flight_record(record, size - 1U, fixture.writer.generation(), &decoded));
    CHECK(!scan_flight_record(record, size, fixture.writer.generation() + 1U, &decoded));
    const uint32_t total_bytes = flight_read_u32_le(record + 4);
    CHECK(!scan_flight_record(record, total_bytes, fixture.writer.generation(), &decoded));
    CHECK(scan_flight_record(record, fixture.writer.committed_bytes(),
                             fixture.writer.generation(), &decoded));

    alignas(8) uint8_t unaligned_storage[64]{};
    CHECK(fixture.writer.committed_bytes() + 1U <= sizeof(unaligned_storage));
    std::memcpy(unaligned_storage + 1, record, fixture.writer.committed_bytes());
    CHECK(!scan_flight_record(unaligned_storage + 1, fixture.writer.committed_bytes(),
                              fixture.writer.generation(), &decoded));

    uint8_t saved = fixture.writer.mutable_previous_record_bytes()[kFlightRecordHeaderBytes];
    fixture.writer.mutable_previous_record_bytes()[kFlightRecordHeaderBytes] ^= 0xffU;
    CHECK(!scan_flight_record(record, size, fixture.writer.generation(), &decoded));
    fixture.writer.mutable_previous_record_bytes()[kFlightRecordHeaderBytes] = saved;

    const uint32_t commit = flight_read_u32_le(record + 20);
    flight_atomic_store_u32_le(fixture.writer.mutable_previous_record_bytes() + 20,
                               commit ^ 1U, std::memory_order_release);
    CHECK(!scan_flight_record(record, size, fixture.writer.generation(), &decoded));
}

void torn_final_record_does_not_hide_preceding_committed_record() {
    Fixture fixture;
    const uint8_t payload[] = {7, 8, 9};
    CHECK(fixture.writer.append(FlightRecordType::Instruction, {payload, sizeof(payload)}) ==
          FlightWriteResult::Written);
    fixture.writer.test_interrupt_before_commit();

    FlightDecodedRecord decoded{};
    CHECK(!scan_flight_record(fixture.writer.active_bytes(), fixture.writer.active_size(),
                              fixture.writer.generation(), &decoded));
    CHECK(scan_flight_record(fixture.writer.previous_record_bytes(),
                             fixture.writer.previous_record_size(),
                             fixture.writer.generation(), &decoded));
    CHECK(decoded.type == FlightRecordType::Instruction);
}

void seal_publishes_lengths_endpoints_counts_and_chunk_checksum() {
    Fixture fixture;
    const uint8_t first[] = {0x10};
    const uint8_t second[] = {0x20, 0x21};
    CHECK(fixture.writer.append(FlightRecordType::ThreadBegin, {first, sizeof(first)}) ==
          FlightWriteResult::Written);
    CHECK(fixture.writer.append(FlightRecordType::Call, {second, sizeof(second)}) ==
          FlightWriteResult::Written);
    const uint32_t chunk_index = fixture.writer.chunk_index();
    const size_t committed = fixture.writer.committed_bytes();
    CHECK(fixture.writer.seal());

    FlightChunkSnapshot snapshot{};
    CHECK(fixture.artifact.read_chunk(chunk_index, &snapshot));
    CHECK(snapshot.state == FlightChunkState::Sealed);
    CHECK(snapshot.tid == fixture.thread.tid);
    CHECK(snapshot.first_sequence == 1);
    CHECK(snapshot.last_sequence == 2);
    CHECK(snapshot.committed_bytes == committed);
    CHECK(snapshot.record_count == 2);
    CHECK(snapshot.checksum == flight_checksum32(fixture.artifact.chunk_data(chunk_index),
                                                 committed));
}

void rotation_seals_old_chunk_and_increments_reclaimed_generations() {
    Fixture fixture;
    const uint8_t payload[] = {0x42};
    CHECK(fixture.writer.append(FlightRecordType::Instruction, {payload, sizeof(payload)}) ==
          FlightWriteResult::Written);
    const uint32_t old_chunk = fixture.writer.chunk_index();
    CHECK(fixture.writer.rotate());
    CHECK(fixture.writer.chunk_index() != old_chunk);
    FlightChunkSnapshot old_snapshot{};
    CHECK(fixture.artifact.read_chunk(old_chunk, &old_snapshot));
    CHECK(old_snapshot.state == FlightChunkState::Sealed);
}

struct LeaseIdentity {
    uint32_t chunk_index;
    uint32_t generation;
    uint32_t tid;
};

LeaseIdentity identity(const FlightChunkLease &lease) {
    return {lease.chunk_index, lease.generation, lease.tid};
}

bool same_lease(const LeaseIdentity &left, const LeaseIdentity &right) {
    return left.chunk_index == right.chunk_index && left.generation == right.generation &&
           left.tid == right.tid;
}

void exact_oldest_unprotected_reclamation() {
    char directory_template[] = "/tmp/qtrace-flight-fairness-XXXXXX";
    char *created = ::mkdtemp(directory_template);
    CHECK(created != nullptr);
    const std::string path = std::string(created) + "/artifact.flight.bin";
    FlightOptions options;
    options.enabled = true;
    options.capacity_bytes = 64ULL * 1024 * 1024;
    options.chunk_bytes = 1024U * 1024;
    options.max_threads = 2;
    options.protected_chunks = 4;
    FlightArtifact artifact;
    CHECK(artifact.create(path.c_str(), options, test_identity()));
    FlightThreadRegistration threads[2]{};
    CHECK(artifact.register_thread(311, &threads[0]));
    CHECK(artifact.register_thread(422, &threads[1]));

    std::vector<LeaseIdentity> allocation_order;
    uint64_t sequence = 1;
    for (uint32_t index = 0; index < artifact.chunk_count(); ++index) {
        FlightChunkLease lease{};
        CHECK(artifact.acquire_chunk(threads[index % 2U], sequence++, &lease));
        allocation_order.push_back(identity(lease));
    }
    for (uint32_t iteration = 0; iteration < 100; ++iteration) {
        std::vector<LeaseIdentity> protected_leases;
        for (const FlightThreadRegistration &thread : threads) {
            uint32_t retained = 0;
            for (auto candidate = allocation_order.rbegin();
                 candidate != allocation_order.rend() && retained < options.protected_chunks;
                 ++candidate) {
                if (candidate->tid != thread.tid) continue;
                protected_leases.push_back(*candidate);
                ++retained;
            }
            CHECK(retained == options.protected_chunks);
        }
        auto expected = allocation_order.begin();
        while (expected != allocation_order.end() &&
               std::find_if(protected_leases.begin(), protected_leases.end(),
                            [&](const LeaseIdentity &protected_lease) {
                                return same_lease(*expected, protected_lease);
                            }) != protected_leases.end()) {
            ++expected;
        }
        CHECK(expected != allocation_order.end());
        const LeaseIdentity expected_victim = *expected;

        FlightChunkLease acquired{};
        CHECK(artifact.acquire_chunk(threads[iteration % 2U], sequence++, &acquired));
        CHECK(acquired.chunk_index == expected_victim.chunk_index);
        CHECK(acquired.generation == expected_victim.generation + 1U);
        allocation_order.erase(expected);
        allocation_order.push_back(identity(acquired));

        for (const LeaseIdentity &protected_lease : protected_leases) {
            CHECK(artifact.chunk_generation(protected_lease.chunk_index) ==
                  protected_lease.generation);
            CHECK(artifact.chunk_tid(protected_lease.chunk_index) == protected_lease.tid);
        }
        for (const FlightThreadRegistration &thread : threads) {
            uint32_t retained = 0;
            for (auto candidate = allocation_order.rbegin();
                 candidate != allocation_order.rend() && retained < options.protected_chunks;
                 ++candidate) {
                if (candidate->tid != thread.tid) continue;
                CHECK(artifact.chunk_is_protected(candidate->chunk_index));
                ++retained;
            }
            uint32_t observed_protected = 0;
            for (uint32_t index = 0; index < artifact.chunk_count(); ++index) {
                if (artifact.chunk_tid(index) == thread.tid &&
                    artifact.chunk_is_protected(index)) {
                    ++observed_protected;
                }
            }
            CHECK(observed_protected == options.protected_chunks);
        }
    }
    artifact.close();
    CHECK(::unlink(path.c_str()) == 0);
    CHECK(::rmdir(created) == 0);
}

void stress_rotations(unsigned int rotations) {
    exact_oldest_unprotected_reclamation();
    char directory_template[] = "/tmp/qtrace-flight-stress-XXXXXX";
    char *created = ::mkdtemp(directory_template);
    CHECK(created != nullptr);
    const std::string path = std::string(created) + "/artifact.flight.bin";
    FlightOptions options;
    options.enabled = true;
    options.capacity_bytes = 64ULL * 1024 * 1024;
    options.chunk_bytes = 1024U * 1024;
    options.max_threads = 2;
    options.protected_chunks = 4;
    FlightArtifact artifact;
    CHECK(artifact.create(path.c_str(), options, test_identity()));
    FlightThreadRegistration first_thread{};
    FlightThreadRegistration second_thread{};
    CHECK(artifact.register_thread(111, &first_thread));
    CHECK(artifact.register_thread(222, &second_thread));
    FlightChunkWriter first_writer;
    FlightChunkWriter second_writer;
    CHECK(first_writer.initialize(&artifact, first_thread));
    CHECK(second_writer.initialize(&artifact, second_thread));
    const uint8_t payload[] = {1, 3, 3, 7};
    std::atomic<bool> start{false};
    std::atomic<bool> succeeded{true};
    std::vector<LeaseIdentity> first_leases{{first_writer.chunk_index(),
                                             first_writer.generation(),
                                             first_thread.tid}};
    std::vector<LeaseIdentity> second_leases{{second_writer.chunk_index(),
                                              second_writer.generation(),
                                              second_thread.tid}};
    auto rotate = [&](FlightChunkWriter *writer, std::vector<LeaseIdentity> *leases) {
        while (!start.load(std::memory_order_acquire)) {
        }
        for (unsigned int iteration = 0; iteration < rotations; ++iteration) {
            if (writer->append(FlightRecordType::Instruction, {payload, sizeof(payload)}) !=
                        FlightWriteResult::Written ||
                !writer->rotate()) {
                succeeded.store(false, std::memory_order_relaxed);
                return;
            }
            leases->push_back({writer->chunk_index(), writer->generation(),
                               writer == &first_writer ? first_thread.tid
                                                       : second_thread.tid});
        }
    };
    std::thread first(rotate, &first_writer, &first_leases);
    std::thread second(rotate, &second_writer, &second_leases);
    start.store(true, std::memory_order_release);
    first.join();
    second.join();
    CHECK(succeeded.load(std::memory_order_relaxed));

    uint32_t first_chunks = 0;
    uint32_t second_chunks = 0;
    uint32_t reclaimed_chunks = 0;
    std::vector<uint64_t> retained_sequences;
    for (uint32_t index = 0; index < artifact.chunk_count(); ++index) {
        FlightChunkSnapshot snapshot{};
        if (!artifact.read_chunk(index, &snapshot)) continue;
        if (snapshot.tid == first_thread.tid) ++first_chunks;
        if (snapshot.tid == second_thread.tid) ++second_chunks;
        if (snapshot.generation > 1) ++reclaimed_chunks;
        if (snapshot.state != FlightChunkState::Sealed) continue;
        CHECK(snapshot.record_count == 1);
        CHECK(snapshot.committed_bytes >= kFlightRecordHeaderBytes);
        CHECK(snapshot.checksum ==
              flight_checksum32(artifact.chunk_data(index), snapshot.committed_bytes));
        FlightDecodedRecord decoded{};
        CHECK(scan_flight_record(artifact.chunk_data(index), snapshot.committed_bytes,
                                 snapshot.generation, &decoded));
        retained_sequences.push_back(decoded.sequence);
    }
    CHECK(first_chunks >= options.protected_chunks);
    CHECK(second_chunks >= options.protected_chunks);
    auto check_latest = [&](const std::vector<LeaseIdentity> &leases) {
        CHECK(leases.size() >= options.protected_chunks);
        for (size_t offset = 0; offset < options.protected_chunks; ++offset) {
            const LeaseIdentity &lease = leases[leases.size() - 1U - offset];
            CHECK(artifact.chunk_generation(lease.chunk_index) == lease.generation);
            CHECK(artifact.chunk_tid(lease.chunk_index) == lease.tid);
            CHECK(artifact.chunk_is_protected(lease.chunk_index));
        }
    };
    check_latest(first_leases);
    check_latest(second_leases);
    if (rotations * 2U >= artifact.chunk_count()) CHECK(reclaimed_chunks != 0);
    std::sort(retained_sequences.begin(), retained_sequences.end());
    CHECK(std::adjacent_find(retained_sequences.begin(), retained_sequences.end()) ==
          retained_sequences.end());

    first_writer.detach();
    second_writer.detach();
    artifact.close();
    CHECK(::unlink(path.c_str()) == 0);
    CHECK(::rmdir(created) == 0);
}

} // namespace

int main(int argc, char **argv) {
    if (argc == 3 && std::strcmp(argv[1], "--stress-rotations") == 0) {
        const long rotations = std::strtol(argv[2], nullptr, 10);
        CHECK(rotations > 0);
        stress_rotations(static_cast<unsigned int>(rotations));
        return 0;
    }
    appends_explicit_little_endian_records_with_valid_commit_and_checksum();
    distinguishes_written_no_space_and_writer_errors();
    pair_append_preflights_both_records_before_publishing_either();
    rejects_bad_bounds_commit_checksum_and_generation();
    torn_final_record_does_not_hide_preceding_committed_record();
    seal_publishes_lengths_endpoints_counts_and_chunk_checksum();
    rotation_seals_old_chunk_and_increments_reclaimed_generations();
}
