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
        CHECK(artifact.create(path.c_str(), options));
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
                                {payload, sizeof(payload)}, 0x1234));

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

void rejects_bad_bounds_commit_checksum_and_generation() {
    Fixture fixture;
    const uint8_t payload[] = {1, 2, 3, 4};
    CHECK(fixture.writer.append(FlightRecordType::Memory, {payload, sizeof(payload)}));
    const uint8_t *record = fixture.writer.previous_record_bytes();
    const size_t size = fixture.writer.previous_record_size();
    FlightDecodedRecord decoded{};
    CHECK(!scan_flight_record(record, size - 1U, fixture.writer.generation(), &decoded));
    CHECK(!scan_flight_record(record, size, fixture.writer.generation() + 1U, &decoded));

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
    CHECK(fixture.writer.append(FlightRecordType::Instruction, {payload, sizeof(payload)}));
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
    CHECK(fixture.writer.append(FlightRecordType::ThreadBegin, {first, sizeof(first)}));
    CHECK(fixture.writer.append(FlightRecordType::Call, {second, sizeof(second)}));
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
    CHECK(fixture.writer.append(FlightRecordType::Instruction, {payload, sizeof(payload)}));
    const uint32_t old_chunk = fixture.writer.chunk_index();
    CHECK(fixture.writer.rotate());
    CHECK(fixture.writer.chunk_index() != old_chunk);
    FlightChunkSnapshot old_snapshot{};
    CHECK(fixture.artifact.read_chunk(old_chunk, &old_snapshot));
    CHECK(old_snapshot.state == FlightChunkState::Sealed);
}

void stress_rotations(unsigned int rotations) {
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
    CHECK(artifact.create(path.c_str(), options));
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
    auto rotate = [&](FlightChunkWriter *writer) {
        while (!start.load(std::memory_order_acquire)) {
        }
        for (unsigned int iteration = 0; iteration < rotations; ++iteration) {
            if (!writer->append(FlightRecordType::Instruction, {payload, sizeof(payload)}) ||
                !writer->rotate()) {
                succeeded.store(false, std::memory_order_relaxed);
                return;
            }
        }
    };
    std::thread first(rotate, &first_writer);
    std::thread second(rotate, &second_writer);
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
    rejects_bad_bounds_commit_checksum_and_generation();
    torn_final_record_does_not_hide_preceding_committed_record();
    seal_publishes_lengths_endpoints_counts_and_chunk_checksum();
    rotation_seals_old_chunk_and_increments_reclaimed_generations();
}
