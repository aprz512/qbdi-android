#include "demo_target/flight_acceptance_protocol.h"

#include <array>
#include <cstdio>
#include <cstdlib>

namespace {

void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

void start_is_nonblocking_and_snapshot_requires_release_ordering() {
    FlightAcceptanceProtocol protocol;
    const uint64_t generation = protocol.start(101, 0, 3);
    CHECK(generation != 0);

    DemoFlightAcceptanceSnapshot snapshot{};
    CHECK(!protocol.snapshot(&snapshot));
    CHECK(!protocol.release(generation));

    std::array<uint32_t, kDemoFlightAcceptanceWorkers> tids{};
    for (size_t index = 0; index < tids.size(); ++index) {
        tids[index] = 31000U + static_cast<uint32_t>(index);
    }
    CHECK(protocol.publish_ready(generation, 31003, 0x1234, 0x17, 4,
                                 tids.data(), tids.size()));
    CHECK(protocol.snapshot(&snapshot));
    CHECK(snapshot.generation == generation);
    CHECK(snapshot.seed == 101);
    CHECK(snapshot.mode == 0);
    CHECK(snapshot.selected_worker == 3);
    CHECK(snapshot.selected_tid == 31003);
    CHECK(snapshot.original_pc == 0x1234);
    CHECK(snapshot.probe == 0x17);
    CHECK(snapshot.worker_count == kDemoFlightAcceptanceWorkers);
    CHECK(snapshot.rotations == 4);
    CHECK(snapshot.state == kDemoFlightAcceptanceReady);
    CHECK(!protocol.released(generation));
    CHECK(!protocol.release(generation + 1));
    CHECK(protocol.release(generation));
    CHECK(protocol.released(generation));
}

void new_start_invalidates_old_snapshot_and_release() {
    FlightAcceptanceProtocol protocol;
    const uint64_t first = protocol.start(101, 0, 3);
    std::array<uint32_t, kDemoFlightAcceptanceWorkers> tids{};
    CHECK(protocol.publish_ready(first, 7, 0x1234, 0x17, 5,
                                 tids.data(), tids.size()));
    const uint64_t second = protocol.start(202, 1, 4);
    CHECK(second > first);
    DemoFlightAcceptanceSnapshot snapshot{};
    CHECK(!protocol.snapshot(&snapshot));
    CHECK(!protocol.release(first));
    CHECK(!protocol.publish_ready(first, 7, 0x1234, 0x17, 5,
                                  tids.data(), tids.size()));
}

void external_sigkill_publishes_no_initiator_or_pc() {
    FlightAcceptanceProtocol protocol;
    const uint64_t generation = protocol.start(505, 4, 0);
    std::array<uint32_t, kDemoFlightAcceptanceWorkers> tids{};
    for (size_t index = 0; index < tids.size(); ++index) {
        tids[index] = 32000U + static_cast<uint32_t>(index);
    }
    CHECK(protocol.publish_ready(generation, 0, 0, 0x17, 5,
                                 tids.data(), tids.size()));
    DemoFlightAcceptanceSnapshot snapshot{};
    CHECK(protocol.snapshot(&snapshot));
    CHECK(snapshot.selected_tid == 0);
    CHECK(snapshot.original_pc == 0);
}

}  // namespace

int main() {
    start_is_nonblocking_and_snapshot_requires_release_ordering();
    new_start_invalidates_old_snapshot_and_release();
    external_sigkill_publishes_no_initiator_or_pc();
}
