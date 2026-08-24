#include "core/signal_broker.h"
#include "core/instruction_collector.h"

#include "flight/flight_artifact.h"

#include <array>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <unistd.h>

namespace QBDI {

const InstAnalysis *VM::getInstAnalysis(AnalysisType) const { return nullptr; }
std::vector<MemoryAccess> VM::getInstMemoryAccess() const { return {}; }

} // namespace QBDI

namespace {

void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

struct Fixture {
    Fixture() {
        char directory_template[] = "/tmp/qtrace-termination-XXXXXX";
        char *created = ::mkdtemp(directory_template);
        CHECK(created != nullptr);
        directory = created;
        path = directory + "/artifact.flight.bin";
        FlightOptions options{};
        options.enabled = true;
        options.capacity_bytes = 8ULL * 1024U * 1024U;
        options.chunk_bytes = 256U * 1024U;
        options.max_threads = 2;
        options.protected_chunks = 1;
        static constexpr char target[] = "libtarget.so";
        const FlightArtifactIdentityView identity{
                0x87654321U, 4242, 9, target,
                static_cast<uint16_t>(sizeof(target) - 1U)};
        CHECK(artifact.create(path.c_str(), options, identity));
        CHECK(artifact.register_thread(731, &registration));
        CHECK(writer.initialize(731, &artifact, registration, &gpr));
    }

    ~Fixture() {
        artifact.close();
        (void)::unlink(path.c_str());
        (void)::rmdir(directory.c_str());
    }

    std::string directory;
    std::string path;
    FlightArtifact artifact;
    FlightThreadRegistration registration{};
    SignalBrokerThreadState writer{};
    QBDI::GPRState gpr{};
};

void arm64_termination_intent_is_committed_before_continue() {
    constexpr std::array<int64_t, 6> terminating{93, 94, 129, 130, 131, 138};
    Fixture fixture;
    uint64_t previous_sequence = 0;
    for (const int64_t number : terminating) {
        Arm64SyscallSnapshot snapshot{};
        snapshot.pc = 0x71000000U + static_cast<uintptr_t>(number) * 4U;
        snapshot.number = number;
        snapshot.args = {0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U};
        CHECK(TerminationObserver::before_svc(snapshot, &fixture.writer) ==
              QBDI::CONTINUE);
        FlightEmergencyRecord record{};
        const uint8_t *slot = fixture.artifact.emergency_bytes(
                fixture.registration.directory_index);
        if (number == 138) {
            FlightEmergencyRecord cells[2]{};
            bool valid[2]{};
            for (size_t index = 0; index < 2; ++index) {
                std::array<uint8_t, kFlightEmergencySlotBytes> isolated{};
                std::memcpy(isolated.data(),
                            slot + index * kFlightEmergencyRecordBytes,
                            kFlightEmergencyRecordBytes);
                valid[index] =
                        scan_flight_emergency(isolated.data(), &cells[index]);
            }
            bool found_intent = false;
            bool found_gap = false;
            for (size_t index = 0; index < 2; ++index) {
                if (!valid[index]) continue;
                if (cells[index].type == static_cast<uint32_t>(
                                                 FlightRecordType::TerminationIntent) &&
                    cells[index].signal_number == 138) {
                    record = cells[index];
                    found_intent = true;
                }
                found_gap |= cells[index].type == static_cast<uint32_t>(
                                                       FlightRecordType::CoverageGap);
            }
            CHECK(found_intent);
            CHECK(found_gap);
            CHECK(fixture.artifact.incomplete());
        } else {
            CHECK(scan_flight_emergency(slot, &record));
        }
        CHECK(record.type ==
              static_cast<uint32_t>(FlightRecordType::TerminationIntent));
        CHECK(record.tid == 731);
        CHECK(record.sequence > previous_sequence);
        CHECK(record.pc == snapshot.pc);
        CHECK(record.sp == snapshot.args[0]);
        CHECK(record.fault_address == snapshot.args[1]);
        CHECK(record.signal_number == static_cast<uint32_t>(number));
        CHECK(record.signal_code == static_cast<uint32_t>(snapshot.args[2]));
        previous_sequence = record.sequence;
    }
}

void nontermination_syscalls_continue_without_overwriting_evidence() {
    Fixture fixture;
    Arm64SyscallSnapshot terminal{};
    terminal.pc = 0x71001000U;
    terminal.number = 94;
    CHECK(TerminationObserver::before_svc(terminal, &fixture.writer) ==
          QBDI::CONTINUE);
    FlightEmergencyRecord before{};
    CHECK(scan_flight_emergency(
            fixture.artifact.emergency_bytes(fixture.registration.directory_index),
            &before));

    Arm64SyscallSnapshot ordinary{};
    ordinary.pc = 0x71002000U;
    ordinary.number = 64;
    CHECK(TerminationObserver::before_svc(ordinary, &fixture.writer) ==
          QBDI::CONTINUE);
    FlightEmergencyRecord after{};
    CHECK(scan_flight_emergency(
            fixture.artifact.emergency_bytes(fixture.registration.directory_index),
            &after));
    CHECK(after.sequence == before.sequence);
    CHECK(after.pc == before.pc);
}

void instruction_preinst_commits_termination_before_returning_continue() {
    Fixture fixture;
    alignas(uint32_t) uint32_t svc = 0xd4000001U;
    QBDI::GPRState gpr{};
    gpr.pc = reinterpret_cast<uintptr_t>(&svc);
    gpr.x8 = 94;
    gpr.x0 = 0x77U;
    TraceOptions options{};
    ModuleRange module{};
    module.start = gpr.pc;
    module.end = gpr.pc + sizeof(svc);
    InstructionCollector collector(nullptr, nullptr, nullptr, nullptr, nullptr,
                                   options, module, nullptr, &fixture.writer);

    CHECK(collector.on_pre(nullptr, &gpr, nullptr) == QBDI::CONTINUE);
    FlightEmergencyRecord record{};
    CHECK(scan_flight_emergency(
            fixture.artifact.emergency_bytes(fixture.registration.directory_index),
            &record));
    CHECK(record.type ==
          static_cast<uint32_t>(FlightRecordType::TerminationIntent));
    CHECK(record.pc == reinterpret_cast<uintptr_t>(&svc));
    CHECK(record.sp == 0x77U);
}

void termination_publication_failure_is_durable_before_continue() {
    Fixture fixture;
    CHECK(fixture.artifact.test_claim_emergency_slot(
            fixture.registration.directory_index));
    Arm64SyscallSnapshot snapshot{};
    snapshot.pc = 0x71003000U;
    snapshot.number = 94;

    CHECK(TerminationObserver::before_svc(snapshot, &fixture.writer) ==
          QBDI::CONTINUE);

    CHECK((fixture.artifact.flags() & static_cast<uint32_t>(
                                              FlightIncompleteReason::EmergencyFailure)) !=
          0);
    FlightEmergencyRecord absent{};
    CHECK(!scan_flight_emergency(
            fixture.artifact.emergency_bytes(fixture.registration.directory_index),
            &absent));
    fixture.artifact.test_release_emergency_slot(
            fixture.registration.directory_index);
}

} // namespace

int main() {
    arm64_termination_intent_is_committed_before_continue();
    nontermination_syscalls_continue_without_overwriting_evidence();
    instruction_preinst_commits_termination_before_returning_continue();
    termination_publication_failure_is_durable_before_continue();
}
