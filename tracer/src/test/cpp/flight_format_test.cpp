#include "flight/flight_format.h"

#include <cstdio>
#include <cstdlib>
#include <type_traits>

static void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

int main() {
    CHECK(kFlightMagic == 0x51464c54U);
    CHECK(kFlightVersion == 1);
    CHECK(sizeof(FlightSuperblock) == kFlightSuperblockBytes);
    CHECK(sizeof(FlightDirectoryEntry) == kFlightDirectoryEntryBytes);
    CHECK(sizeof(FlightChunkHeader) == kFlightChunkHeaderBytes);
    CHECK(sizeof(FlightRecordHeader) == kFlightRecordHeaderBytes);
    CHECK(sizeof(FlightEmergencyRecord) == kFlightEmergencyRecordBytes);
    CHECK(static_cast<uint16_t>(FlightRecordType::ChunkBegin) == 1);
    CHECK(static_cast<uint16_t>(FlightRecordType::SignalHandlerBegin) == 12);
    CHECK(static_cast<uint16_t>(FlightRecordType::SignalHandlerReturn) == 13);
    CHECK(static_cast<uint16_t>(FlightRecordType::TerminationIntent) == 14);
    CHECK(static_cast<uint16_t>(FlightRecordType::CoverageGap) == 15);
    CHECK(std::is_trivially_copyable_v<FlightSuperblock>);
    CHECK(std::is_trivially_copyable_v<FlightDirectoryEntry>);
    CHECK(std::is_trivially_copyable_v<FlightChunkHeader>);
    CHECK(std::is_trivially_copyable_v<FlightRecordHeader>);
    CHECK(std::is_trivially_copyable_v<FlightEmergencyRecord>);
    CHECK(std::is_trivial_v<FlightSuperblock>);
    CHECK(std::is_trivial_v<FlightDirectoryEntry>);
    CHECK(std::is_trivial_v<FlightChunkHeader>);
    CHECK(std::is_trivial_v<FlightRecordHeader>);
    CHECK(std::is_trivial_v<FlightEmergencyRecord>);
}
