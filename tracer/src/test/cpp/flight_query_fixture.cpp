// A 256 MiB corpus written by the production Flight encoder, with dense
// semantic payloads, instructions and memory. No decoder is duplicated here.
#include "core/instruction_cache.h"
#include "flight/flight_encoder.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

static void require(bool passed) {
    if (!passed) { std::fprintf(stderr, "flight fixture write failed\n"); std::exit(1); }
}

int main(int argc, char **argv) {
    if (argc != 2 && argc != 3) return 2;
    const uint32_t groups = argc == 3 ? std::strtoul(argv[2], nullptr, 10) : 60000;
    if (groups == 0 || groups > 100000) return 2;
    FlightOptions options{};
    options.enabled = true;
    options.capacity_bytes = 256ULL * 1024 * 1024;
    options.chunk_bytes = 16 * 1024;
    options.max_threads = 1;
    options.protected_chunks = 1;
    FlightArtifact artifact;
    require(artifact.create(argv[1], options, {0x10203040, 4242, 1, "libquery.so", 11}));
    FlightThreadRegistration registration{};
    require(artifact.register_thread(42, &registration));
    FlightChunkWriter writer;
    require(writer.initialize(&artifact, registration));
    TraceContext context{};
    context.target_so = "libquery.so";
    context.scene_name = "query";
    context.module_base = 0x71000000;
    context.target_offset = 0x88;
    context.target_address = context.module_base + context.target_offset;
    context.pid = 4242;
    context.tid = 42;
    QBDI::GPRState registers{};
    registers.pc = context.target_address;
    registers.sp = 0x7fff0000;
    FlightEncoder encoder;
    require(encoder.initialize(&writer, TraceProfile::Full, context, &registers));
    require(encoder.thread_begin(41, 42, context.target_address, 1));
    CachedInstruction decoded{};
    decoded.opcode = 0xD503201F;
    std::strcpy(decoded.mnemonic, "NOP");
    std::strcpy(decoded.disassembly, "nop");
    InstructionRecord instruction{};
    instruction.module_base = context.module_base;
    instruction.decoded = &decoded;
    MemoryRecord memory{};
    memory.kind = MemoryAccessKind::Read;
    memory.metadata_available = true;
    memory.size = 8;
    for (uint32_t index = 0; index < groups; ++index) {
        char boundary[256];
        const uintptr_t pc = context.target_address + (index % 16) * 4;
        std::snprintf(boundary, sizeof(boundary),
            "{\"schema\":1,\"id\":%u,\"phase\":\"enter\",\"address\":\"0x%lx\","
            "\"monotonicNs\":%llu,\"returnValue\":null}", index + 1, pc,
            static_cast<unsigned long long>(1000000000ULL + index * 1000000ULL));
        require(encoder.rule("qtrace.scene", boundary));
        instruction.sequence = index + 1;
        instruction.pc = pc;
        require(encoder.instruction(context, instruction));
        memory.address = 0x220000 + (index % 16) * 8;
        require(encoder.memory(context, pc, memory));
        const std::string detail = std::to_string(index) + ":" + std::string(3000, char('a' + index % 26));
        require(encoder.call(index % 2 ? "native" : "jni", "helper", detail));
        std::snprintf(boundary, sizeof(boundary),
            "{\"schema\":1,\"id\":%u,\"phase\":\"return\",\"address\":\"0x%lx\","
            "\"monotonicNs\":%llu,\"returnValue\":\"0x2a\"}", index + 1, pc,
            static_cast<unsigned long long>(1000500000ULL + index * 1000000ULL));
        require(encoder.rule("qtrace.scene", boundary));
    }
    require(encoder.thread_end(42));
    require(writer.seal());
    writer.detach();
    artifact.close();
    std::printf("{\"capacity_bytes\":268435456,\"groups\":%u,\"instructions\":%u,"
                "\"memory\":%u,\"calls\":%u,\"scene_boundaries\":%u}\n", groups, groups, groups, groups, groups * 2);
}
