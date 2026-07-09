#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct TraceContext {
    std::string package_name;
    std::string scene_name;
    std::string target_so;
    uintptr_t module_base = 0;
    uintptr_t target_offset = 0;
    uintptr_t target_address = 0;
    int pid = 0;
    int tid = 0;
};

struct MemoryAccessText {
    char type = 'r';
    uintptr_t address = 0;
    uint32_t size = 0;
    uint64_t value = 0;
};

struct InstructionText {
    uint64_t sequence = 0;
    uintptr_t pc = 0;
    std::string disassembly;
    std::string reads;
    std::string writes;
    std::vector<MemoryAccessText> memory;
};
