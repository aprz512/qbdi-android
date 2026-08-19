#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

constexpr size_t kArm64RegisterCount = 34;
constexpr size_t kMaxCapturedMemoryBytes = 64;

struct RegisterSnapshot {
    std::array<uint64_t, kArm64RegisterCount> values{};
};

enum class MemoryIndexExtend : uint8_t { None, Uxtw, Sxtw, Lsl, Sxtx };
enum class MemoryAddressMode : uint8_t { Offset, PreIndex, PostIndex };
enum class MemoryAccessKind : uint8_t { Read = 1, Write = 2, ReadWrite = 3 };
enum class MemoryBytesState : uint8_t { NotCaptured, Available, Unavailable };

struct MemoryBytes {
    std::array<uint8_t, kMaxCapturedMemoryBytes> data{};
    uint8_t size = 0;
    MemoryBytesState state = MemoryBytesState::NotCaptured;
};

using MemoryReadFunction = bool (*)(uintptr_t, void *, size_t);

size_t bounded_memory_capture_size(size_t access_size, size_t configured_limit) noexcept;
void capture_memory_bytes(uintptr_t address, size_t access_size, size_t configured_limit,
                          MemoryReadFunction reader, MemoryBytes *capture) noexcept;
uint64_t truncate_memory_value(uint64_t value, uint32_t access_size,
                               uint16_t access_flags) noexcept;

struct MemoryOperand {
    static constexpr uint8_t kNoRegister = UINT8_MAX;

    uint8_t base_reg = kNoRegister;
    uint8_t index_reg = kNoRegister;
    MemoryIndexExtend extend = MemoryIndexExtend::None;
    MemoryAddressMode address_mode = MemoryAddressMode::Offset;
    uint8_t shift = 0;
    MemoryAccessKind kind = MemoryAccessKind::Read;
    uint32_t access_size = 0;
    int64_t displacement = 0;
    bool writeback = false;

    bool try_effective_address(const RegisterSnapshot &registers,
                               uintptr_t *address) const noexcept;
    uintptr_t effective_address(const RegisterSnapshot &registers) const noexcept;
    uintptr_t writeback_address(const RegisterSnapshot &registers) const noexcept;
};

enum class InstructionFlags : uint32_t {
    None = 0,
    Branch = 1U << 0U,
    PcRelative = 1U << 1U,
    Call = 1U << 2U,
    Return = 1U << 3U,
};

constexpr InstructionFlags operator|(InstructionFlags left, InstructionFlags right) {
    return static_cast<InstructionFlags>(static_cast<uint32_t>(left) | static_cast<uint32_t>(right));
}

struct CachedInstruction {
    static constexpr size_t kGprCount = kArm64RegisterCount;
    static constexpr size_t kRegisterNameBytes = 16;
    static constexpr size_t kMaxMemoryOperands = 4;

    uint32_t opcode = 0;
    uint64_t read_gpr_mask = 0;
    uint64_t write_gpr_mask = 0;
    uint8_t read_gpr_widths[kGprCount]{};
    uint8_t write_gpr_widths[kGprCount]{};
    int32_t pc_relative_displacement = 0;
    uint8_t condition = 0;
    InstructionFlags flags = InstructionFlags::None;
    char mnemonic[16]{};
    char operands[96]{};
    char disassembly[112]{};
    char read_register_names[kGprCount][kRegisterNameBytes]{};
    char write_register_names[kGprCount][kRegisterNameBytes]{};
    MemoryOperand memory_operands[kMaxMemoryOperands]{};
    uint8_t memory_operand_count = 0;
    bool requires_slow_memory_path = false;

    uintptr_t absolute_branch_target(uintptr_t pc) const;
};

bool cache_memory_operand(CachedInstruction *instruction,
                          const MemoryOperand &operand) noexcept;
bool decode_arm64_memory_operands(CachedInstruction *instruction, uint32_t opcode,
                                  bool may_load, bool may_store, uint32_t load_size,
                                  uint32_t store_size) noexcept;

bool arm64_branch_displacement(int64_t instruction_units, int32_t *byte_displacement) noexcept;
void cache_gpr_access(CachedInstruction *instruction, size_t index, const char *register_name,
                      uint8_t width_bytes, bool reads, bool writes) noexcept;

struct InstructionView {
    uintptr_t address = 0;
    const CachedInstruction *decoded = nullptr;
};

struct InstructionCacheMetrics {
    uint64_t hits = 0;
    uint64_t misses = 0;
    uint64_t collisions = 0;
};

class InstructionCache {
public:
    using Decoder = bool (*)(uint32_t opcode, void *data,
                             CachedInstruction *instruction) noexcept;

    static constexpr uint32_t kPreferredSlotCount = 1U << 22U;

    explicit InstructionCache(uint32_t requested_slot_count = kPreferredSlotCount) noexcept;
    ~InstructionCache();

    InstructionCache(const InstructionCache &) = delete;
    InstructionCache &operator=(const InstructionCache &) = delete;

    bool enabled() const { return slots_ != nullptr; }
    uint32_t slot_count() const { return slot_count_; }
    uint32_t metadata_chunk_count() const { return metadata_chunk_count_; }
    const InstructionCacheMetrics &metrics() const { return metrics_; }

    const CachedInstruction *find(uint32_t opcode) noexcept;
    const CachedInstruction *insert(const CachedInstruction &instruction) noexcept;
    const CachedInstruction *populate_after_miss(
            const CachedInstruction &instruction) noexcept;
    const CachedInstruction *resolve(uint32_t opcode, Decoder decoder, void *decoder_data,
                                     CachedInstruction *scratch) noexcept;

private:
    struct Slot {
        uint32_t opcode;
        uint32_t entry_plus_one;
    };

    struct MetadataChunk;

    static constexpr uint32_t kFallbackSlotCount = 1U << 20U;
    static constexpr uint32_t kMinimumSlotCount = 1U << 18U;
    static constexpr uint32_t kMetadataEntriesPerChunk = 4096;

    static bool is_power_of_two(uint32_t value);
    static uint32_t slot_index(uint32_t opcode, uint32_t mask);

    bool allocate_slots(uint32_t count) noexcept;
    CachedInstruction *allocate_entry() noexcept;
    CachedInstruction *entry(uint32_t entry_plus_one) noexcept;
    const CachedInstruction *entry(uint32_t entry_plus_one) const noexcept;
    const CachedInstruction *store(const CachedInstruction &instruction) noexcept;

    Slot *slots_ = nullptr;
    uint32_t slot_count_ = 0;
    uint32_t next_entry_index_ = 0;
    std::size_t slots_mapping_size_ = 0;
    MetadataChunk **metadata_chunk_index_ = nullptr;
    uint32_t metadata_chunk_index_size_ = 0;
    uint32_t metadata_chunk_count_ = 0;
    std::size_t metadata_chunk_index_mapping_size_ = 0;
    InstructionCacheMetrics metrics_{};
};
