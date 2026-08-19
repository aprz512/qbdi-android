#include "events/trace_encoder.h"
#include "events/trace_number_formatter.h"

#include <algorithm>
#include <limits>

namespace {

struct AppendBuffer {
    char *cursor = nullptr;
    char *end = nullptr;
    size_t required = 0;
    bool count_only = true;
    bool ok = true;
};

bool append_bytes(AppendBuffer &buffer, const char *data, size_t size) noexcept {
    if (size > std::numeric_limits<size_t>::max() - buffer.required) {
        buffer.ok = false;
        buffer.required = 0;
        return false;
    }
    if (!buffer.count_only && static_cast<size_t>(buffer.end - buffer.cursor) < size) {
        buffer.ok = false;
        return false;
    }
    if (!buffer.count_only) {
        for (size_t index = 0; index < size; ++index) buffer.cursor[index] = data[index];
        buffer.cursor += size;
    }
    buffer.required += size;
    return true;
}

bool append_char(AppendBuffer &buffer, char value) noexcept {
    return append_bytes(buffer, &value, 1);
}

bool append_literal(AppendBuffer &buffer, std::string_view value) noexcept {
    return append_bytes(buffer, value.data(), value.size());
}

bool append_hex_u64(AppendBuffer &buffer, uint64_t value) noexcept {
    char digits[16];
    size_t count = 0;
    do {
        const uint8_t digit = static_cast<uint8_t>(value & 0xfU);
        digits[count++] = static_cast<char>(digit < 10U ? '0' + digit : 'a' + (digit - 10U));
        value >>= 4U;
    } while (value != 0);
    while (count != 0) {
        if (!append_char(buffer, digits[--count])) return false;
    }
    return true;
}

bool append_dec_u64(AppendBuffer &buffer, uint64_t value) noexcept {
    char digits[20];
    size_t count = 0;
    do {
        digits[count++] = static_cast<char>('0' + (value % 10U));
        value /= 10U;
    } while (value != 0);
    while (count != 0) {
        if (!append_char(buffer, digits[--count])) return false;
    }
    return true;
}

bool append_dec_i64(AppendBuffer &buffer, int value) noexcept {
    if (value < 0) {
        if (!append_char(buffer, '-')) return false;
        return append_dec_u64(buffer, static_cast<uint64_t>(-(static_cast<int64_t>(value))));
    }
    return append_dec_u64(buffer, static_cast<uint64_t>(value));
}

bool append_hex_prefix(AppendBuffer &buffer, uint64_t value) noexcept {
    return append_literal(buffer, "0x") && append_hex_u64(buffer, value);
}

size_t bounded_length(const char *value, size_t maximum) noexcept {
    size_t length = 0;
    while (length < maximum && value[length] != '\0') ++length;
    return length;
}

bool append_c_string(AppendBuffer &buffer, const char *value, size_t maximum) noexcept {
    return append_bytes(buffer, value, bounded_length(value, maximum));
}

bool append_register_name(AppendBuffer &buffer, const InstructionRecord &record,
                          size_t index, bool write) noexcept {
    const char *name = write ? record.write_register_names[index]
                             : record.read_register_names[index];
    if (name != nullptr && name[0] != '\0') {
        return append_c_string(buffer, name, kMaxRegisterNameBytes);
    }
    return append_char(buffer, 'X') && append_dec_u64(buffer, index);
}

bool append_memory_type(AppendBuffer &buffer, const MemoryRecord &memory) noexcept {
    switch (memory.access_type) {
        case 1: return append_char(buffer, 'r');
        case 2: return append_char(buffer, 'w');
        case 3: return append_literal(buffer, "rw");
        default: return append_char(buffer, memory.type);
    }
}

bool append_memory_bytes(AppendBuffer &buffer, const char *label,
                         const MemoryBytes &bytes) noexcept {
    if (bytes.state == MemoryBytesState::NotCaptured) return true;
    if (!append_char(buffer, ' ') || !append_literal(buffer, label) ||
        !append_char(buffer, '=')) {
        return false;
    }
    if (bytes.state == MemoryBytesState::Unavailable) {
        return append_literal(buffer, "<unavailable>");
    }
    const size_t size = std::min(static_cast<size_t>(bytes.size),
                                 kMaxCapturedMemoryBytes);
    for (size_t index = 0; index < size; ++index) {
        const uint8_t value = bytes.data[index];
        const uint8_t high = value >> 4U;
        const uint8_t low = value & 0xfU;
        if (!append_char(buffer, static_cast<char>(high < 10U ? '0' + high
                                                              : 'a' + high - 10U)) ||
            !append_char(buffer, static_cast<char>(low < 10U ? '0' + low
                                                             : 'a' + low - 10U))) {
            return false;
        }
    }
    return true;
}

bool append_memory_details(AppendBuffer &buffer,
                           const MemoryRecord &memory) noexcept {
    if (memory.access_type != 0 || memory.flags != 0 ||
        memory.before.state != MemoryBytesState::NotCaptured ||
        memory.after.state != MemoryBytesState::NotCaptured) {
        if (!append_literal(buffer, " flags=0x") ||
            !append_hex_u64(buffer, memory.flags) ||
            !append_memory_bytes(buffer, "pre", memory.before) ||
            !append_memory_bytes(buffer, "post", memory.after)) {
            return false;
        }
    }
    return true;
}

const char *profile_name(TraceProfile profile) noexcept {
    switch (profile) {
        case TraceProfile::Fast: return "fast";
        case TraceProfile::Balanced: return "balanced";
        case TraceProfile::Full: return "full";
    }
    return "fast";
}

bool append_rate(AppendBuffer &buffer, unsigned __int128 numerator,
                 unsigned __int128 denominator) noexcept {
    char formatted[kMaxFixedSixBytes];
    const FixedSixResult result =
        format_fixed_six(formatted, sizeof(formatted), numerator, denominator);
    return result.ok && append_bytes(buffer, formatted, result.size);
}

template <typename Emit>
EncodeResult encode_atomic(char *output, size_t capacity, size_t maximum_size, Emit emit) noexcept {
    AppendBuffer count{};
    emit(count);
    if (!count.ok) return {};
    if (count.required > capacity || count.required > maximum_size ||
        (count.required != 0 && output == nullptr)) {
        return {false, count.required};
    }

    AppendBuffer write{output, output + capacity, 0, false, true};
    emit(write);
    if (!write.ok) return {false, write.required};
    return {true, write.required};
}

bool append_instruction(AppendBuffer &buffer, const char *module_name,
                        const InstructionRecord &record) noexcept {
    const char *module = module_name == nullptr ? "<unknown>" : module_name;
    if (!append_dec_u64(buffer, record.sequence) || !append_char(buffer, ' ') ||
        !append_c_string(buffer, module, kMaxInstructionLineBytes) || !append_char(buffer, '+') ||
        !append_hex_prefix(buffer, static_cast<uint64_t>(record.pc - record.module_base)) ||
        !append_char(buffer, ' ')) {
        return false;
    }

    if (record.decoded == nullptr) {
        if (!append_literal(buffer, "<undecoded>")) return false;
    } else {
        const size_t mnemonic_size = bounded_length(record.decoded->mnemonic,
                                                    sizeof(record.decoded->mnemonic));
        const size_t operands_size = bounded_length(record.decoded->operands,
                                                    sizeof(record.decoded->operands));
        const size_t disassembly_size = bounded_length(record.decoded->disassembly,
                                                       sizeof(record.decoded->disassembly));
        if (mnemonic_size != 0) {
            if (!append_bytes(buffer, record.decoded->mnemonic, mnemonic_size)) return false;
            if (operands_size != 0 &&
                (!append_char(buffer, ' ') ||
                 !append_bytes(buffer, record.decoded->operands, operands_size))) {
                return false;
            }
        } else if (disassembly_size != 0) {
            if (!append_bytes(buffer, record.decoded->disassembly, disassembly_size)) return false;
        } else if (!append_literal(buffer, "<undecoded>")) {
            return false;
        }

        bool has_reads = false;
        for (size_t index = 0; index < kTraceGprCount; ++index) {
            if ((record.decoded->read_gpr_mask & (1ULL << index)) == 0) continue;
            if (!has_reads) {
                if (!append_literal(buffer, " | R:")) return false;
                has_reads = true;
            } else if (!append_char(buffer, ' ')) {
                return false;
            }
            if (!append_register_name(buffer, record, index, false) ||
                !append_literal(buffer, "=0x") ||
                !append_hex_u64(buffer, record.before[index])) {
                return false;
            }
        }

        bool has_writes = false;
        for (size_t index = 0; index < kTraceGprCount; ++index) {
            if ((record.decoded->write_gpr_mask & (1ULL << index)) == 0) continue;
            if (!has_writes) {
                if (!append_literal(buffer, " | W:")) return false;
                has_writes = true;
            } else if (!append_char(buffer, ' ')) {
                return false;
            }
            if (!append_register_name(buffer, record, index, true) ||
                !append_literal(buffer, "=0x") ||
                !append_hex_u64(buffer, record.after[index])) {
                return false;
            }
        }
    }

    const size_t memory_count = std::min(static_cast<size_t>(record.memory_count), kMaxMemoryRecords);
    for (size_t index = 0; index < memory_count; ++index) {
        const MemoryRecord &memory = record.memory[index];
        if (!append_literal(buffer, " | MEM:") || !append_memory_type(buffer, memory) ||
            !append_literal(buffer, " addr=0x") || !append_hex_u64(buffer, memory.address) ||
            !append_literal(buffer, " size=") || !append_dec_u64(buffer, memory.size) ||
            !append_literal(buffer, " value=0x") || !append_hex_u64(buffer, memory.value) ||
            !append_memory_details(buffer, memory)) {
            return false;
        }
        const size_t hexdump_size = std::min(static_cast<size_t>(memory.hexdump_size), kMaxHexdumpBytes);
        if (hexdump_size != 0 && !append_literal(buffer, " hex=")) return false;
        for (size_t byte = 0; byte < hexdump_size; ++byte) {
            const uint8_t value = memory.hexdump[byte];
            const char high = static_cast<char>((value >> 4U) < 10U ? '0' + (value >> 4U)
                                                                       : 'a' + ((value >> 4U) - 10U));
            const uint8_t low_nibble = static_cast<uint8_t>(value & 0xfU);
            const char low = static_cast<char>(low_nibble < 10U ? '0' + low_nibble
                                                                : 'a' + (low_nibble - 10U));
            if (!append_char(buffer, high) || !append_char(buffer, low)) return false;
        }
    }
    return append_char(buffer, '\n');
}

bool append_memory(AppendBuffer &buffer, const char *module_name, uintptr_t relative_pc,
                   const MemoryRecord &record) noexcept {
    const char *module = module_name == nullptr ? "<unknown>" : module_name;
    return append_literal(buffer, "MEM ") &&
           append_c_string(buffer, module, kMaxInstructionLineBytes) &&
           append_literal(buffer, "+0x") && append_hex_u64(buffer, relative_pc) &&
           append_literal(buffer, " type=") && append_memory_type(buffer, record) &&
           append_literal(buffer, " addr=0x") && append_hex_u64(buffer, record.address) &&
           append_literal(buffer, " size=") && append_dec_u64(buffer, record.size) &&
           append_literal(buffer, " value=0x") && append_hex_u64(buffer, record.value) &&
           append_memory_details(buffer, record) &&
           append_char(buffer, '\n');
}

} // namespace

EncodeResult TraceEncoder::encode_instruction(char *output, size_t capacity, const char *module_name,
                                              const InstructionRecord &record) const noexcept {
    return encode_atomic(output, capacity, kMaxInstructionLineBytes, [&](AppendBuffer &buffer) {
        return append_instruction(buffer, module_name, record);
    });
}

EncodeResult TraceEncoder::encode_memory(char *output, size_t capacity, const char *module_name,
                                         uintptr_t relative_pc,
                                         const MemoryRecord &record) const noexcept {
    return encode_atomic(output, capacity, kMaxInstructionLineBytes, [&](AppendBuffer &buffer) {
        return append_memory(buffer, module_name, relative_pc, record);
    });
}

EncodeResult TraceEncoder::encode_begin(char *output, size_t capacity, const TraceContext &context,
                                        TraceProfile profile, bool compression_enabled,
                                        size_t effective_buffer_bytes) const noexcept {
    return encode_atomic(output, capacity, std::numeric_limits<size_t>::max(), [&](AppendBuffer &buffer) {
        return append_literal(buffer, "TRACE_BEGIN format=2 scene=") &&
               append_literal(buffer, context.scene_name) && append_literal(buffer, " target=") &&
               append_literal(buffer, context.target_so) && append_literal(buffer, "+0x") &&
               append_hex_u64(buffer, context.target_offset) && append_literal(buffer, " base=0x") &&
               append_hex_u64(buffer, context.module_base) && append_literal(buffer, " address=0x") &&
               append_hex_u64(buffer, context.target_address) && append_literal(buffer, " pid=") &&
               append_dec_i64(buffer, context.pid) && append_literal(buffer, " tid=") &&
               append_dec_i64(buffer, context.tid) && append_literal(buffer, " profile=") &&
               append_literal(buffer, profile_name(profile)) && append_literal(buffer, " compression=") &&
               append_char(buffer, compression_enabled ? '1' : '0') &&
               append_literal(buffer, " effective_buffer_bytes=") &&
               append_dec_u64(buffer, effective_buffer_bytes) && append_char(buffer, '\n');
    });
}

EncodeResult TraceEncoder::encode_end(char *output, size_t capacity, bool ok, uint64_t return_value,
                                      uint64_t elapsed_ms, const TraceMetrics &metrics) const noexcept {
    return encode_atomic(output, capacity, std::numeric_limits<size_t>::max(), [&](AppendBuffer &buffer) {
        return append_literal(buffer, "TRACE_END status=") &&
               append_literal(buffer, ok ? "ok" : "failed") && append_literal(buffer, " ret=0x") &&
               append_hex_u64(buffer, return_value) && append_literal(buffer, " elapsed_ms=") &&
               append_dec_u64(buffer, elapsed_ms) && append_literal(buffer, " instructions=") &&
               append_dec_u64(buffer, metrics.instructions) && append_literal(buffer, " raw_bytes=") &&
               append_dec_u64(buffer, metrics.raw_bytes) && append_literal(buffer, " cache_hit_rate=") &&
               append_rate(buffer, metrics.cache_hits,
                           static_cast<unsigned __int128>(metrics.cache_hits) + metrics.cache_misses) &&
               append_literal(buffer, " buffer_swaps=") && append_dec_u64(buffer, metrics.buffer_swaps) &&
               append_literal(buffer, " producer_waits=") && append_dec_u64(buffer, metrics.producer_waits) &&
               append_literal(buffer, " producer_wait_ns=") && append_dec_u64(buffer, metrics.producer_wait_ns) &&
               append_char(buffer, '\n');
    });
}

EncodeResult TraceEncoder::encode_event(char *output, size_t capacity, std::string_view event_type,
                                        std::string_view name, std::string_view detail) const noexcept {
    return encode_atomic(output, capacity, std::numeric_limits<size_t>::max(), [&](AppendBuffer &buffer) {
        if (!append_literal(buffer, event_type)) return false;
        if (!name.empty() && (!append_char(buffer, ' ') || !append_literal(buffer, name))) return false;
        if (!detail.empty() && (!append_char(buffer, ' ') || !append_literal(buffer, detail))) return false;
        return append_char(buffer, '\n');
    });
}
