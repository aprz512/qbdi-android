pub(super) const MAGIC: &[u8; 4] = b"QTRB";
pub(super) const MAJOR_VERSION: u8 = 1;
pub(super) const LITTLE_ENDIAN_MARKER: u8 = 1;
pub(super) const STREAM_HEADER_BYTES: usize = 16;
pub(super) const RECORD_HEADER_BYTES: usize = 8;
pub(super) const STOPPED_TERMINAL_FEATURE: u32 = 1;

pub(super) const MAX_CONTEXT_STRING_BYTES: usize = 255;
pub(super) const MAX_MODULE_NAME_BYTES: usize = 255;
pub(super) const MAX_CALL_CATEGORY_BYTES: usize = 255;
pub(super) const MAX_CALL_NAME_BYTES: usize = 255;
pub(super) const MAX_EVENT_NAME_BYTES: usize = 255;
pub(super) const MAX_EVENT_DETAIL_BYTES: usize = 4_096;
pub(super) const MAX_CALL_CHUNK_DETAIL_BYTES: usize = 3_072;
pub(super) const MAX_EVENT_CHUNK_DETAIL_BYTES: usize = 3_072;
pub(super) const MAX_LOGICAL_CALL_DETAIL_BYTES: u32 = 1 << 20;
pub(super) const MAX_MNEMONIC_BYTES: usize = 16;
pub(super) const MAX_OPERANDS_BYTES: usize = 96;
pub(super) const MAX_DISASSEMBLY_BYTES: usize = 112;
pub(super) const MAX_REGISTER_NAME_BYTES: usize = 16;
pub(super) const MAX_GPR_COUNT: usize = 34;
pub(super) const MAX_MEMORY_OPERAND_COUNT: usize = 4;
pub(super) const MAX_CAPTURED_MEMORY_BYTES: usize = 64;
pub(super) const MAX_DICTIONARY_ENTRIES: usize = 1 << 16;

pub(super) const TRACE_BEGIN_FIXED_PAYLOAD_BYTES: u32 = 54;
pub(super) const MODULE_DEFINITION_FIXED_PAYLOAD_BYTES: u32 = 14;
pub(super) const INSTRUCTION_DEFINITION_FIXED_PAYLOAD_BYTES: u32 = 40;
pub(super) const ENCODED_MEMORY_OPERAND_BYTES: u32 = 19;
pub(super) const INSTRUCTION_FIXED_PAYLOAD_BYTES: u32 = 26;
pub(super) const MEMORY_FIXED_PAYLOAD_BYTES: u32 = 40;
pub(super) const CALL_FIXED_PAYLOAD_BYTES: u32 = 6;
pub(super) const CALL_CHUNK_METADATA_BYTES: u32 = 16;
pub(super) const CALL_CHUNK_FIXED_PAYLOAD_BYTES: u32 =
    CALL_CHUNK_METADATA_BYTES + CALL_FIXED_PAYLOAD_BYTES;
pub(super) const RULE_ERROR_FIXED_PAYLOAD_BYTES: u32 = 4;
pub(super) const EVENT_CHUNK_METADATA_BYTES: u32 = 16;
pub(super) const EVENT_CHUNK_FIXED_PAYLOAD_BYTES: u32 =
    EVENT_CHUNK_METADATA_BYTES + RULE_ERROR_FIXED_PAYLOAD_BYTES;
pub(super) const TRACE_BEGIN_PAYLOAD_MAX: u32 =
    TRACE_BEGIN_FIXED_PAYLOAD_BYTES + 2 * MAX_CONTEXT_STRING_BYTES as u32;
pub(super) const MODULE_DEFINITION_PAYLOAD_MAX: u32 =
    MODULE_DEFINITION_FIXED_PAYLOAD_BYTES + MAX_MODULE_NAME_BYTES as u32;
pub(super) const INSTRUCTION_DEFINITION_PAYLOAD_MAX: u32 =
    INSTRUCTION_DEFINITION_FIXED_PAYLOAD_BYTES
        + (2 + MAX_MNEMONIC_BYTES as u32)
        + (2 + MAX_OPERANDS_BYTES as u32)
        + (2 + MAX_DISASSEMBLY_BYTES as u32)
        + 2 * MAX_GPR_COUNT as u32 * (1 + 2 + MAX_REGISTER_NAME_BYTES as u32)
        + MAX_MEMORY_OPERAND_COUNT as u32 * ENCODED_MEMORY_OPERAND_BYTES;
pub(super) const INSTRUCTION_PAYLOAD_MAX: u32 =
    INSTRUCTION_FIXED_PAYLOAD_BYTES + 2 * MAX_GPR_COUNT as u32 * 8;
pub(super) const MEMORY_PAYLOAD_MAX: u32 =
    MEMORY_FIXED_PAYLOAD_BYTES + 2 * MAX_CAPTURED_MEMORY_BYTES as u32;
pub(super) const CALL_PAYLOAD_MAX: u32 = CALL_FIXED_PAYLOAD_BYTES
    + MAX_CALL_CATEGORY_BYTES as u32
    + MAX_CALL_NAME_BYTES as u32
    + MAX_EVENT_DETAIL_BYTES as u32;
pub(super) const CALL_CHUNK_PAYLOAD_MAX: u32 = CALL_CHUNK_FIXED_PAYLOAD_BYTES
    + MAX_CALL_CATEGORY_BYTES as u32
    + MAX_CALL_NAME_BYTES as u32
    + MAX_CALL_CHUNK_DETAIL_BYTES as u32;
pub(super) const RULE_ERROR_PAYLOAD_MAX: u32 =
    RULE_ERROR_FIXED_PAYLOAD_BYTES + MAX_EVENT_NAME_BYTES as u32 + MAX_EVENT_DETAIL_BYTES as u32;
pub(super) const EVENT_CHUNK_PAYLOAD_MAX: u32 = EVENT_CHUNK_FIXED_PAYLOAD_BYTES
    + MAX_EVENT_NAME_BYTES as u32
    + MAX_EVENT_CHUNK_DETAIL_BYTES as u32;
pub(super) const TRACE_END_PAYLOAD_BYTES: u32 = 97;
pub(super) const TRACE_STOP_PAYLOAD_BYTES: u32 = 96;
pub(super) const MAX_RECORD_BYTES: u32 = RECORD_HEADER_BYTES as u32 + CALL_PAYLOAD_MAX;
pub(super) const MAX_OPAQUE_PAYLOAD_BYTES: u32 = MAX_RECORD_BYTES - RECORD_HEADER_BYTES as u32;

pub(super) const OPTIONAL_RECORD_TYPE_MIN: u16 = 0x8000;
pub(super) const CHUNK_FLAG: u16 = 1;
pub(super) const VALID_INSTRUCTION_FLAGS: u32 = 0x0f;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub(super) enum RecordType {
    TraceBegin = 1,
    ModuleDefinition = 2,
    InstructionDefinition = 3,
    Instruction = 4,
    Memory = 5,
    Call = 6,
    Rule = 7,
    Error = 8,
    TraceEnd = 9,
    TraceStop = 10,
}

impl RecordType {
    pub(super) const fn from_raw(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::TraceBegin),
            2 => Some(Self::ModuleDefinition),
            3 => Some(Self::InstructionDefinition),
            4 => Some(Self::Instruction),
            5 => Some(Self::Memory),
            6 => Some(Self::Call),
            7 => Some(Self::Rule),
            8 => Some(Self::Error),
            9 => Some(Self::TraceEnd),
            10 => Some(Self::TraceStop),
            _ => None,
        }
    }

    pub(super) const fn payload_limit(self, flags: u16) -> Option<u32> {
        match (self, flags) {
            (Self::TraceBegin, 0) => Some(TRACE_BEGIN_PAYLOAD_MAX),
            (Self::ModuleDefinition, 0) => Some(MODULE_DEFINITION_PAYLOAD_MAX),
            (Self::InstructionDefinition, 0) => Some(INSTRUCTION_DEFINITION_PAYLOAD_MAX),
            (Self::Instruction, 0) => Some(INSTRUCTION_PAYLOAD_MAX),
            (Self::Memory, 0) => Some(MEMORY_PAYLOAD_MAX),
            (Self::Call, 0) => Some(CALL_PAYLOAD_MAX),
            (Self::Call, CHUNK_FLAG) => Some(CALL_CHUNK_PAYLOAD_MAX),
            (Self::Rule | Self::Error, 0) => Some(RULE_ERROR_PAYLOAD_MAX),
            (Self::Rule | Self::Error, CHUNK_FLAG) => Some(EVENT_CHUNK_PAYLOAD_MAX),
            (Self::TraceEnd, 0) => Some(TRACE_END_PAYLOAD_BYTES),
            (Self::TraceStop, 0) => Some(TRACE_STOP_PAYLOAD_BYTES),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_wire_sizes_and_maxima_are_exact() {
        assert_eq!(STREAM_HEADER_BYTES, 16);
        assert_eq!(RECORD_HEADER_BYTES, 8);
        assert_eq!(MAX_CONTEXT_STRING_BYTES, 255);
        assert_eq!(MAX_MODULE_NAME_BYTES, 255);
        assert_eq!(MAX_CALL_CATEGORY_BYTES, 255);
        assert_eq!(MAX_CALL_NAME_BYTES, 255);
        assert_eq!(MAX_EVENT_NAME_BYTES, 255);
        assert_eq!(MAX_EVENT_DETAIL_BYTES, 4_096);
        assert_eq!(MAX_CALL_CHUNK_DETAIL_BYTES, 3_072);
        assert_eq!(MAX_EVENT_CHUNK_DETAIL_BYTES, 3_072);
        assert_eq!(MAX_LOGICAL_CALL_DETAIL_BYTES, 1 << 20);
        assert_eq!(MAX_MNEMONIC_BYTES, 16);
        assert_eq!(MAX_OPERANDS_BYTES, 96);
        assert_eq!(MAX_DISASSEMBLY_BYTES, 112);
        assert_eq!(MAX_REGISTER_NAME_BYTES, 16);
        assert_eq!(MAX_GPR_COUNT, 34);
        assert_eq!(MAX_MEMORY_OPERAND_COUNT, 4);
        assert_eq!(MAX_CAPTURED_MEMORY_BYTES, 64);
        assert_eq!(MAX_DICTIONARY_ENTRIES, 1 << 16);
        assert_eq!(MAJOR_VERSION, 1);
        assert_eq!(LITTLE_ENDIAN_MARKER, 1);
        assert_eq!(STOPPED_TERMINAL_FEATURE, 1);
        assert_eq!(OPTIONAL_RECORD_TYPE_MIN, 0x8000);
        assert_eq!(CHUNK_FLAG, 1);
        assert_eq!(VALID_INSTRUCTION_FLAGS, 0x0f);
        assert_eq!(TRACE_BEGIN_FIXED_PAYLOAD_BYTES, 54);
        assert_eq!(MODULE_DEFINITION_FIXED_PAYLOAD_BYTES, 14);
        assert_eq!(INSTRUCTION_DEFINITION_FIXED_PAYLOAD_BYTES, 40);
        assert_eq!(ENCODED_MEMORY_OPERAND_BYTES, 19);
        assert_eq!(INSTRUCTION_FIXED_PAYLOAD_BYTES, 26);
        assert_eq!(MEMORY_FIXED_PAYLOAD_BYTES, 40);
        assert_eq!(CALL_FIXED_PAYLOAD_BYTES, 6);
        assert_eq!(CALL_CHUNK_METADATA_BYTES, 16);
        assert_eq!(CALL_CHUNK_FIXED_PAYLOAD_BYTES, 22);
        assert_eq!(RULE_ERROR_FIXED_PAYLOAD_BYTES, 4);
        assert_eq!(EVENT_CHUNK_METADATA_BYTES, 16);
        assert_eq!(EVENT_CHUNK_FIXED_PAYLOAD_BYTES, 20);
        assert_eq!(TRACE_BEGIN_PAYLOAD_MAX + 8, 572);
        assert_eq!(MODULE_DEFINITION_PAYLOAD_MAX + 8, 277);
        assert_eq!(INSTRUCTION_DEFINITION_PAYLOAD_MAX + 8, 1_646);
        assert_eq!(INSTRUCTION_PAYLOAD_MAX + 8, 578);
        assert_eq!(MEMORY_PAYLOAD_MAX + 8, 176);
        assert_eq!(CALL_PAYLOAD_MAX + 8, 4_620);
        assert_eq!(CALL_CHUNK_PAYLOAD_MAX + 8, 3_612);
        assert_eq!(RULE_ERROR_PAYLOAD_MAX + 8, 4_363);
        assert_eq!(EVENT_CHUNK_PAYLOAD_MAX + 8, 3_355);
        assert_eq!(TRACE_END_PAYLOAD_BYTES + 8, 105);
        assert_eq!(TRACE_STOP_PAYLOAD_BYTES + 8, 104);
        assert_eq!(MAX_RECORD_BYTES, 4_620);
    }
}
