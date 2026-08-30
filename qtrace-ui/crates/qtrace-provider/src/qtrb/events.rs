use serde::{Deserialize, Serialize};

use crate::{ProviderError, SourceCoordinate};

use super::{cursor::PayloadCursor, wire::*};

fn is_zero_u8(value: &u8) -> bool {
    *value == 0
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceProfile {
    Fast,
    Balanced,
    #[default]
    Full,
}

impl TraceProfile {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Balanced => "balanced",
            Self::Full => "full",
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct BeginMetadata {
    pub module_base: u64,
    pub target_offset: u64,
    pub target_address: u64,
    pub pid: u32,
    pub tid: Option<u32>,
    pub profile: TraceProfile,
    pub compression_enabled: bool,
    pub effective_buffer_bytes: u64,
    pub run_id: u64,
    pub scene: String,
    pub target: String,
    #[serde(default, skip_serializing_if = "is_zero_u8")]
    pub pointer_width: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_index: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_generation: Option<u32>,
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PcRelativeKind {
    #[default]
    None,
    Instruction,
    Page,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct RegisterDefinition {
    pub slot: u8,
    pub captured_width: u8,
    pub name: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct RegisterObservation {
    pub slot: u8,
    pub captured_width: u8,
    pub name: String,
    pub value: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegisterExtend {
    #[default]
    None,
    Uxtw,
    Sxtw,
    Lsl,
    Sxtx,
}

impl RegisterExtend {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Uxtw => "uxtw",
            Self::Sxtw => "sxtw",
            Self::Lsl => "lsl",
            Self::Sxtx => "sxtx",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryAddressMode {
    #[default]
    Offset,
    PreIndex,
    PostIndex,
}

impl MemoryAddressMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Offset => "offset",
            Self::PreIndex => "preindex",
            Self::PostIndex => "postindex",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryDirection {
    Read,
    Write,
    ReadWrite,
    #[default]
    Unknown,
}

impl MemoryDirection {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::ReadWrite => "readwrite",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemoryOperand {
    pub base: Option<u8>,
    pub index: Option<u8>,
    pub extend: RegisterExtend,
    pub mode: MemoryAddressMode,
    pub shift: u8,
    pub direction: MemoryDirection,
    pub writeback: bool,
    pub size: u32,
    pub displacement: i64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct InstructionDefinition {
    pub definition_id: u32,
    pub opcode: u32,
    pub read_mask: u64,
    pub write_mask: u64,
    pub pc_displacement: i64,
    pub flags: u32,
    pub pc_kind: PcRelativeKind,
    pub condition: u8,
    pub slow_memory_path: bool,
    pub mnemonic: String,
    pub operands: String,
    pub disassembly: String,
    pub reads: Vec<RegisterDefinition>,
    pub writes: Vec<RegisterDefinition>,
    pub memory_operands: Vec<MemoryOperand>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Instruction {
    pub definition_id: u32,
    pub module_id: u32,
    pub relative_pc: u64,
    pub read_before: Vec<RegisterObservation>,
    pub write_after: Vec<RegisterObservation>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureBytes {
    #[default]
    NotCaptured,
    Unavailable,
    Captured(Vec<u8>),
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Memory {
    pub module_id: u32,
    pub relative_pc: u64,
    pub address: u64,
    pub size: u32,
    pub direction: MemoryDirection,
    pub metadata_available: bool,
    pub flags: u16,
    pub value: u64,
    pub before: CaptureBytes,
    pub after: CaptureBytes,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct TerminalMetrics {
    pub instructions: u64,
    pub encoded_bytes: u64,
    pub compressed_bytes: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_collisions: u64,
    pub buffer_swaps: u64,
    pub producer_waits: u64,
    pub producer_wait_ns: u64,
    pub effective_buffer_bytes: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminationKind {
    Completed,
    Stopped,
    Intent,
    #[default]
    Unknown,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Termination {
    pub kind: TerminationKind,
    pub reason: Option<String>,
    pub return_value: Option<u64>,
    pub elapsed_ms: u64,
    pub metrics: TerminalMetrics,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<TerminationIntent>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct TerminationIntent {
    pub pc: u64,
    pub syscall_number: i64,
    pub arguments: [u64; 4],
}

pub(crate) struct DecodedInstruction {
    pub(crate) local_sequence: u64,
    pub(crate) instruction: Instruction,
}

fn nested(
    payload: &[u8],
    expected_kind: u16,
    coordinate: SourceCoordinate,
) -> Result<&[u8], ProviderError> {
    let mut cursor = PayloadCursor::new(payload, "nested QTRB record", coordinate);
    let kind = cursor.u16_le()?;
    let flags = cursor.u16_le()?;
    let size = usize::try_from(cursor.u32_le()?)
        .map_err(|_| invalid_payload(coordinate, "nested QTRB payload size does not fit host"))?;
    if kind != expected_kind || flags != 0 || size != payload.len().saturating_sub(8) {
        return Err(invalid_payload(coordinate, "invalid nested QTRB record"));
    }
    cursor.take(size)
}

pub(crate) fn decode_instruction_definition_record(
    payload: &[u8],
    coordinate: SourceCoordinate,
) -> Result<InstructionDefinition, ProviderError> {
    decode_instruction_definition_payload(nested(payload, 3, coordinate)?, coordinate)
}

pub(crate) fn decode_instruction_definition_payload(
    payload: &[u8],
    coordinate: SourceCoordinate,
) -> Result<InstructionDefinition, ProviderError> {
    let mut cursor = PayloadCursor::new(payload, "INSTRUCTION_DEF", coordinate);
    let definition_id = cursor.u32_le()?;
    let opcode = cursor.u32_le()?;
    let read_mask = cursor.u64_le()?;
    let write_mask = cursor.u64_le()?;
    let pc_displacement = cursor.i64_le()?;
    let flags = cursor.u32_le()?;
    let pc_kind = cursor.u8()?;
    let condition = cursor.u8()?;
    let memory_count = usize::from(cursor.u8()?);
    let slow_memory_path = cursor.u8()?;
    if definition_id == 0
        || flags & !VALID_INSTRUCTION_FLAGS != 0
        || pc_kind > 2
        || slow_memory_path > 1
        || memory_count > MAX_MEMORY_OPERAND_COUNT
        || read_mask >> MAX_GPR_COUNT != 0
        || write_mask >> MAX_GPR_COUNT != 0
    {
        return Err(invalid_payload(
            coordinate,
            "invalid instruction definition metadata",
        ));
    }
    let mnemonic = cursor.bounded_utf8(MAX_MNEMONIC_BYTES, "mnemonic")?;
    let operands = cursor.bounded_utf8(MAX_OPERANDS_BYTES, "operands")?;
    let disassembly = cursor.bounded_utf8(MAX_DISASSEMBLY_BYTES, "disassembly")?;
    let reads = shared_registers(&mut cursor, read_mask, "read register", coordinate)?;
    let writes = shared_registers(&mut cursor, write_mask, "write register", coordinate)?;
    let mut memory_operands = Vec::new();
    memory_operands
        .try_reserve_exact(memory_count)
        .map_err(|_| invalid_payload(coordinate, "memory operand allocation failed"))?;
    for _ in 0..memory_count {
        let base = cursor.u8()?;
        let index = cursor.u8()?;
        let extend = cursor.u8()?;
        let mode = cursor.u8()?;
        let shift = cursor.u8()?;
        let direction = cursor.u8()?;
        let writeback = cursor.u8()?;
        let size = cursor.u32_le()?;
        let displacement = cursor.i64_le()?;
        if (base >= MAX_GPR_COUNT as u8 && base != u8::MAX)
            || (index >= MAX_GPR_COUNT as u8 && index != u8::MAX)
            || extend > 4
            || mode > 2
            || !matches!(direction, 1..=3)
            || writeback > 1
        {
            return Err(invalid_payload(
                coordinate,
                "invalid instruction memory operand",
            ));
        }
        memory_operands.push(MemoryOperand {
            base: (base != u8::MAX).then_some(base),
            index: (index != u8::MAX).then_some(index),
            extend: match extend {
                0 => RegisterExtend::None,
                1 => RegisterExtend::Uxtw,
                2 => RegisterExtend::Sxtw,
                3 => RegisterExtend::Lsl,
                _ => RegisterExtend::Sxtx,
            },
            mode: match mode {
                0 => MemoryAddressMode::Offset,
                1 => MemoryAddressMode::PreIndex,
                _ => MemoryAddressMode::PostIndex,
            },
            shift,
            direction: decode_direction(direction, coordinate)?,
            writeback: writeback == 1,
            size,
            displacement,
        });
    }
    cursor.finish()?;
    Ok(InstructionDefinition {
        definition_id,
        opcode,
        read_mask,
        write_mask,
        pc_displacement,
        flags,
        pc_kind: match pc_kind {
            0 => PcRelativeKind::None,
            1 => PcRelativeKind::Instruction,
            _ => PcRelativeKind::Page,
        },
        condition,
        slow_memory_path: slow_memory_path == 1,
        mnemonic,
        operands,
        disassembly,
        reads,
        writes,
        memory_operands,
    })
}

pub(crate) fn decode_instruction_record(
    payload: &[u8],
    definition: &InstructionDefinition,
    coordinate: SourceCoordinate,
) -> Result<DecodedInstruction, ProviderError> {
    let payload = nested(payload, 4, coordinate)?;
    decode_instruction_payload(payload, definition, Some(1), coordinate)
}

pub(crate) fn decode_instruction_payload(
    payload: &[u8],
    definition: &InstructionDefinition,
    expected_module_id: Option<u32>,
    coordinate: SourceCoordinate,
) -> Result<DecodedInstruction, ProviderError> {
    let mut cursor = PayloadCursor::new(payload, "INSTRUCTION", coordinate);
    let local_sequence = cursor.u64_le()?;
    let module_id = cursor.u32_le()?;
    let relative_pc = cursor.u64_le()?;
    let definition_id = cursor.u32_le()?;
    let read_count = usize::from(cursor.u8()?);
    let write_count = usize::from(cursor.u8()?);
    if expected_module_id.is_some_and(|expected| module_id != expected)
        || definition_id != definition.definition_id
        || read_count != definition.reads.len()
        || write_count != definition.writes.len()
    {
        return Err(invalid_payload(
            coordinate,
            "instruction register counts or dictionary references are invalid",
        ));
    }
    let mut read_before = Vec::new();
    read_before
        .try_reserve_exact(read_count)
        .map_err(|_| invalid_payload(coordinate, "instruction read allocation failed"))?;
    for register in &definition.reads {
        read_before.push(RegisterObservation {
            slot: register.slot,
            captured_width: register.captured_width,
            name: register.name.clone(),
            value: cursor.u64_le()?,
        });
    }
    let mut write_after = Vec::new();
    write_after
        .try_reserve_exact(write_count)
        .map_err(|_| invalid_payload(coordinate, "instruction write allocation failed"))?;
    for register in &definition.writes {
        write_after.push(RegisterObservation {
            slot: register.slot,
            captured_width: register.captured_width,
            name: register.name.clone(),
            value: cursor.u64_le()?,
        });
    }
    cursor.finish()?;
    Ok(DecodedInstruction {
        local_sequence,
        instruction: Instruction {
            definition_id,
            module_id,
            relative_pc,
            read_before,
            write_after,
        },
    })
}

pub(crate) fn decode_memory_record(
    payload: &[u8],
    coordinate: SourceCoordinate,
) -> Result<Memory, ProviderError> {
    let payload = nested(payload, 5, coordinate)?;
    decode_memory_payload_for_module(payload, Some(1), coordinate)
}

pub(crate) fn decode_memory_payload(
    payload: &[u8],
    coordinate: SourceCoordinate,
) -> Result<Memory, ProviderError> {
    decode_memory_payload_for_module(payload, None, coordinate)
}

fn decode_memory_payload_for_module(
    payload: &[u8],
    expected_module_id: Option<u32>,
    coordinate: SourceCoordinate,
) -> Result<Memory, ProviderError> {
    let mut cursor = PayloadCursor::new(payload, "MEMORY", coordinate);
    let module_id = cursor.u32_le()?;
    let relative_pc = cursor.u64_le()?;
    let direction = decode_direction(cursor.u8()?, coordinate)?;
    let metadata_available = cursor.u8()?;
    let flags = cursor.u16_le()?;
    let address = cursor.u64_le()?;
    let size = cursor.u32_le()?;
    let value = cursor.u64_le()?;
    if expected_module_id.is_some_and(|expected| module_id != expected) || metadata_available > 1 {
        return Err(invalid_payload(coordinate, "invalid memory metadata"));
    }
    let before = shared_memory_state(&mut cursor, "before memory", coordinate)?;
    let after = shared_memory_state(&mut cursor, "after memory", coordinate)?;
    cursor.finish()?;
    Ok(Memory {
        module_id,
        relative_pc,
        address,
        size,
        direction,
        metadata_available: metadata_available == 1,
        flags,
        value,
        before,
        after,
    })
}

fn shared_registers(
    cursor: &mut PayloadCursor<'_>,
    mask: u64,
    field: &'static str,
    coordinate: SourceCoordinate,
) -> Result<Vec<RegisterDefinition>, ProviderError> {
    let mut registers = Vec::new();
    registers
        .try_reserve_exact(mask.count_ones() as usize)
        .map_err(|_| invalid_payload(coordinate, "register definition allocation failed"))?;
    for slot in 0..MAX_GPR_COUNT {
        if mask & (1_u64 << slot) == 0 {
            continue;
        }
        let captured_width = cursor.u8()?;
        let name = cursor.bounded_utf8(MAX_REGISTER_NAME_BYTES, field)?;
        if captured_width == 0 || captured_width > 16 || name.is_empty() {
            return Err(invalid_payload(coordinate, "invalid register definition"));
        }
        registers.push(RegisterDefinition {
            slot: slot as u8,
            captured_width,
            name,
        });
    }
    Ok(registers)
}

fn shared_memory_state(
    cursor: &mut PayloadCursor<'_>,
    field: &'static str,
    coordinate: SourceCoordinate,
) -> Result<CaptureBytes, ProviderError> {
    let state = cursor.u8()?;
    let count = usize::from(cursor.u8()?);
    if count > MAX_CAPTURED_MEMORY_BYTES {
        return Err(invalid_payload(
            coordinate,
            "memory capture exceeds maximum",
        ));
    }
    let bytes = cursor.take(count)?;
    match (state, count) {
        (0, 0) => Ok(CaptureBytes::NotCaptured),
        (1, _) => Ok(CaptureBytes::Captured(bytes.to_vec())),
        (2, 0) => Ok(CaptureBytes::Unavailable),
        _ => Err(invalid_payload(
            coordinate,
            format!("invalid {field} state"),
        )),
    }
}

fn decode_direction(
    value: u8,
    coordinate: SourceCoordinate,
) -> Result<MemoryDirection, ProviderError> {
    match value {
        1 => Ok(MemoryDirection::Read),
        2 => Ok(MemoryDirection::Write),
        3 => Ok(MemoryDirection::ReadWrite),
        _ => Err(invalid_payload(
            coordinate,
            "invalid memory access direction",
        )),
    }
}

fn invalid_payload(coordinate: SourceCoordinate, detail: impl AsRef<str>) -> ProviderError {
    ProviderError::new(
        "source.invalid_payload",
        "qtrb.shared_payload",
        Some(coordinate),
        false,
        detail,
    )
}
