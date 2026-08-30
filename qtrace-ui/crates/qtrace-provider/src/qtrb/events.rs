use serde::{Deserialize, Serialize};

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
}
