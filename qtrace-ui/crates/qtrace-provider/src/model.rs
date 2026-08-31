use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser::SerializeStruct};

use crate::qtrb::events::{BeginMetadata, Instruction, InstructionDefinition, Memory, Termination};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    Captured,
    Derived,
    Heuristic,
    Unknown,
    Damaged,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCapabilities {
    pub global_ordering: bool,
    pub per_thread_ordering: bool,
    pub full_register_checkpoint: bool,
    pub register_read_write_observation: bool,
    pub memory_metadata: bool,
    pub memory_before_after: bool,
    pub lifecycle: bool,
    pub signal_and_termination: bool,
    pub loss_and_damage_ranges: bool,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Begin,
    ModuleDefinition,
    InstructionDefinition,
    Instruction,
    Memory,
    SemanticCall,
    SemanticRule,
    SemanticError,
    ThreadLifecycle,
    Syscall,
    Signal,
    SignalHandlerBoundary,
    Termination,
    RegisterCheckpoint,
    RegisterDelta,
    StringDefinition,
    CoverageGap,
    Discontinuity,
    OpaqueOptional,
}

impl EventKind {
    pub const ALL: [Self; 19] = [
        Self::Begin,
        Self::ModuleDefinition,
        Self::InstructionDefinition,
        Self::Instruction,
        Self::Memory,
        Self::SemanticCall,
        Self::SemanticRule,
        Self::SemanticError,
        Self::ThreadLifecycle,
        Self::Syscall,
        Self::Signal,
        Self::SignalHandlerBoundary,
        Self::Termination,
        Self::RegisterCheckpoint,
        Self::RegisterDelta,
        Self::StringDefinition,
        Self::CoverageGap,
        Self::Discontinuity,
        Self::OpaqueOptional,
    ];

    pub const fn external_tag(self) -> &'static [u8] {
        match self {
            Self::Begin => b"begin",
            Self::ModuleDefinition => b"module_definition",
            Self::InstructionDefinition => b"instruction_definition",
            Self::Instruction => b"instruction",
            Self::Memory => b"memory",
            Self::SemanticCall => b"semantic_call",
            Self::SemanticRule => b"semantic_rule",
            Self::SemanticError => b"semantic_error",
            Self::ThreadLifecycle => b"thread_lifecycle",
            Self::Syscall => b"syscall",
            Self::Signal => b"signal",
            Self::SignalHandlerBoundary => b"signal_handler_boundary",
            Self::Termination => b"termination",
            Self::RegisterCheckpoint => b"register_checkpoint",
            Self::RegisterDelta => b"register_delta",
            Self::StringDefinition => b"string_definition",
            Self::CoverageGap => b"coverage_gap",
            Self::Discontinuity => b"discontinuity",
            Self::OpaqueOptional => b"opaque_optional",
        }
    }

    pub fn from_external_tag(tag: &[u8]) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.external_tag() == tag)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ModuleDefinition {
    pub module_id: u32,
    pub base: u64,
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SemanticEvent {
    pub category: Option<String>,
    pub name: String,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fragment_sequences: Vec<u64>,
}

/// Canonical instruction-definition semantics with the source-local ID normalized away.
pub struct SemanticDefinition<'a>(pub &'a InstructionDefinition);

impl Serialize for SemanticDefinition<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let InstructionDefinition {
            definition_id: _,
            opcode,
            read_mask,
            write_mask,
            pc_displacement,
            flags,
            pc_kind,
            condition,
            slow_memory_path,
            mnemonic,
            operands,
            disassembly,
            reads,
            writes,
            memory_operands,
        } = self.0;
        let mut state = serializer.serialize_struct("InstructionDefinition", 15)?;
        state.serialize_field("definition_id", &0_u32)?;
        state.serialize_field("opcode", opcode)?;
        state.serialize_field("read_mask", read_mask)?;
        state.serialize_field("write_mask", write_mask)?;
        state.serialize_field("pc_displacement", pc_displacement)?;
        state.serialize_field("flags", flags)?;
        state.serialize_field("pc_kind", pc_kind)?;
        state.serialize_field("condition", condition)?;
        state.serialize_field("slow_memory_path", slow_memory_path)?;
        state.serialize_field("mnemonic", mnemonic)?;
        state.serialize_field("operands", operands)?;
        state.serialize_field("disassembly", disassembly)?;
        state.serialize_field("reads", reads)?;
        state.serialize_field("writes", writes)?;
        state.serialize_field("memory_operands", memory_operands)?;
        state.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreadLifecyclePhase {
    Begin,
    End,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ThreadLifecycle {
    pub tid: u32,
    pub phase: ThreadLifecyclePhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creator_tid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_routine: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module_generation: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Syscall {
    pub tid: u32,
    pub number: i64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub pc: u64,
    #[serde(default, skip_serializing_if = "is_zero_args")]
    pub arguments: [u64; 6],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Signal {
    pub tid: u32,
    pub number: i32,
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub code: i32,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub pc: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub sp: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub fault_address: u64,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub flags: u32,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalHandlerPhase {
    Begin,
    Return,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignalHandlerBoundary {
    pub tid: u32,
    pub phase: SignalHandlerPhase,
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub number: i32,
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub code: i32,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub pc: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub sp: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub fault_address: u64,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub flags: u32,
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub depth: u16,
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub nested_delivery_count: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub begin_sequence: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegisterSlot {
    X0,
    X1,
    X2,
    X3,
    X4,
    X5,
    X6,
    X7,
    X8,
    X9,
    X10,
    X11,
    X12,
    X13,
    X14,
    X15,
    X16,
    X17,
    X18,
    X19,
    X20,
    X21,
    X22,
    X23,
    X24,
    X25,
    X26,
    X27,
    X28,
    X29,
    X30,
    Sp,
    Pc,
    Nzcv,
}

impl RegisterSlot {
    pub const COUNT: usize = 34;

    pub const fn index(self) -> usize {
        match self {
            Self::X0 => 0,
            Self::X1 => 1,
            Self::X2 => 2,
            Self::X3 => 3,
            Self::X4 => 4,
            Self::X5 => 5,
            Self::X6 => 6,
            Self::X7 => 7,
            Self::X8 => 8,
            Self::X9 => 9,
            Self::X10 => 10,
            Self::X11 => 11,
            Self::X12 => 12,
            Self::X13 => 13,
            Self::X14 => 14,
            Self::X15 => 15,
            Self::X16 => 16,
            Self::X17 => 17,
            Self::X18 => 18,
            Self::X19 => 19,
            Self::X20 => 20,
            Self::X21 => 21,
            Self::X22 => 22,
            Self::X23 => 23,
            Self::X24 => 24,
            Self::X25 => 25,
            Self::X26 => 26,
            Self::X27 => 27,
            Self::X28 => 28,
            Self::X29 => 29,
            Self::X30 => 30,
            Self::Sp => 31,
            Self::Pc => 32,
            Self::Nzcv => 33,
        }
    }

    pub const fn from_index(index: usize) -> Option<Self> {
        Some(match index {
            0 => Self::X0,
            1 => Self::X1,
            2 => Self::X2,
            3 => Self::X3,
            4 => Self::X4,
            5 => Self::X5,
            6 => Self::X6,
            7 => Self::X7,
            8 => Self::X8,
            9 => Self::X9,
            10 => Self::X10,
            11 => Self::X11,
            12 => Self::X12,
            13 => Self::X13,
            14 => Self::X14,
            15 => Self::X15,
            16 => Self::X16,
            17 => Self::X17,
            18 => Self::X18,
            19 => Self::X19,
            20 => Self::X20,
            21 => Self::X21,
            22 => Self::X22,
            23 => Self::X23,
            24 => Self::X24,
            25 => Self::X25,
            26 => Self::X26,
            27 => Self::X27,
            28 => Self::X28,
            29 => Self::X29,
            30 => Self::X30,
            31 => Self::Sp,
            32 => Self::Pc,
            33 => Self::Nzcv,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RegisterValue {
    pub slot: RegisterSlot,
    pub value: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RegisterSnapshot {
    values: Vec<u64>,
}

impl<'de> Deserialize<'de> for RegisterSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SerializedSnapshot {
            values: Vec<u64>,
        }

        let value = SerializedSnapshot::deserialize(deserializer)?;
        Self::new(value.values)
            .ok_or_else(|| de::Error::custom("register snapshot must contain exactly 34 values"))
    }
}

impl RegisterSnapshot {
    pub fn new(values: Vec<u64>) -> Option<Self> {
        (values.len() == RegisterSlot::COUNT).then_some(Self { values })
    }

    pub fn values(&self) -> &[u64] {
        &self.values
    }

    pub fn value(&self, slot: RegisterSlot) -> Option<u64> {
        self.values.get(slot.index()).copied()
    }

    pub(crate) fn apply(&mut self, changed: &[RegisterValue]) {
        for item in changed {
            if let Some(value) = self.values.get_mut(item.slot.index()) {
                *value = item.value;
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RegisterCheckpoint {
    pub values: Vec<RegisterValue>,
}

impl RegisterCheckpoint {
    pub fn value(&self, slot: RegisterSlot) -> Option<u64> {
        self.values
            .iter()
            .find(|item| item.slot == slot)
            .map(|item| item.value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RegisterDelta {
    pub mask: u64,
    pub changed: Vec<RegisterValue>,
    pub ancestry_reliable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StringDefinition {
    pub id: u32,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CoverageGap {
    pub tid: u32,
    pub pc: u64,
    pub sp: u64,
    pub fault_address: u64,
    pub reason_flags: u32,
    pub dropped_count: u32,
}

fn is_zero_u16(value: &u16) -> bool {
    *value == 0
}
fn is_zero_u32(value: &u32) -> bool {
    *value == 0
}
fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}
fn is_zero_i32(value: &i32) -> bool {
    *value == 0
}
fn is_zero_args(value: &[u64; 6]) -> bool {
    value.iter().all(|item| *item == 0)
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscontinuityCause {
    Loss,
    Damage,
    Overwrite,
    Truncation,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Discontinuity {
    pub cause: DiscontinuityCause,
    pub evidence: CompletenessRange,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OpaqueOptionalRecord {
    pub record_type: u16,
    pub flags: u16,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventPayload {
    Begin(BeginMetadata),
    ModuleDefinition(ModuleDefinition),
    InstructionDefinition(InstructionDefinition),
    Instruction(Instruction),
    Memory(Memory),
    SemanticCall(SemanticEvent),
    SemanticRule(SemanticEvent),
    SemanticError(SemanticEvent),
    ThreadLifecycle(ThreadLifecycle),
    Syscall(Syscall),
    Signal(Signal),
    SignalHandlerBoundary(SignalHandlerBoundary),
    Termination(Termination),
    RegisterCheckpoint(RegisterCheckpoint),
    RegisterDelta(RegisterDelta),
    StringDefinition(StringDefinition),
    CoverageGap(CoverageGap),
    Discontinuity(Discontinuity),
    OpaqueOptional(OpaqueOptionalRecord),
}

impl EventPayload {
    pub const fn kind(&self) -> EventKind {
        match self {
            Self::Begin(_) => EventKind::Begin,
            Self::ModuleDefinition(_) => EventKind::ModuleDefinition,
            Self::InstructionDefinition(_) => EventKind::InstructionDefinition,
            Self::Instruction(_) => EventKind::Instruction,
            Self::Memory(_) => EventKind::Memory,
            Self::SemanticCall(_) => EventKind::SemanticCall,
            Self::SemanticRule(_) => EventKind::SemanticRule,
            Self::SemanticError(_) => EventKind::SemanticError,
            Self::ThreadLifecycle(_) => EventKind::ThreadLifecycle,
            Self::Syscall(_) => EventKind::Syscall,
            Self::Signal(_) => EventKind::Signal,
            Self::SignalHandlerBoundary(_) => EventKind::SignalHandlerBoundary,
            Self::Termination(_) => EventKind::Termination,
            Self::RegisterCheckpoint(_) => EventKind::RegisterCheckpoint,
            Self::RegisterDelta(_) => EventKind::RegisterDelta,
            Self::StringDefinition(_) => EventKind::StringDefinition,
            Self::CoverageGap(_) => EventKind::CoverageGap,
            Self::Discontinuity(_) => EventKind::Discontinuity,
            Self::OpaqueOptional(_) => EventKind::OpaqueOptional,
        }
    }
}

pub const MAX_FRAGMENT_SOURCE_OFFSETS: usize = u16::MAX as usize;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct FragmentSourceOffsets(Vec<u64>);

impl FragmentSourceOffsets {
    pub fn new(offsets: Vec<u64>) -> Option<Self> {
        if offsets.len() > MAX_FRAGMENT_SOURCE_OFFSETS
            || offsets.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return None;
        }
        Some(Self(offsets))
    }

    pub fn as_slice(&self) -> &[u64] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for FragmentSourceOffsets {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BoundedOffsetsVisitor;

        impl<'de> de::Visitor<'de> for BoundedOffsetsVisitor {
            type Value = FragmentSourceOffsets;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    formatter,
                    "at most {MAX_FRAGMENT_SOURCE_OFFSETS} strictly increasing source offsets"
                )
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let capacity = sequence
                    .size_hint()
                    .unwrap_or(0)
                    .min(MAX_FRAGMENT_SOURCE_OFFSETS);
                let mut offsets = Vec::with_capacity(capacity);
                while let Some(offset) = sequence.next_element::<u64>()? {
                    if offsets.len() == MAX_FRAGMENT_SOURCE_OFFSETS {
                        return Err(de::Error::custom(
                            "fragment source offsets exceed their bound",
                        ));
                    }
                    if offsets.last().is_some_and(|previous| *previous >= offset) {
                        return Err(de::Error::custom(
                            "fragment source offsets must be strictly increasing",
                        ));
                    }
                    offsets.push(offset);
                }
                Ok(FragmentSourceOffsets(offsets))
            }
        }

        deserializer.deserialize_seq(BoundedOffsetsVisitor)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EventRecord {
    pub key: EventKey,
    pub provenance: Provenance,
    pub payload: EventPayload,
    scope: EventScope,
    fragment_source_offsets: FragmentSourceOffsets,
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum EventScope {
    #[default]
    Artifact,
    FlightChunk {
        chunk_index: u32,
        generation: u32,
        tid: u32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceIdentity {
    pub artifact: ArtifactDigest,
    pub format: String,
    #[serde(default)]
    pub format_major: u8,
    #[serde(default)]
    pub format_minor: u8,
    pub source_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TimelineDescriptor {
    pub id: TimelineId,
    pub tid: Option<u32>,
    pub label: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderCounters {
    pub records_seen: u64,
    pub events_emitted: u64,
    pub opaque_records: u64,
    pub damaged_records: u64,
    pub input_bytes: u64,
    pub decompressed_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderSummary {
    pub timelines: Vec<TimelineDescriptor>,
    pub termination: Option<Termination>,
    pub counters: ProviderCounters,
    pub completeness: Vec<CompletenessRange>,
}

impl EventRecord {
    pub const fn new(key: EventKey, provenance: Provenance, payload: EventPayload) -> Self {
        Self {
            key,
            provenance,
            payload,
            scope: EventScope::Artifact,
            fragment_source_offsets: FragmentSourceOffsets(Vec::new()),
        }
    }

    pub const fn new_scoped(
        key: EventKey,
        provenance: Provenance,
        scope: EventScope,
        payload: EventPayload,
    ) -> Self {
        Self {
            key,
            provenance,
            payload,
            scope,
            fragment_source_offsets: FragmentSourceOffsets(Vec::new()),
        }
    }

    pub fn with_fragment_source_offsets(
        key: EventKey,
        provenance: Provenance,
        payload: EventPayload,
        offsets: Vec<u64>,
    ) -> Option<Self> {
        let fragment_source_offsets = FragmentSourceOffsets::new(offsets)?;
        if fragment_source_offsets
            .as_slice()
            .first()
            .is_some_and(|first| *first != key.source_offset)
        {
            return None;
        }
        Some(Self {
            key,
            provenance,
            payload,
            scope: EventScope::Artifact,
            fragment_source_offsets,
        })
    }

    pub const fn scope(&self) -> EventScope {
        self.scope
    }

    pub fn set_scope(&mut self, scope: EventScope) {
        self.scope = scope;
    }

    pub fn fragment_source_offsets(&self) -> &[u64] {
        self.fragment_source_offsets.as_slice()
    }

    pub const fn kind(&self) -> EventKind {
        self.payload.kind()
    }

    pub fn register_delta(&self) -> Option<&RegisterDelta> {
        match &self.payload {
            EventPayload::RegisterDelta(value) => Some(value),
            _ => None,
        }
    }
}

impl<'de> Deserialize<'de> for EventRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SerializedEventRecord {
            key: EventKey,
            provenance: Provenance,
            payload: EventPayload,
            #[serde(default)]
            scope: EventScope,
            #[serde(default)]
            fragment_source_offsets: FragmentSourceOffsets,
        }

        let value = SerializedEventRecord::deserialize(deserializer)?;
        if value
            .fragment_source_offsets
            .as_slice()
            .first()
            .is_some_and(|first| *first != value.key.source_offset)
        {
            return Err(de::Error::custom(
                "first fragment source offset must match the event key",
            ));
        }
        Ok(Self {
            key: value.key,
            provenance: value.provenance,
            payload: value.payload,
            scope: value.scope,
            fragment_source_offsets: value.fragment_source_offsets,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RangeDomain {
    CapturedSequence,
    SourceBytes,
    MemoryAddresses,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RangeBounds {
    InclusiveSequence { first: u64, last: u64 },
    HalfOpen { start: u64, end_exclusive: u64 },
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletenessCause {
    Retained,
    MissingTerminal,
    Active,
    Stale,
    Rotating,
    Unreliable,
    Incomplete,
    Lost,
    Overwritten,
    CoverageGap,
    Checksum,
    UnterminatedThread,
    Truncation,
    #[default]
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct CompletenessRange {
    domain: RangeDomain,
    bounds: RangeBounds,
    pub provenance: Provenance,
    pub cause: CompletenessCause,
}

impl CompletenessRange {
    pub const fn captured_sequence(first: u64, last: u64, provenance: Provenance) -> Option<Self> {
        Self::captured_sequence_with_cause(first, last, provenance, CompletenessCause::Unknown)
    }

    pub const fn captured_sequence_with_cause(
        first: u64,
        last: u64,
        provenance: Provenance,
        cause: CompletenessCause,
    ) -> Option<Self> {
        if first > last {
            return None;
        }
        Some(Self {
            domain: RangeDomain::CapturedSequence,
            bounds: RangeBounds::InclusiveSequence { first, last },
            provenance,
            cause,
        })
    }

    pub const fn source_bytes(
        start: u64,
        end_exclusive: u64,
        provenance: Provenance,
    ) -> Option<Self> {
        Self::source_bytes_with_cause(start, end_exclusive, provenance, CompletenessCause::Unknown)
    }

    pub const fn source_bytes_with_cause(
        start: u64,
        end_exclusive: u64,
        provenance: Provenance,
        cause: CompletenessCause,
    ) -> Option<Self> {
        Self::half_open(
            RangeDomain::SourceBytes,
            start,
            end_exclusive,
            provenance,
            cause,
        )
    }

    pub const fn memory_addresses(
        start: u64,
        end_exclusive: u64,
        provenance: Provenance,
    ) -> Option<Self> {
        Self::memory_addresses_with_cause(
            start,
            end_exclusive,
            provenance,
            CompletenessCause::Unknown,
        )
    }

    pub const fn memory_addresses_with_cause(
        start: u64,
        end_exclusive: u64,
        provenance: Provenance,
        cause: CompletenessCause,
    ) -> Option<Self> {
        Self::half_open(
            RangeDomain::MemoryAddresses,
            start,
            end_exclusive,
            provenance,
            cause,
        )
    }

    const fn half_open(
        domain: RangeDomain,
        start: u64,
        end_exclusive: u64,
        provenance: Provenance,
        cause: CompletenessCause,
    ) -> Option<Self> {
        if start > end_exclusive {
            return None;
        }
        Some(Self {
            domain,
            bounds: RangeBounds::HalfOpen {
                start,
                end_exclusive,
            },
            provenance,
            cause,
        })
    }

    pub const fn contains(&self, coordinate: u64) -> bool {
        match self.bounds {
            RangeBounds::InclusiveSequence { first, last } => {
                first <= coordinate && coordinate <= last
            }
            RangeBounds::HalfOpen {
                start,
                end_exclusive,
            } => start <= coordinate && coordinate < end_exclusive,
        }
    }

    pub const fn domain(&self) -> RangeDomain {
        self.domain
    }

    pub const fn bounds(&self) -> RangeBounds {
        self.bounds
    }

    pub const fn provenance(&self) -> Provenance {
        self.provenance
    }

    pub const fn cause(&self) -> CompletenessCause {
        self.cause
    }
}

pub fn completeness_canonical_key(range: &CompletenessRange) -> (u8, u8, u64, u64, u8) {
    let domain = match range.domain() {
        RangeDomain::CapturedSequence => 0,
        RangeDomain::SourceBytes => 1,
        RangeDomain::MemoryAddresses => 2,
    };
    let (first, last) = match range.bounds() {
        RangeBounds::InclusiveSequence { first, last } => (first, last),
        RangeBounds::HalfOpen {
            start,
            end_exclusive,
        } => (start, end_exclusive),
    };
    (
        domain,
        completeness_cause_order(range.cause()),
        first,
        last,
        provenance_canonical_order(range.provenance()),
    )
}

pub fn merge_canonical_completeness(
    left: CompletenessRange,
    right: CompletenessRange,
) -> Option<CompletenessRange> {
    if left.domain() != right.domain()
        || left.cause() != right.cause()
        || left.provenance() != right.provenance()
    {
        return None;
    }
    match (left.bounds(), right.bounds()) {
        (
            RangeBounds::InclusiveSequence {
                first: left_first,
                last: left_last,
            },
            RangeBounds::InclusiveSequence {
                first: right_first,
                last: right_last,
            },
        ) if right_first <= left_last.saturating_add(1) => {
            CompletenessRange::captured_sequence_with_cause(
                left_first,
                left_last.max(right_last),
                left.provenance(),
                left.cause(),
            )
        }
        (
            RangeBounds::HalfOpen {
                start: left_start,
                end_exclusive: left_end,
            },
            RangeBounds::HalfOpen {
                start: right_start,
                end_exclusive: right_end,
            },
        ) if right_start <= left_end => match left.domain() {
            RangeDomain::SourceBytes => CompletenessRange::source_bytes_with_cause(
                left_start,
                left_end.max(right_end),
                left.provenance(),
                left.cause(),
            ),
            RangeDomain::MemoryAddresses => CompletenessRange::memory_addresses_with_cause(
                left_start,
                left_end.max(right_end),
                left.provenance(),
                left.cause(),
            ),
            RangeDomain::CapturedSequence => None,
        },
        _ => None,
    }
}

const fn completeness_cause_order(cause: CompletenessCause) -> u8 {
    match cause {
        CompletenessCause::Retained => 0,
        CompletenessCause::Active => 1,
        CompletenessCause::Rotating => 2,
        CompletenessCause::Stale => 3,
        CompletenessCause::Unreliable => 4,
        CompletenessCause::Incomplete => 5,
        CompletenessCause::Lost => 6,
        CompletenessCause::Overwritten => 7,
        CompletenessCause::CoverageGap => 8,
        CompletenessCause::Checksum => 9,
        CompletenessCause::UnterminatedThread => 10,
        CompletenessCause::MissingTerminal => 11,
        CompletenessCause::Truncation => 12,
        CompletenessCause::Unknown => 13,
    }
}

const fn provenance_canonical_order(provenance: Provenance) -> u8 {
    match provenance {
        Provenance::Captured => 0,
        Provenance::Derived => 1,
        Provenance::Heuristic => 2,
        Provenance::Unknown => 3,
        Provenance::Damaged => 4,
    }
}

impl<'de> Deserialize<'de> for CompletenessRange {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SerializedRange {
            domain: RangeDomain,
            bounds: RangeBounds,
            provenance: Provenance,
            #[serde(default)]
            cause: CompletenessCause,
        }

        let value = SerializedRange::deserialize(deserializer)?;
        let range = match (value.domain, value.bounds) {
            (RangeDomain::CapturedSequence, RangeBounds::InclusiveSequence { first, last }) => {
                Self::captured_sequence_with_cause(first, last, value.provenance, value.cause)
            }
            (
                RangeDomain::SourceBytes,
                RangeBounds::HalfOpen {
                    start,
                    end_exclusive,
                },
            ) => Self::source_bytes_with_cause(start, end_exclusive, value.provenance, value.cause),
            (
                RangeDomain::MemoryAddresses,
                RangeBounds::HalfOpen {
                    start,
                    end_exclusive,
                },
            ) => Self::memory_addresses_with_cause(
                start,
                end_exclusive,
                value.provenance,
                value.cause,
            ),
            _ => None,
        };
        range.ok_or_else(|| de::Error::custom("invalid completeness range domain or bounds"))
    }
}

impl ProviderCapabilities {
    pub const fn qtrb_register_observations() -> Self {
        Self {
            global_ordering: false,
            per_thread_ordering: true,
            full_register_checkpoint: false,
            register_read_write_observation: true,
            memory_metadata: true,
            memory_before_after: true,
            lifecycle: true,
            signal_and_termination: true,
            loss_and_damage_ranges: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ArtifactDigest([u8; 32]);

impl ArtifactDigest {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_hex(value: &str) -> Option<Self> {
        let mut bytes = [0; 32];
        hex::decode_to_slice(value, &mut bytes).ok()?;
        Some(Self(bytes))
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for ArtifactDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

impl Serialize for ArtifactDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for ArtifactDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_hex(&value)
            .ok_or_else(|| de::Error::custom("expected a 64-digit SHA-256 hex digest"))
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct TimelineId(pub u64);

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct EventKey {
    pub artifact: ArtifactDigest,
    pub timeline: TimelineId,
    pub record_ordinal: u64,
    pub source_offset: u64,
    pub sequence: Option<u64>,
    pub tid: Option<u32>,
}

impl EventKey {
    pub const fn new(
        artifact: ArtifactDigest,
        timeline: TimelineId,
        record_ordinal: u64,
        source_offset: u64,
        sequence: Option<u64>,
        tid: Option<u32>,
    ) -> Self {
        Self {
            artifact,
            timeline,
            record_ordinal,
            source_offset,
            sequence,
            tid,
        }
    }
}
