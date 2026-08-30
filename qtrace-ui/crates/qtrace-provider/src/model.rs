use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    Captured,
    Derived,
    Heuristic,
    Unknown,
    Damaged,
}

#[derive(Clone, Debug, Eq, PartialEq)]
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
    Discontinuity,
    OpaqueOptional,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BeginMetadata {
    pub run_id: u64,
    pub pid: u32,
    pub tid: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ModuleDefinition {
    pub module_id: u32,
    pub base: u64,
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InstructionDefinition {
    pub definition_id: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Instruction {
    pub definition_id: u32,
    pub module_id: u32,
    pub relative_pc: u64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryDirection {
    Read,
    Write,
    ReadWrite,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Memory {
    pub address: u64,
    pub size: u32,
    pub direction: MemoryDirection,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SemanticEvent {
    pub category: Option<String>,
    pub name: String,
    pub detail: String,
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
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Syscall {
    pub tid: u32,
    pub number: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Signal {
    pub tid: u32,
    pub number: i32,
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
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminationKind {
    Completed,
    Stopped,
    Intent,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Termination {
    pub kind: TerminationKind,
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
    fragment_source_offsets: FragmentSourceOffsets,
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
            fragment_source_offsets,
        })
    }

    pub fn fragment_source_offsets(&self) -> &[u64] {
        self.fragment_source_offsets.as_slice()
    }

    pub const fn kind(&self) -> EventKind {
        self.payload.kind()
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
