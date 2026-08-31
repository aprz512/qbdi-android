mod cursor;
pub(crate) mod events;
mod input;
mod wire;

pub use events::{
    BeginMetadata, CaptureBytes, Instruction, InstructionDefinition, Memory, MemoryAddressMode,
    MemoryDirection, MemoryOperand, PcRelativeKind, RegisterDefinition, RegisterExtend,
    RegisterObservation, TerminalMetrics, Termination, TerminationIntent, TerminationKind,
    TraceProfile,
};
pub use input::QtrbInput;

use std::{collections::HashMap, fmt, mem::size_of, sync::Arc};

use cursor::PayloadCursor;
use wire::{RecordType, *};

use crate::{
    CompletenessCause, CompletenessRange, EventCursor, EventKey, EventPayload, EventRecord,
    ModuleDefinition, OpaqueOptionalRecord, Provenance, ProviderCapabilities, ProviderCounters,
    ProviderError, ProviderSummary, ReadAtSource, SemanticEvent, SourceCoordinate, SourceIdentity,
    TimelineDescriptor, TimelineId, TraceProvider, WorkDelta, WorkGuard,
};

const TIMELINE_ID: TimelineId = TimelineId(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenMode {
    Sealed,
    RecoverablePartial,
}

pub struct QtrbProvider {
    source: Arc<dyn ReadAtSource>,
    identity: SourceIdentity,
    capabilities: ProviderCapabilities,
    timelines: Vec<TimelineDescriptor>,
    mode: OpenMode,
    header: StreamHeader,
}

impl fmt::Debug for QtrbProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QtrbProvider")
            .field("identity", &self.identity)
            .field("mode", &self.mode)
            .field("header", &self.header)
            .finish_non_exhaustive()
    }
}

impl QtrbProvider {
    pub const CURSOR_RESIDENT_BYTES: usize = size_of::<QtrbEventCursor>();

    pub fn open(
        source: Arc<dyn ReadAtSource>,
        mut identity: SourceIdentity,
        mode: OpenMode,
        guard: &dyn WorkGuard,
    ) -> Result<Self, ProviderError> {
        let source_bytes = source.len();
        let mut bytes = [0_u8; STREAM_HEADER_BYTES];
        guard.consume(WorkDelta {
            input_bytes: STREAM_HEADER_BYTES as u64,
            decompressed_bytes: STREAM_HEADER_BYTES as u64,
            ..WorkDelta::default()
        })?;
        source
            .read_exact_at(0, &mut bytes)
            .map_err(|error| with_coordinate(error, 0, None, "qtrb.header"))?;
        let header = StreamHeader::parse(&bytes)?;
        identity.format_major = MAJOR_VERSION;
        identity.format_minor = header.minor;
        identity.source_bytes = source_bytes;
        let timeline_resident = size_of::<QtrbEventCursor>()
            .checked_add(size_of::<TimelineDescriptor>())
            .and_then(|bytes| bytes.checked_add(4))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| provider_allocation_error("QTRB provider allocation bound overflow"))?;
        guard.consume(WorkDelta {
            nodes: 1,
            resident_bytes: timeline_resident,
            ..WorkDelta::default()
        })?;
        let mut timelines = Vec::new();
        timelines
            .try_reserve_exact(1)
            .map_err(|_| provider_allocation_error("QTRB timeline allocation failed"))?;
        let mut label = String::new();
        label
            .try_reserve_exact(4)
            .map_err(|_| provider_allocation_error("QTRB timeline label allocation failed"))?;
        label.push_str("QTRB");
        timelines.push(TimelineDescriptor {
            id: TIMELINE_ID,
            tid: None,
            label: Some(label),
        });
        Ok(Self {
            source,
            identity,
            capabilities: ProviderCapabilities::qtrb_register_observations(),
            timelines,
            mode,
            header,
        })
    }
}

impl TraceProvider for QtrbProvider {
    fn identity(&self) -> &SourceIdentity {
        &self.identity
    }

    fn capabilities(&self) -> &ProviderCapabilities {
        &self.capabilities
    }

    fn timelines(&self) -> &[TimelineDescriptor] {
        &self.timelines
    }

    fn into_cursor(self: Box<Self>) -> Result<Box<dyn EventCursor>, ProviderError> {
        let provider = *self;
        Ok(Box::new(QtrbEventCursor {
            source: provider.source,
            identity: provider.identity,
            mode: provider.mode,
            header: provider.header,
            offset: STREAM_HEADER_BYTES as u64,
            next_ordinal: 0,
            modules: HashMap::new(),
            definitions: HashMap::new(),
            pending: None,
            began: false,
            terminal_seen: false,
            drained: false,
            poisoned: false,
            tid: None,
            next_sequence: 1,
            instruction_count: 0,
            effective_buffer_bytes: 0,
            termination: None,
            completeness: Vec::new(),
            counters: ProviderCounters {
                input_bytes: STREAM_HEADER_BYTES as u64,
                decompressed_bytes: STREAM_HEADER_BYTES as u64,
                ..ProviderCounters::default()
            },
        }))
    }
}

#[derive(Clone, Copy, Debug)]
struct StreamHeader {
    minor: u8,
    profile: u8,
    required_features: u32,
}

impl StreamHeader {
    fn parse(bytes: &[u8; STREAM_HEADER_BYTES]) -> Result<Self, ProviderError> {
        let coordinate = SourceCoordinate {
            offset: 0,
            record_ordinal: None,
        };
        let mut cursor = PayloadCursor::new(bytes, "stream header", coordinate);
        let magic = cursor.take(4)?;
        let major = cursor.u8()?;
        let minor = cursor.u8()?;
        let endian = cursor.u8()?;
        let pointer_width = cursor.u8()?;
        let profile = cursor.u8()?;
        let reserved = cursor.u8()?;
        let header_bytes = cursor.u16_le()?;
        let required_features = cursor.u32_le()?;
        cursor.finish()?;

        if magic != MAGIC {
            return Err(header_error("invalid QTRB magic"));
        }
        if major != MAJOR_VERSION {
            return Err(version_error("unsupported QTRB major version"));
        }
        if endian != LITTLE_ENDIAN_MARKER {
            return Err(header_error("QTRB stream is not little-endian"));
        }
        if !matches!(pointer_width, 4 | 8) {
            return Err(header_error("invalid QTRB pointer width"));
        }
        if profile > 2 {
            return Err(header_error("invalid QTRB trace profile"));
        }
        if reserved != 0 {
            return Err(header_error("nonzero QTRB header reserved byte"));
        }
        if usize::from(header_bytes) != STREAM_HEADER_BYTES {
            return Err(header_error("invalid QTRB stream header size"));
        }
        if !matches!((minor, required_features), (0, 0) | (1, 0) | (2, 1)) {
            return Err(version_error("unsupported QTRB minor/features matrix"));
        }
        Ok(Self {
            minor,
            profile,
            required_features,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ModuleWire {
    base: u64,
    name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RegisterWire {
    slot: u8,
    width: u8,
    name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MemoryOperandWire {
    base: u8,
    index: u8,
    extend: u8,
    mode: u8,
    shift: u8,
    kind: u8,
    writeback: u8,
    size: u32,
    displacement: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InstructionDefinitionWire {
    opcode: u32,
    read_mask: u64,
    write_mask: u64,
    displacement: i64,
    flags: u32,
    pc_kind: u8,
    condition: u8,
    slow_memory_path: u8,
    mnemonic: String,
    operands: String,
    disassembly: String,
    reads: Vec<RegisterWire>,
    writes: Vec<RegisterWire>,
    memory_operands: Vec<MemoryOperandWire>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FragmentKind {
    Call,
    Rule,
    Error,
}

#[derive(Debug)]
struct PendingFragment {
    kind: FragmentKind,
    event_id: u64,
    total_detail_bytes: u32,
    chunk_count: u16,
    next_index: u16,
    category: Option<Vec<u8>>,
    name: Vec<u8>,
    detail: Vec<u8>,
    first_offset: u64,
    first_ordinal: u64,
    fragment_offsets: Vec<u64>,
}

struct PhysicalRecord {
    record_type: Option<RecordType>,
    raw_type: u16,
    flags: u16,
    payload: Vec<u8>,
    offset: u64,
    ordinal: u64,
}

fn provider_allocation_error(detail: &'static str) -> ProviderError {
    ProviderError::new(
        "control.resource_exhausted",
        "qtrb.allocation",
        None,
        false,
        detail,
    )
}

fn hash_map_entry_resident_upper_bound<T>() -> u64 {
    // HashMap growth may reserve several buckets at once. Charging four entries
    // per insertion also covers control bytes and the initial small table.
    (size_of::<T>() as u64 + 1).saturating_mul(4)
}

fn record_resident_upper_bound(
    record_type: Option<RecordType>,
    flags: u16,
    payload_bytes: u32,
) -> u64 {
    let decoded = match (record_type, flags) {
        (Some(RecordType::TraceBegin), 0) => (2 * MAX_CONTEXT_STRING_BYTES) as u64,
        (Some(RecordType::ModuleDefinition), 0) => {
            (2 * MAX_MODULE_NAME_BYTES) as u64
                + hash_map_entry_resident_upper_bound::<(u32, ModuleWire)>()
        }
        (Some(RecordType::InstructionDefinition), 0) => {
            let string_bytes = MAX_MNEMONIC_BYTES
                + MAX_OPERANDS_BYTES
                + MAX_DISASSEMBLY_BYTES
                + 2 * MAX_GPR_COUNT * MAX_REGISTER_NAME_BYTES;
            let register_capacity = 2 * MAX_GPR_COUNT * size_of::<RegisterWire>();
            let memory_capacity = MAX_MEMORY_OPERAND_COUNT * size_of::<MemoryOperandWire>();
            (2 * (string_bytes + register_capacity + memory_capacity)) as u64
                + hash_map_entry_resident_upper_bound::<(u32, InstructionDefinitionWire)>()
        }
        (Some(RecordType::Instruction), 0) => {
            (2 * MAX_GPR_COUNT * (size_of::<RegisterObservation>() + MAX_REGISTER_NAME_BYTES))
                as u64
        }
        (Some(RecordType::Memory), 0) => (2 * MAX_CAPTURED_MEMORY_BYTES) as u64,
        (Some(RecordType::Call), 0) => {
            (MAX_CALL_CATEGORY_BYTES + MAX_CALL_NAME_BYTES + MAX_EVENT_DETAIL_BYTES) as u64
        }
        (Some(RecordType::Call), CHUNK_FLAG) => {
            (MAX_CALL_CATEGORY_BYTES + MAX_CALL_NAME_BYTES + MAX_CALL_CHUNK_DETAIL_BYTES) as u64
        }
        (Some(RecordType::Rule | RecordType::Error), 0) => {
            (MAX_EVENT_NAME_BYTES + MAX_EVENT_DETAIL_BYTES) as u64
        }
        (Some(RecordType::Rule | RecordType::Error), CHUNK_FLAG) => {
            (MAX_EVENT_NAME_BYTES + MAX_EVENT_CHUNK_DETAIL_BYTES) as u64
        }
        (Some(RecordType::TraceStop), 0) => "duration_elapsed".len() as u64,
        _ => 0,
    };
    u64::from(payload_bytes).saturating_add(decoded)
}

const fn record_node_upper_bound(
    record_type: Option<RecordType>,
    flags: u16,
    may_start_fragment: bool,
) -> u64 {
    match (record_type, flags, may_start_fragment) {
        (Some(RecordType::ModuleDefinition | RecordType::InstructionDefinition), 0, _) => 1,
        (Some(RecordType::Call | RecordType::Rule | RecordType::Error), CHUNK_FLAG, true) => 1,
        _ => 0,
    }
}

fn pending_fragment_resident_upper_bound(
    total_detail_bytes: u32,
    chunk_count: u16,
    category_bytes: usize,
    name_bytes: usize,
) -> u64 {
    u64::from(total_detail_bytes)
        .saturating_add(u64::from(chunk_count).saturating_mul(size_of::<u64>() as u64))
        .saturating_add(category_bytes as u64)
        .saturating_add(name_bytes as u64)
}

struct QtrbEventCursor {
    source: Arc<dyn ReadAtSource>,
    identity: SourceIdentity,
    mode: OpenMode,
    header: StreamHeader,
    offset: u64,
    next_ordinal: u64,
    modules: HashMap<u32, ModuleWire>,
    definitions: HashMap<u32, InstructionDefinitionWire>,
    pending: Option<PendingFragment>,
    began: bool,
    terminal_seen: bool,
    drained: bool,
    poisoned: bool,
    tid: Option<u32>,
    next_sequence: u64,
    instruction_count: u64,
    effective_buffer_bytes: u64,
    termination: Option<Termination>,
    completeness: Vec<CompletenessRange>,
    counters: ProviderCounters,
}

impl EventCursor for QtrbEventCursor {
    fn next_event(&mut self, guard: &dyn WorkGuard) -> Result<Option<EventRecord>, ProviderError> {
        if self.drained {
            return Ok(None);
        }
        if self.poisoned {
            return Err(ProviderError::new(
                "source.cursor_failed",
                "qtrb.cursor",
                None,
                false,
                "QTRB cursor cannot continue after a prior failure",
            ));
        }
        match self.next_event_inner(guard) {
            Ok(event) => Ok(event),
            Err(error) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }

    fn finish(self: Box<Self>) -> Result<ProviderSummary, ProviderError> {
        if !self.drained || self.poisoned {
            return Err(ProviderError::stream_not_drained());
        }
        self.validate_source_identity()?;
        let tid = self.tid;
        Ok(ProviderSummary {
            timelines: vec![TimelineDescriptor {
                id: TIMELINE_ID,
                tid,
                label: Some("QTRB".to_owned()),
            }],
            termination: self.termination,
            counters: self.counters,
            completeness: self.completeness,
        })
    }
}

impl QtrbEventCursor {
    fn next_event_inner(
        &mut self,
        guard: &dyn WorkGuard,
    ) -> Result<Option<EventRecord>, ProviderError> {
        loop {
            if self.terminal_seen {
                if self.offset < self.source.len() {
                    return Err(self.error_at_current(
                        "source.record_after_terminal",
                        "qtrb.lifecycle",
                        "record follows QTRB terminal",
                    ));
                }
                return self.finish_stream();
            }
            if self.offset == self.source.len() {
                return self.finish_stream();
            }
            if self.offset > self.source.len() {
                return Err(self.error_at_current(
                    "source.short_read",
                    "qtrb.read",
                    "QTRB cursor passed source end",
                ));
            }

            let record = self.read_record(guard)?;
            if !self.began && record.record_type != Some(RecordType::TraceBegin) {
                return Err(self.record_error(
                    &record,
                    "source.invalid_order",
                    "qtrb.lifecycle",
                    "TRACE_BEGIN must be the first record",
                ));
            }
            if let Some(pending) = &self.pending {
                let expected = match pending.kind {
                    FragmentKind::Call => Some(RecordType::Call),
                    FragmentKind::Rule => Some(RecordType::Rule),
                    FragmentKind::Error => Some(RecordType::Error),
                };
                if record.record_type != expected || record.flags != CHUNK_FLAG {
                    return Err(self.record_error(
                        &record,
                        "source.incomplete_fragment",
                        "qtrb.fragment",
                        "fragment records must be contiguous",
                    ));
                }
            }

            let event = self.decode_record(record, guard)?;
            if let Some(event) = event {
                guard.consume(WorkDelta {
                    events: 1,
                    ..WorkDelta::default()
                })?;
                self.counters.events_emitted = self.counters.events_emitted.saturating_add(1);
                return Ok(Some(event));
            }
        }
    }

    fn finish_stream(&mut self) -> Result<Option<EventRecord>, ProviderError> {
        self.validate_source_identity()?;
        if self.pending.is_some() {
            return Err(self.error_at_current(
                "source.incomplete_fragment",
                "qtrb.fragment",
                "source ended during a logical fragment group",
            ));
        }
        if !self.began {
            return Err(self.error_at_current(
                "source.invalid_order",
                "qtrb.lifecycle",
                "QTRB source has no TRACE_BEGIN",
            ));
        }
        if !self.terminal_seen {
            match self.mode {
                OpenMode::Sealed => {
                    return Err(self.error_at_current(
                        "source.missing_terminal",
                        "qtrb.lifecycle",
                        "sealed QTRB source has no successful terminal",
                    ));
                }
                OpenMode::RecoverablePartial => {
                    if let Some(range) = CompletenessRange::source_bytes_with_cause(
                        self.offset,
                        self.offset,
                        Provenance::Unknown,
                        CompletenessCause::MissingTerminal,
                    ) {
                        self.completeness.push(range);
                    }
                }
            }
        }
        if let Some(range) = CompletenessRange::source_bytes_with_cause(
            0,
            self.offset,
            Provenance::Captured,
            CompletenessCause::Retained,
        ) {
            self.completeness.insert(0, range);
        }
        self.drained = true;
        Ok(None)
    }

    fn validate_source_identity(&self) -> Result<(), ProviderError> {
        if self.source.len() != self.identity.source_bytes {
            return Err(ProviderError::new(
                "source.identity_changed",
                "qtrb.identity",
                Some(SourceCoordinate {
                    offset: self.offset,
                    record_ordinal: Some(self.next_ordinal),
                }),
                false,
                "QTRB source length changed while parsing",
            ));
        }
        Ok(())
    }

    fn read_record(&mut self, guard: &dyn WorkGuard) -> Result<PhysicalRecord, ProviderError> {
        let record_offset = self.offset;
        let ordinal = self.next_ordinal;
        let coordinate = SourceCoordinate {
            offset: record_offset,
            record_ordinal: Some(ordinal),
        };
        let mut header = [0_u8; RECORD_HEADER_BYTES];
        guard.consume(WorkDelta {
            input_bytes: RECORD_HEADER_BYTES as u64,
            decompressed_bytes: RECORD_HEADER_BYTES as u64,
            ..WorkDelta::default()
        })?;
        self.source
            .read_exact_at(record_offset, &mut header)
            .map_err(|error| with_coordinate(error, record_offset, Some(ordinal), "qtrb.record"))?;
        self.offset = self
            .offset
            .checked_add(RECORD_HEADER_BYTES as u64)
            .ok_or_else(|| self.record_overflow_error(record_offset, ordinal))?;

        let mut cursor = PayloadCursor::new(&header, "record header", coordinate);
        let raw_type = cursor.u16_le()?;
        let flags = cursor.u16_le()?;
        let payload_bytes = cursor.u32_le()?;
        cursor.finish()?;
        let record_type = RecordType::from_raw(raw_type);
        let payload_limit = match record_type {
            Some(record_type) => record_type.payload_limit(flags).ok_or_else(|| {
                ProviderError::new(
                    "source.unsupported_record",
                    "qtrb.framing",
                    Some(coordinate),
                    false,
                    format!("unsupported flags {flags:#x} for record type {raw_type}"),
                )
            })?,
            None if raw_type >= OPTIONAL_RECORD_TYPE_MIN
                && self.header.minor >= 1
                && flags == 0 =>
            {
                MAX_OPAQUE_PAYLOAD_BYTES
            }
            None => {
                return Err(ProviderError::new(
                    "source.unsupported_record",
                    "qtrb.framing",
                    Some(coordinate),
                    false,
                    format!("unsupported required record type {raw_type} or flags {flags:#x}"),
                ));
            }
        };
        if payload_bytes > payload_limit {
            return Err(ProviderError::new(
                "source.record_too_large",
                "qtrb.framing",
                Some(coordinate),
                false,
                format!(
                    "record type {raw_type} payload {payload_bytes} exceeds {payload_limit} bytes"
                ),
            ));
        }

        let payload_len = usize::try_from(payload_bytes).map_err(|_| {
            ProviderError::new(
                "source.record_too_large",
                "qtrb.framing",
                Some(coordinate),
                false,
                "record payload cannot be represented on this host",
            )
        })?;
        guard.consume(WorkDelta {
            input_bytes: u64::from(payload_bytes),
            decompressed_bytes: u64::from(payload_bytes),
            nodes: record_node_upper_bound(record_type, flags, self.pending.is_none()),
            resident_bytes: record_resident_upper_bound(record_type, flags, payload_bytes),
            ..WorkDelta::default()
        })?;
        let mut payload = vec![0_u8; payload_len];
        self.source
            .read_exact_at(self.offset, &mut payload)
            .map_err(|error| {
                with_coordinate(error, record_offset, Some(ordinal), "qtrb.payload")
            })?;
        self.offset = self
            .offset
            .checked_add(u64::from(payload_bytes))
            .ok_or_else(|| self.record_overflow_error(record_offset, ordinal))?;
        self.next_ordinal = self
            .next_ordinal
            .checked_add(1)
            .ok_or_else(|| self.record_overflow_error(record_offset, ordinal))?;
        self.counters.records_seen = self.counters.records_seen.saturating_add(1);
        self.counters.input_bytes = self
            .counters
            .input_bytes
            .saturating_add(RECORD_HEADER_BYTES as u64 + u64::from(payload_bytes));
        self.counters.decompressed_bytes = self
            .counters
            .decompressed_bytes
            .saturating_add(RECORD_HEADER_BYTES as u64 + u64::from(payload_bytes));
        Ok(PhysicalRecord {
            record_type,
            raw_type,
            flags,
            payload,
            offset: record_offset,
            ordinal,
        })
    }

    fn decode_record(
        &mut self,
        record: PhysicalRecord,
        guard: &dyn WorkGuard,
    ) -> Result<Option<EventRecord>, ProviderError> {
        match record.record_type {
            Some(RecordType::TraceBegin) => self.decode_begin(record).map(Some),
            Some(RecordType::ModuleDefinition) => self.decode_module(record).map(Some),
            Some(RecordType::InstructionDefinition) => {
                self.decode_instruction_definition(record).map(Some)
            }
            Some(RecordType::Instruction) => self.decode_instruction(record).map(Some),
            Some(RecordType::Memory) => self.decode_memory(record).map(Some),
            Some(RecordType::Call) => self.decode_semantic(record, FragmentKind::Call, guard),
            Some(RecordType::Rule) => self.decode_semantic(record, FragmentKind::Rule, guard),
            Some(RecordType::Error) => self.decode_semantic(record, FragmentKind::Error, guard),
            Some(RecordType::TraceEnd) => self.decode_trace_end(record).map(Some),
            Some(RecordType::TraceStop) => self.decode_trace_stop(record).map(Some),
            None => {
                self.counters.opaque_records = self.counters.opaque_records.saturating_add(1);
                let key = EventKey::new(
                    self.identity.artifact,
                    TIMELINE_ID,
                    record.ordinal,
                    record.offset,
                    None,
                    self.tid,
                );
                Ok(Some(EventRecord::new(
                    key,
                    Provenance::Captured,
                    EventPayload::OpaqueOptional(OpaqueOptionalRecord {
                        record_type: record.raw_type,
                        flags: record.flags,
                        bytes: record.payload,
                    }),
                )))
            }
        }
    }

    fn decode_begin(&mut self, record: PhysicalRecord) -> Result<EventRecord, ProviderError> {
        if self.began {
            return Err(self.record_error(
                &record,
                "source.invalid_order",
                "qtrb.lifecycle",
                "TRACE_BEGIN appears more than once",
            ));
        }
        let coordinate = coordinate(&record);
        let mut cursor = PayloadCursor::new(&record.payload, "TRACE_BEGIN", coordinate);
        let module_base = cursor.u64_le()?;
        let target_offset = cursor.u64_le()?;
        let target_address = cursor.u64_le()?;
        let pid = cursor.u32_le()?;
        let tid = cursor.u32_le()?;
        let profile = cursor.u8()?;
        let compression = cursor.u8()?;
        let effective_buffer_bytes = cursor.u64_le()?;
        let run_id = cursor.u64_le()?;
        let scene = cursor.bounded_utf8(MAX_CONTEXT_STRING_BYTES, "scene")?;
        let target = cursor.bounded_utf8(MAX_CONTEXT_STRING_BYTES, "target")?;
        cursor.finish()?;
        if profile != self.header.profile || !matches!(compression, 0 | 1) {
            return Err(self.record_error(
                &record,
                "source.invalid_payload",
                "qtrb.lifecycle",
                "TRACE_BEGIN profile or compression does not match the stream",
            ));
        }
        self.began = true;
        self.tid = Some(tid);
        self.effective_buffer_bytes = effective_buffer_bytes;
        Ok(self.event(
            &record,
            None,
            EventPayload::Begin(BeginMetadata {
                module_base,
                target_offset,
                target_address,
                pid,
                tid: Some(tid),
                profile: match profile {
                    0 => TraceProfile::Fast,
                    1 => TraceProfile::Balanced,
                    _ => TraceProfile::Full,
                },
                compression_enabled: compression == 1,
                effective_buffer_bytes,
                run_id,
                scene,
                target,
                pointer_width: 0,
                chunk_index: None,
                chunk_generation: None,
            }),
        ))
    }

    fn decode_module(&mut self, record: PhysicalRecord) -> Result<EventRecord, ProviderError> {
        let mut cursor = PayloadCursor::new(&record.payload, "MODULE_DEF", coordinate(&record));
        let module_id = cursor.u32_le()?;
        let base = cursor.u64_le()?;
        let name = cursor.bounded_utf8(MAX_MODULE_NAME_BYTES, "module name")?;
        cursor.finish()?;
        let definition = ModuleWire {
            base,
            name: name.clone(),
        };
        match self.modules.get(&module_id) {
            Some(existing) if existing != &definition => {
                return Err(self.record_error(
                    &record,
                    "source.definition_conflict",
                    "qtrb.dictionary",
                    "conflicting module definition",
                ));
            }
            None if self.modules.len() >= MAX_DICTIONARY_ENTRIES => {
                return Err(self.record_error(
                    &record,
                    "source.dictionary_limit",
                    "qtrb.dictionary",
                    "module dictionary limit exceeded",
                ));
            }
            None => {
                self.modules.insert(module_id, definition);
            }
            Some(_) => {}
        }
        Ok(self.event(
            &record,
            None,
            EventPayload::ModuleDefinition(ModuleDefinition {
                module_id,
                base,
                name,
            }),
        ))
    }

    fn decode_instruction_definition(
        &mut self,
        record: PhysicalRecord,
    ) -> Result<EventRecord, ProviderError> {
        let _shared_definition =
            events::decode_instruction_definition_payload(&record.payload, coordinate(&record))?;
        let mut cursor =
            PayloadCursor::new(&record.payload, "INSTRUCTION_DEF", coordinate(&record));
        let metadata_id = cursor.u32_le()?;
        let opcode = cursor.u32_le()?;
        let read_mask = cursor.u64_le()?;
        let write_mask = cursor.u64_le()?;
        let displacement = cursor.i64_le()?;
        let flags = cursor.u32_le()?;
        let pc_kind = cursor.u8()?;
        let condition = cursor.u8()?;
        let memory_count = usize::from(cursor.u8()?);
        let slow_memory_path = cursor.u8()?;
        if flags & !VALID_INSTRUCTION_FLAGS != 0
            || pc_kind > 2
            || slow_memory_path > 1
            || memory_count > MAX_MEMORY_OPERAND_COUNT
            || read_mask >> MAX_GPR_COUNT != 0
            || write_mask >> MAX_GPR_COUNT != 0
        {
            return Err(self.record_error(
                &record,
                "source.invalid_payload",
                "qtrb.instruction_definition",
                "invalid instruction definition metadata",
            ));
        }
        let mnemonic = cursor.bounded_utf8(MAX_MNEMONIC_BYTES, "mnemonic")?;
        let operands = cursor.bounded_utf8(MAX_OPERANDS_BYTES, "operands")?;
        let disassembly = cursor.bounded_utf8(MAX_DISASSEMBLY_BYTES, "disassembly")?;
        let reads = decode_registers(&mut cursor, read_mask, "read register", coordinate(&record))?;
        let writes = decode_registers(
            &mut cursor,
            write_mask,
            "write register",
            coordinate(&record),
        )?;
        let mut memory_operands = Vec::with_capacity(memory_count);
        for _ in 0..memory_count {
            let operand = MemoryOperandWire {
                base: cursor.u8()?,
                index: cursor.u8()?,
                extend: cursor.u8()?,
                mode: cursor.u8()?,
                shift: cursor.u8()?,
                kind: cursor.u8()?,
                writeback: cursor.u8()?,
                size: cursor.u32_le()?,
                displacement: cursor.i64_le()?,
            };
            if (operand.base >= MAX_GPR_COUNT as u8 && operand.base != u8::MAX)
                || (operand.index >= MAX_GPR_COUNT as u8 && operand.index != u8::MAX)
                || operand.extend > 4
                || operand.mode > 2
                || !matches!(operand.kind, 1..=3)
                || operand.writeback > 1
            {
                return Err(self.record_error(
                    &record,
                    "source.invalid_payload",
                    "qtrb.instruction_definition",
                    "invalid instruction memory operand",
                ));
            }
            memory_operands.push(operand);
        }
        cursor.finish()?;
        let definition = InstructionDefinitionWire {
            opcode,
            read_mask,
            write_mask,
            displacement,
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
        };
        match self.definitions.get(&metadata_id) {
            Some(existing) if existing != &definition => {
                return Err(self.record_error(
                    &record,
                    "source.definition_conflict",
                    "qtrb.dictionary",
                    "conflicting instruction definition",
                ));
            }
            None if self.definitions.len() >= MAX_DICTIONARY_ENTRIES => {
                return Err(self.record_error(
                    &record,
                    "source.dictionary_limit",
                    "qtrb.dictionary",
                    "instruction dictionary limit exceeded",
                ));
            }
            None => {
                self.definitions.insert(metadata_id, definition.clone());
            }
            Some(_) => {}
        }
        Ok(self.event(
            &record,
            None,
            EventPayload::InstructionDefinition(typed_definition(metadata_id, &definition)),
        ))
    }

    fn decode_instruction(&mut self, record: PhysicalRecord) -> Result<EventRecord, ProviderError> {
        let mut cursor = PayloadCursor::new(&record.payload, "INSTRUCTION", coordinate(&record));
        let sequence = cursor.u64_le()?;
        let module_id = cursor.u32_le()?;
        let relative_pc = cursor.u64_le()?;
        let metadata_id = cursor.u32_le()?;
        let read_count = usize::from(cursor.u8()?);
        let write_count = usize::from(cursor.u8()?);
        if !self.modules.contains_key(&module_id) || !self.definitions.contains_key(&metadata_id) {
            return Err(self.record_error(
                &record,
                "source.undefined_reference",
                "qtrb.dictionary",
                "instruction references an undefined module or metadata definition",
            ));
        }
        let definition = &self.definitions[&metadata_id];
        if read_count != definition.reads.len() || write_count != definition.writes.len() {
            return Err(self.record_error(
                &record,
                "source.invalid_payload",
                "qtrb.instruction",
                "instruction register counts do not match its definition",
            ));
        }
        let shared_definition = typed_definition(metadata_id, definition);
        let shared = events::decode_instruction_payload(
            &record.payload,
            &shared_definition,
            None,
            coordinate(&record),
        )?;
        let mut read_before = Vec::with_capacity(read_count);
        for register in &definition.reads {
            read_before.push(RegisterObservation {
                slot: register.slot,
                captured_width: register.width,
                name: register.name.clone(),
                value: cursor.u64_le()?,
            });
        }
        let mut write_after = Vec::with_capacity(write_count);
        for register in &definition.writes {
            write_after.push(RegisterObservation {
                slot: register.slot,
                captured_width: register.width,
                name: register.name.clone(),
                value: cursor.u64_le()?,
            });
        }
        cursor.finish()?;
        if sequence != self.next_sequence {
            return Err(self.record_error(
                &record,
                "source.sequence_gap",
                "qtrb.sequence",
                "instruction sequence is not contiguous",
            ));
        }
        self.next_sequence = self.next_sequence.checked_add(1).ok_or_else(|| {
            self.record_error(
                &record,
                "source.sequence_gap",
                "qtrb.sequence",
                "instruction sequence overflows u64",
            )
        })?;
        self.instruction_count = self.instruction_count.checked_add(1).ok_or_else(|| {
            self.record_error(
                &record,
                "source.terminal_counter_mismatch",
                "qtrb.sequence",
                "instruction counter overflows u64",
            )
        })?;
        debug_assert_eq!(shared.local_sequence, sequence);
        debug_assert_eq!(shared.instruction.read_before, read_before);
        debug_assert_eq!(shared.instruction.write_after, write_after);
        Ok(self.event(
            &record,
            Some(sequence),
            EventPayload::Instruction(Instruction {
                definition_id: metadata_id,
                module_id,
                relative_pc,
                read_before,
                write_after,
            }),
        ))
    }

    fn decode_memory(&self, record: PhysicalRecord) -> Result<EventRecord, ProviderError> {
        let shared = events::decode_memory_payload(&record.payload, coordinate(&record))?;
        let mut cursor = PayloadCursor::new(&record.payload, "MEMORY", coordinate(&record));
        let module_id = cursor.u32_le()?;
        let relative_pc = cursor.u64_le()?;
        let direction = match cursor.u8()? {
            1 => MemoryDirection::Read,
            2 => MemoryDirection::Write,
            3 => MemoryDirection::ReadWrite,
            _ => {
                return Err(self.record_error(
                    &record,
                    "source.invalid_payload",
                    "qtrb.memory",
                    "invalid memory access direction",
                ));
            }
        };
        let metadata_available = cursor.u8()?;
        let flags = cursor.u16_le()?;
        let address = cursor.u64_le()?;
        let size = cursor.u32_le()?;
        let value = cursor.u64_le()?;
        if !self.modules.contains_key(&module_id) {
            return Err(self.record_error(
                &record,
                "source.undefined_reference",
                "qtrb.dictionary",
                "memory record references an undefined module",
            ));
        }
        if metadata_available > 1 {
            return Err(self.record_error(
                &record,
                "source.invalid_payload",
                "qtrb.memory",
                "invalid memory metadata availability",
            ));
        }
        let before = decode_memory_state(&mut cursor, "before memory", coordinate(&record))?;
        let after = decode_memory_state(&mut cursor, "after memory", coordinate(&record))?;
        cursor.finish()?;
        debug_assert_eq!(shared.module_id, module_id);
        debug_assert_eq!(shared.before, before);
        debug_assert_eq!(shared.after, after);
        Ok(self.event(
            &record,
            None,
            EventPayload::Memory(Memory {
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
            }),
        ))
    }

    fn decode_semantic(
        &mut self,
        record: PhysicalRecord,
        kind: FragmentKind,
        guard: &dyn WorkGuard,
    ) -> Result<Option<EventRecord>, ProviderError> {
        if record.flags == 0 {
            let mut cursor =
                PayloadCursor::new(&record.payload, "semantic event", coordinate(&record));
            let category = if kind == FragmentKind::Call {
                Some(cursor.bounded_utf8(MAX_CALL_CATEGORY_BYTES, "CALL category")?)
            } else {
                None
            };
            let name_limit = if kind == FragmentKind::Call {
                MAX_CALL_NAME_BYTES
            } else {
                MAX_EVENT_NAME_BYTES
            };
            let name = cursor.bounded_utf8(name_limit, "event name")?;
            let detail = cursor.bounded_utf8(MAX_EVENT_DETAIL_BYTES, "event detail")?;
            cursor.finish()?;
            return Ok(Some(
                self.semantic_event(&record, kind, category, name, detail),
            ));
        }
        if kind != FragmentKind::Call && self.header.minor == 0 {
            return Err(self.record_error(
                &record,
                "source.version_unsupported",
                "qtrb.fragment",
                "RULE/ERROR fragments require QTRB minor 1 or newer",
            ));
        }
        self.decode_fragment(record, kind, guard)
    }

    fn decode_fragment(
        &mut self,
        record: PhysicalRecord,
        kind: FragmentKind,
        guard: &dyn WorkGuard,
    ) -> Result<Option<EventRecord>, ProviderError> {
        let mut cursor =
            PayloadCursor::new(&record.payload, "semantic fragment", coordinate(&record));
        let event_id = cursor.u64_le()?;
        let total_detail_bytes = cursor.u32_le()?;
        let chunk_index = cursor.u16_le()?;
        let chunk_count = cursor.u16_le()?;
        let category = if kind == FragmentKind::Call {
            Some(decode_bounded_raw(
                &mut cursor,
                MAX_CALL_CATEGORY_BYTES,
                "CALL category",
                coordinate(&record),
            )?)
        } else {
            None
        };
        let name_limit = if kind == FragmentKind::Call {
            MAX_CALL_NAME_BYTES
        } else {
            MAX_EVENT_NAME_BYTES
        };
        let name = decode_bounded_raw(&mut cursor, name_limit, "event name", coordinate(&record))?;
        let fragment_maximum = if kind == FragmentKind::Call {
            MAX_CALL_CHUNK_DETAIL_BYTES
        } else {
            MAX_EVENT_CHUNK_DETAIL_BYTES
        };
        let detail = decode_bounded_raw(
            &mut cursor,
            fragment_maximum,
            "event detail fragment",
            coordinate(&record),
        )?;
        cursor.finish()?;
        let logical_maximum = if kind == FragmentKind::Call {
            MAX_LOGICAL_CALL_DETAIL_BYTES
        } else {
            MAX_EVENT_DETAIL_BYTES as u32
        };
        if event_id == 0
            || chunk_count < 2
            || chunk_index >= chunk_count
            || total_detail_bytes > logical_maximum
            || detail.is_empty()
            || total_detail_bytes <= detail.len() as u32
            || total_detail_bytes < u32::from(chunk_count)
        {
            return Err(self.record_error(
                &record,
                "source.invalid_fragment",
                "qtrb.fragment",
                "invalid semantic fragment metadata",
            ));
        }

        let mut pending = match self.pending.take() {
            Some(pending) => pending,
            None => {
                if chunk_index != 0 {
                    return Err(self.record_error(
                        &record,
                        "source.invalid_fragment",
                        "qtrb.fragment",
                        "fragment index must start at zero",
                    ));
                }
                guard.consume(WorkDelta {
                    resident_bytes: pending_fragment_resident_upper_bound(
                        total_detail_bytes,
                        chunk_count,
                        category.as_ref().map_or(0, Vec::len),
                        name.len(),
                    ),
                    ..WorkDelta::default()
                })?;
                PendingFragment {
                    kind,
                    event_id,
                    total_detail_bytes,
                    chunk_count,
                    next_index: 0,
                    category: category.clone(),
                    name: name.clone(),
                    detail: Vec::with_capacity(total_detail_bytes as usize),
                    first_offset: record.offset,
                    first_ordinal: record.ordinal,
                    fragment_offsets: Vec::with_capacity(usize::from(chunk_count)),
                }
            }
        };
        if pending.kind != kind
            || pending.event_id != event_id
            || pending.total_detail_bytes != total_detail_bytes
            || pending.chunk_count != chunk_count
            || pending.category != category
            || pending.name != name
        {
            return Err(self.record_error(
                &record,
                "source.invalid_fragment",
                "qtrb.fragment",
                "fragment metadata does not match the logical event",
            ));
        }
        if chunk_index != pending.next_index {
            return Err(self.record_error(
                &record,
                "source.invalid_fragment",
                "qtrb.fragment",
                "fragment index is duplicate or out of order",
            ));
        }
        pending.detail.extend_from_slice(&detail);
        pending.fragment_offsets.push(record.offset);
        pending.next_index = pending.next_index.saturating_add(1);
        if pending.detail.len() > pending.total_detail_bytes as usize {
            return Err(self.record_error(
                &record,
                "source.invalid_fragment",
                "qtrb.fragment",
                "fragment data exceeds declared logical detail length",
            ));
        }
        if pending.next_index < pending.chunk_count {
            self.pending = Some(pending);
            return Ok(None);
        }
        if pending.detail.len() != pending.total_detail_bytes as usize
            || pending.fragment_offsets.len() != usize::from(pending.chunk_count)
        {
            return Err(self.record_error(
                &record,
                "source.invalid_fragment",
                "qtrb.fragment",
                "fragment group does not match declared length or count",
            ));
        }
        let category = pending
            .category
            .map(|bytes| {
                String::from_utf8(bytes).map_err(|_| {
                    self.record_error(
                        &record,
                        "source.invalid_utf8",
                        "qtrb.fragment",
                        "logical CALL category is not valid UTF-8",
                    )
                })
            })
            .transpose()?;
        let name = String::from_utf8(pending.name).map_err(|_| {
            self.record_error(
                &record,
                "source.invalid_utf8",
                "qtrb.fragment",
                "logical event name is not valid UTF-8",
            )
        })?;
        let detail = String::from_utf8(pending.detail).map_err(|_| {
            self.record_error(
                &record,
                "source.invalid_utf8",
                "qtrb.fragment",
                "logical event detail is not valid UTF-8",
            )
        })?;
        let first = PhysicalRecord {
            record_type: record.record_type,
            raw_type: record.raw_type,
            flags: record.flags,
            payload: Vec::new(),
            offset: pending.first_offset,
            ordinal: pending.first_ordinal,
        };
        let event = self.semantic_event(&first, kind, category, name, detail);
        let event = EventRecord::with_fragment_source_offsets(
            event.key,
            event.provenance,
            event.payload,
            pending.fragment_offsets,
        )
        .ok_or_else(|| {
            self.record_error(
                &record,
                "source.invalid_fragment",
                "qtrb.fragment",
                "fragment provenance offsets are invalid or exceed their bound",
            )
        })?;
        Ok(Some(event))
    }

    fn semantic_event(
        &self,
        record: &PhysicalRecord,
        kind: FragmentKind,
        category: Option<String>,
        name: String,
        detail: String,
    ) -> EventRecord {
        let semantic = SemanticEvent {
            category,
            name,
            detail,
            fragment_sequences: Vec::new(),
        };
        let payload = match kind {
            FragmentKind::Call => EventPayload::SemanticCall(semantic),
            FragmentKind::Rule => EventPayload::SemanticRule(semantic),
            FragmentKind::Error => EventPayload::SemanticError(semantic),
        };
        self.event(record, None, payload)
    }

    fn decode_trace_end(&mut self, record: PhysicalRecord) -> Result<EventRecord, ProviderError> {
        if record.payload.len() != TRACE_END_PAYLOAD_BYTES as usize {
            return Err(self.invalid_terminal(&record, "invalid TRACE_END payload size"));
        }
        let mut cursor = PayloadCursor::new(&record.payload, "TRACE_END", coordinate(&record));
        let success = cursor.u8()?;
        let return_value = cursor.u64_le()?;
        let elapsed_ms = cursor.u64_le()?;
        let metrics = decode_metrics(&mut cursor)?;
        cursor.finish()?;
        if success != 1 {
            return Err(self.invalid_terminal(&record, "TRACE_END is not successful"));
        }
        self.accept_terminal(
            &record,
            &metrics,
            TerminationKind::Completed,
            None,
            Some(return_value),
            elapsed_ms,
        )
    }

    fn decode_trace_stop(&mut self, record: PhysicalRecord) -> Result<EventRecord, ProviderError> {
        if self.header.minor != 2 || self.header.required_features & STOPPED_TERMINAL_FEATURE == 0 {
            return Err(self.record_error(
                &record,
                "source.version_unsupported",
                "qtrb.lifecycle",
                "TRACE_STOP requires QTRB 1.2 feature bit 0",
            ));
        }
        if record.payload.len() != TRACE_STOP_PAYLOAD_BYTES as usize {
            return Err(self.invalid_terminal(&record, "invalid TRACE_STOP payload size"));
        }
        let mut cursor = PayloadCursor::new(&record.payload, "TRACE_STOP", coordinate(&record));
        let reason = cursor.u8()?;
        let reserved = cursor.take(7)?;
        let elapsed_ms = cursor.u64_le()?;
        let metrics = decode_metrics(&mut cursor)?;
        cursor.finish()?;
        if reason != 1 || reserved != [0; 7] {
            return Err(
                self.invalid_terminal(&record, "invalid TRACE_STOP reason or reserved bytes")
            );
        }
        self.accept_terminal(
            &record,
            &metrics,
            TerminationKind::Stopped,
            Some("duration_elapsed".to_owned()),
            None,
            elapsed_ms,
        )
    }

    fn accept_terminal(
        &mut self,
        record: &PhysicalRecord,
        metrics: &[u64; 10],
        kind: TerminationKind,
        reason: Option<String>,
        return_value: Option<u64>,
        elapsed_ms: u64,
    ) -> Result<EventRecord, ProviderError> {
        if self.offset != self.source.len() {
            return Err(self.record_error(
                record,
                "source.record_after_terminal",
                "qtrb.lifecycle",
                "record follows QTRB terminal",
            ));
        }
        if metrics[0] != self.instruction_count
            || metrics[1] != self.offset
            || metrics[9] != self.effective_buffer_bytes
        {
            return Err(self.record_error(
                record,
                "source.terminal_counter_mismatch",
                "qtrb.lifecycle",
                "terminal instruction, encoded-byte, or buffer metric does not match the stream",
            ));
        }
        let termination = Termination {
            kind,
            reason,
            return_value,
            elapsed_ms,
            metrics: TerminalMetrics {
                instructions: metrics[0],
                encoded_bytes: metrics[1],
                compressed_bytes: metrics[2],
                cache_hits: metrics[3],
                cache_misses: metrics[4],
                cache_collisions: metrics[5],
                buffer_swaps: metrics[6],
                producer_waits: metrics[7],
                producer_wait_ns: metrics[8],
                effective_buffer_bytes: metrics[9],
            },
            intent: None,
        };
        self.termination = Some(termination.clone());
        self.terminal_seen = true;
        Ok(self.event(record, None, EventPayload::Termination(termination)))
    }

    fn event(
        &self,
        record: &PhysicalRecord,
        sequence: Option<u64>,
        payload: EventPayload,
    ) -> EventRecord {
        EventRecord::new(
            EventKey::new(
                self.identity.artifact,
                TIMELINE_ID,
                record.ordinal,
                record.offset,
                sequence,
                self.tid,
            ),
            Provenance::Captured,
            payload,
        )
    }

    fn invalid_terminal(&self, record: &PhysicalRecord, detail: &str) -> ProviderError {
        self.record_error(record, "source.invalid_terminal", "qtrb.lifecycle", detail)
    }

    fn error_at_current(&self, code: &str, stage: &str, detail: &str) -> ProviderError {
        ProviderError::new(
            code,
            stage,
            Some(SourceCoordinate {
                offset: self.offset,
                record_ordinal: Some(self.next_ordinal),
            }),
            false,
            detail,
        )
    }

    fn record_error(
        &self,
        record: &PhysicalRecord,
        code: &str,
        stage: &str,
        detail: &str,
    ) -> ProviderError {
        ProviderError::new(code, stage, Some(coordinate(record)), false, detail)
    }

    fn record_overflow_error(&self, offset: u64, ordinal: u64) -> ProviderError {
        ProviderError::new(
            "source.coordinate_overflow",
            "qtrb.framing",
            Some(SourceCoordinate {
                offset,
                record_ordinal: Some(ordinal),
            }),
            false,
            "QTRB source coordinate overflow",
        )
    }
}

fn decode_registers(
    cursor: &mut PayloadCursor<'_>,
    mask: u64,
    field: &'static str,
    coordinate: SourceCoordinate,
) -> Result<Vec<RegisterWire>, ProviderError> {
    let count = mask.count_ones() as usize;
    let mut registers = Vec::with_capacity(count);
    for slot in 0..MAX_GPR_COUNT {
        if mask & (1_u64 << slot) == 0 {
            continue;
        }
        let width = cursor.u8()?;
        let name = cursor.bounded_utf8(MAX_REGISTER_NAME_BYTES, field)?;
        if width == 0 || width > 16 || name.is_empty() {
            return Err(ProviderError::new(
                "source.invalid_payload",
                "qtrb.instruction_definition",
                Some(coordinate),
                false,
                format!("invalid {field} definition"),
            ));
        }
        registers.push(RegisterWire {
            slot: slot as u8,
            width,
            name,
        });
    }
    Ok(registers)
}

fn typed_definition(
    definition_id: u32,
    definition: &InstructionDefinitionWire,
) -> InstructionDefinition {
    InstructionDefinition {
        definition_id,
        opcode: definition.opcode,
        read_mask: definition.read_mask,
        write_mask: definition.write_mask,
        pc_displacement: definition.displacement,
        flags: definition.flags,
        pc_kind: match definition.pc_kind {
            0 => PcRelativeKind::None,
            1 => PcRelativeKind::Instruction,
            _ => PcRelativeKind::Page,
        },
        condition: definition.condition,
        slow_memory_path: definition.slow_memory_path == 1,
        mnemonic: definition.mnemonic.clone(),
        operands: definition.operands.clone(),
        disassembly: definition.disassembly.clone(),
        reads: definition.reads.iter().map(typed_register).collect(),
        writes: definition.writes.iter().map(typed_register).collect(),
        memory_operands: definition
            .memory_operands
            .iter()
            .map(typed_memory_operand)
            .collect(),
    }
}

fn typed_register(register: &RegisterWire) -> RegisterDefinition {
    RegisterDefinition {
        slot: register.slot,
        captured_width: register.width,
        name: register.name.clone(),
    }
}

fn typed_memory_operand(operand: &MemoryOperandWire) -> MemoryOperand {
    MemoryOperand {
        base: (operand.base != u8::MAX).then_some(operand.base),
        index: (operand.index != u8::MAX).then_some(operand.index),
        extend: match operand.extend {
            0 => RegisterExtend::None,
            1 => RegisterExtend::Uxtw,
            2 => RegisterExtend::Sxtw,
            3 => RegisterExtend::Lsl,
            _ => RegisterExtend::Sxtx,
        },
        mode: match operand.mode {
            0 => MemoryAddressMode::Offset,
            1 => MemoryAddressMode::PreIndex,
            _ => MemoryAddressMode::PostIndex,
        },
        shift: operand.shift,
        direction: match operand.kind {
            1 => MemoryDirection::Read,
            2 => MemoryDirection::Write,
            _ => MemoryDirection::ReadWrite,
        },
        writeback: operand.writeback == 1,
        size: operand.size,
        displacement: operand.displacement,
    }
}

fn decode_bounded_raw(
    cursor: &mut PayloadCursor<'_>,
    maximum: usize,
    field: &'static str,
    coordinate: SourceCoordinate,
) -> Result<Vec<u8>, ProviderError> {
    let size = usize::from(cursor.u16_le()?);
    if size > maximum {
        return Err(ProviderError::new(
            "source.invalid_payload",
            "qtrb.payload",
            Some(coordinate),
            false,
            format!("{field} exceeds {maximum} bytes"),
        ));
    }
    Ok(cursor.take(size)?.to_vec())
}

fn decode_memory_state(
    cursor: &mut PayloadCursor<'_>,
    field: &'static str,
    coordinate: SourceCoordinate,
) -> Result<CaptureBytes, ProviderError> {
    let state = cursor.u8()?;
    let count = usize::from(cursor.u8()?);
    if count > MAX_CAPTURED_MEMORY_BYTES {
        return Err(ProviderError::new(
            "source.invalid_payload",
            "qtrb.memory",
            Some(coordinate),
            false,
            format!("{field} exceeds capture maximum"),
        ));
    }
    let bytes = cursor.take(count)?;
    if !matches!((state, count), (0, 0) | (1, _) | (2, 0)) {
        return Err(ProviderError::new(
            "source.invalid_payload",
            "qtrb.memory",
            Some(coordinate),
            false,
            format!("invalid {field} state"),
        ));
    }
    Ok(match state {
        0 => CaptureBytes::NotCaptured,
        1 => CaptureBytes::Captured(bytes.to_vec()),
        2 => CaptureBytes::Unavailable,
        _ => unreachable!(),
    })
}

fn decode_metrics(cursor: &mut PayloadCursor<'_>) -> Result<[u64; 10], ProviderError> {
    let mut metrics = [0_u64; 10];
    for metric in &mut metrics {
        *metric = cursor.u64_le()?;
    }
    Ok(metrics)
}

fn coordinate(record: &PhysicalRecord) -> SourceCoordinate {
    SourceCoordinate {
        offset: record.offset,
        record_ordinal: Some(record.ordinal),
    }
}

fn with_coordinate(
    error: ProviderError,
    offset: u64,
    record_ordinal: Option<u64>,
    stage: &str,
) -> ProviderError {
    ProviderError::new(
        error.code(),
        stage,
        Some(SourceCoordinate {
            offset,
            record_ordinal,
        }),
        error.retryable(),
        error.detail(),
    )
}

fn header_error(detail: &str) -> ProviderError {
    ProviderError::new(
        "source.invalid_header",
        "qtrb.header",
        Some(SourceCoordinate {
            offset: 0,
            record_ordinal: None,
        }),
        false,
        detail,
    )
}

fn version_error(detail: &str) -> ProviderError {
    ProviderError::new(
        "source.version_unsupported",
        "qtrb.header",
        Some(SourceCoordinate {
            offset: 0,
            record_ordinal: None,
        }),
        false,
        detail,
    )
}
