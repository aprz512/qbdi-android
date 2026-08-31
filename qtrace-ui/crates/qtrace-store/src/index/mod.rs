mod builder;
mod checkpoints;
mod intervals;
mod postings;
mod wire;

use std::{collections::HashMap, error::Error, fmt, sync::Arc};

use qtrace_provider::{
    CompletenessCause, CompletenessRange, EventKey, EventKind, EventScope, MemoryDirection,
    PcRelativeKind, Provenance, ProviderCapabilities, RangeBounds, RangeDomain, RegisterSlot,
    WorkDelta, WorkGuard,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    ArtifactSource, CacheError, CacheIdentity, CacheOpen, CacheReader, CacheWriter,
    MappedStoreView, OwnedStoreView, StoreView,
};

pub use builder::IndexBuilder;
pub use checkpoints::{RegisterAccess, RegisterObservationRow};
pub use postings::{PostingList, intersect_rows};

pub(crate) fn binary_section_contract(name: &str) -> Option<(u32, u32)> {
    wire::contract(name)
}

pub(crate) fn binary_section_specs() -> &'static [(&'static str, u32, u32)] {
    wire::EXACT_SECTIONS
}

pub(crate) fn binary_section_max_length(name: &str, event_count: usize) -> Result<u64, IndexError> {
    wire::max_length(name, event_count)
}

pub(crate) fn validate_binary_sections(
    sections: Vec<(&'static str, Vec<u8>)>,
    keys: &[EventKey],
    kinds: &[EventKind],
    source_format: &str,
    guard: &dyn WorkGuard,
) -> Result<ValidatedCatalog, IndexError> {
    let catalog = wire::decode(sections, keys, kinds, source_format, true, guard)?;
    guard.consume(WorkDelta {
        resident_bytes: u64::try_from(std::mem::size_of::<NormalizedCatalog>()).unwrap_or(u64::MAX),
        nodes: 1,
        ..WorkDelta::default()
    })?;
    Ok(ValidatedCatalog(Arc::new(catalog)))
}

#[derive(Clone, Debug)]
pub(crate) struct ValidatedCatalog(Arc<NormalizedCatalog>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexError {
    code: String,
    detail: String,
}

impl IndexError {
    pub fn code(&self) -> &str {
        &self.code
    }

    fn new(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            detail: detail.into(),
        }
    }

    pub(crate) fn invalid(detail: impl Into<String>) -> Self {
        Self::new("index.invalid", detail)
    }

    pub(crate) fn corrupt(detail: impl Into<String>) -> Self {
        Self::new("cache.normalized_corrupt", detail)
    }

    pub(crate) fn resource(detail: impl Into<String>) -> Self {
        Self::new("control.resource_exhausted", detail)
    }

    pub(crate) fn duplicate_key(detail: impl Into<String>) -> Self {
        Self::new("index.duplicate_source_key", detail)
    }
}

impl fmt::Display for IndexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl Error for IndexError {}

impl From<qtrace_provider::ProviderError> for IndexError {
    fn from(error: qtrace_provider::ProviderError) -> Self {
        let code = if error.code() == "control.cancelled" {
            "job.cancelled"
        } else {
            error.code()
        };
        Self::new(code, error.to_string())
    }
}

impl From<qtrace_provider::OperationAbort> for IndexError {
    fn from(error: qtrace_provider::OperationAbort) -> Self {
        let code = match error {
            qtrace_provider::OperationAbort::Cancelled => "job.cancelled",
            qtrace_provider::OperationAbort::BudgetExceeded { .. } => "control.budget_exceeded",
        };
        Self::new(code, error.to_string())
    }
}

impl From<CacheError> for IndexError {
    fn from(error: CacheError) -> Self {
        Self::new(error.code(), error.to_string())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildOptions {
    interval_block_rows: u32,
    max_payload_bytes: u64,
    max_blob_bytes: u64,
    max_string_bytes: u64,
}

impl Default for BuildOptions {
    fn default() -> Self {
        Self {
            interval_block_rows: 64,
            max_payload_bytes: 8 * 1024 * 1024 * 1024,
            max_blob_bytes: 64 * 1024 * 1024,
            max_string_bytes: 16 * 1024 * 1024,
        }
    }
}

impl BuildOptions {
    pub fn with_interval_block_rows(mut self, rows: u32) -> Result<Self, IndexError> {
        self.interval_block_rows = rows;
        self.validate()?;
        Ok(self)
    }

    pub fn digest(&self) -> [u8; 32] {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        Sha256::digest(bytes).into()
    }

    fn validate(&self) -> Result<(), IndexError> {
        if self.interval_block_rows == 0 || !self.interval_block_rows.is_power_of_two() {
            return Err(IndexError::invalid(
                "interval block rows must be a non-zero power of two",
            ));
        }
        if self.max_payload_bytes == 0 || self.max_blob_bytes == 0 || self.max_string_bytes == 0 {
            return Err(IndexError::invalid("arena byte bounds must be non-zero"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ByteSpan {
    offset: u64,
    length: u64,
}

#[derive(Clone, Debug)]
struct ByteArena {
    bytes: Arc<Vec<u8>>,
    spans: Arc<Vec<ByteSpan>>,
    max_bytes: u64,
    by_hash: HashMap<[u8; 32], HashCandidates>,
    validation_next_id: Option<u32>,
}

#[derive(Clone, Debug)]
enum HashCandidates {
    One(u32),
    Collisions(Vec<u32>),
}

impl HashCandidates {
    fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        let (first, rest): (Option<u32>, &[u32]) = match self {
            Self::One(id) => (Some(*id), &[]),
            Self::Collisions(ids) => (None, ids),
        };
        first.into_iter().chain(rest.iter().copied())
    }
}

impl PartialEq for ByteArena {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes && self.spans == other.spans && self.max_bytes == other.max_bytes
    }
}

impl Eq for ByteArena {}

impl ByteArena {
    fn new(max_bytes: u64) -> Self {
        Self {
            bytes: Arc::new(Vec::new()),
            spans: Arc::new(Vec::new()),
            max_bytes,
            by_hash: HashMap::new(),
            validation_next_id: None,
        }
    }

    fn validation(source: &Self) -> Self {
        Self {
            bytes: Arc::clone(&source.bytes),
            spans: Arc::clone(&source.spans),
            max_bytes: source.max_bytes,
            by_hash: HashMap::new(),
            validation_next_id: Some(0),
        }
    }

    fn intern(&mut self, value: &[u8], guard: &dyn WorkGuard) -> Result<u32, IndexError> {
        let hash: [u8; 32] = Sha256::digest(value).into();
        let hash_was_present = self.by_hash.contains_key(&hash);
        if let Some(candidates) = self.by_hash.get(&hash) {
            for id in candidates.iter() {
                if self.get(id)? == value {
                    return Ok(id);
                }
            }
        }
        if let Some(next_id) = self.validation_next_id {
            if self.get(next_id)? != value {
                return Err(IndexError::corrupt(
                    "arena dictionary order disagrees with canonical payload facts",
                ));
            }
            self.validation_next_id = Some(
                next_id
                    .checked_add(1)
                    .ok_or_else(|| IndexError::corrupt("arena validation ID overflow"))?,
            );
            guard.consume(WorkDelta {
                resident_bytes: if hash_was_present {
                    u64::try_from(std::mem::size_of::<u32>()).unwrap_or(u64::MAX)
                } else {
                    u64::try_from(std::mem::size_of::<([u8; 32], HashCandidates)>())
                        .unwrap_or(u64::MAX)
                },
                nodes: 1,
                ..WorkDelta::default()
            })?;
            if !hash_was_present {
                self.by_hash
                    .try_reserve(1)
                    .map_err(|_| IndexError::resource("bounded arena hash allocation failed"))?;
            }
            self.insert_hash_candidate(hash, next_id)?;
            return Ok(next_id);
        }
        let new_length = u64::try_from(self.bytes.len())
            .ok()
            .and_then(|length| length.checked_add(value.len() as u64))
            .ok_or_else(|| IndexError::resource("bounded arena length overflow"))?;
        if new_length > self.max_bytes {
            return Err(IndexError::new(
                "control.budget_exceeded",
                "bounded arena byte limit exceeded",
            ));
        }
        guard.consume(WorkDelta {
            resident_bytes: (value.len() as u64)
                .checked_add(u64::try_from(std::mem::size_of::<ByteSpan>()).unwrap_or(u64::MAX))
                .and_then(|bytes| {
                    bytes.checked_add(if hash_was_present {
                        u64::try_from(std::mem::size_of::<u32>()).unwrap_or(u64::MAX)
                    } else {
                        u64::try_from(std::mem::size_of::<([u8; 32], HashCandidates)>())
                            .unwrap_or(u64::MAX)
                    })
                })
                .ok_or_else(|| IndexError::resource("bounded arena budget size overflow"))?,
            nodes: 1,
            ..WorkDelta::default()
        })?;
        Arc::get_mut(&mut self.bytes)
            .ok_or_else(|| IndexError::invalid("mutable arena bytes are unexpectedly shared"))?
            .try_reserve_exact(value.len())
            .map_err(|_| IndexError::resource("bounded arena allocation failed"))?;
        Arc::get_mut(&mut self.spans)
            .ok_or_else(|| IndexError::invalid("mutable arena spans are unexpectedly shared"))?
            .try_reserve(1)
            .map_err(|_| IndexError::resource("bounded arena span allocation failed"))?;
        let id = u32::try_from(self.spans.len())
            .map_err(|_| IndexError::resource("bounded arena has too many spans"))?;
        let offset = u64::try_from(self.bytes.len())
            .map_err(|_| IndexError::resource("bounded arena offset does not fit u64"))?;
        Arc::get_mut(&mut self.bytes)
            .ok_or_else(|| IndexError::invalid("mutable arena bytes are unexpectedly shared"))?
            .extend_from_slice(value);
        Arc::get_mut(&mut self.spans)
            .ok_or_else(|| IndexError::invalid("mutable arena spans are unexpectedly shared"))?
            .push(ByteSpan {
                offset,
                length: value.len() as u64,
            });
        if !hash_was_present {
            self.by_hash
                .try_reserve(1)
                .map_err(|_| IndexError::resource("bounded arena hash allocation failed"))?;
        }
        self.insert_hash_candidate(hash, id)?;
        Ok(id)
    }

    fn insert_hash_candidate(&mut self, hash: [u8; 32], id: u32) -> Result<(), IndexError> {
        match self.by_hash.entry(hash) {
            std::collections::hash_map::Entry::Occupied(mut entry) => match entry.get_mut() {
                HashCandidates::One(first) => {
                    let first = *first;
                    let mut candidates = Vec::new();
                    candidates.try_reserve_exact(2).map_err(|_| {
                        IndexError::resource("bounded arena collision allocation failed")
                    })?;
                    candidates.push(first);
                    candidates.push(id);
                    *entry.get_mut() = HashCandidates::Collisions(candidates);
                }
                HashCandidates::Collisions(candidates) => {
                    candidates.try_reserve(1).map_err(|_| {
                        IndexError::resource("bounded arena collision allocation failed")
                    })?;
                    candidates.push(id);
                }
            },
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(HashCandidates::One(id));
            }
        }
        Ok(())
    }

    fn get(&self, id: u32) -> Result<&[u8], IndexError> {
        let span = self
            .spans
            .get(id as usize)
            .ok_or_else(|| IndexError::corrupt("arena span id is out of range"))?;
        let start = usize::try_from(span.offset)
            .map_err(|_| IndexError::corrupt("arena offset does not fit usize"))?;
        let end = span
            .offset
            .checked_add(span.length)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| IndexError::corrupt("arena span range overflow"))?;
        self.bytes
            .get(start..end)
            .ok_or_else(|| IndexError::corrupt("arena span is outside its bytes"))
    }

    fn validate(&self) -> Result<(), IndexError> {
        if self.bytes.len() as u64 > self.max_bytes {
            return Err(IndexError::corrupt("arena exceeds its declared byte bound"));
        }
        let mut expected = 0_u64;
        for span in self.spans.iter() {
            if span.offset != expected {
                return Err(IndexError::corrupt(
                    "arena spans are not append-only contiguous",
                ));
            }
            expected = expected
                .checked_add(span.length)
                .ok_or_else(|| IndexError::corrupt("arena span end overflow"))?;
        }
        if expected != self.bytes.len() as u64 {
            return Err(IndexError::corrupt("arena spans do not cover exact bytes"));
        }
        Ok(())
    }

    fn validate_dictionary_complete(&self) -> Result<(), IndexError> {
        let spans = u32::try_from(self.spans.len())
            .map_err(|_| IndexError::corrupt("arena span count exceeds u32"))?;
        if self.validation_next_id != Some(spans) {
            return Err(IndexError::corrupt(
                "arena has unreferenced or missing dictionary entries",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct EventColumn {
    timeline: u64,
    tid: Option<u32>,
    sequence: Option<u64>,
    scope: EventScope,
    provenance: Provenance,
    payload_blob: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ModuleRow {
    pub source_event_row: usize,
    pub provenance: Provenance,
    pub source_id: u32,
    pub base: u64,
    pub name: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DefinitionRow {
    pub source_event_row: usize,
    pub provenance: Provenance,
    pub source_id: u32,
    pub opcode: u32,
    pub read_mask: u64,
    pub write_mask: u64,
    pub pc_displacement: i64,
    pub flags: u32,
    pub pc_kind: PcRelativeKind,
    pub condition: u8,
    pub slow_memory_path: bool,
    pub mnemonic: u32,
    pub operands: u32,
    pub disassembly: u32,
    pub exact_blob: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InstructionRow {
    pub owner_row: usize,
    pub module: Option<u32>,
    pub relative_pc: u64,
    pub definition: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemoryRow {
    pub owner_row: usize,
    pub module: Option<u32>,
    pub relative_pc: u64,
    pub address: u64,
    pub end_exclusive: u64,
    pub size: u32,
    pub direction: MemoryDirection,
    pub metadata_available: bool,
    pub flags: u16,
    pub value: u64,
    before_blob: u32,
    after_blob: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SemanticRow {
    pub owner_row: usize,
    pub category: Option<u32>,
    pub name: u32,
    pub detail_blob: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompletenessRow {
    pub domain: RangeDomain,
    pub bounds: RangeBounds,
    pub provenance: Provenance,
    pub cause: CompletenessCause,
}

impl CompletenessRow {
    fn from_range(value: CompletenessRange) -> Self {
        Self {
            domain: value.domain(),
            bounds: value.bounds(),
            provenance: value.provenance(),
            cause: value.cause(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct SourceKeyRow {
    key: EventKey,
    row: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct SortedMap<K, V> {
    entries: Vec<(K, V)>,
}

impl<K: Ord, V> SortedMap<K, V> {
    fn from_sorted(entries: Vec<(K, V)>) -> Result<Self, IndexError> {
        if entries.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
            return Err(IndexError::corrupt(
                "sorted map keys are not strictly increasing",
            ));
        }
        Ok(Self { entries })
    }

    fn get(&self, key: &K) -> Option<&V> {
        self.entries
            .binary_search_by(|(candidate, _)| candidate.cmp(key))
            .ok()
            .map(|index| &self.entries[index].1)
    }

    fn values(&self) -> impl Iterator<Item = &V> {
        self.entries.iter().map(|(_, value)| value)
    }

    fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.entries.iter().map(|(key, value)| (key, value))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct IndexCatalog {
    timeline: SortedMap<u64, PostingList>,
    tid: SortedMap<u32, PostingList>,
    kind: SortedMap<u8, PostingList>,
    module: SortedMap<u32, PostingList>,
    definition: SortedMap<u32, PostingList>,
    register: SortedMap<u8, PostingList>,
    semantic_category: SortedMap<u32, PostingList>,
    semantic_name: SortedMap<u32, PostingList>,
    call: PostingList,
    return_rows: PostingList,
    checkpoint: PostingList,
    sequence: Vec<(u64, usize)>,
    module_pc: SortedMap<u32, Vec<(u64, usize)>>,
    memory: intervals::IntervalIndex,
    source_keys: Vec<SourceKeyRow>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NormalizedCatalog {
    schema: u32,
    capabilities: ProviderCapabilities,
    events: Vec<EventColumn>,
    payloads: ByteArena,
    strings: ByteArena,
    blobs: ByteArena,
    modules: Vec<ModuleRow>,
    definitions: Vec<DefinitionRow>,
    instructions: Vec<InstructionRow>,
    memories: Vec<MemoryRow>,
    semantics: Vec<SemanticRow>,
    observations: Vec<RegisterObservationRow>,
    completeness: Vec<CompletenessRow>,
    indexes: IndexCatalog,
}

impl NormalizedCatalog {
    fn validate_shape(&self, event_count: usize, guard: &dyn WorkGuard) -> Result<(), IndexError> {
        if self.schema != 2 || self.events.len() != event_count {
            return Err(IndexError::corrupt(
                "normalized event-column row counts differ",
            ));
        }
        self.strings.validate()?;
        self.payloads.validate()?;
        self.blobs.validate()?;
        for chunk in self.events.chunks(4096) {
            guard.consume(WorkDelta::default())?;
            for event in chunk {
                self.payloads.get(event.payload_blob).map_err(|error| {
                    IndexError::corrupt(format!("event payload reference is invalid: {error}"))
                })?;
            }
        }
        for chunk in self.modules.chunks(4096) {
            guard.consume(WorkDelta::default())?;
            for module in chunk {
                self.strings.get(module.name).map_err(|error| {
                    IndexError::corrupt(format!("module name reference is invalid: {error}"))
                })?;
            }
        }
        for chunk in self.definitions.chunks(4096) {
            guard.consume(WorkDelta::default())?;
            for definition in chunk {
                self.strings.get(definition.mnemonic).map_err(|error| {
                    IndexError::corrupt(format!(
                        "definition mnemonic reference is invalid: {error}"
                    ))
                })?;
                self.strings.get(definition.operands).map_err(|error| {
                    IndexError::corrupt(format!(
                        "definition operands reference is invalid: {error}"
                    ))
                })?;
                self.strings.get(definition.disassembly).map_err(|error| {
                    IndexError::corrupt(format!(
                        "definition disassembly reference is invalid: {error}"
                    ))
                })?;
                self.blobs.get(definition.exact_blob).map_err(|error| {
                    IndexError::corrupt(format!("definition blob reference is invalid: {error}"))
                })?;
            }
        }
        checkpoint_chunks(self.instructions.len(), guard)?;
        checkpoint_chunks(self.memories.len(), guard)?;
        checkpoint_chunks(self.semantics.len(), guard)?;
        checkpoint_chunks(self.observations.len(), guard)?;
        if self.instructions.iter().any(|row| {
            row.owner_row >= event_count
                || row
                    .module
                    .is_some_and(|id| id as usize >= self.modules.len())
                || row
                    .definition
                    .is_some_and(|id| id as usize >= self.definitions.len())
        }) || self.memories.iter().any(|row| {
            row.owner_row >= event_count
                || row
                    .module
                    .is_some_and(|id| id as usize >= self.modules.len())
                || row.address.checked_add(u64::from(row.size)) != Some(row.end_exclusive)
                || self.blobs.get(row.before_blob).is_err()
                || self.blobs.get(row.after_blob).is_err()
        }) || self.semantics.iter().any(|row| {
            row.owner_row >= event_count
                || row.category.is_some_and(|id| self.strings.get(id).is_err())
                || self.strings.get(row.name).is_err()
                || self.blobs.get(row.detail_blob).is_err()
        }) || self.observations.iter().any(|row| {
            row.owner_row >= event_count
                || row.slot as usize >= RegisterSlot::COUNT
                || row.captured_width == 0
        }) {
            return Err(IndexError::corrupt(
                "normalized typed-table reference is invalid",
            ));
        }
        if self.indexes.source_keys.len() != event_count {
            return Err(IndexError::corrupt(
                "source row and EventKey mapping is not bijective",
            ));
        }
        Ok(())
    }

    fn validate(
        &self,
        keys: &[EventKey],
        kinds: &[EventKind],
        guard: &dyn WorkGuard,
    ) -> Result<(), IndexError> {
        self.validate_shape(keys.len(), guard)?;
        if kinds.len() != keys.len() {
            return Err(IndexError::corrupt(
                "normalized event-column row counts differ",
            ));
        }
        for (row, event) in self.events.iter().enumerate() {
            if row % 4096 == 0 {
                guard.consume(WorkDelta::default())?;
            }
            if event.timeline != keys[row].timeline.0
                || event.tid != keys[row].tid
                || event.sequence != keys[row].sequence
            {
                return Err(IndexError::corrupt(
                    "normalized source coordinates disagree",
                ));
            }
            self.payloads.get(event.payload_blob).map_err(|error| {
                IndexError::corrupt(format!("event payload reference is invalid: {error}"))
            })?;
        }
        let interval_block_rows = u32::try_from(self.indexes.memory.block_rows())
            .map_err(|_| IndexError::corrupt("interval block size does not fit u32"))?;
        let options = BuildOptions {
            interval_block_rows,
            max_payload_bytes: self.payloads.max_bytes,
            max_blob_bytes: self.blobs.max_bytes,
            max_string_bytes: self.strings.max_bytes,
        };
        builder::validate_index_families(keys, kinds, self, &options, guard).map_err(|error| {
            if error.code().starts_with("control.") || error.code() == "job.cancelled" {
                error
            } else {
                IndexError::corrupt("eager index reconstruction failed")
            }
        })?;
        Ok(())
    }
}

fn checkpoint_chunks(rows: usize, guard: &dyn WorkGuard) -> Result<(), IndexError> {
    for _ in (0..rows).step_by(4096) {
        guard.consume(WorkDelta::default())?;
    }
    Ok(())
}

/// Stable, read-only normalized facts and eager-index primitives shared by owned and mapped stores.
pub trait TraceStoreView {
    fn event_count(&self) -> usize;
    fn event_key(&self, row: usize) -> Result<Option<EventKey>, IndexError>;
    fn event_kind(&self, row: usize) -> Result<Option<EventKind>, IndexError>;
    fn provenance(&self, row: usize) -> Result<Option<Provenance>, IndexError>;
    fn capabilities(&self) -> &ProviderCapabilities;
    fn instruction(&self, event_row: usize) -> Option<InstructionRow>;
    fn memory(&self, event_row: usize) -> Option<MemoryRow>;
    fn semantic(&self, event_row: usize) -> Option<SemanticRow>;
    fn payload_bytes(&self, event_row: usize) -> Result<&[u8], IndexError>;
    fn string_bytes(&self, string_id: u32) -> Result<&[u8], IndexError>;
    fn blob_bytes(&self, blob_id: u32) -> Result<&[u8], IndexError>;
    fn memory_before_bytes(&self, event_row: usize) -> Result<Option<&[u8]>, IndexError>;
    fn memory_after_bytes(&self, event_row: usize) -> Result<Option<&[u8]>, IndexError>;
    fn module(&self, module: u32) -> Option<&ModuleRow>;
    fn definition(&self, definition: u32) -> Option<&DefinitionRow>;
    fn register_observations(&self, event_row: usize) -> Vec<RegisterObservationRow>;
    fn completeness(&self) -> &[CompletenessRow];
    fn rows_for_timeline(&self, timeline: u64) -> Result<Vec<usize>, IndexError>;
    fn rows_for_tids(&self, tids: &[u32]) -> Result<Vec<usize>, IndexError>;
    fn rows_for_sequence_range(
        &self,
        start: u64,
        end_exclusive: u64,
    ) -> Result<Vec<usize>, IndexError>;
    fn rows_of_kinds(&self, kinds: &[EventKind]) -> Result<Vec<usize>, IndexError>;
    fn rows_for_modules(&self, modules: &[u32]) -> Result<Vec<usize>, IndexError>;
    fn rows_for_module_pc_range(
        &self,
        module: u32,
        start: u64,
        end_exclusive: u64,
    ) -> Result<Vec<usize>, IndexError>;
    fn rows_for_definitions(&self, definitions: &[u32]) -> Result<Vec<usize>, IndexError>;
    fn rows_observing_register(&self, slot: RegisterSlot) -> Result<Vec<usize>, IndexError>;
    fn checkpoint_rows(&self) -> Result<Vec<usize>, IndexError>;
    fn call_rows(&self) -> Result<Vec<usize>, IndexError>;
    fn return_rows(&self) -> Result<Vec<usize>, IndexError>;
    fn rows_for_semantic_categories(&self, categories: &[&[u8]]) -> Result<Vec<usize>, IndexError>;
    fn rows_for_semantic_names(&self, names: &[&[u8]]) -> Result<Vec<usize>, IndexError>;
    fn memory_overlaps(&self, start: u64, end_exclusive: u64) -> Result<Vec<usize>, IndexError>;
    fn row_for_source_key(&self, key: &EventKey) -> Option<usize>;
    fn source_key_for_row(&self, row: usize) -> Result<Option<EventKey>, IndexError>;
}

fn rows_for_posting_keys<K: Ord>(
    map: &SortedMap<K, PostingList>,
    keys: &[K],
) -> Result<Vec<usize>, IndexError> {
    let lists = keys
        .iter()
        .filter_map(|key| map.get(key))
        .map(PostingList::rows)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(postings::union_rows(&lists))
}

fn rows_for_semantic_bytes(
    catalog: &NormalizedCatalog,
    values: &[&[u8]],
    by_category: bool,
) -> Result<Vec<usize>, IndexError> {
    let mut ids = Vec::new();
    ids.try_reserve_exact(values.len())
        .map_err(|_| IndexError::resource("semantic lookup allocation failed"))?;
    for value in values {
        if let Some(id) = catalog
            .strings
            .spans
            .iter()
            .enumerate()
            .find_map(|(id, _)| {
                (catalog.strings.get(id as u32).ok() == Some(*value)).then_some(id as u32)
            })
        {
            ids.push(id);
        }
    }
    if by_category {
        rows_for_posting_keys(&catalog.indexes.semantic_category, &ids)
    } else {
        rows_for_posting_keys(&catalog.indexes.semantic_name, &ids)
    }
}

fn row_for_source(catalog: &NormalizedCatalog, key: &EventKey) -> Option<usize> {
    catalog
        .indexes
        .source_keys
        .binary_search_by(|entry| compare_event_keys(&entry.key, key))
        .ok()
        .map(|index| catalog.indexes.source_keys[index].row)
}

fn rows_for_sequence(catalog: &NormalizedCatalog, start: u64, end: u64) -> Vec<usize> {
    if start >= end {
        return Vec::new();
    }
    let first = catalog
        .indexes
        .sequence
        .partition_point(|(sequence, _)| *sequence < start);
    let last = catalog
        .indexes
        .sequence
        .partition_point(|(sequence, _)| *sequence < end);
    catalog.indexes.sequence[first..last]
        .iter()
        .map(|(_, row)| *row)
        .collect()
}

fn rows_for_module_pc(
    catalog: &NormalizedCatalog,
    module: u32,
    start: u64,
    end: u64,
) -> Vec<usize> {
    if start >= end {
        return Vec::new();
    }
    let Some(rows) = catalog.indexes.module_pc.get(&module) else {
        return Vec::new();
    };
    let first = rows.partition_point(|(pc, _)| *pc < start);
    let last = rows.partition_point(|(pc, _)| *pc < end);
    rows[first..last].iter().map(|(_, row)| *row).collect()
}

#[derive(Clone, Debug)]
pub struct OwnedTraceStore {
    base: OwnedStoreView,
    catalog: Arc<NormalizedCatalog>,
}

impl OwnedTraceStore {
    fn new(
        keys: Vec<EventKey>,
        kinds: Vec<EventKind>,
        catalog: NormalizedCatalog,
        guard: &dyn WorkGuard,
    ) -> Result<Self, IndexError> {
        catalog.validate(&keys, &kinds, guard)?;
        guard.consume(WorkDelta {
            resident_bytes: u64::try_from(std::mem::size_of::<NormalizedCatalog>())
                .unwrap_or(u64::MAX),
            nodes: 1,
            ..WorkDelta::default()
        })?;
        Ok(Self {
            base: OwnedStoreView::new(keys, kinds)?,
            catalog: Arc::new(catalog),
        })
    }

    pub fn event_count(&self) -> usize {
        self.base.event_count()
    }

    pub fn event_key(&self, row: usize) -> Option<EventKey> {
        self.base.event_key(row).ok()
    }

    pub fn event_kind(&self, row: usize) -> Option<EventKind> {
        self.base.event_kind(row).ok()
    }

    pub fn provenance(&self, row: usize) -> Option<Provenance> {
        self.catalog.events.get(row).map(|event| event.provenance)
    }

    pub fn capabilities(&self) -> &ProviderCapabilities {
        &self.catalog.capabilities
    }

    pub fn row_for_key(&self, key: &EventKey) -> Option<usize> {
        self.catalog
            .indexes
            .source_keys
            .binary_search_by(|entry| compare_event_keys(&entry.key, key))
            .ok()
            .map(|index| self.catalog.indexes.source_keys[index].row)
    }

    pub fn rows_of_kind(&self, kind: EventKind) -> Rows {
        self.rows_of_kinds(&[kind])
    }

    pub fn rows_of_kinds(&self, kinds: &[EventKind]) -> Rows {
        let lists = kinds
            .iter()
            .filter_map(|kind| {
                self.catalog
                    .indexes
                    .kind
                    .get(&crate::layout::encode_event_kind(*kind))
            })
            .filter_map(|list| list.rows().ok())
            .collect::<Vec<_>>();
        Rows::new(postings::union_rows(&lists))
    }

    pub fn rows_of_tids(&self, tids: &[u32]) -> Rows {
        let lists = tids
            .iter()
            .filter_map(|tid| self.catalog.indexes.tid.get(tid))
            .filter_map(|list| list.rows().ok())
            .collect::<Vec<_>>();
        Rows::new(postings::union_rows(&lists))
    }

    pub fn rows_observing_register(&self, slot: RegisterSlot) -> Rows {
        Rows::new(
            self.catalog
                .indexes
                .register
                .get(&(slot.index() as u8))
                .and_then(|list| list.rows().ok())
                .unwrap_or_default(),
        )
    }

    pub fn call_rows(&self) -> Rows {
        Rows::new(self.catalog.indexes.call.rows().unwrap_or_default())
    }

    pub fn return_rows(&self) -> Rows {
        Rows::new(self.catalog.indexes.return_rows.rows().unwrap_or_default())
    }

    pub fn memory_overlaps(&self, start: u64, end: u64) -> Result<Rows, IndexError> {
        Ok(Rows::new(self.catalog.indexes.memory.overlaps(start, end)?))
    }

    pub fn memory(&self, event_row: usize) -> Option<&MemoryRow> {
        self.catalog
            .memories
            .iter()
            .find(|memory| memory.owner_row == event_row)
    }

    fn into_cache_view_with_catalog(
        self,
        guard: &dyn WorkGuard,
    ) -> Result<OwnedStoreView, IndexError> {
        let mut view = self.base;
        let catalog = Arc::try_unwrap(self.catalog)
            .map_err(|_| IndexError::resource("owned catalog is still shared during encoding"))?;
        for section in wire::encode(catalog, guard)? {
            guard.consume(WorkDelta::default())?;
            view = view.with_section(section)?;
        }
        Ok(view)
    }
}

#[derive(Clone, Debug)]
pub struct MappedTraceStore {
    view: MappedStoreView,
    catalog: Arc<NormalizedCatalog>,
}

impl MappedTraceStore {
    fn open(mut view: MappedStoreView, guard: &dyn WorkGuard) -> Result<Self, IndexError> {
        guard.consume(WorkDelta::default())?;
        let ValidatedCatalog(catalog) = view.take_validated_catalog().ok_or_else(|| {
            IndexError::corrupt("schema-two cache did not transfer its validated catalog")
        })?;
        Ok(Self { view, catalog })
    }

    pub fn event_count(&self) -> usize {
        self.view.event_count()
    }
    pub fn event_key(&self, row: usize) -> Result<Option<EventKey>, IndexError> {
        if row >= self.event_count() {
            return Ok(None);
        }
        Ok(Some(self.view.event_key(row)?))
    }
    pub fn event_kind(&self, row: usize) -> Result<Option<EventKind>, IndexError> {
        if row >= self.event_count() {
            return Ok(None);
        }
        Ok(Some(self.view.event_kind(row)?))
    }
    pub fn provenance(&self, row: usize) -> Result<Option<Provenance>, IndexError> {
        Ok(self.catalog.events.get(row).map(|event| event.provenance))
    }
    pub fn capabilities(&self) -> &ProviderCapabilities {
        &self.catalog.capabilities
    }
    fn rows_of_kinds(&self, kinds: &[EventKind]) -> Result<Vec<usize>, IndexError> {
        let lists = kinds
            .iter()
            .filter_map(|kind| {
                self.catalog
                    .indexes
                    .kind
                    .get(&crate::layout::encode_event_kind(*kind))
            })
            .map(PostingList::rows)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(postings::union_rows(&lists))
    }
    fn memory_overlaps(&self, start: u64, end: u64) -> Result<Vec<usize>, IndexError> {
        self.catalog.indexes.memory.overlaps(start, end)
    }
}

#[derive(Clone, Debug)]
pub enum TraceStore {
    Owned(OwnedTraceStore),
    Mapped(MappedTraceStore),
}

trait HasNormalizedCatalog {
    fn normalized_catalog(&self) -> &NormalizedCatalog;
    fn base_event_count(&self) -> usize;
    fn base_event_key(&self, row: usize) -> Result<EventKey, IndexError>;
    fn base_event_kind(&self, row: usize) -> Result<EventKind, IndexError>;
}

impl HasNormalizedCatalog for OwnedTraceStore {
    fn normalized_catalog(&self) -> &NormalizedCatalog {
        &self.catalog
    }
    fn base_event_count(&self) -> usize {
        self.base.event_count()
    }
    fn base_event_key(&self, row: usize) -> Result<EventKey, IndexError> {
        self.base.event_key(row).map_err(IndexError::from)
    }
    fn base_event_kind(&self, row: usize) -> Result<EventKind, IndexError> {
        self.base.event_kind(row).map_err(IndexError::from)
    }
}

impl HasNormalizedCatalog for MappedTraceStore {
    fn normalized_catalog(&self) -> &NormalizedCatalog {
        &self.catalog
    }
    fn base_event_count(&self) -> usize {
        self.view.event_count()
    }
    fn base_event_key(&self, row: usize) -> Result<EventKey, IndexError> {
        self.view.event_key(row).map_err(IndexError::from)
    }
    fn base_event_kind(&self, row: usize) -> Result<EventKind, IndexError> {
        self.view.event_kind(row).map_err(IndexError::from)
    }
}

impl HasNormalizedCatalog for TraceStore {
    fn normalized_catalog(&self) -> &NormalizedCatalog {
        match self {
            Self::Owned(store) => &store.catalog,
            Self::Mapped(store) => &store.catalog,
        }
    }
    fn base_event_count(&self) -> usize {
        match self {
            Self::Owned(store) => store.base.event_count(),
            Self::Mapped(store) => store.view.event_count(),
        }
    }
    fn base_event_key(&self, row: usize) -> Result<EventKey, IndexError> {
        match self {
            Self::Owned(store) => store.base.event_key(row).map_err(IndexError::from),
            Self::Mapped(store) => store.view.event_key(row).map_err(IndexError::from),
        }
    }
    fn base_event_kind(&self, row: usize) -> Result<EventKind, IndexError> {
        match self {
            Self::Owned(store) => store.base.event_kind(row).map_err(IndexError::from),
            Self::Mapped(store) => store.view.event_kind(row).map_err(IndexError::from),
        }
    }
}

impl<T: HasNormalizedCatalog> TraceStoreView for T {
    fn event_count(&self) -> usize {
        self.base_event_count()
    }
    fn event_key(&self, row: usize) -> Result<Option<EventKey>, IndexError> {
        (row < self.base_event_count())
            .then(|| self.base_event_key(row))
            .transpose()
    }
    fn event_kind(&self, row: usize) -> Result<Option<EventKind>, IndexError> {
        (row < self.base_event_count())
            .then(|| self.base_event_kind(row))
            .transpose()
    }
    fn provenance(&self, row: usize) -> Result<Option<Provenance>, IndexError> {
        Ok(self
            .normalized_catalog()
            .events
            .get(row)
            .map(|event| event.provenance))
    }
    fn capabilities(&self) -> &ProviderCapabilities {
        &self.normalized_catalog().capabilities
    }
    fn instruction(&self, event_row: usize) -> Option<InstructionRow> {
        self.normalized_catalog()
            .instructions
            .iter()
            .find(|row| row.owner_row == event_row)
            .copied()
    }
    fn memory(&self, event_row: usize) -> Option<MemoryRow> {
        self.normalized_catalog()
            .memories
            .iter()
            .find(|row| row.owner_row == event_row)
            .copied()
    }
    fn semantic(&self, event_row: usize) -> Option<SemanticRow> {
        self.normalized_catalog()
            .semantics
            .iter()
            .find(|row| row.owner_row == event_row)
            .copied()
    }
    fn payload_bytes(&self, event_row: usize) -> Result<&[u8], IndexError> {
        let event = self
            .normalized_catalog()
            .events
            .get(event_row)
            .ok_or_else(|| IndexError::invalid("event row is out of range"))?;
        self.normalized_catalog()
            .payloads
            .get(event.payload_blob)
            .map_err(|_| IndexError::corrupt("event payload span is invalid"))
    }
    fn string_bytes(&self, string_id: u32) -> Result<&[u8], IndexError> {
        self.normalized_catalog()
            .strings
            .get(string_id)
            .map_err(|_| IndexError::invalid("string ID is out of range"))
    }
    fn blob_bytes(&self, blob_id: u32) -> Result<&[u8], IndexError> {
        self.normalized_catalog()
            .blobs
            .get(blob_id)
            .map_err(|_| IndexError::invalid("blob ID is out of range"))
    }
    fn memory_before_bytes(&self, event_row: usize) -> Result<Option<&[u8]>, IndexError> {
        if event_row >= self.base_event_count() {
            return Err(IndexError::invalid("event row is out of range"));
        }
        self.normalized_catalog()
            .memories
            .iter()
            .find(|row| row.owner_row == event_row)
            .map(|row| {
                self.normalized_catalog()
                    .blobs
                    .get(row.before_blob)
                    .map_err(|_| IndexError::corrupt("memory before blob is invalid"))
            })
            .transpose()
    }
    fn memory_after_bytes(&self, event_row: usize) -> Result<Option<&[u8]>, IndexError> {
        if event_row >= self.base_event_count() {
            return Err(IndexError::invalid("event row is out of range"));
        }
        self.normalized_catalog()
            .memories
            .iter()
            .find(|row| row.owner_row == event_row)
            .map(|row| {
                self.normalized_catalog()
                    .blobs
                    .get(row.after_blob)
                    .map_err(|_| IndexError::corrupt("memory after blob is invalid"))
            })
            .transpose()
    }
    fn module(&self, module: u32) -> Option<&ModuleRow> {
        self.normalized_catalog().modules.get(module as usize)
    }
    fn definition(&self, definition: u32) -> Option<&DefinitionRow> {
        self.normalized_catalog()
            .definitions
            .get(definition as usize)
    }
    fn register_observations(&self, event_row: usize) -> Vec<RegisterObservationRow> {
        self.normalized_catalog()
            .observations
            .iter()
            .filter(|row| row.owner_row == event_row)
            .copied()
            .collect()
    }
    fn completeness(&self) -> &[CompletenessRow] {
        &self.normalized_catalog().completeness
    }
    fn rows_for_timeline(&self, timeline: u64) -> Result<Vec<usize>, IndexError> {
        rows_for_posting_keys(&self.normalized_catalog().indexes.timeline, &[timeline])
    }
    fn rows_for_tids(&self, tids: &[u32]) -> Result<Vec<usize>, IndexError> {
        rows_for_posting_keys(&self.normalized_catalog().indexes.tid, tids)
    }
    fn rows_for_sequence_range(&self, start: u64, end: u64) -> Result<Vec<usize>, IndexError> {
        Ok(rows_for_sequence(self.normalized_catalog(), start, end))
    }
    fn rows_of_kinds(&self, kinds: &[EventKind]) -> Result<Vec<usize>, IndexError> {
        let encoded = kinds
            .iter()
            .map(|kind| crate::layout::encode_event_kind(*kind))
            .collect::<Vec<_>>();
        rows_for_posting_keys(&self.normalized_catalog().indexes.kind, &encoded)
    }
    fn rows_for_modules(&self, modules: &[u32]) -> Result<Vec<usize>, IndexError> {
        rows_for_posting_keys(&self.normalized_catalog().indexes.module, modules)
    }
    fn rows_for_module_pc_range(
        &self,
        module: u32,
        start: u64,
        end: u64,
    ) -> Result<Vec<usize>, IndexError> {
        Ok(rows_for_module_pc(
            self.normalized_catalog(),
            module,
            start,
            end,
        ))
    }
    fn rows_for_definitions(&self, definitions: &[u32]) -> Result<Vec<usize>, IndexError> {
        rows_for_posting_keys(&self.normalized_catalog().indexes.definition, definitions)
    }
    fn rows_observing_register(&self, slot: RegisterSlot) -> Result<Vec<usize>, IndexError> {
        rows_for_posting_keys(
            &self.normalized_catalog().indexes.register,
            &[slot.index() as u8],
        )
    }
    fn checkpoint_rows(&self) -> Result<Vec<usize>, IndexError> {
        self.normalized_catalog().indexes.checkpoint.rows()
    }
    fn call_rows(&self) -> Result<Vec<usize>, IndexError> {
        self.normalized_catalog().indexes.call.rows()
    }
    fn return_rows(&self) -> Result<Vec<usize>, IndexError> {
        self.normalized_catalog().indexes.return_rows.rows()
    }
    fn rows_for_semantic_categories(&self, categories: &[&[u8]]) -> Result<Vec<usize>, IndexError> {
        rows_for_semantic_bytes(self.normalized_catalog(), categories, true)
    }
    fn rows_for_semantic_names(&self, names: &[&[u8]]) -> Result<Vec<usize>, IndexError> {
        rows_for_semantic_bytes(self.normalized_catalog(), names, false)
    }
    fn memory_overlaps(&self, start: u64, end: u64) -> Result<Vec<usize>, IndexError> {
        self.normalized_catalog()
            .indexes
            .memory
            .overlaps(start, end)
    }
    fn row_for_source_key(&self, key: &EventKey) -> Option<usize> {
        row_for_source(self.normalized_catalog(), key)
    }
    fn source_key_for_row(&self, row: usize) -> Result<Option<EventKey>, IndexError> {
        TraceStoreView::event_key(self, row)
    }
}

impl TraceStore {
    pub fn open_or_build(
        cache_root: &std::path::Path,
        source: &ArtifactSource,
        options: &BuildOptions,
        guard: &dyn WorkGuard,
    ) -> Result<Self, IndexError> {
        options.validate()?;
        let identity = cache_identity(source, options);
        guard.consume(WorkDelta::default())?;
        match CacheReader::open(cache_root, &identity, guard)? {
            CacheOpen::Ready(view) => {
                return Ok(Self::Mapped(MappedTraceStore::open(view, guard)?));
            }
            CacheOpen::Missing | CacheOpen::Rebuild(_) => {}
        }
        guard.consume(WorkDelta::default())?;
        let owned = IndexBuilder::build(source, options, guard)?;
        guard.consume(WorkDelta::default())?;
        let (outcome, receipt) =
            CacheWriter::new(identity.clone(), owned.into_cache_view_with_catalog(guard)?)?
                .publish_with_receipt(cache_root, guard)?;
        let reopened = (|| {
            guard.consume(WorkDelta::default())?;
            let view = match CacheReader::open(cache_root, &identity, guard)? {
                CacheOpen::Ready(view) => view,
                CacheOpen::Missing => {
                    return Err(IndexError::corrupt("published cache is missing"));
                }
                CacheOpen::Rebuild(reason) => {
                    return Err(IndexError::corrupt(format!(
                        "published cache did not validate: {reason:?}"
                    )));
                }
            };
            Ok(Self::Mapped(MappedTraceStore::open(view, guard)?))
        })();
        match reopened {
            Ok(store) => Ok(store),
            Err(error) if outcome == crate::PublishOutcome::Published => {
                let receipt = receipt
                    .ok_or_else(|| IndexError::corrupt("published cache receipt is missing"))?;
                CacheWriter::remove_published(cache_root, &identity, receipt).map_err(
                    |cleanup| {
                        IndexError::new(
                            cleanup.code(),
                            format!(
                                "post-publish reopen failed ({error}); rollback failed ({cleanup})"
                            ),
                        )
                    },
                )?;
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    pub const fn is_mapped(&self) -> bool {
        matches!(self, Self::Mapped(_))
    }
    pub fn event_count(&self) -> usize {
        match self {
            Self::Owned(store) => store.event_count(),
            Self::Mapped(store) => store.event_count(),
        }
    }
    pub fn event_key(&self, row: usize) -> Result<Option<EventKey>, IndexError> {
        match self {
            Self::Owned(store) => Ok(store.event_key(row)),
            Self::Mapped(store) => store.event_key(row),
        }
    }
    pub fn event_kind(&self, row: usize) -> Result<Option<EventKind>, IndexError> {
        match self {
            Self::Owned(store) => Ok(store.event_kind(row)),
            Self::Mapped(store) => store.event_kind(row),
        }
    }
    pub fn provenance(&self, row: usize) -> Result<Option<Provenance>, IndexError> {
        match self {
            Self::Owned(store) => Ok(store.provenance(row)),
            Self::Mapped(store) => store.provenance(row),
        }
    }
    pub fn capabilities(&self) -> &ProviderCapabilities {
        match self {
            Self::Owned(store) => store.capabilities(),
            Self::Mapped(store) => store.capabilities(),
        }
    }
    pub fn rows_of_kinds(&self, kinds: &[EventKind]) -> Result<Vec<usize>, IndexError> {
        match self {
            Self::Owned(store) => Ok(store.rows_of_kinds(kinds).collect()),
            Self::Mapped(store) => store.rows_of_kinds(kinds),
        }
    }
    pub fn memory_overlaps(&self, start: u64, end: u64) -> Result<Vec<usize>, IndexError> {
        match self {
            Self::Owned(store) => Ok(store.memory_overlaps(start, end)?.collect()),
            Self::Mapped(store) => store.memory_overlaps(start, end),
        }
    }
}

impl From<OwnedTraceStore> for TraceStore {
    fn from(value: OwnedTraceStore) -> Self {
        Self::Owned(value)
    }
}

fn cache_identity(source: &ArtifactSource, options: &BuildOptions) -> CacheIdentity {
    let provider = source.identity().provider();
    CacheIdentity {
        analyzer_version: env!("CARGO_PKG_VERSION").to_owned(),
        artifact_digest: *provider.artifact.as_bytes(),
        build_option_digest: options.digest(),
        cache_schema: 2,
        endian: "little".to_owned(),
        layout_version: 2,
        source_features: 0,
        source_format: provider.format.clone(),
        source_major: u16::from(provider.format_major),
        source_minor: u16::from(provider.format_minor),
    }
}

pub struct Rows {
    inner: std::vec::IntoIter<usize>,
}

impl Rows {
    fn new(rows: Vec<usize>) -> Self {
        Self {
            inner: rows.into_iter(),
        }
    }
}

impl Iterator for Rows {
    type Item = usize;
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl ExactSizeIterator for Rows {}

pub(crate) fn compare_event_keys(left: &EventKey, right: &EventKey) -> std::cmp::Ordering {
    left.artifact
        .as_bytes()
        .cmp(right.artifact.as_bytes())
        .then_with(|| left.timeline.0.cmp(&right.timeline.0))
        .then_with(|| left.record_ordinal.cmp(&right.record_ordinal))
        .then_with(|| left.source_offset.cmp(&right.source_offset))
        .then_with(|| left.sequence.cmp(&right.sequence))
        .then_with(|| left.tid.cmp(&right.tid))
}
