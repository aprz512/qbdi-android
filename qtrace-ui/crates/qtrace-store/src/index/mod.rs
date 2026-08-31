mod builder;
mod checkpoints;
mod intervals;
mod postings;

use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    fmt,
};

use qtrace_provider::{
    CompletenessCause, CompletenessRange, EventKey, EventKind, MemoryDirection, PcRelativeKind,
    Provenance, ProviderCapabilities, RangeBounds, RangeDomain, RegisterSlot, WorkDelta, WorkGuard,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    ArtifactSource, CacheError, CacheIdentity, CacheOpen, CacheReader, CacheWriter,
    MappedStoreView, OwnedStoreView, StoreView, cache::OwnedSection,
};

pub use builder::IndexBuilder;
pub use checkpoints::{RegisterAccess, RegisterObservationRow};
pub use postings::{PostingList, intersect_rows};

pub(crate) const NORMALIZED_CATALOG_SECTION: &str = "normalized_catalog.v1";
pub(crate) const NORMALIZED_CATALOG_ALIGNMENT: u32 = 8;
pub(crate) const NORMALIZED_CATALOG_ELEMENT_SIZE: u32 = 1;

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
    max_blob_bytes: u64,
    max_string_bytes: u64,
}

impl Default for BuildOptions {
    fn default() -> Self {
        Self {
            interval_block_rows: 64,
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
        if self.max_blob_bytes == 0 || self.max_string_bytes == 0 {
            return Err(IndexError::invalid("arena byte bounds must be non-zero"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ByteSpan {
    offset: u64,
    length: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ByteArena {
    bytes: Vec<u8>,
    spans: Vec<ByteSpan>,
    max_bytes: u64,
    #[serde(skip, default)]
    by_hash: HashMap<[u8; 32], Vec<u32>>,
}

impl ByteArena {
    fn new(max_bytes: u64) -> Self {
        Self {
            bytes: Vec::new(),
            spans: Vec::new(),
            max_bytes,
            by_hash: HashMap::new(),
        }
    }

    fn intern(&mut self, value: &[u8], guard: &dyn WorkGuard) -> Result<u32, IndexError> {
        let hash: [u8; 32] = Sha256::digest(value).into();
        if let Some(candidates) = self.by_hash.get(&hash) {
            for id in candidates {
                if self.get(*id)? == value {
                    return Ok(*id);
                }
            }
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
            resident_bytes: value.len() as u64,
            nodes: 1,
            ..WorkDelta::default()
        })?;
        self.bytes
            .try_reserve_exact(value.len())
            .map_err(|_| IndexError::resource("bounded arena allocation failed"))?;
        self.spans
            .try_reserve(1)
            .map_err(|_| IndexError::resource("bounded arena span allocation failed"))?;
        let id = u32::try_from(self.spans.len())
            .map_err(|_| IndexError::resource("bounded arena has too many spans"))?;
        let offset = u64::try_from(self.bytes.len())
            .map_err(|_| IndexError::resource("bounded arena offset does not fit u64"))?;
        self.bytes.extend_from_slice(value);
        self.spans.push(ByteSpan {
            offset,
            length: value.len() as u64,
        });
        self.by_hash
            .try_reserve(1)
            .map_err(|_| IndexError::resource("bounded arena hash allocation failed"))?;
        let candidates = self.by_hash.entry(hash).or_default();
        candidates
            .try_reserve(1)
            .map_err(|_| IndexError::resource("bounded arena collision allocation failed"))?;
        candidates.push(id);
        Ok(id)
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
        for span in &self.spans {
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct EventColumn {
    timeline: u64,
    tid: Option<u32>,
    sequence: Option<u64>,
    provenance: Provenance,
    payload_blob: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ModuleRow {
    source_event_row: usize,
    provenance: Provenance,
    source_id: u32,
    base: u64,
    name: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DefinitionRow {
    source_event_row: usize,
    provenance: Provenance,
    source_id: u32,
    opcode: u32,
    read_mask: u64,
    write_mask: u64,
    pc_displacement: i64,
    flags: u32,
    pc_kind: PcRelativeKind,
    condition: u8,
    slow_memory_path: bool,
    mnemonic: u32,
    operands: u32,
    disassembly: u32,
    exact_blob: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct InstructionRow {
    owner_row: usize,
    module: Option<u32>,
    relative_pc: u64,
    definition: Option<u32>,
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
struct SemanticRow {
    owner_row: usize,
    category: Option<u32>,
    name: u32,
    detail_blob: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct CompletenessRow {
    domain: RangeDomain,
    bounds: RangeBounds,
    provenance: Provenance,
    cause: CompletenessCause,
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
struct IndexCatalog {
    timeline: BTreeMap<u64, PostingList>,
    tid: BTreeMap<u32, PostingList>,
    kind: BTreeMap<u8, PostingList>,
    module: BTreeMap<u32, PostingList>,
    definition: BTreeMap<u32, PostingList>,
    register: BTreeMap<u8, PostingList>,
    semantic_category: BTreeMap<u32, PostingList>,
    semantic_name: BTreeMap<u32, PostingList>,
    call: PostingList,
    return_rows: PostingList,
    checkpoint: PostingList,
    sequence: Vec<(u64, usize)>,
    module_pc: BTreeMap<u32, Vec<(u64, usize)>>,
    memory: intervals::IntervalIndex,
    source_keys: Vec<SourceKeyRow>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct NormalizedCatalog {
    schema: u32,
    capabilities: ProviderCapabilities,
    events: Vec<EventColumn>,
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
    fn validate_shape(&self, event_count: usize) -> Result<(), IndexError> {
        if self.schema != 1 || self.events.len() != event_count {
            return Err(IndexError::corrupt(
                "normalized event-column row counts differ",
            ));
        }
        self.strings.validate()?;
        self.blobs.validate()?;
        for event in &self.events {
            self.blobs.get(event.payload_blob)?;
        }
        for module in &self.modules {
            self.strings.get(module.name)?;
        }
        for definition in &self.definitions {
            self.strings.get(definition.mnemonic)?;
            self.strings.get(definition.operands)?;
            self.strings.get(definition.disassembly)?;
            self.blobs.get(definition.exact_blob)?;
        }
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
        for list in self
            .indexes
            .timeline
            .values()
            .chain(self.indexes.tid.values())
            .chain(self.indexes.kind.values())
            .chain(self.indexes.module.values())
            .chain(self.indexes.definition.values())
            .chain(self.indexes.register.values())
            .chain(self.indexes.semantic_category.values())
            .chain(self.indexes.semantic_name.values())
            .chain([
                &self.indexes.call,
                &self.indexes.return_rows,
                &self.indexes.checkpoint,
            ])
        {
            list.validate(event_count)?;
        }
        if self
            .indexes
            .sequence
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
            || self
                .indexes
                .sequence
                .iter()
                .any(|(_, row)| *row >= event_count)
            || self.indexes.module_pc.values().any(|values| {
                values.windows(2).any(|pair| pair[0] >= pair[1])
                    || values.iter().any(|(_, row)| *row >= event_count)
            })
        {
            return Err(IndexError::corrupt("sorted range index is invalid"));
        }
        self.indexes.memory.validate(event_count)?;
        let mut seen_rows = Vec::new();
        seen_rows
            .try_reserve_exact(event_count)
            .map_err(|_| IndexError::resource("source-key bijection allocation failed"))?;
        seen_rows.resize(event_count, false);
        if self.indexes.source_keys.len() != event_count
            || self.indexes.source_keys.windows(2).any(|pair| {
                compare_event_keys(&pair[0].key, &pair[1].key) != std::cmp::Ordering::Less
            })
            || self.indexes.source_keys.iter().any(|entry| {
                entry.row >= event_count || std::mem::replace(&mut seen_rows[entry.row], true)
            })
            || seen_rows.iter().any(|seen| !*seen)
        {
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
        self.validate_shape(keys.len())?;
        if kinds.len() != keys.len() {
            return Err(IndexError::corrupt(
                "normalized event-column row counts differ",
            ));
        }
        for (row, event) in self.events.iter().enumerate() {
            if event.timeline != keys[row].timeline.0
                || event.tid != keys[row].tid
                || event.sequence != keys[row].sequence
            {
                return Err(IndexError::corrupt(
                    "normalized source coordinates disagree",
                ));
            }
            self.blobs.get(event.payload_blob)?;
        }
        for list in self
            .indexes
            .timeline
            .values()
            .chain(self.indexes.tid.values())
            .chain(self.indexes.kind.values())
            .chain(self.indexes.module.values())
            .chain(self.indexes.definition.values())
            .chain(self.indexes.register.values())
            .chain(self.indexes.semantic_category.values())
            .chain(self.indexes.semantic_name.values())
            .chain([
                &self.indexes.call,
                &self.indexes.return_rows,
                &self.indexes.checkpoint,
            ])
        {
            list.validate(keys.len())?;
        }
        if self
            .indexes
            .sequence
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
            || self
                .indexes
                .sequence
                .iter()
                .any(|(_, row)| *row >= keys.len())
            || self.indexes.module_pc.values().any(|values| {
                values.windows(2).any(|pair| pair[0] >= pair[1])
                    || values.iter().any(|(_, row)| *row >= keys.len())
            })
        {
            return Err(IndexError::corrupt("sorted range index is invalid"));
        }
        self.indexes.memory.validate(keys.len())?;
        if self.indexes.source_keys.len() != keys.len()
            || self.indexes.source_keys.windows(2).any(|pair| {
                compare_event_keys(&pair[0].key, &pair[1].key) != std::cmp::Ordering::Less
            })
            || self
                .indexes
                .source_keys
                .iter()
                .any(|entry| keys.get(entry.row) != Some(&entry.key))
        {
            return Err(IndexError::corrupt(
                "source row and EventKey mapping is not bijective",
            ));
        }
        let interval_block_rows = u32::try_from(self.indexes.memory.block_rows())
            .map_err(|_| IndexError::corrupt("interval block size does not fit u32"))?;
        let options = BuildOptions {
            interval_block_rows,
            max_blob_bytes: self.blobs.max_bytes,
            max_string_bytes: self.strings.max_bytes,
        };
        let expected = builder::build_indexes(
            keys,
            kinds,
            &self.events,
            &self.definitions,
            &self.instructions,
            &self.memories,
            &self.semantics,
            &self.observations,
            &options,
            guard,
        )
        .map_err(|error| {
            if error.code().starts_with("control.") || error.code() == "job.cancelled" {
                error
            } else {
                IndexError::corrupt("eager index reconstruction failed")
            }
        })?;
        if expected != self.indexes {
            return Err(IndexError::corrupt(
                "eager indexes do not match normalized columns",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct OwnedTraceStore {
    base: OwnedStoreView,
    catalog: NormalizedCatalog,
}

impl OwnedTraceStore {
    fn new(
        keys: Vec<EventKey>,
        kinds: Vec<EventKind>,
        catalog: NormalizedCatalog,
        guard: &dyn WorkGuard,
    ) -> Result<Self, IndexError> {
        catalog.validate(&keys, &kinds, guard)?;
        Ok(Self {
            base: OwnedStoreView::new(keys, kinds)?,
            catalog,
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

    pub const fn capabilities(&self) -> &ProviderCapabilities {
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

    fn cache_view_with_catalog(&self) -> Result<OwnedStoreView, IndexError> {
        Ok(self.base.clone().with_section(OwnedSection {
            name: NORMALIZED_CATALOG_SECTION,
            alignment: NORMALIZED_CATALOG_ALIGNMENT,
            element_size: NORMALIZED_CATALOG_ELEMENT_SIZE,
            bytes: self.catalog_bytes()?,
        })?)
    }

    pub(crate) fn catalog_bytes(&self) -> Result<Vec<u8>, IndexError> {
        builder::canonical_bytes(&self.catalog)
    }
}

#[derive(Clone, Debug)]
pub struct MappedTraceStore {
    view: MappedStoreView,
    catalog: NormalizedCatalog,
}

impl MappedTraceStore {
    fn open(view: MappedStoreView, guard: &dyn WorkGuard) -> Result<Self, IndexError> {
        guard.consume(WorkDelta::default())?;
        let bytes = view
            .section_bytes(NORMALIZED_CATALOG_SECTION, guard)?
            .ok_or_else(|| IndexError::corrupt("normalized catalog section is missing"))?;
        let catalog: NormalizedCatalog = serde_json::from_slice(&bytes)
            .map_err(|_| IndexError::corrupt("normalized catalog JSON is invalid"))?;
        let mut keys = Vec::new();
        let mut kinds = Vec::new();
        keys.try_reserve_exact(view.event_count())
            .map_err(|_| IndexError::resource("mapped key validation allocation failed"))?;
        kinds
            .try_reserve_exact(view.event_count())
            .map_err(|_| IndexError::resource("mapped kind validation allocation failed"))?;
        for row in 0..view.event_count() {
            if row % 4096 == 0 {
                guard.consume(WorkDelta::default())?;
            }
            keys.push(view.event_key(row)?);
            kinds.push(view.event_kind(row)?);
        }
        catalog.validate(&keys, &kinds, guard)?;
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
    pub const fn capabilities(&self) -> &ProviderCapabilities {
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
        let outcome = CacheWriter::new(identity.clone(), owned.cache_view_with_catalog()?)?
            .publish(cache_root, guard)?;
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
                CacheWriter::remove_published(cache_root, &identity).map_err(|cleanup| {
                    IndexError::new(
                        cleanup.code(),
                        format!(
                            "post-publish reopen failed ({error}); rollback failed ({cleanup})"
                        ),
                    )
                })?;
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

pub(crate) fn validate_catalog_bytes(bytes: &[u8], event_count: usize) -> Result<(), IndexError> {
    let catalog: NormalizedCatalog = serde_json::from_slice(bytes)
        .map_err(|_| IndexError::corrupt("normalized catalog JSON is invalid"))?;
    let canonical = serde_json::to_vec(&catalog)
        .map_err(|_| IndexError::corrupt("normalized catalog cannot be re-encoded"))?;
    if canonical != bytes {
        return Err(IndexError::corrupt(
            "normalized catalog JSON is not canonical",
        ));
    }
    catalog.validate_shape(event_count)
}

pub(crate) fn validate_catalog_bytes_with_rows(
    bytes: &[u8],
    keys: &[EventKey],
    kinds: &[EventKind],
    guard: &dyn WorkGuard,
) -> Result<(), IndexError> {
    let catalog: NormalizedCatalog = serde_json::from_slice(bytes)
        .map_err(|_| IndexError::corrupt("normalized catalog JSON is invalid"))?;
    let canonical = serde_json::to_vec(&catalog)
        .map_err(|_| IndexError::corrupt("normalized catalog cannot be re-encoded"))?;
    if canonical != bytes {
        return Err(IndexError::corrupt(
            "normalized catalog JSON is not canonical",
        ));
    }
    catalog.validate(keys, kinds, guard)
}
