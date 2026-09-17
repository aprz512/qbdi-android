mod builder;
mod checkpoints;
mod intervals;
mod postings;
mod validation;
mod wire;

use std::{
    collections::{BTreeSet, HashMap},
    error::Error,
    fmt,
};

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
    let source_format = NormalizedSourceFormat::parse(source_format)?;
    let content_identity =
        derive_normalized_content_identity(&catalog, keys, kinds, source_format, guard)?;
    Ok(ValidatedCatalog {
        catalog: crate::allocation::try_box(catalog, guard, "validated normalized catalog")?,
        content_identity,
        source_format,
    })
}

#[derive(Debug)]
pub(crate) struct ValidatedCatalog {
    catalog: Box<NormalizedCatalog>,
    content_identity: NormalizedContentIdentity,
    source_format: NormalizedSourceFormat,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexError {
    detail: IndexErrorDetail,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum IndexErrorDetail {
    Message { code: &'static str, detail: String },
    Provider(qtrace_provider::ProviderError),
    Cache(CacheError),
    Abort(qtrace_provider::OperationAbort),
}

impl IndexError {
    pub fn code(&self) -> &str {
        match &self.detail {
            IndexErrorDetail::Message { code, .. } => code,
            IndexErrorDetail::Provider(error) if error.code() == "control.cancelled" => {
                "job.cancelled"
            }
            IndexErrorDetail::Provider(error) => error.code(),
            IndexErrorDetail::Cache(error) => error.code(),
            IndexErrorDetail::Abort(qtrace_provider::OperationAbort::Cancelled) => "job.cancelled",
            IndexErrorDetail::Abort(qtrace_provider::OperationAbort::BudgetExceeded { .. }) => {
                "control.budget_exceeded"
            }
        }
    }

    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            detail: IndexErrorDetail::Message {
                code,
                detail: detail.into(),
            },
        }
    }

    pub fn operation_abort(&self) -> Option<&qtrace_provider::OperationAbort> {
        match &self.detail {
            IndexErrorDetail::Abort(abort) => Some(abort),
            IndexErrorDetail::Cache(error) => error.operation_abort(),
            IndexErrorDetail::Provider(error) => error.operation_abort(),
            IndexErrorDetail::Message { .. } => None,
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
        write!(formatter, "{}: ", self.code())?;
        match &self.detail {
            IndexErrorDetail::Message { detail, .. } => formatter.write_str(detail),
            IndexErrorDetail::Provider(error) => fmt::Display::fmt(error, formatter),
            IndexErrorDetail::Cache(error) => fmt::Display::fmt(error, formatter),
            IndexErrorDetail::Abort(abort) => fmt::Display::fmt(abort, formatter),
        }
    }
}

impl Error for IndexError {}

impl From<qtrace_provider::ProviderError> for IndexError {
    fn from(error: qtrace_provider::ProviderError) -> Self {
        Self {
            detail: IndexErrorDetail::Provider(error),
        }
    }
}

impl From<qtrace_provider::OperationAbort> for IndexError {
    fn from(error: qtrace_provider::OperationAbort) -> Self {
        Self {
            detail: IndexErrorDetail::Abort(error),
        }
    }
}

impl From<CacheError> for IndexError {
    fn from(error: CacheError) -> Self {
        Self {
            detail: IndexErrorDetail::Cache(error),
        }
    }
}

impl From<crate::allocation::AllocationFailure> for IndexError {
    fn from(error: crate::allocation::AllocationFailure) -> Self {
        match error {
            crate::allocation::AllocationFailure::Aborted(abort) => Self::from(abort),
            crate::allocation::AllocationFailure::Overflow(detail)
            | crate::allocation::AllocationFailure::Failed(detail) => Self::resource(detail),
        }
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
        let mut digest = Sha256::new();
        digest.update(b"qtrace-build-options-v2\0");
        digest.update(self.interval_block_rows.to_le_bytes());
        digest.update(self.max_payload_bytes.to_le_bytes());
        digest.update(self.max_blob_bytes.to_le_bytes());
        digest.update(self.max_string_bytes.to_le_bytes());
        digest.finalize().into()
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ByteSpan {
    offset: u64,
    length: u64,
}

#[derive(Debug)]
enum ArenaBacking<'a, T> {
    Owned(Vec<T>),
    Borrowed(&'a [T]),
}

impl<T> ArenaBacking<'_, T> {
    fn as_slice(&self) -> &[T] {
        match self {
            Self::Owned(values) => values,
            Self::Borrowed(values) => values,
        }
    }

    fn owned_mut(&mut self) -> Result<&mut Vec<T>, IndexError> {
        match self {
            Self::Owned(values) => Ok(values),
            Self::Borrowed(_) => Err(IndexError::invalid(
                "borrowed validation arena cannot append new bytes",
            )),
        }
    }

    fn into_owned(self) -> Result<Vec<T>, IndexError> {
        match self {
            Self::Owned(values) => Ok(values),
            Self::Borrowed(_) => Err(IndexError::invalid(
                "borrowed validation arena cannot become owned",
            )),
        }
    }
}

#[derive(Debug)]
struct ByteArena<'a> {
    bytes: ArenaBacking<'a, u8>,
    spans: ArenaBacking<'a, ByteSpan>,
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

impl PartialEq for ByteArena<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.as_slice() == other.bytes.as_slice()
            && self.spans.as_slice() == other.spans.as_slice()
            && self.max_bytes == other.max_bytes
    }
}

impl Eq for ByteArena<'_> {}

impl<'a> ByteArena<'a> {
    fn new(max_bytes: u64) -> Self {
        Self {
            bytes: ArenaBacking::Owned(Vec::new()),
            spans: ArenaBacking::Owned(Vec::new()),
            max_bytes,
            by_hash: HashMap::new(),
            validation_next_id: None,
        }
    }

    fn validation(source: &'a ByteArena<'static>) -> Self {
        Self {
            bytes: ArenaBacking::Borrowed(source.bytes.as_slice()),
            spans: ArenaBacking::Borrowed(source.spans.as_slice()),
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
                nodes: 1,
                ..WorkDelta::default()
            })?;
            if !hash_was_present {
                crate::allocation::try_reserve_hash_map(
                    &mut self.by_hash,
                    1,
                    guard,
                    "bounded arena hash allocation",
                )?;
            }
            self.insert_hash_candidate(hash, next_id, guard)?;
            return Ok(next_id);
        }
        let new_length = u64::try_from(self.bytes.as_slice().len())
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
            nodes: 1,
            ..WorkDelta::default()
        })?;
        crate::allocation::try_reserve_vec(
            self.bytes.owned_mut()?,
            value.len(),
            guard,
            "bounded arena allocation",
        )?;
        crate::allocation::try_reserve_vec(
            self.spans.owned_mut()?,
            1,
            guard,
            "bounded arena span allocation",
        )?;
        let id = u32::try_from(self.spans.as_slice().len())
            .map_err(|_| IndexError::resource("bounded arena has too many spans"))?;
        let offset = u64::try_from(self.bytes.as_slice().len())
            .map_err(|_| IndexError::resource("bounded arena offset does not fit u64"))?;
        self.bytes.owned_mut()?.extend_from_slice(value);
        self.spans.owned_mut()?.push(ByteSpan {
            offset,
            length: value.len() as u64,
        });
        if !hash_was_present {
            crate::allocation::try_reserve_hash_map(
                &mut self.by_hash,
                1,
                guard,
                "bounded arena hash allocation",
            )?;
        }
        self.insert_hash_candidate(hash, id, guard)?;
        Ok(id)
    }

    fn insert_hash_candidate(
        &mut self,
        hash: [u8; 32],
        id: u32,
        guard: &dyn WorkGuard,
    ) -> Result<(), IndexError> {
        match self.by_hash.entry(hash) {
            std::collections::hash_map::Entry::Occupied(mut entry) => match entry.get_mut() {
                HashCandidates::One(first) => {
                    let first = *first;
                    let mut candidates = Vec::new();
                    crate::allocation::try_reserve_vec(
                        &mut candidates,
                        2,
                        guard,
                        "bounded arena collision allocation",
                    )?;
                    candidates.push(first);
                    candidates.push(id);
                    *entry.get_mut() = HashCandidates::Collisions(candidates);
                }
                HashCandidates::Collisions(candidates) => {
                    crate::allocation::try_reserve_vec(
                        candidates,
                        1,
                        guard,
                        "bounded arena collision allocation",
                    )?;
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
            .as_slice()
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
            .as_slice()
            .get(start..end)
            .ok_or_else(|| IndexError::corrupt("arena span is outside its bytes"))
    }

    fn validate(&self, guard: &dyn WorkGuard) -> Result<(), IndexError> {
        if self.bytes.as_slice().len() as u64 > self.max_bytes {
            return Err(IndexError::corrupt("arena exceeds its declared byte bound"));
        }
        let mut expected = 0_u64;
        guarded_row_chunks(self.spans.as_slice(), guard, |chunk| {
            for span in chunk {
                if span.offset != expected {
                    return Err(IndexError::corrupt(
                        "arena spans are not append-only contiguous",
                    ));
                }
                expected = expected
                    .checked_add(span.length)
                    .ok_or_else(|| IndexError::corrupt("arena span end overflow"))?;
            }
            Ok(())
        })?;
        if expected != self.bytes.as_slice().len() as u64 {
            return Err(IndexError::corrupt("arena spans do not cover exact bytes"));
        }
        Ok(())
    }

    fn validate_dictionary_complete(&self) -> Result<(), IndexError> {
        let spans = u32::try_from(self.spans.as_slice().len())
            .map_err(|_| IndexError::corrupt("arena span count exceeds u32"))?;
        if self.validation_next_id != Some(spans) {
            return Err(IndexError::corrupt(
                "arena has unreferenced or missing dictionary entries",
            ));
        }
        Ok(())
    }

    fn spans(&self) -> &[ByteSpan] {
        self.spans.as_slice()
    }

    fn into_owned_parts(self) -> Result<(Vec<u8>, Vec<ByteSpan>, u64), IndexError> {
        Ok((
            self.bytes.into_owned()?,
            self.spans.into_owned()?,
            self.max_bytes,
        ))
    }

    fn from_owned_parts(
        bytes: Vec<u8>,
        spans: Vec<ByteSpan>,
        max_bytes: u64,
    ) -> ByteArena<'static> {
        ByteArena {
            bytes: ArenaBacking::Owned(bytes),
            spans: ArenaBacking::Owned(spans),
            max_bytes,
            by_hash: HashMap::new(),
            validation_next_id: None,
        }
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

/// Versioned identity of the normalized facts and their persistent binary layout.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct NormalizedLayoutIdentity {
    schema_version: u32,
    layout_fingerprint: [u8; 32],
}

impl NormalizedLayoutIdentity {
    pub const fn new(schema_version: u32, layout_fingerprint: [u8; 32]) -> Self {
        Self {
            schema_version,
            layout_fingerprint,
        }
    }

    pub const fn schema_version(self) -> u32 {
        self.schema_version
    }

    pub const fn layout_fingerprint(self) -> [u8; 32] {
        self.layout_fingerprint
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NormalizedSourceFormat {
    Qtrb,
    Flight,
    Other,
}

impl NormalizedSourceFormat {
    pub(crate) fn parse(value: &str) -> Result<Self, IndexError> {
        if value.eq_ignore_ascii_case("qtrb") {
            Ok(Self::Qtrb)
        } else if value.eq_ignore_ascii_case("flight") {
            Ok(Self::Flight)
        } else {
            Ok(Self::Other)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct NormalizedContentIdentity([u8; 32]);

impl NormalizedContentIdentity {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

const NORMALIZED_LAYOUT_FINGERPRINT: [u8; 32] = [
    0x70, 0x9a, 0x76, 0x70, 0x96, 0x41, 0x78, 0x36, 0xfb, 0x0a, 0xde, 0x5a, 0xb4, 0xc6, 0xeb, 0x26,
    0x36, 0xa3, 0xd0, 0x42, 0xa0, 0x5c, 0x1a, 0x4e, 0x35, 0x4d, 0xee, 0x23, 0x0d, 0x7a, 0xb8, 0xf2,
];

impl CompletenessRow {
    fn from_range(value: CompletenessRange) -> Self {
        Self {
            domain: value.domain(),
            bounds: value.bounds(),
            provenance: value.provenance(),
            cause: value.cause(),
        }
    }

    fn to_range(self) -> Option<CompletenessRange> {
        match (self.domain, self.bounds) {
            (RangeDomain::CapturedSequence, RangeBounds::InclusiveSequence { first, last }) => {
                CompletenessRange::captured_sequence_with_cause(
                    first,
                    last,
                    self.provenance,
                    self.cause,
                )
            }
            (
                RangeDomain::SourceBytes,
                RangeBounds::HalfOpen {
                    start,
                    end_exclusive,
                },
            ) => CompletenessRange::source_bytes_with_cause(
                start,
                end_exclusive,
                self.provenance,
                self.cause,
            ),
            (
                RangeDomain::MemoryAddresses,
                RangeBounds::HalfOpen {
                    start,
                    end_exclusive,
                },
            ) => CompletenessRange::memory_addresses_with_cause(
                start,
                end_exclusive,
                self.provenance,
                self.cause,
            ),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct SourceKeyRow {
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

    fn guarded_get<'a>(
        &'a self,
        key: &K,
        guard: &dyn WorkGuard,
    ) -> Result<(Option<&'a V>, u64), IndexError> {
        let mut left = 0_usize;
        let mut right = self.entries.len();
        let mut work = 0_u64;
        while left < right {
            consume_row_work(guard, 1)?;
            work = work
                .checked_add(1)
                .ok_or_else(|| IndexError::resource("sorted-map lookup work overflow"))?;
            let middle = left + (right - left) / 2;
            match self.entries[middle].0.cmp(key) {
                std::cmp::Ordering::Less => left = middle + 1,
                std::cmp::Ordering::Greater => right = middle,
                std::cmp::Ordering::Equal => return Ok((Some(&self.entries[middle].1), work)),
            }
        }
        Ok((None, work))
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

#[derive(Debug, Eq, PartialEq)]
struct NormalizedCatalog {
    schema: u32,
    capabilities: ProviderCapabilities,
    events: Vec<EventColumn>,
    payloads: ByteArena<'static>,
    strings: ByteArena<'static>,
    blobs: ByteArena<'static>,
    modules: Vec<ModuleRow>,
    definitions: Vec<DefinitionRow>,
    instructions: Vec<InstructionRow>,
    memories: Vec<MemoryRow>,
    semantics: Vec<SemanticRow>,
    observations: Vec<RegisterObservationRow>,
    completeness: Vec<CompletenessRow>,
    indexes: IndexCatalog,
}

#[cfg(test)]
fn guarded_byte_chunks(
    bytes: &[u8],
    guard: &dyn WorkGuard,
    mut work: impl FnMut(&[u8]),
) -> Result<(), IndexError> {
    for chunk in bytes.chunks(4096) {
        guard.consume(WorkDelta {
            input_bytes: chunk.len() as u64,
            ..WorkDelta::default()
        })?;
        work(chunk);
    }
    Ok(())
}

fn guarded_row_chunks<T>(
    rows: &[T],
    guard: &dyn WorkGuard,
    mut work: impl FnMut(&[T]) -> Result<(), IndexError>,
) -> Result<(), IndexError> {
    for chunk in rows.chunks(4096) {
        guard.consume(WorkDelta::default())?;
        work(chunk)?;
    }
    Ok(())
}

fn derive_normalized_content_identity(
    catalog: &NormalizedCatalog,
    keys: &[EventKey],
    kinds: &[EventKind],
    source_format: NormalizedSourceFormat,
    guard: &dyn WorkGuard,
) -> Result<NormalizedContentIdentity, IndexError> {
    if keys.len() != kinds.len() || catalog.events.len() != keys.len() {
        return Err(IndexError::corrupt("normalized content identity shape"));
    }
    guard.consume(WorkDelta::default())?;
    let mut digest = Sha256::new();
    digest.update(b"qtrace-store/normalized-content/v2\0source-identity");
    digest.update(catalog.schema.to_le_bytes());
    digest.update([match source_format {
        NormalizedSourceFormat::Qtrb => 0,
        NormalizedSourceFormat::Flight => 1,
        NormalizedSourceFormat::Other => 2,
    }]);
    digest.update((keys.len() as u64).to_le_bytes());
    if let Some(first) = keys.first() {
        digest.update(first.artifact.as_bytes());
    }
    Ok(NormalizedContentIdentity(digest.finalize().into()))
}

impl NormalizedCatalog {
    fn validate_shape(&self, event_count: usize, guard: &dyn WorkGuard) -> Result<(), IndexError> {
        if self.schema != 2 || self.events.len() != event_count {
            return Err(IndexError::corrupt(
                "normalized event-column row counts differ",
            ));
        }
        self.strings.validate(guard)?;
        self.payloads.validate(guard)?;
        self.blobs.validate(guard)?;
        guarded_row_chunks(&self.events, guard, |chunk| {
            for event in chunk {
                self.payloads.get(event.payload_blob).map_err(|error| {
                    IndexError::corrupt(format!("event payload reference is invalid: {error}"))
                })?;
            }
            Ok(())
        })?;
        guarded_row_chunks(&self.modules, guard, |chunk| {
            for module in chunk {
                self.strings.get(module.name).map_err(|error| {
                    IndexError::corrupt(format!("module name reference is invalid: {error}"))
                })?;
            }
            Ok(())
        })?;
        guarded_row_chunks(&self.definitions, guard, |chunk| {
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
            Ok(())
        })?;
        let invalid = || IndexError::corrupt("normalized typed-table reference is invalid");
        guarded_row_chunks(&self.instructions, guard, |chunk| {
            if chunk.iter().any(|row| {
                row.owner_row >= event_count
                    || row
                        .module
                        .is_some_and(|id| id as usize >= self.modules.len())
                    || row
                        .definition
                        .is_some_and(|id| id as usize >= self.definitions.len())
            }) {
                return Err(invalid());
            }
            Ok(())
        })?;
        guarded_row_chunks(&self.memories, guard, |chunk| {
            if chunk.iter().any(|row| {
                row.owner_row >= event_count
                    || row
                        .module
                        .is_some_and(|id| id as usize >= self.modules.len())
                    || row.address.checked_add(u64::from(row.size)) != Some(row.end_exclusive)
                    || self.blobs.get(row.before_blob).is_err()
                    || self.blobs.get(row.after_blob).is_err()
            }) {
                return Err(invalid());
            }
            Ok(())
        })?;
        guarded_row_chunks(&self.semantics, guard, |chunk| {
            if chunk.iter().any(|row| {
                row.owner_row >= event_count
                    || row.category.is_some_and(|id| self.strings.get(id).is_err())
                    || self.strings.get(row.name).is_err()
                    || self.blobs.get(row.detail_blob).is_err()
            }) {
                return Err(invalid());
            }
            Ok(())
        })?;
        guarded_row_chunks(&self.observations, guard, |chunk| {
            if chunk.iter().any(|row| {
                row.owner_row >= event_count
                    || row.slot as usize >= RegisterSlot::COUNT
                    || row.captured_width == 0
            }) {
                return Err(invalid());
            }
            Ok(())
        })?;
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
    fn thread_ids(&self) -> Result<Vec<u32>, IndexError> {
        let mut tids = BTreeSet::new();
        for row in 0..self.event_count() {
            let key = self
                .event_key(row)?
                .ok_or_else(|| IndexError::corrupt("event key is absent"))?;
            if let Some(tid) = key.tid {
                tids.insert(tid);
            }
        }
        Ok(tids.into_iter().collect())
    }
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

/// Optional zero-copy normalized catalog seam for consumers that need bulk analysis.
pub trait NormalizedBulkView: TraceStoreView {
    fn normalized_layout_identity(&self) -> NormalizedLayoutIdentity;
    fn normalized_content_identity(&self) -> NormalizedContentIdentity;
    fn normalized_source_format(&self) -> NormalizedSourceFormat;
    fn module_rows(&self) -> &[ModuleRow];
    fn definition_rows(&self) -> &[DefinitionRow];
    fn instruction_rows(&self) -> &[InstructionRow];
    fn memory_rows(&self) -> &[MemoryRow];
    fn semantic_rows(&self) -> &[SemanticRow];
    fn register_observation_rows(&self) -> &[RegisterObservationRow];
    fn string_count(&self) -> usize;
    fn blob_count(&self) -> usize;
    fn semantic_dictionary_work(
        &self,
        _family: SemanticDictionaryFamily,
        term_count: usize,
        guard: &dyn WorkGuard,
    ) -> Result<SemanticDictionaryWork, IndexError> {
        let mut dictionary_bytes = 0_u64;
        for start in (0..self.string_count()).step_by(4096) {
            let end = start.saturating_add(4096).min(self.string_count());
            consume_row_work(guard, end - start)?;
            for id in start..end {
                dictionary_bytes = dictionary_bytes
                    .checked_add(
                        self.string_bytes(u32::try_from(id).map_err(|_| {
                            IndexError::resource("semantic dictionary ID overflow")
                        })?)?
                        .len() as u64,
                    )
                    .ok_or_else(|| {
                        IndexError::resource("semantic dictionary byte count overflow")
                    })?;
            }
        }
        semantic_dictionary_work_from_counts(term_count, self.string_count(), dictionary_bytes, 0)
    }
    /// Returns allocation-free posting cardinality and a checked upper bound for the Nodes work
    /// consumed by one subsequent [`Self::bounded_rows`] call for the same query.
    ///
    /// The estimate excludes work already consumed while producing the estimate. Implementations
    /// whose decode can scan data not bounded by the returned row count must override this method;
    /// the default fails closed so hidden scans cannot silently escape the analysis work plan.
    fn bounded_row_estimate(
        &self,
        _query: NormalizedPostingQuery<'_>,
        _max_rows: usize,
        _guard: &dyn WorkGuard,
    ) -> Result<NormalizedPostingEstimate, IndexError> {
        Err(IndexError::resource(
            "normalized bulk view does not provide a bounded decode-work estimate",
        ))
    }
    /// Returns a checked store-owned work bound for a future definition posting query whose
    /// allocation-free mnemonic planning can produce at most `query_terms` definition IDs and
    /// at most `max_rows` encoded rows.
    fn bounded_definition_decode_work(
        &self,
        _query_terms: usize,
        _max_rows: usize,
    ) -> Result<u64, IndexError> {
        Err(IndexError::resource(
            "normalized bulk view does not provide a definition decode-work bound",
        ))
    }
    /// Returns an allocation-free upper bound for the ascending-unique row IDs returned by
    /// [`Self::bounded_rows`], rejecting before decode when that bound exceeds `max_rows`.
    fn bounded_row_count(
        &self,
        query: NormalizedPostingQuery<'_>,
        max_rows: usize,
        guard: &dyn WorkGuard,
    ) -> Result<usize, IndexError>;
    /// Returns row IDs in strictly ascending order with duplicates removed.
    fn bounded_rows(
        &self,
        query: NormalizedPostingQuery<'_>,
        max_rows: usize,
        guard: &dyn WorkGuard,
    ) -> Result<Vec<usize>, IndexError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalizedPostingEstimate {
    /// Upper bound for decoded rows before duplicate removal.
    pub rows: usize,
    /// Checked Nodes-work upper bound for one subsequent production decode of this query.
    pub decode_work: u64,
}

impl NormalizedPostingEstimate {
    pub const fn new(rows: usize, decode_work: u64) -> Self {
        Self { rows, decode_work }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemanticDictionaryFamily {
    Categories,
    Names,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SemanticDictionaryWork {
    pub term_count: u64,
    pub dictionary_items: u64,
    pub dictionary_bytes: u64,
    pub posting_lists: u64,
    pub lookup_items: u64,
    pub lookup_bytes: u64,
}

fn semantic_dictionary_work_from_counts(
    term_count: usize,
    dictionary_items: usize,
    dictionary_bytes: u64,
    posting_lists: usize,
) -> Result<SemanticDictionaryWork, IndexError> {
    let term_count = u64::try_from(term_count)
        .map_err(|_| IndexError::resource("semantic term count overflow"))?;
    let dictionary_items = u64::try_from(dictionary_items)
        .map_err(|_| IndexError::resource("semantic dictionary item count overflow"))?;
    Ok(SemanticDictionaryWork {
        term_count,
        dictionary_items,
        dictionary_bytes,
        posting_lists: u64::try_from(posting_lists)
            .map_err(|_| IndexError::resource("semantic posting-list count overflow"))?,
        lookup_items: dictionary_items
            .checked_mul(term_count)
            .ok_or_else(|| IndexError::resource("semantic dictionary item work overflow"))?,
        lookup_bytes: dictionary_bytes
            .checked_mul(term_count)
            .ok_or_else(|| IndexError::resource("semantic dictionary byte work overflow"))?,
    })
}

#[derive(Clone, Copy, Debug)]
pub enum NormalizedPostingQuery<'a> {
    Tids(&'a [u32]),
    Kinds(&'a [EventKind]),
    Modules(&'a [u32]),
    Sequence {
        start: u64,
        end_exclusive: u64,
    },
    ModulePc {
        module: u32,
        start: u64,
        end_exclusive: u64,
    },
    Definitions(&'a [u32]),
    Registers(&'a [RegisterSlot]),
    SemanticCategories(&'a [&'a [u8]]),
    SemanticNames(&'a [&'a [u8]]),
    Memory {
        start: u64,
        end_exclusive: u64,
    },
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

fn bounded_posting_union(
    lists: &[&PostingList],
    max_rows: usize,
    guard: &dyn WorkGuard,
) -> Result<Vec<usize>, IndexError> {
    let mut total = 0_usize;
    for list in lists {
        consume_row_work(guard, 1)?;
        total = total
            .checked_add(list.row_count())
            .filter(|total| *total <= max_rows)
            .ok_or_else(|| IndexError::resource("bounded posting result exceeds row limit"))?;
    }
    guard.consume(WorkDelta::default())?;
    let mut rows = Vec::new();
    crate::allocation::try_reserve_vec(
        &mut rows,
        total,
        guard,
        "bounded posting decode allocation",
    )?;
    for list in lists {
        let mut previous = None::<u64>;
        let mut visited = 0usize;
        list.visit_deltas(|delta| {
            if visited % 4096 == 0 {
                consume_row_work(guard, list.row_count().saturating_sub(visited).min(4096))?;
            }
            visited += 1;
            if delta == 0 {
                return Err(IndexError::corrupt("posting delta is zero"));
            }
            let row = match previous {
                None => delta
                    .checked_sub(1)
                    .ok_or_else(|| IndexError::corrupt("first posting delta underflow"))?,
                Some(previous) => previous
                    .checked_add(delta)
                    .ok_or_else(|| IndexError::corrupt("posting delta overflow"))?,
            };
            rows.push(
                usize::try_from(row)
                    .map_err(|_| IndexError::corrupt("posting row does not fit usize"))?,
            );
            previous = Some(row);
            Ok(())
        })?;
    }
    if lists.len() > 1 {
        radix_sort_unique_rows(&mut rows, guard)?;
    }
    Ok(rows)
}

fn bounded_map_count<'a, K, I>(
    map: &'a SortedMap<K, PostingList>,
    keys: I,
    max_rows: usize,
    guard: &dyn WorkGuard,
) -> Result<usize, IndexError>
where
    K: Ord + 'a,
    I: Iterator<Item = K>,
{
    Ok(bounded_map_estimate(map, keys, max_rows, guard)?.rows)
}

fn bounded_map_estimate<'a, K, I>(
    map: &'a SortedMap<K, PostingList>,
    keys: I,
    max_rows: usize,
    guard: &dyn WorkGuard,
) -> Result<NormalizedPostingEstimate, IndexError>
where
    K: Ord + 'a,
    I: Iterator<Item = K>,
{
    let mut encoded_rows = 0_usize;
    let mut matched_lists = 0_usize;
    let mut query_terms = 0_u64;
    let mut lookup_work = 0_u64;
    for key in keys {
        consume_row_work(guard, 1)?;
        query_terms = query_terms
            .checked_add(1)
            .ok_or_else(|| IndexError::resource("bounded posting term work overflow"))?;
        let (list, comparisons) = map.guarded_get(&key, guard)?;
        lookup_work = lookup_work
            .checked_add(comparisons)
            .ok_or_else(|| IndexError::resource("bounded posting lookup work overflow"))?;
        if let Some(list) = list {
            matched_lists = matched_lists
                .checked_add(1)
                .ok_or_else(|| IndexError::resource("bounded posting list count overflow"))?;
            encoded_rows = encoded_rows
                .checked_add(list.row_count())
                .ok_or_else(|| IndexError::resource("bounded posting row count overflow"))?;
            if encoded_rows > max_rows {
                return Err(IndexError::resource(
                    "bounded posting result exceeds row limit",
                ));
            }
        }
    }
    let decode_work = map_decode_work(query_terms, lookup_work, matched_lists, encoded_rows)?;
    Ok(NormalizedPostingEstimate::new(encoded_rows, decode_work))
}

fn map_decode_work(
    query_terms: u64,
    lookup_work: u64,
    matched_lists: usize,
    encoded_rows: usize,
) -> Result<u64, IndexError> {
    let lookup_pass = query_terms
        .checked_add(lookup_work)
        .ok_or_else(|| IndexError::resource("bounded posting lookup pass overflow"))?;
    let rows = u64::try_from(encoded_rows)
        .map_err(|_| IndexError::resource("bounded posting row work overflow"))?;
    let lists = u64::try_from(matched_lists)
        .map_err(|_| IndexError::resource("bounded posting list work overflow"))?;
    let radix = if matched_lists > 1 {
        RadixWork::for_rows(encoded_rows).checked_total()?
    } else {
        0
    };
    lookup_pass
        .checked_mul(2)
        .and_then(|work| work.checked_add(lists))
        .and_then(|work| work.checked_add(rows))
        .and_then(|work| work.checked_add(radix))
        .ok_or_else(|| IndexError::resource("bounded posting decode work overflow"))
}

fn map_decode_work_upper(
    query_terms: usize,
    map_entries: usize,
    encoded_rows: usize,
) -> Result<u64, IndexError> {
    let query_terms = u64::try_from(query_terms)
        .map_err(|_| IndexError::resource("bounded posting term work overflow"))?;
    let comparisons_per_lookup = if map_entries == 0 {
        0
    } else {
        u64::from(usize::BITS - map_entries.leading_zeros())
    };
    let lookup_work = query_terms
        .checked_mul(comparisons_per_lookup)
        .ok_or_else(|| IndexError::resource("bounded posting lookup work overflow"))?;
    let map_entries = u64::try_from(map_entries)
        .map_err(|_| IndexError::resource("bounded posting map size overflow"))?;
    let matched_lists = usize::try_from(query_terms.min(map_entries))
        .map_err(|_| IndexError::resource("bounded posting list count overflow"))?;
    map_decode_work(query_terms, lookup_work, matched_lists, encoded_rows)
}

fn bounded_map_rows<'a, K, I>(
    map: &'a SortedMap<K, PostingList>,
    keys: I,
    max_rows: usize,
    guard: &dyn WorkGuard,
) -> Result<Vec<usize>, IndexError>
where
    K: Ord + 'a,
    I: Iterator<Item = K> + Clone,
{
    bounded_map_count(map, keys.clone(), max_rows, guard)?;
    let mut lists = Vec::new();
    for key in keys {
        consume_row_work(guard, 1)?;
        if let (Some(list), _) = map.guarded_get(&key, guard)? {
            crate::allocation::try_reserve_vec(
                &mut lists,
                1,
                guard,
                "bounded posting list references",
            )?;
            lists.push(list);
        }
    }
    bounded_posting_union(&lists, max_rows, guard)
}

fn bounded_pair_rows(
    rows: &[(u64, usize)],
    start: u64,
    end: u64,
    max_rows: usize,
    guard: &dyn WorkGuard,
) -> Result<Vec<usize>, IndexError> {
    if start >= end {
        return Ok(Vec::new());
    }
    let first = guarded_partition_point(rows, guard, |(value, _)| *value < start)?;
    let last = guarded_partition_point(rows, guard, |(value, _)| *value < end)?;
    let count = last - first;
    if count > max_rows {
        return Err(IndexError::resource(
            "bounded posting result exceeds row limit",
        ));
    }
    guard.consume(WorkDelta::default())?;
    let mut result = Vec::new();
    crate::allocation::try_reserve_vec(
        &mut result,
        count,
        guard,
        "bounded pair posting allocation",
    )?;
    for chunk in rows[first..last].chunks(4096) {
        consume_row_work(guard, chunk.len())?;
        result.extend(chunk.iter().map(|(_, row)| *row));
    }
    radix_sort_unique_rows(&mut result, guard)?;
    Ok(result)
}

fn bounded_pair_estimate(
    rows: &[(u64, usize)],
    start: u64,
    end: u64,
    max_rows: usize,
    guard: &dyn WorkGuard,
) -> Result<NormalizedPostingEstimate, IndexError> {
    if start >= end {
        return Ok(NormalizedPostingEstimate::new(0, 0));
    }
    let (first, first_work) =
        guarded_partition_point_with_work(rows, guard, |(value, _)| *value < start)?;
    let (last, last_work) =
        guarded_partition_point_with_work(rows, guard, |(value, _)| *value < end)?;
    let count = last - first;
    if count > max_rows {
        return Err(IndexError::resource(
            "bounded posting result exceeds row limit",
        ));
    }
    let decode_work = first_work
        .checked_add(last_work)
        .and_then(|work| work.checked_add(u64::try_from(count).ok()?))
        .and_then(|work| work.checked_add(RadixWork::for_rows(count).checked_total().ok()?))
        .ok_or_else(|| IndexError::resource("bounded pair decode work overflow"))?;
    Ok(NormalizedPostingEstimate::new(count, decode_work))
}

#[derive(Clone, Copy)]
struct RadixWork {
    rows: usize,
    passes: usize,
    dedup: usize,
}

impl RadixWork {
    fn for_rows(rows: usize) -> Self {
        Self {
            rows,
            passes: usize::from(rows >= 2) * (usize::BITS as usize / 8),
            dedup: rows.saturating_sub(1) * usize::from(rows >= 2),
        }
    }

    fn checked_total(self) -> Result<u64, IndexError> {
        let rows = u64::try_from(self.rows)
            .map_err(|_| IndexError::resource("radix row work overflow"))?;
        let passes = u64::try_from(self.passes)
            .map_err(|_| IndexError::resource("radix pass work overflow"))?;
        let dedup = u64::try_from(self.dedup)
            .map_err(|_| IndexError::resource("radix dedup work overflow"))?;
        rows.checked_mul(2)
            .and_then(|per_pass| per_pass.checked_add(256))
            .and_then(|per_pass| per_pass.checked_mul(passes))
            .and_then(|work| work.checked_add(dedup))
            .ok_or_else(|| IndexError::resource("radix work overflow"))
    }
}

pub(super) fn radix_sort_unique_rows(
    rows: &mut Vec<usize>,
    guard: &dyn WorkGuard,
) -> Result<(), IndexError> {
    let work = RadixWork::for_rows(rows.len());
    if work.passes == 0 {
        return Ok(());
    }
    let mut scratch = Vec::new();
    crate::allocation::try_reserve_vec(
        &mut scratch,
        rows.len(),
        guard,
        "bounded row radix scratch allocation",
    )?;
    scratch.resize(rows.len(), 0);
    for pass in 0..work.passes {
        let mut counts = [0_usize; 256];
        for chunk in rows.chunks(4096) {
            consume_row_work(guard, chunk.len())?;
            for row in chunk.iter().copied() {
                counts[row.to_le_bytes()[pass] as usize] += 1;
            }
        }
        consume_row_work(guard, counts.len())?;
        let mut position = 0_usize;
        for count in &mut counts {
            let current = *count;
            *count = position;
            position += current;
        }
        for chunk in rows.chunks(4096) {
            consume_row_work(guard, chunk.len())?;
            for row in chunk.iter().copied() {
                let slot = &mut counts[row.to_le_bytes()[pass] as usize];
                scratch[*slot] = row;
                *slot += 1;
            }
        }
        std::mem::swap(rows, &mut scratch);
    }
    let mut output = 1_usize;
    let mut index = 1;
    while index < rows.len() {
        let end = (index + 4096).min(rows.len());
        consume_row_work(guard, end - index)?;
        while index < end {
            if rows[index] != rows[output - 1] {
                rows[output] = rows[index];
                output += 1;
            }
            index += 1;
        }
    }
    rows.truncate(output);
    Ok(())
}

pub(super) fn consume_row_work(guard: &dyn WorkGuard, rows: usize) -> Result<(), IndexError> {
    guard
        .consume(WorkDelta {
            rows: u64::try_from(rows).unwrap_or(u64::MAX),
            ..WorkDelta::default()
        })
        .map_err(IndexError::from)
}

pub(super) fn guarded_partition_point<T>(
    values: &[T],
    guard: &dyn WorkGuard,
    predicate: impl FnMut(&T) -> bool,
) -> Result<usize, IndexError> {
    Ok(guarded_partition_point_with_work(values, guard, predicate)?.0)
}

pub(super) fn guarded_partition_point_with_work<T>(
    values: &[T],
    guard: &dyn WorkGuard,
    mut predicate: impl FnMut(&T) -> bool,
) -> Result<(usize, u64), IndexError> {
    let mut left = 0_usize;
    let mut right = values.len();
    let mut work = 0_u64;
    while left < right {
        consume_row_work(guard, 1)?;
        work = work
            .checked_add(1)
            .ok_or_else(|| IndexError::resource("partition work overflow"))?;
        let middle = left + (right - left) / 2;
        if predicate(&values[middle]) {
            left = middle + 1;
        } else {
            right = middle;
        }
    }
    Ok((left, work))
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
            .spans()
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

fn row_for_source<T: HasNormalizedCatalog>(store: &T, key: &EventKey) -> Option<usize> {
    let rows = &store.normalized_catalog().indexes.source_keys;
    let mut left = 0;
    let mut right = rows.len();
    while left < right {
        let middle = left + (right - left) / 2;
        let row = rows[middle].row;
        match compare_event_keys(&store.base_event_key(row).ok()?, key) {
            std::cmp::Ordering::Less => left = middle + 1,
            std::cmp::Ordering::Greater => right = middle,
            std::cmp::Ordering::Equal => return Some(row),
        }
    }
    None
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

#[derive(Debug)]
pub struct OwnedTraceStore {
    base: OwnedStoreView,
    catalog: Box<NormalizedCatalog>,
    content_identity: NormalizedContentIdentity,
    source_format: NormalizedSourceFormat,
}

impl OwnedTraceStore {
    fn new(
        keys: Vec<EventKey>,
        kinds: Vec<EventKind>,
        catalog: NormalizedCatalog,
        source_format: NormalizedSourceFormat,
        guard: &dyn WorkGuard,
    ) -> Result<Self, IndexError> {
        catalog.validate(&keys, &kinds, guard)?;
        let content_identity =
            derive_normalized_content_identity(&catalog, &keys, &kinds, source_format, guard)?;
        Ok(Self {
            base: OwnedStoreView::new(keys, kinds)?,
            catalog: crate::allocation::try_box(catalog, guard, "owned normalized catalog")?,
            content_identity,
            source_format,
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
        row_for_source(self, key)
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
        let catalog = *self.catalog;
        for section in wire::encode(catalog, guard)? {
            guard.consume(WorkDelta::default())?;
            view = view.with_section(section, guard)?;
        }
        Ok(view)
    }
}

#[derive(Debug)]
pub struct MappedTraceStore {
    view: MappedStoreView,
    catalog: Box<NormalizedCatalog>,
    content_identity: NormalizedContentIdentity,
    source_format: NormalizedSourceFormat,
}

impl MappedTraceStore {
    fn open(mut view: MappedStoreView, guard: &dyn WorkGuard) -> Result<Self, IndexError> {
        guard.consume(WorkDelta::default())?;
        let ValidatedCatalog {
            catalog,
            content_identity,
            source_format,
        } = view.take_validated_catalog().ok_or_else(|| {
            IndexError::corrupt("schema-two cache did not transfer its validated catalog")
        })?;
        Ok(Self {
            view,
            catalog,
            content_identity,
            source_format,
        })
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

#[derive(Debug)]
pub enum TraceStore {
    Owned(OwnedTraceStore),
    Mapped(MappedTraceStore),
}

trait HasNormalizedCatalog {
    fn normalized_catalog(&self) -> &NormalizedCatalog;
    fn normalized_content_identity(&self) -> NormalizedContentIdentity;
    fn normalized_source_format(&self) -> NormalizedSourceFormat;
    fn base_event_count(&self) -> usize;
    fn base_event_key(&self, row: usize) -> Result<EventKey, IndexError>;
    fn base_event_kind(&self, row: usize) -> Result<EventKind, IndexError>;
}

impl HasNormalizedCatalog for OwnedTraceStore {
    fn normalized_catalog(&self) -> &NormalizedCatalog {
        &self.catalog
    }
    fn normalized_content_identity(&self) -> NormalizedContentIdentity {
        self.content_identity
    }
    fn normalized_source_format(&self) -> NormalizedSourceFormat {
        self.source_format
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
    fn normalized_content_identity(&self) -> NormalizedContentIdentity {
        self.content_identity
    }
    fn normalized_source_format(&self) -> NormalizedSourceFormat {
        self.source_format
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
    fn normalized_content_identity(&self) -> NormalizedContentIdentity {
        match self {
            Self::Owned(store) => store.content_identity,
            Self::Mapped(store) => store.content_identity,
        }
    }
    fn normalized_source_format(&self) -> NormalizedSourceFormat {
        match self {
            Self::Owned(store) => store.source_format,
            Self::Mapped(store) => store.source_format,
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
    fn thread_ids(&self) -> Result<Vec<u32>, IndexError> {
        Ok(self
            .normalized_catalog()
            .indexes
            .tid
            .iter()
            .map(|(tid, _)| *tid)
            .collect())
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
        row_for_source(self, key)
    }
    fn source_key_for_row(&self, row: usize) -> Result<Option<EventKey>, IndexError> {
        TraceStoreView::event_key(self, row)
    }
}

impl<T: HasNormalizedCatalog> NormalizedBulkView for T {
    fn normalized_layout_identity(&self) -> NormalizedLayoutIdentity {
        NormalizedLayoutIdentity::new(
            self.normalized_catalog().schema,
            NORMALIZED_LAYOUT_FINGERPRINT,
        )
    }

    fn normalized_content_identity(&self) -> NormalizedContentIdentity {
        HasNormalizedCatalog::normalized_content_identity(self)
    }

    fn normalized_source_format(&self) -> NormalizedSourceFormat {
        HasNormalizedCatalog::normalized_source_format(self)
    }

    fn module_rows(&self) -> &[ModuleRow] {
        &self.normalized_catalog().modules
    }
    fn definition_rows(&self) -> &[DefinitionRow] {
        &self.normalized_catalog().definitions
    }
    fn instruction_rows(&self) -> &[InstructionRow] {
        &self.normalized_catalog().instructions
    }
    fn memory_rows(&self) -> &[MemoryRow] {
        &self.normalized_catalog().memories
    }
    fn semantic_rows(&self) -> &[SemanticRow] {
        &self.normalized_catalog().semantics
    }
    fn register_observation_rows(&self) -> &[RegisterObservationRow] {
        &self.normalized_catalog().observations
    }
    fn string_count(&self) -> usize {
        self.normalized_catalog().strings.spans().len()
    }
    fn blob_count(&self) -> usize {
        self.normalized_catalog().blobs.spans().len()
    }

    fn semantic_dictionary_work(
        &self,
        family: SemanticDictionaryFamily,
        term_count: usize,
        guard: &dyn WorkGuard,
    ) -> Result<SemanticDictionaryWork, IndexError> {
        let catalog = self.normalized_catalog();
        let spans = catalog.strings.spans();
        let mut dictionary_bytes = 0_u64;
        for chunk in spans.chunks(4096) {
            consume_row_work(guard, chunk.len())?;
            for span in chunk {
                dictionary_bytes = dictionary_bytes.checked_add(span.length).ok_or_else(|| {
                    IndexError::resource("semantic dictionary byte count overflow")
                })?;
            }
        }
        let posting_lists = match family {
            SemanticDictionaryFamily::Categories => catalog.indexes.semantic_category.entries.len(),
            SemanticDictionaryFamily::Names => catalog.indexes.semantic_name.entries.len(),
        };
        semantic_dictionary_work_from_counts(
            term_count,
            spans.len(),
            dictionary_bytes,
            posting_lists,
        )
    }

    fn bounded_definition_decode_work(
        &self,
        query_terms: usize,
        max_rows: usize,
    ) -> Result<u64, IndexError> {
        map_decode_work_upper(
            query_terms,
            self.normalized_catalog().indexes.definition.entries.len(),
            max_rows,
        )
    }

    fn bounded_row_estimate(
        &self,
        query: NormalizedPostingQuery<'_>,
        max_rows: usize,
        guard: &dyn WorkGuard,
    ) -> Result<NormalizedPostingEstimate, IndexError> {
        let catalog = self.normalized_catalog();
        match query {
            NormalizedPostingQuery::Tids(values) => bounded_map_estimate(
                &catalog.indexes.tid,
                values.iter().copied(),
                max_rows,
                guard,
            ),
            NormalizedPostingQuery::Kinds(values) => bounded_map_estimate(
                &catalog.indexes.kind,
                values
                    .iter()
                    .map(|kind| crate::layout::encode_event_kind(*kind)),
                max_rows,
                guard,
            ),
            NormalizedPostingQuery::Modules(values) => bounded_map_estimate(
                &catalog.indexes.module,
                values.iter().copied(),
                max_rows,
                guard,
            ),
            NormalizedPostingQuery::Sequence {
                start,
                end_exclusive,
            } => bounded_pair_estimate(
                &catalog.indexes.sequence,
                start,
                end_exclusive,
                max_rows,
                guard,
            ),
            NormalizedPostingQuery::ModulePc {
                module,
                start,
                end_exclusive,
            } => bounded_pair_estimate(
                catalog
                    .indexes
                    .module_pc
                    .get(&module)
                    .map_or(&[], Vec::as_slice),
                start,
                end_exclusive,
                max_rows,
                guard,
            ),
            NormalizedPostingQuery::Definitions(values) => bounded_map_estimate(
                &catalog.indexes.definition,
                values.iter().copied(),
                max_rows,
                guard,
            ),
            NormalizedPostingQuery::Registers(values) => bounded_map_estimate(
                &catalog.indexes.register,
                values.iter().map(|slot| slot.index() as u8),
                max_rows,
                guard,
            ),
            NormalizedPostingQuery::SemanticCategories(values) => {
                bounded_semantic_estimate(catalog, values, true, max_rows, guard)
            }
            NormalizedPostingQuery::SemanticNames(values) => {
                bounded_semantic_estimate(catalog, values, false, max_rows, guard)
            }
            NormalizedPostingQuery::Memory {
                start,
                end_exclusive,
            } => catalog.indexes.memory.overlap_estimate_bounded(
                start,
                end_exclusive,
                max_rows,
                guard,
            ),
        }
    }

    fn bounded_row_count(
        &self,
        query: NormalizedPostingQuery<'_>,
        max_rows: usize,
        guard: &dyn WorkGuard,
    ) -> Result<usize, IndexError> {
        Ok(self.bounded_row_estimate(query, max_rows, guard)?.rows)
    }

    fn bounded_rows(
        &self,
        query: NormalizedPostingQuery<'_>,
        max_rows: usize,
        guard: &dyn WorkGuard,
    ) -> Result<Vec<usize>, IndexError> {
        let catalog = self.normalized_catalog();
        match query {
            NormalizedPostingQuery::Tids(values) => bounded_map_rows(
                &catalog.indexes.tid,
                values.iter().copied(),
                max_rows,
                guard,
            ),
            NormalizedPostingQuery::Kinds(values) => bounded_map_rows(
                &catalog.indexes.kind,
                values
                    .iter()
                    .map(|kind| crate::layout::encode_event_kind(*kind)),
                max_rows,
                guard,
            ),
            NormalizedPostingQuery::Modules(values) => bounded_map_rows(
                &catalog.indexes.module,
                values.iter().copied(),
                max_rows,
                guard,
            ),
            NormalizedPostingQuery::Sequence {
                start,
                end_exclusive,
            } => bounded_pair_rows(
                &catalog.indexes.sequence,
                start,
                end_exclusive,
                max_rows,
                guard,
            ),
            NormalizedPostingQuery::ModulePc {
                module,
                start,
                end_exclusive,
            } => bounded_pair_rows(
                catalog
                    .indexes
                    .module_pc
                    .get(&module)
                    .map_or(&[], Vec::as_slice),
                start,
                end_exclusive,
                max_rows,
                guard,
            ),
            NormalizedPostingQuery::Definitions(values) => bounded_map_rows(
                &catalog.indexes.definition,
                values.iter().copied(),
                max_rows,
                guard,
            ),
            NormalizedPostingQuery::Registers(values) => bounded_map_rows(
                &catalog.indexes.register,
                values.iter().map(|slot| slot.index() as u8),
                max_rows,
                guard,
            ),
            NormalizedPostingQuery::SemanticCategories(values) => {
                bounded_semantic_rows(catalog, values, true, max_rows, guard)
            }
            NormalizedPostingQuery::SemanticNames(values) => {
                bounded_semantic_rows(catalog, values, false, max_rows, guard)
            }
            NormalizedPostingQuery::Memory {
                start,
                end_exclusive,
            } => catalog
                .indexes
                .memory
                .overlaps_bounded(start, end_exclusive, max_rows, guard),
        }
    }
}

fn bounded_semantic_estimate(
    catalog: &NormalizedCatalog,
    values: &[&[u8]],
    categories: bool,
    max_rows: usize,
    guard: &dyn WorkGuard,
) -> Result<NormalizedPostingEstimate, IndexError> {
    let map = if categories {
        &catalog.indexes.semantic_category
    } else {
        &catalog.indexes.semantic_name
    };
    let mut count = 0_usize;
    let mut matched_lists = 0_usize;
    let mut query_terms = 0_u64;
    let mut lookup_work = 0_u64;
    let dictionary_work = visit_semantic_dictionary_matches(catalog, values, guard, |id| {
        query_terms = query_terms
            .checked_add(1)
            .ok_or_else(|| IndexError::resource("semantic matched-term work overflow"))?;
        let (list, comparisons) = map.guarded_get(&id, guard)?;
        lookup_work = lookup_work
            .checked_add(comparisons)
            .ok_or_else(|| IndexError::resource("semantic map lookup work overflow"))?;
        if let Some(list) = list {
            matched_lists = matched_lists
                .checked_add(1)
                .ok_or_else(|| IndexError::resource("bounded posting list count overflow"))?;
            count = count
                .checked_add(list.row_count())
                .ok_or_else(|| IndexError::resource("bounded posting row count overflow"))?;
            if count > max_rows {
                return Err(IndexError::resource(
                    "bounded posting result exceeds row limit",
                ));
            }
        }
        Ok(())
    })?;
    let decode_work = dictionary_work
        .checked_add(map_decode_work(
            query_terms,
            lookup_work,
            matched_lists,
            count,
        )?)
        .ok_or_else(|| IndexError::resource("semantic decode work overflow"))?;
    Ok(NormalizedPostingEstimate::new(count, decode_work))
}

fn bounded_semantic_rows(
    catalog: &NormalizedCatalog,
    values: &[&[u8]],
    categories: bool,
    max_rows: usize,
    guard: &dyn WorkGuard,
) -> Result<Vec<usize>, IndexError> {
    let mut ids = Vec::new();
    crate::allocation::try_reserve_vec(&mut ids, values.len(), guard, "bounded semantic IDs")?;
    visit_semantic_dictionary_matches(catalog, values, guard, |id| {
        ids.push(id);
        Ok(())
    })?;
    if categories {
        bounded_map_rows(
            &catalog.indexes.semantic_category,
            ids.into_iter(),
            max_rows,
            guard,
        )
    } else {
        bounded_map_rows(
            &catalog.indexes.semantic_name,
            ids.into_iter(),
            max_rows,
            guard,
        )
    }
}

fn visit_semantic_dictionary_matches(
    catalog: &NormalizedCatalog,
    values: &[&[u8]],
    guard: &dyn WorkGuard,
    mut visit: impl FnMut(u32) -> Result<(), IndexError>,
) -> Result<u64, IndexError> {
    let mut work = 0_u64;
    for value in values {
        for (id, span) in catalog.strings.spans().iter().enumerate() {
            work = work
                .checked_add(consume_dictionary_entry_work(span, guard)?)
                .ok_or_else(|| IndexError::resource("semantic dictionary work overflow"))?;
            if catalog.strings.get(id as u32)? == *value {
                visit(id as u32)?;
                break;
            }
        }
    }
    Ok(work)
}

fn consume_dictionary_entry_work(
    span: &ByteSpan,
    guard: &dyn WorkGuard,
) -> Result<u64, IndexError> {
    consume_row_work(guard, 1)?;
    let mut remaining = span.length;
    while remaining != 0 {
        let bytes = remaining.min(4096);
        guard.consume(WorkDelta {
            input_bytes: bytes,
            ..WorkDelta::default()
        })?;
        remaining -= bytes;
    }
    span.length
        .checked_add(1)
        .ok_or_else(|| IndexError::resource("semantic dictionary entry work overflow"))
}

impl TraceStore {
    pub fn open_or_build(
        cache_root: &std::path::Path,
        source: &ArtifactSource,
        options: &BuildOptions,
        guard: &dyn WorkGuard,
    ) -> Result<Self, IndexError> {
        Self::open_or_build_with_guards(cache_root, source, options, guard, guard)
    }

    pub fn open_or_build_with_guards(
        cache_root: &std::path::Path,
        source: &ArtifactSource,
        options: &BuildOptions,
        source_guard: &dyn WorkGuard,
        cache_guard: &dyn WorkGuard,
    ) -> Result<Self, IndexError> {
        options.validate()?;
        let identity = cache_identity(source, options, cache_guard)?;
        cache_guard.consume(WorkDelta::default())?;
        match CacheReader::open(cache_root, &identity, cache_guard)? {
            CacheOpen::Ready(view) => {
                return Ok(Self::Mapped(MappedTraceStore::open(view, cache_guard)?));
            }
            CacheOpen::Missing | CacheOpen::Rebuild(_) => {}
        }
        source_guard.consume(WorkDelta::default())?;
        let owned = IndexBuilder::build(source, options, source_guard)?;
        cache_guard.consume(WorkDelta::default())?;
        let (outcome, receipt) = CacheWriter::new(
            identity.try_clone_guarded(cache_guard)?,
            owned.into_cache_view_with_catalog(cache_guard)?,
        )?
        .publish_with_receipt(cache_root, cache_guard)?;
        let reopened = (|| {
            cache_guard.consume(WorkDelta::default())?;
            let view = match CacheReader::open(cache_root, &identity, cache_guard)? {
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
            Ok(Self::Mapped(MappedTraceStore::open(view, cache_guard)?))
        })();
        match reopened {
            Ok(store) => Ok(store),
            Err(error) if outcome == crate::PublishOutcome::Published => {
                let receipt = receipt
                    .ok_or_else(|| IndexError::corrupt("published cache receipt is missing"))?;
                CacheWriter::remove_published(receipt).map_err(|cleanup| {
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

fn cache_identity(
    source: &ArtifactSource,
    options: &BuildOptions,
    guard: &dyn WorkGuard,
) -> Result<CacheIdentity, IndexError> {
    let provider = source.identity().provider();
    Ok(CacheIdentity {
        analyzer_version: crate::allocation::try_copy_string(
            env!("CARGO_PKG_VERSION"),
            guard,
            "cache analyzer version",
        )?,
        artifact_digest: *provider.artifact.as_bytes(),
        build_option_digest: options.digest(),
        cache_schema: 2,
        endian: crate::allocation::try_copy_string("little", guard, "cache endian")?,
        layout_version: 3,
        source_features: 0,
        source_format: crate::allocation::try_copy_string(
            &provider.format,
            guard,
            "cache source format",
        )?,
        source_major: u16::from(provider.format_major),
        source_minor: u16::from(provider.format_minor),
    })
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

#[cfg(test)]
mod guard_order_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use qtrace_provider::{OperationAbort, WorkDelta, WorkGuard};

    use super::{guarded_byte_chunks, guarded_row_chunks};

    struct RejectAt {
        call: AtomicUsize,
        reject_at: usize,
    }

    impl WorkGuard for RejectAt {
        fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
            let call = self.call.fetch_add(1, Ordering::SeqCst) + 1;
            if call == self.reject_at {
                Err(OperationAbort::Cancelled)
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn guarded_bytes_authorize_each_chunk_before_hash_work() {
        let mut processed = 0_usize;
        let error = guarded_byte_chunks(
            &[0_u8; 8192],
            &RejectAt {
                call: AtomicUsize::new(0),
                reject_at: 1,
            },
            |chunk| processed += chunk.len(),
        )
        .expect_err("first guard rejects before hashing");
        assert_eq!(error.code(), "job.cancelled");
        assert_eq!(processed, 0);
    }

    #[test]
    fn guarded_rows_cancel_inside_the_real_validation_loop() {
        let rows = vec![0_u8; 10_000];
        let mut processed = 0_usize;
        let error = guarded_row_chunks(
            &rows,
            &RejectAt {
                call: AtomicUsize::new(0),
                reject_at: 2,
            },
            |chunk| {
                processed += chunk.len();
                Ok(())
            },
        )
        .expect_err("second chunk cancelled");
        assert_eq!(error.code(), "job.cancelled");
        assert_eq!(processed, 4096);
    }
}
