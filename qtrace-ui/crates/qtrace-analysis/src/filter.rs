use qtrace_provider::{EventKind, MemoryDirection, RegisterSlot};
use sha2::{Digest, Sha256};

use crate::AnalysisError;

const MAX_FILTER_TERMS: usize = 512;
const MAX_FILTER_CARTESIAN_PAIRS: usize = 4_096;
pub(crate) const MAX_FILTER_TEXT_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SequenceRange {
    pub first: u64,
    pub last: u64,
}

impl SequenceRange {
    pub fn new(first: u64, last: u64) -> Result<Self, AnalysisError> {
        if first > last {
            return Err(AnalysisError::invalid_filter(
                "sequence range must be inclusive and ordered",
            ));
        }
        Ok(Self { first, last })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AddressRange {
    pub start: u64,
    pub end_exclusive: u64,
}

impl AddressRange {
    pub fn new(start: u64, end_exclusive: u64) -> Result<Self, AnalysisError> {
        if start >= end_exclusive {
            return Err(AnalysisError::invalid_filter(
                "address range must be non-empty and half-open",
            ));
        }
        Ok(Self {
            start,
            end_exclusive,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MnemonicFilter {
    Exact(String),
    Contains(String),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RegisterFilter {
    pub reads: Vec<RegisterSlot>,
    pub writes: Vec<RegisterSlot>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryFilter {
    pub range: AddressRange,
    pub directions: Vec<MemoryDirection>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EventFilter {
    pub tids: Vec<u32>,
    pub kinds: Vec<EventKind>,
    pub modules: Vec<u32>,
    pub relative_pc: Vec<AddressRange>,
    pub absolute_pc: Vec<AddressRange>,
    pub sequence: Vec<SequenceRange>,
    pub mnemonic: Vec<MnemonicFilter>,
    pub register: RegisterFilter,
    pub memory: Vec<MemoryFilter>,
    pub semantic_categories: Vec<String>,
    pub semantic_names: Vec<String>,
    pub semantic_detail_contains: Vec<String>,
}

impl EventFilter {
    pub(crate) fn normalized(&self) -> Result<Self, AnalysisError> {
        if raw_term_count(self) > MAX_FILTER_TERMS {
            return Err(AnalysisError::filter_too_complex(
                "filter exceeds 512 terms",
            ));
        }
        if raw_text_bytes(self).is_none_or(|bytes| bytes > MAX_FILTER_TEXT_BYTES) {
            return Err(AnalysisError::filter_too_complex(
                "filter text exceeds 1 MiB",
            ));
        }
        let mut filter = self.clone();
        filter.tids.sort_unstable();
        filter.tids.dedup();
        filter.kinds.sort_by_key(|kind| kind_tag(*kind));
        filter.kinds.dedup();
        filter.modules.sort_unstable();
        filter.modules.dedup();
        normalize_address_ranges(&mut filter.relative_pc)?;
        normalize_address_ranges(&mut filter.absolute_pc)?;
        if filter.sequence.iter().any(|range| range.first > range.last) {
            return Err(AnalysisError::invalid_filter("invalid sequence range"));
        }
        normalize_sequence_ranges(&mut filter.sequence);
        for matcher in &mut filter.mnemonic {
            let value = match matcher {
                MnemonicFilter::Exact(value) | MnemonicFilter::Contains(value) => value,
            };
            *value = value.trim().to_ascii_lowercase();
            if value.is_empty() {
                return Err(AnalysisError::invalid_filter(
                    "mnemonic matcher must not be empty",
                ));
            }
        }
        filter.mnemonic.sort_by(|left, right| {
            mnemonic_key(left)
                .0
                .cmp(&mnemonic_key(right).0)
                .then_with(|| mnemonic_key(left).1.cmp(mnemonic_key(right).1))
        });
        filter.mnemonic.dedup();
        normalize_slots(&mut filter.register.reads);
        normalize_slots(&mut filter.register.writes);
        for memory in &mut filter.memory {
            if memory.range.start >= memory.range.end_exclusive {
                return Err(AnalysisError::invalid_filter("invalid memory range"));
            }
            memory
                .directions
                .sort_by_key(|direction| direction_tag(*direction));
            memory.directions.dedup();
        }
        filter.memory.sort_by(|left, right| {
            (left.range.start, left.range.end_exclusive)
                .cmp(&(right.range.start, right.range.end_exclusive))
                .then_with(|| {
                    left.directions
                        .iter()
                        .map(|direction| direction_tag(*direction))
                        .cmp(
                            right
                                .directions
                                .iter()
                                .map(|direction| direction_tag(*direction)),
                        )
                })
        });
        normalize_memory_ranges(&mut filter.memory);
        normalize_text(&mut filter.semantic_categories, "semantic category")?;
        normalize_text(&mut filter.semantic_names, "semantic name")?;
        normalize_text(
            &mut filter.semantic_detail_contains,
            "semantic detail matcher",
        )?;
        let terms = filter.tids.len()
            + filter.kinds.len()
            + filter.modules.len()
            + filter.relative_pc.len()
            + filter.absolute_pc.len()
            + filter.sequence.len()
            + filter.mnemonic.len()
            + filter.register.reads.len()
            + filter.register.writes.len()
            + filter.memory.len()
            + filter.semantic_categories.len()
            + filter.semantic_names.len()
            + filter.semantic_detail_contains.len();
        if terms > MAX_FILTER_TERMS {
            return Err(AnalysisError::filter_too_complex(
                "normalized filter exceeds 512 terms",
            ));
        }
        if filter.modules.len().saturating_mul(
            filter
                .relative_pc
                .len()
                .saturating_add(filter.absolute_pc.len()),
        ) > MAX_FILTER_CARTESIAN_PAIRS
        {
            return Err(AnalysisError::filter_too_complex(
                "module/range expansion exceeds 4096 pairs",
            ));
        }
        Ok(filter)
    }

    pub(crate) fn digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"qtrace-filter-v1");
        hash_u32s(&mut hash, &self.tids);
        hash_values(&mut hash, self.kinds.iter().map(|kind| kind_tag(*kind)));
        hash_u32s(&mut hash, &self.modules);
        hash_address_ranges(&mut hash, &self.relative_pc);
        hash_address_ranges(&mut hash, &self.absolute_pc);
        hash.update((self.sequence.len() as u64).to_le_bytes());
        for range in &self.sequence {
            hash.update(range.first.to_le_bytes());
            hash.update(range.last.to_le_bytes());
        }
        hash.update((self.mnemonic.len() as u64).to_le_bytes());
        for matcher in &self.mnemonic {
            let (tag, value) = mnemonic_key(matcher);
            hash.update([tag]);
            hash_bytes(&mut hash, value.as_bytes());
        }
        hash_values(
            &mut hash,
            self.register.reads.iter().map(|slot| slot.index() as u8),
        );
        hash_values(
            &mut hash,
            self.register.writes.iter().map(|slot| slot.index() as u8),
        );
        hash.update((self.memory.len() as u64).to_le_bytes());
        for memory in &self.memory {
            hash.update(memory.range.start.to_le_bytes());
            hash.update(memory.range.end_exclusive.to_le_bytes());
            hash_values(
                &mut hash,
                memory
                    .directions
                    .iter()
                    .map(|direction| direction_tag(*direction)),
            );
        }
        hash_strings(&mut hash, &self.semantic_categories);
        hash_strings(&mut hash, &self.semantic_names);
        hash_strings(&mut hash, &self.semantic_detail_contains);
        hash.finalize().into()
    }

    pub(crate) fn has_semantic_detail_residual(&self) -> bool {
        !self.semantic_detail_contains.is_empty()
    }
}

fn normalize_address_ranges(ranges: &mut Vec<AddressRange>) -> Result<(), AnalysisError> {
    if ranges
        .iter()
        .any(|range| range.start >= range.end_exclusive)
    {
        return Err(AnalysisError::invalid_filter("invalid address range"));
    }
    ranges.sort_by_key(|range| (range.start, range.end_exclusive));
    let mut merged: Vec<AddressRange> = Vec::with_capacity(ranges.len());
    for range in ranges.drain(..) {
        if let Some(previous) = merged.last_mut()
            && range.start <= previous.end_exclusive
        {
            previous.end_exclusive = previous.end_exclusive.max(range.end_exclusive);
            continue;
        }
        merged.push(range);
    }
    *ranges = merged;
    Ok(())
}

fn normalize_sequence_ranges(ranges: &mut Vec<SequenceRange>) {
    ranges.sort_by_key(|range| (range.first, range.last));
    let mut merged: Vec<SequenceRange> = Vec::with_capacity(ranges.len());
    for range in ranges.drain(..) {
        if let Some(previous) = merged.last_mut()
            && range.first <= previous.last.saturating_add(1)
        {
            previous.last = previous.last.max(range.last);
            continue;
        }
        merged.push(range);
    }
    *ranges = merged;
}

fn normalize_memory_ranges(ranges: &mut Vec<MemoryFilter>) {
    let mut boundaries = ranges
        .iter()
        .flat_map(|range| [range.range.start, range.range.end_exclusive])
        .collect::<Vec<_>>();
    boundaries.sort_unstable();
    boundaries.dedup();
    let mut canonical: Vec<MemoryFilter> = Vec::new();
    for bounds in boundaries.windows(2) {
        let start = bounds[0];
        let end_exclusive = bounds[1];
        let active = ranges.iter().filter(|range| {
            range.range.start <= start && end_exclusive <= range.range.end_exclusive
        });
        let mut any = false;
        let mut wildcard = false;
        let mut directions = Vec::new();
        for range in active {
            any = true;
            if range.directions.is_empty() {
                wildcard = true;
            } else {
                directions.extend(range.directions.iter().copied());
            }
        }
        if !any {
            continue;
        }
        directions.sort_by_key(|direction| direction_tag(*direction));
        directions.dedup();
        if directions.contains(&MemoryDirection::Read)
            || directions.contains(&MemoryDirection::Write)
        {
            directions.retain(|direction| *direction != MemoryDirection::ReadWrite);
        }
        if wildcard {
            directions.clear();
        }
        if let Some(previous) = canonical.last_mut()
            && previous.range.end_exclusive == start
            && previous.directions == directions
        {
            previous.range.end_exclusive = end_exclusive;
        } else {
            canonical.push(MemoryFilter {
                range: AddressRange {
                    start,
                    end_exclusive,
                },
                directions,
            });
        }
    }
    *ranges = canonical;
}

fn raw_term_count(filter: &EventFilter) -> usize {
    filter.tids.len()
        + filter.kinds.len()
        + filter.modules.len()
        + filter.relative_pc.len()
        + filter.absolute_pc.len()
        + filter.sequence.len()
        + filter.mnemonic.len()
        + filter.register.reads.len()
        + filter.register.writes.len()
        + filter.memory.len()
        + filter.semantic_categories.len()
        + filter.semantic_names.len()
        + filter.semantic_detail_contains.len()
}

fn raw_text_bytes(filter: &EventFilter) -> Option<usize> {
    filter
        .mnemonic
        .iter()
        .map(|matcher| match matcher {
            MnemonicFilter::Exact(value) | MnemonicFilter::Contains(value) => value.len(),
        })
        .chain(filter.semantic_categories.iter().map(String::len))
        .chain(filter.semantic_names.iter().map(String::len))
        .chain(filter.semantic_detail_contains.iter().map(String::len))
        .try_fold(0_usize, usize::checked_add)
}

fn normalize_slots(slots: &mut Vec<RegisterSlot>) {
    slots.sort_by_key(|slot| slot.index());
    slots.dedup();
}

fn normalize_text(values: &mut Vec<String>, label: &str) -> Result<(), AnalysisError> {
    for value in values.iter_mut() {
        *value = value.trim().to_owned();
        if value.is_empty() {
            return Err(AnalysisError::invalid_filter(format!(
                "{label} must not be empty"
            )));
        }
    }
    values.sort();
    values.dedup();
    Ok(())
}

fn mnemonic_key(value: &MnemonicFilter) -> (u8, &str) {
    match value {
        MnemonicFilter::Exact(value) => (0, value),
        MnemonicFilter::Contains(value) => (1, value),
    }
}

fn kind_tag(kind: EventKind) -> u8 {
    EventKind::ALL
        .iter()
        .position(|candidate| *candidate == kind)
        .expect("EventKind::ALL is exhaustive") as u8
}

fn direction_tag(direction: MemoryDirection) -> u8 {
    match direction {
        MemoryDirection::Read => 0,
        MemoryDirection::Write => 1,
        MemoryDirection::ReadWrite => 2,
        MemoryDirection::Unknown => 3,
    }
}

fn hash_values(hash: &mut Sha256, values: impl ExactSizeIterator<Item = u8>) {
    hash.update((values.len() as u64).to_le_bytes());
    for value in values {
        hash.update([value]);
    }
}

fn hash_u32s(hash: &mut Sha256, values: &[u32]) {
    hash.update((values.len() as u64).to_le_bytes());
    for value in values {
        hash.update(value.to_le_bytes());
    }
}

fn hash_address_ranges(hash: &mut Sha256, ranges: &[AddressRange]) {
    hash.update((ranges.len() as u64).to_le_bytes());
    for range in ranges {
        hash.update(range.start.to_le_bytes());
        hash.update(range.end_exclusive.to_le_bytes());
    }
}

fn hash_strings(hash: &mut Sha256, values: &[String]) {
    hash.update((values.len() as u64).to_le_bytes());
    for value in values {
        hash_bytes(hash, value.as_bytes());
    }
}

fn hash_bytes(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_le_bytes());
    hash.update(value);
}
