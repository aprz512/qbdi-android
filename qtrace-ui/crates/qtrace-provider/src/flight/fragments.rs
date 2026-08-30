use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use crate::{
    EventKey, EventPayload, EventRecord, Provenance, ProviderError, SemanticEvent, WorkDelta,
    WorkGuard,
};

use super::recovery::MERGED_TIMELINE_ID;
use super::{
    recovery::ChunkIdentity,
    wire::{FLIGHT_CHUNK_HEADER_BYTES, Superblock},
};

pub(super) struct Fragment {
    key: EventKey,
    provenance: Provenance,
    kind: u16,
    event_id: u64,
    total: u32,
    index: u16,
    count: u16,
    fixed: Vec<Arc<[u8]>>,
    detail: Arc<[u8]>,
    chunk_index: u32,
    generation: u32,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn decode(
    kind: u16,
    bytes: &[u8],
    strings: &HashMap<u32, Arc<[u8]>>,
    key: EventKey,
    provenance: Provenance,
    chunk_index: u32,
    generation: u32,
) -> Result<Fragment, ()> {
    let field_count = if kind == 6 { 3 } else { 2 };
    if bytes.len() != 16 + field_count * 4 {
        return Err(());
    }
    let event_id = u64::from_le_bytes(bytes[..8].try_into().map_err(|_| ())?);
    let total = u32::from_le_bytes(bytes[8..12].try_into().map_err(|_| ())?);
    let index = u16::from_le_bytes(bytes[12..14].try_into().map_err(|_| ())?);
    let count = u16::from_le_bytes(bytes[14..16].try_into().map_err(|_| ())?);
    if event_id == 0 || total == 0 || count < 2 || index >= count {
        return Err(());
    }
    let mut raw_fields = Vec::with_capacity(field_count);
    for field in 0..field_count {
        let id = u32::from_le_bytes(
            bytes[16 + field * 4..20 + field * 4]
                .try_into()
                .map_err(|_| ())?,
        );
        raw_fields.push(Arc::clone(strings.get(&id).ok_or(())?));
    }
    let detail = raw_fields.pop().ok_or(())?;
    let total_limit = if kind == 6 { 1 << 20 } else { 4096 };
    if raw_fields.first().is_none_or(|field| field.len() > 255)
        || (kind == 6 && raw_fields.get(1).is_none_or(|field| field.len() > 255))
        || detail.is_empty()
        || detail.len() > 3072
        || total as usize > total_limit
        || total as usize <= detail.len()
        || total < u32::from(count)
        || (total as usize)
            < detail
                .len()
                .saturating_add(count as usize)
                .saturating_sub(1)
    {
        return Err(());
    }
    Ok(Fragment {
        key,
        provenance,
        kind,
        event_id,
        total,
        index,
        count,
        fixed: raw_fields,
        detail,
        chunk_index,
        generation,
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn finish(
    fragments: Vec<Fragment>,
    artifact: crate::ArtifactDigest,
    output: &mut Vec<EventRecord>,
    damaged: &mut Vec<u64>,
    damaged_offsets: &mut Vec<u64>,
    superblock: &Superblock,
    chunks: &[Option<ChunkIdentity>],
    guard: &dyn WorkGuard,
) -> Result<(), ProviderError> {
    let mut groups: BTreeMap<(u32, u64, u16), Vec<Fragment>> = BTreeMap::new();
    for (index, fragment) in fragments.into_iter().enumerate() {
        if index as u64 % crate::MAX_UNGUARDED_RECORDS == 0 {
            guard.consume(WorkDelta::default())?;
        }
        groups
            .entry((
                fragment.key.tid.unwrap_or(0),
                fragment.event_id,
                fragment.kind,
            ))
            .or_default()
            .push(fragment);
    }
    for (group_index, ((tid, _, kind), values)) in groups.into_iter().enumerate() {
        checkpoint(guard, group_index)?;
        let Some(first) = values.first() else {
            continue;
        };
        let expected_total = first.total;
        let expected_count = first.count;
        let expected_fixed = first.fixed.clone();
        let mut evidence = Vec::new();
        if evidence.try_reserve_exact(values.len()).is_err() {
            return Err(fragment_allocation_error());
        }
        for (index, item) in values.iter().enumerate() {
            checkpoint(guard, index)?;
            evidence.push((item.key.sequence, item.key.source_offset));
        }
        let mut ordered = Vec::new();
        if ordered.try_reserve_exact(expected_count as usize).is_err() {
            mark_damaged(&evidence, damaged, damaged_offsets, guard)?;
            continue;
        }
        for index in 0..expected_count as usize {
            if index as u64 % crate::MAX_UNGUARDED_RECORDS == 0 {
                guard.consume(WorkDelta::default())?;
            }
            ordered.push(None);
        }
        let mut stable = values.len() == expected_count as usize;
        for (index, item) in values.into_iter().enumerate() {
            if index as u64 % crate::MAX_UNGUARDED_RECORDS == 0 {
                guard.consume(WorkDelta::default())?;
            }
            stable &= item.total == expected_total
                && item.count == expected_count
                && item.fixed == expected_fixed
                && contributor_matches(&item, tid, superblock, chunks);
            match ordered.get_mut(item.index as usize) {
                Some(slot) if slot.is_none() => *slot = Some(item),
                _ => stable = false,
            }
        }
        let mut values = Vec::new();
        if values.try_reserve_exact(expected_count as usize).is_err() {
            mark_damaged(&evidence, damaged, damaged_offsets, guard)?;
            continue;
        }
        for (index, item) in ordered.into_iter().enumerate() {
            if index as u64 % crate::MAX_UNGUARDED_RECORDS == 0 {
                guard.consume(WorkDelta::default())?;
            }
            match item {
                Some(item) => values.push(item),
                None => stable = false,
            }
        }
        let mut previous_sequence: Option<u64> = None;
        for (index, item) in values.iter().enumerate() {
            checkpoint(guard, index)?;
            let current = item.key.sequence.unwrap_or(0);
            if previous_sequence.is_some_and(|previous| current <= previous) {
                stable = false;
            }
            previous_sequence = Some(current);
        }
        if !stable {
            mark_damaged(&evidence, damaged, damaged_offsets, guard)?;
            continue;
        }
        let Some(first) = values.first() else {
            mark_damaged(&evidence, damaged, damaged_offsets, guard)?;
            continue;
        };
        let mut fixed = Vec::new();
        if fixed.try_reserve_exact(first.fixed.len()).is_err() {
            return Err(fragment_allocation_error());
        }
        let mut fixed_valid = true;
        for raw in &first.fixed {
            match std::str::from_utf8(raw) {
                Ok(value) => fixed.push(value.to_owned()),
                Err(_) => {
                    mark_damaged(&evidence, damaged, damaged_offsets, guard)?;
                    fixed_valid = false;
                    break;
                }
            }
        }
        if !fixed_valid {
            continue;
        }
        let mut detail = Vec::new();
        if detail.try_reserve_exact(first.total as usize).is_err() {
            mark_damaged(&evidence, damaged, damaged_offsets, guard)?;
            continue;
        }
        for (index, value) in values.iter().enumerate() {
            checkpoint(guard, index)?;
            let Some(next_len) = detail.len().checked_add(value.detail.len()) else {
                mark_damaged(&evidence, damaged, damaged_offsets, guard)?;
                stable = false;
                break;
            };
            if next_len > first.total as usize {
                mark_damaged(&evidence, damaged, damaged_offsets, guard)?;
                stable = false;
                break;
            }
            detail.extend_from_slice(&value.detail);
        }
        if !stable {
            continue;
        }
        if detail.len() != first.total as usize {
            mark_damaged(&evidence, damaged, damaged_offsets, guard)?;
            continue;
        }
        let detail = match String::from_utf8(detail) {
            Ok(value) => value,
            Err(_) => {
                mark_damaged(&evidence, damaged, damaged_offsets, guard)?;
                continue;
            }
        };
        let mut fragment_sequences = Vec::new();
        let mut offsets = Vec::new();
        if fragment_sequences.try_reserve_exact(values.len()).is_err()
            || offsets.try_reserve_exact(values.len()).is_err()
        {
            return Err(fragment_allocation_error());
        }
        let mut sequence = 0;
        let mut all_captured = true;
        let mut first_ordinal = first.key.record_ordinal;
        let mut first_offset = first.key.source_offset;
        for (index, item) in values.iter().enumerate() {
            checkpoint(guard, index)?;
            if let Some(item_sequence) = item.key.sequence {
                fragment_sequences.push(item_sequence);
                sequence = sequence.max(item_sequence);
            }
            all_captured &= item.provenance == Provenance::Captured;
            if item.key.source_offset < first_offset {
                first_offset = item.key.source_offset;
                first_ordinal = item.key.record_ordinal;
            }
            offsets.push(item.key.source_offset);
        }
        let semantic = SemanticEvent {
            category: (kind == 6).then(|| fixed[0].clone()),
            name: fixed[if kind == 6 { 1 } else { 0 }].clone(),
            detail,
            fragment_sequences,
        };
        let payload = match kind {
            6 => EventPayload::SemanticCall(semantic),
            7 => EventPayload::SemanticRule(semantic),
            _ => EventPayload::SemanticError(semantic),
        };
        let provenance = if all_captured {
            Provenance::Captured
        } else {
            Provenance::Derived
        };
        let offsets = super::events::guarded_sort_u64(offsets, guard)?;
        let key = EventKey::new(
            artifact,
            MERGED_TIMELINE_ID,
            first_ordinal,
            first_offset,
            Some(sequence),
            Some(tid),
        );
        if let Some(event) =
            EventRecord::with_fragment_source_offsets(key, provenance, payload, offsets)
        {
            output.push(event);
        }
    }
    Ok(())
}

fn contributor_matches(
    item: &Fragment,
    tid: u32,
    superblock: &Superblock,
    chunks: &[Option<ChunkIdentity>],
) -> bool {
    let Some(identity) = usize::try_from(item.chunk_index)
        .ok()
        .and_then(|index| chunks.get(index))
        .and_then(Option::as_ref)
    else {
        return false;
    };
    let Some(chunk_start) = u64::from(item.chunk_index)
        .checked_mul(u64::from(superblock.chunk_bytes))
        .and_then(|relative| superblock.chunks.offset.checked_add(relative))
    else {
        return false;
    };
    let Some(data_start) = chunk_start.checked_add(FLIGHT_CHUNK_HEADER_BYTES as u64) else {
        return false;
    };
    let Some(chunk_end) = chunk_start.checked_add(u64::from(superblock.chunk_bytes)) else {
        return false;
    };
    identity.tid == tid
        && identity.generation == item.generation
        && item.key.tid == Some(tid)
        && item.key.source_offset >= data_start
        && item.key.source_offset < chunk_end
}

fn mark_damaged(
    evidence: &[(Option<u64>, u64)],
    damaged: &mut Vec<u64>,
    damaged_offsets: &mut Vec<u64>,
    guard: &dyn WorkGuard,
) -> Result<(), ProviderError> {
    for (index, (sequence, offset)) in evidence.iter().copied().enumerate() {
        checkpoint(guard, index)?;
        if let Some(sequence) = sequence {
            damaged.push(sequence);
        }
        damaged_offsets.push(offset);
    }
    Ok(())
}

fn checkpoint(guard: &dyn WorkGuard, index: usize) -> Result<(), ProviderError> {
    if index as u64 % crate::MAX_UNGUARDED_RECORDS == 0 {
        guard.consume(WorkDelta::default())?;
    }
    Ok(())
}

fn fragment_allocation_error() -> ProviderError {
    ProviderError::new(
        "source.flight.allocation",
        "flight.fragment",
        None,
        false,
        "Flight fragment allocation failed",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ArtifactDigest, OperationAbort, TimelineId};

    struct AllowAll;

    impl WorkGuard for AllowAll {
        fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
            Ok(())
        }
    }

    fn test_superblock() -> Superblock {
        Superblock {
            pointer_width: 8,
            run_id: 1,
            pid: 1,
            module_generation: 1,
            target: [0; 128],
            target_len: 0,
            artifact_bytes: 16_384,
            directory: super::super::wire::Region {
                offset: 4096,
                end: 4160,
            },
            directory_entries: 1,
            chunks: super::super::wire::Region {
                offset: 8192,
                end: 12_288,
            },
            chunk_bytes: 2048,
            chunk_count: 2,
            emergencies: super::super::wire::Region {
                offset: 4160,
                end: 4288,
            },
            emergency_count: 1,
            flags: 0,
        }
    }

    fn fragment(index: u16, chunk_index: u32, generation: u32, offset: u64) -> Fragment {
        Fragment {
            key: EventKey::new(
                ArtifactDigest::new([7; 32]),
                TimelineId(0),
                u64::from(index),
                offset,
                Some(u64::from(index) + 1),
                Some(77),
            ),
            provenance: Provenance::Captured,
            kind: 7,
            event_id: 9,
            total: 2,
            index,
            count: 2,
            fixed: vec![Arc::from(&b"rule"[..])],
            detail: Arc::from(&[b'a' + index as u8][..]),
            chunk_index,
            generation,
        }
    }

    #[test]
    fn repeated_fragment_references_share_string_storage() {
        let shared: Arc<[u8]> = Arc::from(vec![b'x'; 3072]);
        let mut strings = HashMap::new();
        strings.insert(1, Arc::from(&b"jni"[..]));
        strings.insert(2, Arc::from(&b"Lookup"[..]));
        strings.insert(3, Arc::clone(&shared));
        let mut payload = Vec::new();
        payload.extend_from_slice(&9_u64.to_le_bytes());
        payload.extend_from_slice(&6144_u32.to_le_bytes());
        payload.extend_from_slice(&0_u16.to_le_bytes());
        payload.extend_from_slice(&2_u16.to_le_bytes());
        payload.extend_from_slice(&1_u32.to_le_bytes());
        payload.extend_from_slice(&2_u32.to_le_bytes());
        payload.extend_from_slice(&3_u32.to_le_bytes());
        let key = EventKey::new(
            ArtifactDigest::new([7; 32]),
            TimelineId(0),
            0,
            4096,
            Some(1),
            Some(77),
        );

        let first = decode(
            6,
            &payload,
            &strings,
            key.clone(),
            Provenance::Captured,
            0,
            1,
        )
        .expect("first fragment");
        payload[12..14].copy_from_slice(&1_u16.to_le_bytes());
        let second = decode(6, &payload, &strings, key, Provenance::Captured, 0, 1)
            .expect("second fragment");

        assert!(Arc::ptr_eq(&first.detail, &shared));
        assert!(Arc::ptr_eq(&second.detail, &shared));
    }

    #[test]
    fn cross_chunk_group_requires_each_contributors_real_span_and_generation() {
        let superblock = test_superblock();
        let chunks = [
            Some(ChunkIdentity {
                tid: 77,
                generation: 3,
                state: 2,
            }),
            Some(ChunkIdentity {
                tid: 77,
                generation: 4,
                state: 2,
            }),
        ];
        let valid = vec![fragment(0, 0, 3, 8192 + 64), fragment(1, 1, 4, 10_240 + 64)];
        let mut output = Vec::new();
        finish(
            valid,
            ArtifactDigest::new([7; 32]),
            &mut output,
            &mut Vec::new(),
            &mut Vec::new(),
            &superblock,
            &chunks,
            &AllowAll,
        )
        .expect("valid cross-chunk group");
        assert!(matches!(output[0].payload, EventPayload::SemanticRule(_)));

        for forged in [fragment(1, 1, 3, 10_240 + 64), fragment(1, 1, 4, 8192 + 64)] {
            let mut output = Vec::new();
            let mut damaged = Vec::new();
            let mut offsets = Vec::new();
            finish(
                vec![fragment(0, 0, 3, 8192 + 64), forged],
                ArtifactDigest::new([7; 32]),
                &mut output,
                &mut damaged,
                &mut offsets,
                &superblock,
                &chunks,
                &AllowAll,
            )
            .expect("reject forged contributor as damage");
            assert!(output.is_empty());
            assert_eq!(damaged, [1, 2]);
            assert_eq!(offsets.len(), 2);
        }
    }
}
