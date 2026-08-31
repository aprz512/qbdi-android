use qtrace_provider::{ArtifactDigest, EventKey, EventKind, TimelineId};

use crate::cache::{CacheError, RebuildReason};

pub(crate) const HEADER_BYTES: usize = 64;
pub(crate) const CACHE_MAGIC: &[u8; 8] = b"QTCACHE\0";
pub(crate) const EVENT_KEY_BYTES: usize = 80;
pub(crate) const EVENT_KEYS_SECTION: &str = "event_keys.v1";
pub(crate) const EVENT_KINDS_SECTION: &str = "event_kinds.v1";

pub(crate) fn known_section_contract(name: &str) -> Option<(u32, u32)> {
    match name {
        EVENT_KINDS_SECTION => Some((1, 1)),
        EVENT_KEYS_SECTION => Some((8, EVENT_KEY_BYTES as u32)),
        _ => crate::index::binary_section_contract(name),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CacheHeader {
    pub schema: u32,
    pub manifest_offset: u64,
    pub manifest_length: u64,
    pub manifest_checksum: [u8; 32],
}

impl CacheHeader {
    pub(crate) fn encode(&self) -> [u8; HEADER_BYTES] {
        let mut output = [0_u8; HEADER_BYTES];
        output[0..8].copy_from_slice(CACHE_MAGIC);
        output[8..12].copy_from_slice(&self.schema.to_le_bytes());
        output[12..14].copy_from_slice(&(HEADER_BYTES as u16).to_le_bytes());
        output[16..24].copy_from_slice(&self.manifest_offset.to_le_bytes());
        output[24..32].copy_from_slice(&self.manifest_length.to_le_bytes());
        output[32..64].copy_from_slice(&self.manifest_checksum);
        output
    }

    pub(crate) fn decode(input: &[u8; HEADER_BYTES]) -> Result<Self, RebuildReason> {
        if &input[0..8] != CACHE_MAGIC {
            return Err(RebuildReason::Header("magic"));
        }
        let schema = u32::from_le_bytes(copy_array(&input[8..12])?);
        let size = u16::from_le_bytes(copy_array(&input[12..14])?);
        if usize::from(size) != HEADER_BYTES {
            return Err(RebuildReason::Header("size"));
        }
        if input[14..16] != [0, 0] {
            return Err(RebuildReason::Header("reserved"));
        }
        Ok(Self {
            schema,
            manifest_offset: u64::from_le_bytes(copy_array(&input[16..24])?),
            manifest_length: u64::from_le_bytes(copy_array(&input[24..32])?),
            manifest_checksum: copy_array(&input[32..64])?,
        })
    }
}

pub(crate) fn encode_event_key(key: &EventKey, output: &mut [u8; EVENT_KEY_BYTES]) {
    output.fill(0);
    output[0..32].copy_from_slice(key.artifact.as_bytes());
    output[32..40].copy_from_slice(&key.timeline.0.to_le_bytes());
    output[40..48].copy_from_slice(&key.record_ordinal.to_le_bytes());
    output[48..56].copy_from_slice(&key.source_offset.to_le_bytes());
    if let Some(sequence) = key.sequence {
        output[56..64].copy_from_slice(&sequence.to_le_bytes());
        output[68] |= 1;
    }
    if let Some(tid) = key.tid {
        output[64..68].copy_from_slice(&tid.to_le_bytes());
        output[68] |= 2;
    }
}

pub(crate) fn decode_event_key(input: &[u8; EVENT_KEY_BYTES]) -> Result<EventKey, CacheError> {
    if input[69..].iter().any(|byte| *byte != 0) || input[68] & !3 != 0 {
        return Err(CacheError::access("event key has non-zero reserved bytes"));
    }
    let artifact = ArtifactDigest::new(copy_array(&input[0..32]).map_err(CacheError::from)?);
    let timeline = TimelineId(u64::from_le_bytes(
        copy_array(&input[32..40]).map_err(CacheError::from)?,
    ));
    let record_ordinal = u64::from_le_bytes(copy_array(&input[40..48]).map_err(CacheError::from)?);
    let source_offset = u64::from_le_bytes(copy_array(&input[48..56]).map_err(CacheError::from)?);
    let sequence_value = u64::from_le_bytes(copy_array(&input[56..64]).map_err(CacheError::from)?);
    let tid_value = u32::from_le_bytes(copy_array(&input[64..68]).map_err(CacheError::from)?);
    if (input[68] & 1 == 0 && sequence_value != 0) || (input[68] & 2 == 0 && tid_value != 0) {
        return Err(CacheError::access(
            "absent optional event-key fields must have zero wire values",
        ));
    }
    Ok(EventKey::new(
        artifact,
        timeline,
        record_ordinal,
        source_offset,
        (input[68] & 1 != 0).then_some(sequence_value),
        (input[68] & 2 != 0).then_some(tid_value),
    ))
}

pub(crate) const fn encode_event_kind(kind: EventKind) -> u8 {
    match kind {
        EventKind::Begin => 0,
        EventKind::ModuleDefinition => 1,
        EventKind::InstructionDefinition => 2,
        EventKind::Instruction => 3,
        EventKind::Memory => 4,
        EventKind::SemanticCall => 5,
        EventKind::SemanticRule => 6,
        EventKind::SemanticError => 7,
        EventKind::ThreadLifecycle => 8,
        EventKind::Syscall => 9,
        EventKind::Signal => 10,
        EventKind::SignalHandlerBoundary => 11,
        EventKind::Termination => 12,
        EventKind::RegisterCheckpoint => 13,
        EventKind::RegisterDelta => 14,
        EventKind::StringDefinition => 15,
        EventKind::CoverageGap => 16,
        EventKind::Discontinuity => 17,
        EventKind::OpaqueOptional => 18,
    }
}

pub(crate) fn decode_event_kind(value: u8) -> Result<EventKind, CacheError> {
    match value {
        0 => Ok(EventKind::Begin),
        1 => Ok(EventKind::ModuleDefinition),
        2 => Ok(EventKind::InstructionDefinition),
        3 => Ok(EventKind::Instruction),
        4 => Ok(EventKind::Memory),
        5 => Ok(EventKind::SemanticCall),
        6 => Ok(EventKind::SemanticRule),
        7 => Ok(EventKind::SemanticError),
        8 => Ok(EventKind::ThreadLifecycle),
        9 => Ok(EventKind::Syscall),
        10 => Ok(EventKind::Signal),
        11 => Ok(EventKind::SignalHandlerBoundary),
        12 => Ok(EventKind::Termination),
        13 => Ok(EventKind::RegisterCheckpoint),
        14 => Ok(EventKind::RegisterDelta),
        15 => Ok(EventKind::StringDefinition),
        16 => Ok(EventKind::CoverageGap),
        17 => Ok(EventKind::Discontinuity),
        18 => Ok(EventKind::OpaqueOptional),
        _ => Err(CacheError::access(
            "event kind is outside the wire contract",
        )),
    }
}

fn copy_array<const N: usize>(input: &[u8]) -> Result<[u8; N], RebuildReason> {
    input
        .try_into()
        .map_err(|_| RebuildReason::Header("truncated numeric field"))
}
