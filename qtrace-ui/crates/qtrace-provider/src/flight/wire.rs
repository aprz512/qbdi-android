use std::str;

use crate::{ProviderError, SourceCoordinate};

pub const FLIGHT_SUPERBLOCK_BYTES: usize = 4096;
pub const FLIGHT_DIRECTORY_ENTRY_BYTES: usize = 64;
pub const FLIGHT_CHUNK_HEADER_BYTES: usize = 64;
pub const FLIGHT_RECORD_HEADER_BYTES: usize = 24;
pub const FLIGHT_EMERGENCY_RECORD_BYTES: usize = 64;
pub const FLIGHT_EMERGENCY_SLOT_BYTES: usize = 128;

pub(super) const MAGIC: u32 = 0x5146_4c54;
pub(super) const VERSION: u16 = 2;
pub(super) const RECORD_COMMIT: u32 = 0x5143_4d54;
pub(super) const EMERGENCY_COMMITTED: u32 = 0x8000_0000;
pub(super) const INVALID_INDEX: u32 = u32::MAX;
pub(super) const KNOWN_INCOMPLETE_FLAGS: u32 = 0x0f;
const TARGET_NAME_BYTES: usize = 128;
const TARGET_NAME_OFFSET: usize = 98;

#[derive(Clone, Copy, Debug)]
pub(super) struct Region {
    pub(super) offset: u64,
    pub(super) end: u64,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Superblock {
    pub(super) pointer_width: u8,
    pub(super) run_id: u64,
    pub(super) pid: u32,
    pub(super) module_generation: u32,
    pub(super) target: [u8; TARGET_NAME_BYTES],
    pub(super) target_len: u16,
    pub(super) artifact_bytes: u64,
    pub(super) directory: Region,
    pub(super) directory_entries: u32,
    pub(super) chunks: Region,
    pub(super) chunk_bytes: u32,
    pub(super) chunk_count: u32,
    pub(super) emergencies: Region,
    pub(super) emergency_count: u32,
    pub(super) flags: u32,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct DirectoryEntry {
    pub(super) index: u32,
    pub(super) tid: u32,
    pub(super) state: u32,
    pub(super) first_sequence: u64,
    pub(super) last_sequence: u64,
    pub(super) chunk_index: u32,
    pub(super) generation: u32,
    pub(super) range_reliable: bool,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ChunkHeader {
    pub(super) state: u32,
    pub(super) tid: u32,
    pub(super) generation: u32,
    pub(super) first_sequence: u64,
    pub(super) last_sequence: u64,
    pub(super) committed_bytes: u32,
    pub(super) record_count: u32,
    pub(super) checksum: u32,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct RecordHeader {
    pub(super) kind: u16,
    pub(super) flags: u16,
    pub(super) total_bytes: u32,
    pub(super) sequence: u64,
    pub(super) checksum: u32,
    pub(super) commit: u32,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct EmergencyCell {
    pub(super) kind: u32,
    pub(super) tid: u32,
    pub(super) sequence: u64,
    pub(super) pc: u64,
    pub(super) sp: u64,
    pub(super) fault_address: u64,
    pub(super) signal_number: u32,
    pub(super) signal_code: u32,
    pub(super) flags: u32,
    pub(super) checksum: u32,
    pub(super) checksum_inverse: u32,
    pub(super) version: u32,
}

pub(super) fn parse_superblock(
    bytes: &[u8; FLIGHT_SUPERBLOCK_BYTES],
    source_size: u64,
) -> Result<Superblock, ProviderError> {
    let coordinate = SourceCoordinate {
        offset: 0,
        record_ordinal: None,
    };
    require_zero(
        bytes,
        10,
        16,
        "superblock header reserved bytes",
        coordinate,
    )?;
    require_zero(
        bytes,
        76,
        80,
        "superblock identity reserved bytes",
        coordinate,
    )?;
    require_zero(
        bytes,
        226,
        FLIGHT_SUPERBLOCK_BYTES,
        "superblock tail reserved bytes",
        coordinate,
    )?;

    let mut cursor = Cursor::new(bytes, coordinate, "flight superblock");
    let magic = cursor.u32_le()?;
    let version = cursor.u16_le()?;
    let byte_order = cursor.u8()?;
    let pointer_width = cursor.u8()?;
    let header_bytes = cursor.u16_le()?;
    cursor.skip(6)?;
    let artifact_bytes = cursor.u64_le()?;
    let directory_offset = cursor.u64_le()?;
    let directory_entry_bytes = cursor.u32_le()?;
    let directory_entries = cursor.u32_le()?;
    let chunk_offset = cursor.u64_le()?;
    let chunk_bytes = cursor.u32_le()?;
    let chunk_count = cursor.u32_le()?;
    let emergency_offset = cursor.u64_le()?;
    let emergency_record_bytes = cursor.u32_le()?;
    let emergency_count = cursor.u32_le()?;
    let flags = cursor.u32_le()?;
    cursor.skip(4)?;
    let run_id = cursor.u64_le()?;
    let pid = cursor.u32_le()?;
    let module_generation = cursor.u32_le()?;
    let target_name_bytes = usize::from(cursor.u16_le()?);

    if magic != MAGIC
        || version != VERSION
        || byte_order != 1
        || !matches!(pointer_width, 4 | 8)
        || usize::from(header_bytes) != FLIGHT_SUPERBLOCK_BYTES
    {
        return Err(superblock_error("invalid Flight v2 header identity"));
    }
    if artifact_bytes != source_size || artifact_bytes < FLIGHT_SUPERBLOCK_BYTES as u64 {
        return Err(superblock_error("artifact size does not match source"));
    }
    if directory_entry_bytes != FLIGHT_DIRECTORY_ENTRY_BYTES as u32 || directory_entries == 0 {
        return Err(superblock_error("invalid directory configuration"));
    }
    let expected_emergency_count = directory_entries
        .checked_add(1)
        .ok_or_else(|| superblock_error("emergency count overflow"))?;
    if emergency_record_bytes != FLIGHT_EMERGENCY_SLOT_BYTES as u32
        || emergency_count != expected_emergency_count
    {
        return Err(superblock_error("invalid emergency configuration"));
    }
    if chunk_bytes <= FLIGHT_CHUNK_HEADER_BYTES as u32
        || !chunk_bytes.is_power_of_two()
        || chunk_count == 0
    {
        return Err(superblock_error("invalid chunk configuration"));
    }
    if flags & !KNOWN_INCOMPLETE_FLAGS != 0 {
        return Err(superblock_error("unknown Flight incomplete flags"));
    }
    if run_id == 0 || pid == 0 || target_name_bytes == 0 || target_name_bytes > TARGET_NAME_BYTES {
        return Err(superblock_error("invalid Flight producer identity"));
    }
    let target_end = TARGET_NAME_OFFSET
        .checked_add(target_name_bytes)
        .ok_or_else(|| superblock_error("target name overflow"))?;
    let target = bytes
        .get(TARGET_NAME_OFFSET..target_end)
        .ok_or_else(|| superblock_error("invalid target name bounds"))?;
    if target.contains(&0) || str::from_utf8(target).is_err() {
        return Err(superblock_error("invalid target module name"));
    }
    require_zero(
        bytes,
        target_end,
        TARGET_NAME_OFFSET + TARGET_NAME_BYTES,
        "target name padding",
        coordinate,
    )?;

    let directory = checked_region(
        directory_offset,
        directory_entries,
        directory_entry_bytes,
        artifact_bytes,
        "directory",
    )?;
    let emergencies = checked_region(
        emergency_offset,
        emergency_count,
        emergency_record_bytes,
        artifact_bytes,
        "emergency",
    )?;
    let chunks = checked_region(
        chunk_offset,
        chunk_count,
        chunk_bytes,
        artifact_bytes,
        "chunk",
    )?;
    if directory.offset < FLIGHT_SUPERBLOCK_BYTES as u64
        || directory.end > emergencies.offset
        || emergencies.end > chunks.offset
    {
        return Err(superblock_error("overlapping Flight regions"));
    }
    if directory.offset % 8 != 0
        || emergencies.offset % FLIGHT_EMERGENCY_RECORD_BYTES as u64 != 0
        || chunks.offset % u64::from(chunk_bytes) != 0
    {
        return Err(superblock_error("misaligned Flight region"));
    }

    let mut target_copy = [0_u8; TARGET_NAME_BYTES];
    target_copy[..target_name_bytes].copy_from_slice(target);
    Ok(Superblock {
        pointer_width,
        run_id,
        pid,
        module_generation,
        target: target_copy,
        target_len: target_name_bytes as u16,
        artifact_bytes,
        directory,
        directory_entries,
        chunks,
        chunk_bytes,
        chunk_count,
        emergencies,
        emergency_count,
        flags,
    })
}

pub(super) fn parse_directory(
    bytes: &[u8; FLIGHT_DIRECTORY_ENTRY_BYTES],
    index: u32,
    chunk_count: u32,
    offset: u64,
) -> Result<Option<DirectoryEntry>, ProviderError> {
    let coordinate = SourceCoordinate {
        offset,
        record_ordinal: None,
    };
    let mut cursor = Cursor::new(bytes, coordinate, "Flight directory entry");
    let tid = cursor.u32_le()?;
    let state = cursor.u32_le()?;
    let mut first_sequence = cursor.u64_le()?;
    let mut last_sequence = cursor.u64_le()?;
    let mut chunk_index = cursor.u32_le()?;
    let mut generation = cursor.u32_le()?;
    if state == 0 {
        return Ok(None);
    }
    if !matches!(state, 1 | 2) {
        return Err(directory_error(offset, "invalid directory state"));
    }
    require_zero(
        bytes,
        32,
        FLIGHT_DIRECTORY_ENTRY_BYTES,
        "directory reserved bytes",
        coordinate,
    )?;
    if tid == 0 {
        return Err(directory_error(offset, "directory TID is zero"));
    }
    if state == 2 {
        return Ok(Some(DirectoryEntry {
            index,
            tid,
            state,
            first_sequence: 0,
            last_sequence: 0,
            chunk_index: INVALID_INDEX,
            generation: 0,
            range_reliable: false,
        }));
    }
    let range_reliable = !((first_sequence == 0) != (last_sequence == 0)
        || (first_sequence != 0 && first_sequence > last_sequence));
    if !range_reliable {
        first_sequence = 0;
        last_sequence = 0;
    }
    if chunk_index == INVALID_INDEX {
        if generation != 0 {
            return Err(directory_error(offset, "invalid directory generation"));
        }
    } else if chunk_index >= chunk_count || generation == 0 {
        return Err(directory_error(offset, "invalid directory chunk reference"));
    }
    if chunk_index == INVALID_INDEX {
        chunk_index = INVALID_INDEX;
        generation = 0;
    }
    Ok(Some(DirectoryEntry {
        index,
        tid,
        state,
        first_sequence,
        last_sequence,
        chunk_index,
        generation,
        range_reliable,
    }))
}

pub(super) fn parse_chunk_header(
    bytes: &[u8; FLIGHT_CHUNK_HEADER_BYTES],
    expected_index: u32,
    offset: u64,
) -> Result<Option<ChunkHeader>, ProviderError> {
    let coordinate = SourceCoordinate {
        offset,
        record_ordinal: None,
    };
    let mut cursor = Cursor::new(bytes, coordinate, "Flight chunk header");
    let magic = cursor.u32_le()?;
    let version = cursor.u16_le()?;
    let header_bytes = cursor.u16_le()?;
    let index = cursor.u32_le()?;
    let state = cursor.u32_le()?;
    let tid = cursor.u32_le()?;
    let generation = cursor.u32_le()?;
    let first_sequence = cursor.u64_le()?;
    let last_sequence = cursor.u64_le()?;
    let committed_bytes = cursor.u32_le()?;
    let record_count = cursor.u32_le()?;
    let checksum = cursor.u32_le()?;
    if state == 0 {
        return Ok(None);
    }
    if !matches!(state, 1 | 2) {
        return Err(chunk_error(offset, "invalid chunk state"));
    }
    if magic != MAGIC
        || version != VERSION
        || usize::from(header_bytes) != FLIGHT_CHUNK_HEADER_BYTES
        || index != expected_index
    {
        return Err(chunk_error(offset, "invalid chunk header identity"));
    }
    require_zero(
        bytes,
        52,
        FLIGHT_CHUNK_HEADER_BYTES,
        "chunk reserved bytes",
        coordinate,
    )?;
    if tid == 0 || generation == 0 {
        return Err(chunk_error(offset, "invalid chunk ownership"));
    }
    Ok(Some(ChunkHeader {
        state,
        tid,
        generation,
        first_sequence,
        last_sequence,
        committed_bytes,
        record_count,
        checksum,
    }))
}

pub(super) fn parse_record_header(
    bytes: &[u8; FLIGHT_RECORD_HEADER_BYTES],
    coordinate: SourceCoordinate,
) -> Result<RecordHeader, ProviderError> {
    let mut cursor = Cursor::new(bytes, coordinate, "Flight record header");
    Ok(RecordHeader {
        kind: cursor.u16_le()?,
        flags: cursor.u16_le()?,
        total_bytes: cursor.u32_le()?,
        sequence: cursor.u64_le()?,
        checksum: cursor.u32_le()?,
        commit: cursor.u32_le()?,
    })
}

pub(super) fn parse_emergency_cell(
    bytes: &[u8],
    offset: u64,
) -> Result<EmergencyCell, ProviderError> {
    let coordinate = SourceCoordinate {
        offset,
        record_ordinal: None,
    };
    let mut cursor = Cursor::new(bytes, coordinate, "Flight emergency cell");
    let kind = cursor.u32_le()?;
    let tid = cursor.u32_le()?;
    let sequence = cursor.u64_le()?;
    let pc = cursor.u64_le()?;
    let sp = cursor.u64_le()?;
    let fault_address = cursor.u64_le()?;
    let signal_number = cursor.u32_le()?;
    let signal_code = cursor.u32_le()?;
    let published_flags = cursor.u32_le()?;
    let checksum = cursor.u32_le()?;
    let checksum_inverse = cursor.u32_le()?;
    let version = cursor.u32_le()?;
    cursor.finish()?;
    Ok(EmergencyCell {
        kind,
        tid,
        sequence,
        pc,
        sp,
        fault_address,
        signal_number,
        signal_code,
        flags: published_flags,
        checksum,
        checksum_inverse,
        version,
    })
}

pub(super) fn valid_record_flags(kind: u16, flags: u16) -> bool {
    match kind {
        4 => matches!(flags, 0 | 1),
        6 => matches!(flags, 0 | 3 | 4),
        7 | 8 => matches!(flags, 0 | 4),
        9 => matches!(flags, 0 | 1),
        1..=15 => flags == 0,
        _ => false,
    }
}

pub(super) fn fnv32(bytes: &[u8]) -> u32 {
    bytes.iter().fold(2_166_136_261_u32, |value, byte| {
        (value ^ u32::from(*byte)).wrapping_mul(16_777_619)
    })
}

pub(super) fn fnv32_update(mut value: u32, bytes: &[u8]) -> u32 {
    for byte in bytes {
        value = (value ^ u32::from(*byte)).wrapping_mul(16_777_619);
    }
    value
}

pub(super) fn record_checksum(header: &[u8], payload: &[u8]) -> Option<u32> {
    let prefix = header.get(..16)?;
    Some(fnv32_update(fnv32(prefix), payload))
}

pub(super) fn emergency_checksum(cell: &EmergencyCell) -> u32 {
    let mut value = 2_166_136_261_u32;
    value = fnv32_update(value, &cell.kind.to_le_bytes());
    value = fnv32_update(value, &cell.tid.to_le_bytes());
    value = fnv32_update(value, &cell.sequence.to_le_bytes());
    value = fnv32_update(value, &cell.pc.to_le_bytes());
    value = fnv32_update(value, &cell.sp.to_le_bytes());
    value = fnv32_update(value, &cell.fault_address.to_le_bytes());
    value = fnv32_update(value, &cell.signal_number.to_le_bytes());
    value = fnv32_update(
        value,
        &(if cell.kind == 15 { 0 } else { cell.signal_code }).to_le_bytes(),
    );
    fnv32_update(value, &(cell.flags & !EMERGENCY_COMMITTED).to_le_bytes())
}

fn checked_region(
    offset: u64,
    count: u32,
    size: u32,
    artifact_size: u64,
    label: &str,
) -> Result<Region, ProviderError> {
    let extent = u64::from(count)
        .checked_mul(u64::from(size))
        .ok_or_else(|| superblock_error(format!("invalid {label} region extent")))?;
    let end = offset
        .checked_add(extent)
        .ok_or_else(|| superblock_error(format!("invalid {label} region bounds")))?;
    if offset > artifact_size || end > artifact_size {
        return Err(superblock_error(format!("invalid {label} region bounds")));
    }
    Ok(Region { offset, end })
}

fn require_zero(
    bytes: &[u8],
    start: usize,
    end: usize,
    label: &str,
    coordinate: SourceCoordinate,
) -> Result<(), ProviderError> {
    let region = bytes.get(start..end).ok_or_else(|| {
        ProviderError::new(
            "source.flight.superblock",
            "flight.superblock",
            Some(coordinate),
            false,
            format!("invalid {label} bounds"),
        )
    })?;
    if region.iter().any(|byte| *byte != 0) {
        return Err(ProviderError::new(
            if start >= 32 && end == FLIGHT_DIRECTORY_ENTRY_BYTES {
                "source.flight.directory"
            } else if start >= 52 && end == FLIGHT_CHUNK_HEADER_BYTES {
                "source.flight.chunk"
            } else {
                "source.flight.superblock"
            },
            if start >= 32 && end == FLIGHT_DIRECTORY_ENTRY_BYTES {
                "flight.directory"
            } else if start >= 52 && end == FLIGHT_CHUNK_HEADER_BYTES {
                "flight.chunk"
            } else {
                "flight.superblock"
            },
            Some(coordinate),
            false,
            format!("nonzero {label}"),
        ));
    }
    Ok(())
}

pub(super) fn superblock_error(detail: impl AsRef<str>) -> ProviderError {
    ProviderError::new(
        "source.flight.superblock",
        "flight.superblock",
        Some(SourceCoordinate {
            offset: 0,
            record_ordinal: None,
        }),
        false,
        detail,
    )
}

pub(super) fn directory_error(offset: u64, detail: impl AsRef<str>) -> ProviderError {
    ProviderError::new(
        "source.flight.directory",
        "flight.directory",
        Some(SourceCoordinate {
            offset,
            record_ordinal: None,
        }),
        false,
        detail,
    )
}

pub(super) fn chunk_error(offset: u64, detail: impl AsRef<str>) -> ProviderError {
    ProviderError::new(
        "source.flight.chunk",
        "flight.chunk",
        Some(SourceCoordinate {
            offset,
            record_ordinal: None,
        }),
        false,
        detail,
    )
}

pub(super) fn record_error(coordinate: SourceCoordinate, detail: impl AsRef<str>) -> ProviderError {
    ProviderError::new(
        "source.flight.record",
        "flight.record",
        Some(coordinate),
        false,
        detail,
    )
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
    coordinate: SourceCoordinate,
    label: &'static str,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8], coordinate: SourceCoordinate, label: &'static str) -> Self {
        Self {
            bytes,
            position: 0,
            coordinate,
            label,
        }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], ProviderError> {
        let end = self
            .position
            .checked_add(N)
            .ok_or_else(|| self.invalid_length())?;
        let source = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| self.invalid_length())?;
        let mut output = [0; N];
        output.copy_from_slice(source);
        self.position = end;
        Ok(output)
    }

    fn skip(&mut self, count: usize) -> Result<(), ProviderError> {
        let end = self
            .position
            .checked_add(count)
            .ok_or_else(|| self.invalid_length())?;
        self.bytes
            .get(self.position..end)
            .ok_or_else(|| self.invalid_length())?;
        self.position = end;
        Ok(())
    }

    fn u8(&mut self) -> Result<u8, ProviderError> {
        Ok(u8::from_le_bytes(self.take()?))
    }

    fn u16_le(&mut self) -> Result<u16, ProviderError> {
        Ok(u16::from_le_bytes(self.take()?))
    }

    fn u32_le(&mut self) -> Result<u32, ProviderError> {
        Ok(u32::from_le_bytes(self.take()?))
    }

    fn u64_le(&mut self) -> Result<u64, ProviderError> {
        Ok(u64::from_le_bytes(self.take()?))
    }

    fn finish(self) -> Result<(), ProviderError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(self.invalid_length())
        }
    }

    fn invalid_length(&self) -> ProviderError {
        ProviderError::new(
            "source.flight.invalid_length",
            "flight.wire",
            Some(self.coordinate),
            false,
            format!("invalid {} length", self.label),
        )
    }
}
