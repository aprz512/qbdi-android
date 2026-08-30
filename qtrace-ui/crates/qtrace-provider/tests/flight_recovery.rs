use std::{
    fs,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use qtrace_provider::{
    ArtifactDigest, BudgetDimension, ByteSource, CompletenessCause, EventKey, EventRecord,
    FLIGHT_CHUNK_HEADER_BYTES, FLIGHT_DIRECTORY_ENTRY_BYTES, FLIGHT_EMERGENCY_RECORD_BYTES,
    FLIGHT_EMERGENCY_SLOT_BYTES, FLIGHT_RECORD_HEADER_BYTES, FLIGHT_SUPERBLOCK_BYTES,
    FlightProvider, OperationAbort, Provenance, ProviderCapabilities, ProviderError,
    ProviderSummary, RangeBounds, ReadAtSource, SourceIdentity, TraceProvider, WorkDelta,
    WorkGuard,
};

const MAGIC: u32 = 0x5146_4c54;
const VERSION: u16 = 2;
const RECORD_COMMIT: u32 = 0x5143_4d54;
const EMERGENCY_COMMITTED: u32 = 0x8000_0000;
const INVALID_INDEX: u32 = u32::MAX;
const CHUNK_BYTES: usize = 2048;

#[derive(Default)]
struct AllowAll;

impl WorkGuard for AllowAll {
    fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
        Ok(())
    }
}

struct RejectAll;

impl WorkGuard for RejectAll {
    fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
        Err(OperationAbort::Cancelled)
    }
}

struct RejectAfterCalls {
    remaining: Mutex<usize>,
}

impl RejectAfterCalls {
    fn new(allowed: usize) -> Self {
        Self {
            remaining: Mutex::new(allowed),
        }
    }
}

impl WorkGuard for RejectAfterCalls {
    fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
        let mut remaining = self.remaining.lock().expect("guard lock");
        if *remaining == 0 {
            return Err(OperationAbort::Cancelled);
        }
        *remaining -= 1;
        Ok(())
    }
}

struct RejectEvents;

impl WorkGuard for RejectEvents {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        if delta.events != 0 {
            Err(OperationAbort::budget_exceeded(
                BudgetDimension::Events,
                0,
                delta.events,
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
struct RecordingSource {
    bytes: Arc<[u8]>,
    reads: Mutex<Vec<(u64, usize)>>,
}

impl RecordingSource {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: bytes.into(),
            reads: Mutex::new(Vec::new()),
        }
    }

    fn reads(&self) -> Vec<(u64, usize)> {
        self.reads.lock().expect("reads lock").clone()
    }
}

impl ReadAtSource for RecordingSource {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), ProviderError> {
        self.reads
            .lock()
            .expect("reads lock")
            .push((offset, output.len()));
        let end = offset
            .checked_add(output.len() as u64)
            .and_then(|end| usize::try_from(end).ok());
        let start = usize::try_from(offset).ok();
        let bytes = start
            .zip(end)
            .and_then(|(start, end)| self.bytes.get(start..end))
            .ok_or_else(|| {
                ProviderError::new(
                    "source.short_read",
                    "test.read",
                    None,
                    false,
                    "recording source short read",
                )
            })?;
        output.copy_from_slice(bytes);
        Ok(())
    }
}

#[derive(Debug)]
struct ChangingLenSource {
    bytes: ByteSource,
    calls: AtomicUsize,
}

impl ChangingLenSource {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: ByteSource::new(bytes),
            calls: AtomicUsize::new(0),
        }
    }
}

impl ReadAtSource for ChangingLenSource {
    fn len(&self) -> u64 {
        let actual = self.bytes.len();
        if self.calls.fetch_add(1, Ordering::SeqCst) < 2 {
            actual
        } else {
            actual.saturating_add(1)
        }
    }

    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), ProviderError> {
        self.bytes.read_exact_at(offset, output)
    }
}

#[derive(Debug)]
struct Collected {
    identity: SourceIdentity,
    capabilities: ProviderCapabilities,
    projections: Vec<(u32, Vec<EventKey>)>,
    events: Vec<EventRecord>,
    summary: ProviderSummary,
}

fn identity(source_bytes: u64) -> SourceIdentity {
    SourceIdentity {
        artifact: ArtifactDigest::new([0x66; 32]),
        format: "caller-spoof".to_owned(),
        format_major: 99,
        format_minor: 99,
        source_bytes,
    }
}

fn collect_source(
    source: Arc<dyn ReadAtSource>,
    guard: &dyn WorkGuard,
) -> Result<Collected, ProviderError> {
    let provider = FlightProvider::open(source, identity(7), guard)?;
    let identity = provider.identity().clone();
    let capabilities = provider.capabilities().clone();
    let projections = provider
        .projections()
        .iter()
        .map(|projection| (projection.tid, projection.event_keys.clone()))
        .collect();
    let mut cursor = Box::new(provider).into_cursor()?;
    let mut events = Vec::new();
    while let Some(event) = cursor.next_event(guard)? {
        events.push(event);
    }
    let summary = cursor.finish()?;
    Ok(Collected {
        identity,
        capabilities,
        projections,
        events,
        summary,
    })
}

fn collect_bytes(bytes: Vec<u8>) -> Result<Collected, ProviderError> {
    collect_source(Arc::new(ByteSource::new(bytes)), &AllowAll)
}

fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/../../fixtures/flight/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    fs::read(path).expect("checked-in Flight fixture")
}

fn put_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn get_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(input[offset..offset + 8].try_into().expect("u64 field"))
}

fn align(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

fn fnv32(bytes: &[u8]) -> u32 {
    bytes.iter().fold(2_166_136_261_u32, |value, byte| {
        (value ^ u32::from(*byte)).wrapping_mul(16_777_619)
    })
}

fn record(
    kind: u16,
    sequence: u64,
    payload: &[u8],
    flags: u16,
    generation: u32,
    committed: bool,
) -> Vec<u8> {
    let total = FLIGHT_RECORD_HEADER_BYTES + payload.len();
    let storage = align(total, 8);
    let mut output = vec![0; storage];
    put_u16(&mut output, 0, kind);
    put_u16(&mut output, 2, flags);
    put_u32(&mut output, 4, total as u32);
    put_u64(&mut output, 8, sequence);
    output[FLIGHT_RECORD_HEADER_BYTES..total].copy_from_slice(payload);
    let mut checksum_input = output[..16].to_vec();
    checksum_input.extend_from_slice(&output[FLIGHT_RECORD_HEADER_BYTES..total]);
    put_u32(&mut output, 16, fnv32(&checksum_input));
    if committed {
        put_u32(&mut output, 20, RECORD_COMMIT ^ total as u32 ^ generation);
    }
    output
}

fn directory(
    tid: u32,
    first: u64,
    last: u64,
    chunk_index: u32,
    generation: u32,
    state: u32,
) -> [u8; FLIGHT_DIRECTORY_ENTRY_BYTES] {
    let mut output = [0; FLIGHT_DIRECTORY_ENTRY_BYTES];
    put_u32(&mut output, 0, tid);
    put_u32(&mut output, 4, state);
    put_u64(&mut output, 8, first);
    put_u64(&mut output, 16, last);
    put_u32(&mut output, 24, chunk_index);
    put_u32(&mut output, 28, generation);
    output
}

fn chunk(
    index: u32,
    tid: u32,
    generation: u32,
    records: &[Vec<u8>],
    state: u32,
    suffix: &[u8],
) -> Vec<u8> {
    let committed = records.iter().map(Vec::len).sum::<usize>();
    let mut output = vec![0; CHUNK_BYTES];
    put_u32(&mut output, 0, MAGIC);
    put_u16(&mut output, 4, VERSION);
    put_u16(&mut output, 6, FLIGHT_CHUNK_HEADER_BYTES as u16);
    put_u32(&mut output, 8, index);
    put_u32(&mut output, 12, state);
    put_u32(&mut output, 16, tid);
    put_u32(&mut output, 20, generation);
    if state == 2 {
        let first = records.first().map(|item| get_u64(item, 8)).unwrap_or(0);
        let last = records.last().map(|item| get_u64(item, 8)).unwrap_or(0);
        put_u64(&mut output, 24, first);
        put_u64(&mut output, 32, last);
        put_u32(&mut output, 40, committed as u32);
        put_u32(&mut output, 44, records.len() as u32);
    }
    let mut cursor = FLIGHT_CHUNK_HEADER_BYTES;
    for item in records {
        output[cursor..cursor + item.len()].copy_from_slice(item);
        cursor += item.len();
    }
    output[cursor..cursor + suffix.len()].copy_from_slice(suffix);
    if state == 2 {
        let checksum =
            fnv32(&output[FLIGHT_CHUNK_HEADER_BYTES..FLIGHT_CHUNK_HEADER_BYTES + committed]);
        put_u32(&mut output, 48, checksum);
    }
    output
}

#[allow(clippy::too_many_arguments)]
fn emergency_cell(
    kind: u32,
    tid: u32,
    sequence: u64,
    pc: u64,
    code: u32,
    flags: u32,
    version: u32,
    committed: bool,
) -> [u8; FLIGHT_EMERGENCY_RECORD_BYTES] {
    let mut output = [0; FLIGHT_EMERGENCY_RECORD_BYTES];
    put_u32(&mut output, 0, kind);
    put_u32(&mut output, 4, tid);
    put_u64(&mut output, 8, sequence);
    put_u64(&mut output, 16, pc);
    put_u32(&mut output, 44, code);
    let published = flags | if committed { EMERGENCY_COMMITTED } else { 0 };
    put_u32(&mut output, 48, published);
    let mut logical = output[..52].to_vec();
    if kind == 15 {
        put_u32(&mut logical, 44, 0);
    }
    put_u32(&mut logical, 48, flags);
    let checksum = fnv32(&logical);
    put_u32(&mut output, 52, checksum);
    put_u32(&mut output, 56, !checksum);
    put_u32(&mut output, 60, version);
    output
}

fn emergency_slot(
    first: [u8; FLIGHT_EMERGENCY_RECORD_BYTES],
    second: [u8; FLIGHT_EMERGENCY_RECORD_BYTES],
) -> [u8; FLIGHT_EMERGENCY_SLOT_BYTES] {
    let mut output = [0; FLIGHT_EMERGENCY_SLOT_BYTES];
    output[..FLIGHT_EMERGENCY_RECORD_BYTES].copy_from_slice(&first);
    output[FLIGHT_EMERGENCY_RECORD_BYTES..].copy_from_slice(&second);
    output
}

fn artifact(
    directories: &[[u8; FLIGHT_DIRECTORY_ENTRY_BYTES]],
    chunks: &[Vec<u8>],
    emergencies: &[[u8; FLIGHT_EMERGENCY_SLOT_BYTES]],
    flags: u32,
) -> Vec<u8> {
    assert!(!directories.is_empty());
    assert!(!chunks.is_empty());
    assert!(emergencies.len() <= directories.len() + 1);
    let directory_offset = FLIGHT_SUPERBLOCK_BYTES;
    let emergency_offset = align(
        directory_offset + directories.len() * FLIGHT_DIRECTORY_ENTRY_BYTES,
        FLIGHT_EMERGENCY_SLOT_BYTES,
    );
    let chunk_offset = align(
        emergency_offset + (directories.len() + 1) * FLIGHT_EMERGENCY_SLOT_BYTES,
        CHUNK_BYTES,
    );
    let artifact_bytes = chunk_offset + chunks.len() * CHUNK_BYTES;
    let mut output = vec![0; artifact_bytes];
    put_u32(&mut output, 0, MAGIC);
    put_u16(&mut output, 4, VERSION);
    output[6] = 1;
    output[7] = 8;
    put_u16(&mut output, 8, FLIGHT_SUPERBLOCK_BYTES as u16);
    put_u64(&mut output, 16, artifact_bytes as u64);
    put_u64(&mut output, 24, directory_offset as u64);
    put_u32(&mut output, 32, FLIGHT_DIRECTORY_ENTRY_BYTES as u32);
    put_u32(&mut output, 36, directories.len() as u32);
    put_u64(&mut output, 40, chunk_offset as u64);
    put_u32(&mut output, 48, CHUNK_BYTES as u32);
    put_u32(&mut output, 52, chunks.len() as u32);
    put_u64(&mut output, 56, emergency_offset as u64);
    put_u32(&mut output, 64, FLIGHT_EMERGENCY_SLOT_BYTES as u32);
    put_u32(&mut output, 68, (directories.len() + 1) as u32);
    put_u32(&mut output, 72, flags);
    put_u64(&mut output, 80, 0x1020_3040_5060_7080);
    put_u32(&mut output, 88, 4242);
    put_u32(&mut output, 92, 17);
    let target = b"libtarget.so";
    put_u16(&mut output, 96, target.len() as u16);
    output[98..98 + target.len()].copy_from_slice(target);
    for (index, entry) in directories.iter().enumerate() {
        let start = directory_offset + index * FLIGHT_DIRECTORY_ENTRY_BYTES;
        output[start..start + FLIGHT_DIRECTORY_ENTRY_BYTES].copy_from_slice(entry);
    }
    for (index, slot) in emergencies.iter().enumerate() {
        let start = emergency_offset + index * FLIGHT_EMERGENCY_SLOT_BYTES;
        output[start..start + FLIGHT_EMERGENCY_SLOT_BYTES].copy_from_slice(slot);
    }
    for (index, encoded) in chunks.iter().enumerate() {
        let start = chunk_offset + index * CHUNK_BYTES;
        output[start..start + CHUNK_BYTES].copy_from_slice(encoded);
    }
    output
}

fn chunk_offset(bytes: &[u8]) -> usize {
    usize::try_from(get_u64(bytes, 40)).expect("chunk offset")
}

fn sequence_ranges(summary: &ProviderSummary, cause: CompletenessCause) -> Vec<(u64, u64)> {
    summary
        .completeness
        .iter()
        .filter(|item| item.cause() == cause)
        .filter_map(|item| match item.bounds() {
            RangeBounds::InclusiveSequence { first, last } => Some((first, last)),
            RangeBounds::HalfOpen { .. } => None,
        })
        .collect()
}

fn sequences(events: &[EventRecord]) -> Vec<u64> {
    events
        .iter()
        .map(|event| event.key.sequence.expect("Flight sequence"))
        .collect()
}

#[test]
fn public_wire_sizes_match_flight_v2_contract() {
    assert_eq!(FLIGHT_SUPERBLOCK_BYTES, 4096);
    assert_eq!(FLIGHT_DIRECTORY_ENTRY_BYTES, 64);
    assert_eq!(FLIGHT_CHUNK_HEADER_BYTES, 64);
    assert_eq!(FLIGHT_RECORD_HEADER_BYTES, 24);
    assert_eq!(FLIGHT_EMERGENCY_RECORD_BYTES, 64);
    assert_eq!(FLIGHT_EMERGENCY_SLOT_BYTES, 128);
}

#[test]
fn every_checked_in_flight_fixture_opens_as_physical_evidence() {
    for name in [
        "v2-complete.bin",
        "v2-active.bin",
        "v2-checkpoint-delta.bin",
        "v2-overwritten.bin",
        "v2-coverage-gap.bin",
        "v2-checksum-damaged.bin",
        "v2-stale-directory.bin",
        "v2-incomplete-fragment.bin",
    ] {
        let parsed = collect_bytes(fixture(name)).unwrap_or_else(|error| {
            panic!("{name} did not recover: {error}");
        });
        assert_eq!(parsed.identity.format, "Flight");
        assert_eq!(parsed.identity.format_major, 2);
        assert_eq!(parsed.identity.format_minor, 0);
        assert!(parsed.identity.source_bytes >= FLIGHT_SUPERBLOCK_BYTES as u64);
    }
}

#[test]
fn validated_source_replaces_caller_version_and_size_identity() {
    let bytes = fixture("v2-complete.bin");
    let parsed = collect_source(Arc::new(ByteSource::new(bytes.clone())), &AllowAll).unwrap();

    assert_eq!(parsed.identity.format, "Flight");
    assert_eq!(
        (parsed.identity.format_major, parsed.identity.format_minor),
        (2, 0)
    );
    assert_eq!(parsed.identity.source_bytes, bytes.len() as u64);
    assert_eq!(parsed.identity.artifact, ArtifactDigest::new([0x66; 32]));

    let changing =
        collect_source(Arc::new(ChangingLenSource::new(bytes.clone())), &AllowAll).unwrap();
    assert_eq!(changing.identity.source_bytes, bytes.len() as u64);
}

#[test]
fn merged_and_per_thread_timelines_reference_one_stable_event_identity() {
    let parsed = collect_bytes(fixture("v2-complete.bin")).unwrap();

    assert!(parsed.capabilities.global_ordering);
    assert!(parsed.capabilities.per_thread_ordering);
    assert!(
        sequences(&parsed.events)
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    assert_eq!(sequences(&parsed.events), (1..=30).collect::<Vec<_>>());
    for (tid, keys) in &parsed.projections {
        let expected = parsed
            .events
            .iter()
            .filter(|event| event.key.tid == Some(*tid))
            .map(|event| event.key.clone())
            .collect::<Vec<_>>();
        assert_eq!(keys, &expected);
        assert!(
            keys.windows(2)
                .all(|pair| pair[0].sequence < pair[1].sequence)
        );
        assert!(keys.iter().all(|key| key.timeline.0 == 0));
    }
    assert_eq!(
        parsed.events.len(),
        30,
        "events must not be copied per projection"
    );
}

#[test]
fn damaged_chunk_becomes_explicit_checksum_completeness() {
    let parsed = collect_bytes(fixture("v2-checksum-damaged.bin")).unwrap();

    assert!(parsed.summary.completeness.iter().any(|item| {
        item.provenance() == Provenance::Damaged && item.cause() == CompletenessCause::Checksum
    }));
    assert!(parsed.events.is_empty());
}

#[test]
fn superblock_is_fully_validated_before_subordinate_reads() {
    let valid = fixture("v2-complete.bin");
    let mutations = [
        ("header reserved", 10, 1_u8),
        ("identity reserved", 76, 1),
        ("tail reserved", 226, 1),
    ];
    for (label, offset, value) in mutations {
        let mut bytes = valid.clone();
        bytes[offset] = value;
        let source = Arc::new(RecordingSource::new(bytes));
        let error = match FlightProvider::open(source.clone(), identity(0), &AllowAll) {
            Ok(_) => panic!("accepted {label}"),
            Err(error) => error,
        };
        assert_eq!(error.code(), "source.flight.superblock");
        assert_eq!(source.reads(), vec![(0, FLIGHT_SUPERBLOCK_BYTES)]);
    }
}

#[test]
fn source_size_regions_alignment_and_nonoverlap_fail_closed() {
    let valid = fixture("v2-complete.bin");
    let mut cases = Vec::new();
    let mut wrong_size = valid.clone();
    put_u64(&mut wrong_size, 16, valid.len() as u64 - 1);
    cases.push(("source size", wrong_size));
    let mut directory_alignment = valid.clone();
    put_u64(&mut directory_alignment, 24, 4097);
    cases.push(("directory alignment", directory_alignment));
    let mut overlap = valid.clone();
    put_u64(&mut overlap, 56, 4096);
    cases.push(("region overlap", overlap));
    let mut chunk_alignment = valid;
    let old_chunk_offset = get_u64(&chunk_alignment, 40);
    put_u64(&mut chunk_alignment, 40, old_chunk_offset + 1);
    cases.push(("chunk alignment", chunk_alignment));

    for (label, bytes) in cases {
        let source = Arc::new(RecordingSource::new(bytes));
        let error = match FlightProvider::open(source.clone(), identity(0), &AllowAll) {
            Ok(_) => panic!("accepted invalid {label}"),
            Err(error) => error,
        };
        assert_eq!(error.code(), "source.flight.superblock", "{label}");
        assert_eq!(source.reads(), vec![(0, FLIGHT_SUPERBLOCK_BYTES)]);
    }
}

#[test]
fn directory_rejects_duplicate_tids_and_impossible_generations() {
    let valid = fixture("v2-complete.bin");
    let mut duplicate = valid.clone();
    let first_tid = u32::from_le_bytes(duplicate[4096..4100].try_into().unwrap());
    put_u32(
        &mut duplicate,
        FLIGHT_SUPERBLOCK_BYTES + FLIGHT_DIRECTORY_ENTRY_BYTES,
        first_tid,
    );
    let mut invalid_generation = valid;
    put_u32(
        &mut invalid_generation,
        FLIGHT_SUPERBLOCK_BYTES + 24,
        INVALID_INDEX,
    );
    put_u32(&mut invalid_generation, FLIGHT_SUPERBLOCK_BYTES + 28, 7);

    for bytes in [duplicate, invalid_generation] {
        let error = collect_bytes(bytes).expect_err("invalid directory accepted");
        assert_eq!(error.code(), "source.flight.directory");
    }
}

#[test]
fn stale_rotating_and_unreliable_directory_states_remain_visible() {
    let stale = collect_bytes(fixture("v2-stale-directory.bin")).unwrap();
    assert!(
        stale
            .summary
            .completeness
            .iter()
            .any(|item| item.cause() == CompletenessCause::Stale)
    );
    assert_eq!(sequences(&stale.events), vec![1, 2]);

    let records = vec![record(1, 5, b"", 0, 3, true), record(1, 7, b"", 0, 3, true)];
    let mut torn = directory(77, 9, 5, 0, 3, 2);
    put_u64(&mut torn, 8, 9);
    put_u64(&mut torn, 16, 5);
    let bytes = artifact(&[torn], &[chunk(0, 77, 3, &records, 2, b"")], &[], 0);
    let parsed = collect_bytes(bytes).unwrap();
    assert!(
        parsed
            .summary
            .completeness
            .iter()
            .any(|item| item.cause() == CompletenessCause::Rotating)
    );
    assert!(
        parsed
            .summary
            .completeness
            .iter()
            .any(|item| item.cause() == CompletenessCause::Unreliable)
    );
    assert_eq!(
        sequence_ranges(&parsed.summary, CompletenessCause::Lost),
        vec![(6, 6)]
    );
}

#[test]
fn active_scan_stops_at_first_uncommitted_record_without_reading_suffix() {
    let generation = 4;
    let first = record(2, 1, b"one", 0, generation, true);
    let second = record(3, 2, b"two", 0, generation, true);
    let torn = record(5, 3, &[0xaa; 80], 0, generation, false);
    let poisonous_suffix = vec![0xff; 96];
    let encoded = artifact(
        &[directory(44, 1, 2, 0, generation, 1)],
        &[chunk(
            0,
            44,
            generation,
            &[first.clone(), second.clone()],
            1,
            &[torn.clone(), poisonous_suffix.clone()].concat(),
        )],
        &[],
        0,
    );
    let data_start = chunk_offset(&encoded) + FLIGHT_CHUNK_HEADER_BYTES;
    let uncommitted_payload_start =
        data_start + first.len() + second.len() + FLIGHT_RECORD_HEADER_BYTES;
    let source = Arc::new(RecordingSource::new(encoded));

    let parsed = collect_source(source.clone(), &AllowAll).unwrap();

    assert_eq!(sequences(&parsed.events), vec![1, 2]);
    assert!(
        !parsed
            .summary
            .completeness
            .iter()
            .any(|item| item.cause() == CompletenessCause::Incomplete)
    );
    assert!(source.reads().iter().all(|(offset, size)| {
        let end = offset.saturating_add(*size as u64);
        end <= uncommitted_payload_start as u64 || *offset >= (data_start + CHUNK_BYTES) as u64
    }));
}

#[test]
fn sealed_checksum_count_range_commit_checksum_and_padding_are_transactional() {
    let generation = 2;
    let original_record = record(2, 9, b"x", 0, generation, true);
    let base = artifact(
        &[directory(7, 9, 9, 0, generation, 1)],
        &[chunk(
            0,
            7,
            generation,
            std::slice::from_ref(&original_record),
            2,
            b"",
        )],
        &[],
        0,
    );
    let offset = chunk_offset(&base);
    let data = offset + FLIGHT_CHUNK_HEADER_BYTES;

    let mut cases = Vec::new();
    let mut chunk_checksum = base.clone();
    chunk_checksum[offset + 48] ^= 1;
    cases.push((CompletenessCause::Checksum, chunk_checksum));
    let mut count = base.clone();
    put_u32(&mut count, offset + 44, 2);
    cases.push((CompletenessCause::Incomplete, count));
    let mut range = base.clone();
    put_u64(&mut range, offset + 32, 10);
    cases.push((CompletenessCause::Incomplete, range));
    let mut commit = base.clone();
    put_u32(
        &mut commit,
        data + 20,
        RECORD_COMMIT ^ original_record.len() as u32 ^ 99,
    );
    let committed = original_record.len();
    let commit_chunk_checksum = fnv32(&commit[data..data + committed]);
    put_u32(&mut commit, offset + 48, commit_chunk_checksum);
    cases.push((CompletenessCause::Incomplete, commit));
    let mut record_checksum = base.clone();
    record_checksum[data + 16] ^= 1;
    let damaged_record_chunk_checksum = fnv32(&record_checksum[data..data + committed]);
    put_u32(
        &mut record_checksum,
        offset + 48,
        damaged_record_chunk_checksum,
    );
    cases.push((CompletenessCause::Checksum, record_checksum));
    let mut padding = base;
    let last_padding = data + committed - 1;
    padding[last_padding] = 1;
    let padding_chunk_checksum = fnv32(&padding[data..data + committed]);
    put_u32(&mut padding, offset + 48, padding_chunk_checksum);
    cases.push((CompletenessCause::Incomplete, padding));

    for (cause, bytes) in cases {
        let parsed = collect_bytes(bytes).unwrap();
        assert!(parsed.events.is_empty());
        assert!(
            parsed
                .summary
                .completeness
                .iter()
                .any(|item| { item.provenance() == Provenance::Damaged && item.cause() == cause })
        );
    }
}

#[test]
fn active_committed_checksum_or_type_damage_fails_instead_of_truncating_prefix() {
    let generation = 1;
    let mut bad_checksum = record(2, 1, b"", 0, generation, true);
    bad_checksum[16] ^= 1;
    let bad_type = record(99, 1, b"", 0, generation, true);

    for item in [bad_checksum, bad_type] {
        let bytes = artifact(
            &[directory(7, 1, 1, 0, generation, 1)],
            &[chunk(0, 7, generation, &[item], 1, b"")],
            &[],
            0,
        );
        let error = collect_bytes(bytes).expect_err("committed active damage accepted");
        assert!(matches!(
            error.code(),
            "source.flight.record" | "source.flight.record_checksum"
        ));
    }
}

#[test]
fn clean_missing_ranges_are_overwritten_and_flagged_ranges_are_lost() {
    let generation = 1;
    let records = [1, 3, 4, 8, 10]
        .into_iter()
        .map(|sequence| record(1, sequence, b"", 0, generation, true))
        .collect::<Vec<_>>();
    let make = |flags| {
        artifact(
            &[directory(7, 1, 10, 0, generation, 1)],
            &[chunk(0, 7, generation, &records, 2, b"")],
            &[],
            flags,
        )
    };

    let overwritten = collect_bytes(make(0)).unwrap();
    assert_eq!(
        sequence_ranges(&overwritten.summary, CompletenessCause::Overwritten),
        vec![(2, 2), (5, 7), (9, 9)],
        "{:?}",
        overwritten.summary.completeness
    );
    assert!(sequence_ranges(&overwritten.summary, CompletenessCause::Lost).is_empty());

    let lost = collect_bytes(make(4)).unwrap();
    assert_eq!(
        sequence_ranges(&lost.summary, CompletenessCause::Lost),
        vec![(2, 2), (5, 7), (9, 9)]
    );
    assert!(sequence_ranges(&lost.summary, CompletenessCause::Overwritten).is_empty());
}

#[test]
fn inclusive_lost_union_handles_u64_max_without_overflow() {
    let generation = 1;
    let records = vec![
        record(2, u64::MAX - 2, b"", 0, generation, true),
        record(3, u64::MAX, b"", 0, generation, true),
    ];
    let parsed = collect_bytes(artifact(
        &[directory(7, u64::MAX - 2, u64::MAX, 0, generation, 1)],
        &[chunk(0, 7, generation, &records, 2, b"")],
        &[],
        4,
    ))
    .unwrap();

    assert_eq!(
        sequence_ranges(&parsed.summary, CompletenessCause::Lost),
        vec![(u64::MAX - 1, u64::MAX - 1)]
    );
    assert_eq!(
        sequence_ranges(&parsed.summary, CompletenessCause::Retained),
        vec![(u64::MAX - 2, u64::MAX - 2), (u64::MAX, u64::MAX)]
    );
}

#[test]
fn chunk_wrap_generations_recover_physical_survivors_in_global_order() {
    let older = vec![record(2, 5, b"old", 0, 2, true)];
    let newer = vec![record(3, 9, b"new", 0, 7, true)];
    let parsed = collect_bytes(artifact(
        &[directory(55, 1, 9, 1, 7, 1)],
        &[
            chunk(0, 55, 2, &older, 2, b""),
            chunk(1, 55, 7, &newer, 1, b""),
        ],
        &[],
        0,
    ))
    .unwrap();

    assert_eq!(sequences(&parsed.events), vec![5, 9]);
    assert_eq!(
        sequence_ranges(&parsed.summary, CompletenessCause::Overwritten),
        vec![(1, 4), (6, 8)],
        "{:?}",
        parsed.summary.completeness
    );
}

#[test]
fn duplicate_global_sequences_across_physical_chunks_fail_closed() {
    let parsed = collect_bytes(artifact(
        &[directory(1, 5, 5, 0, 1, 1), directory(2, 5, 5, 1, 1, 1)],
        &[
            chunk(0, 1, 1, &[record(2, 5, b"", 0, 1, true)], 2, b""),
            chunk(1, 2, 1, &[record(2, 5, b"", 0, 1, true)], 2, b""),
        ],
        &[],
        0,
    ));

    let error = parsed.expect_err("duplicate sequence accepted");
    assert_eq!(error.code(), "source.flight.sequence");
}

#[test]
fn emergency_cells_validate_checksum_complement_version_and_stale_history() {
    let empty = chunk(0, 7, 1, &[], 1, b"");
    let first = emergency_cell(14, 7, 6, 0x1000, 0, 0, 2, true);
    let second = emergency_cell(11, 7, 7, 0x1004, 0, 0, 4, true);
    let parsed = collect_bytes(artifact(
        &[directory(7, 0, 0, 0, 1, 1)],
        std::slice::from_ref(&empty),
        &[emergency_slot(first, second)],
        0,
    ))
    .unwrap();
    assert_eq!(sequences(&parsed.events), vec![6, 7]);

    let stale_first = emergency_cell(14, 7, 6, 0x1000, 0, 0, 2, true);
    let stale_second = emergency_cell(11, 7, 7, 0x1004, 0, 0, 8, true);
    let stale = collect_bytes(artifact(
        &[directory(7, 0, 0, 0, 1, 1)],
        std::slice::from_ref(&empty),
        &[emergency_slot(stale_first, stale_second)],
        0,
    ))
    .unwrap();
    assert_eq!(sequences(&stale.events), vec![7]);
    assert!(
        stale
            .summary
            .completeness
            .iter()
            .any(|item| item.cause() == CompletenessCause::Stale)
    );

    let mut damaged = emergency_cell(14, 7, 6, 0x1000, 0, 0, 2, true);
    damaged[56] ^= 1;
    let damaged = collect_bytes(artifact(
        &[directory(7, 0, 0, 0, 1, 1)],
        std::slice::from_ref(&empty),
        &[emergency_slot(damaged, [0; FLIGHT_EMERGENCY_RECORD_BYTES])],
        0,
    ))
    .unwrap();
    assert!(damaged.events.is_empty());
    assert!(damaged.summary.completeness.iter().any(|item| {
        item.provenance() == Provenance::Damaged && item.cause() == CompletenessCause::Checksum
    }));

    let mut bad_gap_cell = emergency_cell(14, 7, 2, 0x1000, 0, 0, 2, true);
    bad_gap_cell[56] ^= 1;
    let gap_records = vec![record(1, 1, b"", 0, 1, true), record(1, 3, b"", 0, 1, true)];
    let damaged_gap = collect_bytes(artifact(
        &[directory(7, 1, 3, 0, 1, 1)],
        &[chunk(0, 7, 1, &gap_records, 2, b"")],
        &[emergency_slot(
            bad_gap_cell,
            [0; FLIGHT_EMERGENCY_RECORD_BYTES],
        )],
        0,
    ))
    .unwrap();
    assert_eq!(
        sequence_ranges(&damaged_gap.summary, CompletenessCause::Lost),
        vec![(2, 2)]
    );
    assert!(sequence_ranges(&damaged_gap.summary, CompletenessCause::Overwritten).is_empty());

    let odd = emergency_cell(14, 7, 6, 0x1000, 0, 0, 3, true);
    let odd = collect_bytes(artifact(
        &[directory(7, 0, 0, 0, 1, 1)],
        &[empty],
        &[emergency_slot(odd, [0; FLIGHT_EMERGENCY_RECORD_BYTES])],
        0,
    ))
    .unwrap();
    assert!(odd.events.is_empty());
    assert!(
        odd.summary
            .completeness
            .iter()
            .any(|item| item.cause() == CompletenessCause::Incomplete)
    );

    let same_left = emergency_cell(14, 7, 6, 0x1000, 0, 0, 2, true);
    let same_right = emergency_cell(11, 7, 7, 0x1004, 0, 0, 2, true);
    let same_version = collect_bytes(artifact(
        &[directory(7, 0, 0, 0, 1, 1)],
        &[chunk(0, 7, 1, &[], 1, b"")],
        &[emergency_slot(same_left, same_right)],
        0,
    ))
    .unwrap();
    assert!(same_version.events.is_empty());
    assert!(
        same_version
            .summary
            .completeness
            .iter()
            .any(|item| item.provenance() == Provenance::Damaged
                && item.cause() == CompletenessCause::Incomplete)
    );
}

#[test]
fn emergency_evidence_never_replaces_a_committed_record_with_the_same_sequence() {
    let generation = 1;
    let regular = record(2, 5, b"committed", 0, generation, true);
    let emergency = emergency_cell(14, 7, 5, 0x9999, 0, 0, 2, true);
    let parsed = collect_bytes(artifact(
        &[directory(7, 5, 5, 0, generation, 1)],
        &[chunk(0, 7, generation, &[regular], 2, b"")],
        &[emergency_slot(
            emergency,
            [0; FLIGHT_EMERGENCY_RECORD_BYTES],
        )],
        0,
    ))
    .unwrap();

    assert_eq!(sequences(&parsed.events), vec![5]);
    let payload = match &parsed.events[0].payload {
        qtrace_provider::EventPayload::OpaqueOptional(payload) => payload,
        other => panic!("unexpected physical payload: {other:?}"),
    };
    assert_eq!(payload.record_type, 2);
    assert_eq!(payload.bytes, b"committed");
}

#[test]
fn coverage_gap_and_unterminated_thread_are_explicit_completeness() {
    let begin = record(2, 1, b"", 0, 1, true);
    let gap = emergency_cell(15, 7, 4, 0x7100_9000, 0, 2, 2, true);
    let parsed = collect_bytes(artifact(
        &[directory(7, 1, 4, 0, 1, 1)],
        &[chunk(0, 7, 1, &[begin], 2, b"")],
        &[emergency_slot(gap, [0; FLIGHT_EMERGENCY_RECORD_BYTES])],
        0,
    ))
    .unwrap();

    assert!(
        parsed
            .summary
            .completeness
            .iter()
            .any(|item| item.cause() == CompletenessCause::CoverageGap)
    );
    assert!(
        parsed
            .summary
            .completeness
            .iter()
            .any(|item| item.cause() == CompletenessCause::UnterminatedThread)
    );
    assert_eq!(
        sequence_ranges(&parsed.summary, CompletenessCause::Lost),
        vec![(2, 3)]
    );

    let physical_gap = record(15, 4, b"", 0, 1, true);
    let regular = collect_bytes(artifact(
        &[directory(7, 1, 4, 0, 1, 1)],
        &[chunk(
            0,
            7,
            1,
            &[record(1, 1, b"", 0, 1, true), physical_gap],
            2,
            b"",
        )],
        &[],
        0,
    ))
    .unwrap();
    assert!(
        regular
            .summary
            .completeness
            .iter()
            .any(|item| item.cause() == CompletenessCause::CoverageGap)
    );
    assert_eq!(
        sequence_ranges(&regular.summary, CompletenessCause::Lost),
        vec![(2, 3)]
    );
}

#[test]
fn work_guard_authorizes_header_metadata_and_event_work_before_io_or_allocation() {
    let bytes = fixture("v2-complete.bin");
    let rejected_header = Arc::new(RecordingSource::new(bytes.clone()));
    let error = FlightProvider::open(rejected_header.clone(), identity(0), &RejectAll)
        .expect_err("cancelled header read succeeded");
    assert_eq!(error.code(), "control.cancelled");
    assert!(rejected_header.reads().is_empty());

    let rejected_metadata = Arc::new(RecordingSource::new(bytes));
    let error = FlightProvider::open(
        rejected_metadata.clone(),
        identity(0),
        &RejectAfterCalls::new(2),
    )
    .expect_err("cancelled metadata allocation succeeded");
    assert_eq!(error.code(), "control.cancelled");
    assert_eq!(
        rejected_metadata.reads(),
        vec![(0, FLIGHT_SUPERBLOCK_BYTES)]
    );

    let generation = 1;
    let payload = vec![0xaa; 256];
    let encoded = artifact(
        &[directory(7, 1, 1, 0, generation, 1)],
        &[chunk(
            0,
            7,
            generation,
            &[record(2, 1, &payload, 0, generation, true)],
            1,
            b"",
        )],
        &[],
        0,
    );
    let source = Arc::new(RecordingSource::new(encoded));
    let data_start = chunk_offset(&source.bytes) + FLIGHT_CHUNK_HEADER_BYTES;
    let error = FlightProvider::open(source.clone(), identity(0), &RejectEvents)
        .expect_err("event-budget rejection succeeded");
    assert_eq!(error.code(), "control.budget_exceeded");
    assert!(
        source
            .reads()
            .contains(&(data_start as u64, FLIGHT_RECORD_HEADER_BYTES))
    );
    assert!(
        !source
            .reads()
            .iter()
            .any(|(offset, _)| *offset == (data_start + FLIGHT_RECORD_HEADER_BYTES) as u64)
    );
}

#[test]
fn completeness_serialization_keeps_new_stable_causes_and_checked_ranges() {
    let values = [
        CompletenessCause::Incomplete,
        CompletenessCause::Unreliable,
        CompletenessCause::UnterminatedThread,
    ];
    assert_eq!(
        serde_json::to_value(values).unwrap(),
        serde_json::json!(["incomplete", "unreliable", "unterminated_thread"])
    );
}
