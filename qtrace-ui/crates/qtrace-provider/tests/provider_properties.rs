use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use proptest::prelude::*;
use qtrace_provider::{
    ArtifactDigest, BudgetDimension, ByteSource, EventRecord, FlightProvider, OpenMode,
    OperationAbort, Provenance, ProviderError, ProviderSummary, QtrbInput, QtrbProvider,
    ReadAtSource, SourceIdentity, TraceProvider, WorkDelta, WorkGuard,
};

const VALID_QTRB: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/qtrb/v1.2-completed.bin"
));
const CHUNKED_QTRB: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/qtrb/v1.1-chunked.bin"
));
const VALID_FLIGHT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/flight/v2-complete.bin"
));

const INPUT_LIMIT: u64 = 16 * 1024 * 1024;
const DECOMPRESSED_LIMIT: u64 = 16 * 1024 * 1024;
const EVENT_LIMIT: u64 = 100_000;
const NODE_LIMIT: u64 = 100_000;
const ROW_LIMIT: u64 = 100_000;
const RESIDENT_LIMIT: u64 = 32 * 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(1);

#[derive(Clone, Debug)]
struct BoundedOutput {
    source_bytes: u64,
    events: Vec<EventRecord>,
    summary: ProviderSummary,
}

#[derive(Default)]
struct Totals {
    input_bytes: u64,
    decompressed_bytes: u64,
    events: u64,
    nodes: u64,
    rows: u64,
    resident_bytes: u64,
}

struct StrictGuard {
    started: Instant,
    totals: Mutex<Totals>,
}

impl StrictGuard {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            totals: Mutex::new(Totals::default()),
        }
    }

    fn assert_within_limits(&self) {
        let totals = self.totals.lock().expect("strict guard totals");
        assert!(totals.input_bytes <= INPUT_LIMIT);
        assert!(totals.decompressed_bytes <= DECOMPRESSED_LIMIT);
        assert!(totals.events <= EVENT_LIMIT);
        assert!(totals.nodes <= NODE_LIMIT);
        assert!(totals.rows <= ROW_LIMIT);
        assert!(totals.resident_bytes <= RESIDENT_LIMIT);
        assert!(self.started.elapsed() <= DEADLINE);
    }
}

impl WorkGuard for StrictGuard {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        if self.started.elapsed() > DEADLINE {
            return Err(OperationAbort::Cancelled);
        }
        let mut totals = self.totals.lock().map_err(|_| OperationAbort::Cancelled)?;
        charge(
            &mut totals.input_bytes,
            delta.input_bytes,
            INPUT_LIMIT,
            BudgetDimension::InputBytes,
        )?;
        charge(
            &mut totals.decompressed_bytes,
            delta.decompressed_bytes,
            DECOMPRESSED_LIMIT,
            BudgetDimension::DecompressedBytes,
        )?;
        charge(
            &mut totals.events,
            delta.events,
            EVENT_LIMIT,
            BudgetDimension::Events,
        )?;
        charge(
            &mut totals.nodes,
            delta.nodes,
            NODE_LIMIT,
            BudgetDimension::Nodes,
        )?;
        charge(
            &mut totals.rows,
            delta.rows,
            ROW_LIMIT,
            BudgetDimension::Rows,
        )?;
        charge(
            &mut totals.resident_bytes,
            delta.resident_bytes,
            RESIDENT_LIMIT,
            BudgetDimension::ResidentBytes,
        )
    }
}

fn charge(
    consumed: &mut u64,
    delta: u64,
    limit: u64,
    dimension: BudgetDimension,
) -> Result<(), OperationAbort> {
    let next = consumed.checked_add(delta).unwrap_or(u64::MAX);
    if next > limit {
        return Err(OperationAbort::budget_exceeded(dimension, limit, next));
    }
    *consumed = next;
    Ok(())
}

fn identity(source_bytes: u64) -> SourceIdentity {
    SourceIdentity {
        artifact: ArtifactDigest::new([0x81; 32]),
        format: "untrusted-caller".to_owned(),
        format_major: 99,
        format_minor: 99,
        source_bytes,
    }
}

fn drain_qtrb(bytes: &[u8], guard: &dyn WorkGuard) -> Result<BoundedOutput, ProviderError> {
    let provider = QtrbProvider::open(
        Arc::new(ByteSource::new(bytes.to_vec())),
        identity(0),
        OpenMode::Sealed,
        guard,
    )?;
    let source_bytes = provider.identity().source_bytes;
    let mut cursor = Box::new(provider).into_cursor()?;
    let mut events = Vec::new();
    while let Some(event) = cursor.next_event(guard)? {
        events.push(event);
    }
    let summary = cursor.finish()?;
    Ok(BoundedOutput {
        source_bytes,
        events,
        summary,
    })
}

fn drain_lz4_qtrb(bytes: &[u8], guard: &dyn WorkGuard) -> Result<BoundedOutput, ProviderError> {
    let source = QtrbInput::lz4(std::io::Cursor::new(bytes.to_vec())).into_source(guard)?;
    let provider = QtrbProvider::open(source, identity(0), OpenMode::Sealed, guard)?;
    let source_bytes = provider.identity().source_bytes;
    let mut cursor = Box::new(provider).into_cursor()?;
    let mut events = Vec::new();
    while let Some(event) = cursor.next_event(guard)? {
        events.push(event);
    }
    let summary = cursor.finish()?;
    Ok(BoundedOutput {
        source_bytes,
        events,
        summary,
    })
}

fn drain_flight(bytes: &[u8], guard: &dyn WorkGuard) -> Result<BoundedOutput, ProviderError> {
    let provider = FlightProvider::open(
        Arc::new(ByteSource::new(bytes.to_vec())),
        identity(0),
        guard,
    )?;
    let source_bytes = provider.identity().source_bytes;
    let mut cursor = Box::new(provider).into_cursor()?;
    let mut events = Vec::new();
    while let Some(event) = cursor.next_event(guard)? {
        events.push(event);
    }
    let summary = cursor.finish()?;
    Ok(BoundedOutput {
        source_bytes,
        events,
        summary,
    })
}

fn assert_bounded_result(
    result: Result<BoundedOutput, ProviderError>,
    guard: &StrictGuard,
    source_family: &str,
) {
    match result {
        Ok(output) => {
            assert!(output.events.len() <= EVENT_LIMIT as usize);
            assert!(output.summary.counters.events_emitted <= EVENT_LIMIT);
            assert!(output.summary.counters.input_bytes <= INPUT_LIMIT);
            assert!(output.summary.counters.decompressed_bytes <= DECOMPRESSED_LIMIT);
        }
        Err(error) => {
            assert!(
                error.code().starts_with(source_family) || error.code().starts_with("control."),
                "unstable error family: {}",
                error.code()
            );
            assert!(error.detail().len() <= 512);
            assert!(!error.detail().contains(['\r', '\n']));
        }
    }
    guard.assert_within_limits();
}

#[derive(Clone, Copy)]
struct QtrbRecord {
    kind: u16,
    flags: u16,
    payload: usize,
}

fn qtrb_records(bytes: &[u8]) -> Vec<QtrbRecord> {
    let mut output = Vec::new();
    let mut offset = 16_usize;
    while let Some(header) = bytes.get(offset..offset.saturating_add(8)) {
        let kind = u16::from_le_bytes([header[0], header[1]]);
        let flags = u16::from_le_bytes([header[2], header[3]]);
        let size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
        let payload = offset + 8;
        let Some(end) = payload.checked_add(size) else {
            break;
        };
        if end > bytes.len() {
            break;
        }
        output.push(QtrbRecord {
            kind,
            flags,
            payload,
        });
        offset = end;
    }
    output
}

fn qtrb_mutation(class: u8, value: u8) -> (Vec<u8>, &'static str) {
    let mut bytes = if class == 7 {
        CHUNKED_QTRB.to_vec()
    } else {
        VALID_QTRB.to_vec()
    };
    let records = qtrb_records(&bytes);
    match class {
        0 => {
            bytes[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
            (bytes, "source.record_too_large")
        }
        1 => {
            bytes[18..20].copy_from_slice(&(u16::from(value) | 1).to_le_bytes());
            (bytes, "source.unsupported_record")
        }
        2 => {
            bytes[4] = value.max(2);
            (bytes, "source.version_unsupported")
        }
        3 => {
            let record = records.iter().find(|record| record.kind == 4).unwrap();
            bytes[record.payload + 20..record.payload + 24]
                .copy_from_slice(&u32::MAX.to_le_bytes());
            (bytes, "source.undefined_reference")
        }
        4 => {
            let record = records.iter().find(|record| record.kind == 4).unwrap();
            bytes[record.payload + 24] = u8::MAX;
            (bytes, "source.invalid_payload")
        }
        5 => {
            let record = records.iter().find(|record| record.kind == 2).unwrap();
            bytes[record.payload + 14] = 0xff;
            (bytes, "source.invalid_utf8")
        }
        6 => {
            bytes.push(value);
            (bytes, "source.record_after_terminal")
        }
        _ => {
            let fragments = records
                .iter()
                .filter(|record| matches!(record.kind, 6..=8) && record.flags == 1)
                .collect::<Vec<_>>();
            let record = fragments.get(1).expect("chunked fixture second fragment");
            bytes[record.payload + 12..record.payload + 14].copy_from_slice(&0_u16.to_le_bytes());
            (bytes, "source.invalid_fragment")
        }
    }
}

fn assert_required_mutation_rejected(bytes: &[u8], expected: &str) {
    let guard = StrictGuard::new();
    let observed = catch_unwind(AssertUnwindSafe(|| drain_qtrb(bytes, &guard)));
    assert!(observed.is_ok(), "QTRB mutation panicked");
    let error = observed
        .unwrap()
        .expect_err("invalid required QTRB evidence was accepted");
    assert_eq!(error.code(), expected);
    assert_bounded_result(Err(error), &guard, "source.");
}

#[derive(Clone, Copy)]
struct FlightRecord {
    offset: usize,
    chunk: usize,
    kind: u16,
    flags: u16,
    total: usize,
    generation: u32,
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn fnv32(bytes: &[u8]) -> u32 {
    bytes.iter().fold(2_166_136_261_u32, |value, byte| {
        (value ^ u32::from(*byte)).wrapping_mul(16_777_619)
    })
}

fn flight_records(bytes: &[u8]) -> Vec<FlightRecord> {
    let chunk_offset = read_u64(bytes, 40) as usize;
    let chunk_bytes = read_u32(bytes, 48) as usize;
    let chunk_count = read_u32(bytes, 52) as usize;
    let mut output = Vec::new();
    for index in 0..chunk_count {
        let chunk = chunk_offset + index * chunk_bytes;
        if read_u32(bytes, chunk + 12) != 2 {
            continue;
        }
        let generation = read_u32(bytes, chunk + 20);
        let committed = read_u32(bytes, chunk + 40) as usize;
        let mut offset = chunk + 64;
        let end = offset + committed;
        while offset < end {
            let kind = u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap());
            let flags = u16::from_le_bytes(bytes[offset + 2..offset + 4].try_into().unwrap());
            let total = read_u32(bytes, offset + 4) as usize;
            output.push(FlightRecord {
                offset,
                chunk,
                kind,
                flags,
                total,
                generation,
            });
            offset += (total + 7) & !7;
        }
    }
    output
}

fn refresh_record_checksum(bytes: &mut [u8], record: FlightRecord) {
    let mut logical = bytes[record.offset..record.offset + 16].to_vec();
    logical.extend_from_slice(&bytes[record.offset + 24..record.offset + record.total]);
    write_u32(bytes, record.offset + 16, fnv32(&logical));
}

fn refresh_chunk_checksum(bytes: &mut [u8], chunk: usize) {
    let committed = read_u32(bytes, chunk + 40) as usize;
    let checksum = fnv32(&bytes[chunk + 64..chunk + 64 + committed]);
    write_u32(bytes, chunk + 48, checksum);
}

fn flight_mutation(class: u8, value: u8) -> (Vec<u8>, bool) {
    let mut bytes = VALID_FLIGHT.to_vec();
    match class {
        0 => bytes[4..6].copy_from_slice(&(3_u16 + u16::from(value)).to_le_bytes()),
        1 => write_u64(&mut bytes, 24, u64::MAX - u64::from(value)),
        2 => write_u32(&mut bytes, 36, u32::MAX - u32::from(value)),
        3 => write_u32(&mut bytes, 72, 0x8000_0000 | u32::from(value)),
        4 => bytes[98] = 0xff,
        5 => {
            let chunk = flight_records(&bytes)[0].chunk;
            bytes[chunk + 48] ^= 1;
        }
        6 => {
            let record = flight_records(&bytes)[0];
            bytes[record.offset + 20] ^= 1;
            refresh_chunk_checksum(&mut bytes, record.chunk);
        }
        7 => {
            let record = flight_records(&bytes)[0];
            write_u32(&mut bytes, record.offset + 4, u32::MAX);
            write_u32(
                &mut bytes,
                record.offset + 20,
                0x5143_4d54 ^ u32::MAX ^ record.generation,
            );
            refresh_chunk_checksum(&mut bytes, record.chunk);
        }
        8 => {
            let record = flight_records(&bytes)
                .into_iter()
                .filter(|record| matches!(record.kind, 6..=8) && record.flags == 4)
                .nth(1)
                .expect("complete fixture second fragment reference");
            bytes[record.offset + 24 + 12..record.offset + 24 + 14]
                .copy_from_slice(&0_u16.to_le_bytes());
            refresh_record_checksum(&mut bytes, record);
            refresh_chunk_checksum(&mut bytes, record.chunk);
        }
        _ => {
            let record = flight_records(&bytes)
                .into_iter()
                .find(|record| matches!(record.kind, 6..=8) && record.flags == 0)
                .expect("complete fixture semantic reference");
            write_u32(&mut bytes, record.offset + 24, u32::MAX);
            refresh_record_checksum(&mut bytes, record);
            refresh_chunk_checksum(&mut bytes, record.chunk);
        }
    }
    (bytes, class < 5)
}

fn assert_flight_mutation_is_bounded(bytes: &[u8], required_error: bool) {
    let guard = StrictGuard::new();
    let observed = catch_unwind(AssertUnwindSafe(|| drain_flight(bytes, &guard)));
    assert!(observed.is_ok(), "Flight mutation panicked");
    match observed.unwrap() {
        Err(error) => {
            if required_error {
                assert_eq!(error.code(), "source.flight.superblock");
            } else {
                assert!(error.code().starts_with("source.flight."));
            }
        }
        Ok(output) => {
            assert!(
                !required_error,
                "invalid required Flight evidence was accepted"
            );
            assert!(
                output
                    .events
                    .iter()
                    .any(|event| event.provenance == Provenance::Damaged)
                    || output
                        .summary
                        .completeness
                        .iter()
                        .any(|range| range.provenance() == Provenance::Damaged),
                "damaged Flight evidence was reported as captured"
            );
        }
    }
    guard.assert_within_limits();
}

#[test]
fn qtrb_identity_uses_the_observed_source_length() {
    let guard = StrictGuard::new();
    let provider = QtrbProvider::open(
        Arc::new(ByteSource::new(VALID_QTRB.to_vec())),
        identity(1),
        OpenMode::Sealed,
        &guard,
    )
    .unwrap();

    assert_eq!(provider.identity().source_bytes, VALID_QTRB.len() as u64);
}

struct ChangingLengthSource {
    bytes: ByteSource,
    changed: Arc<AtomicBool>,
}

impl ReadAtSource for ChangingLengthSource {
    fn len(&self) -> u64 {
        let length = self.bytes.len();
        if self.changed.load(Ordering::SeqCst) {
            length.saturating_sub(1)
        } else {
            length
        }
    }

    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), ProviderError> {
        self.bytes.read_exact_at(offset, output)
    }
}

struct ChangeAfterEvents {
    inner: StrictGuard,
    changed: Arc<AtomicBool>,
    emitted: AtomicU64,
    change_after: u64,
}

impl WorkGuard for ChangeAfterEvents {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        self.inner.consume(delta)?;
        if delta.events != 0 {
            let emitted = self.emitted.fetch_add(delta.events, Ordering::SeqCst) + delta.events;
            if emitted >= self.change_after {
                self.changed.store(true, Ordering::SeqCst);
            }
        }
        Ok(())
    }
}

#[test]
fn qtrb_rejects_a_source_length_change_before_publishing_summary() {
    let expected_events = drain_qtrb(VALID_QTRB, &StrictGuard::new())
        .unwrap()
        .events
        .len() as u64;
    let changed = Arc::new(AtomicBool::new(false));
    let source = Arc::new(ChangingLengthSource {
        bytes: ByteSource::new(VALID_QTRB.to_vec()),
        changed: Arc::clone(&changed),
    });
    let guard = ChangeAfterEvents {
        inner: StrictGuard::new(),
        changed,
        emitted: AtomicU64::new(0),
        change_after: expected_events,
    };
    let provider = QtrbProvider::open(source, identity(0), OpenMode::Sealed, &guard).unwrap();
    let mut cursor = Box::new(provider).into_cursor().unwrap();
    let error = loop {
        match cursor.next_event(&guard) {
            Ok(Some(_)) => {}
            Ok(None) => break cursor.finish().unwrap_err(),
            Err(error) => break error,
        }
    };
    assert_eq!(error.code(), "source.identity_changed");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn arbitrary_qtrb_bytes_return_a_bounded_result_or_typed_error(
        bytes in proptest::collection::vec(any::<u8>(), 0..16_384)
    ) {
        let guard = StrictGuard::new();
        let observed = catch_unwind(AssertUnwindSafe(|| drain_qtrb(&bytes, &guard)));
        prop_assert!(observed.is_ok(), "QTRB parser panicked");
        assert_bounded_result(observed.unwrap(), &guard, "source.");
    }

    #[test]
    fn arbitrary_lz4_bytes_return_a_bounded_result_or_typed_error(
        bytes in proptest::collection::vec(any::<u8>(), 0..16_384)
    ) {
        let guard = StrictGuard::new();
        let observed = catch_unwind(AssertUnwindSafe(|| drain_lz4_qtrb(&bytes, &guard)));
        prop_assert!(observed.is_ok(), "LZ4/QTRB parser panicked");
        assert_bounded_result(observed.unwrap(), &guard, "source.qtrb.");
    }

    #[test]
    fn arbitrary_flight_bytes_return_a_bounded_result_or_typed_error(
        bytes in proptest::collection::vec(any::<u8>(), 0..16_384)
    ) {
        let guard = StrictGuard::new();
        let observed = catch_unwind(AssertUnwindSafe(|| drain_flight(&bytes, &guard)));
        prop_assert!(observed.is_ok(), "Flight parser panicked");
        assert_bounded_result(observed.unwrap(), &guard, "source.");
    }

    #[test]
    fn truncating_qtrb_at_any_byte_never_panics(cut in 0usize..VALID_QTRB.len()) {
        let guard = StrictGuard::new();
        let observed = catch_unwind(AssertUnwindSafe(|| drain_qtrb(&VALID_QTRB[..cut], &guard)));
        prop_assert!(observed.is_ok(), "truncated QTRB panicked");
        let error = observed.unwrap().expect_err("truncated sealed QTRB was accepted");
        prop_assert!(error.code().starts_with("source.") || error.code().starts_with("control."));
        guard.assert_within_limits();
    }

    #[test]
    fn truncating_flight_at_any_byte_never_panics(cut in 0usize..VALID_FLIGHT.len()) {
        let guard = StrictGuard::new();
        let observed = catch_unwind(AssertUnwindSafe(|| drain_flight(&VALID_FLIGHT[..cut], &guard)));
        prop_assert!(observed.is_ok(), "truncated Flight panicked");
        let error = observed.unwrap().expect_err("truncated Flight was accepted");
        prop_assert!(error.code().starts_with("source.") || error.code().starts_with("control."));
        guard.assert_within_limits();
    }

    #[test]
    fn qtrb_required_mutation_classes_fail_with_stable_codes(
        class in 0_u8..8,
        value in any::<u8>(),
    ) {
        let (bytes, expected) = qtrb_mutation(class, value);
        assert_required_mutation_rejected(&bytes, expected);
    }

    #[test]
    fn flight_offset_chunk_mutations_are_bounded_and_fail_closed(
        class in 0_u8..10,
        value in any::<u8>(),
    ) {
        let (bytes, required_error) = flight_mutation(class, value);
        assert_flight_mutation_is_bounded(&bytes, required_error);
    }
}

#[test]
fn checked_valid_skeletons_fit_the_strict_budget() {
    for (bytes, open) in [
        (
            VALID_QTRB,
            drain_qtrb as fn(&[u8], &dyn WorkGuard) -> Result<BoundedOutput, ProviderError>,
        ),
        (
            VALID_FLIGHT,
            drain_flight as fn(&[u8], &dyn WorkGuard) -> Result<BoundedOutput, ProviderError>,
        ),
    ] {
        let guard = StrictGuard::new();
        let output = open(bytes, &guard).unwrap();
        assert_eq!(output.source_bytes, bytes.len() as u64);
        assert!(output.events.iter().all(|event| {
            matches!(event.provenance, Provenance::Captured | Provenance::Damaged)
        }));
        guard.assert_within_limits();
    }
}
