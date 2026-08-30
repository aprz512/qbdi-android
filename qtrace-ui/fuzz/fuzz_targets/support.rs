#![allow(dead_code)]

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use qtrace_provider::{
    ArtifactDigest, BudgetDimension, ByteSource, FlightProvider, OpenMode, OperationAbort,
    QtrbInput, QtrbProvider, SourceIdentity, TraceProvider, WorkDelta, WorkGuard,
};

const INPUT_LIMIT: u64 = 16 * 1024 * 1024;
const DECOMPRESSED_LIMIT: u64 = 16 * 1024 * 1024;
const EVENT_LIMIT: u64 = 100_000;
const NODE_LIMIT: u64 = 100_000;
const ROW_LIMIT: u64 = 100_000;
const RESIDENT_LIMIT: u64 = 32 * 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(1);

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
        artifact: ArtifactDigest::new([0x91; 32]),
        format: String::new(),
        format_major: 0,
        format_minor: 0,
        source_bytes,
    }
}

fn drain(provider: Box<dyn TraceProvider>, guard: &dyn WorkGuard) {
    let Ok(mut cursor) = provider.into_cursor() else {
        return;
    };
    loop {
        match cursor.next_event(guard) {
            Ok(Some(_)) => {}
            Ok(None) => {
                let _ = cursor.finish();
                return;
            }
            Err(_) => return,
        }
    }
}

pub fn fuzz_qtrb(data: &[u8]) {
    if data.len() > INPUT_LIMIT as usize {
        return;
    }
    let bytes = qtrb_seed(data);
    let guard = StrictGuard::new();
    if let Ok(provider) = QtrbProvider::open(
        Arc::new(ByteSource::new(bytes.clone())),
        identity(bytes.len() as u64),
        OpenMode::Sealed,
        &guard,
    ) {
        drain(Box::new(provider), &guard);
    }

    let guard = StrictGuard::new();
    if let Ok(source) = QtrbInput::lz4(std::io::Cursor::new(bytes.clone())).into_source(&guard)
        && let Ok(provider) = QtrbProvider::open(
            source,
            identity(bytes.len() as u64),
            OpenMode::Sealed,
            &guard,
        )
    {
        drain(Box::new(provider), &guard);
    }
}

pub fn fuzz_flight(data: &[u8]) {
    if data.len() > INPUT_LIMIT as usize {
        return;
    }
    let bytes = flight_seed(data);
    let guard = StrictGuard::new();
    if let Ok(provider) = FlightProvider::open(
        Arc::new(ByteSource::new(bytes.clone())),
        identity(bytes.len() as u64),
        &guard,
    ) {
        drain(Box::new(provider), &guard);
    }
}

fn qtrb_seed(data: &[u8]) -> Vec<u8> {
    let seeds: &[(&[u8], &[u8])] = &[
        (
            b"qtrb:v1.0-completed\n",
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../fixtures/qtrb/v1.0-completed.bin"
            )),
        ),
        (
            b"qtrb:v1.1-chunked\n",
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../fixtures/qtrb/v1.1-chunked.bin"
            )),
        ),
        (
            b"qtrb:v1.2-completed\n",
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../fixtures/qtrb/v1.2-completed.bin"
            )),
        ),
        (
            b"qtrb:v1.2-partial\n",
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../fixtures/qtrb/v1.2-partial.bin"
            )),
        ),
        (
            b"qtrb:v1.2-stopped\n",
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../fixtures/qtrb/v1.2-stopped.bin"
            )),
        ),
        (
            b"qtrb:bad-header\n",
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../fixtures/qtrb/malformed/bad-header.bin"
            )),
        ),
        (
            b"qtrb:oversized-record\n",
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../fixtures/qtrb/malformed/oversized-record.bin"
            )),
        ),
        (
            b"qtrb:record-after-terminal\n",
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../fixtures/qtrb/malformed/record-after-terminal.bin"
            )),
        ),
        (
            b"qtrb:sequence-gap\n",
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../fixtures/qtrb/malformed/sequence-gap.bin"
            )),
        ),
        (
            b"qtrb:truncated-payload\n",
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../fixtures/qtrb/malformed/truncated-payload.bin"
            )),
        ),
        (
            b"qtrb:undefined-metadata\n",
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../fixtures/qtrb/malformed/undefined-metadata.bin"
            )),
        ),
        (
            b"qtrb:unsupported-feature\n",
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../fixtures/qtrb/malformed/unsupported-feature.bin"
            )),
        ),
    ];
    expand_seed(data, seeds).unwrap_or_else(|| data.to_vec())
}

fn flight_seed(data: &[u8]) -> Vec<u8> {
    let seeds: &[(&[u8], &[u8])] = &[
        (
            b"flight:v2-active\n",
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../fixtures/flight/v2-active.bin"
            )),
        ),
        (
            b"flight:v2-checkpoint-delta\n",
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../fixtures/flight/v2-checkpoint-delta.bin"
            )),
        ),
        (
            b"flight:v2-checksum-damaged\n",
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../fixtures/flight/v2-checksum-damaged.bin"
            )),
        ),
        (
            b"flight:v2-complete\n",
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../fixtures/flight/v2-complete.bin"
            )),
        ),
        (
            b"flight:v2-coverage-gap\n",
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../fixtures/flight/v2-coverage-gap.bin"
            )),
        ),
        (
            b"flight:v2-incomplete-fragment\n",
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../fixtures/flight/v2-incomplete-fragment.bin"
            )),
        ),
        (
            b"flight:v2-overwritten\n",
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../fixtures/flight/v2-overwritten.bin"
            )),
        ),
        (
            b"flight:v2-stale-directory\n",
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../fixtures/flight/v2-stale-directory.bin"
            )),
        ),
    ];
    expand_seed(data, seeds).unwrap_or_else(|| data.to_vec())
}

fn expand_seed(data: &[u8], seeds: &[(&[u8], &[u8])]) -> Option<Vec<u8>> {
    for (prefix, fixture) in seeds {
        let Some(patches) = data.strip_prefix(*prefix) else {
            continue;
        };
        let mut output = fixture.to_vec();
        for patch in patches.chunks_exact(3) {
            let offset = usize::from(u16::from_le_bytes([patch[0], patch[1]])) % output.len();
            output[offset] ^= patch[2];
        }
        return Some(output);
    }
    None
}
