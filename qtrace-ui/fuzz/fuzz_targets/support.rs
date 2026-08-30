#![allow(dead_code)]

use std::{
    io::Write,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use lz4_flex::frame::{BlockMode, BlockSize, FrameEncoder, FrameInfo};
use qtrace_provider::{
    ArtifactDigest, BudgetDimension, ByteSource, FlightProvider, OpenMode, OperationAbort,
    QtrbInput, QtrbProvider, ReadAtSource, SourceIdentity, TraceProvider, WorkDelta, WorkGuard,
};

const INPUT_LIMIT: u64 = 16 * 1024 * 1024;
const DECOMPRESSED_LIMIT: u64 = 16 * 1024 * 1024;
const EVENT_LIMIT: u64 = 100_000;
const NODE_LIMIT: u64 = 100_000;
const ROW_LIMIT: u64 = 100_000;
const RESIDENT_LIMIT: u64 = 32 * 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(1);
const VALID_QTRB_SEED: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../fixtures/qtrb/v1.2-completed.bin"
));

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

fn drain(provider: Box<dyn TraceProvider>, guard: &dyn WorkGuard) -> bool {
    let Ok(mut cursor) = provider.into_cursor() else {
        return false;
    };
    loop {
        match cursor.next_event(guard) {
            Ok(Some(_)) => {}
            Ok(None) => {
                return cursor.finish().is_ok();
            }
            Err(_) => return false,
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
        let _ = drain(Box::new(provider), &guard);
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
        let _ = drain(Box::new(provider), &guard);
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
        let _ = drain(Box::new(provider), &guard);
    }
}

pub fn expand_qtrb_seed(data: &[u8]) -> Vec<u8> {
    if data.len() > INPUT_LIMIT as usize {
        return Vec::new();
    }
    qtrb_seed(data)
}

pub fn qtrb_lz4_seed_fully_drains(data: &[u8]) -> bool {
    if data.len() > INPUT_LIMIT as usize {
        return false;
    }
    let bytes = qtrb_seed(data);
    let guard = StrictGuard::new();
    let Ok(source) = QtrbInput::lz4(std::io::Cursor::new(bytes)).into_source(&guard) else {
        return false;
    };
    let source_bytes = source.len();
    let Ok(provider) = QtrbProvider::open(source, identity(source_bytes), OpenMode::Sealed, &guard)
    else {
        return false;
    };
    drain(Box::new(provider), &guard)
}

fn qtrb_seed(data: &[u8]) -> Vec<u8> {
    if let Some(seed) = compressed_qtrb_seed(data) {
        return seed;
    }
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
        (b"qtrb:v1.2-completed\n", VALID_QTRB_SEED),
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

fn compressed_qtrb_seed(data: &[u8]) -> Option<Vec<u8>> {
    let (prefix, mut output) = if data.starts_with(b"qtrb-lz4:standard\n") {
        (
            &b"qtrb-lz4:standard\n"[..],
            encode_frame(VALID_QTRB_SEED, BlockMode::Independent, false)?,
        )
    } else if data.starts_with(b"qtrb-lz4:linked-blocks\n") {
        (
            &b"qtrb-lz4:linked-blocks\n"[..],
            encode_frame(VALID_QTRB_SEED, BlockMode::Linked, true)?,
        )
    } else if data.starts_with(b"qtrb-lz4:concatenated-frames\n") {
        let prefix = &b"qtrb-lz4:concatenated-frames\n"[..];
        let split = VALID_QTRB_SEED.len() / 2;
        let mut first = encode_frame(&VALID_QTRB_SEED[..split], BlockMode::Independent, false)?;
        first.extend(encode_frame(
            &VALID_QTRB_SEED[split..],
            BlockMode::Independent,
            false,
        )?);
        (prefix, first)
    } else {
        return None;
    };
    apply_patches(&mut output, data.strip_prefix(prefix)?);
    Some(output)
}

fn encode_frame(payload: &[u8], mode: BlockMode, split_blocks: bool) -> Option<Vec<u8>> {
    let content_size = u64::try_from(payload.len()).ok()?;
    let frame = FrameInfo::new()
        .block_mode(mode)
        .block_size(BlockSize::Max64KB)
        .content_size(Some(content_size));
    let mut encoder = FrameEncoder::with_frame_info(frame, Vec::new());
    if split_blocks {
        let split = payload.len() / 2;
        encoder.write_all(&payload[..split]).ok()?;
        encoder.flush().ok()?;
        encoder.write_all(&payload[split..]).ok()?;
    } else {
        encoder.write_all(payload).ok()?;
    }
    encoder.finish().ok()
}

fn apply_patches(output: &mut [u8], patches: &[u8]) {
    if output.is_empty() {
        return;
    }
    for patch in patches.chunks_exact(3) {
        let offset = usize::from(u16::from_le_bytes([patch[0], patch[1]])) % output.len();
        output[offset] ^= patch[2];
    }
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
        apply_patches(&mut output, patches);
        return Some(output);
    }
    None
}
