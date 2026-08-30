use std::{
    io::{Cursor, Error, ErrorKind, Read},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use qtrace_provider::{
    BudgetDimension, OperationAbort, QtrbInput, ReadAtSource, WorkDelta, WorkGuard,
};
use twox_hash::XxHash32;

const MAGIC: [u8; 4] = 0x184d_2204_u32.to_le_bytes();

#[derive(Clone)]
struct TestBlock {
    encoded: Vec<u8>,
    decoded: Vec<u8>,
    raw: bool,
}

#[derive(Clone, Copy, Default)]
struct FrameOptions {
    independent: bool,
    block_checksum: bool,
    content_size: bool,
    content_checksum: bool,
    dictionary_id: Option<u32>,
}

fn checksum(bytes: &[u8]) -> u32 {
    use std::hash::Hasher;

    let mut hasher = XxHash32::with_seed(0);
    hasher.write(bytes);
    hasher.finish_32()
}

fn test_frame(blocks: &[TestBlock], options: FrameOptions) -> Vec<u8> {
    let mut frame = MAGIC.to_vec();
    let mut descriptor = vec![
        0x40 | (u8::from(options.independent) * 0x20)
            | (u8::from(options.block_checksum) * 0x10)
            | (u8::from(options.content_size) * 0x08)
            | (u8::from(options.content_checksum) * 0x04)
            | u8::from(options.dictionary_id.is_some()),
        0x40,
    ];
    let decoded: Vec<u8> = blocks
        .iter()
        .flat_map(|block| block.decoded.iter().copied())
        .collect();
    if options.content_size {
        descriptor.extend_from_slice(&(decoded.len() as u64).to_le_bytes());
    }
    if let Some(dictionary_id) = options.dictionary_id {
        descriptor.extend_from_slice(&dictionary_id.to_le_bytes());
    }
    let header_checksum = (checksum(&descriptor) >> 8) as u8;
    frame.extend_from_slice(&descriptor);
    frame.push(header_checksum);
    for block in blocks {
        let size =
            u32::try_from(block.encoded.len()).unwrap() | if block.raw { 0x8000_0000 } else { 0 };
        frame.extend_from_slice(&size.to_le_bytes());
        frame.extend_from_slice(&block.encoded);
        if options.block_checksum {
            frame.extend_from_slice(&checksum(&block.encoded).to_le_bytes());
        }
    }
    frame.extend_from_slice(&0_u32.to_le_bytes());
    if options.content_checksum {
        frame.extend_from_slice(&checksum(&decoded).to_le_bytes());
    }
    frame
}

fn raw_block(bytes: &[u8]) -> TestBlock {
    TestBlock {
        encoded: bytes.to_vec(),
        decoded: bytes.to_vec(),
        raw: true,
    }
}

fn compressed_block(bytes: &[u8]) -> TestBlock {
    TestBlock {
        encoded: lz4_flex::block::compress(bytes),
        decoded: bytes.to_vec(),
        raw: false,
    }
}

fn decode(reader: impl Read + Send + 'static, guard: &dyn WorkGuard) -> Result<Vec<u8>, String> {
    QtrbInput::lz4(reader)
        .into_source(guard)
        .map(|source| {
            let mut bytes = vec![0; source.len() as usize];
            source.read_exact_at(0, &mut bytes).unwrap();
            bytes
        })
        .map_err(|error| format!("{}:{}", error.code(), error.detail()))
}

struct AllowAll;

impl WorkGuard for AllowAll {
    fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
        Ok(())
    }
}

#[test]
fn descriptor_options_checksums_and_dictionary_id_are_validated() {
    let payload = b"descriptor-options";
    let options = FrameOptions {
        independent: true,
        block_checksum: true,
        content_size: true,
        content_checksum: true,
        dictionary_id: Some(0x1234_5678),
    };
    let frame = test_frame(&[compressed_block(payload)], options);
    assert_eq!(
        decode(Cursor::new(frame.clone()), &AllowAll).unwrap(),
        payload
    );

    let mut bad_header = frame.clone();
    let header_checksum = 4 + 2 + 8 + 4;
    bad_header[header_checksum] ^= 1;
    assert!(
        decode(Cursor::new(bad_header), &AllowAll)
            .unwrap_err()
            .contains("compression")
    );

    let mut bad_block = frame.clone();
    let block_checksum = header_checksum + 1 + 4 + compressed_block(payload).encoded.len();
    bad_block[block_checksum] ^= 1;
    assert!(
        decode(Cursor::new(bad_block), &AllowAll)
            .unwrap_err()
            .contains("compression")
    );

    let mut bad_content = frame;
    *bad_content.last_mut().unwrap() ^= 1;
    assert!(
        decode(Cursor::new(bad_content), &AllowAll)
            .unwrap_err()
            .contains("compression")
    );
}

#[test]
fn independent_and_linked_compressed_blocks_decode() {
    let first = vec![b'a'; 512];
    let second = first[128..384].to_vec();
    let independent = test_frame(
        &[compressed_block(&first), compressed_block(&second)],
        FrameOptions {
            independent: true,
            ..FrameOptions::default()
        },
    );
    assert_eq!(
        decode(Cursor::new(independent), &AllowAll).unwrap(),
        [first.clone(), second.clone()].concat()
    );

    let linked_second = TestBlock {
        encoded: lz4_flex::block::compress_with_dict(&second, &first),
        decoded: second.clone(),
        raw: false,
    };
    let linked = test_frame(&[raw_block(&first), linked_second], FrameOptions::default());
    assert_eq!(
        decode(Cursor::new(linked), &AllowAll).unwrap(),
        [first, second].concat()
    );
}

#[test]
fn concatenated_linked_frames_reset_history_between_frames() {
    let dictionary = b"frame one dictionary phrase frame one dictionary phrase";
    let payload = b"frame one dictionary phrase";
    let first = test_frame(&[raw_block(dictionary)], FrameOptions::default());
    let dependent = TestBlock {
        encoded: lz4_flex::block::compress_with_dict(payload, dictionary),
        decoded: payload.to_vec(),
        raw: false,
    };
    let second = test_frame(&[dependent], FrameOptions::default());
    let error = decode(Cursor::new([first, second].concat()), &AllowAll).unwrap_err();

    assert!(error.starts_with("source.qtrb.compression"), "{error}");
}

#[test]
fn dictionary_id_accepts_self_contained_blocks_and_rejects_required_unknown_dictionary() {
    let self_contained = test_frame(
        &[compressed_block(b"self-contained self-contained")],
        FrameOptions {
            independent: true,
            dictionary_id: Some(7),
            ..FrameOptions::default()
        },
    );
    assert_eq!(
        decode(Cursor::new(self_contained), &AllowAll).unwrap(),
        b"self-contained self-contained"
    );

    let dictionary = b"external dictionary phrase external dictionary phrase";
    let payload = b"external dictionary phrase";
    let dependent = TestBlock {
        encoded: lz4_flex::block::compress_with_dict(payload, dictionary),
        decoded: payload.to_vec(),
        raw: false,
    };
    let frame = test_frame(
        &[dependent],
        FrameOptions {
            independent: true,
            dictionary_id: Some(9),
            ..FrameOptions::default()
        },
    );
    let error = decode(Cursor::new(frame), &AllowAll).unwrap_err();
    assert!(error.contains("unavailable dictionary 9"), "{error}");
}

struct ShortReads<R> {
    inner: R,
    maximum: usize,
}

impl<R: Read> Read for ShortReads<R> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let request = output.len().min(self.maximum);
        self.inner.read(&mut output[..request])
    }
}

#[derive(Default)]
struct Totals(Mutex<WorkDelta>);

impl WorkGuard for Totals {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        let mut totals = self.0.lock().unwrap();
        totals.input_bytes += delta.input_bytes;
        totals.decompressed_bytes += delta.decompressed_bytes;
        totals.events += delta.events;
        totals.nodes += delta.nodes;
        totals.rows += delta.rows;
        totals.resident_bytes += delta.resident_bytes;
        Ok(())
    }
}

#[test]
fn charges_do_not_depend_on_underlying_short_read_pattern() {
    let payload = vec![0x5a; 4096];
    let frame = test_frame(
        &[compressed_block(&payload)],
        FrameOptions {
            independent: true,
            ..FrameOptions::default()
        },
    );
    let mut charged = Vec::new();
    for maximum in [1, 7, usize::MAX] {
        let guard = Totals::default();
        let actual = decode(
            ShortReads {
                inner: Cursor::new(frame.clone()),
                maximum,
            },
            &guard,
        )
        .unwrap();
        assert_eq!(actual, payload);
        let totals = *guard.0.lock().unwrap();
        charged.push((totals.input_bytes, totals.decompressed_bytes));
    }
    assert_eq!(charged[0], charged[1]);
    assert_eq!(charged[1], charged[2]);
    assert_eq!(charged[0].0, frame.len() as u64 + 1);
}

#[test]
fn raw_charges_exact_bytes_plus_one_eof_probe_for_every_reader() {
    let raw = vec![0x6b; 257];
    for maximum in [1, 7, usize::MAX] {
        let guard = Totals::default();
        let source = QtrbInput::raw(ShortReads {
            inner: Cursor::new(raw.clone()),
            maximum,
        })
        .into_source(&guard)
        .unwrap();
        let totals = *guard.0.lock().unwrap();
        assert_eq!(totals.input_bytes, raw.len() as u64 + 1);
        let mut actual = vec![0; source.len() as usize];
        source.read_exact_at(0, &mut actual).unwrap();
        assert_eq!(actual, raw);
    }

    QtrbInput::raw(Cursor::new(raw.clone()))
        .into_source(&LimitInput {
            remaining: Mutex::new(raw.len() as u64 + 1),
        })
        .unwrap();
}

struct LimitInput {
    remaining: Mutex<u64>,
}

impl WorkGuard for LimitInput {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        let mut remaining = self.remaining.lock().unwrap();
        if delta.input_bytes > *remaining {
            return Err(OperationAbort::budget_exceeded(
                BudgetDimension::InputBytes,
                *remaining,
                delta.input_bytes,
            ));
        }
        *remaining -= delta.input_bytes;
        Ok(())
    }
}

struct CountedReader {
    inner: Cursor<Vec<u8>>,
    bytes_read: Arc<AtomicUsize>,
}

impl Read for CountedReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(output)?;
        self.bytes_read.fetch_add(read, Ordering::SeqCst);
        Ok(read)
    }
}

#[test]
fn finite_input_budget_stops_before_block_payload_io() {
    let frame = test_frame(&[raw_block(&[0x33; 128])], FrameOptions::default());
    let payload_offset = 4 + 3 + 4;
    let bytes_read = Arc::new(AtomicUsize::new(0));
    let error = decode(
        CountedReader {
            inner: Cursor::new(frame),
            bytes_read: bytes_read.clone(),
        },
        &LimitInput {
            remaining: Mutex::new(payload_offset as u64),
        },
    )
    .unwrap_err();
    assert!(error.starts_with("control.budget_exceeded"), "{error}");
    assert_eq!(bytes_read.load(Ordering::SeqCst), payload_offset);
}

struct RejectDecompression;

impl WorkGuard for RejectDecompression {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        if delta.decompressed_bytes != 0 {
            return Err(OperationAbort::budget_exceeded(
                BudgetDimension::DecompressedBytes,
                0,
                delta.decompressed_bytes,
            ));
        }
        Ok(())
    }
}

#[test]
fn decompressed_budget_stops_before_decode_and_footer_io() {
    let block = compressed_block(&vec![0x44; 4096]);
    let payload_end = 4 + 3 + 4 + block.encoded.len();
    let frame = test_frame(&[block], FrameOptions::default());
    let bytes_read = Arc::new(AtomicUsize::new(0));
    let error = decode(
        CountedReader {
            inner: Cursor::new(frame),
            bytes_read: bytes_read.clone(),
        },
        &RejectDecompression,
    )
    .unwrap_err();
    assert!(error.starts_with("control.budget_exceeded"), "{error}");
    assert_eq!(bytes_read.load(Ordering::SeqCst), payload_end);
}

struct CancelAfterNodes {
    remaining: Mutex<u64>,
}

impl WorkGuard for CancelAfterNodes {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        let mut remaining = self.remaining.lock().unwrap();
        if delta.nodes > *remaining {
            return Err(OperationAbort::Cancelled);
        }
        *remaining -= delta.nodes;
        Ok(())
    }
}

#[test]
fn many_zero_blocks_remain_cancellable() {
    let blocks = vec![raw_block(&[]); 100];
    let frame = test_frame(&blocks, FrameOptions::default());
    let error = decode(
        Cursor::new(frame),
        &CancelAfterNodes {
            remaining: Mutex::new(8),
        },
    )
    .unwrap_err();
    assert!(error.starts_with("control.cancelled"), "{error}");
}

struct ZeroReader;

impl Read for ZeroReader {
    fn read(&mut self, _output: &mut [u8]) -> std::io::Result<usize> {
        Ok(0)
    }
}

struct ErrorReader;

impl Read for ErrorReader {
    fn read(&mut self, _output: &mut [u8]) -> std::io::Result<usize> {
        Err(Error::other("raw read failed"))
    }
}

struct OverreportReader;

impl Read for OverreportReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        Ok(output.len() + 1)
    }
}

struct InterruptedReader;

impl Read for InterruptedReader {
    fn read(&mut self, _output: &mut [u8]) -> std::io::Result<usize> {
        Err(Error::new(ErrorKind::Interrupted, "never makes progress"))
    }
}

#[test]
fn malformed_lengths_zero_reads_and_raw_io_errors_fail_stably() {
    let mut oversized = test_frame(&[], FrameOptions::default());
    oversized.splice(7..11, (64_u32 * 1024 + 1).to_le_bytes());
    let error = decode(Cursor::new(oversized), &AllowAll).unwrap_err();
    assert!(error.starts_with("source.qtrb.compression"), "{error}");

    let error = decode(ZeroReader, &AllowAll).unwrap_err();
    assert!(error.starts_with("source.qtrb.compression"), "{error}");

    let error = decode(OverreportReader, &AllowAll).unwrap_err();
    assert!(error.starts_with("source.qtrb.compression"), "{error}");

    let error = decode(InterruptedReader, &AllowAll).unwrap_err();
    assert!(error.starts_with("source.qtrb.compression"), "{error}");

    let mut impossible_content_size = test_frame(
        &[raw_block(b"payload")],
        FrameOptions {
            content_size: true,
            ..FrameOptions::default()
        },
    );
    impossible_content_size[6..14].copy_from_slice(&u64::MAX.to_le_bytes());
    impossible_content_size[14] = (checksum(&impossible_content_size[4..14]) >> 8) as u8;
    let error = decode(Cursor::new(impossible_content_size), &AllowAll).unwrap_err();
    assert!(error.starts_with("source.qtrb.compression"), "{error}");

    let error = QtrbInput::raw(ErrorReader)
        .into_source(&AllowAll)
        .unwrap_err();
    assert_ne!(error.code(), "source.qtrb.compression");

    let error = QtrbInput::raw(InterruptedReader)
        .into_source(&AllowAll)
        .unwrap_err();
    assert_eq!(error.code(), "source.qtrb.io");
}
