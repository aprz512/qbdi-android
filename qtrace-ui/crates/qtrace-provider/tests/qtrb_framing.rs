use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use qtrace_provider::{
    ArtifactDigest, ByteSource, CompletenessCause, EventKind, EventPayload, OpenMode, Provenance,
    ProviderError, QtrbProvider, RangeBounds, ReadAtSource, SourceIdentity, TerminationKind,
    TraceProvider, WorkDelta, WorkGuard,
};

const HEADER_BYTES: usize = 16;
const RECORD_HEADER_BYTES: usize = 8;
const TRACE_BEGIN_PAYLOAD_MAX: u32 = 564;
const MODULE_PAYLOAD_MAX: u32 = 269;
const INSTRUCTION_DEFINITION_PAYLOAD_MAX: u32 = 1_638;
const INSTRUCTION_PAYLOAD_MAX: u32 = 570;
const MEMORY_PAYLOAD_MAX: u32 = 168;
const CALL_PAYLOAD_MAX: u32 = 4_612;
const CALL_CHUNK_PAYLOAD_MAX: u32 = 3_604;
const RULE_ERROR_PAYLOAD_MAX: u32 = 4_355;
const EVENT_CHUNK_PAYLOAD_MAX: u32 = 3_347;
const TRACE_END_PAYLOAD_BYTES: u32 = 97;
const TRACE_STOP_PAYLOAD_BYTES: u32 = 96;
const MAX_OPAQUE_PAYLOAD_BYTES: u32 = 4_612;

#[derive(Debug)]
struct Parsed {
    events: Vec<qtrace_provider::EventRecord>,
    summary: qtrace_provider::ProviderSummary,
}

#[derive(Default)]
struct AllowAll;

impl WorkGuard for AllowAll {
    fn consume(&self, _delta: WorkDelta) -> Result<(), qtrace_provider::OperationAbort> {
        Ok(())
    }
}

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/qtrb")
        .join(name);
    std::fs::read(path).unwrap()
}

fn identity(source_bytes: u64) -> SourceIdentity {
    SourceIdentity {
        artifact: ArtifactDigest::new([0x41; 32]),
        format: "QTRB".to_owned(),
        format_major: 0,
        format_minor: 0,
        source_bytes,
    }
}

fn open_bytes(bytes: Vec<u8>, mode: OpenMode) -> Result<QtrbProvider, ProviderError> {
    let source_bytes = bytes.len() as u64;
    QtrbProvider::open(
        Arc::new(ByteSource::new(bytes)),
        identity(source_bytes),
        mode,
        &AllowAll,
    )
}

fn collect_bytes(bytes: Vec<u8>, mode: OpenMode) -> Result<Parsed, ProviderError> {
    let provider = open_bytes(bytes, mode)?;
    let mut cursor = Box::new(provider).into_cursor()?;
    let mut events = Vec::new();
    while let Some(event) = cursor.next_event(&AllowAll)? {
        events.push(event);
    }
    Ok(Parsed {
        events,
        summary: cursor.finish()?,
    })
}

fn collect_fixture(name: &str, mode: OpenMode) -> Result<Parsed, ProviderError> {
    collect_bytes(fixture(name), mode)
}

fn assert_error(bytes: Vec<u8>, mode: OpenMode, code: &str) {
    let error = match collect_bytes(bytes, mode) {
        Ok(parsed) => panic!("expected {code}, got {parsed:?}"),
        Err(error) => error,
    };
    assert_eq!(error.code(), code);
    assert!(error.detail().len() <= 512);
    assert!(!error.detail().contains(['\r', '\n']));
}

fn le16(value: u16) -> [u8; 2] {
    value.to_le_bytes()
}

fn le32(value: u32) -> [u8; 4] {
    value.to_le_bytes()
}

fn le64(value: u64) -> [u8; 8] {
    value.to_le_bytes()
}

fn wire_string(value: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(2 + value.len());
    result.extend_from_slice(&le16(value.len() as u16));
    result.extend_from_slice(value);
    result
}

fn header(minor: u8, features: u32) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER_BYTES);
    bytes.extend_from_slice(b"QTRB");
    bytes.extend_from_slice(&[1, minor, 1, 8, 2, 0]);
    bytes.extend_from_slice(&le16(HEADER_BYTES as u16));
    bytes.extend_from_slice(&le32(features));
    bytes
}

fn record(record_type: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(RECORD_HEADER_BYTES + payload.len());
    bytes.extend_from_slice(&le16(record_type));
    bytes.extend_from_slice(&le16(flags));
    bytes.extend_from_slice(&le32(payload.len() as u32));
    bytes.extend_from_slice(payload);
    bytes
}

fn begin_payload(profile: u8) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&le64(0x100000));
    payload.extend_from_slice(&le64(0x40));
    payload.extend_from_slice(&le64(0x100040));
    payload.extend_from_slice(&le32(12));
    payload.extend_from_slice(&le32(13));
    payload.extend_from_slice(&[profile, 0]);
    payload.extend_from_slice(&le64(4096));
    payload.extend_from_slice(&le64(7));
    payload.extend_from_slice(&wire_string(b"scene"));
    payload.extend_from_slice(&wire_string(b"target"));
    payload
}

fn begin(profile: u8) -> Vec<u8> {
    record(1, 0, &begin_payload(profile))
}

fn module(module_id: u32, base: u64, name: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&le32(module_id));
    payload.extend_from_slice(&le64(base));
    payload.extend_from_slice(&wire_string(name));
    record(2, 0, &payload)
}

fn instruction_definition(metadata_id: u32, opcode: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&le32(metadata_id));
    payload.extend_from_slice(&le32(opcode));
    payload.extend_from_slice(&le64(0));
    payload.extend_from_slice(&le64(0));
    payload.extend_from_slice(&0_i64.to_le_bytes());
    payload.extend_from_slice(&le32(0));
    payload.extend_from_slice(&[0, 0, 0, 0]);
    payload.extend_from_slice(&wire_string(b"nop"));
    payload.extend_from_slice(&wire_string(b""));
    payload.extend_from_slice(&wire_string(b"nop"));
    record(3, 0, &payload)
}

fn instruction(sequence: u64, module_id: u32, metadata_id: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&le64(sequence));
    payload.extend_from_slice(&le32(module_id));
    payload.extend_from_slice(&le64(0x20));
    payload.extend_from_slice(&le32(metadata_id));
    payload.extend_from_slice(&[0, 0]);
    record(4, 0, &payload)
}

fn terminal_payload(
    success: u8,
    instructions: u64,
    encoded_bytes: u64,
    effective_buffer: u64,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(success);
    payload.extend_from_slice(&le64(0x55));
    payload.extend_from_slice(&le64(17));
    for value in [
        instructions,
        encoded_bytes,
        encoded_bytes,
        0,
        0,
        0,
        0,
        0,
        0,
        effective_buffer,
    ] {
        payload.extend_from_slice(&le64(value));
    }
    payload
}

fn completed_stream(records: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = header(2, 1);
    bytes.extend_from_slice(&begin(2));
    for item in records {
        bytes.extend_from_slice(item);
    }
    let instructions = records
        .iter()
        .filter(|item| u16::from_le_bytes([item[0], item[1]]) == 4)
        .count() as u64;
    let encoded_bytes =
        (bytes.len() + RECORD_HEADER_BYTES + TRACE_END_PAYLOAD_BYTES as usize) as u64;
    bytes.extend_from_slice(&record(
        9,
        0,
        &terminal_payload(success_status(), instructions, encoded_bytes, 4096),
    ));
    bytes
}

const fn success_status() -> u8 {
    1
}

fn header_with_first_record(record: Vec<u8>) -> Vec<u8> {
    let mut bytes = header(2, 1);
    bytes.extend_from_slice(&record);
    bytes
}

#[test]
fn supports_exact_qtrb_minor_and_feature_matrix() {
    for (name, kind) in [
        ("v1.0-completed.bin", TerminationKind::Completed),
        ("v1.1-chunked.bin", TerminationKind::Completed),
        ("v1.2-completed.bin", TerminationKind::Completed),
        ("v1.2-stopped.bin", TerminationKind::Stopped),
    ] {
        let source = fixture(name);
        let provider = open_bytes(source.clone(), OpenMode::Sealed).unwrap();
        assert_eq!(provider.identity().artifact, identity(0).artifact);
        assert_eq!(provider.identity().format, "QTRB");
        assert_eq!(provider.identity().format_major, 1);
        assert_eq!(provider.identity().format_minor, name.as_bytes()[3] - b'0');
        assert_eq!(provider.identity().source_bytes, source.len() as u64);
        assert!(!provider.capabilities().global_ordering);
        assert!(provider.capabilities().per_thread_ordering);
        assert!(provider.capabilities().register_read_write_observation);
        let parsed = collect_fixture(name, OpenMode::Sealed).unwrap();
        assert_eq!(parsed.summary.termination.unwrap().kind, kind, "{name}");
        assert_eq!(
            parsed.summary.counters.input_bytes,
            fixture(name).len() as u64
        );
    }

    for (minor, features) in [(0, 1), (1, 1), (2, 0), (2, 2), (3, 0)] {
        let mut bytes = header(minor, features);
        bytes.extend_from_slice(&begin(2));
        assert_error(bytes, OpenMode::Sealed, "source.version_unsupported");
    }
}

#[test]
fn partial_mode_never_invents_a_terminal() {
    let bytes = fixture("v1.2-partial.bin");
    let parsed = collect_bytes(bytes.clone(), OpenMode::RecoverablePartial).unwrap();
    assert!(parsed.summary.termination.is_none());
    assert!(
        !parsed
            .events
            .iter()
            .any(|event| event.kind() == EventKind::Termination)
    );
    assert!(parsed.summary.completeness.iter().any(|range| {
        range.provenance() == Provenance::Unknown
            && range.cause() == CompletenessCause::MissingTerminal
            && range.bounds()
                == (RangeBounds::HalfOpen {
                    start: bytes.len() as u64,
                    end_exclusive: bytes.len() as u64,
                })
    }));
    assert_error(bytes, OpenMode::Sealed, "source.missing_terminal");
}

#[test]
fn checked_in_malformed_corpus_fails_closed() {
    let cases = [
        ("malformed/bad-header.bin", "source.invalid_header"),
        (
            "malformed/unsupported-feature.bin",
            "source.version_unsupported",
        ),
        (
            "malformed/undefined-metadata.bin",
            "source.undefined_reference",
        ),
        ("malformed/sequence-gap.bin", "source.sequence_gap"),
        ("malformed/oversized-record.bin", "source.record_too_large"),
        ("malformed/truncated-payload.bin", "source.short_read"),
        (
            "malformed/record-after-terminal.bin",
            "source.record_after_terminal",
        ),
    ];
    for (name, code) in cases {
        assert_error(fixture(name), OpenMode::Sealed, code);
    }
}

#[test]
fn validates_every_field_of_the_exact_sixteen_byte_header() {
    for length in 0..HEADER_BYTES {
        assert_error(
            header(2, 1)[..length].to_vec(),
            OpenMode::Sealed,
            "source.short_read",
        );
    }

    let mutations: &[(usize, u8, &str)] = &[
        (0, b'X', "source.invalid_header"),
        (4, 2, "source.version_unsupported"),
        (6, 2, "source.invalid_header"),
        (7, 3, "source.invalid_header"),
        (8, 3, "source.invalid_header"),
        (9, 1, "source.invalid_header"),
        (10, 15, "source.invalid_header"),
    ];
    for &(offset, value, code) in mutations {
        let mut bytes = header(2, 1);
        bytes[offset] = value;
        assert_error(bytes, OpenMode::Sealed, code);
    }

    let mut big_endian_size = header(2, 1);
    big_endian_size[10..12].copy_from_slice(&16_u16.to_be_bytes());
    assert_error(big_endian_size, OpenMode::Sealed, "source.invalid_header");
}

#[test]
fn validates_record_flags_types_and_per_type_payload_maxima_before_payload_read() {
    for (record_type, flags) in [
        (1, 1),
        (2, 1),
        (3, 1),
        (4, 1),
        (5, 1),
        (6, 2),
        (7, 2),
        (8, 2),
        (9, 1),
        (10, 1),
    ] {
        let bytes = header_with_first_record(record(record_type, flags, &[]));
        assert_error(bytes, OpenMode::Sealed, "source.unsupported_record");
    }
    for record_type in [0, 11, 0x7fff] {
        let bytes = header_with_first_record(record(record_type, 0, &[]));
        assert_error(bytes, OpenMode::Sealed, "source.unsupported_record");
    }

    let maxima = [
        (1, 0, TRACE_BEGIN_PAYLOAD_MAX),
        (2, 0, MODULE_PAYLOAD_MAX),
        (3, 0, INSTRUCTION_DEFINITION_PAYLOAD_MAX),
        (4, 0, INSTRUCTION_PAYLOAD_MAX),
        (5, 0, MEMORY_PAYLOAD_MAX),
        (6, 0, CALL_PAYLOAD_MAX),
        (6, 1, CALL_CHUNK_PAYLOAD_MAX),
        (7, 0, RULE_ERROR_PAYLOAD_MAX),
        (7, 1, EVENT_CHUNK_PAYLOAD_MAX),
        (8, 0, RULE_ERROR_PAYLOAD_MAX),
        (8, 1, EVENT_CHUNK_PAYLOAD_MAX),
        (9, 0, TRACE_END_PAYLOAD_BYTES),
        (10, 0, TRACE_STOP_PAYLOAD_BYTES),
        (0x8000, 0, MAX_OPAQUE_PAYLOAD_BYTES),
    ];
    for (record_type, flags, maximum) in maxima {
        let mut bytes = header(2, 1);
        bytes.extend_from_slice(&le16(record_type));
        bytes.extend_from_slice(&le16(flags));
        bytes.extend_from_slice(&le32(maximum + 1));
        assert_error(bytes, OpenMode::Sealed, "source.record_too_large");
    }
}

#[test]
fn accepts_short_source_reads_but_rejects_truncation_at_every_boundary() {
    #[derive(Clone)]
    struct ThreeByteSource(Arc<[u8]>);

    impl ReadAtSource for ThreeByteSource {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }

        fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), ProviderError> {
            let start = usize::try_from(offset).unwrap();
            let end = start.checked_add(output.len()).unwrap();
            if end > self.0.len() {
                return Err(ProviderError::new(
                    "source.short_read",
                    "read",
                    None,
                    false,
                    "short source",
                ));
            }
            for (destination, chunk) in output.chunks_mut(3).zip(self.0[start..end].chunks(3)) {
                destination.copy_from_slice(chunk);
            }
            Ok(())
        }
    }

    let valid = fixture("v1.2-completed.bin");
    let provider = QtrbProvider::open(
        Arc::new(ThreeByteSource(Arc::from(valid.clone()))),
        identity(valid.len() as u64),
        OpenMode::Sealed,
        &AllowAll,
    )
    .unwrap();
    let mut cursor = Box::new(provider).into_cursor().unwrap();
    while cursor.next_event(&AllowAll).unwrap().is_some() {}
    cursor.finish().unwrap();

    let mut complete_boundaries = vec![HEADER_BYTES];
    let mut offset = HEADER_BYTES;
    while offset < valid.len() {
        let payload = u32::from_le_bytes(valid[offset + 4..offset + 8].try_into().unwrap());
        offset += RECORD_HEADER_BYTES + payload as usize;
        complete_boundaries.push(offset);
    }
    for end in HEADER_BYTES..valid.len() {
        if end == HEADER_BYTES {
            assert_error(
                valid[..end].to_vec(),
                OpenMode::RecoverablePartial,
                "source.invalid_order",
            );
        } else if complete_boundaries.contains(&end) {
            let parsed =
                collect_bytes(valid[..end].to_vec(), OpenMode::RecoverablePartial).unwrap();
            assert!(parsed.summary.termination.is_none());
        } else {
            assert_error(
                valid[..end].to_vec(),
                OpenMode::RecoverablePartial,
                "source.short_read",
            );
        }
    }
}

#[test]
fn enforces_begin_definition_reference_sequence_and_terminal_lifecycle() {
    assert_error(
        header_with_first_record(module(1, 0x100000, b"lib.so")),
        OpenMode::Sealed,
        "source.invalid_order",
    );

    let duplicate_begin = completed_stream(&[begin(2)]);
    assert_error(duplicate_begin, OpenMode::Sealed, "source.invalid_order");

    let conflicting_module = completed_stream(&[
        module(1, 0x100000, b"lib.so"),
        module(1, 0x100000, b"other.so"),
    ]);
    assert_error(
        conflicting_module,
        OpenMode::Sealed,
        "source.definition_conflict",
    );

    let conflicting_definition = completed_stream(&[
        module(1, 0x100000, b"lib.so"),
        instruction_definition(9, 1),
        instruction_definition(9, 2),
    ]);
    assert_error(
        conflicting_definition,
        OpenMode::Sealed,
        "source.definition_conflict",
    );

    let missing_module = completed_stream(&[instruction_definition(9, 1), instruction(1, 2, 9)]);
    assert_error(
        missing_module,
        OpenMode::Sealed,
        "source.undefined_reference",
    );

    let missing_metadata =
        completed_stream(&[module(1, 0x100000, b"lib.so"), instruction(1, 1, 9)]);
    assert_error(
        missing_metadata,
        OpenMode::Sealed,
        "source.undefined_reference",
    );

    let gap = completed_stream(&[
        module(1, 0x100000, b"lib.so"),
        instruction_definition(9, 1),
        instruction(2, 1, 9),
    ]);
    assert_error(gap, OpenMode::Sealed, "source.sequence_gap");

    let valid = completed_stream(&[
        module(1, 0x100000, b"lib.so"),
        module(1, 0x100000, b"lib.so"),
        instruction_definition(9, 1),
        instruction_definition(9, 1),
        instruction(1, 1, 9),
    ]);
    collect_bytes(valid, OpenMode::Sealed).unwrap();
}

#[test]
fn rejects_bad_terminal_metrics_failed_end_and_records_after_terminal() {
    let base = completed_stream(&[]);
    let terminal_start = base.len() - (RECORD_HEADER_BYTES + TRACE_END_PAYLOAD_BYTES as usize);

    let mut failed = base.clone();
    failed[terminal_start + RECORD_HEADER_BYTES] = 0;
    assert_error(failed, OpenMode::Sealed, "source.invalid_terminal");

    let mut bad_encoded = base.clone();
    let encoded_offset = terminal_start + RECORD_HEADER_BYTES + 1 + 8 + 8 + 8;
    bad_encoded[encoded_offset..encoded_offset + 8].copy_from_slice(&le64(1));
    assert_error(
        bad_encoded,
        OpenMode::Sealed,
        "source.terminal_counter_mismatch",
    );

    let mut bad_buffer = base.clone();
    let effective_buffer_offset = terminal_start + RECORD_HEADER_BYTES + 1 + 8 + 8 + 9 * 8;
    bad_buffer[effective_buffer_offset..effective_buffer_offset + 8].copy_from_slice(&le64(8192));
    assert_error(
        bad_buffer,
        OpenMode::Sealed,
        "source.terminal_counter_mismatch",
    );

    let mut trailing = base;
    trailing.extend_from_slice(&record(0x8000, 0, b"x"));
    let provider = open_bytes(trailing, OpenMode::Sealed).unwrap();
    let mut cursor = Box::new(provider).into_cursor().unwrap();
    let mut emitted_terminal = false;
    let error = loop {
        match cursor.next_event(&AllowAll) {
            Ok(Some(event)) => emitted_terminal |= event.kind() == EventKind::Termination,
            Ok(None) => panic!("trailing record was accepted"),
            Err(error) => break error,
        }
    };
    assert_eq!(error.code(), "source.record_after_terminal");
    assert!(!emitted_terminal);
}

#[test]
fn preserves_physical_offsets_ordinals_and_bounded_optional_payloads() {
    let mut bytes = header(1, 0);
    let begin_offset = bytes.len() as u64;
    bytes.extend_from_slice(&begin(2));
    let optional_offset = bytes.len() as u64;
    bytes.extend_from_slice(&record(0x8000, 0, b"opaque"));
    let encoded_bytes =
        (bytes.len() + RECORD_HEADER_BYTES + TRACE_END_PAYLOAD_BYTES as usize) as u64;
    bytes.extend_from_slice(&record(9, 0, &terminal_payload(1, 0, encoded_bytes, 4096)));

    let parsed = collect_bytes(bytes, OpenMode::Sealed).unwrap();
    assert_eq!(parsed.events[0].key.record_ordinal, 0);
    assert_eq!(parsed.events[0].key.source_offset, begin_offset);
    assert_eq!(parsed.events[1].key.record_ordinal, 1);
    assert_eq!(parsed.events[1].key.source_offset, optional_offset);
    assert_eq!(parsed.summary.counters.records_seen, 3);
    assert_eq!(parsed.summary.counters.opaque_records, 1);
    match &parsed.events[1].payload {
        EventPayload::OpaqueOptional(optional) => {
            assert_eq!(optional.record_type, 0x8000);
            assert_eq!(optional.flags, 0);
            assert_eq!(optional.bytes, b"opaque");
        }
        payload => panic!("unexpected payload: {payload:?}"),
    }
}

#[test]
fn chunked_events_emit_once_with_the_first_physical_coordinate() {
    let bytes = fixture("v1.1-chunked.bin");
    let mut offset = HEADER_BYTES;
    let mut ordinal = 0_u64;
    let mut fragment_offsets = Vec::new();
    let mut first_chunk = None;
    while offset < bytes.len() {
        let record_type = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        let flags = u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]);
        let payload = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap());
        if record_type == 7 && flags == 1 {
            first_chunk.get_or_insert((ordinal, offset as u64));
            fragment_offsets.push(offset as u64);
        } else if !fragment_offsets.is_empty() {
            break;
        }
        offset += RECORD_HEADER_BYTES + payload as usize;
        ordinal += 1;
    }
    let expected = first_chunk.unwrap();

    let parsed = collect_bytes(bytes, OpenMode::Sealed).unwrap();
    let event = parsed
        .events
        .iter()
        .find(|event| event.kind() == EventKind::SemanticRule)
        .unwrap();
    assert_eq!(
        (event.key.record_ordinal, event.key.source_offset),
        expected
    );
    assert_eq!(event.fragment_source_offsets(), fragment_offsets);
    assert_eq!(
        parsed
            .events
            .iter()
            .filter(|event| event.kind() == EventKind::SemanticRule)
            .count(),
        1
    );
}

#[test]
fn rejects_incomplete_or_invalid_utf8_fragments_even_in_partial_mode() {
    let mut bytes = header(1, 0);
    bytes.extend_from_slice(&begin(2));
    let mut chunk = Vec::new();
    chunk.extend_from_slice(&le64(1));
    chunk.extend_from_slice(&le32(2));
    chunk.extend_from_slice(&le16(0));
    chunk.extend_from_slice(&le16(2));
    chunk.extend_from_slice(&wire_string(b"rule"));
    chunk.extend_from_slice(&wire_string(&[0xff]));
    bytes.extend_from_slice(&record(7, 1, &chunk));
    assert_error(
        bytes.clone(),
        OpenMode::RecoverablePartial,
        "source.incomplete_fragment",
    );

    let mut complete = bytes[..HEADER_BYTES + begin(2).len()].to_vec();
    complete.extend_from_slice(&record(7, 1, &chunk));
    let mut final_chunk = Vec::new();
    final_chunk.extend_from_slice(&le64(1));
    final_chunk.extend_from_slice(&le32(2));
    final_chunk.extend_from_slice(&le16(1));
    final_chunk.extend_from_slice(&le16(2));
    final_chunk.extend_from_slice(&wire_string(b"rule"));
    final_chunk.extend_from_slice(&wire_string(b"x"));
    complete.extend_from_slice(&record(7, 1, &final_chunk));
    assert_error(
        complete,
        OpenMode::RecoverablePartial,
        "source.invalid_utf8",
    );
}

#[test]
fn work_guard_applies_to_open_and_streaming_without_publishing_a_summary() {
    #[derive(Default)]
    struct Limit {
        bytes: Mutex<u64>,
        events: Mutex<u64>,
        nodes: Mutex<u64>,
        resident_bytes: Mutex<u64>,
        byte_limit: u64,
        event_limit: u64,
        node_limit: u64,
        resident_limit: u64,
    }

    impl WorkGuard for Limit {
        fn consume(&self, delta: WorkDelta) -> Result<(), qtrace_provider::OperationAbort> {
            let mut bytes = self.bytes.lock().unwrap();
            let mut events = self.events.lock().unwrap();
            let mut nodes = self.nodes.lock().unwrap();
            let mut resident_bytes = self.resident_bytes.lock().unwrap();
            *bytes += delta.input_bytes;
            *events += delta.events;
            *nodes += delta.nodes;
            *resident_bytes += delta.resident_bytes;
            if *bytes > self.byte_limit {
                return Err(qtrace_provider::OperationAbort::budget_exceeded(
                    qtrace_provider::BudgetDimension::InputBytes,
                    self.byte_limit,
                    *bytes,
                ));
            }
            if *events > self.event_limit {
                return Err(qtrace_provider::OperationAbort::budget_exceeded(
                    qtrace_provider::BudgetDimension::Events,
                    self.event_limit,
                    *events,
                ));
            }
            if *nodes > self.node_limit {
                return Err(qtrace_provider::OperationAbort::budget_exceeded(
                    qtrace_provider::BudgetDimension::Nodes,
                    self.node_limit,
                    *nodes,
                ));
            }
            if *resident_bytes > self.resident_limit {
                return Err(qtrace_provider::OperationAbort::budget_exceeded(
                    qtrace_provider::BudgetDimension::ResidentBytes,
                    self.resident_limit,
                    *resident_bytes,
                ));
            }
            Ok(())
        }
    }

    let bytes = fixture("v1.2-completed.bin");
    let source = Arc::new(ByteSource::new(bytes.clone()));
    let open_guard = Limit {
        byte_limit: 15,
        event_limit: u64::MAX,
        node_limit: u64::MAX,
        resident_limit: u64::MAX,
        ..Limit::default()
    };
    let error = QtrbProvider::open(
        source.clone(),
        identity(bytes.len() as u64),
        OpenMode::Sealed,
        &open_guard,
    )
    .unwrap_err();
    assert_eq!(error.code(), "control.budget_exceeded");

    let provider = QtrbProvider::open(
        source,
        identity(bytes.len() as u64),
        OpenMode::Sealed,
        &AllowAll,
    )
    .unwrap();
    let mut cursor = Box::new(provider).into_cursor().unwrap();
    let event_guard = Limit {
        byte_limit: u64::MAX,
        event_limit: 0,
        node_limit: u64::MAX,
        resident_limit: u64::MAX,
        ..Limit::default()
    };
    let error = cursor.next_event(&event_guard).unwrap_err();
    assert_eq!(error.code(), "control.budget_exceeded");
    assert_eq!(
        cursor.finish().unwrap_err().code(),
        "source.stream_not_drained"
    );

    let provider = open_bytes(bytes.clone(), OpenMode::Sealed).unwrap();
    let mut cursor = Box::new(provider).into_cursor().unwrap();
    let resident_guard = Limit {
        byte_limit: u64::MAX,
        event_limit: u64::MAX,
        node_limit: u64::MAX,
        resident_limit: 0,
        ..Limit::default()
    };
    let error = cursor.next_event(&resident_guard).unwrap_err();
    assert_eq!(error.code(), "control.budget_exceeded");

    let provider = open_bytes(bytes, OpenMode::Sealed).unwrap();
    let mut cursor = Box::new(provider).into_cursor().unwrap();
    let node_guard = Limit {
        byte_limit: u64::MAX,
        event_limit: u64::MAX,
        node_limit: 0,
        resident_limit: u64::MAX,
        ..Limit::default()
    };
    assert_eq!(
        cursor.next_event(&node_guard).unwrap().unwrap().kind(),
        EventKind::Begin
    );
    let error = cursor.next_event(&node_guard).unwrap_err();
    assert_eq!(error.code(), "control.budget_exceeded");
}

#[test]
fn work_guard_accounts_for_decoded_and_container_residency() {
    #[derive(Default)]
    struct Totals {
        resident_bytes: Mutex<u64>,
        nodes: Mutex<u64>,
    }

    impl WorkGuard for Totals {
        fn consume(&self, delta: WorkDelta) -> Result<(), qtrace_provider::OperationAbort> {
            *self.resident_bytes.lock().unwrap() += delta.resident_bytes;
            *self.nodes.lock().unwrap() += delta.nodes;
            Ok(())
        }
    }

    let module_name = b"libresident-accounting.so";
    let mut bytes = header(2, 1);
    let begin_record = begin(2);
    let module_record = module(1, 0x1000, module_name);
    let raw_payload_bytes =
        (begin_record.len() + module_record.len() - 2 * RECORD_HEADER_BYTES) as u64;
    bytes.extend_from_slice(&begin_record);
    bytes.extend_from_slice(&module_record);

    let provider = open_bytes(bytes, OpenMode::RecoverablePartial).unwrap();
    let mut cursor = Box::new(provider).into_cursor().unwrap();
    let totals = Totals::default();
    assert_eq!(
        cursor.next_event(&totals).unwrap().unwrap().kind(),
        EventKind::Begin
    );
    assert_eq!(
        cursor.next_event(&totals).unwrap().unwrap().kind(),
        EventKind::ModuleDefinition
    );

    assert!(*totals.resident_bytes.lock().unwrap() > raw_payload_bytes);
    assert_eq!(*totals.nodes.lock().unwrap(), 1);
}
