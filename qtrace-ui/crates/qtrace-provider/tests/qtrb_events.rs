use std::{path::PathBuf, sync::Arc};

use qtrace_provider::{
    ArtifactDigest, ByteSource, CaptureBytes, EventPayload, MemoryDirection, OpenMode,
    PcRelativeKind, ProviderError, QtrbProvider, SourceIdentity, TerminationKind, TraceProfile,
    TraceProvider, WorkDelta, WorkGuard,
};

struct AllowAll;

impl WorkGuard for AllowAll {
    fn consume(&self, _delta: WorkDelta) -> Result<(), qtrace_provider::OperationAbort> {
        Ok(())
    }
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/qtrb")
            .join(name),
    )
    .unwrap()
}

fn collect(name: &str) -> Vec<qtrace_provider::EventRecord> {
    let bytes = fixture(name);
    collect_bytes(
        bytes,
        if name.contains("partial") {
            OpenMode::RecoverablePartial
        } else {
            OpenMode::Sealed
        },
    )
    .unwrap()
}

fn collect_bytes(
    bytes: Vec<u8>,
    mode: OpenMode,
) -> Result<Vec<qtrace_provider::EventRecord>, ProviderError> {
    let identity = SourceIdentity {
        artifact: ArtifactDigest::new([0x51; 32]),
        format: "QTRB".to_owned(),
        format_major: 0,
        format_minor: 0,
        source_bytes: bytes.len() as u64,
    };
    let provider = QtrbProvider::open(Arc::new(ByteSource::new(bytes)), identity, mode, &AllowAll)?;
    let mut cursor = Box::new(provider).into_cursor().unwrap();
    let mut events = Vec::new();
    while let Some(event) = cursor.next_event(&AllowAll)? {
        events.push(event);
    }
    cursor.finish()?;
    Ok(events)
}

#[test]
fn v12_preserves_complete_typed_observations() {
    let events = collect("v1.2-completed.bin");

    let begin = events
        .iter()
        .find_map(|event| match &event.payload {
            EventPayload::Begin(value) => Some(value),
            _ => None,
        })
        .unwrap();
    assert_eq!(begin.module_base, 0x100000);
    assert_eq!(begin.target_offset, 0x40);
    assert_eq!(begin.target_address, 0x100040);
    assert_eq!(begin.pid, 12);
    assert_eq!(begin.tid, Some(13));
    assert_eq!(begin.profile, TraceProfile::Full);
    assert!(begin.compression_enabled);
    assert_eq!(begin.effective_buffer_bytes, 4096);
    assert_eq!(begin.run_id, 7);
    assert_eq!(begin.scene, "scene\n\"x");
    assert_eq!(begin.target, "lib.so");

    let definition = events
        .iter()
        .find_map(|event| match &event.payload {
            EventPayload::InstructionDefinition(value) => Some(value),
            _ => None,
        })
        .unwrap();
    assert_eq!(definition.definition_id, 99);
    assert_eq!(definition.opcode, 0x14000000);
    assert_eq!(definition.read_mask, (1 << 0) | (1 << 31));
    assert_eq!(definition.write_mask, (1 << 32) | (1 << 33));
    assert_eq!(definition.pc_kind, PcRelativeKind::Page);
    assert_eq!(definition.pc_displacement, 0x1234);
    assert_eq!(definition.mnemonic, "B.EQ");
    assert_eq!(definition.operands, "x0, #0x4");
    assert_eq!(definition.reads[0].slot, 0);
    assert_eq!(definition.reads[0].captured_width, 8);
    assert_eq!(definition.reads[1].slot, 31);
    assert_eq!(definition.writes[0].slot, 32);
    assert_eq!(definition.writes[1].slot, 33);
    assert_eq!(definition.memory_operands[0].displacement, -16);

    let instruction = events
        .iter()
        .find_map(|event| match &event.payload {
            EventPayload::Instruction(value) => Some(value),
            _ => None,
        })
        .unwrap();
    assert_eq!(instruction.module_id, 1);
    assert_eq!(instruction.relative_pc, 0x2345);
    assert_eq!(instruction.read_before[0].slot, 0);
    assert_eq!(instruction.read_before[0].captured_width, 8);
    assert_eq!(instruction.read_before[0].value, 1);
    assert_eq!(instruction.read_before[1].slot, 31);
    assert_eq!(instruction.read_before[1].value, 2);
    assert_eq!(instruction.write_after[0].slot, 32);
    assert_eq!(instruction.write_after[0].value, 3);
    assert_eq!(instruction.write_after[1].slot, 33);
    assert_eq!(instruction.write_after[1].value, 4);

    let memory = events
        .iter()
        .find_map(|event| match &event.payload {
            EventPayload::Memory(value) => Some(value),
            _ => None,
        })
        .unwrap();
    assert_eq!(memory.module_id, 1);
    assert_eq!(memory.relative_pc, 0x2345);
    assert_eq!(memory.direction, MemoryDirection::ReadWrite);
    assert!(memory.metadata_available);
    assert_eq!(memory.flags, 0x12);
    assert_eq!(memory.address, 0x2000);
    assert_eq!(memory.size, 4);
    assert_eq!(memory.value, 0xab);
    assert_eq!(memory.before, CaptureBytes::Captured(vec![0x00, 0xff]));
    assert_eq!(memory.after, CaptureBytes::Unavailable);

    let semantics: Vec<_> = events
        .iter()
        .filter_map(|event| match &event.payload {
            EventPayload::SemanticCall(value)
            | EventPayload::SemanticRule(value)
            | EventPayload::SemanticError(value) => Some((event.kind(), value)),
            _ => None,
        })
        .collect();
    assert_eq!(semantics[0].1.category.as_deref(), Some("jni"));
    assert_eq!(semantics[0].1.name, "Find");
    assert_eq!(semantics[0].1.detail, "line\n\"quoted\"");
    assert_eq!(semantics[1].1.name, "guard");
    assert_eq!(semantics[1].1.detail, "hit");
    assert_eq!(semantics[2].1.name, "fatal");
    assert_eq!(semantics[2].1.detail, "bad");

    let terminal = events
        .iter()
        .find_map(|event| match &event.payload {
            EventPayload::Termination(value) => Some(value),
            _ => None,
        })
        .unwrap();
    assert_eq!(terminal.kind, TerminationKind::Completed);
    assert_eq!(terminal.return_value, Some(0x55));
    assert_eq!(terminal.elapsed_ms, 17);
    assert_eq!(terminal.metrics.instructions, 1);
    assert_eq!(terminal.metrics.encoded_bytes, 530);
    assert_eq!(terminal.metrics.compressed_bytes, 530);
    assert_eq!(terminal.metrics.cache_hits, 9);
    assert_eq!(terminal.metrics.cache_misses, 1);
    assert_eq!(terminal.metrics.buffer_swaps, 2);
    assert_eq!(terminal.metrics.effective_buffer_bytes, 4096);
}

#[test]
fn unknown_memory_capture_is_not_an_empty_or_zero_capture() {
    let memory = collect("v1.0-completed.bin")
        .into_iter()
        .find_map(|event| match event.payload {
            EventPayload::Memory(value) => Some(value),
            _ => None,
        })
        .unwrap();
    assert_eq!(memory.before, CaptureBytes::NotCaptured);
    assert_eq!(memory.after, CaptureBytes::NotCaptured);
    assert_ne!(memory.before, CaptureBytes::Captured(Vec::new()));
}

#[test]
fn stopped_terminal_preserves_reason_and_metrics() {
    let terminal = collect("v1.2-stopped.bin")
        .into_iter()
        .find_map(|event| match event.payload {
            EventPayload::Termination(value) => Some(value),
            _ => None,
        })
        .unwrap();
    assert_eq!(terminal.kind, TerminationKind::Stopped);
    assert_eq!(terminal.reason.as_deref(), Some("duration_elapsed"));
    assert_eq!(terminal.return_value, None);
    assert_eq!(terminal.elapsed_ms, 17);
    assert_eq!(terminal.metrics.encoded_bytes, 405);
}

fn wire_string(value: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&(value.len() as u16).to_le_bytes());
    encoded.extend_from_slice(value);
    encoded
}

fn record(kind: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&kind.to_le_bytes());
    encoded.extend_from_slice(&flags.to_le_bytes());
    encoded.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    encoded.extend_from_slice(payload);
    encoded
}

fn partial_prefix(minor: u8, features: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"QTRB");
    bytes.extend_from_slice(&[1, minor, 1, 8, 2, 0]);
    bytes.extend_from_slice(&16_u16.to_le_bytes());
    bytes.extend_from_slice(&features.to_le_bytes());
    let mut begin = Vec::new();
    begin.extend_from_slice(&0x100000_u64.to_le_bytes());
    begin.extend_from_slice(&0x40_u64.to_le_bytes());
    begin.extend_from_slice(&0x100040_u64.to_le_bytes());
    begin.extend_from_slice(&12_u32.to_le_bytes());
    begin.extend_from_slice(&13_u32.to_le_bytes());
    begin.extend_from_slice(&[2, 1]);
    begin.extend_from_slice(&4096_u64.to_le_bytes());
    begin.extend_from_slice(&7_u64.to_le_bytes());
    begin.extend_from_slice(&wire_string(b"scene"));
    begin.extend_from_slice(&wire_string(b"lib.so"));
    bytes.extend_from_slice(&record(1, 0, &begin));
    let mut module = Vec::new();
    module.extend_from_slice(&1_u32.to_le_bytes());
    module.extend_from_slice(&0x100000_u64.to_le_bytes());
    module.extend_from_slice(&wire_string(b"lib.so"));
    bytes.extend_from_slice(&record(2, 0, &module));
    bytes
}

#[test]
fn mixed_width_registers_keep_architectural_slots_and_captured_widths() {
    let mut bytes = partial_prefix(2, 1);
    let mut definition = Vec::new();
    definition.extend_from_slice(&123_u32.to_le_bytes());
    definition.extend_from_slice(&0xaa_u32.to_le_bytes());
    definition.extend_from_slice(&((1_u64 << 1) | (1_u64 << 30)).to_le_bytes());
    definition.extend_from_slice(&((1_u64 << 2) | (1_u64 << 31) | (1_u64 << 33)).to_le_bytes());
    definition.extend_from_slice(&(-0x3000_i64).to_le_bytes());
    definition.extend_from_slice(&0_u32.to_le_bytes());
    definition.extend_from_slice(&[1, 0, 0, 0]);
    definition.extend_from_slice(&wire_string(b"ADD"));
    definition.extend_from_slice(&wire_string(b"w2, w1, #1"));
    definition.extend_from_slice(&wire_string(b""));
    for (width, name) in [
        (4, b"W1".as_slice()),
        (8, b"LR"),
        (4, b"W2"),
        (8, b"SP"),
        (8, b"PC"),
    ] {
        definition.push(width);
        definition.extend_from_slice(&wire_string(name));
    }
    bytes.extend_from_slice(&record(3, 0, &definition));
    let mut instruction = Vec::new();
    instruction.extend_from_slice(&1_u64.to_le_bytes());
    instruction.extend_from_slice(&1_u32.to_le_bytes());
    instruction.extend_from_slice(&0x2345_u64.to_le_bytes());
    instruction.extend_from_slice(&123_u32.to_le_bytes());
    instruction.extend_from_slice(&[2, 3]);
    for value in [0x11_u64, 0x22, 0x33, 0x44, 0x55] {
        instruction.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend_from_slice(&record(4, 0, &instruction));

    let events = collect_bytes(bytes, OpenMode::RecoverablePartial).unwrap();
    let definition = events
        .iter()
        .find_map(|event| match &event.payload {
            EventPayload::InstructionDefinition(value) => Some(value),
            _ => None,
        })
        .unwrap();
    assert_eq!(definition.pc_kind, PcRelativeKind::Instruction);
    assert_eq!(definition.pc_displacement, -0x3000);
    let instruction = events
        .iter()
        .find_map(|event| match &event.payload {
            EventPayload::Instruction(value) => Some(value),
            _ => None,
        })
        .unwrap();
    assert_eq!(instruction.read_before[0].slot, 1);
    assert_eq!(instruction.read_before[0].captured_width, 4);
    assert_eq!(instruction.read_before[0].name, "W1");
    assert_eq!(instruction.write_after[0].slot, 2);
    assert_eq!(instruction.write_after[0].captured_width, 4);
    assert_eq!(instruction.write_after[0].name, "W2");
    assert_eq!(instruction.write_after[2].slot, 33);
}

#[test]
fn chunk_metadata_utf8_is_validated_after_the_complete_group() {
    let mut bytes = partial_prefix(1, 0);
    let mut first = Vec::new();
    first.extend_from_slice(&1_u64.to_le_bytes());
    first.extend_from_slice(&2_u32.to_le_bytes());
    first.extend_from_slice(&0_u16.to_le_bytes());
    first.extend_from_slice(&2_u16.to_le_bytes());
    first.extend_from_slice(&wire_string(&[0xff]));
    first.extend_from_slice(&wire_string(b"a"));
    bytes.extend_from_slice(&record(7, 1, &first));

    let error = collect_bytes(bytes, OpenMode::RecoverablePartial).unwrap_err();
    assert_eq!(error.code(), "source.incomplete_fragment");
}
