use std::{
    collections::HashMap,
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use lz4_flex::frame::FrameEncoder;
use qtrace_provider::{
    ArtifactDigest, ByteSource, CaptureBytes, EventPayload, OpenMode, PcRelativeKind, QtrbInput,
    QtrbProvider, SourceIdentity, TerminationKind, TraceProvider, WorkDelta, WorkGuard,
};
use serde_json::Value;

struct AllowAll;

impl WorkGuard for AllowAll {
    fn consume(&self, _delta: WorkDelta) -> Result<(), qtrace_provider::OperationAbort> {
        Ok(())
    }
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/qtrb")
        .join(name)
}

fn identity(source_bytes: u64) -> SourceIdentity {
    SourceIdentity {
        artifact: ArtifactDigest::new([0x52; 32]),
        format: "QTRB".to_owned(),
        format_major: 0,
        format_minor: 0,
        source_bytes,
    }
}

fn collect_source(
    source: Arc<dyn qtrace_provider::ReadAtSource>,
    source_bytes: u64,
    mode: OpenMode,
) -> Result<
    (
        Vec<qtrace_provider::EventRecord>,
        qtrace_provider::ProviderSummary,
    ),
    qtrace_provider::ProviderError,
> {
    let provider = QtrbProvider::open(source, identity(source_bytes), mode, &AllowAll)?;
    let mut cursor = Box::new(provider).into_cursor()?;
    let mut events = Vec::new();
    while let Some(event) = cursor.next_event(&AllowAll)? {
        events.push(event);
    }
    let summary = cursor.finish()?;
    Ok((events, summary))
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).unwrap()
}

fn hex(value: u64) -> String {
    format!("0x{value:x}")
}

fn slot_name(slot: u8) -> String {
    match slot {
        0..=30 => format!("X{slot}"),
        31 => "SP".to_owned(),
        32 => "NZCV".to_owned(),
        33 => "PC".to_owned(),
        _ => format!("R{slot}"),
    }
}

fn render(
    events: &[qtrace_provider::EventRecord],
    summary: &qtrace_provider::ProviderSummary,
) -> (Vec<String>, Value) {
    let mut modules = HashMap::new();
    let mut definitions = HashMap::new();
    let mut lines = Vec::new();
    let mut instruction_count = 0_u64;
    for event in events {
        match &event.payload {
            EventPayload::Begin(value) => lines.push(format!(
                "TRACE_BEGIN format=4 scene={} target={} target_offset={} base={} address={} pid={} tid={} profile={} compression={} effective_buffer_bytes={} run_id={}",
                json_string(&value.scene), json_string(&value.target), hex(value.target_offset),
                hex(value.module_base), hex(value.target_address), value.pid, value.tid.unwrap(),
                value.profile.as_str(), u8::from(value.compression_enabled),
                value.effective_buffer_bytes, value.run_id
            )),
            EventPayload::ModuleDefinition(value) => {
                modules.insert(value.module_id, value.clone());
            }
            EventPayload::InstructionDefinition(value) => {
                definitions.insert(value.definition_id, value.clone());
            }
            EventPayload::Instruction(value) => {
                instruction_count += 1;
                let module = &modules[&value.module_id];
                let definition = &definitions[&value.definition_id];
                let pc = module.base.wrapping_add(value.relative_pc);
                let asm = if definition.mnemonic.is_empty() {
                    if definition.disassembly.is_empty() {
                        "<undecoded>".to_owned()
                    } else {
                        definition.disassembly.clone()
                    }
                } else if definition.pc_kind != PcRelativeKind::None {
                    let base = if definition.pc_kind == PcRelativeKind::Page {
                        pc & !0xfff
                    } else {
                        pc
                    };
                    let target = base.wrapping_add_signed(definition.pc_displacement);
                    let prefix = definition
                        .operands
                        .rsplit_once(',')
                        .map_or("", |(prefix, _)| prefix);
                    if prefix.is_empty() {
                        format!("{} {}", definition.mnemonic, hex(target))
                    } else {
                        format!("{} {}, {}", definition.mnemonic, prefix, hex(target))
                    }
                } else if definition.operands.is_empty() {
                    definition.mnemonic.clone()
                } else {
                    format!("{} {}", definition.mnemonic, definition.operands)
                };
                let registers = |items: &[qtrace_provider::RegisterObservation]| {
                    format!(
                        "[{}]",
                        items
                            .iter()
                            .map(|item| format!(
                                "{}:{}={}",
                                item.name,
                                item.captured_width,
                                hex(item.value)
                            ))
                            .collect::<Vec<_>>()
                            .join(",")
                    )
                };
                let memory_operands = format!(
                    "[{}]",
                    definition
                        .memory_operands
                        .iter()
                        .map(|operand| format!(
                            "base={},index={},extend={},mode={},shift={},kind={},writeback={},size={},disp={}",
                            operand.base.map_or_else(|| "none".to_owned(), slot_name),
                            operand.index.map_or_else(|| "none".to_owned(), slot_name),
                            operand.extend.as_str(), operand.mode.as_str(), operand.shift,
                            operand.direction.as_str(), u8::from(operand.writeback), operand.size,
                            operand.displacement
                        ))
                        .collect::<Vec<_>>()
                        .join(";")
                );
                lines.push(format!(
                    "INST seq={} module={} module_base={} pc={} relative_pc={} metadata_id={} opcode={} asm={} flags={} condition={} reads={} writes={} slow_memory_path={} memory_operands={}",
                    event.key.sequence.unwrap(), json_string(&module.name), hex(module.base), hex(pc),
                    hex(value.relative_pc), value.definition_id, hex(u64::from(definition.opcode)),
                    json_string(&asm), hex(u64::from(definition.flags)), definition.condition,
                    registers(&value.read_before), registers(&value.write_after),
                    u8::from(definition.slow_memory_path), memory_operands
                ));
            }
            EventPayload::Memory(value) => {
                let module = &modules[&value.module_id];
                let pc = module.base.wrapping_add(value.relative_pc);
                let capture = |value: &CaptureBytes| match value {
                    CaptureBytes::NotCaptured => "<not-captured>".to_owned(),
                    CaptureBytes::Unavailable => "<unavailable>".to_owned(),
                    CaptureBytes::Captured(bytes) => hex::encode(bytes),
                };
                lines.push(format!(
                    "MEMORY module={} module_base={} pc={} relative_pc={} kind={} metadata_available={} flags={} address={} size={} value={} before={} after={}",
                    json_string(&module.name), hex(module.base), hex(pc), hex(value.relative_pc),
                    value.direction.as_str(), u8::from(value.metadata_available),
                    hex(u64::from(value.flags)), hex(value.address), value.size, hex(value.value),
                    capture(&value.before), capture(&value.after)
                ));
            }
            EventPayload::SemanticCall(value) => lines.push(format!(
                "CALL category={} name={} detail={}",
                json_string(value.category.as_deref().unwrap()),
                json_string(&value.name),
                json_string(&value.detail)
            )),
            EventPayload::SemanticRule(value) => lines.push(format!(
                "RULE name={} detail={}",
                json_string(&value.name),
                json_string(&value.detail)
            )),
            EventPayload::SemanticError(value) => lines.push(format!(
                "ERROR name={} detail={}",
                json_string(&value.name),
                json_string(&value.detail)
            )),
            EventPayload::Termination(value) => {
                let metrics = &value.metrics;
                let head = match value.kind {
                    TerminationKind::Completed => format!(
                        "TRACE_END status=completed return_valid=1 return={}",
                        hex(value.return_value.unwrap())
                    ),
                    TerminationKind::Stopped => format!(
                        "TRACE_END status=stopped reason={} return_valid=0",
                        value.reason.as_deref().unwrap()
                    ),
                    _ => unreachable!(),
                };
                lines.push(format!(
                    "{head} elapsed_ms={} instructions={} encoded_bytes={} compressed_bytes={} cache_hits={} cache_misses={} cache_collisions={} buffer_swaps={} producer_waits={} producer_wait_ns={} effective_buffer_bytes={}",
                    value.elapsed_ms, metrics.instructions, metrics.encoded_bytes,
                    metrics.compressed_bytes, metrics.cache_hits, metrics.cache_misses,
                    metrics.cache_collisions, metrics.buffer_swaps, metrics.producer_waits,
                    metrics.producer_wait_ns, metrics.effective_buffer_bytes
                ));
            }
            EventPayload::OpaqueOptional(_)
            | EventPayload::ThreadLifecycle(_)
            | EventPayload::Syscall(_)
            | EventPayload::Signal(_)
            | EventPayload::SignalHandlerBoundary(_)
            | EventPayload::Discontinuity(_) => {}
        }
    }
    let converted_text_bytes: usize = lines.iter().map(|line| line.len() + 1).sum();
    let termination = summary.termination.as_ref().map(|value| match value.kind {
        TerminationKind::Completed => "completed",
        TerminationKind::Stopped => "stopped",
        TerminationKind::Intent => "intent",
        TerminationKind::Unknown => "unknown",
    });
    (
        lines,
        serde_json::json!({
            "instructions": instruction_count,
            "converted_text_bytes": converted_text_bytes,
            "partial": summary.termination.is_none(),
            "termination": termination,
        }),
    )
}

#[test]
fn every_valid_fixture_matches_the_python_oracle_exactly() {
    for name in [
        "v1.0-completed.bin",
        "v1.1-chunked.bin",
        "v1.2-completed.bin",
        "v1.2-partial.bin",
        "v1.2-stopped.bin",
    ] {
        let path = fixture_path(name);
        let bytes = std::fs::read(&path).unwrap();
        let mode = if name.contains("partial") {
            OpenMode::RecoverablePartial
        } else {
            OpenMode::Sealed
        };
        let (events, summary) = collect_source(
            Arc::new(ByteSource::new(bytes.clone())),
            bytes.len() as u64,
            mode,
        )
        .unwrap();
        let output = Command::new("python3")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/oracle.py"))
            .args(["qtrb", path.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let oracle: Value = serde_json::from_slice(&output.stdout).unwrap();
        let (lines, stats) = render(&events, &summary);
        assert_eq!(serde_json::json!(lines), oracle["lines"], "{name}");
        assert_eq!(stats, oracle["stats"], "{name}");
    }
}

struct ShortReads<R> {
    inner: R,
    next: usize,
}

impl<R: Read> Read for ShortReads<R> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let maximum = self.next;
        self.next = self.next % 7 + 1;
        let request = output.len().min(maximum);
        self.inner.read(&mut output[..request])
    }
}

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut encoder = FrameEncoder::new(Vec::new());
    encoder.write_all(payload).unwrap();
    encoder.finish().unwrap()
}

fn record_boundaries(bytes: &[u8]) -> Vec<usize> {
    let mut boundaries = vec![16];
    let mut offset = 16;
    while offset < bytes.len() {
        let payload =
            u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap()) as usize;
        offset += 8 + payload;
        boundaries.push(offset);
    }
    boundaries
}

#[test]
fn concatenated_frames_and_one_to_seven_byte_reads_recover_identical_events() {
    let raw = std::fs::read(fixture_path("v1.2-completed.bin")).unwrap();
    let boundaries = record_boundaries(&raw);
    let split_a = boundaries[2];
    let split_b = boundaries[5];
    let frames = [
        frame(&raw[..split_a]),
        frame(&raw[split_a..split_b]),
        frame(&raw[split_b..]),
    ];
    let compressed: Vec<u8> = frames.iter().flatten().copied().collect();
    let input = QtrbInput::lz4(ShortReads {
        inner: Cursor::new(compressed.clone()),
        next: 1,
    });
    let source = input.into_source(&AllowAll).unwrap();
    let (actual, actual_summary) =
        collect_source(source, compressed.len() as u64, OpenMode::Sealed).unwrap();
    let (expected, expected_summary) = collect_source(
        Arc::new(ByteSource::new(raw.clone())),
        raw.len() as u64,
        OpenMode::Sealed,
    )
    .unwrap();
    assert_eq!(actual, expected);
    assert_eq!(actual_summary.termination, expected_summary.termination);
}

#[test]
fn truncating_each_concatenated_frame_is_a_compression_error() {
    let raw = std::fs::read(fixture_path("v1.2-completed.bin")).unwrap();
    let boundaries = record_boundaries(&raw);
    let split_a = boundaries[2];
    let split_b = boundaries[5];
    let frames = [
        frame(&raw[..split_a]),
        frame(&raw[split_a..split_b]),
        frame(&raw[split_b..]),
    ];
    for frame_index in 0..frames.len() {
        for removed in 1..frames[frame_index].len() {
            let mut candidate = Vec::new();
            for (index, frame) in frames.iter().enumerate() {
                if index < frame_index {
                    candidate.extend_from_slice(frame);
                } else if index == frame_index {
                    candidate.extend_from_slice(&frame[..frame.len() - removed]);
                    break;
                }
            }
            let error = match QtrbInput::lz4(Cursor::new(candidate)).into_source(&AllowAll) {
                Ok(_) => panic!("accepted frame={frame_index} removed={removed}"),
                Err(error) => error,
            };
            assert_eq!(
                error.code(),
                "source.qtrb.compression",
                "frame={frame_index} removed={removed}"
            );
        }
    }
}

#[test]
fn compressed_input_rejects_zero_skippable_unknown_and_trailing_frames() {
    let raw = std::fs::read(fixture_path("v1.2-completed.bin")).unwrap();
    let valid = frame(&raw);
    for candidate in [
        Vec::new(),
        vec![0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0],
        vec![0xde, 0xad, 0xbe, 0xef],
        [valid.clone(), b"tail".to_vec()].concat(),
    ] {
        let error = QtrbInput::lz4(Cursor::new(candidate))
            .into_source(&AllowAll)
            .unwrap_err();
        assert_eq!(error.code(), "source.qtrb.compression");
    }
}

#[test]
fn standard_zero_byte_raw_block_is_accepted() {
    let mut encoded = frame(&[]);
    let end_marker = encoded.len() - 4;
    assert_eq!(&encoded[end_marker..], &[0, 0, 0, 0]);
    encoded.splice(end_marker..end_marker, 0x8000_0000_u32.to_le_bytes());

    let source = QtrbInput::lz4(Cursor::new(encoded))
        .into_source(&AllowAll)
        .unwrap();

    assert_eq!(qtrace_provider::ReadAtSource::len(source.as_ref()), 0);
}

struct ObservedReader {
    bytes: Cursor<Vec<u8>>,
    reads: Arc<AtomicUsize>,
}

impl Read for ObservedReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.bytes.read(output)
    }
}

struct RejectAll;

impl WorkGuard for RejectAll {
    fn consume(&self, _delta: WorkDelta) -> Result<(), qtrace_provider::OperationAbort> {
        Err(qtrace_provider::OperationAbort::Cancelled)
    }
}

#[test]
fn qtrb_input_requires_budget_authorization_before_source_io() {
    let reads = Arc::new(AtomicUsize::new(0));
    let input = QtrbInput::lz4(ObservedReader {
        bytes: Cursor::new(frame(b"QTRB")),
        reads: reads.clone(),
    });

    let error = match input.into_source(&RejectAll) {
        Ok(_) => panic!("input bypassed rejecting guard"),
        Err(error) => error,
    };

    assert_eq!(error.code(), "control.cancelled");
    assert_eq!(reads.load(Ordering::SeqCst), 0);
}

#[test]
fn raw_qtrb_input_preserves_source_bytes() {
    let raw = std::fs::read(fixture_path("v1.2-completed.bin")).unwrap();
    let source = QtrbInput::raw(ShortReads {
        inner: Cursor::new(raw.clone()),
        next: 1,
    })
    .into_source(&AllowAll)
    .unwrap();
    let (events, summary) = collect_source(source, raw.len() as u64, OpenMode::Sealed).unwrap();
    let (lines, _) = render(&events, &summary);
    assert_eq!(lines.len(), 7);
    assert_eq!(summary.counters.decompressed_bytes, raw.len() as u64);
}
