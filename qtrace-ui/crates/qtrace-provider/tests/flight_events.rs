use std::{fs, path::PathBuf, sync::Arc};

use qtrace_provider::{
    ArtifactDigest, ByteSource, CaptureBytes, CompletenessCause, EventPayload, EventRecord,
    FlightProvider, OperationAbort, Provenance, RangeBounds, RegisterSlot, SourceIdentity,
    TraceProvider, WorkDelta, WorkGuard,
};

struct AllowAll;

impl WorkGuard for AllowAll {
    fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
        Ok(())
    }
}

struct ParsedFlight {
    events: Vec<EventRecord>,
    summary: qtrace_provider::ProviderSummary,
    projections: Vec<qtrace_provider::FlightProjectionDescriptor>,
    capabilities: qtrace_provider::ProviderCapabilities,
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/flight")
        .join(name)
}

fn collect_flight(name: &str) -> Result<ParsedFlight, qtrace_provider::ProviderError> {
    let bytes = fs::read(fixture_path(name)).expect("read Flight fixture");
    let source_bytes = bytes.len() as u64;
    let provider = FlightProvider::open(
        Arc::new(ByteSource::new(bytes)),
        SourceIdentity {
            artifact: ArtifactDigest::new([0x71; 32]),
            format: "untrusted".to_owned(),
            format_major: 0,
            format_minor: 0,
            source_bytes,
        },
        &AllowAll,
    )?;
    let projections = provider.projections().to_vec();
    let capabilities = provider.capabilities().clone();
    let mut cursor = Box::new(provider).into_cursor()?;
    let mut events = Vec::new();
    while let Some(event) = cursor.next_event(&AllowAll)? {
        events.push(event);
    }
    let summary = cursor.finish()?;
    Ok(ParsedFlight {
        events,
        summary,
        projections,
        capabilities,
    })
}

fn sequence(event: &EventRecord) -> u64 {
    event
        .key
        .sequence
        .expect("Flight events carry global sequence")
}

#[test]
fn complete_fixture_decodes_every_flight_record_kind_as_typed_evidence() {
    let parsed = collect_flight("v2-complete.bin").expect("decode complete Flight fixture");

    assert!(parsed.capabilities.global_ordering);
    assert!(parsed.capabilities.per_thread_ordering);
    assert!(parsed.capabilities.full_register_checkpoint);
    assert!(parsed.capabilities.register_read_write_observation);
    assert!(parsed.capabilities.memory_metadata);
    assert!(parsed.capabilities.memory_before_after);
    assert!(parsed.capabilities.lifecycle);
    assert!(parsed.capabilities.signal_and_termination);
    assert!(parsed.capabilities.loss_and_damage_ranges);

    let begin = parsed
        .events
        .iter()
        .find_map(|event| match &event.payload {
            EventPayload::Begin(value) if sequence(event) == 1 => Some(value),
            _ => None,
        })
        .expect("chunk begin");
    assert_eq!(begin.pid, 4242);
    assert_eq!(begin.tid, Some(101));
    assert_eq!(begin.module_base, 0x7100_0000);
    assert_eq!(begin.target_offset, 0x1234);
    assert_eq!(begin.target_address, 0x7100_1234);
    assert_eq!(begin.target, "libtarget.so");
    assert_eq!(begin.scene, "worker");
    assert_eq!(begin.pointer_width, 8);
    assert_eq!(begin.chunk_index, Some(0));
    assert_eq!(begin.chunk_generation, Some(1));

    let checkpoint = parsed
        .events
        .iter()
        .find_map(|event| match &event.payload {
            EventPayload::RegisterCheckpoint(value) if sequence(event) == 2 => Some(value),
            _ => None,
        })
        .expect("register checkpoint");
    assert_eq!(checkpoint.values.len(), 34);
    assert_eq!(checkpoint.value(RegisterSlot::X0), Some(0));
    assert_eq!(checkpoint.value(RegisterSlot::X30), Some(30));
    assert_eq!(checkpoint.value(RegisterSlot::Sp), Some(0x7fff_0000));
    assert_eq!(checkpoint.value(RegisterSlot::Pc), Some(0x7100_1000));
    assert_eq!(checkpoint.value(RegisterSlot::Nzcv), Some(0x6000_0000));

    let lifecycle = parsed
        .events
        .iter()
        .find_map(|event| match &event.payload {
            EventPayload::ThreadLifecycle(value) if sequence(event) == 3 => Some(value),
            _ => None,
        })
        .expect("thread begin");
    assert_eq!(lifecycle.creator_tid, Some(1));
    assert_eq!(lifecycle.tid, 101);
    assert_eq!(lifecycle.start_routine, Some(0x7100_1234));
    assert_eq!(lifecycle.module_generation, Some(1));

    let definition = parsed
        .events
        .iter()
        .find_map(|event| match &event.payload {
            EventPayload::InstructionDefinition(value) if sequence(event) == 4 => Some(value),
            _ => None,
        })
        .expect("instruction definition");
    assert_eq!(definition.definition_id, 7);
    assert_eq!(definition.opcode, 0x1400_0000);
    assert_eq!(definition.pc_displacement, -32);
    assert_eq!(definition.mnemonic, "B.EQ");
    assert_eq!(definition.operands, "x0, #0x4");
    assert_eq!(definition.reads.len(), 2);
    assert_eq!(definition.writes.len(), 2);

    let instruction = parsed
        .events
        .iter()
        .find_map(|event| match &event.payload {
            EventPayload::Instruction(value) if sequence(event) == 5 => Some(value),
            _ => None,
        })
        .expect("instruction");
    assert_eq!(instruction.definition_id, 7);
    assert_eq!(instruction.relative_pc, 0x2345);
    assert_eq!(instruction.read_before[0].value, 0x11);
    assert_eq!(instruction.write_after[1].value, 0x44);

    let memory = parsed
        .events
        .iter()
        .find_map(|event| match &event.payload {
            EventPayload::Memory(value) if sequence(event) == 6 => Some(value),
            _ => None,
        })
        .expect("memory");
    assert_eq!(memory.address, 0x2000);
    assert_eq!(memory.before, CaptureBytes::Captured(vec![0, 0xff]));
    assert_eq!(memory.after, CaptureBytes::Unavailable);

    let string = parsed
        .events
        .iter()
        .find_map(|event| match &event.payload {
            EventPayload::StringDefinition(value) if sequence(event) == 7 => Some(value),
            _ => None,
        })
        .expect("string definition");
    assert_eq!(string.id, 1);
    assert_eq!(string.bytes, b"jni");

    let call = parsed
        .events
        .iter()
        .find(|event| matches!(event.payload, EventPayload::SemanticCall(_)))
        .expect("fragmented call");
    let EventPayload::SemanticCall(call_value) = &call.payload else {
        unreachable!();
    };
    assert_eq!(sequence(call), 12);
    assert_eq!(call_value.category.as_deref(), Some("jni"));
    assert_eq!(call_value.name, "Lookup");
    assert_eq!(call_value.detail, "snowman☃");
    assert_eq!(call_value.fragment_sequences, [10, 12]);
    assert_eq!(call.fragment_source_offsets().len(), 2);
    assert_eq!(call.key.source_offset, call.fragment_source_offsets()[0]);

    let syscall = parsed
        .events
        .iter()
        .find_map(|event| match &event.payload {
            EventPayload::Syscall(value) if sequence(event) == 20 => Some(value),
            _ => None,
        })
        .expect("syscall");
    assert_eq!(syscall.pc, 64);
    assert_eq!(syscall.arguments, [1, 2, 3, 4, 5, 6]);
    assert_eq!(syscall.number, 7);
    assert_eq!(syscall.result, Some(0));

    let signal = parsed
        .events
        .iter()
        .find_map(|event| match &event.payload {
            EventPayload::Signal(value) if sequence(event) == 21 => Some(value),
            _ => None,
        })
        .expect("signal");
    assert_eq!(signal.number, 10);
    assert_eq!(signal.code, 1);
    assert_eq!(signal.fault_address, 0x7100_9000);

    let boundaries: Vec<_> = parsed
        .events
        .iter()
        .filter_map(|event| match &event.payload {
            EventPayload::SignalHandlerBoundary(value) => Some((sequence(event), value)),
            _ => None,
        })
        .collect();
    assert_eq!(boundaries.len(), 2);
    assert_eq!(boundaries[0].0, 28);
    assert_eq!(boundaries[0].1.depth, 1);
    assert_eq!(boundaries[1].0, 29);
    assert_eq!(boundaries[1].1.begin_sequence, Some(28));

    let termination = parsed
        .events
        .iter()
        .find_map(|event| match &event.payload {
            EventPayload::Termination(value) if sequence(event) == 30 => Some(value),
            _ => None,
        })
        .expect("termination intent");
    let intent = termination.intent.as_ref().expect("typed intent fields");
    assert_eq!(intent.pc, 0x7100_9908);
    assert_eq!(intent.syscall_number, 131);
    assert_eq!(intent.arguments, [0, 0, 9, 0]);
    assert_eq!(parsed.summary.termination.as_ref(), Some(termination));
}

#[test]
fn delta_does_not_make_unmentioned_registers_known() {
    let parsed = collect_flight("v2-checkpoint-delta.bin").expect("decode delta fixture");
    let delta = parsed
        .events
        .iter()
        .find_map(EventRecord::register_delta)
        .expect("register delta");
    assert_eq!(delta.changed.len(), delta.mask.count_ones() as usize);
    assert!(
        !delta
            .changed
            .iter()
            .any(|item| item.slot == RegisterSlot::X3)
    );
    assert!(delta.ancestry_reliable);
    assert_eq!(delta.changed[0].slot, RegisterSlot::X0);
    assert_eq!(delta.changed[0].value, 0x1111);
    assert_eq!(delta.changed[1].slot, RegisterSlot::Pc);
    assert_eq!(delta.changed[1].value, 0x7100_1234);

    let projection = parsed
        .projections
        .iter()
        .find(|projection| projection.tid == 77)
        .expect("TID projection");
    let final_registers = projection
        .final_registers
        .as_ref()
        .expect("reliable final registers");
    assert_eq!(final_registers.value(RegisterSlot::X0), Some(0x1111));
    assert_eq!(final_registers.value(RegisterSlot::X3), Some(3));
    assert_eq!(final_registers.value(RegisterSlot::Pc), Some(0x7100_1234));
}

#[test]
fn an_incomplete_fragment_is_damage_not_a_partial_string() {
    let parsed = collect_flight("v2-incomplete-fragment.bin").expect("recover incomplete fragment");
    assert!(!parsed.events.iter().any(|event| match &event.payload {
        EventPayload::SemanticCall(value)
        | EventPayload::SemanticRule(value)
        | EventPayload::SemanticError(value) => value.detail.contains("partial"),
        _ => false,
    }));
    assert!(
        parsed
            .summary
            .completeness
            .iter()
            .any(|item| { item.provenance() == Provenance::Damaged && item.contains(6) })
    );
}

#[test]
fn coverage_gap_is_typed_and_keeps_emergency_coordinate() {
    let parsed = collect_flight("v2-coverage-gap.bin").expect("decode coverage gap");
    let event = parsed
        .events
        .iter()
        .find(|event| matches!(event.payload, EventPayload::CoverageGap(_)))
        .expect("typed coverage gap");
    let EventPayload::CoverageGap(gap) = &event.payload else {
        unreachable!();
    };
    assert_eq!(sequence(event), 4);
    assert_eq!(gap.pc, 0x7100_9900);
    assert_eq!(gap.reason_flags, 2);
    assert_eq!(gap.dropped_count, 0);
    assert!(event.key.source_offset >= 4096);
    let discontinuity = parsed
        .events
        .iter()
        .find(|candidate| {
            matches!(
                candidate.payload,
                EventPayload::Discontinuity(ref value)
                    if value.evidence.cause() == CompletenessCause::CoverageGap
            )
        })
        .expect("coverage-gap discontinuity");
    assert_eq!(discontinuity.key.source_offset, event.key.source_offset);
}

#[test]
fn synthetic_discontinuity_uses_its_proof_coordinate_and_global_identity() {
    let parsed = collect_flight("v2-stale-directory.bin").expect("recover stale directory");
    let event = parsed
        .events
        .iter()
        .find(|event| {
            matches!(
                event.payload,
                EventPayload::Discontinuity(ref value)
                    if value.evidence.cause() == CompletenessCause::Stale
            )
        })
        .expect("stale discontinuity");
    let EventPayload::Discontinuity(value) = &event.payload else {
        unreachable!();
    };
    let RangeBounds::HalfOpen { start, .. } = value.evidence.bounds() else {
        panic!("stale directory evidence must use source bytes");
    };
    assert_eq!(event.key.source_offset, start);
    assert_eq!(event.key.tid, None);
    assert_eq!(event.key.sequence, None);
    assert_eq!(
        parsed
            .events
            .iter()
            .filter(|candidate| candidate.key == event.key)
            .count(),
        1
    );
}
