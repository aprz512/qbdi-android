use std::{
    cell::Cell,
    sync::atomic::{AtomicU64, Ordering},
};

use qtrace_provider::{
    ArtifactDigest, BeginMetadata, BudgetDimension, ByteSource, CompletenessCause,
    CompletenessRange, CoverageGap, Discontinuity, DiscontinuityCause, EventCursor, EventKey,
    EventKind, EventPayload, EventRecord, EventScope, FragmentSourceOffsets, Instruction,
    InstructionDefinition, MAX_FRAGMENT_SOURCE_OFFSETS, Memory, MemoryDirection, ModuleDefinition,
    OpaqueOptionalRecord, OperationAbort, Provenance, ProviderCapabilities, ProviderCounters,
    ProviderError, ProviderSummary, RangeBounds, RangeDomain, ReadAtSource, RegisterCheckpoint,
    RegisterDelta, RegisterSlot, RegisterValue, SemanticEvent, Signal, SignalHandlerBoundary,
    SignalHandlerPhase, SourceIdentity, StringDefinition, Syscall, Termination, TerminationKind,
    ThreadLifecycle, ThreadLifecyclePhase, TimelineDescriptor, TimelineId, TraceProvider,
    WorkDelta, WorkGuard,
};
use serde::Deserialize;

fn digest(byte: u8) -> ArtifactDigest {
    ArtifactDigest::new([byte; 32])
}

#[test]
fn event_identity_does_not_depend_on_visible_row_or_optional_sequence() {
    let key = EventKey::new(digest(0x11), TimelineId(7), 19, 0x240, None, Some(42));
    assert_eq!(key.record_ordinal, 19);
    assert_eq!(key.source_offset, 0x240);
    assert_eq!(key.sequence, None);
    assert_eq!(key.tid, Some(42));
}

#[test]
fn event_scope_distinguishes_flight_chunk_generations_without_changing_event_identity() {
    let key = EventKey::new(digest(0x11), TimelineId(0), 19, 0x240, Some(91), Some(42));
    let event = EventRecord::new_scoped(
        key.clone(),
        Provenance::Captured,
        EventScope::FlightChunk {
            chunk_index: 3,
            generation: 7,
            tid: 42,
        },
        EventPayload::Instruction(Instruction::default()),
    );
    assert_eq!(event.key, key);
    assert_eq!(
        event.scope(),
        EventScope::FlightChunk {
            chunk_index: 3,
            generation: 7,
            tid: 42,
        }
    );
    let encoded = serde_json::to_vec(&event).expect("event JSON");
    let decoded: EventRecord = serde_json::from_slice(&encoded).expect("event round trip");
    assert_eq!(decoded.scope(), event.scope());
    assert_eq!(
        EventRecord::new(
            key,
            Provenance::Captured,
            EventPayload::Instruction(Instruction::default())
        )
        .scope(),
        EventScope::Artifact
    );
}

#[test]
fn provenance_keeps_unknown_and_damaged_distinct() {
    assert_ne!(Provenance::Unknown, Provenance::Damaged);
    assert_eq!(
        serde_json::to_string(&Provenance::Captured).unwrap(),
        "\"captured\""
    );
}

#[test]
fn capabilities_are_explicit_not_inferred_from_nullable_data() {
    let caps = ProviderCapabilities::qtrb_register_observations();
    assert!(caps.per_thread_ordering);
    assert!(caps.register_read_write_observation);
    assert!(!caps.global_ordering);
    assert!(!caps.full_register_checkpoint);
}

#[test]
fn event_kind_serialization_stably_names_every_payload_category() {
    let kinds = [
        EventKind::Begin,
        EventKind::ModuleDefinition,
        EventKind::InstructionDefinition,
        EventKind::Instruction,
        EventKind::Memory,
        EventKind::SemanticCall,
        EventKind::SemanticRule,
        EventKind::SemanticError,
        EventKind::ThreadLifecycle,
        EventKind::Syscall,
        EventKind::Signal,
        EventKind::SignalHandlerBoundary,
        EventKind::Termination,
        EventKind::RegisterCheckpoint,
        EventKind::RegisterDelta,
        EventKind::StringDefinition,
        EventKind::CoverageGap,
        EventKind::Discontinuity,
        EventKind::OpaqueOptional,
    ];

    assert_eq!(
        serde_json::to_value(kinds).unwrap(),
        serde_json::json!([
            "begin",
            "module_definition",
            "instruction_definition",
            "instruction",
            "memory",
            "semantic_call",
            "semantic_rule",
            "semantic_error",
            "thread_lifecycle",
            "syscall",
            "signal",
            "signal_handler_boundary",
            "termination",
            "register_checkpoint",
            "register_delta",
            "string_definition",
            "coverage_gap",
            "discontinuity",
            "opaque_optional"
        ])
    );
}

#[test]
fn captured_sequence_range_includes_u64_max_without_overflow() {
    let coverage =
        CompletenessRange::captured_sequence(u64::MAX - 2, u64::MAX, Provenance::Captured).unwrap();

    assert_eq!(coverage.domain(), RangeDomain::CapturedSequence);
    assert_eq!(
        coverage.bounds(),
        RangeBounds::InclusiveSequence {
            first: u64::MAX - 2,
            last: u64::MAX,
        }
    );
}

#[test]
fn completeness_range_deserialization_rejects_invalid_domain_or_bounds() {
    let reversed = serde_json::json!({
        "domain": "source_bytes",
        "bounds": { "half_open": { "start": 5, "end_exclusive": 4 } },
        "provenance": "damaged"
    });
    let mismatched = serde_json::json!({
        "domain": "captured_sequence",
        "bounds": { "half_open": { "start": 1, "end_exclusive": 2 } },
        "provenance": "captured"
    });

    assert!(serde_json::from_value::<CompletenessRange>(reversed).is_err());
    assert!(serde_json::from_value::<CompletenessRange>(mismatched).is_err());
}

#[test]
fn completeness_cause_is_stable_and_cannot_bypass_range_validation() {
    let missing = CompletenessRange::source_bytes_with_cause(
        0x200,
        0x200,
        Provenance::Unknown,
        CompletenessCause::MissingTerminal,
    )
    .unwrap();
    let checksum = CompletenessRange::captured_sequence_with_cause(
        7,
        9,
        Provenance::Damaged,
        CompletenessCause::Checksum,
    )
    .unwrap();

    assert_eq!(missing.cause(), CompletenessCause::MissingTerminal);
    assert_eq!(checksum.cause(), CompletenessCause::Checksum);
    assert_eq!(
        serde_json::to_value(missing).unwrap()["cause"],
        "missing_terminal"
    );
    assert_eq!(serde_json::to_value(checksum).unwrap()["cause"], "checksum");

    let legacy = serde_json::json!({
        "domain": "source_bytes",
        "bounds": { "half_open": { "start": 1, "end_exclusive": 2 } },
        "provenance": "captured"
    });
    assert_eq!(
        serde_json::from_value::<CompletenessRange>(legacy)
            .unwrap()
            .cause(),
        CompletenessCause::Unknown
    );

    let reversed = serde_json::json!({
        "domain": "source_bytes",
        "bounds": { "half_open": { "start": 5, "end_exclusive": 4 } },
        "provenance": "damaged",
        "cause": "checksum"
    });
    assert!(serde_json::from_value::<CompletenessRange>(reversed).is_err());
}

#[test]
fn fragment_offsets_are_bounded_ordered_and_deserialization_checked() {
    let key = EventKey::new(digest(0x44), TimelineId(2), 8, 0x100, None, Some(9));
    let record = EventRecord::with_fragment_source_offsets(
        key,
        Provenance::Captured,
        EventPayload::SemanticRule(SemanticEvent {
            category: None,
            name: "rule".into(),
            detail: "detail".into(),
            fragment_sequences: Vec::new(),
        }),
        vec![0x100, 0x120, 0x148],
    )
    .unwrap();
    assert_eq!(record.fragment_source_offsets(), &[0x100, 0x120, 0x148]);
    let encoded = serde_json::to_value(&record).unwrap();
    assert_eq!(
        serde_json::from_value::<EventRecord>(encoded.clone())
            .unwrap()
            .fragment_source_offsets(),
        &[0x100, 0x120, 0x148]
    );

    let mut wrong_first = encoded.clone();
    wrong_first["fragment_source_offsets"] = serde_json::json!([0x101, 0x120]);
    assert!(serde_json::from_value::<EventRecord>(wrong_first).is_err());
    let mut duplicate = encoded;
    duplicate["fragment_source_offsets"] = serde_json::json!([0x100, 0x100]);
    assert!(serde_json::from_value::<EventRecord>(duplicate).is_err());

    let mut legacy = serde_json::to_value(&record).unwrap();
    legacy
        .as_object_mut()
        .unwrap()
        .remove("fragment_source_offsets");
    assert!(
        serde_json::from_value::<EventRecord>(legacy)
            .unwrap()
            .fragment_source_offsets()
            .is_empty()
    );

    let mut oversized = serde_json::to_value(&record).unwrap();
    oversized["fragment_source_offsets"] = serde_json::to_value(
        (0..=MAX_FRAGMENT_SOURCE_OFFSETS)
            .map(|index| 0x100 + index as u64)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    assert!(serde_json::from_value::<EventRecord>(oversized).is_err());

    let key = EventKey::new(digest(0x44), TimelineId(2), 8, 0x100, None, Some(9));
    assert!(
        EventRecord::with_fragment_source_offsets(
            key,
            Provenance::Captured,
            EventPayload::SemanticRule(SemanticEvent {
                category: None,
                name: "rule".into(),
                detail: "detail".into(),
                fragment_sequences: Vec::new(),
            }),
            vec![0x100; MAX_FRAGMENT_SOURCE_OFFSETS + 1],
        )
        .is_none()
    );
}

#[test]
fn fragment_offset_deserialization_stops_at_the_public_bound() {
    let visited = Cell::new(0_usize);
    let values = (0..MAX_FRAGMENT_SOURCE_OFFSETS + 100).map(|index| {
        visited.set(visited.get() + 1);
        index as u64
    });
    let deserializer = serde::de::value::SeqDeserializer::<_, serde::de::value::Error>::new(values);

    assert!(FragmentSourceOffsets::deserialize(deserializer).is_err());
    assert_eq!(visited.get(), MAX_FRAGMENT_SOURCE_OFFSETS + 1);
}

#[test]
fn source_and_memory_ranges_are_checked_and_half_open() {
    for coverage in [
        CompletenessRange::source_bytes(0x100, 0x110, Provenance::Damaged).unwrap(),
        CompletenessRange::memory_addresses(0x100, 0x110, Provenance::Unknown).unwrap(),
    ] {
        assert!(coverage.contains(0x100));
        assert!(coverage.contains(0x10f));
        assert!(!coverage.contains(0x110));
    }
    assert!(CompletenessRange::source_bytes(5, 4, Provenance::Damaged).is_none());
    assert!(CompletenessRange::memory_addresses(5, 4, Provenance::Damaged).is_none());
}

#[test]
fn artifact_digest_round_trips_canonical_sha256_hex() {
    let expected = "abababababababababababababababababababababababababababababababab";
    let digest = ArtifactDigest::from_hex(expected).unwrap();

    assert_eq!(digest.to_hex(), expected);
    assert_eq!(
        serde_json::to_string(&digest).unwrap(),
        format!("\"{expected}\"")
    );
    assert!(ArtifactDigest::from_hex("ab").is_none());
}

#[test]
fn source_identity_version_fields_keep_legacy_deserialization_compatible() {
    let identity: SourceIdentity = serde_json::from_value(serde_json::json!({
        "artifact": "abababababababababababababababababababababababababababababababab",
        "format": "legacy",
        "source_bytes": 9
    }))
    .unwrap();
    assert_eq!(identity.format_major, 0);
    assert_eq!(identity.format_minor, 0);
}

#[test]
fn provider_error_detail_is_bounded_single_line_utf8() {
    let detail = format!("first\r\nsecond\n{}", "é".repeat(300));
    let error = ProviderError::new("source.invalid", "decode", None, false, detail);

    assert!(error.detail().starts_with("first  second "));
    assert!(!error.detail().contains(['\r', '\n']));
    assert_eq!(error.detail().len(), 512);
    assert!(error.detail().is_char_boundary(error.detail().len()));
    assert_eq!(error.code(), "source.invalid");
    assert_eq!(error.stage(), "decode");
    assert!(!error.retryable());
}

#[test]
fn provider_error_deserialization_preserves_bounded_single_line_detail() {
    let value = serde_json::json!({
        "code": "source.invalid",
        "stage": "decode",
        "source": null,
        "retryable": false,
        "detail": format!("first\r\nsecond\n{}", "é".repeat(300)),
    });

    let error: ProviderError = serde_json::from_value(value).unwrap();

    assert!(error.detail().starts_with("first  second "));
    assert!(!error.detail().contains(['\r', '\n']));
    assert_eq!(error.detail().len(), 512);
    assert!(error.detail().is_char_boundary(error.detail().len()));
}

#[test]
fn byte_source_reports_exact_short_reads_without_partial_success() {
    let source = ByteSource::new(vec![0x10, 0x20, 0x30]);
    let mut output = [0xaa; 2];

    let error = source.read_exact_at(2, &mut output).unwrap_err();

    assert_eq!(output, [0xaa; 2]);
    assert_eq!(error.code(), "source.short_read");
    assert_eq!(error.stage(), "read");
    assert_eq!(error.source().unwrap().offset, 2);
    assert!(!error.retryable());
}

struct LimitGuard {
    input_limit: u64,
    event_limit: u64,
    input: AtomicU64,
    events: AtomicU64,
}

impl WorkGuard for LimitGuard {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        let input = self.input.fetch_add(delta.input_bytes, Ordering::Relaxed) + delta.input_bytes;
        let events = self.events.fetch_add(delta.events, Ordering::Relaxed) + delta.events;
        if input > self.input_limit {
            return Err(OperationAbort::budget_exceeded(
                BudgetDimension::InputBytes,
                self.input_limit,
                input,
            ));
        }
        if events > self.event_limit {
            return Err(OperationAbort::budget_exceeded(
                BudgetDimension::Events,
                self.event_limit,
                events,
            ));
        }
        Ok(())
    }
}

#[test]
fn work_guard_can_abort_independently_on_byte_and_event_limits() {
    let guard = LimitGuard {
        input_limit: 5,
        event_limit: 2,
        input: AtomicU64::new(0),
        events: AtomicU64::new(0),
    };
    guard
        .consume(WorkDelta {
            input_bytes: 5,
            events: 2,
            ..WorkDelta::default()
        })
        .unwrap();

    assert_eq!(
        guard
            .consume(WorkDelta {
                input_bytes: 1,
                ..WorkDelta::default()
            })
            .unwrap_err(),
        OperationAbort::budget_exceeded(BudgetDimension::InputBytes, 5, 6)
    );

    let event_guard = LimitGuard {
        input_limit: 100,
        event_limit: 0,
        input: AtomicU64::new(0),
        events: AtomicU64::new(0),
    };
    assert_eq!(
        event_guard
            .consume(WorkDelta {
                events: 1,
                ..WorkDelta::default()
            })
            .unwrap_err(),
        OperationAbort::budget_exceeded(BudgetDimension::Events, 0, 1)
    );
}

#[test]
fn event_record_kind_is_derived_from_every_closed_payload_variant() {
    let semantic = SemanticEvent {
        category: Some("jni".into()),
        name: "FindClass".into(),
        detail: "java/lang/String".into(),
        fragment_sequences: Vec::new(),
    };
    let payloads = [
        (
            EventPayload::Begin(BeginMetadata {
                run_id: 9,
                pid: 10,
                tid: Some(11),
                ..BeginMetadata::default()
            }),
            EventKind::Begin,
        ),
        (
            EventPayload::ModuleDefinition(ModuleDefinition {
                module_id: 1,
                base: 0x1000,
                name: "libtarget.so".into(),
            }),
            EventKind::ModuleDefinition,
        ),
        (
            EventPayload::InstructionDefinition(InstructionDefinition {
                definition_id: 2,
                ..InstructionDefinition::default()
            }),
            EventKind::InstructionDefinition,
        ),
        (
            EventPayload::Instruction(Instruction {
                definition_id: 2,
                module_id: 1,
                relative_pc: 0x40,
                ..Instruction::default()
            }),
            EventKind::Instruction,
        ),
        (
            EventPayload::Memory(Memory {
                address: 0x2000,
                size: 8,
                direction: MemoryDirection::Read,
                ..Memory::default()
            }),
            EventKind::Memory,
        ),
        (
            EventPayload::SemanticCall(semantic.clone()),
            EventKind::SemanticCall,
        ),
        (
            EventPayload::SemanticRule(semantic.clone()),
            EventKind::SemanticRule,
        ),
        (
            EventPayload::SemanticError(semantic),
            EventKind::SemanticError,
        ),
        (
            EventPayload::ThreadLifecycle(ThreadLifecycle {
                tid: 11,
                phase: ThreadLifecyclePhase::Begin,
                creator_tid: None,
                start_routine: None,
                module_generation: None,
            }),
            EventKind::ThreadLifecycle,
        ),
        (
            EventPayload::Syscall(Syscall {
                tid: 11,
                number: 93,
                pc: 0,
                arguments: [0; 6],
                result: None,
            }),
            EventKind::Syscall,
        ),
        (
            EventPayload::Signal(Signal {
                tid: 11,
                number: 6,
                code: 0,
                pc: 0,
                sp: 0,
                fault_address: 0,
                flags: 0,
            }),
            EventKind::Signal,
        ),
        (
            EventPayload::SignalHandlerBoundary(SignalHandlerBoundary {
                tid: 11,
                phase: SignalHandlerPhase::Return,
                number: 0,
                code: 0,
                pc: 0,
                sp: 0,
                fault_address: 0,
                flags: 0,
                depth: 0,
                nested_delivery_count: 0,
                begin_sequence: None,
            }),
            EventKind::SignalHandlerBoundary,
        ),
        (
            EventPayload::Termination(Termination {
                kind: TerminationKind::Completed,
                ..Termination::default()
            }),
            EventKind::Termination,
        ),
        (
            EventPayload::RegisterCheckpoint(RegisterCheckpoint {
                values: vec![RegisterValue {
                    slot: RegisterSlot::X0,
                    value: 1,
                }],
            }),
            EventKind::RegisterCheckpoint,
        ),
        (
            EventPayload::RegisterDelta(RegisterDelta {
                mask: 1,
                changed: vec![RegisterValue {
                    slot: RegisterSlot::X0,
                    value: 2,
                }],
                ancestry_reliable: true,
            }),
            EventKind::RegisterDelta,
        ),
        (
            EventPayload::StringDefinition(StringDefinition {
                id: 1,
                bytes: b"x".to_vec(),
            }),
            EventKind::StringDefinition,
        ),
        (
            EventPayload::CoverageGap(CoverageGap {
                tid: 11,
                pc: 0,
                sp: 0,
                fault_address: 0,
                reason_flags: 1,
                dropped_count: 0,
            }),
            EventKind::CoverageGap,
        ),
        (
            EventPayload::Discontinuity(Discontinuity {
                cause: DiscontinuityCause::Damage,
                evidence: CompletenessRange::source_bytes(1, 2, Provenance::Damaged).unwrap(),
            }),
            EventKind::Discontinuity,
        ),
        (
            EventPayload::OpaqueOptional(OpaqueOptionalRecord {
                record_type: 0x8001,
                flags: 3,
                bytes: vec![0xde, 0xad],
            }),
            EventKind::OpaqueOptional,
        ),
    ];

    for (ordinal, (payload, expected_kind)) in payloads.into_iter().enumerate() {
        assert_eq!(payload.kind(), expected_kind);
        let record = EventRecord::new(
            EventKey::new(digest(0x22), TimelineId(3), ordinal as u64, 0, None, None),
            Provenance::Captured,
            payload,
        );
        assert_eq!(record.kind(), expected_kind);
    }
}

#[test]
fn register_snapshot_deserialization_preserves_the_exact_34_slot_invariant() {
    let valid = serde_json::json!({"values": vec![0_u64; RegisterSlot::COUNT]});
    let snapshot: qtrace_provider::RegisterSnapshot =
        serde_json::from_value(valid).expect("valid register snapshot");
    assert_eq!(snapshot.values().len(), RegisterSlot::COUNT);

    let invalid = serde_json::json!({"values": []});
    assert!(serde_json::from_value::<qtrace_provider::RegisterSnapshot>(invalid).is_err());
}

struct PermitAll;

impl WorkGuard for PermitAll {
    fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
        Ok(())
    }
}

struct FakeCursor {
    events: std::vec::IntoIter<EventRecord>,
    drained: bool,
    summary: ProviderSummary,
}

impl EventCursor for FakeCursor {
    fn next_event(&mut self, guard: &dyn WorkGuard) -> Result<Option<EventRecord>, ProviderError> {
        if let Some(event) = self.events.next() {
            guard
                .consume(WorkDelta {
                    events: 1,
                    ..WorkDelta::default()
                })
                .map_err(ProviderError::from)?;
            return Ok(Some(event));
        }
        self.drained = true;
        Ok(None)
    }

    fn finish(self: Box<Self>) -> Result<ProviderSummary, ProviderError> {
        if !self.drained {
            return Err(ProviderError::stream_not_drained());
        }
        Ok(self.summary)
    }
}

struct FakeProvider {
    identity: SourceIdentity,
    capabilities: ProviderCapabilities,
    timelines: Vec<TimelineDescriptor>,
    events: Vec<EventRecord>,
}

impl TraceProvider for FakeProvider {
    fn identity(&self) -> &SourceIdentity {
        &self.identity
    }

    fn capabilities(&self) -> &ProviderCapabilities {
        &self.capabilities
    }

    fn timelines(&self) -> &[TimelineDescriptor] {
        &self.timelines
    }

    fn into_cursor(self: Box<Self>) -> Result<Box<dyn EventCursor>, ProviderError> {
        let summary = ProviderSummary {
            timelines: self.timelines.clone(),
            termination: None,
            counters: ProviderCounters {
                events_emitted: self.events.len() as u64,
                ..ProviderCounters::default()
            },
            completeness: vec![],
        };
        Ok(Box::new(FakeCursor {
            events: self.events.into_iter(),
            drained: false,
            summary,
        }))
    }
}

fn fake_provider() -> Box<dyn TraceProvider> {
    Box::new(FakeProvider {
        identity: SourceIdentity {
            artifact: digest(0x33),
            format: "test".into(),
            format_major: 7,
            format_minor: 4,
            source_bytes: 4,
        },
        capabilities: ProviderCapabilities::qtrb_register_observations(),
        timelines: vec![TimelineDescriptor {
            id: TimelineId(8),
            tid: Some(17),
            label: None,
        }],
        events: vec![EventRecord::new(
            EventKey::new(digest(0x33), TimelineId(8), 0, 0, None, Some(17)),
            Provenance::Captured,
            EventPayload::Begin(BeginMetadata {
                run_id: 1,
                pid: 2,
                tid: Some(17),
                ..BeginMetadata::default()
            }),
        )],
    })
}

#[test]
fn one_shot_cursor_releases_summary_only_after_stream_is_drained() {
    let early = fake_provider().into_cursor().unwrap().finish().unwrap_err();
    assert_eq!(early.code(), "source.stream_not_drained");

    let mut cursor = fake_provider().into_cursor().unwrap();
    let mut events = vec![];
    while let Some(event) = cursor.next_event(&PermitAll).unwrap() {
        events.push(event);
    }
    let summary = cursor.finish().unwrap();

    assert_eq!(events.len(), 1);
    assert_eq!(summary.counters.events_emitted, 1);
    assert_eq!(summary.timelines[0].tid, Some(17));
}
