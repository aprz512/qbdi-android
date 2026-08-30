use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

use qtrace_provider::{
    ArtifactDigest, ByteSource, CompletenessCause, EventPayload, FlightProvider, OperationAbort,
    RangeBounds, SourceIdentity, TraceProvider, WorkDelta, WorkGuard,
};
use serde_json::{Value, json};

struct AllowAll;

impl WorkGuard for AllowAll {
    fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
        Ok(())
    }
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/flight")
        .join(name)
}

fn oracle(path: &Path) -> Value {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("python3")
        .arg("tools/oracle.py")
        .arg("flight")
        .arg(path)
        .current_dir(&workspace)
        .output()
        .expect("run Flight oracle");
    assert!(
        output.status.success(),
        "oracle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("parse oracle JSON")
}

struct Collected {
    projections: Vec<qtrace_provider::FlightProjectionDescriptor>,
    recovery: qtrace_provider::FlightRecoverySummary,
    events: Vec<qtrace_provider::EventRecord>,
    summary: qtrace_provider::ProviderSummary,
}

fn collect(name: &str) -> Collected {
    let bytes = fs::read(fixture_path(name)).expect("read Flight fixture");
    let size = bytes.len() as u64;
    let provider = FlightProvider::open(
        Arc::new(ByteSource::new(bytes)),
        SourceIdentity {
            artifact: ArtifactDigest::new([0x72; 32]),
            format: "Flight".to_owned(),
            format_major: 0,
            format_minor: 0,
            source_bytes: size,
        },
        &AllowAll,
    )
    .expect("open Flight fixture");
    let snapshots = provider.projections().to_vec();
    let recovery = provider.recovery_summary().clone();
    let mut cursor = Box::new(provider).into_cursor().expect("Flight cursor");
    let mut events = Vec::new();
    while let Some(event) = cursor.next_event(&AllowAll).expect("Flight event") {
        events.push(event);
    }
    let summary = cursor.finish().expect("Flight summary");
    Collected {
        projections: snapshots,
        recovery,
        events,
        summary,
    }
}

fn semantic_events(events: &[qtrace_provider::EventRecord]) -> Vec<Value> {
    events
        .iter()
        .filter_map(|event| {
            let global_seq = event.key.sequence?;
            let tid = event.key.tid?;
            let (kind, data) = match &event.payload {
                EventPayload::ThreadLifecycle(value) => {
                    let kind = match value.phase {
                        qtrace_provider::ThreadLifecyclePhase::Begin => "thread_begin",
                        qtrace_provider::ThreadLifecyclePhase::End => "thread_end",
                    };
                    (kind, serde_json::to_value(value).ok()?)
                }
                EventPayload::Instruction(value) => {
                    ("instruction", serde_json::to_value(value).ok()?)
                }
                EventPayload::Memory(value) => ("memory", serde_json::to_value(value).ok()?),
                EventPayload::SemanticCall(value) => ("call", serde_json::to_value(value).ok()?),
                EventPayload::SemanticRule(value) => ("rule", serde_json::to_value(value).ok()?),
                EventPayload::SemanticError(value) => ("error", serde_json::to_value(value).ok()?),
                EventPayload::RegisterDelta(value) => {
                    ("register_delta", serde_json::to_value(value).ok()?)
                }
                EventPayload::Syscall(value) => ("syscall", serde_json::to_value(value).ok()?),
                EventPayload::Signal(value) => ("signal", serde_json::to_value(value).ok()?),
                EventPayload::SignalHandlerBoundary(value) => {
                    let kind = match value.phase {
                        qtrace_provider::SignalHandlerPhase::Begin => "signal_handler_begin",
                        qtrace_provider::SignalHandlerPhase::Return => "signal_handler_return",
                    };
                    (kind, serde_json::to_value(value).ok()?)
                }
                EventPayload::Termination(value) => {
                    ("termination_intent", serde_json::to_value(value).ok()?)
                }
                EventPayload::CoverageGap(value) => {
                    ("coverage_gap", serde_json::to_value(value).ok()?)
                }
                _ => return None,
            };
            Some(json!({"global_seq": global_seq, "tid": tid, "kind": kind, "data": data}))
        })
        .collect()
}

fn ranges(summary: &qtrace_provider::ProviderSummary, cause: CompletenessCause) -> Vec<[u64; 2]> {
    summary
        .completeness
        .iter()
        .filter_map(|range| {
            if range.cause() != cause {
                return None;
            }
            match range.bounds() {
                RangeBounds::InclusiveSequence { first, last } => Some([first, last]),
                RangeBounds::HalfOpen { .. } => None,
            }
        })
        .collect()
}

fn u32_values(value: &Value) -> Vec<u32> {
    value
        .as_array()
        .expect("u32 array")
        .iter()
        .map(|item| item.as_u64().expect("u32") as u32)
        .collect()
}

fn u64_values(value: &Value) -> Vec<u64> {
    value
        .as_array()
        .expect("u64 array")
        .iter()
        .map(|item| item.as_u64().expect("u64"))
        .collect()
}

#[test]
fn every_flight_fixture_matches_the_python_recovery_oracle() {
    for name in [
        "v2-active.bin",
        "v2-checkpoint-delta.bin",
        "v2-checksum-damaged.bin",
        "v2-complete.bin",
        "v2-coverage-gap.bin",
        "v2-incomplete-fragment.bin",
        "v2-overwritten.bin",
        "v2-stale-directory.bin",
    ] {
        let expected = oracle(&fixture_path(name));
        let actual = collect(name);
        let actual_events = semantic_events(&actual.events);
        let expected_events = expected["events"].as_array().expect("oracle events");
        assert_eq!(
            actual_events
                .iter()
                .map(|event| (&event["global_seq"], &event["tid"], &event["kind"]))
                .collect::<Vec<_>>(),
            expected_events
                .iter()
                .map(|event| (&event["global_seq"], &event["tid"], &event["kind"]))
                .collect::<Vec<_>>(),
            "merged semantic order mismatch for {name}"
        );

        let expected_threads = expected["threads"].as_object().expect("oracle threads");
        let actual_threads: BTreeMap<_, _> = actual
            .projections
            .iter()
            .map(|projection| {
                let registers = projection
                    .final_registers
                    .as_ref()
                    .map(|snapshot| snapshot.values());
                (projection.tid.to_string(), registers)
            })
            .collect();
        for (tid, expected_registers) in expected_threads {
            let expected_values: Vec<u64> = expected_registers["x"]
                .as_array()
                .expect("oracle X registers")
                .iter()
                .map(|value| value.as_u64().expect("register value"))
                .chain([
                    expected_registers["sp"].as_u64().expect("SP"),
                    expected_registers["pc"].as_u64().expect("PC"),
                    expected_registers["nzcv"].as_u64().expect("NZCV"),
                ])
                .collect();
            assert_eq!(
                actual_threads[tid],
                Some(expected_values.as_slice()),
                "final registers for {name} TID {tid}"
            );
        }
        for projection in &actual.projections {
            let expected_keys = actual
                .events
                .iter()
                .filter(|event| event.key.tid == Some(projection.tid))
                .map(|event| event.key.clone())
                .collect::<Vec<_>>();
            assert_eq!(
                projection.event_keys, expected_keys,
                "per-TID projection for {name}"
            );
            assert!(
                projection
                    .event_keys
                    .windows(2)
                    .all(|pair| pair[0].sequence < pair[1].sequence)
            );
        }

        assert_eq!(
            ranges(&actual.summary, CompletenessCause::Retained),
            expected["summary"]["retained_sequences"]
                .as_array()
                .expect("retained ranges")
                .iter()
                .map(|pair| [pair[0].as_u64().unwrap(), pair[1].as_u64().unwrap()])
                .collect::<Vec<_>>(),
            "retained ranges for {name}"
        );
        let mut normalized_lost = ranges(&actual.summary, CompletenessCause::Lost);
        normalized_lost.extend(ranges(&actual.summary, CompletenessCause::Checksum));
        normalized_lost.sort_unstable();
        assert_eq!(
            normalized_lost,
            expected["summary"]["lost_sequences"]
                .as_array()
                .expect("lost ranges")
                .iter()
                .map(|pair| [pair[0].as_u64().unwrap(), pair[1].as_u64().unwrap()])
                .collect::<Vec<_>>(),
            "lost ranges for {name}"
        );
        let mut normalized_overwritten = ranges(&actual.summary, CompletenessCause::Overwritten);
        if actual.recovery.complete && normalized_overwritten.is_empty() {
            normalized_overwritten = ranges(&actual.summary, CompletenessCause::Lost);
        }
        assert_eq!(
            normalized_overwritten,
            expected["summary"]["overwritten_sequences"]
                .as_array()
                .expect("overwritten ranges")
                .iter()
                .map(|pair| [pair[0].as_u64().unwrap(), pair[1].as_u64().unwrap()])
                .collect::<Vec<_>>(),
            "overwritten ranges for {name}"
        );
        let expected_damage = !expected["summary"]["recovery_damage"]
            .as_array()
            .expect("recovery damage")
            .is_empty()
            || !expected["summary"]["incomplete_logical_events"]
                .as_array()
                .expect("incomplete logical events")
                .is_empty();
        assert_eq!(
            actual
                .summary
                .completeness
                .iter()
                .any(|item| item.provenance() == qtrace_provider::Provenance::Damaged),
            expected_damage,
            "normalized damage evidence for {name}"
        );

        let expected_termination = &expected["summary"]["termination"];
        let actual_termination = actual.summary.termination.as_ref();
        if expected_termination["cause"] == "termination_intent" {
            let intent = actual_termination
                .and_then(|value| value.intent.as_ref())
                .expect("termination intent");
            assert_eq!(intent.pc, expected_termination["pc"].as_u64().unwrap());
            assert_eq!(
                intent.syscall_number,
                expected_termination["signal_number"].as_i64().unwrap()
            );
        } else {
            assert!(
                actual_termination.is_none(),
                "unexpected termination for {name}"
            );
        }

        let expected_handlers = expected["summary"]["signal_handler_intervals"]
            .as_array()
            .expect("handler intervals");
        let actual_handler_begins = actual.events.iter().filter(|event| {
            matches!(
                event.payload,
                EventPayload::SignalHandlerBoundary(ref value)
                    if value.phase == qtrace_provider::SignalHandlerPhase::Begin
            )
        });
        assert_eq!(
            actual_handler_begins.count(),
            expected_handlers.len(),
            "handler intervals for {name}"
        );
        assert_eq!(
            actual.recovery.complete, expected["summary"]["complete"],
            "complete flag for {name}"
        );
        assert_eq!(
            actual.recovery.active_chunks,
            u32_values(&expected["summary"]["active_chunks"]),
            "active chunks for {name}"
        );
        assert_eq!(
            actual.recovery.stale_directory_entries,
            u32_values(&expected["summary"]["stale_directory_entries"]),
            "stale entries for {name}"
        );
        assert_eq!(
            actual.recovery.rotating_directory_entries,
            u32_values(&expected["summary"]["rotating_directory_entries"]),
            "rotating entries for {name}"
        );
        assert_eq!(
            actual.recovery.target_pcs,
            u64_values(&expected["summary"]["target_pcs"]),
            "target PCs for {name}"
        );
    }
}
