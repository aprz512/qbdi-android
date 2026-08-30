use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

use qtrace_provider::{
    ArtifactDigest, ByteSource, CompletenessCause, EventKey, EventPayload, FlightProvider,
    OperationAbort, RangeBounds, SourceIdentity, TimelineId, TraceProvider, WorkDelta, WorkGuard,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

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
    artifact: ArtifactDigest,
    projections: Vec<qtrace_provider::FlightProjectionDescriptor>,
    recovery: qtrace_provider::FlightRecoverySummary,
    events: Vec<qtrace_provider::EventRecord>,
    summary: qtrace_provider::ProviderSummary,
}

fn collect(name: &str) -> Collected {
    let bytes = fs::read(fixture_path(name)).expect("read Flight fixture");
    let size = bytes.len() as u64;
    let calculated = ArtifactDigest::new(Sha256::digest(&bytes).into());
    let manifest: Value = serde_json::from_slice(
        &fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/manifest.json"))
            .expect("read fixture manifest"),
    )
    .expect("parse fixture manifest");
    let relative = format!("flight/{name}");
    let manifest_digest = manifest["fixtures"]
        .as_array()
        .expect("fixture manifest entries")
        .iter()
        .find(|entry| entry["path"] == relative)
        .and_then(|entry| entry["sha256"].as_str())
        .and_then(ArtifactDigest::from_hex)
        .expect("Flight fixture digest in manifest");
    assert_eq!(
        calculated, manifest_digest,
        "fixture digest drift for {name}"
    );
    let provider = FlightProvider::open(
        Arc::new(ByteSource::new(bytes)),
        SourceIdentity {
            artifact: calculated,
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
        artifact: calculated,
        projections: snapshots,
        recovery,
        events,
        summary,
    }
}

fn typed_events(events: &[qtrace_provider::EventRecord]) -> Vec<Value> {
    events
        .iter()
        .filter_map(|event| {
            let (kind, data) = match &event.payload {
                EventPayload::Begin(value) => ("chunk_begin", serde_json::to_value(value).ok()?),
                EventPayload::InstructionDefinition(value) => {
                    ("instruction_definition", serde_json::to_value(value).ok()?)
                }
                EventPayload::RegisterCheckpoint(value) => {
                    ("register_checkpoint", serde_json::to_value(value).ok()?)
                }
                EventPayload::StringDefinition(value) => {
                    ("string_definition", serde_json::to_value(value).ok()?)
                }
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
                EventPayload::Discontinuity(value) => (
                    "discontinuity",
                    discontinuity_data(
                        value.evidence.bounds(),
                        value.evidence.provenance(),
                        value.evidence.cause(),
                    ),
                ),
                _ => return None,
            };
            Some(json!({
                "artifact": event.key.artifact,
                "timeline": event.key.timeline.0,
                "record_ordinal": event.key.record_ordinal,
                "global_seq": event.key.sequence,
                "tid": event.key.tid,
                "kind": kind,
                "source_offset": event.key.source_offset,
                "provenance": event.provenance,
                "fragment_source_offsets": event.fragment_source_offsets(),
                "data": data,
            }))
        })
        .collect()
}

fn projection_key_matches_row(key: &EventKey, row: &Value) -> bool {
    event_key_from_row(row).as_ref() == Some(key)
}

fn event_key_from_row(row: &Value) -> Option<EventKey> {
    Some(EventKey::new(
        ArtifactDigest::from_hex(row["artifact"].as_str()?)?,
        TimelineId(row["timeline"].as_u64()?),
        row["record_ordinal"].as_u64()?,
        row["source_offset"].as_u64()?,
        row["global_seq"].as_u64(),
        row["tid"].as_u64().and_then(|tid| u32::try_from(tid).ok()),
    ))
}

#[test]
fn projection_key_comparison_rejects_wrong_ordinal_artifact_and_timeline() {
    let row = json!({
        "artifact": ArtifactDigest::new([1; 32]), "timeline": 0,
        "record_ordinal": 3, "tid": 7, "global_seq": 11, "source_offset": 4096,
    });
    let correct = EventKey::new(
        ArtifactDigest::new([1; 32]),
        TimelineId(0),
        3,
        4096,
        Some(11),
        Some(7),
    );
    for wrong in [
        EventKey::new(
            ArtifactDigest::new([1; 32]),
            TimelineId(0),
            4,
            4096,
            Some(11),
            Some(7),
        ),
        EventKey::new(
            ArtifactDigest::new([2; 32]),
            TimelineId(0),
            3,
            4096,
            Some(11),
            Some(7),
        ),
        EventKey::new(
            ArtifactDigest::new([1; 32]),
            TimelineId(9),
            3,
            4096,
            Some(11),
            Some(7),
        ),
    ] {
        assert!(
            !projection_key_matches_row(&wrong, &row),
            "wrong full EventKey was accepted against {correct:?}"
        );
    }
}

fn canonical_oracle_typed_events(expected: &Value, artifact: ArtifactDigest) -> Vec<Value> {
    let mut output = expected["events"]
        .as_array()
        .expect("oracle events")
        .iter()
        .map(|event| canonical_oracle_event(event, artifact))
        .collect::<Vec<_>>();
    let semantic = expected["events"].as_array().expect("oracle events");
    for record in expected["summary"]["physical_records"]
        .as_array()
        .expect("physical records")
    {
        let kind = record["kind"].as_u64().expect("wire kind");
        let flags = record["flags"].as_u64().expect("wire flags");
        let bytes = hex_bytes(record);
        let data = match (kind, flags) {
            (1, 0) => {
                let profile = match bytes[0] {
                    0 => "fast",
                    1 => "balanced",
                    _ => "full",
                };
                let target_len = u16::from_le_bytes(bytes[2..4].try_into().unwrap()) as usize;
                let scene_len = u16::from_le_bytes(bytes[4..6].try_into().unwrap()) as usize;
                let target = String::from_utf8(bytes[40..40 + target_len].to_vec()).unwrap();
                let scene =
                    String::from_utf8(bytes[40 + target_len..40 + target_len + scene_len].to_vec())
                        .unwrap();
                json!({
                    "module_base": le_u64(&bytes, 16),
                    "target_offset": le_u64(&bytes, 24),
                    "target_address": le_u64(&bytes, 32),
                    "pid": le_u32(&bytes, 8),
                    "tid": le_u32(&bytes, 12),
                    "profile": profile,
                    "compression_enabled": false,
                    "effective_buffer_bytes": 0,
                    "run_id": expected["summary"]["run_id"],
                    "scene": scene,
                    "target": target,
                    "pointer_width": bytes[1],
                    "chunk_index": record["chunk_index"],
                    "chunk_generation": record["generation"],
                })
            }
            (9, 1) => json!({
                "values": (0..34).map(|index| json!({
                    "slot": slot_name(index),
                    "value": le_u64(&bytes, index as usize * 8),
                })).collect::<Vec<_>>()
            }),
            (4, 1) => {
                let definition_id = le_u32(&bytes, 8);
                let definition = semantic
                    .iter()
                    .find(|event| {
                        event["kind"] == "instruction"
                            && event["data"]["metadata_id"].as_u64()
                                == Some(u64::from(definition_id))
                    })
                    .expect("definition has oracle instruction");
                let raw = &definition["data"];
                json!({
                    "definition_id": definition_id,
                    "opcode": raw["opcode"],
                    "read_mask": raw["read_mask"],
                    "write_mask": raw["write_mask"],
                    "pc_displacement": raw["displacement"],
                    "flags": raw["instruction_flags"],
                    "pc_kind": match raw["pc_kind"].as_u64().unwrap() {
                        0 => "none", 1 => "instruction", _ => "page",
                    },
                    "condition": raw["condition"],
                    "slow_memory_path": raw["slow_memory_path"] == 1,
                    "mnemonic": raw["mnemonic"],
                    "operands": raw["operands"],
                    "disassembly": raw["disassembly"],
                    "reads": raw["read_registers"].as_array().unwrap().iter().map(|item| json!({
                        "slot": item["index"], "captured_width": item["width"], "name": item["name"],
                    })).collect::<Vec<_>>(),
                    "writes": raw["write_registers"].as_array().unwrap().iter().map(|item| json!({
                        "slot": item["index"], "captured_width": item["width"], "name": item["name"],
                    })).collect::<Vec<_>>(),
                    "memory_operands": raw["memory_operands"].as_array().unwrap().iter().map(|item| json!({
                        "base": if item["base"] == 255 { Value::Null } else { item["base"].clone() },
                        "index": if item["index"] == 255 { Value::Null } else { item["index"].clone() },
                        "extend": match item["extend"].as_u64().unwrap() { 0 => "none", 1 => "uxtw", 2 => "sxtw", 3 => "lsl", _ => "sxtx" },
                        "mode": match item["mode"].as_u64().unwrap() { 0 => "offset", 1 => "pre_index", _ => "post_index" },
                        "shift": item["shift"],
                        "direction": match item["access_kind"].as_u64().unwrap() { 1 => "read", 2 => "write", _ => "read_write" },
                        "writeback": item["writeback"] == 1,
                        "size": item["size"],
                        "displacement": item["displacement"],
                    })).collect::<Vec<_>>(),
                })
            }
            (6, 3) => {
                let size = le_u32(&bytes, 4) as usize;
                json!({"id": le_u32(&bytes, 0), "bytes": bytes[8..8 + size]})
            }
            _ => continue,
        };
        let name = match (kind, flags) {
            (1, 0) => "chunk_begin",
            (9, 1) => "register_checkpoint",
            (4, 1) => "instruction_definition",
            (6, 3) => "string_definition",
            _ => unreachable!(),
        };
        output.push(json!({
            "artifact": artifact,
            "timeline": 0,
            "record_ordinal": record["record_ordinal"],
            "global_seq": record["global_seq"],
            "tid": record["tid"],
            "kind": name,
            "source_offset": record["source_offset"],
            "provenance": "captured",
            "fragment_source_offsets": [],
            "data": data,
        }));
    }
    output.sort_by_key(|event| event["global_seq"].as_u64().expect("global sequence"));
    let mut record_ordinal = expected["summary"]["next_record_ordinal"]
        .as_u64()
        .expect("next oracle record ordinal");
    for range in expected_completeness(expected) {
        if range["domain"] != "source_bytes" || range["cause"] == "retained" {
            continue;
        }
        let first = range["first"].as_u64().unwrap();
        let last = range["last"].as_u64().unwrap();
        output.push(json!({
            "artifact": artifact,
            "timeline": 0,
            "record_ordinal": record_ordinal,
            "global_seq": Value::Null,
            "tid": Value::Null,
            "kind": "discontinuity",
            "source_offset": first,
            "provenance": range["provenance"],
            "fragment_source_offsets": [],
            "data": discontinuity_data_from_names(
                "source_bytes", first, last,
                range["provenance"].as_str().unwrap(),
                range["cause"].as_str().unwrap(),
            ),
        }));
        record_ordinal += 1;
    }
    for proof in expected_sequence_proofs_ordered(expected) {
        let first = proof["first"].as_u64().unwrap();
        let last = proof["last"].as_u64().unwrap();
        output.push(json!({
            "artifact": artifact,
            "timeline": 0,
            "record_ordinal": record_ordinal,
            "global_seq": Value::Null,
            "tid": Value::Null,
            "kind": "discontinuity",
            "source_offset": proof["source_offset"],
            "provenance": proof["provenance"],
            "fragment_source_offsets": [],
            "data": discontinuity_data_from_names(
                "captured_sequence", first, last,
                proof["provenance"].as_str().unwrap(),
                proof["cause"].as_str().unwrap(),
            ),
        }));
        record_ordinal += 1;
    }
    output
}

fn hex_bytes(value: &Value) -> Vec<u8> {
    let text = value["payload_hex"]
        .as_str()
        .or_else(|| value["bytes"].as_str())
        .expect("payload hex");
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex byte"))
        .collect()
}

fn le_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("u32 field"))
}

fn le_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("u64 field"))
}

fn slot_name(index: u64) -> String {
    match index {
        0..=30 => format!("x{index}"),
        31 => "sp".to_owned(),
        32 => "pc".to_owned(),
        33 => "nzcv".to_owned(),
        _ => panic!("invalid register slot"),
    }
}

fn capture(value: &Value) -> Value {
    match value["state"].as_u64().expect("capture state") {
        0 => json!("not_captured"),
        1 => json!({"captured": hex_bytes(value)}),
        2 => json!("unavailable"),
        _ => panic!("invalid capture state"),
    }
}

fn canonical_oracle_event(event: &Value, artifact: ArtifactDigest) -> Value {
    let kind = event["kind"].as_str().expect("event kind");
    let tid = event["tid"].as_u64().expect("event tid");
    let source_offset = event["source_offset"]
        .as_u64()
        .expect("event source offset");
    let raw = &event["data"];
    let mut fragment_offsets = Vec::new();
    let mut provenance = "captured";
    let data = match kind {
        "thread_begin" => {
            let bytes = hex_bytes(raw);
            if bytes.len() == 24 && u64::from(le_u32(&bytes, 4)) == tid {
                json!({
                    "tid": tid, "phase": "begin",
                    "creator_tid": le_u32(&bytes, 0),
                    "start_routine": le_u64(&bytes, 8),
                    "module_generation": le_u64(&bytes, 16),
                })
            } else {
                provenance = "damaged";
                json!({"tid": tid, "phase": "begin"})
            }
        }
        "thread_end" => json!({"tid": tid, "phase": "end"}),
        "instruction" => json!({
            "definition_id": raw["metadata_id"],
            "module_id": 1,
            "relative_pc": raw["relative_pc"],
            "read_before": raw["read_registers"].as_array().expect("reads").iter().map(|item| json!({
                "slot": item["index"], "captured_width": item["width"],
                "name": item["name"], "value": item["value"],
            })).collect::<Vec<_>>(),
            "write_after": raw["write_registers"].as_array().expect("writes").iter().map(|item| json!({
                "slot": item["index"], "captured_width": item["width"],
                "name": item["name"], "value": item["value"],
            })).collect::<Vec<_>>(),
        }),
        "memory" => json!({
            "module_id": 1,
            "relative_pc": raw["relative_pc"],
            "address": raw["address"],
            "size": raw["size"],
            "direction": match raw["access_kind"].as_u64().expect("access kind") { 1 => "read", 2 => "write", _ => "read_write" },
            "metadata_available": raw["metadata_available"] == 1,
            "flags": raw["flags"],
            "value": raw["value"],
            "before": capture(&raw["before"]),
            "after": capture(&raw["after"]),
        }),
        "call" | "rule" | "error" => {
            fragment_offsets = raw["fragment_source_offsets"]
                .as_array()
                .map(|values| {
                    values
                        .iter()
                        .map(|value| value.as_u64().expect("fragment offset"))
                        .collect()
                })
                .unwrap_or_default();
            let mut value = json!({
                "category": if kind == "call" { raw["category"].clone() } else { Value::Null },
                "name": raw["name"],
                "detail": raw["detail"],
            });
            if let Some(sequences) = raw["fragment_sequences"].as_array() {
                value["fragment_sequences"] = Value::Array(sequences.clone());
            }
            value
        }
        "register_delta" => {
            let mut changed = raw["changed"]
                .as_object()
                .expect("changed registers")
                .iter()
                .map(|(index, value)| (index.parse::<u64>().expect("slot"), value.clone()))
                .collect::<Vec<_>>();
            changed.sort_by_key(|(index, _)| *index);
            let mask = changed
                .iter()
                .fold(0_u64, |mask, (index, _)| mask | (1_u64 << index));
            json!({
                "mask": mask,
                "changed": changed.into_iter().map(|(index, value)| json!({"slot": slot_name(index), "value": value})).collect::<Vec<_>>(),
                "ancestry_reliable": true,
            })
        }
        "syscall" => {
            let bytes = hex_bytes(raw);
            json!({
                "tid": tid,
                "number": le_u64(&bytes, 56) as i64,
                "pc": le_u64(&bytes, 0),
                "arguments": (0..6).map(|index| le_u64(&bytes, 8 + index * 8)).collect::<Vec<_>>(),
                "result": le_u64(&bytes, 64) as i64,
            })
        }
        "signal" => {
            let bytes = hex_bytes(raw);
            let mut value = json!({"tid": tid, "number": le_u32(&bytes, 0) as i32});
            for (key, field) in [
                ("code", u64::from(le_u32(&bytes, 4))),
                ("fault_address", le_u64(&bytes, 8)),
                ("pc", le_u64(&bytes, 16)),
            ] {
                if field != 0 {
                    value[key] = json!(field);
                }
            }
            value
        }
        "signal_handler_begin" | "signal_handler_return" => {
            let mut value = json!({
                "tid": tid,
                "phase": if kind.ends_with("begin") { "begin" } else { "return" },
            });
            for (key, field) in [
                ("number", raw["signal_number"].as_i64().expect("signal")),
                ("code", raw["signal_code"].as_i64().expect("code")),
                ("pc", raw["pc"].as_i64().expect("pc")),
                ("sp", raw["sp"].as_i64().expect("sp")),
                (
                    "fault_address",
                    raw["fault_address"].as_i64().expect("fault"),
                ),
                ("flags", raw["flags"].as_i64().expect("flags")),
                (
                    "depth",
                    (raw["flags"].as_u64().expect("flags") & 0xffff) as i64,
                ),
                (
                    "nested_delivery_count",
                    (raw["flags"].as_u64().expect("flags") >> 16) as i64,
                ),
            ] {
                if field != 0 {
                    value[key] = json!(field);
                }
            }
            if kind.ends_with("return") {
                value["begin_sequence"] = raw["fault_address"].clone();
            }
            value
        }
        "termination_intent" => json!({
            "kind": "intent", "reason": Value::Null, "return_value": Value::Null,
            "elapsed_ms": 0, "metrics": {
                "instructions": 0, "encoded_bytes": 0, "compressed_bytes": 0,
                "cache_hits": 0, "cache_misses": 0, "cache_collisions": 0,
                "buffer_swaps": 0, "producer_waits": 0, "producer_wait_ns": 0,
                "effective_buffer_bytes": 0,
            },
            "intent": {"pc": raw["pc"], "syscall_number": raw["signal_number"],
                "arguments": [raw["sp"].clone(), raw["fault_address"].clone(), raw["signal_code"].clone(), raw["flags"].clone()]},
        }),
        "coverage_gap" => json!({
            "tid": tid, "pc": raw["pc"], "sp": raw["sp"],
            "fault_address": raw["fault_address"], "reason_flags": raw["reason_flags"],
            "dropped_count": raw["dropped_gap_count"],
        }),
        _ => panic!("unexpected oracle event kind {kind}"),
    };
    json!({
        "artifact": artifact, "timeline": 0,
        "record_ordinal": event["record_ordinal"],
        "global_seq": event["global_seq"], "tid": tid, "kind": kind,
        "source_offset": source_offset, "provenance": provenance,
        "fragment_source_offsets": fragment_offsets, "data": data,
    })
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

fn sorted_json(mut values: Vec<Value>) -> Vec<Value> {
    values.sort_by_key(|value| serde_json::to_string(value).expect("canonical JSON"));
    values
}

fn range_value(domain: &str, first: u64, last: u64, provenance: &str, cause: &str) -> Value {
    json!({
        "domain": domain, "first": first, "last": last,
        "provenance": provenance, "cause": cause,
    })
}

fn discontinuity_cause(cause: &str) -> &'static str {
    match cause {
        "lost" => "loss",
        "overwritten" => "overwrite",
        "checksum" => "damage",
        "truncation" => "truncation",
        _ => "unknown",
    }
}

fn discontinuity_data_from_names(
    domain: &str,
    first: u64,
    last: u64,
    provenance: &str,
    cause: &str,
) -> Value {
    json!({
        "cause": discontinuity_cause(cause),
        "evidence": range_value(domain, first, last, provenance, cause),
    })
}

fn discontinuity_data(
    bounds: RangeBounds,
    provenance: qtrace_provider::Provenance,
    cause: CompletenessCause,
) -> Value {
    let (domain, first, last) = match bounds {
        RangeBounds::InclusiveSequence { first, last } => ("captured_sequence", first, last),
        RangeBounds::HalfOpen {
            start,
            end_exclusive,
        } => ("source_bytes", start, end_exclusive),
    };
    let provenance = serde_json::to_value(provenance).unwrap();
    let cause = serde_json::to_value(cause).unwrap();
    discontinuity_data_from_names(
        domain,
        first,
        last,
        provenance.as_str().unwrap(),
        cause.as_str().unwrap(),
    )
}

fn cause_order(value: &Value) -> u8 {
    match value["cause"].as_str().expect("range cause") {
        "retained" => 0,
        "active" => 1,
        "rotating" => 2,
        "stale" => 3,
        "unreliable" => 4,
        "incomplete" => 5,
        "lost" => 6,
        "overwritten" => 7,
        "coverage_gap" => 8,
        "checksum" => 9,
        "unterminated_thread" => 10,
        "missing_terminal" => 11,
        "truncation" => 12,
        _ => 13,
    }
}

fn provenance_order(value: &Value) -> u8 {
    match value["provenance"].as_str().expect("range provenance") {
        "captured" => 0,
        "derived" => 1,
        "heuristic" => 2,
        "unknown" => 3,
        _ => 4,
    }
}

fn normalize_ranges(mut values: Vec<Value>) -> Vec<Value> {
    values.sort_by_key(|value| {
        (
            u8::from(value["domain"] != "captured_sequence"),
            cause_order(value),
            value["first"].as_u64().unwrap(),
            value["last"].as_u64().unwrap(),
            provenance_order(value),
        )
    });
    let mut output: Vec<Value> = Vec::new();
    for value in values {
        if let Some(previous) = output.last_mut() {
            let mergeable = previous["domain"] == value["domain"]
                && previous["cause"] == value["cause"]
                && previous["provenance"] == value["provenance"]
                && value["first"].as_u64().unwrap()
                    <= previous["last"].as_u64().unwrap().saturating_add(1);
            if mergeable {
                previous["last"] = json!(
                    previous["last"]
                        .as_u64()
                        .unwrap()
                        .max(value["last"].as_u64().unwrap())
                );
                continue;
            }
        }
        output.push(value);
    }
    output
}

fn actual_completeness(summary: &qtrace_provider::ProviderSummary) -> Vec<Value> {
    normalize_ranges(
        summary
            .completeness
            .iter()
            .map(|range| {
                let (first, last) = match range.bounds() {
                    RangeBounds::InclusiveSequence { first, last } => (first, last),
                    RangeBounds::HalfOpen {
                        start,
                        end_exclusive,
                    } => (start, end_exclusive),
                };
                range_value(
                    match range.domain() {
                        qtrace_provider::RangeDomain::CapturedSequence => "captured_sequence",
                        qtrace_provider::RangeDomain::SourceBytes => "source_bytes",
                        qtrace_provider::RangeDomain::MemoryAddresses => "memory_addresses",
                    },
                    first,
                    last,
                    serde_json::to_value(range.provenance())
                        .unwrap()
                        .as_str()
                        .unwrap(),
                    serde_json::to_value(range.cause())
                        .unwrap()
                        .as_str()
                        .unwrap(),
                )
            })
            .collect(),
    )
}

fn expected_completeness(expected: &Value) -> Vec<Value> {
    let summary = &expected["summary"];
    let mut output = Vec::new();
    for (field, provenance, cause) in [
        ("retained_sequences", "captured", "retained"),
        ("lost", "unknown", "lost"),
        ("overwritten", "unknown", "overwritten"),
        ("checksum", "damaged", "checksum"),
    ] {
        let ranges = if field == "retained_sequences" {
            &summary[field]
        } else {
            &summary["provider_ranges"][field]
        };
        for range in ranges.as_array().expect("sequence ranges") {
            output.push(range_value(
                "captured_sequence",
                range[0].as_u64().unwrap(),
                range[1].as_u64().unwrap(),
                provenance,
                cause,
            ));
        }
    }
    for event in expected["events"].as_array().expect("oracle events") {
        if event["kind"] == "coverage_gap" {
            let sequence = event["global_seq"].as_u64().unwrap();
            output.push(range_value(
                "captured_sequence",
                sequence,
                sequence,
                "captured",
                "coverage_gap",
            ));
        }
    }
    for tid in summary["unterminated_threads"]
        .as_array()
        .expect("unterminated threads")
    {
        let sequence = expected["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|event| event["tid"] == *tid && event["kind"] == "thread_begin")
            .expect("unterminated begin")["global_seq"]
            .as_u64()
            .unwrap();
        output.push(range_value(
            "captured_sequence",
            sequence,
            sequence,
            "unknown",
            "unterminated_thread",
        ));
    }
    for detail in summary["damage_details"]
        .as_array()
        .expect("damage details")
    {
        let class = detail["class"].as_str().unwrap();
        output.push(range_value(
            "captured_sequence",
            detail["first_sequence"].as_u64().unwrap(),
            detail["last_sequence"].as_u64().unwrap(),
            "damaged",
            if class == "checksum" {
                "checksum"
            } else {
                "incomplete"
            },
        ));
    }

    let directory_offset = summary["directory_offset"].as_u64().unwrap();
    for (field, cause) in [
        ("stale_directory_entries", "stale"),
        ("rotating_directory_entries", "rotating"),
        ("unreliable_directory_ranges", "unreliable"),
    ] {
        for index in summary[field].as_array().expect("directory entries") {
            let start = directory_offset + index.as_u64().unwrap() * 64;
            output.push(range_value(
                "source_bytes",
                start,
                start + 64,
                "unknown",
                cause,
            ));
        }
    }
    for index in summary["rotating_directory_entries"]
        .as_array()
        .expect("rotating entries")
    {
        let start = directory_offset + index.as_u64().unwrap() * 64;
        output.push(range_value(
            "source_bytes",
            start,
            start + 64,
            "unknown",
            "unreliable",
        ));
    }
    let chunk_offset = summary["chunk_offset"].as_u64().unwrap();
    let chunk_bytes = summary["chunk_bytes"].as_u64().unwrap();
    for index in summary["active_chunks"].as_array().expect("active chunks") {
        let start = chunk_offset + index.as_u64().unwrap() * chunk_bytes;
        output.push(range_value(
            "source_bytes",
            start,
            start + 64,
            "captured",
            "active",
        ));
    }
    if summary["artifact_flags"].as_u64().unwrap() != 0 {
        output.push(range_value("source_bytes", 72, 76, "unknown", "incomplete"));
    }
    for detail in summary["damage_details"]
        .as_array()
        .expect("damage details")
    {
        if detail["class"] == "checksum" {
            continue;
        }
        let source = detail["source_offset"].as_u64().unwrap();
        let index = source.saturating_sub(chunk_offset) / chunk_bytes;
        let start = chunk_offset + index * chunk_bytes;
        output.push(range_value(
            "source_bytes",
            start,
            start + chunk_bytes,
            "damaged",
            "incomplete",
        ));
    }
    normalize_ranges(output)
}

fn actual_source_discontinuities(events: &[qtrace_provider::EventRecord]) -> Vec<Value> {
    sorted_json(
        events
            .iter()
            .filter_map(|event| {
                let EventPayload::Discontinuity(value) = &event.payload else {
                    return None;
                };
                let RangeBounds::HalfOpen {
                    start,
                    end_exclusive,
                } = value.evidence.bounds()
                else {
                    return None;
                };
                Some(json!({
                    "first": start, "last": end_exclusive,
                    "cause": value.evidence.cause(),
                    "provenance": value.evidence.provenance(),
                    "source_offset": event.key.source_offset,
                }))
            })
            .collect(),
    )
}

fn expected_source_discontinuities(expected: &Value) -> Vec<Value> {
    sorted_json(
        expected_completeness(expected)
            .into_iter()
            .filter(|range| range["domain"] == "source_bytes" && range["cause"] != "retained")
            .map(|range| {
                json!({
                    "first": range["first"], "last": range["last"],
                    "cause": range["cause"], "provenance": range["provenance"],
                    "source_offset": range["first"],
                })
            })
            .collect(),
    )
}

fn actual_sequence_proofs(events: &[qtrace_provider::EventRecord]) -> Vec<Value> {
    sorted_json(
        events
            .iter()
            .filter_map(|event| {
                let EventPayload::Discontinuity(value) = &event.payload else {
                    return None;
                };
                let RangeBounds::InclusiveSequence { first, last } = value.evidence.bounds() else {
                    return None;
                };
                matches!(
                    value.evidence.cause(),
                    CompletenessCause::Lost
                        | CompletenessCause::Overwritten
                        | CompletenessCause::Checksum
                        | CompletenessCause::CoverageGap
                        | CompletenessCause::UnterminatedThread
                        | CompletenessCause::Incomplete
                )
                .then(|| {
                    json!({
                        "first": first, "last": last,
                        "cause": value.evidence.cause(),
                        "provenance": value.evidence.provenance(),
                        "source_offset": event.key.source_offset,
                    })
                })
            })
            .collect(),
    )
}

fn expected_sequence_proofs_ordered(expected: &Value) -> Vec<Value> {
    let summary = &expected["summary"];
    let mut output = Vec::new();
    let facts = summary["range_facts"].as_array().expect("range facts");
    for detail in summary["damage_details"]
        .as_array()
        .expect("damage details")
    {
        let class = detail["class"].as_str().expect("damage class");
        if class != "checksum" {
            continue;
        }
        output.push(json!({
            "first": detail["first_sequence"], "last": detail["last_sequence"],
            "cause": "checksum",
            "provenance": "damaged", "source_offset": detail["source_offset"],
        }));
    }
    for event in expected["events"].as_array().expect("oracle events") {
        if event["kind"] == "coverage_gap" {
            output.push(json!({
                "first": event["global_seq"], "last": event["global_seq"],
                "cause": "coverage_gap", "provenance": "captured",
                "source_offset": event["source_offset"],
            }));
        }
    }
    for tid in summary["unterminated_threads"]
        .as_array()
        .expect("unterminated threads")
    {
        let begin = expected["events"]
            .as_array()
            .expect("events")
            .iter()
            .find(|event| event["tid"] == *tid && event["kind"] == "thread_begin")
            .expect("unterminated begin");
        output.push(json!({
            "first": begin["global_seq"], "last": begin["global_seq"],
            "cause": "unterminated_thread", "provenance": "unknown",
            "source_offset": summary["artifact_bytes"],
        }));
    }
    for (field, cause) in [("lost", "lost"), ("overwritten", "overwritten")] {
        for range in summary["provider_ranges"][field]
            .as_array()
            .expect("provider ranges")
        {
            let first = range[0].as_u64().expect("range first");
            let last = range[1].as_u64().expect("range last");
            for fact in facts {
                let overlap_first = first.max(fact["first_sequence"].as_u64().expect("fact first"));
                let overlap_last = last.min(fact["last_sequence"].as_u64().expect("fact last"));
                if overlap_first <= overlap_last {
                    output.push(json!({
                        "first": overlap_first, "last": overlap_last, "cause": cause,
                        "provenance": "unknown", "source_offset": fact["source_offset"],
                    }));
                }
            }
        }
    }
    for detail in summary["damage_details"]
        .as_array()
        .expect("damage details")
    {
        if detail["class"] == "checksum" {
            continue;
        }
        output.push(json!({
            "first": detail["first_sequence"], "last": detail["last_sequence"],
            "cause": "incomplete", "provenance": "damaged",
            "source_offset": detail["source_offset"],
        }));
    }
    output
}

fn expected_sequence_proofs(expected: &Value) -> Vec<Value> {
    sorted_json(expected_sequence_proofs_ordered(expected))
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
        let actual_events = typed_events(&actual.events);
        let expected_events = canonical_oracle_typed_events(&expected, actual.artifact);
        assert_eq!(
            actual_events
                .iter()
                .map(|event| event_key_from_row(event).expect("actual canonical EventKey"))
                .collect::<Vec<_>>(),
            expected_events
                .iter()
                .map(|event| event_key_from_row(event).expect("oracle canonical EventKey"))
                .collect::<Vec<_>>(),
            "merged EventKeys for {name}"
        );
        assert_eq!(
            actual_events, expected_events,
            "merged typed order mismatch for {name}"
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
        assert_eq!(
            actual_threads.keys().collect::<Vec<_>>(),
            expected_threads.keys().collect::<Vec<_>>(),
            "exact projection TID set for {name}"
        );
        for (tid, expected_registers) in expected_threads {
            let actual_registers = actual_threads
                .get(tid)
                .copied()
                .expect("oracle TID projection");
            if expected_registers.is_null() {
                assert_eq!(
                    actual_registers, None,
                    "unknown final registers for {name} TID {tid}"
                );
                continue;
            }
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
                actual_registers,
                Some(expected_values.as_slice()),
                "final registers for {name} TID {tid}"
            );
        }
        for projection in &actual.projections {
            let expected_thread_keys = expected_events
                .iter()
                .filter(|event| event["tid"] == projection.tid)
                .map(|event| event_key_from_row(event).expect("oracle projection EventKey"))
                .collect::<Vec<_>>();
            assert_eq!(
                projection.event_keys.len(),
                expected_thread_keys.len(),
                "exact projection row count for {name} TID {}",
                projection.tid
            );
            assert_eq!(
                projection.event_keys, expected_thread_keys,
                "oracle-derived per-TID EventKeys for {name}"
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
        assert_eq!(
            ranges(&actual.summary, CompletenessCause::Lost),
            expected["summary"]["provider_ranges"]["lost"]
                .as_array()
                .expect("lost ranges")
                .iter()
                .map(|pair| [pair[0].as_u64().unwrap(), pair[1].as_u64().unwrap()])
                .collect::<Vec<_>>(),
            "lost ranges for {name}"
        );
        assert_eq!(
            ranges(&actual.summary, CompletenessCause::Overwritten),
            expected["summary"]["provider_ranges"]["overwritten"]
                .as_array()
                .expect("overwritten ranges")
                .iter()
                .map(|pair| [pair[0].as_u64().unwrap(), pair[1].as_u64().unwrap()])
                .collect::<Vec<_>>(),
            "overwritten ranges for {name}"
        );
        assert_eq!(
            ranges(&actual.summary, CompletenessCause::Checksum),
            expected["summary"]["provider_ranges"]["checksum"]
                .as_array()
                .expect("checksum ranges")
                .iter()
                .map(|pair| [pair[0].as_u64().unwrap(), pair[1].as_u64().unwrap()])
                .collect::<Vec<_>>(),
            "checksum ranges for {name}"
        );
        assert_eq!(
            actual_sequence_proofs(&actual.events),
            expected_sequence_proofs(&expected),
            "exact sequence proof evidence for {name}"
        );
        assert_eq!(
            actual_completeness(&actual.summary),
            expected_completeness(&expected),
            "exact completeness domains/provenance/causes for {name}"
        );
        assert_eq!(
            actual_source_discontinuities(&actual.events),
            expected_source_discontinuities(&expected),
            "exact source discontinuity coordinates for {name}"
        );

        let expected_termination = &expected["summary"]["termination"];
        let actual_termination = actual.summary.termination.as_ref();
        if expected_termination["cause"] == "termination_intent" {
            let expected_event = expected_events
                .iter()
                .find(|event| event["kind"] == "termination_intent")
                .expect("oracle termination event");
            assert_eq!(
                serde_json::to_value(actual_termination.expect("termination intent")).unwrap(),
                expected_event["data"],
                "complete termination payload for {name}"
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
        let actual_handler_begins = actual
            .events
            .iter()
            .filter_map(|event| match &event.payload {
                EventPayload::SignalHandlerBoundary(value)
                    if value.phase == qtrace_provider::SignalHandlerPhase::Begin =>
                {
                    Some((event, value))
                }
                _ => None,
            })
            .map(|(event, value)| {
                let returned =
                    actual
                        .events
                        .iter()
                        .find_map(|candidate| match &candidate.payload {
                            EventPayload::SignalHandlerBoundary(boundary)
                                if boundary.phase
                                    == qtrace_provider::SignalHandlerPhase::Return
                                    && boundary.tid == value.tid
                                    && boundary.begin_sequence == event.key.sequence =>
                            {
                                candidate.key.sequence
                            }
                            _ => None,
                        });
                json!({
                    "tid": value.tid, "depth": value.depth,
                    "nested_delivery_count": value.nested_delivery_count,
                    "begin_sequence": event.key.sequence,
                    "return_sequence": returned,
                    "returned": returned.is_some(),
                    "unreturned_ancestor_count": value.depth.saturating_sub(1),
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(
            actual_handler_begins, *expected_handlers,
            "exact handler intervals for {name}"
        );
        assert_eq!(
            actual.recovery.complete, expected["summary"]["provider_complete"],
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
        let directory_offset = expected["summary"]["directory_offset"]
            .as_u64()
            .expect("directory offset");
        let actual_unreliable = actual
            .summary
            .completeness
            .iter()
            .filter_map(|range| match range.bounds() {
                RangeBounds::HalfOpen { start, .. }
                    if range.cause() == CompletenessCause::Unreliable =>
                {
                    u32::try_from((start - directory_offset) / 64).ok()
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            actual_unreliable,
            u32_values(&expected["summary"]["unreliable_directory_ranges"]),
            "unreliable directory ranges for {name}"
        );
        assert_eq!(
            actual.recovery.target_pcs,
            u64_values(&expected["summary"]["target_pcs"]),
            "target PCs for {name}"
        );
    }
}
