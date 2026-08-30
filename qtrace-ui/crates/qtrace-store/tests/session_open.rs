use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use lz4_flex::frame::FrameEncoder;
use qtrace_provider::{OperationAbort, WorkDelta, WorkGuard};
use qtrace_store::{ArtifactFormat, AuthorizedPath, OpenPolicy, SessionCapability, SessionLoader};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

#[derive(Default)]
struct AllowAll;

impl WorkGuard for AllowAll {
    fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
        Ok(())
    }
}

fn fixture_root(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("qtrace-ui workspace root")
        .join("fixtures/sessions")
        .join(name)
}

fn open_fixture(name: &str) -> Result<qtrace_store::SessionSource, qtrace_provider::ProviderError> {
    SessionLoader::open_report(
        AuthorizedPath::new(fixture_root(name)),
        OpenPolicy::default(),
        &AllowAll,
    )
}

#[test]
fn qtrb_artifacts_remain_independent_timelines() {
    let session = open_fixture("valid-mixed").expect("valid fixture session");
    let qtrb = session
        .artifacts()
        .iter()
        .filter(|item| item.format().is_qtrb())
        .collect::<Vec<_>>();

    assert_eq!(qtrb.len(), 2);
    assert_ne!(qtrb[0].timeline_id(), qtrb[1].timeline_id());
    assert_eq!(session.available_artifacts().count(), 3);
}

#[test]
fn reopened_qtrb_provider_events_use_the_artifacts_independent_timeline() {
    let session = open_fixture("valid-mixed").expect("valid fixture session");
    let qtrb = session
        .artifacts()
        .iter()
        .filter(|item| item.format().is_qtrb())
        .collect::<Vec<_>>();

    for artifact in qtrb {
        let provider = artifact
            .open_provider(&AllowAll)
            .expect("reopen QTRB provider");
        assert_eq!(provider.timelines()[0].id, artifact.timeline_id());
        let mut cursor = provider.into_cursor().expect("QTRB cursor");
        let first = cursor
            .next_event(&AllowAll)
            .expect("first event")
            .expect("nonempty QTRB");
        assert_eq!(first.key.timeline, artifact.timeline_id());
    }
}

#[test]
fn reopening_an_artifact_authorizes_store_timeline_allocation() {
    struct RejectTimelineNodes;
    impl WorkGuard for RejectTimelineNodes {
        fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
            if delta.nodes > 0 {
                Err(OperationAbort::budget_exceeded(
                    qtrace_provider::BudgetDimension::Nodes,
                    0,
                    delta.nodes,
                ))
            } else {
                Ok(())
            }
        }
    }

    let session = open_fixture("valid-mixed").expect("valid fixture session");
    let error = match session.artifacts()[0].open_provider(&RejectTimelineNodes) {
        Ok(_) => panic!("timeline descriptor allocation requires authorization"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "control.budget_exceeded");
}

#[test]
fn flight_keeps_its_merged_and_per_tid_projection_contract() {
    let session = open_fixture("valid-mixed").expect("valid fixture session");
    let flight = session
        .artifacts()
        .iter()
        .find(|item| item.format() == ArtifactFormat::Flight)
        .expect("Flight artifact");

    assert_eq!(flight.timeline_id().0, 2);
    assert!(flight.provider_timelines().len() > 1);
    assert_eq!(flight.provider_timelines()[0].id.0, 0);
    assert!(flight.provider_timelines()[0].tid.is_none());
    assert!(
        flight.provider_timelines()[1..]
            .iter()
            .all(|item| item.tid.is_some())
    );
}

#[test]
fn invalid_artifact_is_isolated_after_a_valid_root_manifest() {
    let session = open_fixture("one-invalid-artifact").expect("valid root manifest");

    assert_eq!(session.available_artifacts().count(), 2);
    assert_eq!(session.failures().len(), 1);
    assert_eq!(
        session.failures()[0].error().code(),
        "source.qtrb.truncated"
    );
}

#[test]
fn checked_path_escape_is_a_root_failure() {
    let error = open_fixture("path-escape").expect_err("path traversal must fail the root");
    assert_eq!(error.code(), "session.path_escape");
}

#[test]
fn report_schema_and_root_fields_are_strict() {
    let temp = TempDir::new().expect("temporary session");
    let root = temp.path();
    let valid = report(Vec::new());

    for document in [
        with_field(&valid, "schema", json!(2)),
        with_field(&valid, "unexpected", json!(true)),
    ] {
        write_json(root.join("report.json"), &document);
        let error = open_path(root).expect_err("invalid root manifest");
        assert_eq!(error.code(), "session.manifest_invalid");
    }

    let encoded = serde_json::to_string(&valid).expect("encode report");
    let duplicate = encoded.replacen("\"schema\":1", "\"schema\":1,\"schema\":1", 1);
    fs::write(root.join("report.json"), duplicate).expect("duplicate report");
    let error = open_path(root).expect_err("duplicate root field");
    assert_eq!(error.code(), "session.manifest_invalid");
}

#[test]
fn oversized_report_is_rejected_before_json_materialization() {
    let temp = TempDir::new().expect("temporary session");
    fs::write(temp.path().join("report.json"), vec![b' '; 1024 * 1024 + 1])
        .expect("oversized report");

    let error = open_path(temp.path()).expect_err("report byte bound");
    assert_eq!(error.code(), "session.manifest_invalid");
}

#[test]
fn successful_artifact_records_require_bounded_path_digest_and_positive_size() {
    let temp = TempDir::new().expect("temporary session");
    let root = temp.path();
    fs::create_dir(root.join("artifacts")).expect("artifact directory");
    fs::write(root.join("artifacts/input.trace.bin"), b"QTRB").expect("artifact");
    let base = artifact_record("artifacts/input.trace.bin", b"QTRB");

    let cases = [
        remove_field(&base, "sha256"),
        remove_field(&base, "destination_size"),
        with_field(&base, "destination_size", json!(0)),
        with_field(&base, "sha256", json!("A".repeat(64))),
        with_field(&base, "sha256", json!("0".repeat(63))),
        with_field(&base, "local_path", json!("a".repeat(4097))),
    ];
    for record in cases {
        write_json(root.join("report.json"), &report(vec![record]));
        let error = open_path(root).expect_err("invalid successful record");
        assert_eq!(error.code(), "session.manifest_invalid");
    }
}

#[test]
fn records_without_local_paths_remain_bounded_warnings_and_are_not_opened() {
    let temp = TempDir::new().expect("temporary session");
    let warning = json!({
        "name": "failed.trace.bin",
        "code": "artifact.invalid",
        "detail": "collector rejected the artifact"
    });
    write_json(temp.path().join("report.json"), &report(vec![warning]));

    let session = open_path(temp.path()).expect("bounded report failure is not a source");
    assert_eq!(session.artifacts().len(), 0);
    assert_eq!(session.warnings().len(), 1);
    assert_eq!(session.warnings()[0].code(), "artifact.invalid");
}

#[test]
fn size_and_hash_mismatch_are_isolated_typed_artifact_failures() {
    let temp = TempDir::new().expect("temporary session");
    let root = temp.path();
    fs::create_dir(root.join("artifacts")).expect("artifact directory");
    let bytes = fixture_bytes("valid-mixed", "artifacts/main.trace.bin");
    fs::write(root.join("artifacts/size.trace.bin"), &bytes).expect("size artifact");
    fs::write(root.join("artifacts/hash.trace.bin"), &bytes).expect("hash artifact");
    let size = with_field(
        &artifact_record("artifacts/size.trace.bin", &bytes),
        "destination_size",
        json!(bytes.len() + 1),
    );
    let hash = with_field(
        &artifact_record("artifacts/hash.trace.bin", &bytes),
        "sha256",
        json!("0".repeat(64)),
    );
    write_json(root.join("report.json"), &report(vec![size, hash]));

    let session = open_path(root).expect("valid root with isolated artifacts");
    assert_eq!(session.artifacts().len(), 0);
    assert_eq!(
        session
            .failures()
            .iter()
            .map(|item| item.error().code())
            .collect::<Vec<_>>(),
        vec!["source.size_mismatch", "source.hash_mismatch"]
    );
}

#[test]
fn known_derived_outputs_are_metadata_and_unknown_local_outputs_are_isolated() {
    let temp = TempDir::new().expect("temporary session");
    let root = temp.path();
    fs::create_dir(root.join("artifacts")).expect("artifact directory");
    let qtrb = fixture_bytes("valid-mixed", "artifacts/main.trace.bin");
    let members = [
        ("artifacts/main.trace.bin", qtrb.as_slice()),
        ("artifacts/main.trace.bin.metrics", b"metrics".as_slice()),
        ("artifacts/main.trace.txt", b"TRACE_END".as_slice()),
        ("artifacts/main.tid-7.trace.txt", b"thread".as_slice()),
        ("artifacts/main.flight.json", b"{}".as_slice()),
        ("artifacts/mystery.data", b"unknown".as_slice()),
    ];
    let mut records = Vec::new();
    for (name, bytes) in members {
        fs::write(root.join(name), bytes).expect("member");
        records.push(artifact_record(name, bytes));
    }
    write_json(root.join("report.json"), &report(records));

    let session = open_path(root).expect("derived records do not reject the session");
    assert_eq!(session.artifacts().len(), 1);
    assert_eq!(session.metadata().len(), 4);
    assert_eq!(session.failures().len(), 1);
    assert_eq!(
        session.failures()[0].error().code(),
        "source.format_unsupported"
    );
}

#[test]
fn unsupported_binary_version_is_a_typed_artifact_failure() {
    let temp = TempDir::new().expect("temporary session");
    let root = temp.path();
    fs::create_dir(root.join("artifacts")).expect("artifact directory");
    let mut bytes = fixture_bytes("valid-mixed", "artifacts/main.trace.bin");
    bytes[4] = 9;
    fs::write(root.join("artifacts/new.trace.bin"), &bytes).expect("artifact");
    write_json(
        root.join("report.json"),
        &report(vec![artifact_record("artifacts/new.trace.bin", &bytes)]),
    );

    let session = open_path(root).expect("unsupported artifact is isolated");
    assert_eq!(
        session.failures()[0].error().code(),
        "source.version_unsupported"
    );
}

#[test]
fn selected_report_file_and_selected_directory_open_the_same_session() {
    let root = fixture_root("valid-mixed");
    let from_directory = open_path(&root).expect("directory selection");
    let from_report = open_path(root.join("report.json")).expect("report selection");

    assert_eq!(from_directory.session_id(), from_report.session_id());
    assert_eq!(
        from_directory.artifacts().len(),
        from_report.artifacts().len()
    );
}

#[test]
fn single_qtrb_is_degraded_with_explicit_missing_context_capabilities() {
    let path = fixture_root("valid-mixed").join("artifacts/main.trace.bin");
    let session =
        SessionLoader::open_artifact(AuthorizedPath::new(path), OpenPolicy::default(), &AllowAll)
            .expect("single QTRB");

    assert_eq!(session.artifacts().len(), 1);
    for capability in [
        SessionCapability::Package,
        SessionCapability::Device,
        SessionCapability::Target,
        SessionCapability::EffectiveConfig,
    ] {
        assert!(!session.capabilities().has(capability));
        assert!(
            session
                .warnings()
                .iter()
                .any(|warning| warning.capability() == Some(capability))
        );
    }
}

#[test]
fn compressed_qtrb_keeps_file_and_provider_identity_distinct_and_complete() {
    let raw = fixture_bytes("valid-mixed", "artifacts/main.trace.bin");
    let mut encoder = FrameEncoder::new(Vec::new());
    encoder.write_all(&raw).expect("compress QTRB");
    let compressed = encoder.finish().expect("finish LZ4 frame");
    let temp = TempDir::new().expect("compressed single artifact");
    let path = temp.path().join("main.trace.bin.lz4");
    fs::write(&path, &compressed).expect("compressed QTRB");

    let session = SessionLoader::open_artifact(
        AuthorizedPath::new(path.clone()),
        OpenPolicy::default(),
        &AllowAll,
    )
    .expect("compressed QTRB source");
    let artifact = &session.artifacts()[0];
    assert_eq!(artifact.format(), ArtifactFormat::QtrbLz4);
    assert_eq!(artifact.identity().display_path(), path);
    assert_eq!(artifact.identity().file().size, compressed.len() as u64);
    assert_eq!(
        artifact.identity().provider().artifact.to_hex(),
        hex_digest(&compressed)
    );
    assert_eq!(
        artifact.identity().provider().source_bytes,
        raw.len() as u64
    );
    assert_eq!(artifact.identity().provider().format_major, 1);
    assert_eq!(artifact.identity().provider().format_minor, 2);
}

#[test]
fn text_and_derived_json_are_not_single_file_analysis_sources() {
    let temp = TempDir::new().expect("single artifacts");
    for name in [
        "trace.trace.txt",
        "trace.trace.txt.lz4",
        "trace.flight.json",
    ] {
        let path = temp.path().join(name);
        fs::write(&path, b"not analysis input").expect("single file");
        let error = SessionLoader::open_artifact(
            AuthorizedPath::new(path),
            OpenPolicy::default(),
            &AllowAll,
        )
        .expect_err("derived/text source must fail");
        assert_eq!(error.code(), "source.format_unsupported");
    }
}

fn open_path(
    path: impl AsRef<Path>,
) -> Result<qtrace_store::SessionSource, qtrace_provider::ProviderError> {
    SessionLoader::open_report(
        AuthorizedPath::new(path.as_ref().to_path_buf()),
        OpenPolicy::default(),
        &AllowAll,
    )
}

fn fixture_bytes(session: &str, relative: &str) -> Vec<u8> {
    fs::read(fixture_root(session).join(relative)).expect("fixture bytes")
}

fn report(artifacts: Vec<Value>) -> Value {
    json!({
        "schema": 1,
        "session_id": "11111111-1111-4111-8111-111111111111",
        "mode": "run",
        "status": "sealed",
        "stage": "sealed",
        "package": "com.example.fixture",
        "serial": "fixture-device",
        "pid": 4242,
        "started_at": "2026-08-30T00:00:00Z",
        "finished_at": "2026-08-30T00:00:01Z",
        "timeline": [],
        "device": {},
        "tracer": {},
        "target": {},
        "effective_config": {},
        "native": {},
        "artifacts": artifacts,
        "warnings": [],
        "error": null,
        "outputs": []
    })
}

fn artifact_record(local_path: &str, bytes: &[u8]) -> Value {
    json!({
        "remote_name": Path::new(local_path).file_name().and_then(|item| item.to_str()),
        "local_path": local_path,
        "source_size": bytes.len(),
        "destination_size": bytes.len(),
        "sha256": hex_digest(bytes),
        "decoder": null,
        "termination": null
    })
}

fn hex_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn with_field(value: &Value, key: &str, member: Value) -> Value {
    let mut value = value.clone();
    value
        .as_object_mut()
        .expect("JSON object")
        .insert(key.to_owned(), member);
    value
}

fn remove_field(value: &Value, key: &str) -> Value {
    let mut value = value.clone();
    value.as_object_mut().expect("JSON object").remove(key);
    value
}

fn write_json(path: PathBuf, value: &Value) {
    fs::write(path, serde_json::to_vec(value).expect("encode JSON")).expect("write JSON");
}
