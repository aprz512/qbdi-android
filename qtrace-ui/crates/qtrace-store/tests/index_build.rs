use std::{
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};

use qtrace_provider::{
    BudgetDimension, EventKind, OperationAbort, RegisterSlot, WorkDelta, WorkGuard,
};
use qtrace_store::{
    ArtifactFormat, AuthorizedPath, BuildOptions, IndexBuilder, OpenPolicy, SessionLoader,
    TraceStore,
};
use tempfile::TempDir;

#[derive(Default)]
struct AllowAll;

impl WorkGuard for AllowAll {
    fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
        Ok(())
    }
}

fn mixed_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("fixtures/sessions/valid-mixed")
}

fn session() -> qtrace_store::SessionSource {
    SessionLoader::open_report(
        AuthorizedPath::new(mixed_fixture()),
        OpenPolicy::default(),
        &AllowAll,
    )
    .expect("checked fixture opens")
}

#[test]
fn qtrb_and_flight_share_normalized_queries_without_false_capabilities() {
    let qtrb_session = session();
    let flight_session = session();
    let qtrb_source = qtrb_session
        .artifacts()
        .iter()
        .find(|artifact| artifact.local_path().ends_with("main.trace.bin"))
        .expect("QTRB artifact");
    let flight_source = flight_session
        .artifacts()
        .iter()
        .find(|artifact| artifact.local_path().ends_with("capture.flight.bin"))
        .expect("Flight artifact");
    let qtrb =
        IndexBuilder::build(qtrb_source, &BuildOptions::default(), &AllowAll).expect("QTRB index");
    let flight = IndexBuilder::build(flight_source, &BuildOptions::default(), &AllowAll)
        .expect("Flight index");

    assert_eq!(qtrb.rows_of_kind(EventKind::Instruction).count(), 1);
    assert!(flight.rows_of_kind(EventKind::Instruction).count() >= 1);
    assert!(!qtrb.capabilities().full_register_checkpoint);
    assert!(flight.capabilities().full_register_checkpoint);
    assert!(flight.rows_observing_register(RegisterSlot::X0).count() >= 1);

    for row in 0..qtrb.event_count() {
        let key = qtrb.event_key(row).expect("row key");
        assert_eq!(qtrb.row_for_key(&key), Some(row));
        assert!(qtrb.event_kind(row).is_some());
        assert!(qtrb.provenance(row).is_some());
    }
}

#[test]
fn eager_indexes_cover_true_overlap_union_intersection_and_control_flags() {
    let session = session();
    let source = session
        .artifacts()
        .iter()
        .find(|artifact| artifact.local_path().ends_with("main.trace.bin"))
        .expect("QTRB artifact");
    let store =
        IndexBuilder::build(source, &BuildOptions::default(), &AllowAll).expect("QTRB index");

    let overlap = store
        .memory_overlaps(0x2002, 0x2004)
        .expect("valid half-open range")
        .collect::<Vec<_>>();
    assert_eq!(overlap.len(), 1);
    let memory = store.memory(overlap[0]).expect("memory row");
    assert_eq!((memory.address, memory.size), (0x2000, 4));

    let semantic_union = store
        .rows_of_kinds(&[
            EventKind::SemanticCall,
            EventKind::SemanticRule,
            EventKind::SemanticError,
        ])
        .collect::<Vec<_>>();
    assert_eq!(semantic_union.len(), 3);
    assert!(semantic_union.windows(2).all(|pair| pair[0] < pair[1]));

    let tid_rows = store.rows_of_tids(&[13]).collect::<Vec<_>>();
    let intersection = qtrace_store::intersect_rows(&semantic_union, &tid_rows);
    assert_eq!(intersection, semantic_union);
    assert_eq!(store.call_rows().count(), 0);
    assert_eq!(store.return_rows().count(), 0);
}

#[test]
fn provider_selection_uses_held_file_magic_instead_of_the_suffix() {
    let temp = TempDir::new().expect("temp");
    let raw_qtrb = fixture_source("qtrb/v1.2-completed.bin");
    let flight = fixture_source("flight/v2-complete.bin");
    let qtrb_with_flight_suffix = temp.path().join("misnamed.flight.bin");
    let flight_with_qtrb_suffix = temp.path().join("misnamed.trace.bin");
    fs::copy(raw_qtrb, &qtrb_with_flight_suffix).expect("copy QTRB");
    fs::copy(flight, &flight_with_qtrb_suffix).expect("copy Flight");

    let qtrb = SessionLoader::open_artifact(
        AuthorizedPath::new(qtrb_with_flight_suffix),
        OpenPolicy::default(),
        &AllowAll,
    )
    .expect("QTRB magic wins");
    let flight = SessionLoader::open_artifact(
        AuthorizedPath::new(flight_with_qtrb_suffix),
        OpenPolicy::default(),
        &AllowAll,
    )
    .expect("Flight magic wins");
    assert_eq!(qtrb.artifacts()[0].format(), ArtifactFormat::Qtrb);
    assert_eq!(flight.artifacts()[0].format(), ArtifactFormat::Flight);
}

fn fixture_source(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("fixtures")
        .join(path)
}

struct CountingGuard {
    calls: Mutex<usize>,
}

impl WorkGuard for CountingGuard {
    fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
        *self.calls.lock().expect("counter") += 1;
        Ok(())
    }
}

struct CancelAt {
    target: usize,
    calls: Mutex<usize>,
    budget: bool,
}

impl WorkGuard for CancelAt {
    fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
        let mut calls = self.calls.lock().expect("counter");
        *calls += 1;
        if *calls == self.target {
            return if self.budget {
                Err(OperationAbort::budget_exceeded(
                    BudgetDimension::Nodes,
                    0,
                    1,
                ))
            } else {
                Err(OperationAbort::Cancelled)
            };
        }
        Ok(())
    }
}

#[test]
fn every_build_checkpoint_aborts_without_visible_cache_or_staging() {
    let session = session();
    let source = session
        .artifacts()
        .iter()
        .find(|artifact| artifact.local_path().ends_with("main.trace.bin"))
        .expect("QTRB artifact");
    let options = BuildOptions::default();
    let counting = CountingGuard {
        calls: Mutex::new(0),
    };
    let first_root = private_root();
    TraceStore::open_or_build(first_root.path(), source, &options, &counting)
        .expect("count successful build checkpoints");
    let calls = *counting.calls.lock().expect("counter");
    assert!(calls > 8, "build must expose periodic stage checkpoints");

    for budget in [false, true] {
        for target in 1..=calls {
            let root = private_root();
            let error = TraceStore::open_or_build(
                root.path(),
                source,
                &options,
                &CancelAt {
                    target,
                    calls: Mutex::new(0),
                    budget,
                },
            )
            .expect_err("injected build control failure");
            assert_eq!(
                error.code(),
                if budget {
                    "control.budget_exceeded"
                } else {
                    "job.cancelled"
                },
                "ordinal {target}: {error}"
            );
            assert_no_publication_debris(root.path());
        }
    }
}

fn private_root() -> TempDir {
    let root = TempDir::new().expect("root");
    fs::set_permissions(
        root.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .expect("private root");
    root
}

fn assert_no_publication_debris(root: &Path) {
    fn walk(path: &Path, bad: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(path) else {
            return;
        };
        for entry in entries.filter_map(Result::ok) {
            let child = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == "index.qtc" || name.ends_with(".tmp") || name.starts_with(".qtrace-dir-") {
                bad.push(child.clone());
            }
            if child.is_dir() {
                walk(&child, bad);
            }
        }
    }
    let mut bad = Vec::new();
    walk(root, &mut bad);
    assert!(bad.is_empty(), "publication debris: {bad:?}");
}
