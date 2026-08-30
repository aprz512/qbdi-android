use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::{
        fs::{FileExt, PermissionsExt, symlink},
        net::UnixListener,
    },
    path::Path,
    process::Command,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use qtrace_provider::{BudgetDimension, OperationAbort, WorkDelta, WorkGuard};
use qtrace_store::{AuthorizedPath, OpenPolicy, SessionLoader};
use rustix::fs::{CWD, Mode, mkfifoat};
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

#[test]
fn fifo_artifact_leaf_child_rejects_without_waiting_for_a_writer() {
    let Some(root) = env::var_os("QTRACE_FIFO_SESSION_ROOT") else {
        return;
    };

    let error = open(Path::new(&root), &AllowAll).expect_err("FIFO leaf must be rejected");
    assert_eq!(error.code(), "session.path_escape");
}

#[test]
fn fifo_artifact_leaf_returns_a_stable_error_without_blocking() {
    let temp = TempDir::new().expect("FIFO session");
    fs::create_dir(temp.path().join("artifacts")).expect("artifacts");
    mkfifoat(
        CWD,
        temp.path().join("artifacts/input.trace.bin"),
        Mode::RUSR | Mode::WUSR,
    )
    .expect("FIFO leaf");
    write_report(temp.path(), "artifacts/input.trace.bin", 1, &"0".repeat(64));

    let mut child = Command::new(env::current_exe().expect("test executable"))
        .arg("--exact")
        .arg("fifo_artifact_leaf_child_rejects_without_waiting_for_a_writer")
        .arg("--nocapture")
        .env("QTRACE_FIFO_SESSION_ROOT", temp.path())
        .spawn()
        .expect("spawn isolated FIFO check");
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        if let Some(status) = child.try_wait().expect("poll FIFO child") {
            assert!(status.success(), "FIFO child failed with {status}");
            break;
        }
        if Instant::now() >= deadline {
            child.kill().expect("kill blocked FIFO child");
            child.wait().expect("reap blocked FIFO child");
            panic!("opening an artifact FIFO blocked for 500ms");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn fifo_selected_report_child_rejects_without_waiting_for_a_writer() {
    let Some(path) = env::var_os("QTRACE_FIFO_REPORT_PATH") else {
        return;
    };

    let error = open(Path::new(&path), &AllowAll).expect_err("FIFO report must be rejected");
    assert_eq!(error.code(), "session.path_escape");
}

#[test]
fn fifo_selected_report_returns_a_stable_error_without_blocking() {
    let temp = TempDir::new().expect("FIFO report container");
    let path = temp.path().join("report.json");
    mkfifoat(CWD, &path, Mode::RUSR | Mode::WUSR).expect("FIFO report");

    let mut child = Command::new(env::current_exe().expect("test executable"))
        .arg("--exact")
        .arg("fifo_selected_report_child_rejects_without_waiting_for_a_writer")
        .arg("--nocapture")
        .env("QTRACE_FIFO_REPORT_PATH", &path)
        .spawn()
        .expect("spawn isolated FIFO report check");
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        if let Some(status) = child.try_wait().expect("poll FIFO report child") {
            assert!(status.success(), "FIFO report child failed with {status}");
            break;
        }
        if Instant::now() >= deadline {
            child.kill().expect("kill blocked FIFO report child");
            child.wait().expect("reap blocked FIFO report child");
            panic!("opening a selected report FIFO blocked for 500ms");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

struct OnArtifactRead {
    trigger_at: usize,
    positive_reads: Mutex<usize>,
    action: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl OnArtifactRead {
    fn new(action: impl FnOnce() + Send + 'static) -> Self {
        Self::at(2, action)
    }

    fn at(trigger_at: usize, action: impl FnOnce() + Send + 'static) -> Self {
        Self {
            trigger_at,
            positive_reads: Mutex::new(0),
            action: Mutex::new(Some(Box::new(action))),
        }
    }
}

impl WorkGuard for OnArtifactRead {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        if delta.input_bytes == 0 {
            return Ok(());
        }
        let mut reads = self.positive_reads.lock().expect("read counter");
        *reads += 1;
        if *reads == self.trigger_at {
            if let Some(action) = self.action.lock().expect("race action").take() {
                action();
            }
        }
        Ok(())
    }
}

struct RejectNthCall {
    reject_at: usize,
    calls: AtomicUsize,
    abort: OperationAbort,
}

impl RejectNthCall {
    fn new(reject_at: usize, abort: OperationAbort) -> Self {
        Self {
            reject_at,
            calls: AtomicUsize::new(0),
            abort,
        }
    }
}

impl WorkGuard for RejectNthCall {
    fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call == self.reject_at {
            Err(self.abort.clone())
        } else {
            Ok(())
        }
    }
}

struct RejectInputCall {
    reject_at: usize,
    calls: AtomicUsize,
    abort: OperationAbort,
}

impl RejectInputCall {
    fn new(reject_at: usize, abort: OperationAbort) -> Self {
        Self {
            reject_at,
            calls: AtomicUsize::new(0),
            abort,
        }
    }
}

impl WorkGuard for RejectInputCall {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        if delta.input_bytes == 0 {
            return Ok(());
        }
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call == self.reject_at {
            Err(self.abort.clone())
        } else {
            Ok(())
        }
    }
}

struct RejectTimelineWork;

impl WorkGuard for RejectTimelineWork {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        if delta.nodes > 0 {
            Err(OperationAbort::budget_exceeded(
                BudgetDimension::Nodes,
                0,
                delta.nodes,
            ))
        } else {
            Ok(())
        }
    }
}

#[test]
fn absolute_parent_empty_nul_and_dot_components_are_rejected() {
    for local_path in [
        "/tmp/escape.trace.bin",
        "artifacts/../escape.trace.bin",
        "artifacts//escape.trace.bin",
        "./artifacts/escape.trace.bin",
        "artifacts/\0escape.trace.bin",
    ] {
        let temp = session_with_record(local_path, b"anything");
        let error = open(temp.path(), &AllowAll).expect_err("unsafe component");
        assert_eq!(error.code(), "session.path_escape", "{local_path:?}");
    }
}

#[test]
fn directory_and_special_file_leaves_are_rejected() {
    let directory = TempDir::new().expect("session");
    fs::create_dir(directory.path().join("artifacts")).expect("artifacts");
    fs::create_dir(directory.path().join("artifacts/dir.trace.bin")).expect("directory leaf");
    write_report(
        directory.path(),
        "artifacts/dir.trace.bin",
        1,
        &"0".repeat(64),
    );
    let error = open(directory.path(), &AllowAll).expect_err("directory leaf");
    assert_eq!(error.code(), "session.path_escape");

    let socket_session = TempDir::new().expect("socket session");
    fs::create_dir(socket_session.path().join("artifacts")).expect("artifacts");
    let _socket = UnixListener::bind(socket_session.path().join("artifacts/socket.trace.bin"))
        .expect("socket leaf");
    write_report(
        socket_session.path(),
        "artifacts/socket.trace.bin",
        1,
        &"0".repeat(64),
    );
    let error = open(socket_session.path(), &AllowAll).expect_err("special leaf");
    assert_eq!(error.code(), "session.path_escape");
}

#[test]
fn a_missing_artifact_is_isolated_without_hiding_a_healthy_timeline() {
    let bytes = fixture_qtrb();
    let temp = TempDir::new().expect("session");
    fs::create_dir(temp.path().join("artifacts")).expect("artifacts");
    fs::write(temp.path().join("artifacts/healthy.trace.bin"), &bytes).expect("healthy artifact");
    let artifact = |local_path: &str| {
        json!({
            "remote_name": Path::new(local_path).file_name().and_then(|item| item.to_str()),
            "local_path": local_path,
            "destination_size": bytes.len(),
            "sha256": digest(&bytes)
        })
    };
    fs::write(
        temp.path().join("report.json"),
        serde_json::to_vec(&report(vec![
            artifact("artifacts/healthy.trace.bin"),
            artifact("artifacts/missing.trace.bin"),
        ]))
        .expect("encode report"),
    )
    .expect("write report");

    let session = open(temp.path(), &AllowAll).expect("missing artifact is local failure");
    assert_eq!(session.artifacts().len(), 1);
    assert_eq!(session.failures().len(), 1);
    assert_eq!(
        session.failures()[0].local_path(),
        Some("artifacts/missing.trace.bin")
    );
    assert_eq!(session.failures()[0].error().code(), "source.not_found");
}

#[test]
fn an_ordinary_non_directory_parent_is_isolated_without_hiding_a_healthy_timeline() {
    let bytes = fixture_qtrb();
    let temp = TempDir::new().expect("session");
    fs::create_dir(temp.path().join("artifacts")).expect("artifacts");
    fs::write(temp.path().join("artifacts/good.trace.bin"), &bytes).expect("healthy artifact");
    fs::write(
        temp.path().join("artifacts/notdir"),
        b"ordinary regular file",
    )
    .expect("non-directory parent");
    let artifact = |local_path: &str| {
        json!({
            "remote_name": Path::new(local_path).file_name().and_then(|item| item.to_str()),
            "local_path": local_path,
            "destination_size": bytes.len(),
            "sha256": digest(&bytes)
        })
    };
    fs::write(
        temp.path().join("report.json"),
        serde_json::to_vec(&report(vec![
            artifact("artifacts/good.trace.bin"),
            artifact("artifacts/notdir/bad.trace.bin"),
        ]))
        .expect("encode report"),
    )
    .expect("write report");

    let session = open(temp.path(), &AllowAll).expect("ordinary non-directory parent is local");
    assert_eq!(session.artifacts().len(), 1);
    assert_eq!(session.failures().len(), 1);
    assert_eq!(
        session.failures()[0].local_path(),
        Some("artifacts/notdir/bad.trace.bin")
    );
    assert_eq!(session.failures()[0].error().code(), "source.not_directory");
}

#[test]
fn a_special_non_directory_parent_is_a_typed_local_failure() {
    let bytes = fixture_qtrb();
    let temp = TempDir::new().expect("session");
    fs::create_dir(temp.path().join("artifacts")).expect("artifacts");
    let _socket = UnixListener::bind(temp.path().join("artifacts/notdir"))
        .expect("special non-directory parent");
    write_report(
        temp.path(),
        "artifacts/notdir/bad.trace.bin",
        bytes.len(),
        &digest(&bytes),
    );

    let session = open(temp.path(), &AllowAll).expect("special non-directory parent is local");
    assert_eq!(session.failures().len(), 1);
    assert_eq!(session.failures()[0].error().code(), "source.not_directory");
}

#[test]
fn a_non_directory_selected_report_parent_is_a_typed_root_error() {
    let temp = TempDir::new().expect("selection container");
    fs::write(temp.path().join("notdir"), b"ordinary file").expect("non-directory parent");

    let error = open(&temp.path().join("notdir/session"), &AllowAll)
        .expect_err("selected report parent must reject the root");
    assert_eq!(error.code(), "session.not_directory");
}

#[test]
fn a_missing_report_is_a_typed_root_error() {
    let temp = TempDir::new().expect("empty selection");

    let error = open(temp.path(), &AllowAll).expect_err("missing report must reject the root");
    assert_eq!(error.code(), "session.report_missing");
}

#[test]
fn a_permission_denied_artifact_is_a_typed_local_failure() {
    let bytes = fixture_qtrb();
    let temp = valid_session(&bytes);
    let artifact = temp.path().join("artifacts/input.trace.bin");
    fs::set_permissions(&artifact, fs::Permissions::from_mode(0o0))
        .expect("remove read permission");
    if fs::File::open(&artifact).is_ok() {
        fs::set_permissions(&artifact, fs::Permissions::from_mode(0o600))
            .expect("restore read permission after privileged preflight");
        return;
    }

    let result = open(temp.path(), &AllowAll);
    fs::set_permissions(&artifact, fs::Permissions::from_mode(0o600))
        .expect("restore read permission");
    let session = result.expect("permission denial is artifact-local");
    assert_eq!(session.failures().len(), 1);
    assert_eq!(
        session.failures()[0].error().code(),
        "source.permission_denied"
    );
}

#[test]
fn parent_and_leaf_symlinks_are_root_failures() {
    let target = fixture_qtrb();
    let parent_session = TempDir::new().expect("parent symlink session");
    let outside = TempDir::new().expect("outside");
    fs::write(outside.path().join("trace.bin"), &target).expect("outside source");
    symlink(outside.path(), parent_session.path().join("artifacts")).expect("parent symlink");
    write_report(
        parent_session.path(),
        "artifacts/trace.bin",
        target.len(),
        &digest(&target),
    );
    let error = open(parent_session.path(), &AllowAll).expect_err("parent symlink");
    assert_eq!(error.code(), "session.path_escape");

    let leaf_session = TempDir::new().expect("leaf symlink session");
    fs::create_dir(leaf_session.path().join("artifacts")).expect("artifacts");
    fs::write(leaf_session.path().join("real.bin"), &target).expect("real source");
    symlink(
        "../real.bin",
        leaf_session.path().join("artifacts/trace.bin"),
    )
    .expect("leaf symlink");
    write_report(
        leaf_session.path(),
        "artifacts/trace.bin",
        target.len(),
        &digest(&target),
    );
    let error = open(leaf_session.path(), &AllowAll).expect_err("leaf symlink");
    assert_eq!(error.code(), "session.path_escape");
}

#[test]
fn replacing_a_path_with_a_symlink_during_hashing_fails_closed() {
    let bytes = fixture_qtrb();
    let temp = valid_session(&bytes);
    let artifact = temp.path().join("artifacts/input.trace.bin");
    let held = temp.path().join("artifacts/held.trace.bin");
    let outside = temp.path().join("outside.trace.bin");
    fs::write(&outside, &bytes).expect("outside file");
    let guard = OnArtifactRead::new(move || {
        fs::rename(&artifact, &held).expect("rename held inode");
        symlink(&outside, &artifact).expect("replace with symlink");
    });

    let error = open(temp.path(), &guard).expect_err("symlink race must fail");
    assert_eq!(error.code(), "session.path_escape");
}

#[test]
fn replacing_a_leaf_with_a_regular_file_during_hashing_fails_closed() {
    let bytes = fixture_qtrb();
    let temp = valid_session(&bytes);
    let artifact = temp.path().join("artifacts/input.trace.bin");
    let held = temp.path().join("artifacts/held.trace.bin");
    let replacement = bytes.clone();
    let guard = OnArtifactRead::new(move || {
        fs::rename(&artifact, &held).expect("rename held inode");
        fs::write(&artifact, replacement).expect("replace with regular file");
    });

    let error = open(temp.path(), &guard).expect_err("regular replacement race must fail");
    assert_eq!(error.code(), "session.path_escape");
}

#[test]
fn replacing_a_parent_directory_with_a_symlink_during_hashing_fails_closed() {
    let bytes = fixture_qtrb();
    let temp = valid_session(&bytes);
    let artifacts = temp.path().join("artifacts");
    let held = temp.path().join("held-artifacts");
    let outside = temp.path().join("outside-artifacts");
    fs::create_dir(&outside).expect("outside directory");
    fs::write(outside.join("input.trace.bin"), &bytes).expect("outside source");
    let guard = OnArtifactRead::new(move || {
        fs::rename(&artifacts, &held).expect("rename held directory");
        symlink(&outside, &artifacts).expect("replace parent with symlink");
    });

    let error = open(temp.path(), &guard).expect_err("parent-directory race must fail");
    assert_eq!(error.code(), "session.path_escape");
}

#[test]
fn replacing_the_selected_session_root_during_hashing_fails_closed() {
    let bytes = fixture_qtrb();
    let container = TempDir::new().expect("container");
    let selected = container.path().join("selected");
    let held = container.path().join("held");
    let outside = container.path().join("outside");
    fs::create_dir(&selected).expect("selected root");
    fs::create_dir(selected.join("artifacts")).expect("selected artifacts");
    fs::write(selected.join("artifacts/input.trace.bin"), &bytes).expect("selected source");
    write_report(
        &selected,
        "artifacts/input.trace.bin",
        bytes.len(),
        &digest(&bytes),
    );
    fs::create_dir(&outside).expect("outside root");
    fs::create_dir(outside.join("artifacts")).expect("outside artifacts");
    fs::write(outside.join("artifacts/input.trace.bin"), &bytes).expect("outside source");
    fs::write(outside.join("report.json"), b"{}").expect("outside report");
    let selected_for_race = selected.clone();
    let held_for_race = held.clone();
    let outside_for_race = outside.clone();
    let guard = OnArtifactRead::new(move || {
        fs::rename(&selected_for_race, &held_for_race).expect("rename selected root");
        symlink(&outside_for_race, &selected_for_race).expect("replace selected root");
    });

    let error = open(&selected, &guard).expect_err("selected-root race must fail");
    assert_eq!(error.code(), "session.path_escape");
    fs::remove_file(&selected).expect("remove replacement symlink");
    fs::rename(&held, &selected).expect("restore selected root for cleanup");
}

#[test]
fn replacing_a_path_after_open_cannot_redirect_the_owned_fd_and_fails_closed() {
    let bytes = fixture_qtrb();
    let temp = valid_session(&bytes);
    let session = open(temp.path(), &AllowAll).expect("open source");
    let path = temp.path().join("artifacts/input.trace.bin");
    fs::rename(&path, temp.path().join("artifacts/original.bin")).expect("rename original");
    fs::write(&path, b"replacement").expect("replacement path");

    let error = session.artifacts()[0]
        .read_all(&AllowAll)
        .expect_err("renamed source identity must fail closed");
    assert_eq!(error.code(), "source.identity_changed");
    assert_eq!(fs::read(path).expect("replacement bytes"), b"replacement");
}

#[test]
fn growth_and_shrink_during_hashing_are_typed_identity_drift() {
    for shrink in [false, true] {
        let bytes = fixture_qtrb();
        let temp = valid_session(&bytes);
        let artifact = temp.path().join("artifacts/input.trace.bin");
        let guard = OnArtifactRead::new(move || {
            if shrink {
                OpenOptions::new()
                    .write(true)
                    .open(&artifact)
                    .expect("open to shrink")
                    .set_len(16)
                    .expect("shrink");
            } else {
                OpenOptions::new()
                    .append(true)
                    .open(&artifact)
                    .expect("open to grow")
                    .write_all(b"growth")
                    .expect("grow");
            }
        });

        let session = open(temp.path(), &guard).expect("identity drift is artifact-local");
        assert_eq!(session.failures().len(), 1);
        assert_eq!(
            session.failures()[0].error().code(),
            "source.identity_changed"
        );
    }
}

#[test]
fn same_size_write_during_provider_probe_is_typed_identity_drift() {
    let bytes = fixture_qtrb();
    let temp = valid_session(&bytes);
    let artifact = temp.path().join("artifacts/input.trace.bin");
    let last = *bytes.last().expect("nonempty fixture");
    let offset = (bytes.len() - 1) as u64;
    let guard = OnArtifactRead::at(3, move || {
        let file = OpenOptions::new()
            .write(true)
            .open(&artifact)
            .expect("open for same-size write");
        file.write_at(&[last], offset).expect("same-size write");
    });

    let session = open(temp.path(), &guard).expect("identity drift is artifact-local");
    assert_eq!(session.failures().len(), 1);
    assert_eq!(
        session.failures()[0].error().code(),
        "source.identity_changed"
    );
}

#[test]
fn artifact_mutation_after_session_open_is_rejected_before_provider_reopen() {
    let bytes = fixture_qtrb();
    let temp = valid_session(&bytes);
    let session = open(temp.path(), &AllowAll).expect("open immutable source");
    touch_same_size(&temp.path().join("artifacts/input.trace.bin"), bytes.len());

    let error = match session.artifacts()[0].open_provider(&AllowAll) {
        Ok(_) => panic!("mutated source must not reopen under its old digest"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "source.identity_changed");
}

#[test]
fn artifact_mutation_after_session_open_is_rejected_before_direct_fd_read() {
    let bytes = fixture_qtrb();
    let temp = valid_session(&bytes);
    let session = open(temp.path(), &AllowAll).expect("open immutable source");
    touch_same_size(&temp.path().join("artifacts/input.trace.bin"), bytes.len());

    let error = session.artifacts()[0]
        .read_all(&AllowAll)
        .expect_err("mutated source must not read under its old digest");
    assert_eq!(error.code(), "source.identity_changed");
}

#[test]
fn artifact_mutation_while_streaming_is_rejected_before_summary_publication() {
    let bytes = fixture_qtrb();
    let temp = valid_session(&bytes);
    let session = open(temp.path(), &AllowAll).expect("open immutable source");
    let provider = session.artifacts()[0]
        .open_provider(&AllowAll)
        .expect("provider before mutation");
    let mut cursor = provider.into_cursor().expect("cursor");
    touch_same_size(&temp.path().join("artifacts/input.trace.bin"), bytes.len());
    while cursor
        .next_event(&AllowAll)
        .expect("drain cursor")
        .is_some()
    {}
    let error = cursor
        .finish()
        .expect_err("identity drift must block summary");
    assert_eq!(error.code(), "source.identity_changed");
}

#[test]
fn cancellation_and_byte_budget_abort_before_unapproved_reads() {
    struct Reject(OperationAbort);
    impl WorkGuard for Reject {
        fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
            Err(self.0.clone())
        }
    }

    let temp = valid_session(&fixture_qtrb());
    let cancelled =
        open(temp.path(), &Reject(OperationAbort::Cancelled)).expect_err("cancelled report read");
    assert_eq!(cancelled.code(), "control.cancelled");

    let budget = open(
        temp.path(),
        &Reject(OperationAbort::budget_exceeded(
            BudgetDimension::InputBytes,
            0,
            1,
        )),
    )
    .expect_err("budgeted report read");
    assert_eq!(budget.code(), "control.budget_exceeded");
}

#[test]
fn control_errors_after_the_report_escape_provider_artifact_isolation() {
    let cases = [
        (2, OperationAbort::Cancelled, "control.cancelled"),
        (
            3,
            OperationAbort::budget_exceeded(BudgetDimension::InputBytes, 0, 1),
            "control.budget_exceeded",
        ),
    ];
    for (reject_at, abort, expected) in cases {
        let temp = valid_session(&fixture_qtrb());
        let error = open(temp.path(), &RejectNthCall::new(reject_at, abort))
            .expect_err("global control errors must not become artifact failures");
        assert_eq!(error.code(), expected, "guard call {reject_at}");
    }

    let temp = valid_session(&fixture_qtrb());
    let error = open(
        temp.path(),
        &RejectInputCall::new(3, OperationAbort::Cancelled),
    )
    .expect_err("provider input cancellation must escape isolation");
    assert_eq!(error.code(), "control.cancelled");

    let temp = valid_session(&fixture_qtrb());
    let error = open(temp.path(), &RejectTimelineWork)
        .expect_err("timeline budget failure must escape isolation");
    assert_eq!(error.code(), "control.budget_exceeded");
}

#[test]
fn control_errors_escape_metadata_and_unknown_artifact_verification() {
    for local_path in ["artifacts/input.metrics", "artifacts/input.unknown"] {
        let bytes = b"metadata";
        let temp = TempDir::new().expect("session");
        fs::create_dir(temp.path().join("artifacts")).expect("artifacts");
        fs::write(temp.path().join(local_path), bytes).expect("artifact");
        write_report(temp.path(), local_path, bytes.len(), &digest(bytes));

        let error = open(
            temp.path(),
            &RejectInputCall::new(2, OperationAbort::Cancelled),
        )
        .expect_err("metadata verification cancellation must escape isolation");
        assert_eq!(error.code(), "control.cancelled", "{local_path}");
    }
}

#[test]
fn control_errors_escape_single_artifact_open_after_initial_work() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("qtrace-ui workspace root")
        .join("fixtures/sessions/valid-mixed/artifacts/main.trace.bin");
    for reject_at in [1, 2, 3] {
        let error = SessionLoader::open_artifact(
            AuthorizedPath::new(path.clone()),
            OpenPolicy::default(),
            &RejectNthCall::new(reject_at, OperationAbort::Cancelled),
        )
        .expect_err("single-artifact control error must abort the open");
        assert_eq!(error.code(), "control.cancelled", "guard call {reject_at}");
    }
}

fn open(
    path: &Path,
    guard: &dyn WorkGuard,
) -> Result<qtrace_store::SessionSource, qtrace_provider::ProviderError> {
    SessionLoader::open_report(
        AuthorizedPath::new(path.to_path_buf()),
        OpenPolicy::default(),
        guard,
    )
}

fn fixture_qtrb() -> Vec<u8> {
    fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("qtrace-ui workspace root")
            .join("fixtures/sessions/valid-mixed/artifacts/main.trace.bin"),
    )
    .expect("fixture QTRB")
}

fn valid_session(bytes: &[u8]) -> TempDir {
    let temp = TempDir::new().expect("session");
    fs::create_dir(temp.path().join("artifacts")).expect("artifacts");
    fs::write(temp.path().join("artifacts/input.trace.bin"), bytes).expect("artifact");
    write_report(
        temp.path(),
        "artifacts/input.trace.bin",
        bytes.len(),
        &digest(bytes),
    );
    temp
}

fn session_with_record(local_path: &str, bytes: &[u8]) -> TempDir {
    let temp = TempDir::new().expect("session");
    write_report(temp.path(), local_path, bytes.len(), &digest(bytes));
    temp
}

fn write_report(root: &Path, local_path: &str, size: usize, sha256: &str) {
    let artifact = json!({
        "remote_name": "input.trace.bin",
        "local_path": local_path,
        "destination_size": size,
        "sha256": sha256
    });
    let report = report(vec![artifact]);
    fs::write(
        root.join("report.json"),
        serde_json::to_vec(&report).expect("encode report"),
    )
    .expect("write report");
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

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn touch_same_size(path: &Path, original_size: usize) {
    let mut file = OpenOptions::new()
        .append(true)
        .open(path)
        .expect("open source to mutate");
    file.write_all(b"x").expect("append mutation");
    file.set_len(original_size as u64)
        .expect("restore source size");
}
