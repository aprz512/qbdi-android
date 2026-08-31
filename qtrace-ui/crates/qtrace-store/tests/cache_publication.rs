use std::{
    fs,
    io::Write,
    os::unix::{
        fs::{PermissionsExt, symlink},
        net::UnixListener,
    },
    path::{Path, PathBuf},
    sync::{Arc, Barrier, Mutex},
    thread,
};

use qtrace_provider::{
    ArtifactDigest, BudgetDimension, EventKey, EventKind, OperationAbort, TimelineId, WorkDelta,
    WorkGuard,
};
use qtrace_store::{
    CacheIdentity, CacheOpen, CacheReader, CacheWriter, OwnedStoreView, PublicationState,
};
use tempfile::TempDir;

fn identity(seed: u8) -> CacheIdentity {
    CacheIdentity {
        analyzer_version: "0.1.0-test".to_owned(),
        artifact_digest: [seed; 32],
        build_option_digest: [seed.wrapping_add(1); 32],
        cache_schema: 1,
        endian: "little".to_owned(),
        layout_version: 1,
        source_features: 3,
        source_format: "qtrb".to_owned(),
        source_major: 1,
        source_minor: 2,
    }
}

fn private_root() -> TempDir {
    let root = TempDir::new().expect("root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private root");
    root
}

fn store(seed: u8) -> OwnedStoreView {
    OwnedStoreView::new(
        vec![EventKey::new(
            ArtifactDigest::new([seed; 32]),
            TimelineId(0),
            0,
            64,
            Some(1),
            Some(7),
        )],
        vec![EventKind::Instruction],
    )
    .expect("store")
}

fn store_rows(seed: u8, rows: usize) -> OwnedStoreView {
    let digest = ArtifactDigest::new([seed; 32]);
    OwnedStoreView::new(
        (0..rows)
            .map(|row| EventKey::new(digest, TimelineId(0), row as u64, 64, Some(1), Some(7)))
            .collect(),
        vec![EventKind::Instruction; rows],
    )
    .expect("store")
}

fn final_path(root: &Path, identity: &CacheIdentity) -> PathBuf {
    root.join("qtrace-ui")
        .join(identity.cache_key())
        .join("index.qtc")
}

fn temporary_paths(digest: &Path) -> Vec<PathBuf> {
    fs::read_dir(digest)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
        .map(|entry| entry.path())
        .collect()
}

#[derive(Default)]
struct AllowAll;

impl WorkGuard for AllowAll {
    fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
        Ok(())
    }
}

struct CancelAll;

impl WorkGuard for CancelAll {
    fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
        Err(OperationAbort::Cancelled)
    }
}

struct CancelCheckpoint {
    target: usize,
    seen: Mutex<usize>,
    budget_failure: bool,
}

struct CaptureCheckpoint {
    target: usize,
    seen: Mutex<usize>,
    digest: PathBuf,
    bytes: Mutex<Vec<u8>>,
}

impl WorkGuard for CaptureCheckpoint {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        if delta == WorkDelta::default() {
            let mut seen = self.seen.lock().expect("checkpoint lock");
            *seen += 1;
            if *seen == self.target {
                let path = if self.target == 4 {
                    self.digest.join("index.qtc")
                } else {
                    let entries = temporary_paths(&self.digest);
                    assert_eq!(
                        entries.len(),
                        1,
                        "pre-rename checkpoint must have exactly one owned temp"
                    );
                    entries[0].clone()
                };
                *self.bytes.lock().expect("capture lock") = fs::read(path).expect("cache bytes");
                return Err(OperationAbort::Cancelled);
            }
        }
        Ok(())
    }
}

impl WorkGuard for CancelCheckpoint {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        if delta == WorkDelta::default() {
            let mut seen = self.seen.lock().expect("checkpoint lock");
            *seen += 1;
            if *seen == self.target {
                return if self.budget_failure {
                    Err(OperationAbort::budget_exceeded(
                        BudgetDimension::Nodes,
                        0,
                        1,
                    ))
                } else {
                    Err(OperationAbort::Cancelled)
                };
            }
        }
        Ok(())
    }
}

#[test]
fn every_publication_cancellation_point_rolls_back_final_and_temp() {
    for budget_failure in [false, true] {
        for checkpoint in 1..=4 {
            let root = private_root();
            let identity = identity(0x11);
            let error = CacheWriter::new(identity.clone(), store(0x11))
                .expect("writer")
                .publish(
                    root.path(),
                    &CancelCheckpoint {
                        target: checkpoint,
                        seen: Mutex::new(0),
                        budget_failure,
                    },
                )
                .expect_err("aborted publication");
            assert_eq!(
                error.code(),
                if budget_failure {
                    "control.budget_exceeded"
                } else {
                    "job.cancelled"
                }
            );
            assert!(
                !final_path(root.path(), &identity).exists(),
                "checkpoint {checkpoint}"
            );
            let digest = root.path().join("qtrace-ui").join(identity.cache_key());
            if digest.exists() {
                assert!(temporary_paths(&digest).is_empty());
            }
        }
    }
}

#[test]
fn checkpoints_observe_sections_manifest_header_and_postrename_final_in_order() {
    let mut captures = Vec::new();
    for checkpoint in 1..=4 {
        let root = private_root();
        let identity = identity(0x12);
        let digest = root.path().join("qtrace-ui").join(identity.cache_key());
        let guard = CaptureCheckpoint {
            target: checkpoint,
            seen: Mutex::new(0),
            digest,
            bytes: Mutex::new(Vec::new()),
        };
        CacheWriter::new(identity.clone(), store(0x12))
            .expect("writer")
            .publish(root.path(), &guard)
            .expect_err("checkpoint cancellation");
        captures.push(guard.bytes.into_inner().expect("captured bytes"));
        assert!(!final_path(root.path(), &identity).exists());
    }
    assert!(captures[0].len() < captures[1].len());
    assert_eq!(captures[1].len(), captures[2].len());
    assert_eq!(captures[2].len(), captures[3].len());
    assert_eq!(&captures[0][..8], &[0; 8]);
    assert_eq!(&captures[1][..8], &[0; 8]);
    assert_eq!(&captures[2][..8], b"QTCACHE\0");
    assert_eq!(&captures[3][..8], b"QTCACHE\0");
}

struct RejectLargeResident {
    limit: u64,
}

struct CaptureResident {
    maximum: Mutex<u64>,
}

impl WorkGuard for CaptureResident {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        let mut maximum = self.maximum.lock().expect("resident maximum");
        *maximum = (*maximum).max(delta.resident_bytes);
        Ok(())
    }
}

impl WorkGuard for RejectLargeResident {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        if delta.resident_bytes > self.limit {
            Err(OperationAbort::budget_exceeded(
                BudgetDimension::ResidentBytes,
                self.limit,
                delta.resident_bytes,
            ))
        } else {
            Ok(())
        }
    }
}

#[test]
fn writer_declares_true_peak_resident_budget_before_cache_path_io() {
    let parent = TempDir::new().expect("parent");
    let root = parent.path().join("not-created");
    let error = CacheWriter::new(identity(0x13), store_rows(0x13, 4096))
        .expect("writer")
        .publish(&root, &RejectLargeResident { limit: 1_500_000 })
        .expect_err("true peak exceeds guard threshold");
    assert_eq!(error.code(), "control.budget_exceeded");
    assert!(
        !root.exists(),
        "authorization must precede cache path allocation"
    );
}

#[test]
fn writer_declared_peak_has_an_exact_success_threshold() {
    let capture_root = private_root();
    let capture = CaptureResident {
        maximum: Mutex::new(0),
    };
    CacheWriter::new(identity(0x23), store_rows(0x23, 4096))
        .expect("writer")
        .publish(capture_root.path(), &capture)
        .expect("capture writer peak");
    let peak = *capture.maximum.lock().expect("resident maximum");
    assert!(peak > 0);

    let parent = TempDir::new().expect("below parent");
    let below_root = parent.path().join("not-created");
    let error = CacheWriter::new(identity(0x24), store_rows(0x24, 4096))
        .expect("writer")
        .publish(&below_root, &RejectLargeResident { limit: peak - 1 })
        .expect_err("one byte below writer peak");
    assert_eq!(error.code(), "control.budget_exceeded");
    assert!(!below_root.exists());

    let exact_root = private_root();
    CacheWriter::new(identity(0x25), store_rows(0x25, 4096))
        .expect("writer")
        .publish(exact_root.path(), &RejectLargeResident { limit: peak })
        .expect("exact writer peak succeeds");
}

#[test]
fn xdg_root_itself_must_be_private_but_ancestors_need_not_be() {
    let parent = TempDir::new().expect("parent");
    let root = parent.path().join("xdg-cache");
    fs::create_dir(&root).expect("root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).expect("root mode");
    let error = CacheWriter::new(identity(0x14), store(0x14))
        .expect("writer")
        .publish(&root, &AllowAll)
        .expect_err("public XDG cache root");
    assert_eq!(error.code(), "cache.path_escape");
    assert_eq!(fs::read_dir(root).expect("root entries").count(), 0);
}

struct ChmodAtCheckpoint {
    target: usize,
    seen: Mutex<usize>,
    path: PathBuf,
}

impl WorkGuard for ChmodAtCheckpoint {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        if delta == WorkDelta::default() {
            let mut seen = self.seen.lock().expect("checkpoint lock");
            *seen += 1;
            if *seen == self.target {
                fs::set_permissions(&self.path, fs::Permissions::from_mode(0o755))
                    .expect("mode drift");
            }
        }
        Ok(())
    }
}

#[test]
fn application_and_digest_mode_drift_fail_closed_before_commit() {
    for drift_app in [true, false] {
        let root = private_root();
        let identity = identity(if drift_app { 0x15 } else { 0x16 });
        let app = root.path().join("qtrace-ui");
        let digest = app.join(identity.cache_key());
        let drift = if drift_app { app } else { digest.clone() };
        let error = CacheWriter::new(identity.clone(), store(identity.artifact_digest[0]))
            .expect("writer")
            .publish(
                root.path(),
                &ChmodAtCheckpoint {
                    target: 3,
                    seen: Mutex::new(0),
                    path: drift,
                },
            )
            .expect_err("mode drift");
        assert_eq!(error.code(), "cache.path_escape");
        assert!(!final_path(root.path(), &identity).exists());
        assert!(temporary_paths(&digest).is_empty());
    }
}

struct ObservePostRenameCancel {
    seen: Mutex<usize>,
    final_path: PathBuf,
    observed_final: Mutex<bool>,
}

impl WorkGuard for ObservePostRenameCancel {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        if delta == WorkDelta::default() {
            let mut seen = self.seen.lock().expect("checkpoint lock");
            *seen += 1;
            if *seen == 4 {
                *self.observed_final.lock().expect("observation lock") = self.final_path.exists();
                return Err(OperationAbort::Cancelled);
            }
        }
        Ok(())
    }
}

#[test]
fn fourth_checkpoint_is_after_rename_and_cancel_rolls_back_owned_final() {
    let root = private_root();
    let identity = identity(0x17);
    let guard = ObservePostRenameCancel {
        seen: Mutex::new(0),
        final_path: final_path(root.path(), &identity),
        observed_final: Mutex::new(false),
    };
    let error = CacheWriter::new(identity.clone(), store(0x17))
        .expect("writer")
        .publish(root.path(), &guard)
        .expect_err("post-rename cancellation");
    assert_eq!(error.code(), "job.cancelled");
    assert_eq!(error.publication_state(), PublicationState::NoVisibleFinal);
    assert!(*guard.observed_final.lock().expect("observation lock"));
    assert!(!final_path(root.path(), &identity).exists());
    assert!(temporary_paths(&root.path().join("qtrace-ui").join(identity.cache_key())).is_empty());
}

#[test]
fn fourth_checkpoint_cancel_restores_exact_displaced_corrupt_inode_bytes() {
    let root = private_root();
    let identity = identity(0x1a);
    CacheWriter::new(identity.clone(), store(0x1a))
        .expect("initial writer")
        .publish(root.path(), &AllowAll)
        .expect("initial publish");
    let final_path = final_path(root.path(), &identity);
    let mut corrupt = fs::read(&final_path).expect("cache bytes");
    corrupt[64] ^= 1;
    fs::write(&final_path, &corrupt).expect("corrupt final");
    let metadata = fs::metadata(&final_path).expect("corrupt metadata");
    let inode = std::os::unix::fs::MetadataExt::ino(&metadata);
    let error = CacheWriter::new(identity.clone(), store(0x1a))
        .expect("replacement writer")
        .publish(
            root.path(),
            &CancelCheckpoint {
                target: 4,
                seen: Mutex::new(0),
                budget_failure: false,
            },
        )
        .expect_err("post-exchange cancellation");
    assert_eq!(error.code(), "job.cancelled");
    assert_eq!(fs::read(&final_path).expect("restored corrupt"), corrupt);
    assert_eq!(
        std::os::unix::fs::MetadataExt::ino(&fs::metadata(&final_path).expect("restored metadata")),
        inode,
        "rollback must restore the exact displaced inode"
    );
    assert!(temporary_paths(final_path.parent().expect("digest")).is_empty());
}

struct ReplacePostRenameOperand {
    seen: Mutex<usize>,
    digest: PathBuf,
    replace_final: bool,
    cancel: bool,
    foreign: Vec<u8>,
}

impl WorkGuard for ReplacePostRenameOperand {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        if delta == WorkDelta::default() {
            let mut seen = self.seen.lock().expect("checkpoint lock");
            *seen += 1;
            if *seen == 4 {
                let target = if self.replace_final {
                    self.digest.join("index.qtc")
                } else {
                    temporary_paths(&self.digest)
                        .into_iter()
                        .next()
                        .expect("displaced staging operand")
                };
                fs::rename(&target, target.with_extension("owned-held")).expect("hold operand");
                let mut file = fs::File::create(&target).expect("foreign replacement");
                file.write_all(&self.foreign).expect("foreign bytes");
                file.sync_all().expect("foreign sync");
                if self.cancel {
                    return Err(OperationAbort::Cancelled);
                }
            }
        }
        Ok(())
    }
}

#[test]
fn ambiguous_final_replacement_is_preserved_and_never_unlinked() {
    let root = private_root();
    let identity = identity(0x18);
    let digest = root.path().join("qtrace-ui").join(identity.cache_key());
    let foreign = b"foreign-final-competitor".to_vec();
    let error = CacheWriter::new(identity.clone(), store(0x18))
        .expect("writer")
        .publish(
            root.path(),
            &ReplacePostRenameOperand {
                seen: Mutex::new(0),
                digest,
                replace_final: true,
                cancel: false,
                foreign: foreign.clone(),
            },
        )
        .expect_err("ambiguous rollback");
    assert_eq!(
        error.publication_state(),
        PublicationState::VisibleDurabilityUncertain
    );
    assert_eq!(
        fs::read(final_path(root.path(), &identity)).expect("foreign survives"),
        foreign
    );
}

#[test]
fn ambiguous_displaced_operand_is_not_exchanged_into_final_or_deleted() {
    let root = private_root();
    let identity = identity(0x19);
    CacheWriter::new(identity.clone(), store(0x19))
        .expect("initial writer")
        .publish(root.path(), &AllowAll)
        .expect("initial publish");
    let final_path = final_path(root.path(), &identity);
    let mut corrupt = fs::read(&final_path).expect("cache bytes");
    corrupt[64] ^= 1;
    fs::write(&final_path, corrupt).expect("corrupt final");
    let digest = final_path.parent().expect("digest").to_owned();
    let foreign = b"foreign-staging-competitor".to_vec();
    let error = CacheWriter::new(identity.clone(), store(0x19))
        .expect("replacement writer")
        .publish(
            root.path(),
            &ReplacePostRenameOperand {
                seen: Mutex::new(0),
                digest: digest.clone(),
                replace_final: false,
                cancel: true,
                foreign: foreign.clone(),
            },
        )
        .expect_err("ambiguous displaced operand");
    assert_eq!(
        error.publication_state(),
        PublicationState::VisibleDurabilityUncertain
    );
    assert_ne!(fs::read(&final_path).expect("final"), foreign);
    assert!(
        temporary_paths(&digest)
            .into_iter()
            .any(|path| fs::read(path).ok().as_deref() == Some(foreign.as_slice()))
    );
}

#[test]
fn concurrent_builders_publish_only_a_complete_deterministic_winner() {
    let root = Arc::new(private_root());
    let barrier = Arc::new(Barrier::new(3));
    let identity = identity(0x22);
    let mut builders = Vec::new();
    for _ in 0..2 {
        let root = root.clone();
        let barrier = barrier.clone();
        let identity = identity.clone();
        builders.push(thread::spawn(move || {
            barrier.wait();
            CacheWriter::new(identity, store(0x22))
                .expect("writer")
                .publish(root.path(), &AllowAll)
        }));
    }
    barrier.wait();

    while builders.iter().any(|builder| !builder.is_finished()) {
        match CacheReader::open(root.path(), &identity, &AllowAll).expect("concurrent read") {
            CacheOpen::Missing | CacheOpen::Ready(_) => {}
            CacheOpen::Rebuild(reason) => panic!("reader observed partial cache: {reason:?}"),
        }
        thread::yield_now();
    }
    for builder in builders {
        builder
            .join()
            .expect("builder thread")
            .expect("builder result");
    }
    assert!(matches!(
        CacheReader::open(root.path(), &identity, &AllowAll).expect("winner"),
        CacheOpen::Ready(_)
    ));
}

#[test]
fn symlinked_roots_and_digest_directories_are_rejected_without_following() {
    let outside = TempDir::new().expect("outside");
    let parent = TempDir::new().expect("parent");
    let linked_root = parent.path().join("xdg");
    symlink(outside.path(), &linked_root).expect("root symlink");
    let identity = identity(0x33);
    let error = CacheWriter::new(identity.clone(), store(0x33))
        .expect("writer")
        .publish(&linked_root, &AllowAll)
        .expect_err("symlinked root");
    assert_eq!(error.code(), "cache.path_escape");
    assert_eq!(
        fs::read_dir(outside.path())
            .expect("outside entries")
            .count(),
        0
    );

    let root = private_root();
    fs::create_dir(root.path().join("qtrace-ui")).expect("app dir");
    fs::set_permissions(
        root.path().join("qtrace-ui"),
        fs::Permissions::from_mode(0o700),
    )
    .expect("private app dir");
    symlink(
        outside.path(),
        root.path().join("qtrace-ui").join(identity.cache_key()),
    )
    .expect("digest symlink");
    let error = CacheWriter::new(identity, store(0x33))
        .expect("writer")
        .publish(root.path(), &AllowAll)
        .expect_err("symlinked digest");
    assert_eq!(error.code(), "cache.path_escape");
    assert_eq!(
        fs::read_dir(outside.path())
            .expect("outside entries")
            .count(),
        0
    );
}

fn prepare_digest(root: &Path, identity: &CacheIdentity) -> PathBuf {
    let app = root.join("qtrace-ui");
    let digest = app.join(identity.cache_key());
    fs::create_dir_all(&digest).expect("digest");
    fs::set_permissions(&app, fs::Permissions::from_mode(0o700)).expect("private app");
    fs::set_permissions(&digest, fs::Permissions::from_mode(0o700)).expect("private digest");
    digest
}

#[test]
fn publication_lock_rejects_symlink_special_and_foreign_mode() {
    for case in 0..3 {
        let root = private_root();
        let identity = identity(0x35 + case);
        let digest = prepare_digest(root.path(), &identity);
        let lock = digest.join(".publish.lock");
        let outside = root.path().join(format!("outside-{case}"));
        let listener = match case {
            0 => {
                fs::write(&outside, b"outside").expect("outside");
                symlink(&outside, &lock).expect("lock symlink");
                None
            }
            1 => Some(UnixListener::bind(&lock).expect("lock socket")),
            _ => {
                fs::write(&lock, b"foreign lock").expect("lock file");
                fs::set_permissions(&lock, fs::Permissions::from_mode(0o644))
                    .expect("foreign lock mode");
                None
            }
        };
        let error = CacheWriter::new(identity, store(0x35 + case))
            .expect("writer")
            .publish(root.path(), &AllowAll)
            .expect_err("unsafe publication lock");
        assert_eq!(error.code(), "cache.path_escape");
        assert!(lock.exists());
        if case == 0 {
            assert_eq!(fs::read(outside).expect("outside survives"), b"outside");
        }
        drop(listener);
    }
}

#[test]
fn final_leaf_mode_is_verified_by_reader_and_writer() {
    let root = private_root();
    let identity = identity(0x39);
    CacheWriter::new(identity.clone(), store(0x39))
        .expect("writer")
        .publish(root.path(), &AllowAll)
        .expect("publish");
    let final_path = final_path(root.path(), &identity);
    fs::set_permissions(&final_path, fs::Permissions::from_mode(0o644)).expect("mode drift");
    let reader_error = CacheReader::open(root.path(), &identity, &AllowAll)
        .expect_err("reader must reject public final");
    assert_eq!(reader_error.code(), "cache.path_escape");
    let writer_error = CacheWriter::new(identity, store(0x39))
        .expect("writer")
        .publish(root.path(), &AllowAll)
        .expect_err("writer must reject public final");
    assert_eq!(writer_error.code(), "cache.path_escape");
}

#[test]
fn reader_authorization_precedes_cache_path_io() {
    let outside = TempDir::new().expect("outside");
    let parent = TempDir::new().expect("parent");
    let linked_root = parent.path().join("xdg");
    symlink(outside.path(), &linked_root).expect("root symlink");
    let error = CacheReader::open(&linked_root, &identity(0x34), &CancelAll)
        .expect_err("control error must precede path traversal");
    assert_eq!(error.code(), "job.cancelled");
}

#[test]
fn a_special_leaf_is_rejected_and_never_removed() {
    let root = private_root();
    let identity = identity(0x44);
    let digest = root.path().join("qtrace-ui").join(identity.cache_key());
    fs::create_dir_all(&digest).expect("digest");
    fs::set_permissions(
        root.path().join("qtrace-ui"),
        fs::Permissions::from_mode(0o700),
    )
    .expect("private app dir");
    fs::set_permissions(&digest, fs::Permissions::from_mode(0o700)).expect("private digest dir");
    let socket_path = digest.join("index.qtc");
    let listener = UnixListener::bind(&socket_path).expect("socket");

    let error = CacheWriter::new(identity, store(0x44))
        .expect("writer")
        .publish(root.path(), &AllowAll)
        .expect_err("special leaf");
    assert_eq!(error.code(), "cache.path_escape");
    assert!(socket_path.exists());
    drop(listener);
}

struct ReplaceDirectory {
    target: usize,
    seen: Mutex<usize>,
    digest: PathBuf,
}

impl WorkGuard for ReplaceDirectory {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        if delta == WorkDelta::default() {
            let mut seen = self.seen.lock().expect("checkpoint lock");
            *seen += 1;
            if *seen == self.target {
                fs::rename(&self.digest, self.digest.with_extension("held")).expect("move digest");
                fs::create_dir(&self.digest).expect("replacement digest");
            }
        }
        Ok(())
    }
}

#[test]
fn digest_directory_replacement_before_commit_fails_without_publishing() {
    let root = private_root();
    let identity = identity(0x55);
    let digest = root.path().join("qtrace-ui").join(identity.cache_key());
    let error = CacheWriter::new(identity.clone(), store(0x55))
        .expect("writer")
        .publish(
            root.path(),
            &ReplaceDirectory {
                target: 4,
                seen: Mutex::new(0),
                digest: digest.clone(),
            },
        )
        .expect_err("directory replacement");
    assert_eq!(error.code(), "cache.path_escape");
    assert!(!final_path(root.path(), &identity).exists());
    assert_eq!(
        fs::read_dir(&digest).expect("replacement entries").count(),
        0
    );
    let displaced = digest.with_extension("held");
    assert!(!displaced.join("index.qtc").exists());
    assert!(temporary_paths(&displaced).is_empty());
}

struct ReplaceDuringRead {
    digest: PathBuf,
    reads: Mutex<usize>,
}

impl WorkGuard for ReplaceDuringRead {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        if delta.input_bytes != 0 {
            let mut reads = self.reads.lock().expect("read count");
            *reads += 1;
            if *reads == 2 {
                fs::rename(&self.digest, self.digest.with_extension("held")).expect("move digest");
                fs::create_dir(&self.digest).expect("replacement digest");
                fs::set_permissions(&self.digest, fs::Permissions::from_mode(0o700))
                    .expect("private replacement");
            }
        }
        Ok(())
    }
}

#[test]
fn reader_rejects_digest_directory_replacement_during_validation() {
    let root = private_root();
    let identity = identity(0x56);
    CacheWriter::new(identity.clone(), store(0x56))
        .expect("writer")
        .publish(root.path(), &AllowAll)
        .expect("publish");
    let digest = root.path().join("qtrace-ui").join(identity.cache_key());
    let error = CacheReader::open(
        root.path(),
        &identity,
        &ReplaceDuringRead {
            digest: digest.clone(),
            reads: Mutex::new(0),
        },
    )
    .expect_err("reader directory replacement");
    assert_eq!(error.code(), "cache.path_escape");
    assert_eq!(
        fs::read_dir(digest).expect("replacement entries").count(),
        0
    );
}

#[test]
fn same_identity_corrupt_cache_is_atomically_replaced_but_other_identity_is_not() {
    let root = private_root();
    let expected = identity(0x66);
    CacheWriter::new(expected.clone(), store(0x66))
        .expect("writer")
        .publish(root.path(), &AllowAll)
        .expect("initial publish");
    let path = final_path(root.path(), &expected);
    let mut corrupt = fs::read(&path).expect("cache bytes");
    corrupt[64] ^= 1;
    fs::write(&path, corrupt).expect("corrupt section");
    assert!(matches!(
        CacheReader::open(root.path(), &expected, &AllowAll).expect("corrupt open"),
        CacheOpen::Rebuild(_)
    ));
    CacheWriter::new(expected.clone(), store(0x66))
        .expect("replacement writer")
        .publish(root.path(), &AllowAll)
        .expect("replace corrupt cache");
    assert!(matches!(
        CacheReader::open(root.path(), &expected, &AllowAll).expect("replacement open"),
        CacheOpen::Ready(_)
    ));

    let other_root = TempDir::new().expect("other root");
    fs::set_permissions(other_root.path(), fs::Permissions::from_mode(0o700))
        .expect("private other root");
    let other = identity(0x77);
    CacheWriter::new(other.clone(), store(0x77))
        .expect("other writer")
        .publish(other_root.path(), &AllowAll)
        .expect("other publish");
    fs::write(
        &path,
        fs::read(final_path(other_root.path(), &other)).expect("other bytes"),
    )
    .expect("foreign final");
    let before = fs::read(&path).expect("before foreign");
    let error = CacheWriter::new(expected, store(0x66))
        .expect("writer")
        .publish(root.path(), &AllowAll)
        .expect_err("foreign identity must fail closed");
    assert_eq!(error.code(), "cache.identity_conflict");
    assert_eq!(fs::read(path).expect("after foreign"), before);
}
