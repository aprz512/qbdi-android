use std::{
    fs,
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
use qtrace_store::{CacheIdentity, CacheOpen, CacheReader, CacheWriter, OwnedStoreView};
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

fn final_path(root: &Path, identity: &CacheIdentity) -> PathBuf {
    root.join("qtrace-ui")
        .join(identity.cache_key())
        .join("index.qtc")
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
                let entries = fs::read_dir(&self.digest)
                    .ok()
                    .into_iter()
                    .flatten()
                    .filter_map(Result::ok)
                    .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
                    .collect::<Vec<_>>();
                assert_eq!(
                    entries.len(),
                    1,
                    "checkpoint must have exactly one owned temp"
                );
                *self.bytes.lock().expect("capture lock") =
                    fs::read(entries[0].path()).expect("temp bytes");
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
fn every_precommit_cancellation_point_leaves_no_visible_final_or_temp() {
    for budget_failure in [false, true] {
        for checkpoint in 1..=4 {
            let root = TempDir::new().expect("root");
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
                assert_eq!(fs::read_dir(digest).expect("digest entries").count(), 0);
            }
        }
    }
}

#[test]
fn checkpoints_observe_sections_manifest_final_header_and_precommit_in_order() {
    let mut captures = Vec::new();
    for checkpoint in 1..=4 {
        let root = TempDir::new().expect("root");
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

#[test]
fn concurrent_builders_publish_only_a_complete_deterministic_winner() {
    let root = Arc::new(TempDir::new().expect("root"));
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

    let root = TempDir::new().expect("root");
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
    let root = TempDir::new().expect("root");
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
    let root = TempDir::new().expect("root");
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
    let root = TempDir::new().expect("root");
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
    let root = TempDir::new().expect("root");
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
