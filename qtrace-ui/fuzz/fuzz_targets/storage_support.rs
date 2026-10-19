#![allow(dead_code)]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
};

use qtrace_provider::{ArtifactDigest, EventKey, EventKind, TimelineId, WorkDelta, WorkGuard};
use qtrace_store::{
    AnnotationOpenRequest, AnnotationStore, AuthorizedPath, CacheIdentity, CacheOpen, CacheReader,
    CacheWriter, EventAnnotation, Highlight, LocalSymbolName, OpenPolicy, OwnedStoreView,
    SessionLoader, StoreView,
};
use rusqlite::Connection;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use super::support::StrictGuard;

pub const STORAGE_INPUT_LIMIT: usize = 1024 * 1024;
pub const ANNOTATION_INPUT_LIMIT: usize = 256 * 1024;
const REPORT: &[u8] = include_bytes!("../../fixtures/sessions/valid-mixed/report.json");
const QTRB: &[u8] = include_bytes!("../../fixtures/qtrb/v1.2-completed.bin");
const LEGACY_QTRB: &[u8] = include_bytes!("../../fixtures/qtrb/v1.0-completed.bin");
const FLIGHT: &[u8] = include_bytes!("../../fixtures/flight/v2-complete.bin");

#[derive(Debug, Eq, PartialEq)]
pub enum Outcome {
    Accepted,
    Rejected,
    Budget,
}

fn event() -> EventKey {
    EventKey::new(
        ArtifactDigest::new([0x61; 32]),
        TimelineId(1),
        0,
        0x100,
        Some(1),
        Some(731),
    )
}

fn identity() -> CacheIdentity {
    CacheIdentity {
        analyzer_version: "storage-fuzz-v1".into(),
        artifact_digest: [0x61; 32],
        build_option_digest: [0x62; 32],
        cache_schema: 1,
        endian: "little".into(),
        layout_version: 1,
        source_features: 1,
        source_format: "QTRB".into(),
        source_major: 1,
        source_minor: 2,
    }
}

fn private_directory(path: &Path) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn private_file(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn cache_path(root: &Path) -> PathBuf {
    root.join("qtrace-ui")
        .join(identity().cache_key())
        .join("index.qtc")
}

fn valid_cache() -> &'static [u8] {
    static CACHE: OnceLock<Vec<u8>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let root = TempDir::new().unwrap();
        private_directory(root.path());
        CacheWriter::new(
            identity(),
            OwnedStoreView::new(vec![event()], vec![EventKind::Instruction]).unwrap(),
        )
        .unwrap()
        .publish(root.path(), &StrictGuard::new())
        .unwrap();
        fs::read(cache_path(root.path())).unwrap()
    })
}

fn patches(bytes: &mut [u8], input: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    for patch in input.chunks_exact(3).take(STORAGE_INPUT_LIMIT / 3) {
        let index = usize::from(u16::from_le_bytes([patch[0], patch[1]])) % bytes.len();
        bytes[index] ^= patch[2];
    }
}

fn selector<'a>(data: &'a [u8], prefix: &[u8]) -> Option<(&'a [u8], &'a [u8])> {
    let rest = data.strip_prefix(prefix)?;
    let newline = rest.iter().position(|byte| *byte == b'\n')?;
    Some((&rest[..newline], &rest[newline + 1..]))
}

pub fn expand_cache_seed(data: &[u8]) -> Vec<u8> {
    let Some((kind, mutations)) = selector(data, b"cache:") else {
        return data.to_vec();
    };
    let mut bytes = valid_cache().to_vec();
    let offset = u64::from_le_bytes(bytes[16..24].try_into().unwrap()) as usize;
    let mut manifest: Value = serde_json::from_slice(&bytes[offset..]).unwrap();
    match kind {
        b"valid" => {}
        b"overlap" => manifest["sections"][1]["offset"] = manifest["sections"][0]["offset"].clone(),
        b"overflow" => manifest["sections"][0]["length"] = json!(u64::MAX),
        b"identity" => manifest["identity"]["source_minor"] = json!(99),
        b"section-count" => {
            let section = manifest["sections"][0].clone();
            manifest["sections"] = json!(vec![section; 65]);
        }
        b"unknown-field" => manifest["injected"] = json!(true),
        b"truncated" => {
            bytes.truncate(65);
            patches(&mut bytes, mutations);
            return bytes;
        }
        _ => return data.to_vec(),
    }
    let encoded = serde_json::to_vec(&manifest).unwrap();
    bytes.truncate(offset);
    bytes.extend_from_slice(&encoded);
    bytes[24..32].copy_from_slice(&(encoded.len() as u64).to_le_bytes());
    bytes[32..64].copy_from_slice(&Sha256::digest(&encoded));
    patches(&mut bytes, mutations);
    // Keep a valid envelope after payload mutations so fuzzing reaches JSON/section checks.
    // Malformed header/range mutations still pass to the production reader unchanged.
    let offset = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
    let length = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
    if let (Ok(offset), Ok(length)) = (usize::try_from(offset), usize::try_from(length))
        && let Some(end) = offset.checked_add(length)
        && offset >= 64
        && end <= bytes.len()
    {
        let digest = Sha256::digest(&bytes[offset..end]);
        bytes[32..64].copy_from_slice(&digest);
    }
    bytes
}

pub fn fuzz_cache_manifest(data: &[u8]) -> Outcome {
    if data.len() > STORAGE_INPUT_LIMIT {
        return Outcome::Budget;
    }
    let bytes = expand_cache_seed(data);
    let guard = StrictGuard::new();
    if guard
        .consume(WorkDelta {
            resident_bytes: bytes.len() as u64,
            ..WorkDelta::default()
        })
        .is_err()
    {
        return Outcome::Budget;
    }
    let root = TempDir::new().unwrap();
    let path = cache_path(root.path());
    private_directory(root.path());
    private_directory(path.parent().unwrap());
    private_directory(path.parent().unwrap().parent().unwrap());
    private_file(&path, &bytes);
    let outcome = match CacheReader::open(root.path(), &identity(), &guard) {
        Ok(CacheOpen::Ready(view)) => {
            for row in 0..view.event_count().min(100_000) {
                if guard
                    .consume(WorkDelta {
                        nodes: 1,
                        ..WorkDelta::default()
                    })
                    .is_err()
                {
                    break;
                }
                let _ = view.event_key(row);
                let _ = view.event_kind(row);
            }
            Outcome::Accepted
        }
        _ => Outcome::Rejected,
    };
    assert_eq!(
        fs::read(path).unwrap(),
        bytes,
        "cache reads must preserve untrusted input"
    );
    outcome
}

pub fn expand_session_seed(data: &[u8]) -> Vec<u8> {
    let Some((kind, mutations)) = selector(data, b"session:") else {
        return data.to_vec();
    };
    let mut report: Value = serde_json::from_slice(REPORT).unwrap();
    match kind {
        b"valid" => {}
        b"path-escape" => report["artifacts"][0]["local_path"] = json!("../escape.trace.bin"),
        b"size-overflow" => report["artifacts"][0]["destination_size"] = json!(u64::MAX),
        b"collection-limit" => report["warnings"] = json!(vec![json!({}); 4097]),
        b"unknown-field" => report["injected"] = json!(true),
        b"deep-json" => {
            report["native"]["deep"] = Value::Null;
            let prefix = serde_json::to_string(&report).unwrap();
            let nested = format!("\"deep\":{}0{}", "[".repeat(160), "]".repeat(160));
            return prefix.replace("\"deep\":null", &nested).into_bytes();
        }
        b"nul-path" => report["artifacts"][0]["local_path"] = json!("artifacts/\0bad.trace.bin"),
        _ => return data.to_vec(),
    }
    let mut bytes = serde_json::to_vec(&report).unwrap();
    patches(&mut bytes, mutations);
    bytes
}

pub fn fuzz_session_report(data: &[u8]) -> Outcome {
    if data.len() > STORAGE_INPUT_LIMIT {
        return Outcome::Budget;
    }
    let bytes = expand_session_seed(data);
    let guard = StrictGuard::new();
    // Reserve a conservative JSON tree bound before entering the production report loader.
    if guard
        .consume(WorkDelta {
            resident_bytes: bytes.len() as u64 * 64,
            nodes: bytes.len() as u64,
            ..WorkDelta::default()
        })
        .is_err()
    {
        return Outcome::Budget;
    }
    let root = TempDir::new().unwrap();
    let artifacts = root.path().join("artifacts");
    private_directory(&artifacts);
    for (name, fixture) in [
        ("main.trace.bin", QTRB),
        ("worker.trace.bin", LEGACY_QTRB),
        ("capture.flight.bin", FLIGHT),
    ] {
        private_file(&artifacts.join(name), fixture);
    }
    let report = root.path().join("report.json");
    private_file(&report, &bytes);
    let outcome = match SessionLoader::open_report(
        AuthorizedPath::new(root.path().to_owned()),
        OpenPolicy::default(),
        &guard,
    ) {
        Ok(session) => {
            assert!(session.artifacts().len() + session.failures().len() <= 4096);
            Outcome::Accepted
        }
        Err(_) => Outcome::Rejected,
    };
    assert_eq!(
        fs::read(report).unwrap(),
        bytes,
        "session reports must remain read-only"
    );
    for (name, fixture) in [
        ("main.trace.bin", QTRB),
        ("worker.trace.bin", LEGACY_QTRB),
        ("capture.flight.bin", FLIGHT),
    ] {
        assert_eq!(
            fs::read(artifacts.join(name)).unwrap(),
            fixture,
            "session artifacts must remain read-only"
        );
    }
    outcome
}

fn annotation_request(root: &Path) -> AnnotationOpenRequest {
    AnnotationOpenRequest::new(
        AuthorizedPath::new(root.to_owned()),
        ArtifactDigest::new([0x63; 32]),
    )
}

fn annotation_path(root: &Path) -> PathBuf {
    root.join("qtrace-ui")
        .join(ArtifactDigest::new([0x63; 32]).to_hex())
        .join("annotations.sqlite3")
}

fn annotation_seed(kind: &[u8]) -> Vec<u8> {
    let root = TempDir::new().unwrap();
    let mut store = AnnotationStore::open_guarded(
        annotation_request(root.path()),
        Arc::new(StrictGuard::new()),
    )
    .unwrap();
    let mut transaction = store.begin_transaction().unwrap();
    transaction
        .put_event_annotation(&EventAnnotation::new(event(), "seed").unwrap())
        .unwrap();
    transaction.commit().unwrap();
    drop(store);
    // Checkpoint production-created pages before copying a standalone main database into fuzz cases.
    let connection = Connection::open(annotation_path(root.path())).unwrap();
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;")
        .unwrap();
    match kind {
        b"legacy-v1" => connection.execute_batch("DROP TABLE event_annotations; DROP TABLE local_symbol_names; DROP TABLE highlights; UPDATE schema_version SET version=1;").unwrap(),
        b"legacy-v2" => connection.execute_batch("UPDATE schema_version SET version=2;").unwrap(),
        b"oversized-text" => connection.execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE schema_version SET version=2; UPDATE event_annotations SET comment=replace(hex(zeroblob(40000)), '0', 'x');").unwrap(),
        b"wrong-type" => connection.execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE schema_version SET version=2; UPDATE event_annotations SET comment=x'ff';").unwrap(),
        b"recursive-view" => connection.execute_batch("UPDATE schema_version SET version=2; DROP TABLE event_annotations; CREATE VIEW event_annotations AS WITH RECURSIVE work(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM work WHERE x<1000000) SELECT zeroblob(70) AS event_key, 'x'||x AS comment FROM work;").unwrap(),
        _ => {}
    }
    drop(connection);
    fs::read(annotation_path(root.path())).unwrap()
}

pub fn expand_annotation_seed(data: &[u8]) -> Vec<u8> {
    let Some((kind, mutations)) = selector(data, b"annotation:") else {
        return data.to_vec();
    };
    static SEEDS: OnceLock<Vec<(&'static [u8], Vec<u8>)>> = OnceLock::new();
    let seeds = SEEDS.get_or_init(|| {
        [
            b"valid".as_slice(),
            b"legacy-v1",
            b"legacy-v2",
            b"oversized-text",
            b"wrong-type",
            b"recursive-view",
        ]
        .into_iter()
        .map(|kind| (kind, annotation_seed(kind)))
        .collect()
    });
    let Some((_, seed)) = seeds.iter().find(|(name, _)| *name == kind) else {
        return data.to_vec();
    };
    let mut bytes = seed.clone();
    patches(&mut bytes, mutations);
    bytes
}

pub fn fuzz_annotations(data: &[u8]) -> Outcome {
    if data.len() > ANNOTATION_INPUT_LIMIT {
        return Outcome::Budget;
    }
    let bytes = expand_annotation_seed(data);
    if bytes.len() > ANNOTATION_INPUT_LIMIT {
        return Outcome::Budget;
    }
    let guard = Arc::new(StrictGuard::new());
    if guard
        .consume(WorkDelta {
            resident_bytes: bytes.len() as u64,
            ..WorkDelta::default()
        })
        .is_err()
    {
        return Outcome::Budget;
    }
    let root = TempDir::new().unwrap();
    let path = annotation_path(root.path());
    private_directory(path.parent().unwrap());
    private_directory(path.parent().unwrap().parent().unwrap());
    // SQLite may migrate this private copy. The input slice and checked-in corpus are immutable.
    private_file(&path, &bytes);
    let Ok(mut store) = AnnotationStore::open_guarded(annotation_request(root.path()), guard)
    else {
        return Outcome::Rejected;
    };
    let _ = store.event_annotation(&event());
    let _ = store.highlight(&event());
    let _ = store.local_symbol_name(ArtifactDigest::new([0x64; 32]), 0x120);
    let text = String::from_utf8_lossy(&data[..data.len().min(4096)]).into_owned();
    if let (Ok(annotation), Ok(name), Ok(highlight)) = (
        EventAnnotation::new(event(), text.clone()),
        LocalSymbolName::new(ArtifactDigest::new([0x64; 32]), 0x120, text.clone()),
        Highlight::new(event(), text.chars().take(64).collect::<String>()),
    ) && let Ok(mut transaction) = store.begin_transaction()
    {
        let _ = transaction.put_event_annotation(&annotation);
        let _ = transaction.put_local_symbol_name(&name);
        let _ = transaction.put_highlight(&highlight);
        let _ = transaction.rollback();
    }
    Outcome::Accepted
}
