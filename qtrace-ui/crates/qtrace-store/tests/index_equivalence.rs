use std::{fs, path::Path, path::PathBuf};

use qtrace_provider::{EventKind, OperationAbort, WorkDelta, WorkGuard};
use qtrace_store::{
    AuthorizedPath, BuildOptions, IndexBuilder, OpenPolicy, SessionLoader, TraceStore,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

struct AllowAll;

impl WorkGuard for AllowAll {
    fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
        Ok(())
    }
}

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("fixtures/sessions/valid-mixed")
}

#[test]
fn published_cache_reopens_as_mapped_store_with_equivalent_queries() {
    let session = SessionLoader::open_report(
        AuthorizedPath::new(fixture()),
        OpenPolicy::default(),
        &AllowAll,
    )
    .expect("Flight fixture");
    let source = session
        .artifacts()
        .iter()
        .find(|artifact| artifact.local_path().ends_with("capture.flight.bin"))
        .expect("Flight artifact");
    let options = BuildOptions::default();
    let owned = IndexBuilder::build(source, &options, &AllowAll).expect("owned index");
    let root = private_root();
    let mapped =
        TraceStore::open_or_build(root.path(), source, &options, &AllowAll).expect("mapped index");

    assert!(mapped.is_mapped());
    assert_eq!(owned.event_count(), mapped.event_count());
    assert_eq!(owned.capabilities(), mapped.capabilities());
    for row in 0..owned.event_count() {
        assert_eq!(
            owned.event_key(row),
            mapped.event_key(row).expect("mapped key")
        );
        assert_eq!(
            owned.event_kind(row),
            mapped.event_kind(row).expect("mapped kind")
        );
        assert_eq!(
            owned.provenance(row),
            mapped.provenance(row).expect("mapped provenance")
        );
    }

    for kinds in [
        vec![EventKind::Instruction],
        vec![EventKind::SemanticCall, EventKind::SemanticRule],
        vec![EventKind::RegisterCheckpoint, EventKind::RegisterDelta],
    ] {
        assert_eq!(
            owned.rows_of_kinds(&kinds).collect::<Vec<_>>(),
            mapped.rows_of_kinds(&kinds).expect("mapped postings")
        );
    }
    assert_eq!(
        owned
            .memory_overlaps(0x2002, 0x2004)
            .expect("owned overlap")
            .collect::<Vec<_>>(),
        mapped
            .memory_overlaps(0x2002, 0x2004)
            .expect("mapped overlap")
    );

    let reopened = TraceStore::open_or_build(root.path(), source, &options, &AllowAll)
        .expect("warm cache open");
    assert!(reopened.is_mapped());
    assert_eq!(mapped.event_count(), reopened.event_count());
}

#[test]
fn build_option_digest_is_deterministic_and_changes_cache_identity() {
    let default = BuildOptions::default();
    let smaller_blocks = default
        .clone()
        .with_interval_block_rows(16)
        .expect("valid block size");
    assert_eq!(default.digest(), BuildOptions::default().digest());
    assert_ne!(default.digest(), smaller_blocks.digest());
}

#[test]
fn normalized_cache_bytes_are_deterministic_for_the_same_source_and_options() {
    let session = SessionLoader::open_report(
        AuthorizedPath::new(fixture()),
        OpenPolicy::default(),
        &AllowAll,
    )
    .expect("mixed fixture");
    let source = session
        .artifacts()
        .iter()
        .find(|artifact| artifact.local_path().ends_with("main.trace.bin"))
        .expect("QTRB artifact");
    let options = BuildOptions::default();
    let first_root = private_root();
    let second_root = private_root();

    TraceStore::open_or_build(first_root.path(), source, &options, &AllowAll)
        .expect("first deterministic cache");
    TraceStore::open_or_build(second_root.path(), source, &options, &AllowAll)
        .expect("second deterministic cache");

    assert_eq!(
        fs::read(only_cache(first_root.path())).expect("first cache bytes"),
        fs::read(only_cache(second_root.path())).expect("second cache bytes")
    );
}

#[test]
fn a_resigned_invalid_source_key_bijection_is_rebuilt_not_opened() {
    let session = SessionLoader::open_report(
        AuthorizedPath::new(fixture()),
        OpenPolicy::default(),
        &AllowAll,
    )
    .expect("mixed fixture");
    let source = session
        .artifacts()
        .iter()
        .find(|artifact| artifact.local_path().ends_with("main.trace.bin"))
        .expect("QTRB artifact");
    let options = BuildOptions::default();
    let root = private_root();
    let first =
        TraceStore::open_or_build(root.path(), source, &options, &AllowAll).expect("initial cache");
    let expected_key = first.event_key(0).expect("key access").expect("row zero");
    let cache = only_cache(root.path());
    let mut bytes = fs::read(&cache).expect("cache bytes");
    resign_source_row_corruption(&mut bytes);
    fs::write(&cache, &bytes).expect("corrupt cache");

    let rebuilt = TraceStore::open_or_build(root.path(), source, &options, &AllowAll)
        .expect("corrupt normalized cache rebuilds");
    assert_eq!(
        rebuilt.event_key(0).expect("key access"),
        Some(expected_key)
    );
}

fn only_cache(root: &Path) -> PathBuf {
    let app = root.join("qtrace-ui");
    let digest = fs::read_dir(app)
        .expect("cache app")
        .filter_map(Result::ok)
        .find(|entry| entry.path().is_dir())
        .expect("digest");
    digest.path().join("index.qtc")
}

fn resign_source_row_corruption(bytes: &mut Vec<u8>) {
    let manifest_offset = usize::try_from(u64::from_le_bytes(
        bytes[16..24].try_into().expect("manifest offset"),
    ))
    .expect("offset usize");
    let manifest_length = usize::try_from(u64::from_le_bytes(
        bytes[24..32].try_into().expect("manifest length"),
    ))
    .expect("length usize");
    let mut manifest: Value =
        serde_json::from_slice(&bytes[manifest_offset..manifest_offset + manifest_length])
            .expect("manifest JSON");
    let section = manifest["sections"]
        .as_array_mut()
        .expect("sections")
        .iter_mut()
        .find(|section| section["name"] == "normalized_catalog.v1")
        .expect("normalized section");
    let offset =
        usize::try_from(section["offset"].as_u64().expect("offset")).expect("offset usize");
    let length =
        usize::try_from(section["length"].as_u64().expect("length")).expect("length usize");
    let relative = bytes[offset..offset + length]
        .windows(7)
        .position(|window| window == b"\"row\":0")
        .expect("source row zero");
    bytes[offset + relative + 6] = b'9';
    section["checksum"] =
        serde_json::to_value(Sha256::digest(&bytes[offset..offset + length]).to_vec())
            .expect("section checksum");
    let encoded = serde_json::to_vec(&manifest).expect("manifest encode");
    bytes.truncate(manifest_offset);
    bytes.extend_from_slice(&encoded);
    bytes[24..32].copy_from_slice(&(encoded.len() as u64).to_le_bytes());
    bytes[32..64].copy_from_slice(&Sha256::digest(&encoded));
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
