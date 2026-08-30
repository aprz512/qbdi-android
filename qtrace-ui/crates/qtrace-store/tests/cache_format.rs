use std::{
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};

use qtrace_provider::{
    ArtifactDigest, EventKey, EventKind, OperationAbort, TimelineId, WorkDelta, WorkGuard,
};
use qtrace_store::{
    CacheIdentity, CacheIdentityField, CacheOpen, CacheReader, CacheWriter, OwnedStoreView,
    RebuildReason, StoreView,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

struct AllowAll;

fn private_root() -> TempDir {
    let root = TempDir::new().expect("root");
    fs::set_permissions(
        root.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .expect("private root");
    root
}

type ByteMutation = Box<dyn Fn(&mut Vec<u8>)>;
type JsonMutation = Box<dyn Fn(&mut Value)>;

impl WorkGuard for AllowAll {
    fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
        Ok(())
    }
}

fn identity() -> CacheIdentity {
    CacheIdentity {
        analyzer_version: "0.1.0-test".to_owned(),
        artifact_digest: [0x5a; 32],
        build_option_digest: [0xa5; 32],
        cache_schema: 1,
        endian: "little".to_owned(),
        layout_version: 1,
        source_features: 0x1020_4080,
        source_format: "qtrb".to_owned(),
        source_major: 1,
        source_minor: 2,
    }
}

fn sample_owned_store() -> OwnedStoreView {
    let digest = ArtifactDigest::new([0x5a; 32]);
    OwnedStoreView::new(
        vec![
            EventKey::new(digest, TimelineId(3), 7, 64, Some(11), Some(42)),
            EventKey::new(digest, TimelineId(3), 8, 96, None, None),
        ],
        vec![EventKind::Instruction, EventKind::SemanticCall],
    )
    .expect("sample store")
}

fn publish(root: &Path) -> std::path::PathBuf {
    CacheWriter::new(identity(), sample_owned_store())
        .expect("writer")
        .publish(root, &AllowAll)
        .expect("publish");
    root.join("qtrace-ui")
        .join(identity().cache_key())
        .join("index.qtc")
}

fn expect_rebuild(root: &Path) -> RebuildReason {
    match CacheReader::open(root, &identity(), &AllowAll).expect("reader result") {
        CacheOpen::Rebuild(reason) => reason,
        CacheOpen::Missing => panic!("corrupt cache was reported missing"),
        CacheOpen::Ready(_) => panic!("corrupt cache was accepted"),
    }
}

fn mutate_file(root: &Path, mutation: impl FnOnce(&mut Vec<u8>)) {
    let path = publish(root);
    let mut bytes = fs::read(&path).expect("cache bytes");
    mutation(&mut bytes);
    fs::write(path, bytes).expect("mutated cache bytes");
}

fn manifest_range(bytes: &[u8]) -> (usize, usize) {
    let offset = u64::from_le_bytes(bytes[16..24].try_into().expect("offset"));
    let length = u64::from_le_bytes(bytes[24..32].try_into().expect("length"));
    (
        usize::try_from(offset).expect("manifest offset"),
        usize::try_from(length).expect("manifest length"),
    )
}

fn mutate_manifest(bytes: &mut Vec<u8>, mutation: impl FnOnce(&mut Value)) {
    let (offset, length) = manifest_range(bytes);
    let mut manifest: Value =
        serde_json::from_slice(&bytes[offset..offset + length]).expect("json");
    mutation(&mut manifest);
    let encoded = serde_json::to_vec(&manifest).expect("encoded json");
    bytes.truncate(offset);
    bytes.extend_from_slice(&encoded);
    bytes[24..32].copy_from_slice(&(encoded.len() as u64).to_le_bytes());
    bytes[32..64].copy_from_slice(&Sha256::digest(&encoded));
}

#[test]
fn header_is_exactly_sixty_four_bytes_and_rejects_every_header_corruption() {
    let cases: Vec<ByteMutation> = vec![
        Box::new(|bytes| bytes[0] ^= 1),
        Box::new(|bytes| bytes[8..12].copy_from_slice(&2_u32.to_le_bytes())),
        Box::new(|bytes| bytes[12..14].copy_from_slice(&63_u16.to_le_bytes())),
        Box::new(|bytes| bytes[14] = 1),
        Box::new(|bytes| bytes[15] = 1),
        Box::new(|bytes| bytes[16..24].copy_from_slice(&u64::MAX.to_le_bytes())),
        Box::new(|bytes| bytes[24..32].copy_from_slice(&u64::MAX.to_le_bytes())),
        Box::new(|bytes| bytes[32] ^= 1),
    ];

    for (index, mutation) in cases.into_iter().enumerate() {
        let root = private_root();
        mutate_file(root.path(), mutation);
        let reason = expect_rebuild(root.path());
        assert!(
            matches!(
                reason,
                RebuildReason::Header(_) | RebuildReason::Manifest(_)
            ),
            "case {index} returned {reason:?}"
        );
    }
}

fn mutate_section_payload(bytes: &mut Vec<u8>, name: &str, mutation: impl FnOnce(&mut [u8])) {
    let (manifest_offset, manifest_length) = manifest_range(bytes);
    let mut manifest: Value =
        serde_json::from_slice(&bytes[manifest_offset..manifest_offset + manifest_length])
            .expect("manifest");
    let section = manifest["sections"]
        .as_array_mut()
        .expect("sections")
        .iter_mut()
        .find(|section| section["name"] == name)
        .expect("named section");
    let offset =
        usize::try_from(section["offset"].as_u64().expect("offset")).expect("offset usize");
    let length =
        usize::try_from(section["length"].as_u64().expect("length")).expect("length usize");
    mutation(&mut bytes[offset..offset + length]);
    section["checksum"] =
        serde_json::to_value(Sha256::digest(&bytes[offset..offset + length]).to_vec())
            .expect("checksum value");
    let encoded = serde_json::to_vec(&manifest).expect("encoded manifest");
    bytes.truncate(manifest_offset);
    bytes.extend_from_slice(&encoded);
    bytes[24..32].copy_from_slice(&(encoded.len() as u64).to_le_bytes());
    bytes[32..64].copy_from_slice(&Sha256::digest(&encoded));
}

#[test]
fn known_section_payloads_are_validated_before_returning_a_view() {
    let cases = [
        ("event_kinds.v1", 0_usize, 0xff_u8),
        ("event_keys.v1", 69_usize, 1_u8),
        ("event_keys.v1", 0_usize, 0_u8),
        ("event_keys.v1", 80_usize + 56, 1_u8),
        ("event_keys.v1", 80_usize + 64, 1_u8),
    ];
    for (name, byte, value) in cases {
        let root = private_root();
        mutate_file(root.path(), |bytes| {
            mutate_section_payload(bytes, name, |section| {
                if name == "event_keys.v1" && byte == 0 {
                    section[byte] ^= 1;
                } else {
                    section[byte] = value;
                }
            });
        });
        assert_eq!(
            expect_rebuild(root.path()),
            RebuildReason::Section("payload")
        );
    }
}

#[test]
fn every_cache_identity_field_mismatch_is_a_typed_rebuild() {
    let cases: Vec<(CacheIdentityField, JsonMutation)> = vec![
        (
            CacheIdentityField::AnalyzerVersion,
            Box::new(|id| id["analyzer_version"] = "other".into()),
        ),
        (
            CacheIdentityField::ArtifactDigest,
            Box::new(|id| id["artifact_digest"][0] = 9.into()),
        ),
        (
            CacheIdentityField::BuildOptionDigest,
            Box::new(|id| id["build_option_digest"][0] = 9.into()),
        ),
        (
            CacheIdentityField::CacheSchema,
            Box::new(|id| id["cache_schema"] = 9.into()),
        ),
        (
            CacheIdentityField::Endian,
            Box::new(|id| id["endian"] = "big".into()),
        ),
        (
            CacheIdentityField::LayoutVersion,
            Box::new(|id| id["layout_version"] = 9.into()),
        ),
        (
            CacheIdentityField::SourceFeatures,
            Box::new(|id| id["source_features"] = 9.into()),
        ),
        (
            CacheIdentityField::SourceFormat,
            Box::new(|id| id["source_format"] = "flight".into()),
        ),
        (
            CacheIdentityField::SourceMajor,
            Box::new(|id| id["source_major"] = 9.into()),
        ),
        (
            CacheIdentityField::SourceMinor,
            Box::new(|id| id["source_minor"] = 9.into()),
        ),
    ];

    for (field, mutation) in cases {
        let root = private_root();
        mutate_file(root.path(), |bytes| {
            mutate_manifest(bytes, |manifest| mutation(&mut manifest["identity"]));
        });
        assert_eq!(
            expect_rebuild(root.path()),
            RebuildReason::IdentityMismatch(field)
        );
    }
}

#[test]
fn manifest_and_section_contract_corruption_never_returns_a_view() {
    let cases: Vec<JsonMutation> = vec![
        Box::new(|manifest| {
            manifest["sections"][1]["name"] = manifest["sections"][0]["name"].clone()
        }),
        Box::new(|manifest| {
            manifest["sections"]
                .as_array_mut()
                .expect("sections")
                .reverse()
        }),
        Box::new(|manifest| manifest["sections"][0]["offset"] = 0.into()),
        Box::new(|manifest| manifest["sections"][0]["offset"] = u64::MAX.into()),
        Box::new(|manifest| manifest["sections"][0]["length"] = u64::MAX.into()),
        Box::new(|manifest| {
            manifest["sections"][1]["offset"] = manifest["sections"][0]["offset"].clone()
        }),
        Box::new(|manifest| manifest["sections"][0]["alignment"] = 0.into()),
        Box::new(|manifest| manifest["sections"][0]["alignment"] = 3.into()),
        Box::new(|manifest| manifest["sections"][0]["offset"] = 65.into()),
        Box::new(|manifest| manifest["sections"][0]["element_size"] = 0.into()),
        Box::new(|manifest| manifest["sections"][0]["element_size"] = 7.into()),
        Box::new(|manifest| manifest["sections"][0]["checksum"][0] = 9.into()),
    ];

    for (index, mutation) in cases.into_iter().enumerate() {
        let root = private_root();
        mutate_file(root.path(), |bytes| mutate_manifest(bytes, mutation));
        assert!(
            matches!(expect_rebuild(root.path()), RebuildReason::Section(_)),
            "section mutation {index} was not typed as section corruption"
        );
    }

    let root = private_root();
    mutate_file(root.path(), |bytes| bytes[64] ^= 1);
    assert!(matches!(
        expect_rebuild(root.path()),
        RebuildReason::Section(_)
    ));
}

#[test]
fn known_sections_require_their_exact_wire_alignment() {
    for (name, alignment) in [("event_keys.v1", 1_u64), ("event_kinds.v1", 64_u64)] {
        let root = private_root();
        mutate_file(root.path(), |bytes| {
            mutate_manifest(bytes, |manifest| {
                let section = manifest["sections"]
                    .as_array_mut()
                    .expect("sections")
                    .iter_mut()
                    .find(|section| section["name"] == name)
                    .expect("known section");
                section["alignment"] = alignment.into();
            });
        });
        assert_eq!(
            expect_rebuild(root.path()),
            RebuildReason::Section("known alignment"),
            "reader accepted re-signed {name} alignment {alignment}"
        );
    }
}

#[test]
fn alignment_padding_is_explicit_zero_and_is_validated() {
    let root = private_root();
    let path = publish(root.path());
    let mut bytes = fs::read(&path).expect("cache bytes");
    let (manifest_offset, manifest_length) = manifest_range(&bytes);
    let manifest: Value =
        serde_json::from_slice(&bytes[manifest_offset..manifest_offset + manifest_length])
            .expect("manifest");
    let sections = manifest["sections"].as_array().expect("sections");
    let first_end = sections[0]["offset"].as_u64().expect("offset")
        + sections[0]["length"].as_u64().expect("length");
    let second_offset = sections[1]["offset"].as_u64().expect("offset");
    assert!(
        second_offset > first_end,
        "sample wire must exercise alignment padding"
    );
    let padding = usize::try_from(first_end).expect("padding offset");
    assert_eq!(bytes[padding], 0);
    bytes[padding] = 1;
    fs::write(path, bytes).expect("mutated padding");
    assert_eq!(
        expect_rebuild(root.path()),
        RebuildReason::Section("padding")
    );
}

#[test]
fn malformed_and_oversized_manifest_lengths_do_not_drive_large_allocation() {
    let root = private_root();
    mutate_file(root.path(), |bytes| {
        let (offset, _) = manifest_range(bytes);
        bytes[offset] = b'!';
        let digest = Sha256::digest(&bytes[offset..]);
        bytes[32..64].copy_from_slice(&digest);
    });
    assert!(matches!(
        expect_rebuild(root.path()),
        RebuildReason::Manifest(_)
    ));

    let root = private_root();
    mutate_file(root.path(), |bytes| {
        bytes[24..32].copy_from_slice(&(2_u64 * 1024 * 1024).to_le_bytes());
    });
    assert!(matches!(
        expect_rebuild(root.path()),
        RebuildReason::Manifest(_)
    ));
}

#[test]
fn mapped_and_owned_views_answer_the_same_values() {
    let root = private_root();
    let owned = sample_owned_store();
    CacheWriter::new(identity(), owned.clone())
        .expect("writer")
        .publish(root.path(), &AllowAll)
        .expect("publish");
    let mapped = match CacheReader::open(root.path(), &identity(), &AllowAll).expect("open") {
        CacheOpen::Ready(view) => view,
        other => panic!("expected ready cache, got {other:?}"),
    };

    assert_eq!(owned.event_count(), mapped.event_count());
    for row in 0..owned.event_count() {
        assert_eq!(
            owned.event_key(row).expect("owned key"),
            mapped.event_key(row).expect("mapped key")
        );
        assert_eq!(
            owned.event_kind(row).expect("owned kind"),
            mapped.event_kind(row).expect("mapped kind")
        );
    }
    assert!(mapped.event_key(owned.event_count()).is_err());
}

#[test]
fn complete_files_are_byte_deterministic_for_the_same_identity() {
    let first = TempDir::new().expect("first");
    let second = TempDir::new().expect("second");
    fs::set_permissions(
        first.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .expect("private first root");
    fs::set_permissions(
        second.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .expect("private second root");
    let first_path = publish(first.path());
    let second_path = publish(second.path());
    assert_eq!(
        fs::read(first_path).expect("first bytes"),
        fs::read(second_path).expect("second bytes")
    );
}

struct CancelFirstRead;

impl WorkGuard for CancelFirstRead {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        if delta.input_bytes != 0 {
            Err(OperationAbort::Cancelled)
        } else {
            Ok(())
        }
    }
}

#[test]
fn reader_control_errors_propagate_instead_of_becoming_rebuild() {
    let root = private_root();
    publish(root.path());
    let error = CacheReader::open(root.path(), &identity(), &CancelFirstRead)
        .expect_err("reader cancellation");
    assert_eq!(error.code(), "job.cancelled");
}

struct MutateDuringRead {
    path: PathBuf,
    reads: Mutex<usize>,
}

impl WorkGuard for MutateDuringRead {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        if delta.input_bytes != 0 {
            let mut reads = self.reads.lock().expect("read count");
            *reads += 1;
            if *reads == 2 {
                let mut bytes = fs::read(&self.path).expect("cache bytes");
                bytes[64] ^= 1;
                fs::write(&self.path, bytes).expect("mutated cache");
            }
        }
        Ok(())
    }
}

#[test]
fn cache_identity_change_during_validation_is_not_downgraded_to_rebuild() {
    let root = private_root();
    let path = publish(root.path());
    let error = CacheReader::open(
        root.path(),
        &identity(),
        &MutateDuringRead {
            path,
            reads: Mutex::new(0),
        },
    )
    .expect_err("identity race must be a control-path error");
    assert_eq!(error.code(), "cache.identity_changed");
}
