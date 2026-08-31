use std::{fs, path::Path, path::PathBuf, sync::Mutex};

use qtrace_provider::{
    BudgetDimension, EventKind, OperationAbort, RegisterSlot, WorkDelta, WorkGuard,
};
use qtrace_store::{
    AuthorizedPath, BuildOptions, IndexBuilder, OpenPolicy, SessionLoader, TraceStore,
    TraceStoreView,
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

struct ResidentLimit {
    limit: u64,
    maximum: Mutex<u64>,
}

impl WorkGuard for ResidentLimit {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        let mut maximum = self.maximum.lock().expect("resident maximum");
        *maximum = (*maximum).max(delta.resident_bytes);
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
fn reader_declares_a_stable_peak_before_normalized_section_allocation() {
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
    TraceStore::open_or_build(root.path(), source, &options, &AllowAll).expect("initial cache");
    let cache = only_cache(root.path());
    let original = fs::read(&cache).expect("cache bytes");

    let capture = ResidentLimit {
        limit: u64::MAX,
        maximum: Mutex::new(0),
    };
    TraceStore::open_or_build(root.path(), source, &options, &capture).expect("capture peak");
    let peak = *capture.maximum.lock().expect("resident maximum");
    assert!(peak > 0);

    let error = TraceStore::open_or_build(
        root.path(),
        source,
        &options,
        &ResidentLimit {
            limit: peak - 1,
            maximum: Mutex::new(0),
        },
    )
    .expect_err("one byte below declared reader peak");
    assert_eq!(error.code(), "control.budget_exceeded");
    assert_eq!(fs::read(&cache).expect("cache retained"), original);

    TraceStore::open_or_build(
        root.path(),
        source,
        &options,
        &ResidentLimit {
            limit: peak,
            maximum: Mutex::new(0),
        },
    )
    .expect("exact reader peak succeeds");
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
fn public_index_view_matches_naive_rows_and_is_owned_mapped_equivalent() {
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
    let owned = IndexBuilder::build(source, &options, &AllowAll).expect("owned store");
    let root = private_root();
    let mapped =
        TraceStore::open_or_build(root.path(), source, &options, &AllowAll).expect("mapped store");
    let owned_view: &dyn TraceStoreView = &owned;
    let mapped_view: &dyn TraceStoreView = &mapped;

    assert_eq!(owned_view.event_count(), mapped_view.event_count());
    assert_eq!(owned_view.capabilities(), mapped_view.capabilities());
    assert_eq!(owned_view.completeness(), mapped_view.completeness());
    for row in 0..=owned_view.event_count() {
        assert_eq!(
            owned_view.event_key(row).unwrap(),
            mapped_view.event_key(row).unwrap()
        );
        assert_eq!(
            owned_view.event_kind(row).unwrap(),
            mapped_view.event_kind(row).unwrap()
        );
        assert_eq!(
            owned_view.provenance(row).unwrap(),
            mapped_view.provenance(row).unwrap()
        );
        assert_eq!(owned_view.instruction(row), mapped_view.instruction(row));
        assert_eq!(owned_view.memory(row), mapped_view.memory(row));
        assert_eq!(owned_view.semantic(row), mapped_view.semantic(row));
        assert_eq!(
            owned_view.register_observations(row),
            mapped_view.register_observations(row)
        );
        if let Some(key) = owned_view.event_key(row).unwrap() {
            assert_eq!(owned_view.row_for_source_key(&key), Some(row));
            assert_eq!(mapped_view.row_for_source_key(&key), Some(row));
            assert_eq!(owned_view.source_key_for_row(row).unwrap(), Some(key));
        }
    }

    let keys = (0..owned_view.event_count())
        .map(|row| owned_view.event_key(row).unwrap().unwrap())
        .collect::<Vec<_>>();
    let timeline = keys[0].timeline.0;
    let expected_timeline = keys
        .iter()
        .enumerate()
        .filter_map(|(row, key)| (key.timeline.0 == timeline).then_some(row))
        .collect::<Vec<_>>();
    assert_eq!(
        owned_view.rows_for_timeline(timeline).unwrap(),
        expected_timeline
    );
    assert_eq!(
        owned_view.rows_for_timeline(timeline).unwrap(),
        mapped_view.rows_for_timeline(timeline).unwrap()
    );
    let tids = keys.iter().filter_map(|key| key.tid).collect::<Vec<_>>();
    let expected_tids = keys
        .iter()
        .enumerate()
        .filter_map(|(row, key)| key.tid.filter(|tid| tids.contains(tid)).map(|_| row))
        .collect::<Vec<_>>();
    assert_eq!(owned_view.rows_for_tids(&tids).unwrap(), expected_tids);
    assert_eq!(owned_view.rows_for_tids(&[]).unwrap(), Vec::<usize>::new());
    assert_eq!(
        owned_view.rows_for_sequence_range(0, u64::MAX).unwrap(),
        mapped_view.rows_for_sequence_range(0, u64::MAX).unwrap()
    );

    for kind in keys
        .iter()
        .enumerate()
        .map(|(row, _)| owned_view.event_kind(row).unwrap().unwrap())
    {
        let expected = (0..owned_view.event_count())
            .filter(|row| owned_view.event_kind(*row).unwrap() == Some(kind))
            .collect::<Vec<_>>();
        assert_eq!(owned_view.rows_of_kinds(&[kind]).unwrap(), expected);
        assert_eq!(
            owned_view.rows_of_kinds(&[kind]).unwrap(),
            mapped_view.rows_of_kinds(&[kind]).unwrap()
        );
    }
    for row in 0..owned_view.event_count() {
        if let Some(instruction) = owned_view.instruction(row) {
            if let Some(module) = instruction.module {
                let expected = (0..owned_view.event_count())
                    .filter(|candidate| {
                        owned_view
                            .instruction(*candidate)
                            .is_some_and(|value| value.module == Some(module))
                    })
                    .collect::<Vec<_>>();
                assert_eq!(owned_view.rows_for_modules(&[module]).unwrap(), expected);
                let end = instruction.relative_pc.checked_add(1).unwrap();
                assert!(
                    owned_view
                        .rows_for_module_pc_range(module, instruction.relative_pc, end)
                        .unwrap()
                        .contains(&row)
                );
                assert_eq!(owned_view.module(module), mapped_view.module(module));
            }
            if let Some(definition) = instruction.definition {
                assert!(
                    owned_view
                        .rows_for_definitions(&[definition])
                        .unwrap()
                        .contains(&row)
                );
                assert_eq!(
                    owned_view.definition(definition),
                    mapped_view.definition(definition)
                );
            }
        }
    }
    for query in [
        owned_view.rows_observing_register(RegisterSlot::X0),
        owned_view.checkpoint_rows(),
        owned_view.call_rows(),
        owned_view.return_rows(),
        owned_view.rows_for_semantic_categories(&[b"does-not-exist"]),
        owned_view.rows_for_semantic_names(&[b"does-not-exist"]),
        owned_view.memory_overlaps(0x2002, 0x2004),
    ] {
        let rows = query.expect("owned index query");
        assert!(rows.windows(2).all(|pair| pair[0] < pair[1]));
    }
    assert!(owned_view.memory_overlaps(9, 4).is_err());
    assert_eq!(
        owned_view.memory_overlaps(4, 4).unwrap(),
        Vec::<usize>::new()
    );
}

#[test]
fn schema_two_cache_has_only_the_exact_binary_section_contract() {
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
    let root = private_root();
    TraceStore::open_or_build(root.path(), source, &BuildOptions::default(), &AllowAll)
        .expect("schema two cache");
    let bytes = fs::read(only_cache(root.path())).expect("cache bytes");
    let manifest_offset = usize::try_from(u64::from_le_bytes(
        bytes[16..24].try_into().expect("manifest offset"),
    ))
    .expect("manifest offset usize");
    let manifest: Value = serde_json::from_slice(&bytes[manifest_offset..]).expect("manifest JSON");
    let names = manifest["sections"]
        .as_array()
        .expect("sections")
        .iter()
        .map(|section| section["name"].as_str().expect("section name"))
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        [
            "event_kinds.v1",
            "event_keys.v1",
            "capabilities.v2",
            "event_meta.v2",
            "payload_spans.v2",
            "payload_arena.v2",
            "string_spans.v2",
            "string_arena.v2",
            "blob_spans.v2",
            "blob_arena.v2",
            "modules.v2",
            "definitions.v2",
            "instructions.v2",
            "memories.v2",
            "semantics.v2",
            "completeness.v2",
            "register_observations.v2",
            "index_meta.v2",
            "timeline_postings.v2",
            "tid_postings.v2",
            "kind_postings.v2",
            "module_postings.v2",
            "definition_postings.v2",
            "register_postings.v2",
            "semantic_category_postings.v2",
            "semantic_name_postings.v2",
            "call_postings.v2",
            "return_postings.v2",
            "checkpoint_postings.v2",
            "sequence_index.v2",
            "module_pc_index.v2",
            "memory_intervals.v2",
            "memory_block_max.v2",
            "source_rows.v2",
        ]
    );
    assert!(names.iter().all(|name| !name.contains("catalog")));
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

#[test]
fn a_resigned_capability_without_payload_evidence_is_rebuilt() {
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
    assert!(!first.capabilities().full_register_checkpoint);
    let cache = only_cache(root.path());
    let mut bytes = fs::read(&cache).expect("cache bytes");
    resign_binary_section_mutation(&mut bytes, "capabilities.v2", |capabilities| {
        assert_eq!(capabilities[2], 0);
        capabilities[2] = 1;
    });
    fs::write(&cache, &bytes).expect("resigned cache");

    let rebuilt = TraceStore::open_or_build(root.path(), source, &options, &AllowAll)
        .expect("unsupported capability is rebuilt");
    assert!(!rebuilt.capabilities().full_register_checkpoint);

    let mut bytes = fs::read(&cache).expect("rebuilt cache bytes");
    resign_binary_section_mutation(&mut bytes, "capabilities.v2", |capabilities| {
        assert_eq!(capabilities[1], 1);
        capabilities[1] = 0;
    });
    fs::write(&cache, &bytes).expect("resigned downgraded cache");
    let rebuilt = TraceStore::open_or_build(root.path(), source, &options, &AllowAll)
        .expect("wrongly downgraded capability is rebuilt");
    assert!(rebuilt.capabilities().per_thread_ordering);
}

#[test]
fn every_resigned_derived_fact_corruption_is_rebuilt_from_closed_payloads() {
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
    let cases = [
        "wrong instruction owner kind",
        "duplicate child and missing child",
        "module source row out of bounds",
        "definition source row out of bounds",
        "register observation splicing",
        "illegal completeness domain",
        "typed column and index synchronized tamper",
    ];
    for case in cases {
        let root = private_root();
        TraceStore::open_or_build(root.path(), source, &BuildOptions::default(), &AllowAll)
            .expect("initial cache");
        let cache = only_cache(root.path());
        let original = fs::read(&cache).expect("original cache");
        let mut corrupted = original.clone();
        match case {
            "wrong instruction owner kind" => {
                resign_binary_section_mutation(&mut corrupted, "instructions.v2", |rows| {
                    rows[0..8].copy_from_slice(&0_u64.to_le_bytes())
                })
            }
            "duplicate child and missing child" => {
                resign_binary_section_mutation(&mut corrupted, "register_observations.v2", |rows| {
                    assert!(rows.len() >= 48);
                    let first = rows[0..24].to_vec();
                    rows[24..48].copy_from_slice(&first);
                })
            }
            "module source row out of bounds" => {
                resign_binary_section_mutation(&mut corrupted, "modules.v2", |rows| {
                    rows[0..8].copy_from_slice(&u64::MAX.to_le_bytes())
                })
            }
            "definition source row out of bounds" => {
                resign_binary_section_mutation(&mut corrupted, "definitions.v2", |rows| {
                    rows[0..8].copy_from_slice(&u64::MAX.to_le_bytes())
                })
            }
            "register observation splicing" => {
                resign_binary_section_mutation(&mut corrupted, "register_observations.v2", |rows| {
                    rows[0..8].copy_from_slice(&0_u64.to_le_bytes())
                })
            }
            "illegal completeness domain" => {
                resign_binary_section_mutation(&mut corrupted, "completeness.v2", |rows| {
                    rows[0] = 0xff
                })
            }
            "typed column and index synchronized tamper" => {
                let mut changed_row = 0_u64;
                let mut changed_pc = 0_u64;
                resign_binary_section_mutation(&mut corrupted, "instructions.v2", |rows| {
                    changed_row = u64::from_le_bytes(rows[0..8].try_into().expect("owner row"));
                    let old_pc = u64::from_le_bytes(rows[16..24].try_into().expect("relative PC"));
                    changed_pc = old_pc.checked_add(1).expect("fixture PC increment");
                    rows[16..24].copy_from_slice(&changed_pc.to_le_bytes());
                });
                resign_binary_section_mutation(&mut corrupted, "module_pc_index.v2", |rows| {
                    let record = rows
                        .chunks_exact_mut(24)
                        .find(|record| {
                            u64::from_le_bytes(record[16..24].try_into().expect("indexed row"))
                                == changed_row
                        })
                        .expect("instruction module-PC entry");
                    record[8..16].copy_from_slice(&changed_pc.to_le_bytes());
                });
            }
            _ => unreachable!(),
        }
        fs::write(&cache, corrupted).expect("corrupted cache");
        TraceStore::open_or_build(root.path(), source, &BuildOptions::default(), &AllowAll)
            .unwrap_or_else(|error| panic!("{case} should rebuild: {error}"));
        assert_eq!(fs::read(&cache).expect("rebuilt bytes"), original, "{case}");
    }
}

#[test]
fn schema_two_rejects_missing_extra_reordered_and_wrong_contract_sections() {
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
    for case in ["missing", "extra", "reordered", "wrong contract"] {
        let root = private_root();
        TraceStore::open_or_build(root.path(), source, &BuildOptions::default(), &AllowAll)
            .expect("initial cache");
        let cache = only_cache(root.path());
        let original = fs::read(&cache).expect("original cache");
        let mut corrupted = original.clone();
        resign_manifest_mutation(&mut corrupted, |manifest| {
            let sections = manifest["sections"].as_array_mut().expect("sections");
            match case {
                "missing" => {
                    sections.remove(2);
                }
                "extra" => {
                    sections[2]["name"] = "unexpected.v2".into();
                }
                "reordered" => sections.swap(2, 3),
                "wrong contract" => sections[2]["element_size"] = 8.into(),
                _ => unreachable!(),
            }
        });
        fs::write(&cache, corrupted).expect("corrupt manifest");
        TraceStore::open_or_build(root.path(), source, &BuildOptions::default(), &AllowAll)
            .unwrap_or_else(|error| panic!("{case} should rebuild: {error}"));
        assert_eq!(fs::read(&cache).expect("rebuilt bytes"), original, "{case}");
    }
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
    resign_binary_section_mutation(bytes, "source_rows.v2", |source_rows| {
        source_rows[0..8].copy_from_slice(&9_u64.to_le_bytes());
    });
}

fn resign_binary_section_mutation(
    bytes: &mut Vec<u8>,
    section_name: &str,
    mutate: impl FnOnce(&mut [u8]),
) {
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
        .find(|section| section["name"] == section_name)
        .expect("binary section");
    let offset =
        usize::try_from(section["offset"].as_u64().expect("offset")).expect("offset usize");
    let length =
        usize::try_from(section["length"].as_u64().expect("length")).expect("length usize");
    mutate(&mut bytes[offset..offset + length]);
    section["checksum"] =
        serde_json::to_value(Sha256::digest(&bytes[offset..offset + length]).to_vec())
            .expect("section checksum");
    let encoded = serde_json::to_vec(&manifest).expect("manifest encode");
    bytes.truncate(manifest_offset);
    bytes.extend_from_slice(&encoded);
    bytes[24..32].copy_from_slice(&(encoded.len() as u64).to_le_bytes());
    bytes[32..64].copy_from_slice(&Sha256::digest(&encoded));
}

fn resign_manifest_mutation(bytes: &mut Vec<u8>, mutate: impl FnOnce(&mut Value)) {
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
    mutate(&mut manifest);
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
