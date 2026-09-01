use std::{
    fs,
    path::Path,
    path::PathBuf,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use qtrace_provider::{
    BudgetDimension, EventKind, OperationAbort, RegisterSlot, WorkDelta, WorkGuard,
};
use qtrace_store::{
    AuthorizedPath, BuildOptions, IndexBuilder, IndexError, NormalizedBulkView,
    NormalizedPostingQuery, NormalizedSourceFormat, OpenPolicy, SemanticDictionaryFamily,
    SessionLoader, TraceStore, TraceStoreView,
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
    consumed: Mutex<u64>,
}

struct AllocationProbe {
    watched: u64,
    watched_count: Mutex<usize>,
    resident_total: Mutex<u64>,
}

struct RejectAllocation {
    watched: u64,
    rejected_count: Mutex<usize>,
}

struct CancelWithoutAllocation {
    allocation_calls: Mutex<usize>,
}

impl WorkGuard for CancelWithoutAllocation {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        if delta.resident_bytes != 0 {
            *self.allocation_calls.lock().expect("allocation calls") += 1;
        }
        Err(OperationAbort::Cancelled)
    }
}

struct RecordAllocations {
    allocation_calls: Mutex<usize>,
}

#[derive(Default)]
struct WorkAccounting {
    rows: AtomicU64,
    input_bytes: AtomicU64,
}

impl WorkGuard for WorkAccounting {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        self.rows.fetch_add(delta.rows, Ordering::SeqCst);
        self.input_bytes
            .fetch_add(delta.input_bytes, Ordering::SeqCst);
        Ok(())
    }
}

impl WorkGuard for RecordAllocations {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        if delta.resident_bytes != 0 {
            *self.allocation_calls.lock().expect("allocation calls") += 1;
        }
        Ok(())
    }
}

impl WorkGuard for RejectAllocation {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        if delta.resident_bytes == self.watched {
            *self.rejected_count.lock().expect("rejected count") += 1;
            return Err(OperationAbort::budget_exceeded(
                BudgetDimension::ResidentBytes,
                self.watched.saturating_sub(1),
                self.watched,
            ));
        }
        Ok(())
    }
}

impl WorkGuard for AllocationProbe {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        if delta.resident_bytes == self.watched {
            *self.watched_count.lock().expect("watched count") += 1;
        }
        let mut total = self.resident_total.lock().expect("resident total");
        *total = total
            .checked_add(delta.resident_bytes)
            .expect("test resident total");
        Ok(())
    }
}

impl WorkGuard for ResidentLimit {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        let mut consumed = self.consumed.lock().expect("resident total");
        let next = consumed
            .checked_add(delta.resident_bytes)
            .expect("test resident total overflow");
        if next > self.limit {
            Err(OperationAbort::budget_exceeded(
                BudgetDimension::ResidentBytes,
                self.limit,
                next,
            ))
        } else {
            *consumed = next;
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

fn flight_fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("fixtures/flight")
        .join(name)
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
        .find(|artifact| artifact.local_path().ends_with("main.trace.bin"))
        .expect("QTRB artifact");
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
fn warm_reader_uses_a_stable_cumulative_allocation_budget() {
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
        consumed: Mutex::new(0),
    };
    TraceStore::open_or_build(root.path(), source, &options, &capture).expect("capture budget");
    let budget = *capture.consumed.lock().expect("resident total");
    assert!(budget > 0);

    let below = ResidentLimit {
        limit: budget - 1,
        consumed: Mutex::new(0),
    };
    let error = TraceStore::open_or_build(root.path(), source, &options, &below)
        .expect_err("one byte below cumulative reader budget");
    assert_eq!(error.code(), "control.budget_exceeded");
    assert!(error.to_string().contains("ResidentBytes"));
    assert!(*below.consumed.lock().expect("below total") < budget);
    assert_eq!(fs::read(&cache).expect("cache retained"), original);
    assert_no_transient_cache_entries(root.path());

    let exact = ResidentLimit {
        limit: budget,
        consumed: Mutex::new(0),
    };
    TraceStore::open_or_build(root.path(), source, &options, &exact)
        .expect("exact cumulative reader budget succeeds");
    assert_eq!(*exact.consumed.lock().expect("exact total"), budget);
}

#[test]
fn warm_open_allocates_each_normalized_section_only_once() {
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
        .expect("initial cache");
    let bytes = fs::read(only_cache(root.path())).expect("cache bytes");
    let manifest = cache_manifest(&bytes);
    let payload_length = manifest["sections"]
        .as_array()
        .expect("sections")
        .iter()
        .find(|section| section["name"] == "payload_arena.v2")
        .and_then(|section| section["length"].as_u64())
        .expect("payload arena length");
    assert!(payload_length > 0);
    let probe = AllocationProbe {
        watched: payload_length,
        watched_count: Mutex::new(0),
        resident_total: Mutex::new(0),
    };
    TraceStore::open_or_build(root.path(), source, &BuildOptions::default(), &probe)
        .expect("warm open");
    assert_eq!(
        *probe.watched_count.lock().expect("watched count"),
        1,
        "validated section backing must transfer into MappedTraceStore"
    );
}

#[test]
fn warm_reader_authorizes_a_large_section_before_allocation_and_preserves_final() {
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
        .expect("initial cache");
    let cache = only_cache(root.path());
    let original = fs::read(&cache).expect("cache bytes");
    let manifest = cache_manifest(&original);
    let payload_length = manifest["sections"]
        .as_array()
        .expect("sections")
        .iter()
        .find(|section| section["name"] == "payload_arena.v2")
        .and_then(|section| section["length"].as_u64())
        .expect("payload arena length");
    assert!(payload_length > 0);
    let reject = RejectAllocation {
        watched: payload_length,
        rejected_count: Mutex::new(0),
    };
    let error = TraceStore::open_or_build(root.path(), source, &BuildOptions::default(), &reject)
        .expect_err("large section allocation is rejected");
    assert_eq!(error.code(), "control.budget_exceeded");
    assert_eq!(*reject.rejected_count.lock().expect("reject count"), 1);
    assert_eq!(fs::read(&cache).expect("cache retained"), original);
    assert_no_transient_cache_entries(root.path());
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
fn exact_byte_views_are_owned_mapped_equivalent_and_reject_invalid_ids() {
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

    for row in 0..owned_view.event_count() {
        assert_eq!(
            owned_view.payload_bytes(row).expect("owned payload"),
            mapped_view.payload_bytes(row).expect("mapped payload")
        );
        if let Some(definition) = owned_view
            .instruction(row)
            .and_then(|instruction| instruction.definition)
            .and_then(|id| owned_view.definition(id))
        {
            for string_id in [
                definition.mnemonic,
                definition.operands,
                definition.disassembly,
            ] {
                assert_eq!(
                    owned_view.string_bytes(string_id).expect("owned string"),
                    mapped_view.string_bytes(string_id).expect("mapped string")
                );
            }
        }
        if let Some(semantic) = owned_view.semantic(row) {
            assert_eq!(
                owned_view
                    .blob_bytes(semantic.detail_blob)
                    .expect("owned semantic detail"),
                mapped_view
                    .blob_bytes(semantic.detail_blob)
                    .expect("mapped semantic detail")
            );
        }
        if owned_view.memory(row).is_some() {
            assert_eq!(
                owned_view.memory_before_bytes(row).expect("owned before"),
                mapped_view.memory_before_bytes(row).expect("mapped before")
            );
            assert_eq!(
                owned_view.memory_after_bytes(row).expect("owned after"),
                mapped_view.memory_after_bytes(row).expect("mapped after")
            );
        }
    }
    assert_eq!(
        owned_view.string_bytes(u32::MAX).unwrap_err().code(),
        "index.invalid"
    );
    assert_eq!(
        mapped_view.blob_bytes(u32::MAX).unwrap_err().code(),
        "index.invalid"
    );
    assert_eq!(
        owned_view.payload_bytes(usize::MAX).unwrap_err().code(),
        "index.invalid"
    );
    assert_eq!(
        mapped_view
            .memory_before_bytes(usize::MAX)
            .unwrap_err()
            .code(),
        "index.invalid"
    );
}

#[test]
fn normalized_row_views_and_layout_identity_are_zero_copy_owned_mapped_equivalent() {
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
    let owned: &dyn NormalizedBulkView = &owned;
    let mapped: &dyn NormalizedBulkView = &mapped;

    assert_eq!(
        owned.normalized_layout_identity(),
        mapped.normalized_layout_identity()
    );
    assert_eq!(owned.module_rows(), mapped.module_rows());
    assert_eq!(owned.definition_rows(), mapped.definition_rows());
    assert_eq!(owned.instruction_rows(), mapped.instruction_rows());
    assert_eq!(owned.memory_rows(), mapped.memory_rows());
    assert_eq!(owned.semantic_rows(), mapped.semantic_rows());
    assert_eq!(
        owned.register_observation_rows(),
        mapped.register_observation_rows()
    );
    assert_eq!(owned.string_count(), mapped.string_count());
    assert_eq!(owned.blob_count(), mapped.blob_count());
    assert_eq!(
        owned.normalized_content_identity(),
        mapped.normalized_content_identity()
    );
    assert_eq!(
        owned.normalized_source_format(),
        NormalizedSourceFormat::Qtrb
    );
    assert_eq!(
        mapped.normalized_source_format(),
        NormalizedSourceFormat::Qtrb
    );

    assert!(
        owned
            .instruction_rows()
            .windows(2)
            .all(|pair| pair[0].owner_row < pair[1].owner_row)
    );
    assert!(
        owned
            .memory_rows()
            .windows(2)
            .all(|pair| pair[0].owner_row < pair[1].owner_row)
    );
    assert!(
        owned
            .semantic_rows()
            .windows(2)
            .all(|pair| pair[0].owner_row < pair[1].owner_row)
    );
    assert!(
        owned
            .register_observation_rows()
            .windows(2)
            .all(|pair| pair[0].owner_row <= pair[1].owner_row)
    );

    assert_eq!(
        owned.instruction_rows().as_ptr(),
        owned.instruction_rows().as_ptr(),
        "repeated typed views must borrow the same backing allocation"
    );
    for id in 0..owned.string_count() {
        assert_eq!(
            owned.string_bytes(id as u32).expect("owned string"),
            mapped.string_bytes(id as u32).expect("mapped string")
        );
    }
    for id in 0..owned.blob_count() {
        assert_eq!(
            owned.blob_bytes(id as u32).expect("owned blob"),
            mapped.blob_bytes(id as u32).expect("mapped blob")
        );
    }
}

#[test]
fn bounded_postings_reject_oversize_and_cancel_before_row_allocation() {
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
    let store =
        IndexBuilder::build(source, &BuildOptions::default(), &AllowAll).expect("owned store");
    let view: &dyn NormalizedBulkView = &store;
    let tid = view
        .event_key(0)
        .expect("event key")
        .and_then(|key| key.tid)
        .expect("fixture tid");

    let allocations = RecordAllocations {
        allocation_calls: Mutex::new(0),
    };
    let error = view
        .bounded_row_count(NormalizedPostingQuery::Tids(&[tid]), 0, &allocations)
        .expect_err("nonempty posting count exceeds zero row budget");
    assert_eq!(error.code(), "control.resource_exhausted");
    assert_eq!(*allocations.allocation_calls.lock().unwrap(), 0);

    let error = view
        .bounded_rows(NormalizedPostingQuery::Tids(&[tid]), 0, &allocations)
        .expect_err("nonempty posting exceeds zero row budget");
    assert_eq!(error.code(), "control.resource_exhausted");
    assert_eq!(*allocations.allocation_calls.lock().unwrap(), 0);

    let cancelled = CancelWithoutAllocation {
        allocation_calls: Mutex::new(0),
    };
    let error = view
        .bounded_rows(
            NormalizedPostingQuery::Sequence {
                start: 0,
                end_exclusive: u64::MAX,
            },
            usize::MAX,
            &cancelled,
        )
        .expect_err("cancel before posting copy");
    assert_eq!(error.code(), "job.cancelled");
    assert_eq!(*cancelled.allocation_calls.lock().unwrap(), 0);
}

#[test]
fn bounded_semantic_dictionary_queries_charge_each_item_and_its_bytes() {
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
    let store =
        IndexBuilder::build(source, &BuildOptions::default(), &AllowAll).expect("owned store");
    let view: &dyn NormalizedBulkView = &store;
    let dictionary_bytes = (0..view.string_count())
        .map(|id| {
            view.string_bytes(id as u32)
                .expect("dictionary entry")
                .len() as u64
        })
        .sum::<u64>();

    for query in [
        NormalizedPostingQuery::SemanticCategories(&[b"does-not-exist"]),
        NormalizedPostingQuery::SemanticNames(&[b"does-not-exist"]),
    ] {
        let count_guard = WorkAccounting::default();
        assert_eq!(
            view.bounded_row_count(query, usize::MAX, &count_guard)
                .expect("semantic estimate"),
            0
        );
        assert_eq!(
            count_guard.rows.load(Ordering::SeqCst),
            view.string_count() as u64
        );
        assert_eq!(
            count_guard.input_bytes.load(Ordering::SeqCst),
            dictionary_bytes
        );

        let decode_guard = WorkAccounting::default();
        assert!(
            view.bounded_rows(query, usize::MAX, &decode_guard)
                .expect("semantic decode")
                .is_empty()
        );
        assert_eq!(
            decode_guard.rows.load(Ordering::SeqCst),
            view.string_count() as u64
        );
        assert_eq!(
            decode_guard.input_bytes.load(Ordering::SeqCst),
            dictionary_bytes
        );
    }
}

#[test]
fn semantic_dictionary_work_metadata_is_checked_exact_and_owned_mapped_equal() {
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
    let dictionary_bytes = (0..owned.string_count())
        .map(|id| owned.string_bytes(id as u32).unwrap().len() as u64)
        .sum::<u64>();

    for family in [
        SemanticDictionaryFamily::Categories,
        SemanticDictionaryFamily::Names,
    ] {
        let guard = WorkAccounting::default();
        let owned_work = owned
            .semantic_dictionary_work(family, 2, &guard)
            .expect("owned semantic dictionary metadata");
        let mapped_work = mapped
            .semantic_dictionary_work(family, 2, &AllowAll)
            .expect("mapped semantic dictionary metadata");
        assert_eq!(owned_work, mapped_work);
        assert_eq!(owned_work.term_count, 2);
        assert_eq!(owned_work.dictionary_items, owned.string_count() as u64);
        assert_eq!(owned_work.dictionary_bytes, dictionary_bytes);
        assert_eq!(owned_work.lookup_items, 2 * owned.string_count() as u64);
        assert_eq!(owned_work.lookup_bytes, 2 * dictionary_bytes);
        assert_eq!(
            guard.rows.load(Ordering::SeqCst),
            owned.string_count() as u64
        );
        assert_eq!(guard.input_bytes.load(Ordering::SeqCst), 0);
    }

    assert!(
        owned
            .semantic_dictionary_work(SemanticDictionaryFamily::Names, usize::MAX, &AllowAll)
            .is_err()
    );
}

#[test]
fn posting_estimate_reports_only_local_radixes_that_decode_will_execute() {
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

    let tid = TraceStoreView::event_key(&owned, 0)
        .unwrap()
        .and_then(|key| key.tid)
        .expect("fixture tid");
    let single_list = NormalizedPostingQuery::Tids(&[tid]);
    let owned_single = owned
        .bounded_row_estimate(single_list, usize::MAX, &AllowAll)
        .unwrap();
    let mapped_single = mapped
        .bounded_row_estimate(single_list, usize::MAX, &AllowAll)
        .unwrap();
    assert_eq!(owned_single, mapped_single);
    assert!(owned_single.rows >= 2);
    assert_eq!(owned_single.matched_lists, 1);
    assert_eq!(owned_single.local_radix_sorts, 0);
    assert_eq!(owned_single.local_radix_rows, 0);

    let pair = NormalizedPostingQuery::Tids(&[tid, tid]);
    let owned_pair = owned
        .bounded_row_estimate(pair, usize::MAX, &AllowAll)
        .unwrap();
    let mapped_pair = mapped
        .bounded_row_estimate(pair, usize::MAX, &AllowAll)
        .unwrap();
    assert_eq!(owned_pair, mapped_pair);
    assert!(owned_pair.rows >= 2);
    assert_eq!(owned_pair.local_radix_sorts, 1);
    assert_eq!(owned_pair.local_radix_rows, owned_pair.rows);
    let decode_guard = WorkAccounting::default();
    let decoded = owned
        .bounded_rows(pair, usize::MAX, &decode_guard)
        .expect("duplicate-list decode");
    assert_eq!(decoded.len(), owned_single.rows);
    let encoded_rows = 2 * owned_single.rows as u64;
    let expected_decode_work = 2
        + 2
        + 2
        + encoded_rows
        + std::mem::size_of::<usize>() as u64 * (2 * encoded_rows + 256)
        + encoded_rows
        - 1;
    assert_eq!(
        decode_guard.rows.load(Ordering::SeqCst),
        expected_decode_work
    );

    let empty = owned
        .bounded_row_estimate(
            NormalizedPostingQuery::Sequence {
                start: u64::MAX,
                end_exclusive: u64::MAX,
            },
            usize::MAX,
            &AllowAll,
        )
        .unwrap();
    assert_eq!(empty.rows, 0);
    assert_eq!(empty.local_radix_sorts, 0);
    assert_eq!(empty.local_radix_rows, 0);
}

#[test]
fn index_error_exposes_its_typed_abort_read_only() {
    let abort = OperationAbort::budget_exceeded(BudgetDimension::Nodes, 7, 8);
    let error = IndexError::from(abort.clone());
    assert_eq!(error.operation_abort(), Some(&abort));
}

#[test]
fn bounded_pair_postings_are_ascending_unique_for_owned_and_mapped_stores() {
    let session = SessionLoader::open_report(
        AuthorizedPath::new(fixture()),
        OpenPolicy::default(),
        &AllowAll,
    )
    .expect("existing normalized trace fixture");
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

    let query = NormalizedPostingQuery::Sequence {
        start: 0,
        end_exclusive: u64::MAX,
    };
    let owned_rows = owned
        .bounded_rows(query, usize::MAX, &AllowAll)
        .expect("owned sequence posting");
    let mapped_rows = mapped
        .bounded_rows(query, usize::MAX, &AllowAll)
        .expect("mapped sequence posting");
    assert_eq!(owned_rows, mapped_rows);
    assert!(
        owned_rows.windows(2).all(|pair| pair[0] < pair[1]),
        "bounded posting contract requires ascending unique row IDs: {owned_rows:?}"
    );

    for module in 0..owned.module_rows().len() {
        let module = module as u32;
        let mut pcs = owned
            .instruction_rows()
            .iter()
            .filter(|row| row.module == Some(module))
            .map(|row| row.relative_pc);
        let Some(first_pc) = pcs.next() else {
            continue;
        };
        let (minimum, maximum) = pcs.fold((first_pc, first_pc), |(minimum, maximum), pc| {
            (minimum.min(pc), maximum.max(pc))
        });
        let end = maximum.saturating_add(1);
        if minimum >= end {
            continue;
        }
        let query = NormalizedPostingQuery::ModulePc {
            module,
            start: minimum,
            end_exclusive: end,
        };
        let owned_count = owned
            .bounded_row_count(query, usize::MAX, &AllowAll)
            .expect("owned module-PC count");
        let mapped_count = mapped
            .bounded_row_count(query, usize::MAX, &AllowAll)
            .expect("mapped module-PC count");
        assert_eq!(owned_count, mapped_count);
        let owned_rows = owned
            .bounded_rows(query, usize::MAX, &AllowAll)
            .expect("owned module-PC posting");
        let mapped_rows = mapped
            .bounded_rows(query, usize::MAX, &AllowAll)
            .expect("mapped module-PC posting");
        assert_eq!(owned_rows, mapped_rows);
        assert_eq!(owned_count, owned_rows.len());
        assert!(
            owned_rows.windows(2).all(|pair| pair[0] < pair[1]),
            "bounded posting contract requires ascending unique row IDs: {owned_rows:?}"
        );
    }
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
            "source_completeness.v2",
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
fn resigned_completeness_must_match_canonical_provider_summary_and_discontinuity() {
    let artifact_root = TempDir::new().expect("Flight artifact root");
    let artifact_path = artifact_root.path().join("damaged.flight.bin");
    fs::copy(flight_fixture("v2-checksum-damaged.bin"), &artifact_path)
        .expect("copy checksum fixture");
    let session = SessionLoader::open_artifact(
        AuthorizedPath::new(artifact_path),
        OpenPolicy::default(),
        &AllowAll,
    )
    .expect("checksum-damaged Flight fixture");
    let source = &session.artifacts()[0];
    for section in ["source_completeness.v2", "completeness.v2"] {
        for case in ["provenance", "range", "reason"] {
            let root = private_root();
            TraceStore::open_or_build(root.path(), source, &BuildOptions::default(), &AllowAll)
                .expect("initial damaged cache");
            let cache = only_cache(root.path());
            let original = fs::read(&cache).expect("original cache");
            let mut corrupted = original.clone();
            resign_binary_section_mutation(&mut corrupted, section, |rows| {
                assert_eq!(rows.len(), 32, "review fixture has one completeness row");
                match case {
                    "provenance" => {
                        assert_eq!(rows[2], 4);
                        rows[2] = 0;
                    }
                    "range" => {
                        let end = u64::from_le_bytes(rows[16..24].try_into().expect("range end"));
                        rows[16..24].copy_from_slice(&end.checked_add(1).unwrap().to_le_bytes());
                    }
                    "reason" => rows[3] = 13,
                    _ => unreachable!(),
                }
            });
            fs::write(&cache, corrupted).expect("resigned completeness mutation");
            TraceStore::open_or_build(root.path(), source, &BuildOptions::default(), &AllowAll)
                .unwrap_or_else(|error| panic!("{case} must rebuild: {error}"));
            assert_eq!(
                fs::read(&cache).expect("rebuilt cache"),
                original,
                "{section} {case}"
            );
        }
    }

    let root = private_root();
    TraceStore::open_or_build(root.path(), source, &BuildOptions::default(), &AllowAll)
        .expect("initial damaged cache");
    let cache = only_cache(root.path());
    let original = fs::read(&cache).expect("original cache");
    let mut corrupted = original.clone();
    resign_binary_section_mutation(&mut corrupted, "capabilities.v2", |capabilities| {
        assert_eq!(capabilities[8], 1, "damage range capability");
        capabilities[8] = 0;
    });
    fs::write(&cache, corrupted).expect("resigned capability mutation");
    TraceStore::open_or_build(root.path(), source, &BuildOptions::default(), &AllowAll)
        .expect("wrongly downgraded completeness capability rebuilds");
    assert_eq!(
        fs::read(&cache).expect("rebuilt cache"),
        original,
        "loss-and-damage capability is independently derived"
    );
}

#[test]
fn resigned_completeness_rejects_spliced_reordered_and_overlap_rows() {
    let artifact_root = TempDir::new().expect("Flight artifact root");
    let artifact_path = artifact_root.path().join("overwritten.flight.bin");
    fs::copy(flight_fixture("v2-overwritten.bin"), &artifact_path)
        .expect("copy overwritten fixture");
    let session = SessionLoader::open_artifact(
        AuthorizedPath::new(artifact_path),
        OpenPolicy::default(),
        &AllowAll,
    )
    .expect("overwritten Flight fixture");
    let source = &session.artifacts()[0];
    for case in ["splice", "reorder", "overlap"] {
        let root = private_root();
        TraceStore::open_or_build(root.path(), source, &BuildOptions::default(), &AllowAll)
            .expect("initial overwritten cache");
        let cache = only_cache(root.path());
        let original = fs::read(&cache).expect("original cache");
        let mut corrupted = original.clone();
        for section in ["source_completeness.v2", "completeness.v2"] {
            resign_binary_section_mutation(&mut corrupted, section, |rows| {
                assert!(rows.len() >= 64, "fixture has multiple completeness rows");
                match case {
                    "splice" => {
                        let first = rows[0..32].to_vec();
                        rows[32..64].copy_from_slice(&first);
                    }
                    "reorder" => {
                        let first = rows[0..32].to_vec();
                        let second = rows[32..64].to_vec();
                        rows[0..32].copy_from_slice(&second);
                        rows[32..64].copy_from_slice(&first);
                    }
                    "overlap" => {
                        let first = rows[0..32].to_vec();
                        rows[32..64].copy_from_slice(&first);
                        let start = u64::from_le_bytes(first[8..16].try_into().expect("start"));
                        let end = u64::from_le_bytes(first[16..24].try_into().expect("end"));
                        assert!(start < end, "fixture first completeness range is non-empty");
                        rows[40..48].copy_from_slice(&end.to_le_bytes());
                        rows[48..56].copy_from_slice(
                            &end.checked_add(1).expect("overlap end").to_le_bytes(),
                        );
                    }
                    _ => unreachable!(),
                }
            });
        }
        fs::write(&cache, corrupted).expect("resigned completeness mutation");
        TraceStore::open_or_build(root.path(), source, &BuildOptions::default(), &AllowAll)
            .unwrap_or_else(|error| panic!("{case} must rebuild: {error}"));
        assert_eq!(fs::read(&cache).expect("rebuilt cache"), original, "{case}");
    }
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
    for case in [
        "missing",
        "extra",
        "reordered",
        "wrong contract",
        "missing source completeness",
        "wrong source completeness contract",
    ] {
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
                "missing source completeness" => {
                    let index = sections
                        .iter()
                        .position(|section| section["name"] == "source_completeness.v2")
                        .expect("source completeness section");
                    sections.remove(index);
                }
                "wrong source completeness contract" => {
                    let section = sections
                        .iter_mut()
                        .find(|section| section["name"] == "source_completeness.v2")
                        .expect("source completeness section");
                    section["element_size"] = 16.into();
                }
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

fn cache_manifest(bytes: &[u8]) -> Value {
    let manifest_offset = usize::try_from(u64::from_le_bytes(
        bytes[16..24].try_into().expect("manifest offset"),
    ))
    .expect("offset usize");
    let manifest_length = usize::try_from(u64::from_le_bytes(
        bytes[24..32].try_into().expect("manifest length"),
    ))
    .expect("length usize");
    serde_json::from_slice(&bytes[manifest_offset..manifest_offset + manifest_length])
        .expect("manifest JSON")
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

fn assert_no_transient_cache_entries(root: &Path) {
    fn walk(path: &Path, bad: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(path) else {
            return;
        };
        for entry in entries.filter_map(Result::ok) {
            let child = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.ends_with(".tmp")
                || name.contains("staging")
                || name.starts_with(".qtrace-dir-")
            {
                bad.push(child.clone());
            }
            if child.is_dir() {
                walk(&child, bad);
            }
        }
    }
    let mut bad = Vec::new();
    walk(root, &mut bad);
    assert!(bad.is_empty(), "transient cache entries: {bad:?}");
}
