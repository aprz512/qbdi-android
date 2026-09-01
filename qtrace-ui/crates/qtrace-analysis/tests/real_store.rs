use std::{fs, os::unix::fs::PermissionsExt, path::Path, sync::Arc};

use qtrace_analysis::{
    AddressRange, CompletenessStatus, EventFilter, QueryContext, SequenceRange, TimelineProjection,
    query_events,
};
use qtrace_provider::{OperationAbort, WorkDelta, WorkGuard};
use qtrace_store::{
    AuthorizedPath, BuildOptions, IndexBuilder, NormalizedBulkView, OpenPolicy, SessionLoader,
    TraceStore, TraceStoreView,
};
use tempfile::TempDir;

struct AllowAll;

impl WorkGuard for AllowAll {
    fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
        Ok(())
    }
}

fn fixture() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("fixtures/sessions/valid-mixed")
}

fn corpus_fixture(path: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("fixtures")
        .join(path)
}

fn stores() -> (qtrace_store::OwnedTraceStore, TraceStore, TempDir) {
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
    let cache = TempDir::new().expect("cache root");
    fs::set_permissions(cache.path(), fs::Permissions::from_mode(0o700))
        .expect("private cache root");
    let mapped =
        TraceStore::open_or_build(cache.path(), source, &options, &AllowAll).expect("mapped store");
    assert!(mapped.is_mapped());
    (owned, mapped, cache)
}

fn stores_for_artifact(
    path: &str,
) -> (qtrace_store::OwnedTraceStore, TraceStore, TempDir, TempDir) {
    let file_name = if path.starts_with("qtrb/") {
        "fixture.trace.bin"
    } else {
        "fixture.flight.bin"
    };
    stores_for_bytes(
        &fs::read(corpus_fixture(path)).expect("fixture bytes"),
        file_name,
    )
}

fn stores_for_bytes(
    bytes: &[u8],
    file_name: &str,
) -> (qtrace_store::OwnedTraceStore, TraceStore, TempDir, TempDir) {
    let source_dir = TempDir::new().expect("source fixture tempdir");
    let source_path = source_dir.path().join(file_name);
    fs::write(&source_path, bytes).expect("write production fixture");
    let session = SessionLoader::open_artifact(
        AuthorizedPath::new(source_path),
        OpenPolicy::default(),
        &AllowAll,
    )
    .expect("production fixture");
    let source = &session.artifacts()[0];
    let options = BuildOptions::default();
    let owned = IndexBuilder::build(source, &options, &AllowAll).expect("owned store");
    let cache = TempDir::new().expect("cache root");
    fs::set_permissions(cache.path(), fs::Permissions::from_mode(0o700))
        .expect("private cache root");
    let mapped =
        TraceStore::open_or_build(cache.path(), source, &options, &AllowAll).expect("mapped store");
    (owned, mapped, cache, source_dir)
}

fn max_sequence_flight_bytes() -> Vec<u8> {
    const CHUNK_BYTES: usize = 2048;
    let generation = 1;
    let begin = flight_begin_payload();
    let records = [flight_record(1, u64::MAX, generation, &begin)];
    let committed = records.iter().map(Vec::len).sum::<usize>();
    let mut chunk = vec![0; CHUNK_BYTES];
    put_u32(&mut chunk, 0, 0x5146_4c54);
    put_u16(&mut chunk, 4, 2);
    put_u16(
        &mut chunk,
        6,
        qtrace_provider::FLIGHT_CHUNK_HEADER_BYTES as u16,
    );
    put_u32(&mut chunk, 8, 0);
    put_u32(&mut chunk, 12, 2);
    put_u32(&mut chunk, 16, 7);
    put_u32(&mut chunk, 20, generation);
    put_u64(&mut chunk, 24, u64::MAX);
    put_u64(&mut chunk, 32, u64::MAX);
    put_u32(&mut chunk, 40, committed as u32);
    put_u32(&mut chunk, 44, records.len() as u32);
    let mut cursor = qtrace_provider::FLIGHT_CHUNK_HEADER_BYTES;
    for record in records {
        chunk[cursor..cursor + record.len()].copy_from_slice(&record);
        cursor += record.len();
    }
    let chunk_checksum = fnv32(&chunk[qtrace_provider::FLIGHT_CHUNK_HEADER_BYTES..cursor]);
    put_u32(&mut chunk, 48, chunk_checksum);

    let directory_offset = qtrace_provider::FLIGHT_SUPERBLOCK_BYTES;
    let emergency_offset = align(
        directory_offset + qtrace_provider::FLIGHT_DIRECTORY_ENTRY_BYTES,
        qtrace_provider::FLIGHT_EMERGENCY_SLOT_BYTES,
    );
    let chunk_offset = align(
        emergency_offset + 2 * qtrace_provider::FLIGHT_EMERGENCY_SLOT_BYTES,
        CHUNK_BYTES,
    );
    let mut bytes = vec![0; chunk_offset + CHUNK_BYTES];
    put_u32(&mut bytes, 0, 0x5146_4c54);
    put_u16(&mut bytes, 4, 2);
    bytes[6] = 1;
    bytes[7] = 8;
    put_u16(
        &mut bytes,
        8,
        qtrace_provider::FLIGHT_SUPERBLOCK_BYTES as u16,
    );
    let artifact_len = bytes.len() as u64;
    put_u64(&mut bytes, 16, artifact_len);
    put_u64(&mut bytes, 24, directory_offset as u64);
    put_u32(
        &mut bytes,
        32,
        qtrace_provider::FLIGHT_DIRECTORY_ENTRY_BYTES as u32,
    );
    put_u32(&mut bytes, 36, 1);
    put_u64(&mut bytes, 40, chunk_offset as u64);
    put_u32(&mut bytes, 48, CHUNK_BYTES as u32);
    put_u32(&mut bytes, 52, 1);
    put_u64(&mut bytes, 56, emergency_offset as u64);
    put_u32(
        &mut bytes,
        64,
        qtrace_provider::FLIGHT_EMERGENCY_SLOT_BYTES as u32,
    );
    put_u32(&mut bytes, 68, 2);
    put_u64(&mut bytes, 80, 1);
    put_u32(&mut bytes, 88, 4242);
    put_u32(&mut bytes, 92, 17);
    let target = b"libtarget.so";
    put_u16(&mut bytes, 96, target.len() as u16);
    bytes[98..98 + target.len()].copy_from_slice(target);
    put_u32(&mut bytes, directory_offset, 7);
    put_u32(&mut bytes, directory_offset + 4, 1);
    put_u64(&mut bytes, directory_offset + 8, u64::MAX);
    put_u64(&mut bytes, directory_offset + 16, u64::MAX);
    put_u32(&mut bytes, directory_offset + 24, 0);
    put_u32(&mut bytes, directory_offset + 28, generation);
    bytes[chunk_offset..chunk_offset + CHUNK_BYTES].copy_from_slice(&chunk);
    bytes
}

fn flight_record(kind: u16, sequence: u64, generation: u32, payload: &[u8]) -> Vec<u8> {
    let total = qtrace_provider::FLIGHT_RECORD_HEADER_BYTES + payload.len();
    let mut record = vec![0; align(total, 8)];
    put_u16(&mut record, 0, kind);
    put_u32(&mut record, 4, total as u32);
    put_u64(&mut record, 8, sequence);
    record[qtrace_provider::FLIGHT_RECORD_HEADER_BYTES..total].copy_from_slice(payload);
    let mut checksum_bytes = record[..16].to_vec();
    checksum_bytes.extend_from_slice(&record[qtrace_provider::FLIGHT_RECORD_HEADER_BYTES..total]);
    let checksum = fnv32(&checksum_bytes);
    put_u32(&mut record, 16, checksum);
    put_u32(&mut record, 20, 0x5143_4d54 ^ total as u32 ^ generation);
    record
}

fn flight_begin_payload() -> Vec<u8> {
    let target = b"libtarget.so";
    let scene = b"max-sequence";
    let mut output = Vec::new();
    output.extend_from_slice(&[2, 8]);
    output.extend_from_slice(&(target.len() as u16).to_le_bytes());
    output.extend_from_slice(&(scene.len() as u16).to_le_bytes());
    output.extend_from_slice(&0_u16.to_le_bytes());
    output.extend_from_slice(&4242_u32.to_le_bytes());
    output.extend_from_slice(&7_u32.to_le_bytes());
    output.extend_from_slice(&0x7100_0000_u64.to_le_bytes());
    output.extend_from_slice(&0x100_u64.to_le_bytes());
    output.extend_from_slice(&0x7100_0100_u64.to_le_bytes());
    output.extend_from_slice(target);
    output.extend_from_slice(scene);
    output
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn align(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

fn fnv32(bytes: &[u8]) -> u32 {
    bytes.iter().fold(2_166_136_261_u32, |value, byte| {
        (value ^ u32::from(*byte)).wrapping_mul(16_777_619)
    })
}

fn completeness_status<T>(store: Arc<T>) -> CompletenessStatus
where
    T: NormalizedBulkView + Send + Sync + 'static,
{
    let context = Arc::new(QueryContext::new(store).expect("query context"));
    let projection = TimelineProjection::new(context, EventFilter::default()).expect("projection");
    query_events(&projection, None, 1)
        .expect("page")
        .completeness
        .status
}

fn source_rows<T>(store: Arc<T>, filter: EventFilter) -> (Vec<usize>, usize)
where
    T: NormalizedBulkView + Send + Sync + 'static,
{
    let context = Arc::new(QueryContext::new(store).expect("query context"));
    let projection = TimelineProjection::new(context, filter).expect("projection");
    let indexed_fields = projection.plan().indexed_fields;
    let mut rows = query_events(&projection, None, 2_000)
        .expect("page")
        .rows
        .into_iter()
        .map(|row| row.source_row())
        .collect::<Vec<_>>();
    rows.sort_unstable();
    (rows, indexed_fields)
}

fn expected_module_rows(store: &dyn NormalizedBulkView, module: u32) -> Vec<usize> {
    let mut rows = store
        .instruction_rows()
        .iter()
        .filter_map(|row| (row.module == Some(module)).then_some(row.owner_row))
        .chain(
            store
                .memory_rows()
                .iter()
                .filter_map(|row| (row.module == Some(module)).then_some(row.owner_row)),
        )
        .collect::<Vec<_>>();
    rows.sort_unstable();
    rows
}

fn assert_real_module_and_pc_queries<T>(store: Arc<T>)
where
    T: NormalizedBulkView + Send + Sync + 'static,
{
    let memory = store
        .memory_rows()
        .iter()
        .find(|row| row.module.is_some())
        .copied()
        .expect("fixture memory with module");
    let module = memory.module.unwrap();
    let expected = expected_module_rows(store.as_ref(), module);
    assert!(expected.contains(&memory.owner_row));
    assert_eq!(
        source_rows(
            store.clone(),
            EventFilter {
                modules: vec![module],
                ..EventFilter::default()
            },
        )
        .0,
        expected
    );

    let range = AddressRange::new(memory.relative_pc, memory.relative_pc + 1).unwrap();
    let expected_relative = expected
        .into_iter()
        .filter(|owner| {
            store
                .instruction_rows()
                .iter()
                .find(|row| row.owner_row == *owner)
                .map(|row| row.relative_pc)
                .or_else(|| {
                    store
                        .memory_rows()
                        .iter()
                        .find(|row| row.owner_row == *owner)
                        .map(|row| row.relative_pc)
                })
                == Some(memory.relative_pc)
        })
        .collect::<Vec<_>>();
    assert!(expected_relative.contains(&memory.owner_row));
    assert_eq!(
        source_rows(
            store,
            EventFilter {
                modules: vec![module],
                relative_pc: vec![range],
                ..EventFilter::default()
            },
        )
        .0,
        expected_relative
    );
}

#[test]
fn real_owned_and_mapped_module_indexes_include_instruction_and_memory_owners() {
    let (owned, mapped, _cache) = stores();
    assert_real_module_and_pc_queries(Arc::new(owned));
    assert_real_module_and_pc_queries(Arc::new(mapped));
}

#[test]
fn real_owned_and_mapped_have_identical_complete_store_identity() {
    let (owned, mapped, _cache) = stores();
    let owned = QueryContext::new(Arc::new(owned)).expect("owned context");
    let mapped = QueryContext::new(Arc::new(mapped)).expect("mapped context");
    assert_eq!(owned.identity(), mapped.identity());
}

#[test]
fn absolute_pc_and_max_sequence_queries_use_indexes_without_losing_memory() {
    let (owned, mapped, _cache) = stores();
    let owned = Arc::new(owned);
    let mapped = Arc::new(mapped);
    let (module_id, first_pc, last_pc) = (0..owned.module_rows().len())
        .find_map(|module| {
            let module = module as u32;
            let instruction = owned
                .instruction_rows()
                .iter()
                .find(|row| row.module == Some(module))?;
            let memory = owned
                .memory_rows()
                .iter()
                .find(|row| row.module == Some(module))?;
            Some((
                module,
                instruction.relative_pc.min(memory.relative_pc),
                instruction.relative_pc.max(memory.relative_pc),
            ))
        })
        .expect("fixture module with instruction and memory");
    let module = owned.module(module_id).expect("module");
    let absolute_start = module.base.checked_add(first_pc).unwrap();
    let absolute_end = module
        .base
        .checked_add(last_pc)
        .and_then(|pc| pc.checked_add(1))
        .unwrap();
    let expected = owned
        .instruction_rows()
        .iter()
        .filter_map(|row| {
            (row.module == Some(module_id)
                && first_pc <= row.relative_pc
                && row.relative_pc <= last_pc)
                .then_some(row.owner_row)
        })
        .chain(owned.memory_rows().iter().filter_map(|row| {
            (row.module == Some(module_id)
                && first_pc <= row.relative_pc
                && row.relative_pc <= last_pc)
                .then_some(row.owner_row)
        }))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    assert!(expected.iter().any(|owner| {
        owned
            .instruction_rows()
            .iter()
            .any(|row| row.owner_row == *owner)
    }));
    assert!(expected.iter().any(|owner| {
        owned
            .memory_rows()
            .iter()
            .any(|row| row.owner_row == *owner)
    }));
    let filter = EventFilter {
        absolute_pc: vec![AddressRange::new(absolute_start, absolute_end).unwrap()],
        ..EventFilter::default()
    };
    let (owned_rows, absolute_indexes) = source_rows(owned.clone(), filter.clone());
    let (mapped_rows, mapped_indexes) = source_rows(mapped, filter);
    assert!(absolute_indexes > 0 && mapped_indexes > 0);
    assert_eq!(owned_rows, expected);
    assert_eq!(mapped_rows, expected);

    let (_, sequence_indexes) = source_rows(
        owned,
        EventFilter {
            sequence: vec![SequenceRange::new(1, u64::MAX).unwrap()],
            ..EventFilter::default()
        },
    );
    assert!(sequence_indexes > 0);
}

#[test]
fn production_max_sequence_row_is_indexed_in_owned_and_mapped_stores() {
    let bytes = max_sequence_flight_bytes();
    let (owned, mapped, _cache, _source) = stores_for_bytes(&bytes, "max.flight.bin");
    let filter = EventFilter {
        sequence: vec![SequenceRange::new(u64::MAX, u64::MAX).unwrap()],
        ..EventFilter::default()
    };
    let owned_rows = source_rows(Arc::new(owned), filter.clone()).0;
    let mapped = Arc::new(mapped);
    let mapped_rows = source_rows(mapped.clone(), filter).0;
    assert_eq!(owned_rows, mapped_rows);
    assert!(!mapped_rows.is_empty());
    for row in mapped_rows {
        assert_eq!(
            mapped.event_key(row).unwrap().unwrap().sequence,
            Some(u64::MAX)
        );
    }
}

#[test]
fn production_qtrb_and_flight_completeness_use_their_native_domains() {
    let (qtrb_owned, qtrb_mapped, _qtrb_cache, _qtrb_source) =
        stores_for_artifact("qtrb/v1.2-completed.bin");
    assert_eq!(
        completeness_status(Arc::new(qtrb_owned)),
        CompletenessStatus::Complete
    );
    assert_eq!(
        completeness_status(Arc::new(qtrb_mapped)),
        CompletenessStatus::Complete
    );

    let (flight_owned, flight_mapped, _flight_cache, _flight_source) =
        stores_for_artifact("flight/v2-complete.bin");
    assert_eq!(
        completeness_status(Arc::new(flight_owned)),
        CompletenessStatus::Complete
    );
    assert_eq!(
        completeness_status(Arc::new(flight_mapped)),
        CompletenessStatus::Complete
    );

    for path in [
        "flight/v2-active.bin",
        "flight/v2-checksum-damaged.bin",
        "flight/v2-coverage-gap.bin",
        "flight/v2-incomplete-fragment.bin",
        "flight/v2-overwritten.bin",
    ] {
        let (owned, mapped, _cache, _source) = stores_for_artifact(path);
        assert_eq!(
            completeness_status(Arc::new(owned)),
            CompletenessStatus::Incomplete,
            "owned {path}"
        );
        assert_eq!(
            completeness_status(Arc::new(mapped)),
            CompletenessStatus::Incomplete,
            "mapped {path}"
        );
    }
}
