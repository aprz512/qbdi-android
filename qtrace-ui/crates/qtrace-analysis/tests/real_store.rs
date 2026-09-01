use std::{fs, os::unix::fs::PermissionsExt, path::Path, sync::Arc};

use qtrace_analysis::{
    AddressRange, EventFilter, QueryContext, SequenceRange, TimelineProjection, query_events,
};
use qtrace_provider::{OperationAbort, WorkDelta, WorkGuard};
use qtrace_store::{
    AuthorizedPath, BuildOptions, IndexBuilder, OpenPolicy, SessionLoader, TraceStore,
    TraceStoreView,
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

fn source_rows<T>(store: Arc<T>, filter: EventFilter) -> (Vec<usize>, usize)
where
    T: TraceStoreView + Send + Sync + 'static,
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

fn expected_module_rows(store: &dyn TraceStoreView, module: u32) -> Vec<usize> {
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
    T: TraceStoreView + Send + Sync + 'static,
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
    let (owned, _mapped, _cache) = stores();
    let store = Arc::new(owned);
    let memory = store
        .memory_rows()
        .iter()
        .find(|row| row.module.is_some())
        .copied()
        .expect("fixture memory with module");
    let module = store.module(memory.module.unwrap()).expect("module");
    let absolute = module.base.checked_add(memory.relative_pc).unwrap();
    let (rows, absolute_indexes) = source_rows(
        store.clone(),
        EventFilter {
            absolute_pc: vec![AddressRange::new(absolute, absolute + 1).unwrap()],
            ..EventFilter::default()
        },
    );
    assert!(absolute_indexes > 0);
    assert!(rows.contains(&memory.owner_row));

    let (_, sequence_indexes) = source_rows(
        store,
        EventFilter {
            sequence: vec![SequenceRange::new(1, u64::MAX).unwrap()],
            ..EventFilter::default()
        },
    );
    assert!(sequence_indexes > 0);
}
