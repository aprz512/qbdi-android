use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use qtrace_analysis::{
    AddressRange, CompletenessStatus, EventFilter, MemoryFilter, QueryContext, SequenceRange,
    TimelineProjection, query_events,
};
use qtrace_provider::{
    BudgetDimension, EventKey, EventKind, OperationAbort, Provenance, ProviderCapabilities,
    RegisterSlot, WorkDelta, WorkGuard,
};
use qtrace_store::{
    AuthorizedPath, BuildOptions, CompletenessRow, DefinitionRow, IndexBuilder, IndexError,
    InstructionRow, MemoryRow, ModuleRow, NormalizedBulkView, NormalizedContentIdentity,
    NormalizedLayoutIdentity, NormalizedPostingEstimate, NormalizedPostingQuery,
    NormalizedSourceFormat, OpenPolicy, RegisterObservationRow, SemanticDictionaryFamily,
    SemanticDictionaryWork, SemanticRow, SessionLoader, TraceStore, TraceStoreView,
};
use tempfile::TempDir;

struct AllowAll;

impl WorkGuard for AllowAll {
    fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
        Ok(())
    }
}

struct DecodeBudgetGuard<'a> {
    upstream: &'a dyn WorkGuard,
    consumed: &'a AtomicU64,
    limit: u64,
}

impl WorkGuard for DecodeBudgetGuard<'_> {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        let work = delta
            .rows
            .checked_add(delta.events)
            .and_then(|work| work.checked_add(delta.nodes))
            .and_then(|work| work.checked_add(delta.input_bytes))
            .and_then(|work| work.checked_add(delta.decompressed_bytes))
            .unwrap_or(u64::MAX);
        let previous = self.consumed.fetch_add(work, Ordering::SeqCst);
        let next = previous.saturating_add(work);
        if next > self.limit {
            self.consumed.fetch_sub(work, Ordering::SeqCst);
            return Err(OperationAbort::budget_exceeded(
                BudgetDimension::Nodes,
                self.limit,
                next,
            ));
        }
        self.upstream.consume(delta)
    }

    fn begin_allocation_scope(
        &self,
        delta: WorkDelta,
        allowed_slack: u64,
    ) -> Result<(), OperationAbort> {
        self.upstream.begin_allocation_scope(delta, allowed_slack)
    }

    fn end_allocation_scope(&self) {
        self.upstream.end_allocation_scope();
    }
}

struct DecodeBudgetView<T> {
    inner: Arc<T>,
    consumed: AtomicU64,
    limit: AtomicU64,
}

impl<T> DecodeBudgetView<T> {
    fn new(inner: Arc<T>, limit: u64) -> Self {
        Self {
            inner,
            consumed: AtomicU64::new(0),
            limit: AtomicU64::new(limit),
        }
    }

    fn arm(&self, limit: u64) {
        self.consumed.store(0, Ordering::SeqCst);
        self.limit.store(limit, Ordering::SeqCst);
    }

    fn consumed(&self) -> u64 {
        self.consumed.load(Ordering::SeqCst)
    }
}

impl<T: TraceStoreView> TraceStoreView for DecodeBudgetView<T> {
    fn event_count(&self) -> usize {
        self.inner.event_count()
    }
    fn event_key(&self, row: usize) -> Result<Option<EventKey>, IndexError> {
        self.inner.event_key(row)
    }
    fn event_kind(&self, row: usize) -> Result<Option<EventKind>, IndexError> {
        self.inner.event_kind(row)
    }
    fn provenance(&self, row: usize) -> Result<Option<Provenance>, IndexError> {
        self.inner.provenance(row)
    }
    fn capabilities(&self) -> &ProviderCapabilities {
        self.inner.capabilities()
    }
    fn instruction(&self, row: usize) -> Option<InstructionRow> {
        self.inner.instruction(row)
    }
    fn memory(&self, row: usize) -> Option<MemoryRow> {
        self.inner.memory(row)
    }
    fn semantic(&self, row: usize) -> Option<SemanticRow> {
        self.inner.semantic(row)
    }
    fn payload_bytes(&self, row: usize) -> Result<&[u8], IndexError> {
        self.inner.payload_bytes(row)
    }
    fn string_bytes(&self, id: u32) -> Result<&[u8], IndexError> {
        self.inner.string_bytes(id)
    }
    fn blob_bytes(&self, id: u32) -> Result<&[u8], IndexError> {
        self.inner.blob_bytes(id)
    }
    fn memory_before_bytes(&self, row: usize) -> Result<Option<&[u8]>, IndexError> {
        self.inner.memory_before_bytes(row)
    }
    fn memory_after_bytes(&self, row: usize) -> Result<Option<&[u8]>, IndexError> {
        self.inner.memory_after_bytes(row)
    }
    fn module(&self, module: u32) -> Option<&ModuleRow> {
        self.inner.module(module)
    }
    fn definition(&self, definition: u32) -> Option<&DefinitionRow> {
        self.inner.definition(definition)
    }
    fn register_observations(&self, row: usize) -> Vec<RegisterObservationRow> {
        self.inner.register_observations(row)
    }
    fn completeness(&self) -> &[CompletenessRow] {
        self.inner.completeness()
    }
    fn rows_for_timeline(&self, timeline: u64) -> Result<Vec<usize>, IndexError> {
        self.inner.rows_for_timeline(timeline)
    }
    fn rows_for_tids(&self, tids: &[u32]) -> Result<Vec<usize>, IndexError> {
        self.inner.rows_for_tids(tids)
    }
    fn rows_for_sequence_range(
        &self,
        start: u64,
        end_exclusive: u64,
    ) -> Result<Vec<usize>, IndexError> {
        self.inner.rows_for_sequence_range(start, end_exclusive)
    }
    fn rows_of_kinds(&self, kinds: &[EventKind]) -> Result<Vec<usize>, IndexError> {
        self.inner.rows_of_kinds(kinds)
    }
    fn rows_for_modules(&self, modules: &[u32]) -> Result<Vec<usize>, IndexError> {
        self.inner.rows_for_modules(modules)
    }
    fn rows_for_module_pc_range(
        &self,
        module: u32,
        start: u64,
        end_exclusive: u64,
    ) -> Result<Vec<usize>, IndexError> {
        self.inner
            .rows_for_module_pc_range(module, start, end_exclusive)
    }
    fn rows_for_definitions(&self, definitions: &[u32]) -> Result<Vec<usize>, IndexError> {
        self.inner.rows_for_definitions(definitions)
    }
    fn rows_observing_register(&self, slot: RegisterSlot) -> Result<Vec<usize>, IndexError> {
        self.inner.rows_observing_register(slot)
    }
    fn checkpoint_rows(&self) -> Result<Vec<usize>, IndexError> {
        self.inner.checkpoint_rows()
    }
    fn call_rows(&self) -> Result<Vec<usize>, IndexError> {
        self.inner.call_rows()
    }
    fn return_rows(&self) -> Result<Vec<usize>, IndexError> {
        self.inner.return_rows()
    }
    fn rows_for_semantic_categories(&self, categories: &[&[u8]]) -> Result<Vec<usize>, IndexError> {
        self.inner.rows_for_semantic_categories(categories)
    }
    fn rows_for_semantic_names(&self, names: &[&[u8]]) -> Result<Vec<usize>, IndexError> {
        self.inner.rows_for_semantic_names(names)
    }
    fn memory_overlaps(&self, start: u64, end: u64) -> Result<Vec<usize>, IndexError> {
        self.inner.memory_overlaps(start, end)
    }
    fn row_for_source_key(&self, key: &EventKey) -> Option<usize> {
        self.inner.row_for_source_key(key)
    }
    fn source_key_for_row(&self, row: usize) -> Result<Option<EventKey>, IndexError> {
        self.inner.source_key_for_row(row)
    }
}

impl<T: NormalizedBulkView> NormalizedBulkView for DecodeBudgetView<T> {
    fn normalized_layout_identity(&self) -> NormalizedLayoutIdentity {
        self.inner.normalized_layout_identity()
    }
    fn normalized_content_identity(&self) -> NormalizedContentIdentity {
        self.inner.normalized_content_identity()
    }
    fn normalized_source_format(&self) -> NormalizedSourceFormat {
        self.inner.normalized_source_format()
    }
    fn module_rows(&self) -> &[ModuleRow] {
        self.inner.module_rows()
    }
    fn definition_rows(&self) -> &[DefinitionRow] {
        self.inner.definition_rows()
    }
    fn instruction_rows(&self) -> &[InstructionRow] {
        self.inner.instruction_rows()
    }
    fn memory_rows(&self) -> &[MemoryRow] {
        self.inner.memory_rows()
    }
    fn semantic_rows(&self) -> &[SemanticRow] {
        self.inner.semantic_rows()
    }
    fn register_observation_rows(&self) -> &[RegisterObservationRow] {
        self.inner.register_observation_rows()
    }
    fn string_count(&self) -> usize {
        self.inner.string_count()
    }
    fn blob_count(&self) -> usize {
        self.inner.blob_count()
    }
    fn semantic_dictionary_work(
        &self,
        family: SemanticDictionaryFamily,
        term_count: usize,
        guard: &dyn WorkGuard,
    ) -> Result<SemanticDictionaryWork, IndexError> {
        self.inner
            .semantic_dictionary_work(family, term_count, guard)
    }
    fn bounded_row_estimate(
        &self,
        query: NormalizedPostingQuery<'_>,
        max_rows: usize,
        guard: &dyn WorkGuard,
    ) -> Result<NormalizedPostingEstimate, IndexError> {
        self.inner.bounded_row_estimate(query, max_rows, guard)
    }
    fn bounded_definition_decode_work(
        &self,
        query_terms: usize,
        max_rows: usize,
    ) -> Result<u64, IndexError> {
        self.inner
            .bounded_definition_decode_work(query_terms, max_rows)
    }
    fn bounded_row_count(
        &self,
        query: NormalizedPostingQuery<'_>,
        max_rows: usize,
        guard: &dyn WorkGuard,
    ) -> Result<usize, IndexError> {
        self.inner.bounded_row_count(query, max_rows, guard)
    }
    fn bounded_rows(
        &self,
        query: NormalizedPostingQuery<'_>,
        max_rows: usize,
        guard: &dyn WorkGuard,
    ) -> Result<Vec<usize>, IndexError> {
        self.inner.bounded_rows(
            query,
            max_rows,
            &DecodeBudgetGuard {
                upstream: guard,
                consumed: &self.consumed,
                limit: self.limit.load(Ordering::SeqCst),
            },
        )
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

fn qtrb_record(kind: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&kind.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn qtrb_string(value: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(value.len() as u16).to_le_bytes());
    bytes.extend_from_slice(value);
    bytes
}

fn indexed_work_qtrb(instruction_count: usize, short_memory_count: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"QTRB");
    bytes.extend_from_slice(&[1, 2, 1, 8, 2, 0]);
    bytes.extend_from_slice(&16_u16.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());

    let mut begin = Vec::new();
    begin.extend_from_slice(&0x7100_0000_u64.to_le_bytes());
    begin.extend_from_slice(&0x100_u64.to_le_bytes());
    begin.extend_from_slice(&0x7100_0100_u64.to_le_bytes());
    begin.extend_from_slice(&4242_u32.to_le_bytes());
    begin.extend_from_slice(&7_u32.to_le_bytes());
    begin.extend_from_slice(&[2, 0]);
    begin.extend_from_slice(&4096_u64.to_le_bytes());
    begin.extend_from_slice(&1_u64.to_le_bytes());
    begin.extend(qtrb_string(b"indexed-work-contract"));
    begin.extend(qtrb_string(b"libtarget.so"));
    bytes.extend(qtrb_record(1, &begin));

    let mut module = Vec::new();
    module.extend_from_slice(&1_u32.to_le_bytes());
    module.extend_from_slice(&0x7100_0000_u64.to_le_bytes());
    module.extend(qtrb_string(b"libtarget.so"));
    bytes.extend(qtrb_record(2, &module));

    if instruction_count != 0 {
        let mut definition = Vec::new();
        definition.extend_from_slice(&7_u32.to_le_bytes());
        definition.extend_from_slice(&0xd503_201f_u32.to_le_bytes());
        definition.extend_from_slice(&0_u64.to_le_bytes());
        definition.extend_from_slice(&0_u64.to_le_bytes());
        definition.extend_from_slice(&0_i64.to_le_bytes());
        definition.extend_from_slice(&0_u32.to_le_bytes());
        definition.extend_from_slice(&[0, 0, 0, 0]);
        definition.extend(qtrb_string(b"nop"));
        definition.extend(qtrb_string(b""));
        definition.extend(qtrb_string(b"nop"));
        bytes.extend(qtrb_record(3, &definition));
    }

    for sequence in 1..=instruction_count as u64 {
        let mut instruction = Vec::new();
        instruction.extend_from_slice(&sequence.to_le_bytes());
        instruction.extend_from_slice(&1_u32.to_le_bytes());
        instruction.extend_from_slice(&sequence.to_le_bytes());
        instruction.extend_from_slice(&7_u32.to_le_bytes());
        instruction.extend_from_slice(&[0, 0]);
        bytes.extend(qtrb_record(4, &instruction));
    }

    if short_memory_count != 0 {
        bytes.extend(qtrb_memory_record(0, 1_000_000));
        for ordinal in 0..short_memory_count {
            let start = ordinal as u64 * 2 + 1;
            bytes.extend(qtrb_memory_record(start, 1));
        }
    }

    let encoded_bytes = (bytes.len() + 8 + 97) as u64;
    let mut terminal = Vec::new();
    terminal.push(1);
    terminal.extend_from_slice(&0_u64.to_le_bytes());
    terminal.extend_from_slice(&1_u64.to_le_bytes());
    for value in [
        instruction_count as u64,
        encoded_bytes,
        encoded_bytes,
        0,
        0,
        0,
        0,
        0,
        0,
        4096,
    ] {
        terminal.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend(qtrb_record(9, &terminal));
    bytes
}

fn qtrb_memory_record(address: u64, size: u32) -> Vec<u8> {
    let mut memory = Vec::new();
    memory.extend_from_slice(&1_u32.to_le_bytes());
    memory.extend_from_slice(&0_u64.to_le_bytes());
    memory.extend_from_slice(&[1, 1]);
    memory.extend_from_slice(&0_u16.to_le_bytes());
    memory.extend_from_slice(&address.to_le_bytes());
    memory.extend_from_slice(&size.to_le_bytes());
    memory.extend_from_slice(&0_u64.to_le_bytes());
    memory.extend_from_slice(&[0, 0, 0, 0]);
    qtrb_record(5, &memory)
}

fn nonmonotonic_posting_qtrb() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"QTRB");
    bytes.extend_from_slice(&[1, 2, 1, 8, 2, 0]);
    bytes.extend_from_slice(&16_u16.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());

    let mut begin = Vec::new();
    begin.extend_from_slice(&0x7100_0000_u64.to_le_bytes());
    begin.extend_from_slice(&0x100_u64.to_le_bytes());
    begin.extend_from_slice(&0x7100_0100_u64.to_le_bytes());
    begin.extend_from_slice(&4242_u32.to_le_bytes());
    begin.extend_from_slice(&7_u32.to_le_bytes());
    begin.extend_from_slice(&[2, 0]);
    begin.extend_from_slice(&4096_u64.to_le_bytes());
    begin.extend_from_slice(&1_u64.to_le_bytes());
    begin.extend(qtrb_string(b"analysis-posting-order"));
    begin.extend(qtrb_string(b"libtarget.so"));
    bytes.extend(qtrb_record(1, &begin));

    let mut module = Vec::new();
    module.extend_from_slice(&1_u32.to_le_bytes());
    module.extend_from_slice(&0x7100_0000_u64.to_le_bytes());
    module.extend(qtrb_string(b"libtarget.so"));
    bytes.extend(qtrb_record(2, &module));

    let mut definition = Vec::new();
    definition.extend_from_slice(&7_u32.to_le_bytes());
    definition.extend_from_slice(&0xd503_201f_u32.to_le_bytes());
    definition.extend_from_slice(&0_u64.to_le_bytes());
    definition.extend_from_slice(&0_u64.to_le_bytes());
    definition.extend_from_slice(&0_i64.to_le_bytes());
    definition.extend_from_slice(&0_u32.to_le_bytes());
    definition.extend_from_slice(&[0, 0, 0, 0]);
    definition.extend(qtrb_string(b"nop"));
    definition.extend(qtrb_string(b""));
    definition.extend(qtrb_string(b"nop"));
    bytes.extend(qtrb_record(3, &definition));

    for (sequence, pc) in [(1_u64, 0x30_u64), (2, 0x10)] {
        let mut instruction = Vec::new();
        instruction.extend_from_slice(&sequence.to_le_bytes());
        instruction.extend_from_slice(&1_u32.to_le_bytes());
        instruction.extend_from_slice(&pc.to_le_bytes());
        instruction.extend_from_slice(&7_u32.to_le_bytes());
        instruction.extend_from_slice(&[0, 0]);
        bytes.extend(qtrb_record(4, &instruction));
    }
    let encoded_bytes = (bytes.len() + 8 + 97) as u64;
    let mut terminal = Vec::new();
    terminal.push(1);
    terminal.extend_from_slice(&0x55_u64.to_le_bytes());
    terminal.extend_from_slice(&17_u64.to_le_bytes());
    for value in [2, encoded_bytes, encoded_bytes, 0, 0, 0, 0, 0, 0, 4096] {
        terminal.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend(qtrb_record(9, &terminal));
    bytes
}

fn large_semantic_dictionary_qtrb() -> Vec<u8> {
    const NAMES: usize = 48_000;
    const NAME_BYTES: usize = 255;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"QTRB");
    bytes.extend_from_slice(&[1, 2, 1, 8, 2, 0]);
    bytes.extend_from_slice(&16_u16.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());

    let mut begin = Vec::new();
    begin.extend_from_slice(&0x7100_0000_u64.to_le_bytes());
    begin.extend_from_slice(&0x100_u64.to_le_bytes());
    begin.extend_from_slice(&0x7100_0100_u64.to_le_bytes());
    begin.extend_from_slice(&4242_u32.to_le_bytes());
    begin.extend_from_slice(&7_u32.to_le_bytes());
    begin.extend_from_slice(&[2, 0]);
    begin.extend_from_slice(&4096_u64.to_le_bytes());
    begin.extend_from_slice(&1_u64.to_le_bytes());
    begin.extend(qtrb_string(b"large-semantic-dictionary"));
    begin.extend(qtrb_string(b"libtarget.so"));
    bytes.extend(qtrb_record(1, &begin));

    for ordinal in 0..NAMES {
        let prefix = format!("name-{ordinal:05}-");
        let mut name = prefix.into_bytes();
        name.resize(NAME_BYTES, b'x');
        let mut semantic = Vec::new();
        semantic.extend(qtrb_string(b"bulk"));
        semantic.extend(qtrb_string(&name));
        semantic.extend(qtrb_string(b""));
        bytes.extend(qtrb_record(6, &semantic));
    }

    let encoded_bytes = (bytes.len() + 8 + 97) as u64;
    let mut terminal = Vec::new();
    terminal.push(1);
    terminal.extend_from_slice(&0_u64.to_le_bytes());
    terminal.extend_from_slice(&1_u64.to_le_bytes());
    for value in [0, encoded_bytes, encoded_bytes, 0, 0, 0, 0, 0, 0, 4096] {
        terminal.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend(qtrb_record(9, &terminal));
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

fn measured_decode_work(run: impl FnOnce(&dyn WorkGuard) -> Result<(), IndexError>) -> u64 {
    let consumed = AtomicU64::new(0);
    run(&DecodeBudgetGuard {
        upstream: &AllowAll,
        consumed: &consumed,
        limit: u64::MAX,
    })
    .expect("production posting decode");
    consumed.load(Ordering::SeqCst)
}

fn assert_public_decode_boundary<T>(
    store: Arc<T>,
    filter: EventFilter,
    measured_work: u64,
    expected_rows: usize,
) where
    T: NormalizedBulkView + Send + Sync + 'static,
{
    assert!(measured_work > 1);
    let rejected = Arc::new(DecodeBudgetView::new(store.clone(), u64::MAX));
    let rejected_context = Arc::new(QueryContext::new(rejected.clone()).expect("W-1 context"));
    rejected.arm(measured_work - 1);
    let error = match TimelineProjection::new(rejected_context, filter.clone()) {
        Ok(_) => panic!("W-1 production decode was accepted"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "analysis.cpu_budget_exceeded");

    for allowance in [measured_work, measured_work + 1] {
        let view = Arc::new(DecodeBudgetView::new(store.clone(), u64::MAX));
        let context = Arc::new(QueryContext::new(view.clone()).expect("bounded context"));
        view.arm(allowance);
        let projection = TimelineProjection::new(context, filter.clone())
            .expect("production decode work must fit the derived plan");
        let page = query_events(&projection, None, 2_000).expect("public page");
        assert_eq!(page.rows.len(), expected_rows);
        assert_eq!(page.total, expected_rows);
        assert!(page.exact_total);
        assert_eq!(view.consumed(), measured_work);
    }
}

fn assert_absent_semantic_term<T>(store: Arc<T>, filter: EventFilter)
where
    T: NormalizedBulkView + Send + Sync + 'static,
{
    let context = Arc::new(QueryContext::new(store).expect("large dictionary context"));
    let projection = TimelineProjection::new(context, filter)
        .expect("absent single semantic term must fit the derived work plan");
    let page = query_events(&projection, None, 1).expect("empty exact page");
    assert!(page.rows.is_empty());
    assert_eq!(page.total, 0);
    assert!(page.exact_total);
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
fn production_nonmonotonic_postings_intersect_without_loss_in_owned_and_mapped_stores() {
    let bytes = nonmonotonic_posting_qtrb();
    let (owned, mapped, _cache, _source) = stores_for_bytes(&bytes, "nonmonotonic.trace.bin");
    let filter = EventFilter {
        kinds: vec![EventKind::Instruction],
        sequence: vec![SequenceRange::new(1, 2).unwrap()],
        modules: vec![0],
        relative_pc: vec![AddressRange::new(0x10, 0x31).unwrap()],
        ..EventFilter::default()
    };
    let owned_rows = source_rows(Arc::new(owned), filter.clone()).0;
    let mapped_rows = source_rows(Arc::new(mapped), filter).0;
    assert_eq!(owned_rows, vec![3, 4]);
    assert_eq!(mapped_rows, owned_rows);
}

#[test]
fn production_large_semantic_dictionary_allows_an_absent_single_term() {
    let bytes = large_semantic_dictionary_qtrb();
    let (owned, mapped, _cache, _source) =
        stores_for_bytes(&bytes, "large-semantic-dictionary.trace.bin");
    let dictionary_bytes = (0..owned.string_count())
        .map(|id| owned.string_bytes(id as u32).unwrap().len())
        .sum::<usize>();
    assert!((11 * 1024 * 1024..=16 * 1024 * 1024).contains(&dictionary_bytes));

    let filter = EventFilter {
        semantic_names: vec!["absent".into()],
        ..EventFilter::default()
    };
    assert_absent_semantic_term(Arc::new(owned), filter.clone());
    assert_absent_semantic_term(Arc::new(mapped), filter);
}

#[test]
fn production_memory_scan_work_bounds_public_owned_and_mapped_projection() {
    const SHORT_INTERVALS: usize = 16_384;
    const QUERY_START: u64 = 900_000;
    let bytes = indexed_work_qtrb(0, SHORT_INTERVALS);
    let (owned, mapped, _cache, _source) = stores_for_bytes(&bytes, "memory-work.trace.bin");
    let filter = EventFilter {
        memory: vec![MemoryFilter {
            range: AddressRange::new(QUERY_START, QUERY_START + 1).unwrap(),
            directions: Vec::new(),
        }],
        ..EventFilter::default()
    };

    let owned = Arc::new(owned);
    let owned_work = measured_decode_work(|guard| {
        let rows = owned.bounded_rows(
            NormalizedPostingQuery::Memory {
                start: QUERY_START,
                end_exclusive: QUERY_START + 1,
            },
            usize::MAX,
            guard,
        )?;
        assert_eq!(rows.len(), 1);
        Ok(())
    });
    let owned_estimate = owned
        .bounded_row_estimate(
            NormalizedPostingQuery::Memory {
                start: QUERY_START,
                end_exclusive: QUERY_START + 1,
            },
            usize::MAX,
            &AllowAll,
        )
        .unwrap();
    assert_eq!(owned_estimate.decode_work, owned_work);
    assert!(owned_work > SHORT_INTERVALS as u64 * 2);
    assert_public_decode_boundary(owned, filter.clone(), owned_work, 1);

    let mapped = Arc::new(mapped);
    let mapped_work = measured_decode_work(|guard| {
        let rows = mapped.bounded_rows(
            NormalizedPostingQuery::Memory {
                start: QUERY_START,
                end_exclusive: QUERY_START + 1,
            },
            usize::MAX,
            guard,
        )?;
        assert_eq!(rows.len(), 1);
        Ok(())
    });
    let mapped_estimate = mapped
        .bounded_row_estimate(
            NormalizedPostingQuery::Memory {
                start: QUERY_START,
                end_exclusive: QUERY_START + 1,
            },
            usize::MAX,
            &AllowAll,
        )
        .unwrap();
    assert_eq!(mapped_estimate.decode_work, mapped_work);
    assert_eq!(mapped_work, owned_work);
    assert_public_decode_boundary(mapped, filter, mapped_work, 1);
}

#[test]
fn production_sparse_sequence_work_bounds_public_owned_and_mapped_projection() {
    const PAIRS: usize = 512;
    let bytes = indexed_work_qtrb(PAIRS * 4, 0);
    let (owned, mapped, _cache, _source) = stores_for_bytes(&bytes, "sequence-work.trace.bin");
    let ranges = (0..PAIRS)
        .map(|pair| {
            let first = pair as u64 * 4 + 1;
            SequenceRange::new(first, first + 1).unwrap()
        })
        .collect::<Vec<_>>();
    let filter = EventFilter {
        sequence: ranges.clone(),
        ..EventFilter::default()
    };

    let owned = Arc::new(owned);
    let owned_work = measured_decode_work(|guard| {
        for range in &ranges {
            let rows = owned.bounded_rows(
                NormalizedPostingQuery::Sequence {
                    start: range.first,
                    end_exclusive: range.last + 1,
                },
                usize::MAX,
                guard,
            )?;
            assert_eq!(rows.len(), 2);
        }
        Ok(())
    });
    assert_public_decode_boundary(owned, filter.clone(), owned_work, PAIRS * 2);

    let mapped = Arc::new(mapped);
    let mapped_work = measured_decode_work(|guard| {
        for range in &ranges {
            let rows = mapped.bounded_rows(
                NormalizedPostingQuery::Sequence {
                    start: range.first,
                    end_exclusive: range.last + 1,
                },
                usize::MAX,
                guard,
            )?;
            assert_eq!(rows.len(), 2);
        }
        Ok(())
    });
    assert_eq!(mapped_work, owned_work);
    assert_public_decode_boundary(mapped, filter, mapped_work, PAIRS * 2);
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
