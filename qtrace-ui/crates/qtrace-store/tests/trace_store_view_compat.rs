use qtrace_provider::{EventKey, EventKind, Provenance, ProviderCapabilities, RegisterSlot};
use qtrace_store::{
    CompletenessRow, DefinitionRow, IndexError, InstructionRow, MemoryRow, ModuleRow,
    RegisterObservationRow, SemanticRow, TraceStoreView,
};

struct LegacyView {
    capabilities: ProviderCapabilities,
}

impl TraceStoreView for LegacyView {
    fn event_count(&self) -> usize {
        0
    }
    fn event_key(&self, _: usize) -> Result<Option<EventKey>, IndexError> {
        Ok(None)
    }
    fn event_kind(&self, _: usize) -> Result<Option<EventKind>, IndexError> {
        Ok(None)
    }
    fn provenance(&self, _: usize) -> Result<Option<Provenance>, IndexError> {
        Ok(None)
    }
    fn capabilities(&self) -> &ProviderCapabilities {
        &self.capabilities
    }
    fn instruction(&self, _: usize) -> Option<InstructionRow> {
        None
    }
    fn memory(&self, _: usize) -> Option<MemoryRow> {
        None
    }
    fn semantic(&self, _: usize) -> Option<SemanticRow> {
        None
    }
    fn payload_bytes(&self, _: usize) -> Result<&[u8], IndexError> {
        Ok(&[])
    }
    fn string_bytes(&self, _: u32) -> Result<&[u8], IndexError> {
        Ok(&[])
    }
    fn blob_bytes(&self, _: u32) -> Result<&[u8], IndexError> {
        Ok(&[])
    }
    fn memory_before_bytes(&self, _: usize) -> Result<Option<&[u8]>, IndexError> {
        Ok(None)
    }
    fn memory_after_bytes(&self, _: usize) -> Result<Option<&[u8]>, IndexError> {
        Ok(None)
    }
    fn module(&self, _: u32) -> Option<&ModuleRow> {
        None
    }
    fn definition(&self, _: u32) -> Option<&DefinitionRow> {
        None
    }
    fn register_observations(&self, _: usize) -> Vec<RegisterObservationRow> {
        Vec::new()
    }
    fn completeness(&self) -> &[CompletenessRow] {
        &[]
    }
    fn rows_for_timeline(&self, _: u64) -> Result<Vec<usize>, IndexError> {
        Ok(Vec::new())
    }
    fn rows_for_tids(&self, _: &[u32]) -> Result<Vec<usize>, IndexError> {
        Ok(Vec::new())
    }
    fn rows_for_sequence_range(&self, _: u64, _: u64) -> Result<Vec<usize>, IndexError> {
        Ok(Vec::new())
    }
    fn rows_of_kinds(&self, _: &[EventKind]) -> Result<Vec<usize>, IndexError> {
        Ok(Vec::new())
    }
    fn rows_for_modules(&self, _: &[u32]) -> Result<Vec<usize>, IndexError> {
        Ok(Vec::new())
    }
    fn rows_for_module_pc_range(&self, _: u32, _: u64, _: u64) -> Result<Vec<usize>, IndexError> {
        Ok(Vec::new())
    }
    fn rows_for_definitions(&self, _: &[u32]) -> Result<Vec<usize>, IndexError> {
        Ok(Vec::new())
    }
    fn rows_observing_register(&self, _: RegisterSlot) -> Result<Vec<usize>, IndexError> {
        Ok(Vec::new())
    }
    fn checkpoint_rows(&self) -> Result<Vec<usize>, IndexError> {
        Ok(Vec::new())
    }
    fn call_rows(&self) -> Result<Vec<usize>, IndexError> {
        Ok(Vec::new())
    }
    fn return_rows(&self) -> Result<Vec<usize>, IndexError> {
        Ok(Vec::new())
    }
    fn rows_for_semantic_categories(&self, _: &[&[u8]]) -> Result<Vec<usize>, IndexError> {
        Ok(Vec::new())
    }
    fn rows_for_semantic_names(&self, _: &[&[u8]]) -> Result<Vec<usize>, IndexError> {
        Ok(Vec::new())
    }
    fn memory_overlaps(&self, _: u64, _: u64) -> Result<Vec<usize>, IndexError> {
        Ok(Vec::new())
    }
    fn row_for_source_key(&self, _: &EventKey) -> Option<usize> {
        None
    }
    fn source_key_for_row(&self, _: usize) -> Result<Option<EventKey>, IndexError> {
        Ok(None)
    }
}

#[test]
fn task11_trace_store_view_implementers_need_no_bulk_methods() {
    let view = LegacyView {
        capabilities: ProviderCapabilities::qtrb_register_observations(),
    };
    assert_eq!(view.event_count(), 0);
}

#[test]
fn normalized_layout_identity_has_a_supported_constructor() {
    let identity = qtrace_store::NormalizedLayoutIdentity::new(7, [9; 32]);
    assert_eq!(identity.schema_version(), 7);
    assert_eq!(identity.layout_fingerprint(), [9; 32]);
}
