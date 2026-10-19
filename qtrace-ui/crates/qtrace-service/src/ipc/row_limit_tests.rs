//! Protocol boundary tests use only view metadata; no multi-billion-row allocation is needed.
#![allow(unused_variables)]
use qtrace_provider::{EventKey, EventKind, Provenance, ProviderCapabilities, RegisterSlot};
use qtrace_store::{
    CompletenessRow, DefinitionRow, IndexError, InstructionRow, MemoryRow, ModuleRow,
    RegisterObservationRow, SemanticRow, TraceStoreView,
};

struct MetadataOnlyView(usize);
impl TraceStoreView for MetadataOnlyView {
    fn event_count(&self) -> usize {
        self.0
    }
    fn event_key(&self, row: usize) -> Result<Option<EventKey>, IndexError> {
        panic!("row data must not be inspected before row-count admission")
    }
    fn event_kind(&self, row: usize) -> Result<Option<EventKind>, IndexError> {
        panic!("row data must not be inspected before row-count admission")
    }
    fn provenance(&self, row: usize) -> Result<Option<Provenance>, IndexError> {
        panic!("row data must not be inspected before row-count admission")
    }
    fn capabilities(&self) -> &ProviderCapabilities {
        panic!("row data must not be inspected before row-count admission")
    }
    fn instruction(&self, event_row: usize) -> Option<InstructionRow> {
        panic!("row data must not be inspected before row-count admission")
    }
    fn memory(&self, event_row: usize) -> Option<MemoryRow> {
        panic!("row data must not be inspected before row-count admission")
    }
    fn semantic(&self, event_row: usize) -> Option<SemanticRow> {
        panic!("row data must not be inspected before row-count admission")
    }
    fn payload_bytes(&self, event_row: usize) -> Result<&[u8], IndexError> {
        panic!("row data must not be inspected before row-count admission")
    }
    fn string_bytes(&self, string_id: u32) -> Result<&[u8], IndexError> {
        panic!("row data must not be inspected before row-count admission")
    }
    fn blob_bytes(&self, blob_id: u32) -> Result<&[u8], IndexError> {
        panic!("row data must not be inspected before row-count admission")
    }
    fn memory_before_bytes(&self, event_row: usize) -> Result<Option<&[u8]>, IndexError> {
        panic!("row data must not be inspected before row-count admission")
    }
    fn memory_after_bytes(&self, event_row: usize) -> Result<Option<&[u8]>, IndexError> {
        panic!("row data must not be inspected before row-count admission")
    }
    fn module(&self, module: u32) -> Option<&ModuleRow> {
        panic!("row data must not be inspected before row-count admission")
    }
    fn definition(&self, definition: u32) -> Option<&DefinitionRow> {
        panic!("row data must not be inspected before row-count admission")
    }
    fn register_observations(&self, event_row: usize) -> Vec<RegisterObservationRow> {
        panic!("row data must not be inspected before row-count admission")
    }
    fn completeness(&self) -> &[CompletenessRow] {
        panic!("row data must not be inspected before row-count admission")
    }
    fn rows_for_timeline(&self, timeline: u64) -> Result<Vec<usize>, IndexError> {
        panic!("row data must not be inspected before row-count admission")
    }
    fn rows_for_tids(&self, tids: &[u32]) -> Result<Vec<usize>, IndexError> {
        panic!("row data must not be inspected before row-count admission")
    }
    fn rows_for_sequence_range(
        &self,
        start: u64,
        end_exclusive: u64,
    ) -> Result<Vec<usize>, IndexError> {
        panic!("row data must not be inspected before row-count admission")
    }
    fn rows_of_kinds(&self, kinds: &[EventKind]) -> Result<Vec<usize>, IndexError> {
        panic!("row data must not be inspected before row-count admission")
    }
    fn rows_for_modules(&self, modules: &[u32]) -> Result<Vec<usize>, IndexError> {
        panic!("row data must not be inspected before row-count admission")
    }
    fn rows_for_module_pc_range(
        &self,
        module: u32,
        start: u64,
        end_exclusive: u64,
    ) -> Result<Vec<usize>, IndexError> {
        panic!("row data must not be inspected before row-count admission")
    }
    fn rows_for_definitions(&self, definitions: &[u32]) -> Result<Vec<usize>, IndexError> {
        panic!("row data must not be inspected before row-count admission")
    }
    fn rows_observing_register(&self, slot: RegisterSlot) -> Result<Vec<usize>, IndexError> {
        panic!("row data must not be inspected before row-count admission")
    }
    fn checkpoint_rows(&self) -> Result<Vec<usize>, IndexError> {
        panic!("row data must not be inspected before row-count admission")
    }
    fn call_rows(&self) -> Result<Vec<usize>, IndexError> {
        panic!("row data must not be inspected before row-count admission")
    }
    fn return_rows(&self) -> Result<Vec<usize>, IndexError> {
        panic!("row data must not be inspected before row-count admission")
    }
    fn rows_for_semantic_categories(&self, categories: &[&[u8]]) -> Result<Vec<usize>, IndexError> {
        panic!("row data must not be inspected before row-count admission")
    }
    fn rows_for_semantic_names(&self, names: &[&[u8]]) -> Result<Vec<usize>, IndexError> {
        panic!("row data must not be inspected before row-count admission")
    }
    fn memory_overlaps(&self, start: u64, end_exclusive: u64) -> Result<Vec<usize>, IndexError> {
        panic!("row data must not be inspected before row-count admission")
    }
    fn row_for_source_key(&self, key: &EventKey) -> Option<usize> {
        panic!("row data must not be inspected before row-count admission")
    }
    fn source_key_for_row(&self, row: usize) -> Result<Option<EventKey>, IndexError> {
        panic!("row data must not be inspected before row-count admission")
    }
}

#[test]
fn simulated_view_over_u32_rows_is_rejected_without_reading_any_row() {
    let supported = MetadataOnlyView(u32::MAX as usize);
    assert_eq!(super::view_event_count(&supported).unwrap(), u32::MAX);
    if let Ok(count) = usize::try_from(u64::from(u32::MAX) + 1) {
        let error = super::view_event_count(&MetadataOnlyView(count)).unwrap_err();
        let json = serde_json::to_value(error).unwrap();
        assert_eq!(json["code"], "workspace.event_limit_exceeded");
        assert_eq!(json["stage"], "open");
        assert_eq!(json["retryable"], false);
    }
}
