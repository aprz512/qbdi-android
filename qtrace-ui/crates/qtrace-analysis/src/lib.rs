//! Indexed filtering and stable timeline projection over immutable trace stores.

mod filter;
mod memory;
mod provenance;
mod registers;
mod symbolize;
mod timeline;

pub use filter::{
    AddressRange, EventFilter, MemoryFilter, MnemonicFilter, RegisterFilter, SequenceRange,
};
pub use memory::{ByteState, MemoryAnalyzer, MemoryEvidence, MemoryStateAtEvent};
pub use provenance::{CompletenessStatus, CompletenessSummary, DiscontinuityRow};
pub use registers::{RegisterCell, RegisterReplay, RegisterSnapshotState, RegisterStateAtEvent};
pub use symbolize::{ResolvedSymbol, SymbolResolveError, SymbolResolver};
pub use timeline::{
    AnalysisError, EventPage, EventRow, MAX_CONTEXT_DICTIONARY_ENTRIES, MAX_CONTEXT_EVENTS,
    MAX_CONTEXT_TYPED_ROWS, MAX_DISCONTINUITY_PAYLOAD_BYTES, MAX_DISCONTINUITY_TOTAL_BYTES,
    PageCursor, ProjectionIdentity, QueryContext, QueryPlan, StoreIdentity, TimelineProjection,
    TimelineRow, query_events,
};

pub use qtrace_provider::{EventKind, MemoryDirection, RegisterSlot};

pub const STORE_CRATE: &str = qtrace_store::PROVIDER_CRATE;
