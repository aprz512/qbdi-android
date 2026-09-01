//! Indexed filtering and stable timeline projection over immutable trace stores.

mod filter;
mod provenance;
mod timeline;

pub use filter::{
    AddressRange, EventFilter, MemoryFilter, MnemonicFilter, RegisterFilter, SequenceRange,
};
pub use provenance::{CompletenessStatus, CompletenessSummary, DiscontinuityRow};
pub use timeline::{
    AnalysisError, EventPage, EventRow, PageCursor, ProjectionIdentity, QueryContext, QueryPlan,
    StoreIdentity, TimelineProjection, TimelineRow, query_events,
};

pub use qtrace_provider::{EventKind, MemoryDirection, RegisterSlot};

pub const STORE_CRATE: &str = qtrace_store::PROVIDER_CRATE;
