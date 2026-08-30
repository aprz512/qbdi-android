//! Trace-input provider boundary.

mod control;
mod error;
mod model;
mod qtrb;
mod source;

pub use control::{
    BudgetDimension, MAX_UNGUARDED_BYTES, MAX_UNGUARDED_RECORDS, OperationAbort, WorkDelta,
    WorkGuard,
};
pub use error::{ProviderError, SourceCoordinate};
pub use model::{
    ArtifactDigest, BeginMetadata, CompletenessCause, CompletenessRange, Discontinuity,
    DiscontinuityCause, EventKey, EventKind, EventPayload, EventRecord, FragmentSourceOffsets,
    Instruction, InstructionDefinition, MAX_FRAGMENT_SOURCE_OFFSETS, Memory, MemoryDirection,
    ModuleDefinition, OpaqueOptionalRecord, Provenance, ProviderCapabilities, ProviderCounters,
    ProviderSummary, RangeBounds, RangeDomain, SemanticEvent, Signal, SignalHandlerBoundary,
    SignalHandlerPhase, SourceIdentity, Syscall, Termination, TerminationKind, ThreadLifecycle,
    ThreadLifecyclePhase, TimelineDescriptor, TimelineId,
};
pub use qtrb::{OpenMode, QtrbProvider};
pub use source::{ByteSource, EventCursor, ReadAtSource, TraceProvider};

pub const CRATE_NAME: &str = "qtrace-provider";
