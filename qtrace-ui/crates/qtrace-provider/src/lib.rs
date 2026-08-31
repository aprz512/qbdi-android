//! Trace-input provider boundary.

mod control;
mod error;
mod flight;
mod model;
mod qtrb;
mod source;

pub use control::{
    BudgetDimension, MAX_UNGUARDED_BYTES, MAX_UNGUARDED_RECORDS, OperationAbort, WorkDelta,
    WorkGuard,
};
pub use error::{ProviderError, SourceCoordinate};
pub use flight::{
    FLIGHT_CHUNK_HEADER_BYTES, FLIGHT_DIRECTORY_ENTRY_BYTES, FLIGHT_EMERGENCY_RECORD_BYTES,
    FLIGHT_EMERGENCY_SLOT_BYTES, FLIGHT_RECORD_HEADER_BYTES, FLIGHT_SUPERBLOCK_BYTES,
    FlightProjectionDescriptor, FlightProvider, FlightRecoverySummary,
};
pub use model::{
    ArtifactDigest, CompletenessCause, CompletenessRange, CoverageGap, Discontinuity,
    DiscontinuityCause, EventKey, EventKind, EventPayload, EventRecord, EventScope,
    FragmentSourceOffsets, MAX_FRAGMENT_SOURCE_OFFSETS, ModuleDefinition, OpaqueOptionalRecord,
    Provenance, ProviderCapabilities, ProviderCounters, ProviderSummary, RangeBounds, RangeDomain,
    RegisterCheckpoint, RegisterDelta, RegisterSlot, RegisterSnapshot, RegisterValue,
    SemanticEvent, Signal, SignalHandlerBoundary, SignalHandlerPhase, SourceIdentity,
    StringDefinition, Syscall, ThreadLifecycle, ThreadLifecyclePhase, TimelineDescriptor,
    TimelineId, completeness_canonical_key, merge_canonical_completeness,
};
pub use qtrb::{
    BeginMetadata, CaptureBytes, Instruction, InstructionDefinition, Memory, MemoryAddressMode,
    MemoryDirection, MemoryOperand, OpenMode, PcRelativeKind, QtrbInput, QtrbProvider,
    RegisterDefinition, RegisterExtend, RegisterObservation, TerminalMetrics, Termination,
    TerminationIntent, TerminationKind, TraceProfile,
};
pub use source::{ByteSource, EventCursor, ReadAtSource, TraceProvider};

pub const CRATE_NAME: &str = "qtrace-provider";
