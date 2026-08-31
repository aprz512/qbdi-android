//! Trace-storage boundary.

mod allocation;
mod cache;
mod identity;
mod index;
mod layout;
mod manifest;
mod secure_path;
mod session;

pub use cache::{
    CacheError, CacheIdentity, CacheIdentityField, CacheManifest, CacheOpen, CacheReader,
    CacheWriter, MappedStoreView, OwnedStoreView, PublicationState, PublishOutcome, RebuildReason,
    SectionDescriptor, StoreView,
};
pub use identity::{FileIdentity, SourceIdentity};
pub use index::{
    BuildOptions, CompletenessRow, DefinitionRow, IndexBuilder, IndexError, InstructionRow,
    MappedTraceStore, MemoryRow, ModuleRow, OwnedTraceStore, PostingList, RegisterAccess,
    RegisterObservationRow, Rows, SemanticRow, TraceStore, TraceStoreView, intersect_rows,
};
pub use session::{
    ArtifactFailure, ArtifactFormat, ArtifactMetadata, ArtifactSource, AuthorizedPath, OpenPolicy,
    SessionCapabilities, SessionCapability, SessionLoader, SessionSource, SessionWarning,
};

pub const PROVIDER_CRATE: &str = qtrace_provider::CRATE_NAME;
