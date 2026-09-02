//! Trace-storage boundary.

mod allocation;
mod annotation_vfs;
mod annotations;
mod cache;
mod identity;
mod index;
mod layout;
mod manifest;
mod secure_path;
mod session;
mod symbols;

pub use annotations::{
    AnnotationError, AnnotationOpenRequest, AnnotationStore, AnnotationTransaction,
    EventAnnotation, Highlight, LocalSymbolName,
};

pub use cache::{
    CacheError, CacheIdentity, CacheIdentityField, CacheManifest, CacheOpen, CacheReader,
    CacheWriter, MappedStoreView, OwnedStoreView, PublicationState, PublishOutcome, RebuildReason,
    SectionDescriptor, StoreView,
};
pub use identity::{FileIdentity, SourceIdentity};
pub use index::{
    BuildOptions, CompletenessRow, DefinitionRow, IndexBuilder, IndexError, InstructionRow,
    MappedTraceStore, MemoryRow, ModuleRow, NormalizedBulkView, NormalizedContentIdentity,
    NormalizedLayoutIdentity, NormalizedPostingEstimate, NormalizedPostingQuery,
    NormalizedSourceFormat, OwnedTraceStore, PostingList, RegisterAccess, RegisterObservationRow,
    Rows, SemanticDictionaryFamily, SemanticDictionaryWork, SemanticRow, TraceStore,
    TraceStoreView, intersect_rows,
};
pub use session::{
    ArtifactFailure, ArtifactFormat, ArtifactMetadata, ArtifactSource, AuthorizedPath, OpenPolicy,
    SessionCapabilities, SessionCapability, SessionLoader, SessionSource, SessionWarning,
};
pub use symbols::{
    ElfLoadRequest, ElfProducerIdentity, ElfSymbolIndex, ElfSymbolMatch, ModuleIdentity,
    SymbolError,
};

pub const PROVIDER_CRATE: &str = qtrace_provider::CRATE_NAME;
