//! Trace-storage boundary.

mod cache;
mod identity;
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
pub use session::{
    ArtifactFailure, ArtifactFormat, ArtifactMetadata, ArtifactSource, AuthorizedPath, OpenPolicy,
    SessionCapabilities, SessionCapability, SessionLoader, SessionSource, SessionWarning,
};

pub const PROVIDER_CRATE: &str = qtrace_provider::CRATE_NAME;
