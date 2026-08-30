//! Trace-storage boundary.

mod identity;
mod manifest;
mod secure_path;
mod session;

pub use identity::{FileIdentity, SourceIdentity};
pub use session::{
    ArtifactFailure, ArtifactFormat, ArtifactMetadata, ArtifactSource, AuthorizedPath, OpenPolicy,
    SessionCapabilities, SessionCapability, SessionLoader, SessionSource, SessionWarning,
};

pub const PROVIDER_CRATE: &str = qtrace_provider::CRATE_NAME;
