use std::{fs::Metadata, os::unix::fs::MetadataExt, path::PathBuf};

use qtrace_provider::SourceIdentity as ProviderSourceIdentity;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileIdentity {
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub modified_seconds: i64,
    pub modified_nanoseconds: i64,
    pub changed_seconds: i64,
    pub changed_nanoseconds: i64,
}

impl FileIdentity {
    pub(crate) fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.size(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceIdentity {
    display_path: PathBuf,
    file: FileIdentity,
    provider: ProviderSourceIdentity,
}

impl SourceIdentity {
    pub(crate) fn new(
        display_path: PathBuf,
        file: FileIdentity,
        provider: ProviderSourceIdentity,
    ) -> Self {
        Self {
            display_path,
            file,
            provider,
        }
    }

    pub fn display_path(&self) -> &std::path::Path {
        &self.display_path
    }

    pub const fn file(&self) -> &FileIdentity {
        &self.file
    }

    pub const fn provider(&self) -> &ProviderSourceIdentity {
        &self.provider
    }
}
