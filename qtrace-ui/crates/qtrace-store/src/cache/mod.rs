mod manifest;
mod reader;
mod writer;

use std::{
    error::Error,
    ffi::{OsStr, OsString},
    fmt,
    fs::File,
    os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, MetadataExt},
    },
    path::{Component, Path},
    sync::Arc,
};

use qtrace_provider::{EventKey, EventKind, OperationAbort, WorkDelta, WorkGuard};
use rustix::{
    fs::{Mode, OFlags, mkdirat, open, openat},
    io::Errno,
};

pub use manifest::{CacheIdentity, CacheManifest, SectionDescriptor};
pub use reader::{CacheOpen, CacheReader, MappedStoreView};
pub use writer::{CacheWriter, PublishOutcome};

const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheIdentityField {
    AnalyzerVersion,
    ArtifactDigest,
    BuildOptionDigest,
    CacheSchema,
    Endian,
    LayoutVersion,
    SourceFeatures,
    SourceFormat,
    SourceMajor,
    SourceMinor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RebuildReason {
    Header(&'static str),
    IdentityMismatch(CacheIdentityField),
    Manifest(&'static str),
    Section(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationState {
    NoVisibleFinal,
    VisibleDurabilityUncertain,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheError {
    code: &'static str,
    detail: String,
    publication_state: PublicationState,
}

impl CacheError {
    pub fn code(&self) -> &'static str {
        self.code
    }

    pub const fn publication_state(&self) -> PublicationState {
        self.publication_state
    }

    pub(crate) fn invalid(detail: impl Into<String>) -> Self {
        Self::new("cache.invalid_argument", detail)
    }

    pub(crate) fn access(detail: impl Into<String>) -> Self {
        Self::new("cache.access", detail)
    }

    pub(crate) fn identity(detail: impl Into<String>) -> Self {
        Self::new("cache.identity_changed", detail)
    }

    pub(crate) fn path(detail: impl Into<String>) -> Self {
        Self::new("cache.path_escape", detail)
    }

    pub(crate) fn io(detail: impl Into<String>) -> Self {
        Self::new("cache.io", detail)
    }

    pub(crate) fn conflict(detail: impl Into<String>) -> Self {
        Self::new("cache.identity_conflict", detail)
    }

    pub(crate) fn durability(detail: impl Into<String>) -> Self {
        Self {
            code: "cache.durability_uncertain",
            detail: detail.into(),
            publication_state: PublicationState::VisibleDurabilityUncertain,
        }
    }

    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
            publication_state: PublicationState::NoVisibleFinal,
        }
    }
}

impl From<OperationAbort> for CacheError {
    fn from(error: OperationAbort) -> Self {
        let code = match error {
            OperationAbort::Cancelled => "job.cancelled",
            OperationAbort::BudgetExceeded { .. } => "control.budget_exceeded",
        };
        Self::new(code, error.to_string())
    }
}

impl From<RebuildReason> for CacheError {
    fn from(reason: RebuildReason) -> Self {
        Self::access(format!("invalid cache bytes: {reason:?}"))
    }
}

impl fmt::Display for CacheError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl Error for CacheError {}

pub trait StoreView {
    fn event_count(&self) -> usize;
    fn event_key(&self, row: usize) -> Result<EventKey, CacheError>;
    fn event_kind(&self, row: usize) -> Result<EventKind, CacheError>;
}

#[derive(Clone, Debug)]
pub struct OwnedStoreView {
    event_keys: Vec<EventKey>,
    event_kinds: Vec<EventKind>,
}

impl OwnedStoreView {
    pub fn new(event_keys: Vec<EventKey>, event_kinds: Vec<EventKind>) -> Result<Self, CacheError> {
        if event_keys.len() != event_kinds.len() {
            return Err(CacheError::invalid("event key and kind counts differ"));
        }
        Ok(Self {
            event_keys,
            event_kinds,
        })
    }

    pub(crate) fn keys(&self) -> &[EventKey] {
        &self.event_keys
    }

    pub(crate) fn kinds(&self) -> &[EventKind] {
        &self.event_kinds
    }
}

impl StoreView for OwnedStoreView {
    fn event_count(&self) -> usize {
        self.event_keys.len()
    }

    fn event_key(&self, row: usize) -> Result<EventKey, CacheError> {
        self.event_keys
            .get(row)
            .cloned()
            .ok_or_else(|| CacheError::access("event row is out of range"))
    }

    fn event_kind(&self, row: usize) -> Result<EventKind, CacheError> {
        self.event_kinds
            .get(row)
            .copied()
            .ok_or_else(|| CacheError::access("event row is out of range"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ObjectIdentity {
    device: u64,
    inode: u64,
    kind: u32,
}

impl ObjectIdentity {
    fn from_file(file: &File) -> Result<Self, CacheError> {
        let metadata = file
            .metadata()
            .map_err(|error| CacheError::io(error.to_string()))?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            kind: metadata.mode() & 0o170000,
        })
    }

    pub(crate) fn regular_file(file: &File) -> Result<Self, CacheError> {
        let metadata = file
            .metadata()
            .map_err(|error| CacheError::io(error.to_string()))?;
        let kind = metadata.file_type();
        if !kind.is_file()
            || kind.is_symlink()
            || kind.is_socket()
            || kind.is_fifo()
            || kind.is_block_device()
            || kind.is_char_device()
        {
            return Err(CacheError::path("cache leaf is not a regular file"));
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            kind: metadata.mode() & 0o170000,
        })
    }
}

#[derive(Debug)]
pub(crate) struct CacheDirectory {
    pub(crate) file: Arc<File>,
    anchor: Arc<File>,
    components: Vec<(OsString, ObjectIdentity)>,
}

impl CacheDirectory {
    pub(crate) fn open(
        root: &Path,
        key: &str,
        create: bool,
        guard: &dyn WorkGuard,
    ) -> Result<Option<Self>, CacheError> {
        if key.len() != 64 || !key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(CacheError::invalid("cache key is not a SHA-256 hex digest"));
        }
        if root.as_os_str().as_bytes().len() > 4096 {
            return Err(CacheError::path("cache root exceeds its byte limit"));
        }
        let absolute = root.is_absolute();
        let component_count = root
            .components()
            .count()
            .checked_add(2)
            .ok_or_else(|| CacheError::path("cache path component count overflow"))?;
        if component_count > 256 {
            return Err(CacheError::path("cache root has too many components"));
        }
        let proof_bytes = component_count
            .checked_mul(128)
            .and_then(|value| u64::try_from(value).ok())
            .ok_or_else(|| CacheError::path("cache path proof size overflow"))?;
        guard.consume(WorkDelta {
            nodes: component_count as u64,
            resident_bytes: proof_bytes,
            ..WorkDelta::default()
        })?;
        let start = if absolute {
            Path::new("/")
        } else {
            Path::new(".")
        };
        let descriptor = open(start, DIRECTORY_FLAGS, Mode::empty())
            .map_err(|error| CacheError::path(format!("cannot open cache anchor: {error}")))?;
        let anchor = Arc::new(File::from(descriptor));
        let mut current = anchor.clone();
        let mut components = Vec::new();
        components
            .try_reserve_exact(root.components().count().saturating_add(2))
            .map_err(|_| CacheError::io("cache path proof allocation failed"))?;
        for component in root.components() {
            match component {
                Component::RootDir if absolute => continue,
                Component::Normal(name) => {
                    let Some(next) = open_or_create_directory(&current, name, create, false)?
                    else {
                        return Ok(None);
                    };
                    let identity = ObjectIdentity::from_file(&next)?;
                    components.push((name.to_owned(), identity));
                    current = Arc::new(next);
                }
                _ => return Err(CacheError::path("cache root contains an unsafe component")),
            }
        }
        for name in [OsStr::new("qtrace-ui"), OsStr::new(key)] {
            let Some(next) = open_or_create_directory(&current, name, create, true)? else {
                return Ok(None);
            };
            let identity = ObjectIdentity::from_file(&next)?;
            components.push((name.to_owned(), identity));
            current = Arc::new(next);
        }
        Ok(Some(Self {
            file: current,
            anchor,
            components,
        }))
    }

    pub(crate) fn verify(&self) -> Result<(), CacheError> {
        let mut current = self.anchor.clone();
        for (name, expected) in &self.components {
            let descriptor =
                openat(&*current, name, DIRECTORY_FLAGS, Mode::empty()).map_err(|error| {
                    CacheError::path(format!("cache directory binding changed: {error}"))
                })?;
            let next = File::from(descriptor);
            let actual = ObjectIdentity::from_file(&next)?;
            if actual != *expected {
                return Err(CacheError::path(
                    "cache directory identity changed during operation",
                ));
            }
            current = Arc::new(next);
        }
        Ok(())
    }
}

fn open_or_create_directory(
    parent: &File,
    name: &OsStr,
    create: bool,
    private: bool,
) -> Result<Option<File>, CacheError> {
    let descriptor = match openat(parent, name, DIRECTORY_FLAGS, Mode::empty()) {
        Ok(descriptor) => descriptor,
        Err(Errno::NOENT) if !create => return Ok(None),
        Err(Errno::NOENT) => {
            match mkdirat(parent, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
                Ok(()) | Err(Errno::EXIST) => {}
                Err(error) => {
                    return Err(CacheError::io(format!(
                        "cannot create cache directory: {error}"
                    )));
                }
            }
            openat(parent, name, DIRECTORY_FLAGS, Mode::empty()).map_err(|error| {
                CacheError::path(format!("cannot open created cache directory: {error}"))
            })?
        }
        Err(error) => {
            return Err(CacheError::path(format!(
                "cannot open cache directory: {error}"
            )));
        }
    };
    let file = File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|error| CacheError::io(error.to_string()))?;
    if !metadata.file_type().is_dir() {
        return Err(CacheError::path("cache path component is not a directory"));
    }
    if private && metadata.mode() & 0o777 != 0o700 {
        return Err(CacheError::path(
            "application cache directory does not have mode 0700",
        ));
    }
    Ok(Some(file))
}
