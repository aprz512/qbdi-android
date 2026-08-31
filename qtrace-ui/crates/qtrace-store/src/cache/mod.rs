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
    fs::{AtFlags, Mode, OFlags, RenameFlags, mkdirat, open, openat, renameat_with, unlinkat},
    io::Errno,
};

pub use manifest::{CacheIdentity, CacheManifest, SectionDescriptor};
pub use reader::{CacheOpen, CacheReader, MappedStoreView};
pub use writer::{CacheWriter, PublishOutcome};

const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const DIRECTORY_INSPECT_FLAGS: OFlags = OFlags::PATH
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

#[derive(Clone, Copy, Eq, PartialEq)]
enum DirectorySetupFault {
    #[cfg(test)]
    None,
    FirstIdentity,
    ModeFinalization,
    OpenedIdentity,
    FinalIdentity,
    PublishedIdentity,
}

#[cfg(test)]
type DirectoryAfterOpenHook = Box<dyn FnMut(&OsStr)>;

#[cfg(test)]
std::thread_local! {
    static INJECT_DIRECTORY_SETUP_FAULT: std::cell::Cell<DirectorySetupFault> = const { std::cell::Cell::new(DirectorySetupFault::None) };
    static INJECT_DIRECTORY_RECOVERY_RESOURCE_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static DIRECTORY_AFTER_OPEN_HOOK: std::cell::RefCell<Option<DirectoryAfterOpenHook>> = const { std::cell::RefCell::new(None) };
}

#[cfg(not(test))]
fn directory_setup_fault(_point: DirectorySetupFault) -> bool {
    false
}

#[cfg(test)]
fn directory_setup_fault(point: DirectorySetupFault) -> bool {
    INJECT_DIRECTORY_SETUP_FAULT.with(|fault| {
        if fault.get() == point {
            fault.set(DirectorySetupFault::None);
            true
        } else {
            false
        }
    })
}

fn recover_created_directory_identity(file: &File) -> Result<ObjectIdentity, CacheError> {
    #[cfg(test)]
    if INJECT_DIRECTORY_RECOVERY_RESOURCE_FAILURE.with(|fault| fault.replace(false)) {
        return Err(map_io_error(
            "injected created directory recovery fstat",
            std::io::Error::from_raw_os_error(12),
        ));
    }
    ObjectIdentity::from_file(file)
}

#[cfg(test)]
fn run_directory_after_open_hook(name: &OsStr) {
    DIRECTORY_AFTER_OPEN_HOOK.with(|slot| {
        if let Some(mut hook) = slot.borrow_mut().take() {
            hook(name);
        }
    });
}

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

    pub fn is_control(&self) -> bool {
        self.code.starts_with("control.") || self.code == "job.cancelled"
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

    pub(crate) fn permission(detail: impl Into<String>) -> Self {
        Self::new("cache.permission_denied", detail)
    }

    pub(crate) fn resource(detail: impl Into<String>) -> Self {
        Self::new("control.resource_exhausted", detail)
    }

    pub(crate) fn conflict(detail: impl Into<String>) -> Self {
        Self::new("cache.identity_conflict", detail)
    }

    pub(crate) fn with_static_context(mut self, context: &'static str) -> Self {
        const MAX_CONTEXT_BYTES: usize = 192;
        let bounded = if context.len() <= MAX_CONTEXT_BYTES {
            context
        } else {
            "cache operation failed"
        };
        self.detail = format!("{bounded}: {}", self.detail);
        self
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

pub(crate) fn map_errno(context: &str, error: Errno) -> CacheError {
    match error {
        Errno::MFILE | Errno::NFILE | Errno::NOMEM => {
            CacheError::resource(format!("{context}: {error}"))
        }
        Errno::ACCESS | Errno::PERM => CacheError::permission(format!("{context}: {error}")),
        _ => CacheError::io(format!("{context}: {error}")),
    }
}

pub(crate) fn map_io_error(context: &str, error: std::io::Error) -> CacheError {
    match error.raw_os_error() {
        Some(12 | 23 | 24) => CacheError::resource(format!("{context}: {error}")),
        Some(1 | 13) => CacheError::permission(format!("{context}: {error}")),
        _ => CacheError::io(format!("{context}: {error}")),
    }
}

pub(crate) fn allocation_error(context: &str) -> CacheError {
    CacheError::resource(format!("{context}: allocation failed"))
}

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

    pub(crate) fn key_capacity(&self) -> usize {
        self.event_keys.capacity()
    }

    pub(crate) fn kind_capacity(&self) -> usize {
        self.event_kinds.capacity()
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
    permissions: u32,
}

impl ObjectIdentity {
    fn same_object(self, other: Self) -> bool {
        self.device == other.device && self.inode == other.inode && self.kind == other.kind
    }

    fn from_file(file: &File) -> Result<Self, CacheError> {
        let metadata = file
            .metadata()
            .map_err(|error| map_io_error("cannot stat cache object", error))?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            kind: metadata.mode() & 0o170000,
            permissions: metadata.mode() & 0o7777,
        })
    }

    pub(crate) fn regular_file(file: &File) -> Result<Self, CacheError> {
        let metadata = file
            .metadata()
            .map_err(|error| map_io_error("cannot stat regular cache object", error))?;
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
            permissions: metadata.mode() & 0o7777,
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
        let root_component_count = root
            .components()
            .filter(|component| matches!(component, Component::Normal(_)))
            .count();
        if root_component_count == 0 {
            return Err(CacheError::path(
                "cache root must name a private directory component",
            ));
        }
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
            .map_err(|error| map_directory_errno("cannot open cache anchor", error))?;
        let anchor = Arc::new(File::from(descriptor));
        let mut current = anchor.clone();
        let mut components = Vec::new();
        components
            .try_reserve_exact(root.components().count().saturating_add(2))
            .map_err(|_| allocation_error("cache path proof"))?;
        let mut normal_index = 0_usize;
        for component in root.components() {
            match component {
                Component::RootDir if absolute => continue,
                Component::Normal(name) => {
                    normal_index += 1;
                    let Some(next) = open_or_create_directory(
                        &current,
                        name,
                        create,
                        normal_index == root_component_count,
                    )?
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
            let descriptor = openat(&*current, name, DIRECTORY_FLAGS, Mode::empty())
                .map_err(|error| map_directory_errno("cache directory binding changed", error))?;
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
        Err(Errno::NOENT) => create_staged_private_directory(parent, name)?.into(),
        Err(error) => {
            return Err(map_directory_errno("cannot open cache directory", error));
        }
    };
    let file = File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|error| map_io_error("cannot stat cache directory", error))?;
    if !metadata.file_type().is_dir() {
        return Err(CacheError::path("cache path component is not a directory"));
    }
    if private && metadata.mode() & 0o7777 != 0o700 {
        return Err(CacheError::path(
            "private cache directory does not have mode 0700",
        ));
    }
    Ok(Some(file))
}

fn create_staged_private_directory(parent: &File, target: &OsStr) -> Result<File, CacheError> {
    for _ in 0..32 {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|error| {
            CacheError::io(format!("cannot generate directory staging name: {error}"))
        })?;
        let staging = format!(".qtrace-dir-{}.tmp", hex::encode(random));
        match mkdirat(
            parent,
            staging.as_str(),
            Mode::RUSR | Mode::WUSR | Mode::XUSR,
        ) {
            Ok(()) => return finalize_staged_private_directory(parent, &staging, target),
            Err(Errno::EXIST) => continue,
            Err(error) => return Err(map_errno("cannot create cache directory staging", error)),
        }
    }
    Err(CacheError::io(
        "cannot allocate a unique cache directory staging name",
    ))
}

fn finalize_staged_private_directory(
    parent: &File,
    staging: &str,
    target: &OsStr,
) -> Result<File, CacheError> {
    let staging_name = OsStr::new(staging);
    let inspect_descriptor = openat(parent, staging, DIRECTORY_INSPECT_FLAGS, Mode::empty())
        .map_err(|error| map_directory_errno("cannot inspect created cache directory", error))?;
    let inspect = File::from(inspect_descriptor);
    #[cfg(test)]
    run_directory_after_open_hook(OsStr::new(staging));
    let created_identity_result = if directory_setup_fault(DirectorySetupFault::FirstIdentity) {
        Err(CacheError::io("injected first directory fstat failure"))
    } else {
        ObjectIdentity::from_file(&inspect)
    };
    let created_identity = match created_identity_result {
        Ok(identity) => identity,
        Err(error) => {
            let recovery = recover_created_directory_identity(&inspect).map_err(|proof_error| {
                proof_error.with_static_context(
                    "created directory setup failed; held identity recovery failed; staging preserved",
                )
            })?;
            return Err(cleanup_created_directory_after_error(
                parent,
                staging_name,
                recovery,
                error,
            ));
        }
    };
    verify_named_directory(parent, staging_name, created_identity)?;
    if directory_setup_fault(DirectorySetupFault::ModeFinalization) {
        return Err(cleanup_created_directory_after_error(
            parent,
            staging_name,
            created_identity,
            CacheError::io("injected directory mode finalization failure"),
        ));
    }
    if created_identity.permissions != 0o700 {
        return Err(cleanup_created_directory_after_error(
            parent,
            staging_name,
            created_identity,
            CacheError::permission(
                "cache directory staging mode was reduced by umask and safe descriptor-bound chmod is unavailable",
            ),
        ));
    }
    let descriptor = match openat(parent, staging, DIRECTORY_FLAGS, Mode::empty()) {
        Ok(descriptor) => descriptor,
        Err(error) => {
            return Err(cleanup_created_directory_after_error(
                parent,
                staging_name,
                created_identity,
                map_directory_errno("cannot open bootstrapped cache directory", error),
            ));
        }
    };
    let file = File::from(descriptor);
    let opened_identity_result = if directory_setup_fault(DirectorySetupFault::OpenedIdentity) {
        Err(CacheError::io("injected opened directory fstat failure"))
    } else {
        ObjectIdentity::from_file(&file)
    };
    let opened_identity = match opened_identity_result {
        Ok(identity) => identity,
        Err(error) => {
            return Err(cleanup_created_directory_after_error(
                parent,
                staging_name,
                created_identity,
                error,
            ));
        }
    };
    if !created_identity.same_object(opened_identity) {
        return Err(CacheError::conflict(
            "created cache directory binding changed before mode finalization",
        ));
    }
    let finalized_result = if directory_setup_fault(DirectorySetupFault::FinalIdentity) {
        Err(CacheError::io("injected final directory fstat failure"))
    } else {
        ObjectIdentity::from_file(&file)
    };
    let finalized = match finalized_result {
        Ok(identity) => identity,
        Err(error) => {
            return Err(cleanup_created_directory_after_error(
                parent,
                staging_name,
                created_identity,
                error,
            ));
        }
    };
    if !created_identity.same_object(finalized) || finalized.permissions != 0o700 {
        return Err(CacheError::conflict(
            "created cache directory mode finalization changed its identity",
        ));
    }
    verify_named_directory(parent, staging_name, finalized)?;
    match renameat_with(parent, staging, parent, target, RenameFlags::NOREPLACE) {
        Ok(()) => open_published_directory(parent, target, finalized),
        Err(Errno::EXIST) => {
            remove_created_directory(parent, staging_name, finalized)?;
            let descriptor = openat(parent, target, DIRECTORY_FLAGS, Mode::empty())
                .map_err(|error| map_directory_errno("cannot open raced cache directory", error))?;
            Ok(File::from(descriptor))
        }
        Err(error) => Err(cleanup_created_directory_after_error(
            parent,
            staging_name,
            finalized,
            map_errno("cannot publish cache directory staging", error),
        )),
    }
}

fn cleanup_created_directory_after_error(
    parent: &File,
    name: &OsStr,
    expected: ObjectIdentity,
    original: CacheError,
) -> CacheError {
    let cleanup = remove_created_directory(parent, name, expected);
    match cleanup {
        Ok(()) => original,
        Err(cleanup_error) => CacheError::conflict(format!(
            "created cache directory setup failed ({original}); cleanup was ambiguous ({cleanup_error})"
        )),
    }
}

fn verify_named_directory(
    parent: &File,
    name: &OsStr,
    expected: ObjectIdentity,
) -> Result<(), CacheError> {
    let descriptor = openat(parent, name, DIRECTORY_INSPECT_FLAGS, Mode::empty())
        .map_err(|error| map_directory_errno("cannot verify cache directory staging", error))?;
    let actual = ObjectIdentity::from_file(&File::from(descriptor))?;
    if actual != expected {
        return Err(CacheError::conflict(
            "cache directory staging binding changed during setup",
        ));
    }
    Ok(())
}

fn open_published_directory(
    parent: &File,
    target: &OsStr,
    expected: ObjectIdentity,
) -> Result<File, CacheError> {
    let descriptor = match openat(parent, target, DIRECTORY_FLAGS, Mode::empty()) {
        Ok(descriptor) => descriptor,
        Err(error) => {
            return Err(cleanup_created_directory_after_error(
                parent,
                target,
                expected,
                map_directory_errno("cannot open published cache directory", error),
            ));
        }
    };
    let file = File::from(descriptor);
    let actual_result = if directory_setup_fault(DirectorySetupFault::PublishedIdentity) {
        Err(CacheError::io("injected published directory fstat failure"))
    } else {
        ObjectIdentity::from_file(&file)
    };
    let actual = match actual_result {
        Ok(identity) => identity,
        Err(error) => {
            return Err(cleanup_created_directory_after_error(
                parent, target, expected, error,
            ));
        }
    };
    if actual != expected {
        return Err(CacheError::conflict(
            "published cache directory binding does not match its staging identity",
        ));
    }
    Ok(file)
}

fn remove_created_directory(
    parent: &File,
    name: &OsStr,
    expected: ObjectIdentity,
) -> Result<(), CacheError> {
    let descriptor = openat(parent, name, DIRECTORY_INSPECT_FLAGS, Mode::empty())
        .map_err(|error| map_directory_errno("cannot recheck created cache directory", error))?;
    let actual = ObjectIdentity::from_file(&File::from(descriptor))?;
    if !expected.same_object(actual) {
        return Err(CacheError::conflict(
            "refusing to remove a replaced cache directory",
        ));
    }
    unlinkat(parent, name, AtFlags::REMOVEDIR)
        .map_err(|error| map_errno("cannot remove failed cache directory", error))
}

fn map_directory_errno(context: &str, error: Errno) -> CacheError {
    match error {
        Errno::LOOP | Errno::NOTDIR => CacheError::path(format!("{context}: {error}")),
        _ => map_errno(context, error),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::OsStr,
        fs::{self, File},
        os::unix::fs::{MetadataExt, PermissionsExt},
    };

    use super::{
        DIRECTORY_AFTER_OPEN_HOOK, DirectorySetupFault, INJECT_DIRECTORY_RECOVERY_RESOURCE_FAILURE,
        INJECT_DIRECTORY_SETUP_FAULT, PublicationState, allocation_error, map_errno,
        open_or_create_directory,
    };
    use rustix::io::Errno;
    use tempfile::TempDir;

    #[test]
    fn resource_failures_have_one_stable_control_code() {
        for error in [Errno::MFILE, Errno::NFILE, Errno::NOMEM] {
            let mapped = map_errno("injected syscall", error);
            assert_eq!(mapped.code(), "control.resource_exhausted");
            assert!(mapped.is_control());
        }
        let mapped = allocation_error("injected reserve");
        assert_eq!(mapped.code(), "control.resource_exhausted");
        assert!(mapped.is_control());
    }

    #[test]
    fn permission_and_ordinary_io_do_not_collapse_into_path_or_rebuild() {
        assert_eq!(
            map_errno("injected syscall", Errno::ACCESS).code(),
            "cache.permission_denied"
        );
        assert_eq!(map_errno("injected syscall", Errno::IO).code(), "cache.io");
    }

    #[test]
    fn created_directory_setup_failures_remove_the_new_component() {
        for fault in [
            DirectorySetupFault::FirstIdentity,
            DirectorySetupFault::ModeFinalization,
            DirectorySetupFault::OpenedIdentity,
            DirectorySetupFault::FinalIdentity,
            DirectorySetupFault::PublishedIdentity,
        ] {
            let parent = TempDir::new().expect("parent");
            let parent_file = File::open(parent.path()).expect("parent descriptor");
            INJECT_DIRECTORY_SETUP_FAULT.with(|injected| injected.set(fault));
            let error = open_or_create_directory(&parent_file, OsStr::new("created"), true, true)
                .expect_err("injected directory setup failure must fail");
            assert_eq!(error.code(), "cache.io");
            assert_eq!(
                fs::read_dir(parent.path())
                    .expect("parent entries")
                    .filter_map(Result::ok)
                    .count(),
                0,
                "created directory or staging leaked after injected setup failure"
            );
        }
    }

    #[test]
    fn created_directory_recovery_resource_error_remains_control() {
        let parent = TempDir::new().expect("parent");
        let parent_file = File::open(parent.path()).expect("parent descriptor");
        INJECT_DIRECTORY_SETUP_FAULT
            .with(|injected| injected.set(DirectorySetupFault::FirstIdentity));
        INJECT_DIRECTORY_RECOVERY_RESOURCE_FAILURE.with(|injected| injected.set(true));

        let error = open_or_create_directory(&parent_file, OsStr::new("created"), true, true)
            .expect_err("both directory identity checks must fail");

        assert_eq!(error.code(), "control.resource_exhausted");
        assert!(error.is_control());
        assert_eq!(error.publication_state(), PublicationState::NoVisibleFinal);
        assert!(!parent.path().join("created").exists());
        assert_eq!(
            fs::read_dir(parent.path())
                .expect("parent entries")
                .filter_map(Result::ok)
                .count(),
            1,
            "unproved staging must be preserved"
        );
    }

    fn install_directory_name_rebind(parent: &std::path::Path) -> File {
        let foreign = parent.join("foreign");
        fs::create_dir(&foreign).expect("foreign directory");
        fs::set_permissions(&foreign, fs::Permissions::from_mode(0o755)).expect("foreign mode");
        let foreign_file = File::open(&foreign).expect("foreign descriptor");
        let parent = parent.to_owned();
        DIRECTORY_AFTER_OPEN_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move |name| {
                fs::rename(parent.join(name), parent.join("held-created"))
                    .expect("hold created directory");
                fs::rename(parent.join("foreign"), parent.join(name))
                    .expect("replace created name");
            }));
        });
        foreign_file
    }

    #[test]
    fn created_directory_name_rebind_never_chmods_the_replacement() {
        let parent = TempDir::new().expect("parent");
        let foreign = install_directory_name_rebind(parent.path());
        let parent_file = File::open(parent.path()).expect("parent descriptor");
        let error = open_or_create_directory(&parent_file, OsStr::new("created"), true, true)
            .expect_err("rebound created name must fail closed");
        assert!(
            matches!(
                error.code(),
                "cache.identity_conflict" | "cache.path_escape"
            ),
            "unexpected rebind error: {error}"
        );
        let metadata = foreign.metadata().expect("foreign metadata");
        assert_eq!(metadata.mode() & 0o7777, 0o755);
        assert_eq!(metadata.nlink(), 2, "foreign directory was unlinked");
    }

    #[test]
    fn first_directory_fstat_failure_never_unlinks_a_replacement() {
        let parent = TempDir::new().expect("parent");
        let foreign = install_directory_name_rebind(parent.path());
        let parent_file = File::open(parent.path()).expect("parent descriptor");
        INJECT_DIRECTORY_SETUP_FAULT
            .with(|injected| injected.set(DirectorySetupFault::FirstIdentity));
        let error = open_or_create_directory(&parent_file, OsStr::new("created"), true, true)
            .expect_err("first fstat failure with rebind must fail closed");
        assert_eq!(error.code(), "cache.identity_conflict");
        let metadata = foreign.metadata().expect("foreign metadata");
        assert_eq!(metadata.mode() & 0o7777, 0o755);
        assert_eq!(metadata.nlink(), 2, "foreign directory was unlinked");
    }
}
