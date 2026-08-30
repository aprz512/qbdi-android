use std::{
    ffi::{OsStr, OsString},
    fs::{File, Metadata},
    os::unix::fs::{FileExt, FileTypeExt},
    path::{Component, Path},
    sync::Arc,
};

use qtrace_provider::{ProviderError, ReadAtSource, SourceCoordinate, WorkDelta, WorkGuard};
use rustix::fs::{Mode, OFlags, open, openat};

use crate::FileIdentity;

const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const FILE_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

#[derive(Debug)]
pub(crate) struct SecureRoot {
    directory: Arc<File>,
    binding: DirectoryBinding,
}

impl SecureRoot {
    pub(crate) fn open(path: &Path) -> Result<Self, ProviderError> {
        let (directory, binding) = walk_directory(path)?;
        Ok(Self { directory, binding })
    }

    pub(crate) fn open_file(&self, relative: &str) -> Result<SecureFile, ProviderError> {
        let components = validated_relative_components(relative)?;
        let (leaf, parents) = components
            .split_last()
            .ok_or_else(|| path_error("artifact path is empty"))?;
        let root = self.directory.clone();
        let mut parent = root.clone();
        let mut parent_components = Vec::new();
        parent_components
            .try_reserve_exact(parents.len())
            .map_err(|_| resource_error("source directory proof allocation failed"))?;
        for component in parents {
            let child = Arc::new(open_directory_at(&parent, component)?);
            let identity = directory_identity(&child)?;
            parent_components.push(((*component).to_owned(), identity));
            parent = child;
        }
        let descriptor = openat(&*parent, *leaf, FILE_FLAGS, Mode::empty())
            .map_err(|error| path_error(format!("cannot open regular source leaf: {error}")))?;
        let file = Arc::new(File::from(descriptor));
        ensure_regular(&file.metadata().map_err(io_error)?)?;
        Ok(SecureFile {
            file,
            root,
            root_binding: self.binding.clone(),
            parent_components,
            leaf: (*leaf).to_owned(),
        })
    }
}

#[derive(Clone, Debug)]
struct DirectoryBinding {
    anchor: Arc<File>,
    components: Vec<(OsString, FileIdentity)>,
}

impl DirectoryBinding {
    fn verify(&self) -> Result<(), ProviderError> {
        let mut directory = self.anchor.clone();
        for (component, expected) in &self.components {
            let child = Arc::new(open_directory_at(&directory, component)?);
            let actual = directory_identity(&child)?;
            if actual.device != expected.device || actual.inode != expected.inode {
                return Err(path_error(
                    "selected session directory was replaced during read",
                ));
            }
            directory = child;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SecureFile {
    file: Arc<File>,
    root: Arc<File>,
    root_binding: DirectoryBinding,
    parent_components: Vec<(OsString, FileIdentity)>,
    leaf: OsString,
}

impl SecureFile {
    pub(crate) fn identity(&self) -> Result<FileIdentity, ProviderError> {
        let metadata = self.file.metadata().map_err(io_error)?;
        ensure_regular(&metadata)?;
        Ok(FileIdentity::from_metadata(&metadata))
    }

    pub(crate) fn read_bounded(
        &self,
        maximum: u64,
        guard: &dyn WorkGuard,
    ) -> Result<Vec<u8>, ProviderError> {
        let before = self.identity()?;
        if before.size == 0 || before.size > maximum {
            return Err(ProviderError::new(
                "session.manifest_invalid",
                "session.manifest",
                None,
                false,
                "report is empty or exceeds its byte limit",
            ));
        }
        guard.consume(WorkDelta {
            input_bytes: before.size,
            resident_bytes: before.size,
            ..WorkDelta::default()
        })?;
        let size =
            usize::try_from(before.size).map_err(|_| resource_error("file size overflow"))?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(size)
            .map_err(|_| resource_error("file allocation failed"))?;
        output.resize(size, 0);
        self.read_exact_at_unchecked(0, &mut output)?;
        self.verify_unchanged(before, true)?;
        Ok(output)
    }

    pub(crate) fn read_all_held(&self, guard: &dyn WorkGuard) -> Result<Vec<u8>, ProviderError> {
        let before = self.identity()?;
        guard.consume(WorkDelta {
            input_bytes: before.size,
            resident_bytes: before.size,
            ..WorkDelta::default()
        })?;
        let size =
            usize::try_from(before.size).map_err(|_| resource_error("file size overflow"))?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(size)
            .map_err(|_| resource_error("file allocation failed"))?;
        output.resize(size, 0);
        self.read_exact_at_unchecked(0, &mut output)?;
        self.verify_unchanged(before, false)?;
        Ok(output)
    }

    pub(crate) fn read_exact_at_unchecked(
        &self,
        offset: u64,
        output: &mut [u8],
    ) -> Result<(), ProviderError> {
        let mut filled = 0_usize;
        while filled < output.len() {
            let current = offset
                .checked_add(filled as u64)
                .ok_or_else(|| identity_error("source offset overflow"))?;
            match self.file.read_at(&mut output[filled..], current) {
                Ok(0) => return Err(identity_error("source shrank during descriptor read")),
                Ok(count) if count <= output.len() - filled => filled += count,
                Ok(_) => return Err(identity_error("source read over-reported bytes")),
                Err(error) => return Err(identity_error(format!("source read failed: {error}"))),
            }
        }
        Ok(())
    }

    pub(crate) fn verify_unchanged(
        &self,
        before: FileIdentity,
        verify_binding: bool,
    ) -> Result<(), ProviderError> {
        let after = self.identity()?;
        if verify_binding {
            self.root_binding.verify()?;
            let mut rebound_parent = self.root.clone();
            for (component, expected) in &self.parent_components {
                let child = Arc::new(open_directory_at(&rebound_parent, component)?);
                let actual = directory_identity(&child)?;
                if actual.device != expected.device || actual.inode != expected.inode {
                    return Err(path_error(
                        "source parent directory was replaced during read",
                    ));
                }
                rebound_parent = child;
            }
            let rebound = openat(&*rebound_parent, &self.leaf, FILE_FLAGS, Mode::empty())
                .map_err(|error| path_error(format!("source path changed during read: {error}")))?;
            let rebound = File::from(rebound);
            let rebound_metadata = rebound.metadata().map_err(io_error)?;
            ensure_regular(&rebound_metadata)?;
            let rebound_identity = FileIdentity::from_metadata(&rebound_metadata);
            if rebound_identity.device != before.device || rebound_identity.inode != before.inode {
                return Err(path_error("source path was replaced during read"));
            }
        }
        if after != before {
            return Err(identity_error("source identity changed during read"));
        }
        Ok(())
    }

    pub(crate) fn source(&self, length: u64) -> Arc<dyn ReadAtSource> {
        Arc::new(FileSource {
            file: self.file.clone(),
            length,
        })
    }

    pub(crate) fn reader(&self) -> FileReader {
        FileReader {
            file: self.file.clone(),
            offset: 0,
        }
    }
}

struct FileSource {
    file: Arc<File>,
    length: u64,
}

impl ReadAtSource for FileSource {
    fn len(&self) -> u64 {
        self.length
    }

    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), ProviderError> {
        let end = offset
            .checked_add(output.len() as u64)
            .ok_or_else(|| short_read(offset, output.len() as u64, self.length))?;
        if end > self.length {
            return Err(short_read(offset, output.len() as u64, self.length));
        }
        let mut filled = 0_usize;
        while filled < output.len() {
            let current = offset + filled as u64;
            match self.file.read_at(&mut output[filled..], current) {
                Ok(0) => {
                    return Err(short_read(
                        current,
                        (output.len() - filled) as u64,
                        self.length,
                    ));
                }
                Ok(count) if count <= output.len() - filled => filled += count,
                Ok(_) => return Err(identity_error("source read over-reported bytes")),
                Err(error) => {
                    return Err(ProviderError::new(
                        "source.io",
                        "read",
                        Some(SourceCoordinate {
                            offset: current,
                            record_ordinal: None,
                        }),
                        false,
                        error.to_string(),
                    ));
                }
            }
        }
        Ok(())
    }
}

pub(crate) struct FileReader {
    file: Arc<File>,
    offset: u64,
}

impl std::io::Read for FileReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let count = self.file.read_at(output, self.offset)?;
        self.offset = self
            .offset
            .checked_add(count as u64)
            .ok_or_else(|| std::io::Error::other("source offset overflow"))?;
        Ok(count)
    }
}

pub(crate) fn split_selected_report(
    path: &Path,
) -> Result<(SecureRoot, &'static str), ProviderError> {
    if path.file_name() == Some(OsStr::new("report.json")) {
        let parent = path
            .parent()
            .ok_or_else(|| path_error("selected report has no parent directory"))?;
        Ok((SecureRoot::open(parent)?, "report.json"))
    } else {
        Ok((SecureRoot::open(path)?, "report.json"))
    }
}

pub(crate) fn split_selected_file(path: &Path) -> Result<(SecureRoot, String), ProviderError> {
    let leaf = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| path_error("selected source has no UTF-8 filename"))?;
    validate_component_text(leaf)?;
    let parent = path
        .parent()
        .ok_or_else(|| path_error("selected source has no parent directory"))?;
    Ok((SecureRoot::open(parent)?, leaf.to_owned()))
}

fn walk_directory(path: &Path) -> Result<(Arc<File>, DirectoryBinding), ProviderError> {
    let absolute = path.is_absolute();
    let start = if absolute {
        Path::new("/")
    } else {
        Path::new(".")
    };
    let descriptor = open(start, DIRECTORY_FLAGS, Mode::empty())
        .map_err(|error| path_error(format!("cannot open trusted root: {error}")))?;
    let anchor = Arc::new(File::from(descriptor));
    let mut directory = anchor.clone();
    let mut components = Vec::new();
    components
        .try_reserve_exact(path.components().count())
        .map_err(|_| resource_error("selected path proof allocation failed"))?;
    for component in path.components() {
        match component {
            Component::RootDir if absolute => continue,
            Component::Normal(component) => {
                let child = Arc::new(open_directory_at(&directory, component)?);
                components.push((component.to_owned(), directory_identity(&child)?));
                directory = child;
            }
            _ => return Err(path_error("selected path contains an unsafe component")),
        }
    }
    Ok((directory, DirectoryBinding { anchor, components }))
}

fn open_directory_at(parent: &File, component: &OsStr) -> Result<File, ProviderError> {
    let descriptor = openat(parent, component, DIRECTORY_FLAGS, Mode::empty())
        .map_err(|error| path_error(format!("cannot open source directory component: {error}")))?;
    Ok(File::from(descriptor))
}

fn directory_identity(directory: &File) -> Result<FileIdentity, ProviderError> {
    let metadata = directory.metadata().map_err(io_error)?;
    if !metadata.file_type().is_dir() {
        return Err(path_error("source parent is not a directory"));
    }
    Ok(FileIdentity::from_metadata(&metadata))
}

fn validated_relative_components(relative: &str) -> Result<Vec<&OsStr>, ProviderError> {
    if relative.is_empty() || relative.len() > 4_096 || relative.contains('\0') {
        return Err(path_error(
            "artifact path is empty, too long, or contains NUL",
        ));
    }
    if relative
        .split('/')
        .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(path_error("artifact path contains an unsafe component"));
    }
    let path = Path::new(relative);
    if path.is_absolute() {
        return Err(path_error("artifact path must be relative"));
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(relative.matches('/').count().saturating_add(1))
        .map_err(|_| resource_error("artifact path allocation failed"))?;
    for component in path.components() {
        match component {
            Component::Normal(component) => output.push(component),
            _ => return Err(path_error("artifact path contains an unsafe component")),
        }
    }
    Ok(output)
}

fn validate_component_text(component: &str) -> Result<(), ProviderError> {
    if component.is_empty()
        || component.len() > 255
        || component.contains(['/', '\0'])
        || matches!(component, "." | "..")
    {
        return Err(path_error("selected filename is unsafe"));
    }
    Ok(())
}

fn ensure_regular(metadata: &Metadata) -> Result<(), ProviderError> {
    let file_type = metadata.file_type();
    if !file_type.is_file()
        || file_type.is_symlink()
        || file_type.is_socket()
        || file_type.is_fifo()
        || file_type.is_block_device()
        || file_type.is_char_device()
    {
        return Err(path_error("source leaf is not a regular file"));
    }
    Ok(())
}

fn path_error(detail: impl AsRef<str>) -> ProviderError {
    ProviderError::new("session.path_escape", "session.path", None, false, detail)
}

fn identity_error(detail: impl AsRef<str>) -> ProviderError {
    ProviderError::new(
        "source.identity_changed",
        "source.identity",
        None,
        false,
        detail,
    )
}

fn io_error(error: std::io::Error) -> ProviderError {
    ProviderError::new("source.io", "source.read", None, false, error.to_string())
}

fn resource_error(detail: impl AsRef<str>) -> ProviderError {
    ProviderError::new("control.budget_exceeded", "control", None, false, detail)
}

fn short_read(offset: u64, requested: u64, length: u64) -> ProviderError {
    ProviderError::new(
        "source.short_read",
        "read",
        Some(SourceCoordinate {
            offset,
            record_ordinal: None,
        }),
        false,
        format!(
            "requested {requested} bytes at offset {offset}, but only {} remain",
            length.saturating_sub(offset)
        ),
    )
}
