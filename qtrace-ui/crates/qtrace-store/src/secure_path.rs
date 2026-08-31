use std::{
    ffi::{OsStr, OsString},
    fs::{File, Metadata},
    mem::size_of,
    os::unix::fs::{FileExt, FileTypeExt},
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use qtrace_provider::{ProviderError, ReadAtSource, SourceCoordinate, WorkDelta, WorkGuard};
use rustix::fs::{FileType as RustixFileType, Mode, OFlags, Stat, fstat, open, openat};
use rustix::io::Errno;

use crate::FileIdentity;

const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const FILE_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NONBLOCK)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const INSPECT_FLAGS: OFlags = OFlags::PATH.union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);

#[derive(Clone, Copy, Debug)]
enum OpenContext {
    Report,
    SelectedSource,
    Source,
    Rebind,
}

#[derive(Debug)]
pub(crate) struct SecureRoot {
    directory: Arc<File>,
    binding: DirectoryBinding,
}

impl SecureRoot {
    fn open(path: &Path, context: OpenContext) -> Result<Self, ProviderError> {
        let (directory, binding) = walk_directory(path, context).map_err(|error| error.error)?;
        Ok(Self { directory, binding })
    }

    pub(crate) fn open_report_file(&self, relative: &str) -> Result<SecureFile, ProviderError> {
        self.open_file(relative, OpenContext::Report)
    }

    pub(crate) fn open_source_file(&self, relative: &str) -> Result<SecureFile, ProviderError> {
        self.open_file(relative, OpenContext::Source)
    }

    fn open_file(&self, relative: &str, context: OpenContext) -> Result<SecureFile, ProviderError> {
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
            let child = Arc::new(open_directory_at(&parent, component, context)?);
            let identity = directory_identity(&child)?;
            parent_components.push(((*component).to_owned(), identity));
            parent = child;
        }
        let descriptor = openat(&*parent, *leaf, FILE_FLAGS, Mode::empty())
            .map_err(|error| map_open_error(error, context, "cannot open regular source leaf"))?;
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
    fn try_clone_guarded(&self, guard: &dyn WorkGuard) -> Result<Self, ProviderError> {
        let mut components = Vec::new();
        crate::allocation::try_reserve_vec(
            &mut components,
            self.components.len(),
            guard,
            "source root binding allocation",
        )
        .map_err(allocation_failure)?;
        for (name, identity) in &self.components {
            components.push((try_copy_os_string(name, guard)?, *identity));
        }
        Ok(Self {
            anchor: Arc::clone(&self.anchor),
            components,
        })
    }

    fn verify(&self) -> Result<(), ProviderError> {
        let mut directory = self.anchor.try_clone().map_err(io_error)?;
        for (component, expected) in &self.components {
            let child = open_directory_at(&directory, component, OpenContext::Rebind)?;
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
    pub(crate) fn try_clone_guarded(&self, guard: &dyn WorkGuard) -> Result<Self, ProviderError> {
        let mut parent_components = Vec::new();
        crate::allocation::try_reserve_vec(
            &mut parent_components,
            self.parent_components.len(),
            guard,
            "source parent binding allocation",
        )
        .map_err(allocation_failure)?;
        for (name, identity) in &self.parent_components {
            parent_components.push((try_copy_os_string(name, guard)?, *identity));
        }
        Ok(Self {
            file: Arc::clone(&self.file),
            root: Arc::clone(&self.root),
            root_binding: self.root_binding.try_clone_guarded(guard)?,
            parent_components,
            leaf: try_copy_os_string(&self.leaf, guard)?,
        })
    }

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
            let mut rebound_parent = self.root.try_clone().map_err(io_error)?;
            for (component, expected) in &self.parent_components {
                let child = open_directory_at(&rebound_parent, component, OpenContext::Rebind)?;
                let actual = directory_identity(&child)?;
                if actual.device != expected.device || actual.inode != expected.inode {
                    return Err(path_error(
                        "source parent directory was replaced during read",
                    ));
                }
                rebound_parent = child;
            }
            let rebound = openat(&rebound_parent, &self.leaf, FILE_FLAGS, Mode::empty()).map_err(
                |error| {
                    map_open_error(
                        error,
                        OpenContext::Rebind,
                        "source path changed during read",
                    )
                },
            )?;
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

    pub(crate) fn source(
        &self,
        length: u64,
        guard: &dyn WorkGuard,
    ) -> Result<Arc<dyn ReadAtSource>, ProviderError> {
        let resident = size_of::<FileSource>()
            .checked_add(3 * size_of::<usize>())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| resource_error("file-source allocation bound overflow"))?;
        guard.consume(WorkDelta {
            resident_bytes: resident,
            ..WorkDelta::default()
        })?;
        Ok(Arc::new(FileSource {
            file: self.file.clone(),
            length,
        }))
    }

    pub(crate) fn reader(&self) -> FileReader {
        FileReader {
            file: self.file.clone(),
            offset: 0,
        }
    }
}

fn try_copy_os_string(value: &OsStr, guard: &dyn WorkGuard) -> Result<OsString, ProviderError> {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    let mut bytes = Vec::new();
    crate::allocation::try_reserve_vec(
        &mut bytes,
        value.as_bytes().len(),
        guard,
        "source path component allocation",
    )
    .map_err(allocation_failure)?;
    bytes.extend_from_slice(value.as_bytes());
    Ok(OsString::from_vec(bytes))
}

fn allocation_failure(error: crate::allocation::AllocationFailure) -> ProviderError {
    match error {
        crate::allocation::AllocationFailure::Aborted(abort) => ProviderError::from(abort),
        crate::allocation::AllocationFailure::Overflow(detail)
        | crate::allocation::AllocationFailure::Failed(detail) => resource_error(detail),
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
) -> Result<(SecureRoot, &'static str, PathBuf), ProviderError> {
    match walk_directory(path, OpenContext::Report) {
        Ok((directory, binding)) => Ok((
            SecureRoot { directory, binding },
            "report.json",
            path.to_owned(),
        )),
        Err(error)
            if error.final_not_directory && path.file_name() == Some(OsStr::new("report.json")) =>
        {
            let parent = path
                .parent()
                .ok_or_else(|| path_error("selected report has no parent directory"))?;
            Ok((
                SecureRoot::open(parent, OpenContext::Report)?,
                "report.json",
                parent.to_owned(),
            ))
        }
        Err(error) => Err(error.error),
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
    Ok((
        SecureRoot::open(parent, OpenContext::SelectedSource)?,
        leaf.to_owned(),
    ))
}

struct DirectoryWalkError {
    error: ProviderError,
    final_not_directory: bool,
}

fn walk_directory(
    path: &Path,
    context: OpenContext,
) -> Result<(Arc<File>, DirectoryBinding), DirectoryWalkError> {
    let absolute = path.is_absolute();
    let start = if absolute {
        Path::new("/")
    } else {
        Path::new(".")
    };
    let descriptor =
        open(start, DIRECTORY_FLAGS, Mode::empty()).map_err(|error| DirectoryWalkError {
            error: map_open_error(error, context, "cannot open trusted root"),
            final_not_directory: false,
        })?;
    let anchor = Arc::new(File::from(descriptor));
    let mut directory = anchor.clone();
    let mut components = Vec::new();
    components
        .try_reserve_exact(path.components().count())
        .map_err(|_| DirectoryWalkError {
            error: resource_error("selected path proof allocation failed"),
            final_not_directory: false,
        })?;
    let mut path_components = path.components().peekable();
    while let Some(component) = path_components.next() {
        match component {
            Component::RootDir if absolute => continue,
            Component::Normal(component) => {
                let child = Arc::new(open_directory_at(&directory, component, context).map_err(
                    |error| DirectoryWalkError {
                        final_not_directory: path_components.peek().is_none()
                            && is_not_directory_error(&error),
                        error,
                    },
                )?);
                let identity = directory_identity(&child).map_err(|error| DirectoryWalkError {
                    error,
                    final_not_directory: false,
                })?;
                components.push((component.to_owned(), identity));
                directory = child;
            }
            _ => {
                return Err(DirectoryWalkError {
                    error: path_error("selected path contains an unsafe component"),
                    final_not_directory: false,
                });
            }
        }
    }
    Ok((directory, DirectoryBinding { anchor, components }))
}

fn open_directory_at(
    parent: &File,
    component: &OsStr,
    context: OpenContext,
) -> Result<File, ProviderError> {
    let descriptor = openat(parent, component, INSPECT_FLAGS, Mode::empty()).map_err(|error| {
        map_open_error(error, context, "cannot inspect source directory component")
    })?;
    let stat = fstat(&descriptor).map_err(|error| {
        map_open_error(
            error,
            context,
            "cannot inspect source directory component type",
        )
    })?;
    match RustixFileType::from_raw_mode(stat.st_mode) {
        RustixFileType::Directory => {
            let directory = match openat(parent, component, DIRECTORY_FLAGS, Mode::empty()) {
                Ok(directory) => directory,
                Err(error) => {
                    if matches!(error, Errno::MFILE | Errno::NFILE | Errno::NOMEM) {
                        return Err(map_open_error(
                            error,
                            context,
                            "cannot open inspected source directory component",
                        ));
                    }
                    verify_inspected_binding(parent, component, &stat)?;
                    return Err(map_open_error(
                        error,
                        context,
                        "cannot open inspected source directory component",
                    ));
                }
            };
            let actual = fstat(&directory).map_err(|error| {
                map_open_error(
                    error,
                    OpenContext::Rebind,
                    "cannot verify opened source directory component",
                )
            })?;
            if !same_file_identity(&actual, &stat) {
                return Err(path_error(
                    "source directory component was rebound during inspection",
                ));
            }
            Ok(File::from(directory))
        }
        RustixFileType::Symlink => Err(path_error("source parent is a symbolic link")),
        _ => {
            verify_inspected_binding(parent, component, &stat)?;
            Err(not_directory_error(context))
        }
    }
}

fn verify_inspected_binding(
    parent: &File,
    component: &OsStr,
    expected: &Stat,
) -> Result<(), ProviderError> {
    let rebound = openat(parent, component, INSPECT_FLAGS, Mode::empty()).map_err(|error| {
        map_open_error(
            error,
            OpenContext::Rebind,
            "non-directory component changed during inspection",
        )
    })?;
    let actual = fstat(&rebound).map_err(|error| {
        map_open_error(
            error,
            OpenContext::Rebind,
            "cannot verify non-directory component inspection",
        )
    })?;
    if !same_file_identity(&actual, expected) {
        return Err(path_error(
            "non-directory component was rebound during inspection",
        ));
    }
    Ok(())
}

fn same_file_identity(left: &Stat, right: &Stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && RustixFileType::from_raw_mode(left.st_mode)
            == RustixFileType::from_raw_mode(right.st_mode)
}

fn not_directory_error(context: OpenContext) -> ProviderError {
    match context {
        OpenContext::Report | OpenContext::SelectedSource => ProviderError::new(
            "session.not_directory",
            "session.path",
            None,
            false,
            "selected path parent is not a directory",
        ),
        OpenContext::Source => ProviderError::new(
            "source.not_directory",
            "source.open",
            None,
            false,
            "artifact parent is not a directory",
        ),
        OpenContext::Rebind => path_error("source parent binding is not a directory"),
    }
}

fn is_not_directory_error(error: &ProviderError) -> bool {
    matches!(
        error.code(),
        "session.not_directory" | "source.not_directory"
    )
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

fn map_open_error(error: Errno, context: OpenContext, action: &str) -> ProviderError {
    let detail = format!("{action}: {error}");
    if matches!(error, Errno::MFILE | Errno::NFILE | Errno::NOMEM) {
        return ProviderError::new("control.resource_exhausted", "control", None, false, detail);
    }
    if matches!(context, OpenContext::Rebind) {
        return path_error(detail);
    }
    if matches!(
        error,
        Errno::LOOP | Errno::NOTDIR | Errno::ISDIR | Errno::NXIO
    ) {
        return path_error(detail);
    }
    if error == Errno::NOENT {
        return match context {
            OpenContext::Report => ProviderError::new(
                "session.report_missing",
                "session.report",
                None,
                false,
                detail,
            ),
            OpenContext::SelectedSource | OpenContext::Source => {
                ProviderError::new("source.not_found", "source.open", None, false, detail)
            }
            OpenContext::Rebind => path_error(detail),
        };
    }
    if matches!(error, Errno::ACCESS | Errno::PERM) {
        return ProviderError::new(
            "source.permission_denied",
            "source.open",
            None,
            false,
            detail,
        );
    }
    ProviderError::new("source.io", "source.open", None, false, detail)
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

#[cfg(test)]
mod tests {
    use std::{ffi::OsStr, fs::File, os::unix::fs::symlink};

    use rustix::{
        fs::{Mode, fstat, openat},
        io::Errno,
    };
    use tempfile::TempDir;

    use super::{INSPECT_FLAGS, OpenContext, map_open_error, verify_inspected_binding};

    #[test]
    fn open_errno_mapping_keeps_resource_permission_and_escape_classes_distinct() {
        for errno in [Errno::MFILE, Errno::NFILE, Errno::NOMEM] {
            assert_eq!(
                map_open_error(errno, OpenContext::Source, "test").code(),
                "control.resource_exhausted"
            );
        }
        for errno in [Errno::ACCESS, Errno::PERM] {
            assert_eq!(
                map_open_error(errno, OpenContext::Source, "test").code(),
                "source.permission_denied"
            );
        }
        for errno in [Errno::LOOP, Errno::NOTDIR] {
            assert_eq!(
                map_open_error(errno, OpenContext::Source, "test").code(),
                "session.path_escape"
            );
        }
        assert_eq!(
            map_open_error(Errno::NOENT, OpenContext::Source, "test").code(),
            "source.not_found"
        );
        assert_eq!(
            map_open_error(Errno::NOENT, OpenContext::Report, "test").code(),
            "session.report_missing"
        );
        assert_eq!(
            map_open_error(Errno::NOENT, OpenContext::Rebind, "test").code(),
            "session.path_escape"
        );
        assert_eq!(
            map_open_error(Errno::ACCESS, OpenContext::Rebind, "test").code(),
            "session.path_escape"
        );
        assert_eq!(
            map_open_error(Errno::IO, OpenContext::Source, "test").code(),
            "source.io"
        );
    }

    #[test]
    fn non_directory_inspection_rejects_disappearance_and_symlink_rebinding() {
        for replace_with_symlink in [false, true] {
            let temp = TempDir::new().expect("inspection root");
            let path = temp.path().join("notdir");
            std::fs::write(&path, b"ordinary file").expect("non-directory component");
            let parent = File::open(temp.path()).expect("held parent");
            let inspected = openat(&parent, OsStr::new("notdir"), INSPECT_FLAGS, Mode::empty())
                .expect("inspect component");
            let expected = fstat(&inspected).expect("inspected identity");
            std::fs::rename(&path, temp.path().join("held")).expect("remove original name");
            if replace_with_symlink {
                symlink(temp.path(), &path).expect("symlink replacement");
            }

            let error = verify_inspected_binding(&parent, OsStr::new("notdir"), &expected)
                .expect_err("inspection ambiguity must fail closed");
            assert_eq!(error.code(), "session.path_escape");
        }
    }
}
