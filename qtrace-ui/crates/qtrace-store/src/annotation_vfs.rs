use std::{
    collections::HashMap,
    ffi::{CStr, CString, c_char, c_int, c_void},
    fs::File,
    mem::size_of,
    os::fd::{BorrowedFd, FromRawFd, IntoRawFd, RawFd},
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicI32, AtomicU64, Ordering},
    },
};

use rusqlite::ffi;
use rustix::{
    fs::{
        AtFlags, Dir, FlockOperation, Mode, OFlags, RenameFlags, fchmod, fcntl_lock, fdatasync,
        fstat, fsync, ftruncate, openat, renameat_with, statat,
    },
    io::{Errno, pread, pwrite},
    process::geteuid,
};

use crate::annotations::AnnotationError;

const MAIN_NAME: &str = "annotations.sqlite3";
const WAL_NAME: &str = "annotations.sqlite3-wal";
const JOURNAL_NAME: &str = "annotations.sqlite3-journal";
const SHM_NAME: &str = "annotations.sqlite3-shm";
const FILE_KIND_MASK: u32 = 0o170000;
const REGULAR_FILE: u32 = 0o100000;
const PRIVATE_MODE: u32 = 0o600;
const QUARANTINE_PREFIX: &str = ".qtrace-sqlite-quarantine-";
const MAX_QUARANTINES: usize = 8;
const MAX_DIRECTORY_ENTRIES: usize = 2 + 4 + MAX_QUARANTINES;

static NEXT_VFS_ID: AtomicU64 = AtomicU64::new(1);
static PROCESS_LOCKS: OnceLock<Mutex<HashMap<(u64, u64), u64>>> = OnceLock::new();

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DeleteHookPhase {
    BeforeProof,
    AfterProof,
}

#[cfg(test)]
type DeleteHook = Box<dyn Fn(DeleteHookPhase, &str) + Send>;

#[cfg(test)]
pub(super) static DELETE_HOOK: OnceLock<Mutex<Option<DeleteHook>>> = OnceLock::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DirectorySyncReason {
    Rename(FileKind),
    CreatedFile(FileKind),
}

#[cfg(test)]
type DirectorySyncHook = Box<dyn Fn(DirectorySyncReason) -> Result<(), Errno> + Send>;

#[cfg(test)]
pub(super) static DIRECTORY_SYNC_HOOK: OnceLock<Mutex<Option<DirectorySyncHook>>> = OnceLock::new();

#[cfg(test)]
type SidecarSetupHook = Box<dyn Fn(&str) + Send>;

#[cfg(test)]
pub(super) static SIDECAR_SETUP_HOOK: OnceLock<Mutex<Option<SidecarSetupHook>>> = OnceLock::new();

#[cfg(test)]
type FileSyncHook = Box<dyn Fn(&str) + Send>;

#[cfg(test)]
pub(super) static FILE_SYNC_HOOK: OnceLock<Mutex<Option<FileSyncHook>>> = OnceLock::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity {
    device: u64,
    inode: u64,
    uid: u32,
    links: u64,
    mode: u32,
}

impl Identity {
    fn from_stat(stat: &rustix::fs::Stat) -> Result<Self, ()> {
        let mode = stat.st_mode;
        let uid = stat.st_uid;
        let links = stat.st_nlink;
        if mode & FILE_KIND_MASK != REGULAR_FILE
            || mode & 0o777 != PRIVATE_MODE
            || uid != geteuid().as_raw()
            || links != 1
        {
            return Err(());
        }
        Ok(Self {
            device: stat.st_dev,
            inode: stat.st_ino,
            uid,
            links,
            mode,
        })
    }

    fn from_file(file: &File) -> Result<Self, AnnotationError> {
        let stat = fstat(file).map_err(|error| {
            AnnotationError::vfs(format!("cannot stat held SQLite file: {error}"))
        })?;
        Self::from_stat(&stat).map_err(|()| {
            AnnotationError::permission(
                "SQLite file must be an owned, single-link, 0600 regular file",
            )
        })
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FileKind {
    Main,
    Wal,
    Journal,
}

impl FileKind {
    const fn name(self) -> &'static str {
        match self {
            Self::Main => MAIN_NAME,
            Self::Wal => WAL_NAME,
            Self::Journal => JOURNAL_NAME,
        }
    }

    const fn slot(self) -> usize {
        match self {
            Self::Main => 0,
            Self::Wal => 1,
            Self::Journal => 2,
        }
    }
}

struct Context {
    id: u64,
    directory: File,
    main: Mutex<Option<(File, bool)>>,
    identities: Mutex<[Option<Identity>; 3]>,
    open_fds: [AtomicI32; 3],
    tombstone_sequence: AtomicU64,
    base: *mut ffi::sqlite3_vfs,
}

// The boxed context outlives its SQLite connection. All mutable members used by callbacks are
// synchronized, while raw VFS pointers are immutable after registration.
unsafe impl Send for Context {}
unsafe impl Sync for Context {}

#[repr(C)]
struct DescriptorFile {
    base: ffi::sqlite3_file,
    context: *const Context,
    fd: RawFd,
    identity: Identity,
    kind: FileKind,
    lock_level: c_int,
    owns_process_lock: bool,
    persist_wal: bool,
    needs_dir_sync: bool,
}

struct RenameReceipt {
    tombstone: String,
    expected: Identity,
}

struct Registration {
    context: Box<Context>,
    name: CString,
    vfs: ffi::sqlite3_vfs,
}

pub(crate) struct DescriptorVfs {
    registration: Box<Registration>,
    registered: bool,
}

impl DescriptorVfs {
    pub(crate) fn register(
        directory: &File,
        main: File,
        main_needs_dir_sync: bool,
    ) -> Result<Self, AnnotationError> {
        inspect_quarantines(directory).map_err(|error| {
            AnnotationError::path(format!("invalid SQLite quarantine directory: {error}"))
        })?;
        let main_identity = Identity::from_file(&main)?;
        let directory = directory.try_clone().map_err(|error| {
            AnnotationError::vfs(format!("cannot retain annotation directory: {error}"))
        })?;
        let base_name = c"unix-excl";
        // SAFETY: SQLite owns the returned built-in VFS for process lifetime.
        let base = unsafe { ffi::sqlite3_vfs_find(base_name.as_ptr()) };
        if base.is_null() {
            return Err(AnnotationError::vfs("SQLite unix-excl VFS is unavailable"));
        }
        let id = NEXT_VFS_ID.fetch_add(1, Ordering::Relaxed);
        let name = CString::new(format!("qtrace-annotation-{id}"))
            .map_err(|_| AnnotationError::vfs("cannot construct SQLite VFS name"))?;
        let context = Box::new(Context {
            id,
            directory,
            main: Mutex::new(Some((main, main_needs_dir_sync))),
            identities: Mutex::new([Some(main_identity), None, None]),
            open_fds: std::array::from_fn(|_| AtomicI32::new(-1)),
            tombstone_sequence: AtomicU64::new(0),
            base,
        });
        let mut registration = Box::new(Registration {
            context,
            name,
            vfs: empty_vfs(),
        });
        registration.vfs = ffi::sqlite3_vfs {
            iVersion: 1,
            szOsFile: c_int::try_from(size_of::<DescriptorFile>())
                .map_err(|_| AnnotationError::vfs("SQLite file structure is too large"))?,
            // SQLite appends fixed sidecar suffixes to the supplied native-picker path.
            mxPathname: 4096,
            pNext: ptr::null_mut(),
            zName: registration.name.as_ptr(),
            pAppData: (&mut *registration.context as *mut Context).cast(),
            xOpen: Some(vfs_open),
            xDelete: Some(vfs_delete),
            xAccess: Some(vfs_access),
            xFullPathname: Some(vfs_full_pathname),
            xDlOpen: Some(vfs_dl_open),
            xDlError: Some(vfs_dl_error),
            xDlSym: Some(vfs_dl_sym),
            xDlClose: Some(vfs_dl_close),
            xRandomness: Some(vfs_randomness),
            xSleep: Some(vfs_sleep),
            xCurrentTime: Some(vfs_current_time),
            xGetLastError: Some(vfs_get_last_error),
            xCurrentTimeInt64: None,
            xSetSystemCall: None,
            xGetSystemCall: None,
            xNextSystemCall: None,
        };
        // SAFETY: registration and all pointers it owns are boxed and remain stable until Drop.
        let status = unsafe { ffi::sqlite3_vfs_register(&mut registration.vfs, 0) };
        if status != ffi::SQLITE_OK {
            return Err(AnnotationError::vfs(format!(
                "cannot register descriptor SQLite VFS: {status}"
            )));
        }
        Ok(Self {
            registration,
            registered: true,
        })
    }

    pub(crate) fn name(&self) -> &CStr {
        self.registration.name.as_c_str()
    }

    #[cfg(test)]
    pub(super) fn create_journal_for_test(&self) -> Result<(), AnnotationError> {
        open_sidecar(&self.registration.context, FileKind::Journal)
            .map(|_| ())
            .map_err(|error| AnnotationError::vfs(format!("cannot create test journal: {error}")))
    }

    #[cfg(test)]
    pub(super) fn sync_created_journal_twice_for_test(
        &self,
    ) -> Result<(c_int, bool, c_int, bool), AnnotationError> {
        let (file, identity, created) = open_sidecar(&self.registration.context, FileKind::Journal)
            .map_err(|error| {
                AnnotationError::vfs(format!("cannot create test journal: {error}"))
            })?;
        if !created {
            return Err(AnnotationError::vfs("test journal unexpectedly existed"));
        }
        let raw = file.into_raw_fd();
        let mut descriptor = DescriptorFile {
            base: ffi::sqlite3_file {
                pMethods: &IO_METHODS,
            },
            context: &*self.registration.context,
            fd: raw,
            identity,
            kind: FileKind::Journal,
            lock_level: ffi::SQLITE_LOCK_NONE,
            owns_process_lock: false,
            persist_wal: false,
            needs_dir_sync: true,
        };
        let first = unsafe { file_sync(&mut descriptor.base, ffi::SQLITE_SYNC_FULL) };
        let first_pending = descriptor.needs_dir_sync;
        let second = unsafe { file_sync(&mut descriptor.base, ffi::SQLITE_SYNC_FULL) };
        let second_pending = descriptor.needs_dir_sync;
        // SAFETY: this helper uniquely owns raw and neither xSync call consumes it.
        drop(unsafe { File::from_raw_fd(raw) });
        Ok((first, first_pending, second, second_pending))
    }

    pub(crate) fn verify_bindings(&self) -> Result<(), AnnotationError> {
        let context = &self.registration.context;
        let identities = *context
            .identities
            .lock()
            .map_err(|_| AnnotationError::identity("SQLite identity state was poisoned"))?;
        for kind in [FileKind::Main, FileKind::Wal, FileKind::Journal] {
            let Some(expected) = identities[kind.slot()] else {
                continue;
            };
            let actual = path_identity(context, kind.name()).map_err(|_| {
                AnnotationError::identity(format!("SQLite {} binding changed", kind.name()))
            })?;
            if actual != expected {
                return Err(AnnotationError::identity(format!(
                    "SQLite {} identity changed",
                    kind.name()
                )));
            }
            let raw = context.open_fds[kind.slot()].load(Ordering::Acquire);
            if raw >= 0 {
                // SAFETY: open_fds is cleared before xClose closes the descriptor, and callers
                // cannot race a Connection method because rusqlite::Connection is not Sync.
                let held = unsafe { BorrowedFd::borrow_raw(raw) };
                let held_identity =
                    Identity::from_stat(&fstat(held).map_err(|_| {
                        AnnotationError::identity("held SQLite descriptor changed")
                    })?)
                    .map_err(|()| AnnotationError::identity("held SQLite file became unsafe"))?;
                if held_identity != expected {
                    return Err(AnnotationError::identity(
                        "held SQLite descriptor identity changed",
                    ));
                }
            }
        }
        if path_exists(context, SHM_NAME).map_err(|_| {
            AnnotationError::identity("cannot inspect forbidden SQLite shared-memory sidecar")
        })? {
            return Err(AnnotationError::identity(
                "exclusive SQLite connection unexpectedly created a shared-memory sidecar",
            ));
        }
        Ok(())
    }
}

impl Drop for DescriptorVfs {
    fn drop(&mut self) {
        if self.registered {
            // SAFETY: AnnotationStore closes the only Connection before DescriptorVfs drops.
            let _ = unsafe { ffi::sqlite3_vfs_unregister(&mut self.registration.vfs) };
            self.registered = false;
        }
    }
}

fn empty_vfs() -> ffi::sqlite3_vfs {
    ffi::sqlite3_vfs {
        iVersion: 1,
        szOsFile: 0,
        mxPathname: 0,
        pNext: ptr::null_mut(),
        zName: ptr::null(),
        pAppData: ptr::null_mut(),
        xOpen: None,
        xDelete: None,
        xAccess: None,
        xFullPathname: None,
        xDlOpen: None,
        xDlError: None,
        xDlSym: None,
        xDlClose: None,
        xRandomness: None,
        xSleep: None,
        xCurrentTime: None,
        xGetLastError: None,
        xCurrentTimeInt64: None,
        xSetSystemCall: None,
        xGetSystemCall: None,
        xNextSystemCall: None,
    }
}

fn ffi_result(body: impl FnOnce() -> c_int) -> c_int {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or(ffi::SQLITE_IOERR)
}

unsafe fn context(vfs: *mut ffi::sqlite3_vfs) -> &'static Context {
    // SAFETY: every callback receives the registered VFS whose pAppData is a live Context.
    unsafe { &*((*vfs).pAppData.cast::<Context>()) }
}

unsafe fn descriptor(file: *mut ffi::sqlite3_file) -> &'static mut DescriptorFile {
    // SAFETY: xOpen initializes SQLite's szOsFile storage as DescriptorFile before publishing
    // pMethods, and SQLite serializes calls on a connection opened with NO_MUTEX.
    unsafe { &mut *file.cast::<DescriptorFile>() }
}

fn classify(flags: c_int) -> Option<FileKind> {
    if flags & ffi::SQLITE_OPEN_MAIN_DB != 0 {
        Some(FileKind::Main)
    } else if flags & ffi::SQLITE_OPEN_WAL != 0 {
        Some(FileKind::Wal)
    } else if flags & ffi::SQLITE_OPEN_MAIN_JOURNAL != 0 {
        Some(FileKind::Journal)
    } else {
        None
    }
}

fn path_identity(context: &Context, name: &str) -> Result<Identity, Errno> {
    path_identity_at(&context.directory, name)
}

fn path_identity_at(directory: &File, name: &str) -> Result<Identity, Errno> {
    let stat = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)?;
    Identity::from_stat(&stat).map_err(|()| Errno::PERM)
}

fn is_quarantine_name(bytes: &[u8]) -> bool {
    let Some(suffix) = bytes.strip_prefix(QUARANTINE_PREFIX.as_bytes()) else {
        return false;
    };
    suffix.len() == 33
        && suffix[16] == b'-'
        && suffix[..16].iter().all(u8::is_ascii_hexdigit)
        && suffix[17..].iter().all(u8::is_ascii_hexdigit)
}

fn inspect_quarantines(directory: &File) -> Result<usize, Errno> {
    let mut stream = Dir::read_from(directory)?;
    let mut entries = 0_usize;
    let mut quarantines = 0_usize;
    while let Some(entry) = stream.read() {
        entries = entries.checked_add(1).ok_or(Errno::OVERFLOW)?;
        if entries > MAX_DIRECTORY_ENTRIES {
            return Err(Errno::NOSPC);
        }
        let entry = entry?;
        let bytes = entry.file_name().to_bytes();
        if matches!(bytes, b"." | b"..")
            || matches!(bytes, name if name == MAIN_NAME.as_bytes()
                || name == WAL_NAME.as_bytes()
                || name == JOURNAL_NAME.as_bytes()
                || name == SHM_NAME.as_bytes())
        {
            continue;
        }
        if !is_quarantine_name(bytes) {
            return Err(Errno::PERM);
        }
        let name = std::str::from_utf8(bytes).map_err(|_| Errno::ILSEQ)?;
        path_identity_at(directory, name)?;
        quarantines = quarantines.checked_add(1).ok_or(Errno::OVERFLOW)?;
        if quarantines > MAX_QUARANTINES {
            return Err(Errno::NOSPC);
        }
    }
    Ok(quarantines)
}

fn path_exists(context: &Context, name: &str) -> Result<bool, Errno> {
    match statat(&context.directory, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(Errno::NOENT) => Ok(false),
        Err(error) => Err(error),
    }
}

fn sync_directory(context: &Context, reason: DirectorySyncReason) -> Result<(), Errno> {
    #[cfg(not(test))]
    let _ = reason;
    #[cfg(test)]
    if let Some(hook) = DIRECTORY_SYNC_HOOK
        .get_or_init(|| Mutex::new(None))
        .lock()
        .expect("directory sync hook lock poisoned")
        .as_ref()
    {
        hook(reason)?;
    }
    fsync(&context.directory)
}

fn open_sidecar(context: &Context, kind: FileKind) -> Result<(File, Identity, bool), Errno> {
    let common = OFlags::RDWR
        .union(OFlags::NONBLOCK)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC);
    let (descriptor, created) = match openat(&context.directory, kind.name(), common, Mode::empty())
    {
        Ok(descriptor) => (descriptor, false),
        Err(Errno::NOENT) => (
            openat(
                &context.directory,
                kind.name(),
                common.union(OFlags::CREATE).union(OFlags::EXCL),
                Mode::RUSR | Mode::WUSR,
            )?,
            true,
        ),
        Err(error) => return Err(error),
    };
    let file = File::from(descriptor);
    if created {
        fchmod(&file, Mode::RUSR | Mode::WUSR)?;
    }
    let identity = Identity::from_stat(&fstat(&file)?).map_err(|()| Errno::PERM)?;
    #[cfg(test)]
    if let Some(hook) = SIDECAR_SETUP_HOOK
        .get_or_init(|| Mutex::new(None))
        .lock()
        .expect("sidecar setup hook lock poisoned")
        .as_ref()
    {
        hook(kind.name());
    }
    let bound = path_identity(context, kind.name())?;
    if identity != bound {
        return Err(Errno::STALE);
    }
    Ok((file, identity, created))
}

fn quarantine_name(context: &Context) -> Result<String, Errno> {
    let sequence = context.tombstone_sequence.fetch_add(1, Ordering::Relaxed);
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random).map_err(|_| Errno::IO)?;
    Ok(format!(
        "{QUARANTINE_PREFIX}{:016x}-{sequence:016x}",
        u64::from_le_bytes(random)
    ))
}

fn rename_to_quarantine(
    context: &Context,
    kind: FileKind,
    expected: Identity,
) -> Result<RenameReceipt, c_int> {
    let tombstone = quarantine_name(context).map_err(|_| ffi::SQLITE_IOERR_DELETE)?;
    renameat_with(
        &context.directory,
        kind.name(),
        &context.directory,
        tombstone.as_str(),
        RenameFlags::NOREPLACE,
    )
    .map_err(|_| ffi::SQLITE_IOERR_DELETE)?;
    if sync_directory(context, DirectorySyncReason::Rename(kind)).is_err() {
        return Err(ffi::SQLITE_IOERR_DIR_FSYNC);
    }
    Ok(RenameReceipt {
        tombstone,
        expected,
    })
}

fn verify_file(file: &DescriptorFile) -> Result<(), ()> {
    // SAFETY: DescriptorFile owns fd from xOpen until xClose.
    let held = unsafe { BorrowedFd::borrow_raw(file.fd) };
    let actual = Identity::from_stat(&fstat(held).map_err(|_| ())?)?;
    if actual != file.identity {
        return Err(());
    }
    let context = unsafe { &*file.context };
    if path_identity(context, file.kind.name()).map_err(|_| ())? != file.identity {
        return Err(());
    }
    Ok(())
}

unsafe extern "C" fn vfs_open(
    vfs: *mut ffi::sqlite3_vfs,
    z_name: ffi::sqlite3_filename,
    output: *mut ffi::sqlite3_file,
    flags: c_int,
    output_flags: *mut c_int,
) -> c_int {
    ffi_result(|| {
        if output.is_null() || z_name.is_null() {
            return ffi::SQLITE_CANTOPEN;
        }
        let Some(kind) = classify(flags) else {
            return ffi::SQLITE_CANTOPEN;
        };
        // SAFETY: z_name is SQLite-owned NUL-terminated input for the callback.
        let name = unsafe { CStr::from_ptr(z_name) }.to_bytes();
        if !name.ends_with(kind.name().as_bytes()) {
            return ffi::SQLITE_CANTOPEN;
        }
        // SAFETY: vfs is the registered object for this callback.
        let context = unsafe { context(vfs) };
        #[cfg(test)]
        if kind == FileKind::Main {
            super::annotations::run_open_hook(super::annotations::OpenHookPhase::BeforeSqliteOpen);
        }
        let opened = match kind {
            FileKind::Main => {
                let Some((file, needs_dir_sync)) =
                    context.main.lock().ok().and_then(|mut slot| slot.take())
                else {
                    return ffi::SQLITE_CANTOPEN;
                };
                let identity = match Identity::from_stat(&match fstat(&file) {
                    Ok(stat) => stat,
                    Err(_) => return ffi::SQLITE_CANTOPEN,
                }) {
                    Ok(identity) => identity,
                    Err(()) => return ffi::SQLITE_CANTOPEN,
                };
                Ok((file, identity, needs_dir_sync))
            }
            FileKind::Wal | FileKind::Journal => open_sidecar(context, kind),
        };
        let (file, identity, needs_dir_sync) = match opened {
            Ok(value) => value,
            Err(_) => return ffi::SQLITE_CANTOPEN,
        };
        #[cfg(test)]
        if kind == FileKind::Main {
            super::annotations::run_open_hook(super::annotations::OpenHookPhase::AfterSqliteOpen);
        }
        if path_identity(context, kind.name()).ok() != Some(identity) {
            if kind == FileKind::Main {
                if let Ok(mut slot) = context.main.lock() {
                    *slot = Some((file, needs_dir_sync));
                }
            }
            return ffi::SQLITE_CANTOPEN;
        }
        let raw = file.into_raw_fd();
        if context.open_fds[kind.slot()]
            .compare_exchange(-1, raw, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            // SAFETY: ownership was just transferred from File and has not escaped.
            drop(unsafe { File::from_raw_fd(raw) });
            return ffi::SQLITE_CANTOPEN;
        }
        if let Ok(mut identities) = context.identities.lock() {
            identities[kind.slot()] = Some(identity);
        } else {
            context.open_fds[kind.slot()].store(-1, Ordering::Release);
            // SAFETY: the open-fd slot has relinquished this owned descriptor.
            drop(unsafe { File::from_raw_fd(raw) });
            return ffi::SQLITE_IOERR;
        }
        let descriptor = DescriptorFile {
            base: ffi::sqlite3_file {
                pMethods: &IO_METHODS,
            },
            context,
            fd: raw,
            identity,
            kind,
            lock_level: ffi::SQLITE_LOCK_NONE,
            owns_process_lock: false,
            persist_wal: false,
            needs_dir_sync,
        };
        // SAFETY: SQLite allocated at least szOsFile bytes suitably aligned and output is live.
        unsafe { ptr::write(output.cast::<DescriptorFile>(), descriptor) };
        if !output_flags.is_null() {
            // SAFETY: SQLite supplied a writable output integer.
            unsafe { *output_flags = flags };
        }
        ffi::SQLITE_OK
    })
}

unsafe extern "C" fn file_close(file: *mut ffi::sqlite3_file) -> c_int {
    ffi_result(|| {
        // SAFETY: SQLite calls xClose only for a successfully opened DescriptorFile.
        let file = unsafe { descriptor(file) };
        if file.owns_process_lock {
            release_process_lock(file);
        }
        let context = unsafe { &*file.context };
        context.open_fds[file.kind.slot()].store(-1, Ordering::Release);
        let raw = std::mem::replace(&mut file.fd, -1);
        file.base.pMethods = ptr::null();
        if raw >= 0 {
            // SAFETY: DescriptorFile uniquely owns fd until this xClose.
            drop(unsafe { File::from_raw_fd(raw) });
        }
        ffi::SQLITE_OK
    })
}

unsafe extern "C" fn file_read(
    file: *mut ffi::sqlite3_file,
    output: *mut c_void,
    amount: c_int,
    offset: ffi::sqlite3_int64,
) -> c_int {
    ffi_result(|| {
        if output.is_null() || amount < 0 || offset < 0 {
            return ffi::SQLITE_IOERR_READ;
        }
        let file = unsafe { descriptor(file) };
        if verify_file(file).is_err() {
            return ffi::SQLITE_IOERR_READ;
        }
        // SAFETY: SQLite guarantees output points to amount writable bytes.
        let bytes = unsafe { std::slice::from_raw_parts_mut(output.cast::<u8>(), amount as usize) };
        let held = unsafe { BorrowedFd::borrow_raw(file.fd) };
        let mut read = 0_usize;
        while read < bytes.len() {
            match pread(held, &mut bytes[read..], offset as u64 + read as u64) {
                Ok(0) => {
                    bytes[read..].fill(0);
                    return if verify_file(file).is_ok() {
                        ffi::SQLITE_IOERR_SHORT_READ
                    } else {
                        ffi::SQLITE_IOERR_READ
                    };
                }
                Ok(count) => read += count,
                Err(_) => return ffi::SQLITE_IOERR_READ,
            }
        }
        if verify_file(file).is_ok() {
            ffi::SQLITE_OK
        } else {
            ffi::SQLITE_IOERR_READ
        }
    })
}

unsafe extern "C" fn file_write(
    file: *mut ffi::sqlite3_file,
    input: *const c_void,
    amount: c_int,
    offset: ffi::sqlite3_int64,
) -> c_int {
    ffi_result(|| {
        if input.is_null() || amount < 0 || offset < 0 {
            return ffi::SQLITE_IOERR_WRITE;
        }
        let file = unsafe { descriptor(file) };
        if verify_file(file).is_err() {
            return ffi::SQLITE_IOERR_WRITE;
        }
        // SAFETY: SQLite guarantees input points to amount readable bytes.
        let bytes = unsafe { std::slice::from_raw_parts(input.cast::<u8>(), amount as usize) };
        let held = unsafe { BorrowedFd::borrow_raw(file.fd) };
        let mut written = 0_usize;
        while written < bytes.len() {
            match pwrite(held, &bytes[written..], offset as u64 + written as u64) {
                Ok(0) | Err(_) => return ffi::SQLITE_IOERR_WRITE,
                Ok(count) => written += count,
            }
        }
        if verify_file(file).is_ok() {
            ffi::SQLITE_OK
        } else {
            ffi::SQLITE_IOERR_WRITE
        }
    })
}

unsafe extern "C" fn file_truncate(
    file: *mut ffi::sqlite3_file,
    size: ffi::sqlite3_int64,
) -> c_int {
    ffi_result(|| {
        if size < 0 {
            return ffi::SQLITE_IOERR_TRUNCATE;
        }
        let file = unsafe { descriptor(file) };
        if verify_file(file).is_err() {
            return ffi::SQLITE_IOERR_TRUNCATE;
        }
        let held = unsafe { BorrowedFd::borrow_raw(file.fd) };
        if ftruncate(held, size as u64).is_err() || verify_file(file).is_err() {
            ffi::SQLITE_IOERR_TRUNCATE
        } else {
            ffi::SQLITE_OK
        }
    })
}

unsafe extern "C" fn file_sync(file: *mut ffi::sqlite3_file, flags: c_int) -> c_int {
    ffi_result(|| {
        let file = unsafe { descriptor(file) };
        if verify_file(file).is_err() {
            return ffi::SQLITE_IOERR_FSYNC;
        }
        #[cfg(test)]
        if let Some(hook) = FILE_SYNC_HOOK
            .get_or_init(|| Mutex::new(None))
            .lock()
            .expect("file sync hook lock poisoned")
            .as_ref()
        {
            hook(file.kind.name());
        }
        let held = unsafe { BorrowedFd::borrow_raw(file.fd) };
        let result = if flags & 0x0f == ffi::SQLITE_SYNC_FULL {
            fsync(held)
        } else {
            fdatasync(held)
        };
        if result.is_err() || verify_file(file).is_err() {
            return ffi::SQLITE_IOERR_FSYNC;
        }
        if file.needs_dir_sync {
            let context = unsafe { &*file.context };
            if sync_directory(context, DirectorySyncReason::CreatedFile(file.kind)).is_err() {
                return ffi::SQLITE_IOERR_DIR_FSYNC;
            }
            file.needs_dir_sync = false;
        }
        ffi::SQLITE_OK
    })
}

unsafe extern "C" fn file_size(
    file: *mut ffi::sqlite3_file,
    output: *mut ffi::sqlite3_int64,
) -> c_int {
    ffi_result(|| {
        if output.is_null() {
            return ffi::SQLITE_IOERR_FSTAT;
        }
        let file = unsafe { descriptor(file) };
        if verify_file(file).is_err() {
            return ffi::SQLITE_IOERR_FSTAT;
        }
        let held = unsafe { BorrowedFd::borrow_raw(file.fd) };
        let Ok(stat) = fstat(held) else {
            return ffi::SQLITE_IOERR_FSTAT;
        };
        let size = stat.st_size as ffi::sqlite3_int64;
        // SAFETY: SQLite supplied a writable output integer.
        unsafe { *output = size };
        if verify_file(file).is_ok() {
            ffi::SQLITE_OK
        } else {
            ffi::SQLITE_IOERR_FSTAT
        }
    })
}

fn acquire_process_lock(file: &mut DescriptorFile) -> c_int {
    if file.owns_process_lock {
        return ffi::SQLITE_OK;
    }
    let key = (file.identity.device, file.identity.inode);
    let Ok(mut locks) = PROCESS_LOCKS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
    else {
        return ffi::SQLITE_IOERR_LOCK;
    };
    let context = unsafe { &*file.context };
    if locks.get(&key).is_some_and(|owner| *owner != context.id) {
        return ffi::SQLITE_BUSY;
    }
    locks.insert(key, context.id);
    let held = unsafe { BorrowedFd::borrow_raw(file.fd) };
    if fcntl_lock(held, FlockOperation::NonBlockingLockExclusive).is_err() {
        locks.remove(&key);
        return ffi::SQLITE_BUSY;
    }
    file.owns_process_lock = true;
    ffi::SQLITE_OK
}

fn release_process_lock(file: &mut DescriptorFile) {
    let held = unsafe { BorrowedFd::borrow_raw(file.fd) };
    let _ = fcntl_lock(held, FlockOperation::NonBlockingUnlock);
    let key = (file.identity.device, file.identity.inode);
    if let Ok(mut locks) = PROCESS_LOCKS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
    {
        locks.remove(&key);
    }
    file.owns_process_lock = false;
}

unsafe extern "C" fn file_lock(file: *mut ffi::sqlite3_file, level: c_int) -> c_int {
    ffi_result(|| {
        if !(ffi::SQLITE_LOCK_SHARED..=ffi::SQLITE_LOCK_EXCLUSIVE).contains(&level) {
            return ffi::SQLITE_IOERR_LOCK;
        }
        let file = unsafe { descriptor(file) };
        if file.kind != FileKind::Main || verify_file(file).is_err() {
            return ffi::SQLITE_IOERR_LOCK;
        }
        let status = acquire_process_lock(file);
        if status == ffi::SQLITE_OK {
            file.lock_level = file.lock_level.max(level);
            if verify_file(file).is_err() {
                release_process_lock(file);
                file.lock_level = ffi::SQLITE_LOCK_NONE;
                return ffi::SQLITE_IOERR_LOCK;
            }
        }
        status
    })
}

unsafe extern "C" fn file_unlock(file: *mut ffi::sqlite3_file, level: c_int) -> c_int {
    ffi_result(|| {
        if !(ffi::SQLITE_LOCK_NONE..=ffi::SQLITE_LOCK_SHARED).contains(&level) {
            return ffi::SQLITE_IOERR_UNLOCK;
        }
        let file = unsafe { descriptor(file) };
        if verify_file(file).is_err() {
            return ffi::SQLITE_IOERR_UNLOCK;
        }
        if level == ffi::SQLITE_LOCK_NONE && file.owns_process_lock {
            release_process_lock(file);
        }
        file.lock_level = level;
        if verify_file(file).is_ok() {
            ffi::SQLITE_OK
        } else {
            ffi::SQLITE_IOERR_UNLOCK
        }
    })
}

unsafe extern "C" fn file_check_reserved(
    file: *mut ffi::sqlite3_file,
    output: *mut c_int,
) -> c_int {
    ffi_result(|| {
        if output.is_null() {
            return ffi::SQLITE_IOERR_CHECKRESERVEDLOCK;
        }
        let file = unsafe { descriptor(file) };
        if verify_file(file).is_err() {
            return ffi::SQLITE_IOERR_CHECKRESERVEDLOCK;
        }
        let key = (file.identity.device, file.identity.inode);
        let reserved = if file.lock_level >= ffi::SQLITE_LOCK_RESERVED {
            true
        } else {
            PROCESS_LOCKS
                .get_or_init(|| Mutex::new(HashMap::new()))
                .lock()
                .map(|locks| locks.contains_key(&key))
                .unwrap_or(true)
        };
        unsafe { *output = c_int::from(reserved) };
        if verify_file(file).is_ok() {
            ffi::SQLITE_OK
        } else {
            ffi::SQLITE_IOERR_CHECKRESERVEDLOCK
        }
    })
}

unsafe extern "C" fn file_control(
    file: *mut ffi::sqlite3_file,
    operation: c_int,
    argument: *mut c_void,
) -> c_int {
    ffi_result(|| {
        let file = unsafe { descriptor(file) };
        match operation {
            ffi::SQLITE_FCNTL_LOCKSTATE => {
                if argument.is_null() {
                    return ffi::SQLITE_IOERR;
                }
                unsafe { *argument.cast::<c_int>() = file.lock_level };
                ffi::SQLITE_OK
            }
            ffi::SQLITE_FCNTL_HAS_MOVED => {
                if argument.is_null() {
                    return ffi::SQLITE_IOERR;
                }
                unsafe { *argument.cast::<c_int>() = c_int::from(verify_file(file).is_err()) };
                ffi::SQLITE_OK
            }
            ffi::SQLITE_FCNTL_SYNC | ffi::SQLITE_FCNTL_COMMIT_PHASETWO => {
                if verify_file(file).is_ok() {
                    ffi::SQLITE_OK
                } else {
                    ffi::SQLITE_IOERR
                }
            }
            ffi::SQLITE_FCNTL_PERSIST_WAL => {
                if argument.is_null() || file.kind != FileKind::Main {
                    return ffi::SQLITE_IOERR;
                }
                let value = unsafe { &mut *argument.cast::<c_int>() };
                if *value < 0 {
                    *value = c_int::from(file.persist_wal);
                } else {
                    file.persist_wal = *value != 0;
                }
                ffi::SQLITE_OK
            }
            ffi::SQLITE_FCNTL_SIZE_HINT
            | ffi::SQLITE_FCNTL_POWERSAFE_OVERWRITE
            | ffi::SQLITE_FCNTL_VFSNAME => ffi::SQLITE_NOTFOUND,
            _ => ffi::SQLITE_NOTFOUND,
        }
    })
}

unsafe extern "C" fn file_sector_size(_file: *mut ffi::sqlite3_file) -> c_int {
    4096
}

unsafe extern "C" fn file_device_characteristics(_file: *mut ffi::sqlite3_file) -> c_int {
    0
}

static IO_METHODS: ffi::sqlite3_io_methods = ffi::sqlite3_io_methods {
    iVersion: 1,
    xClose: Some(file_close),
    xRead: Some(file_read),
    xWrite: Some(file_write),
    xTruncate: Some(file_truncate),
    xSync: Some(file_sync),
    xFileSize: Some(file_size),
    xLock: Some(file_lock),
    xUnlock: Some(file_unlock),
    xCheckReservedLock: Some(file_check_reserved),
    xFileControl: Some(file_control),
    xSectorSize: Some(file_sector_size),
    xDeviceCharacteristics: Some(file_device_characteristics),
    xShmMap: None,
    xShmLock: None,
    xShmBarrier: None,
    xShmUnmap: None,
    xFetch: None,
    xUnfetch: None,
};

fn leaf_from_name(name: &CStr) -> Option<FileKind> {
    let bytes = name.to_bytes();
    if bytes.ends_with(WAL_NAME.as_bytes()) {
        Some(FileKind::Wal)
    } else if bytes.ends_with(JOURNAL_NAME.as_bytes()) {
        Some(FileKind::Journal)
    } else if bytes.ends_with(MAIN_NAME.as_bytes()) {
        Some(FileKind::Main)
    } else {
        None
    }
}

unsafe extern "C" fn vfs_access(
    vfs: *mut ffi::sqlite3_vfs,
    z_name: *const c_char,
    _flags: c_int,
    output: *mut c_int,
) -> c_int {
    ffi_result(|| {
        if z_name.is_null() || output.is_null() {
            return ffi::SQLITE_IOERR_ACCESS;
        }
        let context = unsafe { context(vfs) };
        let name = unsafe { CStr::from_ptr(z_name) };
        let Some(kind) = leaf_from_name(name) else {
            unsafe { *output = 0 };
            return ffi::SQLITE_OK;
        };
        let exists = match path_identity(context, kind.name()) {
            Ok(actual) => {
                let expected = context
                    .identities
                    .lock()
                    .ok()
                    .and_then(|identities| identities[kind.slot()]);
                expected.is_none_or(|identity| identity == actual)
            }
            Err(Errno::NOENT) => false,
            Err(_) => return ffi::SQLITE_IOERR_ACCESS,
        };
        unsafe { *output = c_int::from(exists) };
        ffi::SQLITE_OK
    })
}

unsafe extern "C" fn vfs_delete(
    vfs: *mut ffi::sqlite3_vfs,
    z_name: *const c_char,
    _sync_directory: c_int,
) -> c_int {
    ffi_result(|| {
        if z_name.is_null() {
            return ffi::SQLITE_IOERR_DELETE;
        }
        let context = unsafe { context(vfs) };
        let name = unsafe { CStr::from_ptr(z_name) };
        let Some(kind @ (FileKind::Wal | FileKind::Journal)) = leaf_from_name(name) else {
            return ffi::SQLITE_IOERR_DELETE;
        };
        let expected = context
            .identities
            .lock()
            .ok()
            .and_then(|identities| identities[kind.slot()]);
        let Some(expected) = expected else {
            return if path_exists(context, kind.name()).ok() == Some(false) {
                ffi::SQLITE_OK
            } else {
                ffi::SQLITE_IOERR_DELETE
            };
        };
        let Ok(quarantines) = inspect_quarantines(&context.directory) else {
            return ffi::SQLITE_IOERR_DELETE;
        };
        if quarantines >= MAX_QUARANTINES {
            return ffi::SQLITE_IOERR_DELETE;
        }
        let receipt = match rename_to_quarantine(context, kind, expected) {
            Ok(receipt) => receipt,
            Err(status) => return status,
        };
        #[cfg(test)]
        if let Some(hook) = DELETE_HOOK
            .get_or_init(|| Mutex::new(None))
            .lock()
            .expect("delete hook lock poisoned")
            .as_ref()
        {
            hook(DeleteHookPhase::BeforeProof, &receipt.tombstone);
        }
        let captured = path_identity(context, &receipt.tombstone);
        if captured.ok() != Some(receipt.expected) {
            return ffi::SQLITE_IOERR_DELETE;
        }
        #[cfg(test)]
        if let Some(hook) = DELETE_HOOK
            .get_or_init(|| Mutex::new(None))
            .lock()
            .expect("delete hook lock poisoned")
            .as_ref()
        {
            hook(DeleteHookPhase::AfterProof, &receipt.tombstone);
        }
        if path_identity(context, &receipt.tombstone).ok() != Some(receipt.expected) {
            return ffi::SQLITE_IOERR_DELETE;
        }
        if let Ok(mut identities) = context.identities.lock() {
            identities[kind.slot()] = None;
        }
        ffi::SQLITE_OK
    })
}

unsafe extern "C" fn vfs_full_pathname(
    _vfs: *mut ffi::sqlite3_vfs,
    z_name: *const c_char,
    output_size: c_int,
    output: *mut c_char,
) -> c_int {
    ffi_result(|| {
        if z_name.is_null() || output.is_null() || output_size <= 0 {
            return ffi::SQLITE_CANTOPEN_FULLPATH;
        }
        let name = unsafe { CStr::from_ptr(z_name) }.to_bytes_with_nul();
        if name.len() > output_size as usize {
            return ffi::SQLITE_CANTOPEN_FULLPATH;
        }
        unsafe { ptr::copy_nonoverlapping(name.as_ptr().cast::<c_char>(), output, name.len()) };
        ffi::SQLITE_OK
    })
}

unsafe extern "C" fn vfs_randomness(
    vfs: *mut ffi::sqlite3_vfs,
    amount: c_int,
    output: *mut c_char,
) -> c_int {
    ffi_result(|| {
        let context = unsafe { context(vfs) };
        let Some(callback) = (unsafe { (*context.base).xRandomness }) else {
            return 0;
        };
        unsafe { callback(context.base, amount, output) }
    })
}

unsafe extern "C" fn vfs_sleep(vfs: *mut ffi::sqlite3_vfs, micros: c_int) -> c_int {
    ffi_result(|| {
        let context = unsafe { context(vfs) };
        let Some(callback) = (unsafe { (*context.base).xSleep }) else {
            return 0;
        };
        unsafe { callback(context.base, micros) }
    })
}

unsafe extern "C" fn vfs_current_time(vfs: *mut ffi::sqlite3_vfs, output: *mut f64) -> c_int {
    ffi_result(|| {
        let context = unsafe { context(vfs) };
        let Some(callback) = (unsafe { (*context.base).xCurrentTime }) else {
            return ffi::SQLITE_IOERR;
        };
        unsafe { callback(context.base, output) }
    })
}

unsafe extern "C" fn vfs_get_last_error(
    vfs: *mut ffi::sqlite3_vfs,
    size: c_int,
    output: *mut c_char,
) -> c_int {
    ffi_result(|| {
        let context = unsafe { context(vfs) };
        let Some(callback) = (unsafe { (*context.base).xGetLastError }) else {
            return 0;
        };
        unsafe { callback(context.base, size, output) }
    })
}

unsafe extern "C" fn vfs_dl_open(_vfs: *mut ffi::sqlite3_vfs, _name: *const c_char) -> *mut c_void {
    ptr::null_mut()
}

unsafe extern "C" fn vfs_dl_error(_vfs: *mut ffi::sqlite3_vfs, size: c_int, output: *mut c_char) {
    if size > 0 && !output.is_null() {
        unsafe { *output = 0 };
    }
}

unsafe extern "C" fn vfs_dl_sym(
    _vfs: *mut ffi::sqlite3_vfs,
    _handle: *mut c_void,
    _name: *const c_char,
) -> Option<unsafe extern "C" fn(*mut ffi::sqlite3_vfs, *mut c_void, *const c_char)> {
    None
}

unsafe extern "C" fn vfs_dl_close(_vfs: *mut ffi::sqlite3_vfs, _handle: *mut c_void) {}
