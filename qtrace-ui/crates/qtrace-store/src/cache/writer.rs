use std::{
    fs::File,
    io::{Seek, SeekFrom, Write},
    mem::size_of,
    path::Path,
};

use qtrace_provider::{EventKey, EventKind, WorkDelta, WorkGuard};
use rustix::{
    fs::{
        AtFlags, FlockOperation, Mode, OFlags, RenameFlags, fchmod, flock, fsync, openat,
        renameat_with, unlinkat,
    },
    io::Errno,
};
use sha2::{Digest, Sha256};

use crate::layout::{
    CacheHeader, EVENT_KEY_BYTES, EVENT_KEYS_SECTION, EVENT_KINDS_SECTION, HEADER_BYTES,
    encode_event_key, encode_event_kind,
};

use super::{
    CacheDirectory, CacheError, CacheIdentity, CacheManifest, ObjectIdentity, OwnedStoreView,
    SectionDescriptor,
    manifest::MAX_MANIFEST_BYTES,
    map_errno, map_io_error,
    reader::{ValidationFailure, open_final, probe_identity, validate_file},
};

const FINAL_NAME: &str = "index.qtc";
const LOCK_NAME: &str = ".publish.lock";
const CREATE_FLAGS: OFlags = OFlags::WRONLY
    .union(OFlags::CREATE)
    .union(OFlags::EXCL)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const LOCK_CREATE_FLAGS: OFlags = OFlags::RDWR
    .union(OFlags::CREATE)
    .union(OFlags::EXCL)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const LOCK_OPEN_FLAGS: OFlags = OFlags::RDWR.union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);
const INSPECT_FLAGS: OFlags = OFlags::PATH.union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);
const SECTION_CHUNK_BYTES: usize = 64_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublishOutcome {
    Existing,
    Published,
}

#[derive(Debug)]
pub struct CacheWriter {
    identity: CacheIdentity,
    store: OwnedStoreView,
}

impl CacheWriter {
    pub fn new(identity: CacheIdentity, store: OwnedStoreView) -> Result<Self, CacheError> {
        identity.validate()?;
        Ok(Self { identity, store })
    }

    pub fn publish(
        &self,
        root: &Path,
        guard: &dyn WorkGuard,
    ) -> Result<PublishOutcome, CacheError> {
        self.authorize_resident_peak(guard)?;
        let key = self.identity.cache_key();
        let directory = CacheDirectory::open(root, &key, true, guard)?
            .ok_or_else(|| CacheError::io("created cache directory disappeared"))?;
        let publication_lock = PublicationLock::acquire(&directory)?;
        guard.consume(WorkDelta {
            nodes: 1,
            resident_bytes: 128,
            ..WorkDelta::default()
        })?;
        let mut temporary = OwnedTemporary::create(&directory)?;
        let result = self.publish_locked(&directory, &publication_lock, &mut temporary, guard);
        match result {
            Ok(outcome) => Ok(outcome),
            Err(error) => match temporary.remove_if_armed() {
                Ok(()) => Err(error),
                Err(cleanup) => Err(CacheError::conflict(format!(
                    "publication failed ({error}); owned-temp cleanup was ambiguous ({cleanup})"
                ))),
            },
        }
    }

    fn authorize_resident_peak(&self, guard: &dyn WorkGuard) -> Result<(), CacheError> {
        let keys = self
            .store
            .key_capacity()
            .checked_mul(size_of::<EventKey>())
            .ok_or_else(|| CacheError::invalid("event-key resident bound overflow"))?;
        let kinds = self
            .store
            .kind_capacity()
            .checked_mul(size_of::<EventKind>())
            .ok_or_else(|| CacheError::invalid("event-kind resident bound overflow"))?;
        let identity_text = self
            .identity
            .analyzer_version
            .capacity()
            .checked_add(self.identity.source_format.capacity())
            .ok_or_else(|| CacheError::invalid("identity resident bound overflow"))?;
        let peak = keys
            .checked_add(kinds)
            .and_then(|value| value.checked_add(identity_text))
            .and_then(|value| value.checked_add(MAX_MANIFEST_BYTES as usize))
            .and_then(|value| value.checked_add(SECTION_CHUNK_BYTES * 2))
            .and_then(|value| value.checked_add(4096))
            .ok_or_else(|| CacheError::invalid("cache resident bound overflow"))?;
        guard.consume(WorkDelta {
            resident_bytes: u64::try_from(peak)
                .map_err(|_| CacheError::invalid("cache resident bound does not fit u64"))?,
            ..WorkDelta::default()
        })?;
        Ok(())
    }

    fn publish_locked(
        &self,
        directory: &CacheDirectory,
        publication_lock: &PublicationLock,
        temporary: &mut OwnedTemporary,
        guard: &dyn WorkGuard,
    ) -> Result<PublishOutcome, CacheError> {
        write_part(temporary.file_mut()?, &[0_u8; HEADER_BYTES], guard)?;
        let (sections, manifest_offset) = self.write_sections(temporary.file_mut()?, guard)?;

        guard.consume(WorkDelta::default())?;
        let manifest = CacheManifest {
            identity: try_clone_identity(&self.identity)?,
            sections,
        };
        let manifest_bytes = manifest.canonical_bytes()?;
        write_part(temporary.file_mut()?, &manifest_bytes, guard)?;

        guard.consume(WorkDelta::default())?;
        let header = CacheHeader {
            schema: self.identity.cache_schema,
            manifest_offset,
            manifest_length: manifest_bytes.len() as u64,
            manifest_checksum: Sha256::digest(&manifest_bytes).into(),
        };
        temporary
            .file_mut()?
            .seek(SeekFrom::Start(0))
            .map_err(|error| map_io_error("cannot seek cache temp", error))?;
        write_part(temporary.file_mut()?, &header.encode(), guard)?;
        guard.consume(WorkDelta {
            nodes: 1,
            ..WorkDelta::default()
        })?;
        temporary
            .file_mut()?
            .sync_all()
            .map_err(|error| map_io_error("cannot fsync cache temp", error))?;

        guard.consume(WorkDelta::default())?;
        guard.consume(WorkDelta {
            nodes: 2,
            ..WorkDelta::default()
        })?;
        directory.verify()?;
        publication_lock.verify()?;
        let state = inspect_final(directory, &self.identity, guard)?;
        if matches!(state, FinalState::Valid) {
            temporary.remove_owned()?;
            directory.verify()?;
            publication_lock.verify()?;
            sync_directory(&directory.file, "cannot fsync cache directory")?;
            return Ok(PublishOutcome::Existing);
        }

        let transaction = match state {
            FinalState::Missing => {
                renameat_with(
                    &*directory.file,
                    temporary.name(),
                    &*directory.file,
                    FINAL_NAME,
                    RenameFlags::NOREPLACE,
                )
                .map_err(|error| map_errno("cannot publish cache without replacement", error))?;
                temporary.disarm();
                PublicationTransaction::Missing {
                    own: temporary.identity,
                }
            }
            FinalState::CorruptSame(displaced) => {
                renameat_with(
                    &*directory.file,
                    temporary.name(),
                    &*directory.file,
                    FINAL_NAME,
                    RenameFlags::EXCHANGE,
                )
                .map_err(|error| map_errno("cannot exchange corrupt cache", error))?;
                temporary.disarm();
                PublicationTransaction::Corrupt {
                    own: temporary.identity,
                    displaced,
                    staging: temporary.name.clone(),
                }
            }
            FinalState::Valid => unreachable!("valid winner returned above"),
        };

        if let Err(abort) = guard.consume(WorkDelta::default()) {
            return rollback_after_error(
                directory,
                publication_lock,
                &transaction,
                CacheError::from(abort),
            );
        }
        if let Err(error) = directory.verify() {
            return rollback_after_error(directory, publication_lock, &transaction, error);
        }
        if let Err(error) = publication_lock.verify() {
            return Err(CacheError::durability(format!(
                "published cache lock binding became ambiguous: {error}"
            )));
        }

        commit_transaction(directory, publication_lock, &transaction)?;
        Ok(PublishOutcome::Published)
    }

    fn write_sections(
        &self,
        file: &mut File,
        guard: &dyn WorkGuard,
    ) -> Result<(Vec<SectionDescriptor>, u64), CacheError> {
        let kinds_offset = HEADER_BYTES as u64;
        let mut kinds_digest = Sha256::new();
        let mut kinds_buffer = [0_u8; SECTION_CHUNK_BYTES];
        let mut first = 0_usize;
        while first < self.store.kinds().len() {
            let end = first
                .saturating_add(SECTION_CHUNK_BYTES)
                .min(self.store.kinds().len());
            guard.consume(WorkDelta {
                rows: (end - first) as u64,
                ..WorkDelta::default()
            })?;
            for (output, kind) in kinds_buffer[..end - first]
                .iter_mut()
                .zip(&self.store.kinds()[first..end])
            {
                *output = encode_event_kind(*kind);
            }
            let bytes = &kinds_buffer[..end - first];
            kinds_digest.update(bytes);
            write_part(file, bytes, guard)?;
            first = end;
        }
        let kinds_length = self.store.kinds().len() as u64;
        let kinds_end = kinds_offset
            .checked_add(kinds_length)
            .ok_or_else(|| CacheError::invalid("event-kind section range overflow"))?;
        let keys_offset = align_up(kinds_end, 8)?;
        let padding = usize::try_from(keys_offset - kinds_end)
            .map_err(|_| CacheError::invalid("cache padding length overflow"))?;
        write_part(file, &[0_u8; 7][..padding], guard)?;

        let mut keys_digest = Sha256::new();
        let mut keys_buffer = [0_u8; SECTION_CHUNK_BYTES];
        let rows_per_chunk = SECTION_CHUNK_BYTES / EVENT_KEY_BYTES;
        first = 0;
        while first < self.store.keys().len() {
            let end = first
                .saturating_add(rows_per_chunk)
                .min(self.store.keys().len());
            guard.consume(WorkDelta {
                rows: (end - first) as u64,
                ..WorkDelta::default()
            })?;
            for (index, key) in self.store.keys()[first..end].iter().enumerate() {
                if key.artifact.as_bytes() != &self.identity.artifact_digest {
                    return Err(CacheError::invalid(
                        "event key artifact digest differs from cache identity",
                    ));
                }
                let start = index * EVENT_KEY_BYTES;
                let encoded: &mut [u8; EVENT_KEY_BYTES] = (&mut keys_buffer
                    [start..start + EVENT_KEY_BYTES])
                    .try_into()
                    .map_err(|_| CacheError::invalid("event-key chunk shape"))?;
                encode_event_key(key, encoded);
            }
            let bytes = &keys_buffer[..(end - first) * EVENT_KEY_BYTES];
            keys_digest.update(bytes);
            write_part(file, bytes, guard)?;
            first = end;
        }
        let keys_length = self
            .store
            .keys()
            .len()
            .checked_mul(EVENT_KEY_BYTES)
            .and_then(|value| u64::try_from(value).ok())
            .ok_or_else(|| CacheError::invalid("event-key section length overflow"))?;
        let manifest_offset = keys_offset
            .checked_add(keys_length)
            .ok_or_else(|| CacheError::invalid("manifest offset overflow"))?;
        let mut sections = Vec::new();
        sections
            .try_reserve_exact(2)
            .map_err(|_| super::allocation_error("cache section descriptors"))?;
        sections.push(SectionDescriptor {
            alignment: 1,
            checksum: kinds_digest.finalize().into(),
            element_size: 1,
            length: kinds_length,
            name: try_owned(EVENT_KINDS_SECTION)?,
            offset: kinds_offset,
        });
        sections.push(SectionDescriptor {
            alignment: 8,
            checksum: keys_digest.finalize().into(),
            element_size: EVENT_KEY_BYTES as u32,
            length: keys_length,
            name: try_owned(EVENT_KEYS_SECTION)?,
            offset: keys_offset,
        });
        Ok((sections, manifest_offset))
    }
}

fn try_owned(value: &str) -> Result<String, CacheError> {
    let mut output = String::new();
    output
        .try_reserve_exact(value.len())
        .map_err(|_| super::allocation_error("cache manifest string"))?;
    output.push_str(value);
    Ok(output)
}

fn try_clone_identity(identity: &CacheIdentity) -> Result<CacheIdentity, CacheError> {
    Ok(CacheIdentity {
        analyzer_version: try_owned(&identity.analyzer_version)?,
        artifact_digest: identity.artifact_digest,
        build_option_digest: identity.build_option_digest,
        cache_schema: identity.cache_schema,
        endian: try_owned(&identity.endian)?,
        layout_version: identity.layout_version,
        source_features: identity.source_features,
        source_format: try_owned(&identity.source_format)?,
        source_major: identity.source_major,
        source_minor: identity.source_minor,
    })
}

fn align_up(value: u64, alignment: u64) -> Result<u64, CacheError> {
    let mask = alignment
        .checked_sub(1)
        .ok_or_else(|| CacheError::invalid("zero cache alignment"))?;
    value
        .checked_add(mask)
        .map(|rounded| rounded & !mask)
        .ok_or_else(|| CacheError::invalid("cache alignment overflow"))
}

enum FinalState {
    Missing,
    Valid,
    CorruptSame(ObjectIdentity),
}

enum PublicationTransaction {
    Missing {
        own: ObjectIdentity,
    },
    Corrupt {
        own: ObjectIdentity,
        displaced: ObjectIdentity,
        staging: String,
    },
}

fn inspect_final(
    directory: &CacheDirectory,
    expected: &CacheIdentity,
    guard: &dyn WorkGuard,
) -> Result<FinalState, CacheError> {
    let Some((file, object)) = open_final(directory)? else {
        return Ok(FinalState::Missing);
    };
    let probe = file
        .try_clone()
        .map_err(|error| map_io_error("cannot clone cache descriptor", error))?;
    match validate_file(file, directory, expected, guard) {
        Ok(_) => Ok(FinalState::Valid),
        Err(ValidationFailure::Fatal(error)) => Err(error),
        Err(ValidationFailure::Rebuild(_)) => match probe_identity(&probe, guard) {
            Ok(identity) if identity == *expected => Ok(FinalState::CorruptSame(object)),
            Ok(_) => Err(CacheError::conflict(
                "cache leaf belongs to a different complete identity",
            )),
            Err(ValidationFailure::Fatal(error)) => Err(error),
            Err(ValidationFailure::Rebuild(_)) => Err(CacheError::conflict(
                "cache leaf is not a recognizable cache owned by this identity",
            )),
        },
    }
}

fn rollback_after_error(
    directory: &CacheDirectory,
    publication_lock: &PublicationLock,
    transaction: &PublicationTransaction,
    original: CacheError,
) -> Result<PublishOutcome, CacheError> {
    if let Err(error) = rollback_transaction(directory, publication_lock, transaction) {
        return Err(CacheError::durability(format!(
            "publication failed ({original}); safe rollback was ambiguous: {error}"
        )));
    }
    sync_directory(&directory.file, "cannot fsync rollback directory").map_err(|error| {
        CacheError::durability(format!(
            "publication failed ({original}); rollback directory fsync failed: {error}"
        ))
    })?;
    Err(original)
}

fn rollback_transaction(
    directory: &CacheDirectory,
    publication_lock: &PublicationLock,
    transaction: &PublicationTransaction,
) -> Result<(), CacheError> {
    publication_lock.verify()?;
    match transaction {
        PublicationTransaction::Missing { own } => unlink_verified(directory, FINAL_NAME, *own)?,
        PublicationTransaction::Corrupt {
            own,
            displaced,
            staging,
        } => {
            let final_identity = named_identity(directory, FINAL_NAME)?;
            let staging_identity = named_identity(directory, staging)?;
            if final_identity != *own || staging_identity != *displaced {
                return Err(CacheError::conflict(
                    "exchange rollback operands no longer match the recorded transaction",
                ));
            }
            publication_lock.verify()?;
            renameat_with(
                &*directory.file,
                staging,
                &*directory.file,
                FINAL_NAME,
                RenameFlags::EXCHANGE,
            )
            .map_err(|error| map_errno("cannot roll back cache exchange", error))?;
            if named_identity(directory, FINAL_NAME)? != *displaced
                || named_identity(directory, staging)? != *own
            {
                return Err(CacheError::conflict(
                    "cache exchange rollback produced ambiguous bindings",
                ));
            }
            unlink_verified(directory, staging, *own)?;
        }
    }
    Ok(())
}

fn commit_transaction(
    directory: &CacheDirectory,
    publication_lock: &PublicationLock,
    transaction: &PublicationTransaction,
) -> Result<(), CacheError> {
    verify_transaction_bindings(directory, publication_lock, transaction).map_err(|error| {
        CacheError::durability(format!(
            "published cache bindings became ambiguous before commit: {error}"
        ))
    })?;
    if let Err(original) = sync_directory(&directory.file, "cannot fsync published cache directory")
    {
        return rollback_after_error(directory, publication_lock, transaction, original)
            .map(|_| ());
    }
    verify_transaction_bindings(directory, publication_lock, transaction).map_err(|error| {
        CacheError::durability(format!(
            "published cache bindings became ambiguous after commit fsync: {error}"
        ))
    })?;
    if let PublicationTransaction::Corrupt {
        own,
        displaced,
        staging,
    } = transaction
    {
        publication_lock.verify().map_err(|error| {
            CacheError::durability(format!(
                "cannot verify lock before displaced cleanup: {error}"
            ))
        })?;
        if named_identity(directory, FINAL_NAME)? != *own
            || named_identity(directory, staging)? != *displaced
        {
            return Err(CacheError::durability(
                "published or displaced cache binding changed before cleanup",
            ));
        }
        unlink_verified(directory, staging, *displaced).map_err(|error| {
            CacheError::durability(format!("cannot clean displaced corrupt cache: {error}"))
        })?;
        sync_directory(&directory.file, "cannot fsync displaced-cache cleanup").map_err(
            |error| {
                CacheError::durability(format!("cannot fsync displaced-cache cleanup: {error}"))
            },
        )?;
    }
    Ok(())
}

fn verify_transaction_bindings(
    directory: &CacheDirectory,
    publication_lock: &PublicationLock,
    transaction: &PublicationTransaction,
) -> Result<(), CacheError> {
    publication_lock.verify()?;
    match transaction {
        PublicationTransaction::Missing { own } => {
            if named_identity(directory, FINAL_NAME)? != *own {
                return Err(CacheError::conflict(
                    "published final no longer matches the builder inode",
                ));
            }
        }
        PublicationTransaction::Corrupt {
            own,
            displaced,
            staging,
        } => {
            if named_identity(directory, FINAL_NAME)? != *own
                || named_identity(directory, staging)? != *displaced
            {
                return Err(CacheError::conflict(
                    "published exchange operands no longer match the recorded transaction",
                ));
            }
        }
    }
    Ok(())
}

fn sync_directory(file: &File, context: &str) -> Result<(), CacheError> {
    #[cfg(test)]
    if INJECT_DIRECTORY_FSYNC_FAILURES.with(|remaining| {
        let current = remaining.get();
        if current == 0 {
            false
        } else {
            remaining.set(current - 1);
            true
        }
    }) {
        return Err(CacheError::io(format!("{context}: injected fsync failure")));
    }
    fsync(file).map_err(|error| map_errno(context, error))
}

#[cfg(test)]
thread_local! {
    static INJECT_DIRECTORY_FSYNC_FAILURES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn write_part(file: &mut File, bytes: &[u8], guard: &dyn WorkGuard) -> Result<(), CacheError> {
    guard.consume(WorkDelta {
        input_bytes: bytes.len() as u64,
        ..WorkDelta::default()
    })?;
    file.write_all(bytes)
        .map_err(|error| map_io_error("cannot write cache temp", error))
}

struct PublicationLock<'a> {
    directory: &'a CacheDirectory,
    file: File,
    identity: ObjectIdentity,
}

impl<'a> PublicationLock<'a> {
    fn acquire(directory: &'a CacheDirectory) -> Result<Self, CacheError> {
        let descriptor = match openat(
            &*directory.file,
            LOCK_NAME,
            LOCK_CREATE_FLAGS,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(descriptor) => descriptor,
            Err(Errno::EXIST) => {
                openat(&*directory.file, LOCK_NAME, LOCK_OPEN_FLAGS, Mode::empty())
                    .map_err(map_lock_open_error)?
            }
            Err(error) => return Err(map_lock_open_error(error)),
        };
        let file = File::from(descriptor);
        let identity = ObjectIdentity::regular_file(&file)?;
        if identity.permissions != 0o600 {
            return Err(CacheError::path(
                "cache publication lock does not have mode 0600",
            ));
        }
        flock(&file, FlockOperation::LockExclusive)
            .map_err(|error| map_errno("cannot acquire cache publication lock", error))?;
        let lock = Self {
            directory,
            file,
            identity,
        };
        lock.verify()?;
        Ok(lock)
    }

    fn verify(&self) -> Result<(), CacheError> {
        let descriptor_identity = ObjectIdentity::regular_file(&self.file)?;
        let named = named_identity(self.directory, LOCK_NAME)?;
        if descriptor_identity != self.identity || named != self.identity {
            return Err(CacheError::conflict(
                "cache publication lock binding changed while held",
            ));
        }
        Ok(())
    }
}

fn map_lock_open_error(error: Errno) -> CacheError {
    match error {
        Errno::MFILE | Errno::NFILE | Errno::NOMEM | Errno::ACCESS | Errno::PERM => {
            map_errno("cannot open cache publication lock", error)
        }
        _ => CacheError::path(format!("unsafe cache publication lock: {error}")),
    }
}

struct OwnedTemporary<'a> {
    directory: &'a CacheDirectory,
    file: Option<File>,
    identity: ObjectIdentity,
    name: String,
    armed: bool,
}

impl<'a> OwnedTemporary<'a> {
    fn create(directory: &'a CacheDirectory) -> Result<Self, CacheError> {
        Self::create_impl(directory, TempCreateFault::None)
    }

    fn create_impl(
        directory: &'a CacheDirectory,
        fault: TempCreateFault,
    ) -> Result<Self, CacheError> {
        for _ in 0..32 {
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random).map_err(|error| {
                CacheError::io(format!("cannot generate cache temp name: {error}"))
            })?;
            let name = format!(".index.{}.tmp", hex::encode(random));
            match openat(
                &*directory.file,
                name.as_str(),
                CREATE_FLAGS,
                Mode::RUSR | Mode::WUSR,
            ) {
                Ok(descriptor) => {
                    let file = File::from(descriptor);
                    let provisional_result = if fault == TempCreateFault::FirstIdentity {
                        Err(CacheError::io("injected first temp fstat failure"))
                    } else {
                        ObjectIdentity::regular_file(&file)
                    };
                    let provisional = match provisional_result {
                        Ok(identity) => identity,
                        Err(error) => {
                            let _ = unlinkat(&*directory.file, name.as_str(), AtFlags::empty());
                            return Err(error);
                        }
                    };
                    let chmod_result = if fault == TempCreateFault::Chmod {
                        Err(Errno::IO)
                    } else {
                        fchmod(&file, Mode::RUSR | Mode::WUSR)
                    };
                    if let Err(error) = chmod_result {
                        let cleanup = unlink_verified(directory, &name, provisional);
                        return Err(match cleanup {
                            Ok(()) => map_errno("cannot set private cache temp mode", error),
                            Err(cleanup) => CacheError::conflict(format!(
                                "temp chmod failed ({error}) and cleanup was ambiguous ({cleanup})"
                            )),
                        });
                    }
                    let identity_result = if fault == TempCreateFault::SecondIdentity {
                        Err(CacheError::io("injected second temp fstat failure"))
                    } else {
                        ObjectIdentity::regular_file(&file)
                    };
                    let identity = match identity_result {
                        Ok(identity) => identity,
                        Err(error) => {
                            let _ = unlinkat(&*directory.file, name.as_str(), AtFlags::empty());
                            return Err(error);
                        }
                    };
                    if identity.permissions != 0o600 {
                        let _ = unlink_verified(directory, &name, identity);
                        return Err(CacheError::path("cache temp does not have mode 0600"));
                    }
                    return Ok(Self {
                        directory,
                        file: Some(file),
                        identity,
                        name,
                        armed: true,
                    });
                }
                Err(Errno::EXIST) => continue,
                Err(error) => return Err(map_errno("cannot create cache temp", error)),
            }
        }
        Err(CacheError::io("cannot allocate a unique cache temp name"))
    }

    fn file_mut(&mut self) -> Result<&mut File, CacheError> {
        self.file
            .as_mut()
            .ok_or_else(|| CacheError::io("cache temp descriptor is unavailable"))
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn disarm(&mut self) {
        self.armed = false;
    }

    fn remove_owned(&mut self) -> Result<(), CacheError> {
        self.armed = false;
        unlink_verified(self.directory, &self.name, self.identity)?;
        Ok(())
    }

    fn remove_if_armed(&mut self) -> Result<(), CacheError> {
        if self.armed {
            self.remove_owned()
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum TempCreateFault {
    None,
    FirstIdentity,
    Chmod,
    SecondIdentity,
}

impl Drop for OwnedTemporary<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.remove_owned();
        }
    }
}

fn named_identity(directory: &CacheDirectory, name: &str) -> Result<ObjectIdentity, CacheError> {
    let descriptor = openat(&*directory.file, name, INSPECT_FLAGS, Mode::empty()).map_err(
        |error| match error {
            Errno::LOOP | Errno::NOTDIR => {
                CacheError::path(format!("unsafe cache publication leaf: {error}"))
            }
            _ => map_errno("cannot inspect cache publication leaf", error),
        },
    )?;
    ObjectIdentity::regular_file(&File::from(descriptor))
}

fn unlink_verified(
    directory: &CacheDirectory,
    name: &str,
    expected: ObjectIdentity,
) -> Result<(), CacheError> {
    let actual = named_identity(directory, name)?;
    if actual != expected {
        return Err(CacheError::conflict(
            "refusing to unlink a cache leaf with an unexpected identity or mode",
        ));
    }
    unlinkat(&*directory.file, name, AtFlags::empty())
        .map_err(|error| map_errno("cannot unlink verified cache leaf", error))
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use qtrace_provider::{
        ArtifactDigest, EventKey, EventKind, OperationAbort, TimelineId, WorkDelta, WorkGuard,
    };
    use tempfile::TempDir;

    use super::{
        INJECT_DIRECTORY_FSYNC_FAILURES, OwnedTemporary, PublicationLock, TempCreateFault,
    };
    use crate::cache::{
        CacheDirectory, CacheIdentity, CacheWriter, OwnedStoreView, PublicationState,
    };

    struct AllowAll;

    impl WorkGuard for AllowAll {
        fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
            Ok(())
        }
    }

    #[test]
    fn temp_setup_failures_leave_no_random_temporary_name() {
        for fault in [
            TempCreateFault::FirstIdentity,
            TempCreateFault::Chmod,
            TempCreateFault::SecondIdentity,
        ] {
            let root = TempDir::new().expect("root");
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
                .expect("private root");
            let directory = CacheDirectory::open(root.path(), &"a".repeat(64), true, &AllowAll)
                .expect("directory")
                .expect("created directory");
            let _lock = PublicationLock::acquire(&directory).expect("publication lock");
            assert!(
                OwnedTemporary::create_impl(&directory, fault).is_err(),
                "injected setup failure was ignored"
            );
            let entries = fs::read_dir(root.path().join("qtrace-ui").join("a".repeat(64)))
                .expect("digest entries")
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
                .count();
            assert_eq!(entries, 0, "temp leaked after injected setup failure");
        }
    }

    #[test]
    fn directory_fsync_failure_rolls_back_or_reports_uncertain_durability() {
        for failures in [1, 2] {
            let root = TempDir::new().expect("root");
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
                .expect("private root");
            let identity = CacheIdentity {
                analyzer_version: "test".to_owned(),
                artifact_digest: [0x41; 32],
                build_option_digest: [0x42; 32],
                cache_schema: 1,
                endian: "little".to_owned(),
                layout_version: 1,
                source_features: 0,
                source_format: "qtrb".to_owned(),
                source_major: 1,
                source_minor: 2,
            };
            let store = OwnedStoreView::new(
                vec![EventKey::new(
                    ArtifactDigest::new([0x41; 32]),
                    TimelineId(0),
                    0,
                    1,
                    None,
                    None,
                )],
                vec![EventKind::Instruction],
            )
            .expect("store");
            INJECT_DIRECTORY_FSYNC_FAILURES.with(|remaining| remaining.set(failures));
            let error = CacheWriter::new(identity.clone(), store)
                .expect("writer")
                .publish(root.path(), &AllowAll)
                .expect_err("injected directory fsync failure");
            assert!(
                !root
                    .path()
                    .join("qtrace-ui")
                    .join(identity.cache_key())
                    .join("index.qtc")
                    .exists()
            );
            if failures == 1 {
                assert_eq!(error.code(), "cache.io");
                assert_eq!(error.publication_state(), PublicationState::NoVisibleFinal);
            } else {
                assert_eq!(
                    error.publication_state(),
                    PublicationState::VisibleDurabilityUncertain
                );
            }
        }
    }
}
