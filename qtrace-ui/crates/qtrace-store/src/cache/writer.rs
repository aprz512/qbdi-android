use std::{
    fs::File,
    io::{Seek, SeekFrom, Write},
    mem::size_of,
    path::Path,
};

use qtrace_provider::{EventKey, EventKind, OperationAbort, WorkDelta, WorkGuard};
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
const LOCK_OPEN_FLAGS: OFlags = OFlags::RDWR
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);
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
        let publication_lock = PublicationLock::acquire(&directory, guard)?;
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

    pub(crate) fn remove_published(
        root: &Path,
        identity: &CacheIdentity,
    ) -> Result<(), CacheError> {
        struct CleanupGuard;
        impl WorkGuard for CleanupGuard {
            fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
                Ok(())
            }
        }
        let key = identity.cache_key();
        let directory =
            CacheDirectory::open(root, &key, false, &CleanupGuard)?.ok_or_else(|| {
                CacheError::conflict("published cache directory disappeared before rollback")
            })?;
        let publication_lock = PublicationLock::acquire(&directory, &CleanupGuard)?;
        directory.verify()?;
        publication_lock.verify()?;
        let (file, object) = open_final(&directory)?
            .ok_or_else(|| CacheError::conflict("published cache disappeared before rollback"))?;
        validate_file(file, &directory, identity, &CleanupGuard).map_err(
            |failure| match failure {
                ValidationFailure::Rebuild(reason) => CacheError::conflict(format!(
                    "published rollback target is invalid: {reason:?}"
                )),
                ValidationFailure::Fatal(error) => error,
            },
        )?;
        directory.verify()?;
        publication_lock.verify()?;
        unlink_verified(&directory, FINAL_NAME, object)?;
        sync_directory(&directory.file, "cannot fsync published-cache rollback")?;
        directory.verify()?;
        publication_lock.verify()?;
        Ok(())
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
        let extras = self
            .store
            .extra_sections()
            .iter()
            .try_fold(0_usize, |total, section| {
                total
                    .checked_add(section.bytes.capacity())
                    .ok_or_else(|| CacheError::invalid("extra-section resident bound overflow"))
            })?;
        let identity_text = self
            .identity
            .analyzer_version
            .capacity()
            .checked_add(self.identity.source_format.capacity())
            .ok_or_else(|| CacheError::invalid("identity resident bound overflow"))?;
        let peak = keys
            .checked_add(kinds)
            .and_then(|value| value.checked_add(extras))
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
            sync_directory(&directory.file, "cannot fsync cache directory").map_err(|error| {
                CacheError::durability(format!(
                    "valid cache winner remains visible, but temp-cleanup fsync failed: {error}"
                ))
            })?;
            publication_lock.verify().map_err(|error| {
                CacheError::durability(format!(
                    "valid cache winner remains visible, but lock proof failed: {error}"
                ))
            })?;
            directory.verify()?;
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
        let mut next_offset = keys_offset
            .checked_add(keys_length)
            .ok_or_else(|| CacheError::invalid("manifest offset overflow"))?;
        let mut sections = Vec::new();
        sections
            .try_reserve_exact(2 + self.store.extra_sections().len())
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
        for section in self.store.extra_sections() {
            guard.consume(WorkDelta::default())?;
            let offset = align_up(next_offset, u64::from(section.alignment))?;
            let padding = usize::try_from(offset - next_offset)
                .map_err(|_| CacheError::invalid("extra-section padding overflow"))?;
            if padding > 0 {
                let zeros = [0_u8; 4096];
                write_part(file, &zeros[..padding], guard)?;
            }
            let mut digest = Sha256::new();
            for chunk in section.bytes.chunks(SECTION_CHUNK_BYTES) {
                guard.consume(WorkDelta {
                    rows: (chunk.len() / section.element_size as usize) as u64,
                    ..WorkDelta::default()
                })?;
                digest.update(chunk);
                write_part(file, chunk, guard)?;
            }
            let length = u64::try_from(section.bytes.len())
                .map_err(|_| CacheError::invalid("extra-section length does not fit u64"))?;
            next_offset = offset
                .checked_add(length)
                .ok_or_else(|| CacheError::invalid("extra-section range overflow"))?;
            sections.push(SectionDescriptor {
                alignment: section.alignment,
                checksum: digest.finalize().into(),
                element_size: section.element_size,
                length,
                name: try_owned(section.name)?,
                offset,
            });
        }
        Ok((sections, next_offset))
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
    if let Err(error) = directory.verify() {
        return rollback_after_error(directory, publication_lock, transaction, error).map(|_| ());
    }
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
        publication_lock.verify().map_err(|error| {
            CacheError::durability(format!(
                "published cache lock proof failed after cleanup fsync: {error}"
            ))
        })?;
        if named_identity(directory, FINAL_NAME)? != *own {
            return Err(CacheError::durability(
                "published final changed after displaced-cache cleanup fsync",
            ));
        }
        directory.verify().map_err(|error| {
            CacheError::durability(format!(
                "published cache directory changed after irreversible cleanup: {error}"
            ))
        })?;
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
    fsync(file).map_err(|error| map_errno(context, error))?;
    #[cfg(test)]
    POST_DIRECTORY_FSYNC_HOOK.with(|slot| {
        let mut slot = slot.borrow_mut();
        if let Some(hook) = slot.as_mut() {
            hook.remaining -= 1;
            if hook.remaining == 0 {
                (hook.action)();
                *slot = None;
            }
        }
    });
    Ok(())
}

#[cfg(test)]
thread_local! {
    static INJECT_DIRECTORY_FSYNC_FAILURES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static POST_DIRECTORY_FSYNC_HOOK: std::cell::RefCell<Option<PostDirectoryFsyncHook>> = const { std::cell::RefCell::new(None) };
    static INJECT_LOCK_SETUP_FAULT: std::cell::Cell<CreatedLeafFault> = const { std::cell::Cell::new(CreatedLeafFault::None) };
    static INJECT_CREATED_LEAF_RECOVERY_RESOURCE_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
struct PostDirectoryFsyncHook {
    remaining: usize,
    action: Box<dyn FnMut()>,
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
    fn acquire(directory: &'a CacheDirectory, guard: &dyn WorkGuard) -> Result<Self, CacheError> {
        guard.consume(WorkDelta {
            nodes: 1,
            ..WorkDelta::default()
        })?;
        let (descriptor, created) = match openat(
            &*directory.file,
            LOCK_NAME,
            LOCK_CREATE_FLAGS,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(descriptor) => (descriptor, true),
            Err(Errno::EXIST) => (
                openat(&*directory.file, LOCK_NAME, LOCK_OPEN_FLAGS, Mode::empty())
                    .map_err(map_lock_open_error)?,
                false,
            ),
            Err(error) => return Err(map_lock_open_error(error)),
        };
        let file = File::from(descriptor);
        let identity = if created {
            finalize_created_regular_leaf(
                directory,
                &file,
                LOCK_NAME,
                take_lock_setup_fault(),
                "cache publication lock",
            )
        } else {
            ObjectIdentity::regular_file(&file)
        }?;
        if identity.permissions != 0o600 {
            return Err(CacheError::path(
                "cache publication lock does not have mode 0600",
            ));
        }
        loop {
            guard.consume(WorkDelta {
                nodes: 1,
                ..WorkDelta::default()
            })?;
            match flock(&file, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => break,
                Err(Errno::WOULDBLOCK) => std::thread::sleep(std::time::Duration::from_millis(1)),
                Err(error) => {
                    return Err(map_errno("cannot acquire cache publication lock", error));
                }
            }
        }
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

#[derive(Clone, Copy, Eq, PartialEq)]
enum CreatedLeafFault {
    None,
    FirstIdentity,
    Chmod,
    SecondIdentity,
}

#[cfg(not(test))]
fn take_lock_setup_fault() -> CreatedLeafFault {
    CreatedLeafFault::None
}

#[cfg(test)]
fn take_lock_setup_fault() -> CreatedLeafFault {
    INJECT_LOCK_SETUP_FAULT.with(|fault| fault.replace(CreatedLeafFault::None))
}

fn recover_created_regular_leaf_identity(file: &File) -> Result<ObjectIdentity, CacheError> {
    #[cfg(test)]
    if INJECT_CREATED_LEAF_RECOVERY_RESOURCE_FAILURE.with(|fault| fault.replace(false)) {
        return Err(map_io_error(
            "injected created leaf recovery fstat",
            std::io::Error::from_raw_os_error(12),
        ));
    }
    ObjectIdentity::regular_file(file)
}

fn finalize_created_regular_leaf(
    directory: &CacheDirectory,
    file: &File,
    name: &str,
    fault: CreatedLeafFault,
    kind: &str,
) -> Result<ObjectIdentity, CacheError> {
    let provisional_result = if fault == CreatedLeafFault::FirstIdentity {
        Err(CacheError::io(format!(
            "injected first {kind} fstat failure"
        )))
    } else {
        ObjectIdentity::regular_file(file)
    };
    let provisional = match provisional_result {
        Ok(identity) => identity,
        Err(error) => {
            let recovery = recover_created_regular_leaf_identity(file).map_err(|proof_error| {
                proof_error.with_static_context(
                    "created cache leaf setup failed; held identity recovery failed; leaf preserved",
                )
            })?;
            remove_created_regular_leaf(directory, name, recovery)?;
            return Err(error);
        }
    };
    let chmod_result = if fault == CreatedLeafFault::Chmod {
        Err(Errno::IO)
    } else {
        fchmod(file, Mode::RUSR | Mode::WUSR)
    };
    if let Err(error) = chmod_result {
        remove_created_regular_leaf(directory, name, provisional)?;
        return Err(map_errno(
            &format!("cannot finalize private {kind} mode"),
            error,
        ));
    }
    let identity_result = if fault == CreatedLeafFault::SecondIdentity {
        Err(CacheError::io(format!(
            "injected second {kind} fstat failure"
        )))
    } else {
        ObjectIdentity::regular_file(file)
    };
    let identity = match identity_result {
        Ok(identity) => identity,
        Err(error) => {
            remove_created_regular_leaf(directory, name, provisional)?;
            return Err(error);
        }
    };
    if !provisional.same_object(identity) {
        return Err(CacheError::conflict(format!(
            "{kind} identity changed during mode finalization"
        )));
    }
    if identity.permissions != 0o600 {
        remove_created_regular_leaf(directory, name, identity)?;
        return Err(CacheError::path(format!("{kind} does not have mode 0600")));
    }
    Ok(identity)
}

fn remove_created_regular_leaf(
    directory: &CacheDirectory,
    name: &str,
    expected: ObjectIdentity,
) -> Result<(), CacheError> {
    let actual = named_identity(directory, name)?;
    if !expected.same_object(actual) {
        return Err(CacheError::conflict(
            "refusing to remove a replaced created cache leaf",
        ));
    }
    unlinkat(&*directory.file, name, AtFlags::empty())
        .map_err(|error| map_errno("cannot remove failed created cache leaf", error))
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
        Self::create_impl(directory, CreatedLeafFault::None)
    }

    fn create_impl(
        directory: &'a CacheDirectory,
        fault: CreatedLeafFault,
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
                    let identity = finalize_created_regular_leaf(
                        directory,
                        &file,
                        &name,
                        fault,
                        "cache temp",
                    )?;
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
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::PathBuf,
        process::Command,
        sync::mpsc,
        thread,
        time::{Duration, Instant},
    };

    use qtrace_provider::{
        ArtifactDigest, EventKey, EventKind, OperationAbort, TimelineId, WorkDelta, WorkGuard,
    };
    use tempfile::TempDir;

    use super::{
        CreatedLeafFault, INJECT_CREATED_LEAF_RECOVERY_RESOURCE_FAILURE,
        INJECT_DIRECTORY_FSYNC_FAILURES, INJECT_LOCK_SETUP_FAULT, OwnedTemporary,
        POST_DIRECTORY_FSYNC_HOOK, PostDirectoryFsyncHook, PublicationLock,
    };
    use crate::cache::{
        CacheDirectory, CacheIdentity, CacheOpen, CacheReader, CacheWriter, OwnedStoreView,
        PublicationState,
    };

    struct AllowAll;

    impl WorkGuard for AllowAll {
        fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
            Ok(())
        }
    }

    struct DeadlineGuard {
        deadline: Instant,
    }

    impl WorkGuard for DeadlineGuard {
        fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
            if Instant::now() >= self.deadline {
                Err(OperationAbort::Cancelled)
            } else {
                Ok(())
            }
        }
    }

    fn identity(seed: u8) -> CacheIdentity {
        CacheIdentity {
            analyzer_version: "test".to_owned(),
            artifact_digest: [seed; 32],
            build_option_digest: [seed.wrapping_add(1); 32],
            cache_schema: 1,
            endian: "little".to_owned(),
            layout_version: 1,
            source_features: 0,
            source_format: "qtrb".to_owned(),
            source_major: 1,
            source_minor: 2,
        }
    }

    fn store(seed: u8) -> OwnedStoreView {
        OwnedStoreView::new(
            vec![EventKey::new(
                ArtifactDigest::new([seed; 32]),
                TimelineId(0),
                0,
                1,
                None,
                None,
            )],
            vec![EventKind::Instruction],
        )
        .expect("store")
    }

    fn private_root() -> TempDir {
        let root = TempDir::new().expect("root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private root");
        root
    }

    fn digest_path(root: &TempDir, identity: &CacheIdentity) -> PathBuf {
        root.path().join("qtrace-ui").join(identity.cache_key())
    }

    fn install_rebind_after_sync(digest: PathBuf, sync_count: usize) {
        POST_DIRECTORY_FSYNC_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(PostDirectoryFsyncHook {
                remaining: sync_count,
                action: Box::new(move || {
                    fs::rename(&digest, digest.with_extension("held")).expect("move digest");
                    fs::create_dir(&digest).expect("replacement digest");
                    fs::set_permissions(&digest, fs::Permissions::from_mode(0o700))
                        .expect("private replacement");
                }),
            });
        });
    }

    struct RestoreUmask(rustix::fs::Mode);

    impl Drop for RestoreUmask {
        fn drop(&mut self) {
            rustix::process::umask(self.0);
        }
    }

    fn run_umask_child(test: &str, mode: &str) {
        let status = Command::new(std::env::current_exe().expect("test executable"))
            .arg("--exact")
            .arg(test)
            .arg("--nocapture")
            .env("QTRACE_STORE_UMASK_CHILD", mode)
            .status()
            .expect("umask child");
        assert!(status.success(), "umask {mode} child failed");
    }

    #[test]
    fn ordinary_umasks_create_exact_private_cache_modes() {
        const TEST: &str = "cache::writer::tests::ordinary_umasks_create_exact_private_cache_modes";
        let Some(mode) = std::env::var_os("QTRACE_STORE_UMASK_CHILD") else {
            for mode in ["022", "077"] {
                run_umask_child(TEST, mode);
            }
            return;
        };
        let parent = private_root();
        let root = parent.path().join("xdg-cache");
        let mode = u32::from_str_radix(&mode.to_string_lossy(), 8).expect("octal umask");
        let previous = rustix::process::umask(rustix::fs::Mode::from_raw_mode(mode));
        let _restore = RestoreUmask(previous);
        let identity = identity(0x55);
        CacheWriter::new(identity.clone(), store(0x55))
            .expect("writer")
            .publish(&root, &AllowAll)
            .expect("publish under ordinary umask");
        let app = root.join("qtrace-ui");
        let digest = app.join(identity.cache_key());
        for directory in [&root, &app, &digest] {
            assert_eq!(
                fs::metadata(directory).expect("directory metadata").mode() & 0o7777,
                0o700
            );
        }
        for file in [digest.join(".publish.lock"), digest.join("index.qtc")] {
            assert_eq!(
                fs::metadata(file).expect("file metadata").mode() & 0o7777,
                0o600
            );
        }
    }

    #[test]
    fn all_bits_umask_fails_closed_without_target_or_staging() {
        const TEST: &str =
            "cache::writer::tests::all_bits_umask_fails_closed_without_target_or_staging";
        if std::env::var_os("QTRACE_STORE_UMASK_CHILD").is_none() {
            run_umask_child(TEST, "777");
            return;
        }
        let parent = private_root();
        let root = parent.path().join("xdg-cache");
        let previous = rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o777));
        let _restore = RestoreUmask(previous);
        let error = CacheWriter::new(identity(0x57), store(0x57))
            .expect("writer")
            .publish(&root, &AllowAll)
            .expect_err("descriptor-bound chmod is unavailable");
        assert_eq!(error.code(), "cache.permission_denied");
        assert!(!root.exists(), "private target must not be published");
        assert_eq!(
            fs::read_dir(parent.path())
                .expect("parent entries")
                .filter_map(Result::ok)
                .count(),
            0,
            "verified staging directory must be cleaned"
        );
    }

    #[test]
    fn new_lock_setup_failures_remove_the_insecure_created_leaf() {
        for fault in [
            CreatedLeafFault::FirstIdentity,
            CreatedLeafFault::Chmod,
            CreatedLeafFault::SecondIdentity,
        ] {
            let root = private_root();
            let identity = identity(0x56);
            let directory =
                CacheDirectory::open(root.path(), &identity.cache_key(), true, &AllowAll)
                    .expect("directory")
                    .expect("created directory");
            INJECT_LOCK_SETUP_FAULT.with(|injected| injected.set(fault));
            let error = match PublicationLock::acquire(&directory, &AllowAll) {
                Err(error) => error,
                Ok(_) => panic!("injected lock setup failure was ignored"),
            };
            assert_eq!(error.code(), "cache.io");
            assert!(
                !digest_path(&root, &identity).join(".publish.lock").exists(),
                "insecure lock leaked after injected setup failure"
            );
        }
    }

    #[test]
    fn lock_wait_is_cancellable_without_releasing_the_holder() {
        let root = private_root();
        let identity = identity(0x50);
        let directory = CacheDirectory::open(root.path(), &identity.cache_key(), true, &AllowAll)
            .expect("directory")
            .expect("created directory");
        let holder = PublicationLock::acquire(&directory, &AllowAll).expect("holder lock");
        let root_path = root.path().to_owned();
        let contender_identity = identity.clone();
        let (sender, receiver) = mpsc::channel();
        let contender = thread::spawn(move || {
            let guard = DeadlineGuard {
                deadline: Instant::now() + Duration::from_millis(20),
            };
            let result = CacheWriter::new(contender_identity, store(0x50))
                .expect("contender writer")
                .publish(&root_path, &guard);
            sender.send(result).expect("send contender result");
        });
        let timely = receiver.recv_timeout(Duration::from_millis(250));
        drop(holder);
        contender.join().expect("contender thread");
        let error = timely
            .expect("contender blocked past cancellation deadline")
            .expect_err("contender should be cancelled while waiting");
        assert_eq!(error.code(), "job.cancelled");
        let digest = digest_path(&root, &identity);
        assert!(!digest.join("index.qtc").exists());
        assert_eq!(
            fs::read_dir(&digest)
                .expect("digest entries")
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
                .count(),
            0
        );
        CacheWriter::new(identity, store(0x50))
            .expect("writer after unlock")
            .publish(root.path(), &AllowAll)
            .expect("publish after unlock");
    }

    #[test]
    fn missing_publish_rebind_after_commit_fsync_rolls_back_held_final() {
        let root = private_root();
        let identity = identity(0x51);
        let digest = digest_path(&root, &identity);
        install_rebind_after_sync(digest.clone(), 1);
        let error = CacheWriter::new(identity, store(0x51))
            .expect("writer")
            .publish(root.path(), &AllowAll)
            .expect_err("post-fsync rebind must not return Published");
        assert_eq!(error.code(), "cache.path_escape");
        assert!(!digest.with_extension("held").join("index.qtc").exists());
    }

    #[test]
    fn corrupt_publish_rebind_after_final_fsync_is_visibility_uncertain() {
        let root = private_root();
        let identity = identity(0x52);
        CacheWriter::new(identity.clone(), store(0x52))
            .expect("initial writer")
            .publish(root.path(), &AllowAll)
            .expect("initial publish");
        let digest = digest_path(&root, &identity);
        let final_path = digest.join("index.qtc");
        let mut corrupt = fs::read(&final_path).expect("cache bytes");
        corrupt[64] ^= 1;
        fs::write(&final_path, corrupt).expect("corrupt final");
        install_rebind_after_sync(digest.clone(), 2);
        let error = CacheWriter::new(identity, store(0x52))
            .expect("replacement writer")
            .publish(root.path(), &AllowAll)
            .expect_err("post-cleanup-fsync rebind must not return Published");
        assert_eq!(
            error.publication_state(),
            PublicationState::VisibleDurabilityUncertain
        );
        assert!(digest.with_extension("held").join("index.qtc").exists());
    }

    #[test]
    fn valid_winner_rebind_after_cleanup_fsync_never_returns_existing() {
        let root = private_root();
        let identity = identity(0x53);
        CacheWriter::new(identity.clone(), store(0x53))
            .expect("initial writer")
            .publish(root.path(), &AllowAll)
            .expect("initial publish");
        let digest = digest_path(&root, &identity);
        let winner = fs::read(digest.join("index.qtc")).expect("winner bytes");
        install_rebind_after_sync(digest.clone(), 1);
        let error = CacheWriter::new(identity, store(0x53))
            .expect("second writer")
            .publish(root.path(), &AllowAll)
            .expect_err("post-fsync rebind must not return Existing");
        assert_eq!(error.code(), "cache.path_escape");
        assert_eq!(
            fs::read(digest.with_extension("held").join("index.qtc")).expect("held winner"),
            winner
        );
    }

    #[test]
    fn valid_winner_cleanup_fsync_failure_reports_visible_uncertainty() {
        let root = private_root();
        let identity = identity(0x54);
        CacheWriter::new(identity.clone(), store(0x54))
            .expect("initial writer")
            .publish(root.path(), &AllowAll)
            .expect("initial publish");
        let final_path = digest_path(&root, &identity).join("index.qtc");
        let winner = fs::read(&final_path).expect("winner bytes");
        INJECT_DIRECTORY_FSYNC_FAILURES.with(|remaining| remaining.set(1));
        let error = CacheWriter::new(identity.clone(), store(0x54))
            .expect("second writer")
            .publish(root.path(), &AllowAll)
            .expect_err("winner cleanup fsync failure");
        assert_eq!(
            error.publication_state(),
            PublicationState::VisibleDurabilityUncertain
        );
        assert_eq!(fs::read(&final_path).expect("winner survives"), winner);
        assert!(matches!(
            CacheReader::open(root.path(), &identity, &AllowAll).expect("reader"),
            CacheOpen::Ready(_)
        ));
    }

    #[test]
    fn temp_setup_failures_leave_no_random_temporary_name() {
        for fault in [
            CreatedLeafFault::FirstIdentity,
            CreatedLeafFault::Chmod,
            CreatedLeafFault::SecondIdentity,
        ] {
            let root = TempDir::new().expect("root");
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
                .expect("private root");
            let directory = CacheDirectory::open(root.path(), &"a".repeat(64), true, &AllowAll)
                .expect("directory")
                .expect("created directory");
            let _lock = PublicationLock::acquire(&directory, &AllowAll).expect("publication lock");
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
    fn created_leaf_recovery_resource_error_remains_control() {
        let root = TempDir::new().expect("root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private root");
        let digest = "a".repeat(64);
        let directory = CacheDirectory::open(root.path(), &digest, true, &AllowAll)
            .expect("directory")
            .expect("created directory");
        let _lock = PublicationLock::acquire(&directory, &AllowAll).expect("publication lock");
        INJECT_CREATED_LEAF_RECOVERY_RESOURCE_FAILURE.with(|injected| injected.set(true));

        let error = match OwnedTemporary::create_impl(&directory, CreatedLeafFault::FirstIdentity) {
            Err(error) => error,
            Ok(_) => panic!("both created leaf identity checks must fail"),
        };

        assert_eq!(error.code(), "control.resource_exhausted");
        assert!(error.is_control());
        assert_eq!(error.publication_state(), PublicationState::NoVisibleFinal);
        let temporary_count = fs::read_dir(root.path().join("qtrace-ui").join(digest))
            .expect("digest entries")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(temporary_count, 1, "unproved temp must be preserved");
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
