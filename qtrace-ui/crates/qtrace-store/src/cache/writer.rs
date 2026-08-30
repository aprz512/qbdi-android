use std::{
    fs::File,
    io::{Seek, SeekFrom, Write},
    path::Path,
};

use qtrace_provider::{WorkDelta, WorkGuard};
use rustix::{
    fs::{AtFlags, Mode, OFlags, RenameFlags, fchmod, fsync, openat, renameat_with, unlinkat},
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
    reader::{ValidationFailure, open_final, probe_identity, validate_file},
};

const FINAL_NAME: &str = "index.qtc";
const CREATE_FLAGS: OFlags = OFlags::WRONLY
    .union(OFlags::CREATE)
    .union(OFlags::EXCL)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const INSPECT_FLAGS: OFlags = OFlags::PATH.union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);

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
        let encoded = self.encode(guard)?;
        let key = self.identity.cache_key();
        let directory = CacheDirectory::open(root, &key, true, guard)?
            .ok_or_else(|| CacheError::io("created cache directory disappeared"))?;
        guard.consume(WorkDelta {
            nodes: 1,
            resident_bytes: 128,
            ..WorkDelta::default()
        })?;
        let mut temporary = OwnedTemporary::create(&directory)?;
        write_part(temporary.file_mut()?, &[0_u8; HEADER_BYTES], guard)?;
        write_part(
            temporary.file_mut()?,
            &encoded.bytes[HEADER_BYTES..encoded.manifest_offset],
            guard,
        )?;

        // Checkpoint 1: all sections are present, while only the private temp is visible.
        guard.consume(WorkDelta::default())?;
        write_part(
            temporary.file_mut()?,
            &encoded.bytes[encoded.manifest_offset..],
            guard,
        )?;

        // Checkpoint 2: the manifest is present, but the placeholder header is not finalized.
        guard.consume(WorkDelta::default())?;
        temporary
            .file_mut()?
            .seek(SeekFrom::Start(0))
            .map_err(|error| CacheError::io(error.to_string()))?;
        write_part(temporary.file_mut()?, &encoded.bytes[..HEADER_BYTES], guard)?;
        guard.consume(WorkDelta {
            nodes: 1,
            ..WorkDelta::default()
        })?;
        temporary
            .file_mut()?
            .sync_all()
            .map_err(|error| CacheError::io(format!("cannot fsync cache temp: {error}")))?;

        // Checkpoint 3: the complete temp is durable, and no final name has changed.
        guard.consume(WorkDelta::default())?;
        guard.consume(WorkDelta {
            nodes: 2,
            ..WorkDelta::default()
        })?;
        directory.verify()?;
        let state = inspect_final(&directory, &self.identity, guard)?;

        // Checkpoint 4: cancellation and injected failure remain strictly before rename.
        guard.consume(WorkDelta::default())?;
        guard.consume(WorkDelta {
            nodes: 2,
            ..WorkDelta::default()
        })?;
        directory.verify()?;
        let outcome = match state {
            FinalState::Missing => {
                publish_missing(&directory, &mut temporary, &self.identity, guard)?
            }
            FinalState::Valid => PublishOutcome::Existing,
            FinalState::CorruptSame(old) => {
                publish_replacement(&directory, &mut temporary, old)?;
                PublishOutcome::Published
            }
        };
        if outcome == PublishOutcome::Existing {
            temporary.remove_owned().map_err(|error| {
                CacheError::durability(format!(
                    "a valid cache winner is visible, but temp cleanup failed: {error}"
                ))
            })?;
            directory.verify().map_err(|error| {
                CacheError::durability(format!(
                    "a valid cache winner is visible, but its directory binding changed: {error}"
                ))
            })?;
            fsync(&*directory.file).map_err(|error| {
                CacheError::durability(format!(
                    "a valid cache winner is visible, but parent-directory fsync failed: {error}"
                ))
            })?;
            return Ok(outcome);
        }
        directory.verify().map_err(|error| {
            CacheError::durability(format!(
                "cache was renamed, but its directory binding changed before fsync: {error}"
            ))
        })?;
        fsync(&*directory.file).map_err(|error| {
            CacheError::durability(format!(
                "cache is visible, but parent-directory fsync failed: {error}"
            ))
        })?;
        Ok(outcome)
    }

    fn encode(&self, guard: &dyn WorkGuard) -> Result<EncodedCache, CacheError> {
        let key_length = self
            .store
            .keys()
            .len()
            .checked_mul(EVENT_KEY_BYTES)
            .ok_or_else(|| CacheError::invalid("event-key section length overflow"))?;
        let kinds_length = self.store.kinds().len();
        let upper_bound = key_length
            .checked_add(kinds_length)
            .and_then(|value| value.checked_add(HEADER_BYTES))
            .and_then(|value| value.checked_add(MAX_MANIFEST_BYTES as usize))
            .ok_or_else(|| CacheError::invalid("cache allocation bound overflow"))?;
        guard.consume(WorkDelta {
            resident_bytes: upper_bound as u64,
            ..WorkDelta::default()
        })?;
        let kinds_offset = HEADER_BYTES;
        let kinds_end = kinds_offset
            .checked_add(kinds_length)
            .ok_or_else(|| CacheError::invalid("event-kind section length overflow"))?;
        let key_offset = align_up(kinds_end, 8)?;
        let mut keys = Vec::new();
        keys.try_reserve_exact(key_length)
            .map_err(|_| CacheError::io("event-key cache allocation failed"))?;
        let mut kinds = Vec::new();
        kinds
            .try_reserve_exact(kinds_length)
            .map_err(|_| CacheError::io("event-kind cache allocation failed"))?;
        let mut first = 0_usize;
        while first < self.store.keys().len() {
            let end = first.saturating_add(4096).min(self.store.keys().len());
            guard.consume(WorkDelta {
                rows: (end - first) as u64,
                ..WorkDelta::default()
            })?;
            for row in first..end {
                if self.store.keys()[row].artifact.as_bytes() != &self.identity.artifact_digest {
                    return Err(CacheError::invalid(
                        "event key artifact digest differs from cache identity",
                    ));
                }
                let mut encoded = [0_u8; EVENT_KEY_BYTES];
                encode_event_key(&self.store.keys()[row], &mut encoded);
                keys.extend_from_slice(&encoded);
                kinds.push(encode_event_kind(self.store.kinds()[row]));
            }
            first = end;
        }
        let sections = vec![
            SectionDescriptor {
                alignment: 1,
                checksum: Sha256::digest(&kinds).into(),
                element_size: 1,
                length: kinds.len() as u64,
                name: EVENT_KINDS_SECTION.to_owned(),
                offset: kinds_offset as u64,
            },
            SectionDescriptor {
                alignment: 8,
                checksum: Sha256::digest(&keys).into(),
                element_size: EVENT_KEY_BYTES as u32,
                length: keys.len() as u64,
                name: EVENT_KEYS_SECTION.to_owned(),
                offset: key_offset as u64,
            },
        ];
        let manifest = CacheManifest {
            identity: self.identity.clone(),
            sections,
        };
        let manifest_bytes = manifest.canonical_bytes()?;
        let manifest_offset = key_offset
            .checked_add(keys.len())
            .ok_or_else(|| CacheError::invalid("manifest offset overflow"))?;
        let total = manifest_offset
            .checked_add(manifest_bytes.len())
            .ok_or_else(|| CacheError::invalid("cache file length overflow"))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(total)
            .map_err(|_| CacheError::io("cache-file allocation failed"))?;
        bytes.resize(HEADER_BYTES, 0);
        bytes.extend_from_slice(&kinds);
        bytes.resize(key_offset, 0);
        bytes.extend_from_slice(&keys);
        bytes.extend_from_slice(&manifest_bytes);
        let header = CacheHeader {
            schema: self.identity.cache_schema,
            manifest_offset: manifest_offset as u64,
            manifest_length: manifest_bytes.len() as u64,
            manifest_checksum: Sha256::digest(&manifest_bytes).into(),
        };
        bytes[..HEADER_BYTES].copy_from_slice(&header.encode());
        Ok(EncodedCache {
            bytes,
            manifest_offset,
        })
    }
}

fn align_up(value: usize, alignment: usize) -> Result<usize, CacheError> {
    let mask = alignment
        .checked_sub(1)
        .ok_or_else(|| CacheError::invalid("zero cache alignment"))?;
    value
        .checked_add(mask)
        .map(|rounded| rounded & !mask)
        .ok_or_else(|| CacheError::invalid("cache alignment overflow"))
}

struct EncodedCache {
    bytes: Vec<u8>,
    manifest_offset: usize,
}

enum FinalState {
    Missing,
    Valid,
    CorruptSame(ObjectIdentity),
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
        .map_err(|error| CacheError::io(format!("cannot clone cache descriptor: {error}")))?;
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

fn publish_missing(
    directory: &CacheDirectory,
    temporary: &mut OwnedTemporary,
    expected: &CacheIdentity,
    guard: &dyn WorkGuard,
) -> Result<PublishOutcome, CacheError> {
    match renameat_with(
        &*directory.file,
        temporary.name(),
        &*directory.file,
        FINAL_NAME,
        RenameFlags::NOREPLACE,
    ) {
        Ok(()) => {
            temporary.disarm();
            Ok(PublishOutcome::Published)
        }
        Err(Errno::EXIST) => match inspect_final(directory, expected, guard)? {
            FinalState::Valid => Ok(PublishOutcome::Existing),
            FinalState::CorruptSame(old) => {
                publish_replacement(directory, temporary, old)?;
                Ok(PublishOutcome::Published)
            }
            FinalState::Missing => Err(CacheError::path(
                "cache final disappeared during no-replace publication",
            )),
        },
        Err(error) => Err(CacheError::io(format!(
            "cannot publish cache without replacement: {error}"
        ))),
    }
}

fn publish_replacement(
    directory: &CacheDirectory,
    temporary: &mut OwnedTemporary,
    expected_old: ObjectIdentity,
) -> Result<(), CacheError> {
    renameat_with(
        &*directory.file,
        temporary.name(),
        &*directory.file,
        FINAL_NAME,
        RenameFlags::EXCHANGE,
    )
    .map_err(|error| {
        CacheError::io(format!("cannot atomically exchange corrupt cache: {error}"))
    })?;
    let displaced = named_identity(directory, temporary.name()).map_err(|error| {
        CacheError::durability(format!(
            "replacement cache is visible, but displaced-leaf verification failed: {error}"
        ))
    })?;
    if displaced != expected_old {
        rollback_exchange(directory, temporary).map_err(|error| {
            CacheError::durability(format!(
                "replacement cache may be visible because safe exchange rollback failed: {error}"
            ))
        })?;
        return Err(CacheError::conflict(
            "cache leaf changed identity during corrupt-cache replacement",
        ));
    }
    unlink_verified(directory, temporary.name(), expected_old).map_err(|error| {
        CacheError::durability(format!(
            "replacement cache is visible, but displaced cache cleanup failed: {error}"
        ))
    })?;
    temporary.disarm();
    Ok(())
}

fn rollback_exchange(
    directory: &CacheDirectory,
    temporary: &OwnedTemporary,
) -> Result<(), CacheError> {
    let final_identity = named_identity(directory, FINAL_NAME)?;
    if final_identity != temporary.identity {
        return Err(CacheError::conflict(
            "cannot safely roll back cache exchange after a competing rename",
        ));
    }
    renameat_with(
        &*directory.file,
        temporary.name(),
        &*directory.file,
        FINAL_NAME,
        RenameFlags::EXCHANGE,
    )
    .map_err(|error| {
        CacheError::conflict(format!("cannot safely roll back cache exchange: {error}"))
    })
}

fn write_part(file: &mut File, bytes: &[u8], guard: &dyn WorkGuard) -> Result<(), CacheError> {
    guard.consume(WorkDelta {
        input_bytes: bytes.len() as u64,
        ..WorkDelta::default()
    })?;
    file.write_all(bytes)
        .map_err(|error| CacheError::io(error.to_string()))
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
                    fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(|error| {
                        CacheError::io(format!("cannot set private cache temp mode: {error}"))
                    })?;
                    let identity = ObjectIdentity::regular_file(&file)?;
                    return Ok(Self {
                        directory,
                        file: Some(file),
                        identity,
                        name,
                        armed: true,
                    });
                }
                Err(Errno::EXIST) => continue,
                Err(error) => {
                    return Err(CacheError::io(format!("cannot create cache temp: {error}")));
                }
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
        unlink_verified(self.directory, &self.name, self.identity)?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for OwnedTemporary<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = unlink_verified(self.directory, &self.name, self.identity);
        }
    }
}

fn named_identity(directory: &CacheDirectory, name: &str) -> Result<ObjectIdentity, CacheError> {
    let descriptor =
        openat(&*directory.file, name, INSPECT_FLAGS, Mode::empty()).map_err(|error| {
            CacheError::path(format!("cannot inspect cache publication leaf: {error}"))
        })?;
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
            "refusing to unlink a cache leaf with an unexpected identity",
        ));
    }
    unlinkat(&*directory.file, name, AtFlags::empty())
        .map_err(|error| CacheError::io(format!("cannot unlink owned cache temp: {error}")))
}
