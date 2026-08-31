use std::{
    collections::{BTreeMap, HashSet},
    fs::{File, Metadata},
    os::unix::fs::{FileExt, MetadataExt},
    sync::Arc,
};

use qtrace_provider::{EventKey, EventKind, OperationAbort, WorkDelta, WorkGuard};
use rustix::{
    fs::{Mode, OFlags, openat},
    io::Errno,
};
use sha2::{Digest, Sha256};

use crate::layout::{
    CacheHeader, EVENT_KEY_BYTES, EVENT_KEYS_SECTION, EVENT_KINDS_SECTION, HEADER_BYTES,
    decode_event_key, decode_event_kind, known_section_contract,
};

use super::{
    CacheDirectory, CacheError, CacheIdentity, CacheManifest, ObjectIdentity, RebuildReason,
    StoreView, allocation_error,
    manifest::{MAX_MANIFEST_BYTES, canonical_manifest_json},
    map_errno, map_io_error,
};

const FINAL_NAME: &str = "index.qtc";
const READ_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NONBLOCK)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const CHECKSUM_CHUNK_BYTES: usize = 64_000;

#[cfg(test)]
std::thread_local! {
    static INJECT_PROOF_CLONE_ERRNO: std::cell::Cell<Option<i32>> = const { std::cell::Cell::new(None) };
}

#[derive(Debug)]
pub enum CacheOpen {
    Missing,
    Ready(MappedStoreView),
    Rebuild(RebuildReason),
}

pub struct CacheReader;

impl CacheReader {
    pub fn open(
        root: &std::path::Path,
        expected: &CacheIdentity,
        guard: &dyn WorkGuard,
    ) -> Result<CacheOpen, CacheError> {
        expected.validate()?;
        guard.consume(WorkDelta {
            resident_bytes: 512,
            ..WorkDelta::default()
        })?;
        let key = expected.cache_key();
        let Some(directory) = CacheDirectory::open(root, &key, false, guard)? else {
            return Ok(CacheOpen::Missing);
        };
        let Some((file, _)) = open_final(&directory)? else {
            return Ok(CacheOpen::Missing);
        };
        let proof = clone_proof_descriptor(&file)?;
        let stamp = FileStamp::from_metadata(
            &proof
                .metadata()
                .map_err(|error| map_io_error("cannot stat cache proof", error))?,
        );
        match validate_file(file, &directory, expected, guard) {
            Ok(view) => Ok(CacheOpen::Ready(view)),
            Err(ValidationFailure::Rebuild(reason)) => {
                directory.verify()?;
                stamp.verify(&proof)?;
                Ok(CacheOpen::Rebuild(reason))
            }
            Err(ValidationFailure::Fatal(error)) => Err(error),
        }
    }
}

fn clone_proof_descriptor(file: &File) -> Result<File, CacheError> {
    #[cfg(test)]
    if let Some(errno) = INJECT_PROOF_CLONE_ERRNO.with(std::cell::Cell::take) {
        return Err(map_io_error(
            "cannot clone cache descriptor",
            std::io::Error::from_raw_os_error(errno),
        ));
    }
    file.try_clone()
        .map_err(|error| map_io_error("cannot clone cache descriptor", error))
}

#[derive(Clone, Debug)]
pub struct MappedStoreView {
    file: Arc<File>,
    stamp: FileStamp,
    identity: Arc<CacheIdentity>,
    event_count: usize,
    event_keys_offset: u64,
    event_kinds_offset: u64,
    sections: Vec<super::SectionDescriptor>,
}

impl MappedStoreView {
    pub(crate) fn cache_identity(&self) -> &CacheIdentity {
        &self.identity
    }

    fn checked_read<const N: usize>(&self, offset: u64) -> Result<[u8; N], CacheError> {
        self.stamp.verify(&self.file)?;
        let mut output = [0_u8; N];
        read_exact_at(&self.file, offset, &mut output, None)?;
        self.stamp.verify(&self.file)?;
        Ok(output)
    }

    pub(crate) fn section_bytes(
        &self,
        name: &str,
        guard: &dyn WorkGuard,
    ) -> Result<Option<Vec<u8>>, CacheError> {
        let Some(section) = self.sections.iter().find(|section| section.name == name) else {
            return Ok(None);
        };
        guard.consume(WorkDelta {
            resident_bytes: section.length,
            ..WorkDelta::default()
        })?;
        let length = usize::try_from(section.length)
            .map_err(|_| CacheError::access("cache section length does not fit usize"))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| allocation_error("mapped cache section"))?;
        bytes.resize(length, 0);
        self.stamp.verify(&self.file)?;
        read_exact_at(&self.file, section.offset, &mut bytes, Some(guard))?;
        self.stamp.verify(&self.file)?;
        Ok(Some(bytes))
    }
}

impl StoreView for MappedStoreView {
    fn event_count(&self) -> usize {
        self.event_count
    }

    fn event_key(&self, row: usize) -> Result<EventKey, CacheError> {
        if row >= self.event_count {
            return Err(CacheError::access("event row is out of range"));
        }
        let relative = row
            .checked_mul(EVENT_KEY_BYTES)
            .and_then(|value| u64::try_from(value).ok())
            .ok_or_else(|| CacheError::access("event key offset overflow"))?;
        let offset = self
            .event_keys_offset
            .checked_add(relative)
            .ok_or_else(|| CacheError::access("event key offset overflow"))?;
        decode_event_key(&self.checked_read(offset)?)
    }

    fn event_kind(&self, row: usize) -> Result<EventKind, CacheError> {
        if row >= self.event_count {
            return Err(CacheError::access("event row is out of range"));
        }
        let offset = self
            .event_kinds_offset
            .checked_add(row as u64)
            .ok_or_else(|| CacheError::access("event kind offset overflow"))?;
        decode_event_kind(self.checked_read::<1>(offset)?[0])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileStamp {
    device: u64,
    inode: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl FileStamp {
    fn from_metadata(metadata: &Metadata) -> Self {
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

    fn verify(self, file: &File) -> Result<(), CacheError> {
        let actual = FileStamp::from_metadata(
            &file
                .metadata()
                .map_err(|error| map_io_error("cannot restat cache", error))?,
        );
        if actual != self {
            return Err(CacheError::identity(
                "cache identity changed during validation or access",
            ));
        }
        Ok(())
    }
}

pub(crate) enum ValidationFailure {
    Rebuild(RebuildReason),
    Fatal(CacheError),
}

impl From<CacheError> for ValidationFailure {
    fn from(error: CacheError) -> Self {
        Self::Fatal(error)
    }
}

impl From<OperationAbort> for ValidationFailure {
    fn from(error: OperationAbort) -> Self {
        Self::Fatal(CacheError::from(error))
    }
}

pub(crate) fn open_final(
    directory: &CacheDirectory,
) -> Result<Option<(File, ObjectIdentity)>, CacheError> {
    let descriptor = match openat(&*directory.file, FINAL_NAME, READ_FLAGS, Mode::empty()) {
        Ok(descriptor) => descriptor,
        Err(Errno::NOENT) => return Ok(None),
        Err(Errno::LOOP | Errno::NOTDIR | Errno::NXIO) => {
            return Err(CacheError::path("cache leaf is symlinked or unsafe"));
        }
        Err(error) => return Err(map_errno("cannot open cache leaf", error)),
    };
    let file = File::from(descriptor);
    let identity = ObjectIdentity::regular_file(&file)?;
    if identity.permissions != 0o600 {
        return Err(CacheError::path("cache final does not have mode 0600"));
    }
    Ok(Some((file, identity)))
}

pub(crate) fn validate_file(
    file: File,
    directory: &CacheDirectory,
    expected: &CacheIdentity,
    guard: &dyn WorkGuard,
) -> Result<MappedStoreView, ValidationFailure> {
    let stamp = FileStamp::from_metadata(
        &file
            .metadata()
            .map_err(|error| map_io_error("cannot stat cache", error))?,
    );
    if stamp.size < HEADER_BYTES as u64 {
        return Err(ValidationFailure::Rebuild(RebuildReason::Header(
            "truncated",
        )));
    }
    let mut header_bytes = [0_u8; HEADER_BYTES];
    read_exact_at(&file, 0, &mut header_bytes, Some(guard))?;
    let header = CacheHeader::decode(&header_bytes).map_err(ValidationFailure::Rebuild)?;
    if header.schema != expected.cache_schema {
        return Err(ValidationFailure::Rebuild(RebuildReason::Header("schema")));
    }
    let manifest_end = header
        .manifest_offset
        .checked_add(header.manifest_length)
        .ok_or(ValidationFailure::Rebuild(RebuildReason::Manifest(
            "range overflow",
        )))?;
    if header.manifest_offset < HEADER_BYTES as u64
        || header.manifest_length == 0
        || header.manifest_length > MAX_MANIFEST_BYTES
        || manifest_end != stamp.size
    {
        return Err(ValidationFailure::Rebuild(RebuildReason::Manifest("range")));
    }
    let manifest_resident = header
        .manifest_length
        .checked_mul(3)
        .and_then(|value| value.checked_add(MAX_MANIFEST_BYTES))
        .ok_or(ValidationFailure::Rebuild(RebuildReason::Manifest(
            "resident bound",
        )))?;
    guard.consume(WorkDelta {
        resident_bytes: manifest_resident,
        ..WorkDelta::default()
    })?;
    let manifest_length = usize::try_from(header.manifest_length)
        .map_err(|_| ValidationFailure::Rebuild(RebuildReason::Manifest("length")))?;
    let mut manifest_bytes = Vec::new();
    manifest_bytes
        .try_reserve_exact(manifest_length)
        .map_err(|_| allocation_error("cache manifest"))?;
    manifest_bytes.resize(manifest_length, 0);
    read_exact_at(
        &file,
        header.manifest_offset,
        &mut manifest_bytes,
        Some(guard),
    )?;
    if Sha256::digest(&manifest_bytes).as_slice() != header.manifest_checksum {
        return Err(ValidationFailure::Rebuild(RebuildReason::Manifest(
            "checksum",
        )));
    }
    let manifest: CacheManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|_| ValidationFailure::Rebuild(RebuildReason::Manifest("json")))?;
    let canonical = canonical_manifest_json(&manifest)?;
    if canonical != manifest_bytes {
        return Err(ValidationFailure::Rebuild(RebuildReason::Manifest(
            "canonical JSON",
        )));
    }
    if let Some(field) = manifest.identity.mismatch(expected) {
        return Err(ValidationFailure::Rebuild(RebuildReason::IdentityMismatch(
            field,
        )));
    }
    manifest
        .validate_shape()
        .map_err(ValidationFailure::Rebuild)?;
    validate_sections(&file, &manifest, header.manifest_offset, guard)?;
    directory.verify()?;
    stamp.verify(&file)?;

    let keys = manifest
        .sections
        .iter()
        .find(|section| section.name == EVENT_KEYS_SECTION)
        .ok_or(ValidationFailure::Rebuild(RebuildReason::Section(
            "missing event keys",
        )))?;
    let kinds = manifest
        .sections
        .iter()
        .find(|section| section.name == EVENT_KINDS_SECTION)
        .ok_or(ValidationFailure::Rebuild(RebuildReason::Section(
            "missing event kinds",
        )))?;
    if keys.element_size as usize != EVENT_KEY_BYTES || kinds.element_size != 1 {
        return Err(ValidationFailure::Rebuild(RebuildReason::Section(
            "known element size",
        )));
    }
    if keys.alignment != 8 || kinds.alignment != 1 {
        return Err(ValidationFailure::Rebuild(RebuildReason::Section(
            "known alignment",
        )));
    }
    let key_count = keys.length / u64::from(keys.element_size);
    let kind_count = kinds.length;
    if key_count != kind_count {
        return Err(ValidationFailure::Rebuild(RebuildReason::Section(
            "event count",
        )));
    }
    let event_count = usize::try_from(key_count)
        .map_err(|_| ValidationFailure::Rebuild(RebuildReason::Section("event count")))?;
    if expected.cache_schema == 2 && expected.layout_version == 2 {
        let mut expected_names = Vec::new();
        expected_names
            .try_reserve_exact(2 + crate::index::binary_section_specs().len())
            .map_err(|_| allocation_error("schema-two section names"))?;
        expected_names.push(EVENT_KINDS_SECTION);
        expected_names.push(EVENT_KEYS_SECTION);
        expected_names.extend(
            crate::index::binary_section_specs()
                .iter()
                .map(|(name, _, _)| *name),
        );
        if manifest.sections.len() != expected_names.len()
            || manifest
                .sections
                .iter()
                .zip(expected_names)
                .any(|(section, name)| section.name != name)
        {
            return Err(ValidationFailure::Rebuild(RebuildReason::Section(
                "schema-two exact section set",
            )));
        }
        let normalized_bytes =
            crate::index::binary_section_specs().iter().try_fold(
                0_u64,
                |total, (name, _, _)| {
                    let length = manifest
                        .sections
                        .iter()
                        .find(|section| section.name == *name)
                        .ok_or(ValidationFailure::Rebuild(RebuildReason::Section(
                            "schema-two exact section set",
                        )))?
                        .length;
                    total.checked_add(length).ok_or(ValidationFailure::Rebuild(
                        RebuildReason::Section("normalized resident peak overflow"),
                    ))
                },
            )?;
        let source_facts = key_count
            .checked_mul(
                u64::try_from(std::mem::size_of::<EventKey>() + std::mem::size_of::<EventKind>())
                    .map_err(|_| {
                    ValidationFailure::Rebuild(RebuildReason::Section("source fact resident size"))
                })?,
            )
            .ok_or(ValidationFailure::Rebuild(RebuildReason::Section(
                "source fact resident peak overflow",
            )))?;
        // Serialized sections coexist only until decode consumes them. Four times their encoded
        // size conservatively covers decoded fixed rows, sorted-map descriptors, and the largest
        // one-family reconstruction scratch while arenas move into the catalog without copying.
        let declared_peak = normalized_bytes
            .checked_mul(5)
            .and_then(|value| value.checked_add(source_facts))
            .and_then(|value| value.checked_add(manifest_resident))
            .ok_or(ValidationFailure::Rebuild(RebuildReason::Section(
                "normalized resident peak overflow",
            )))?;
        guard.consume(WorkDelta {
            resident_bytes: declared_peak,
            ..WorkDelta::default()
        })?;
        let (event_keys, event_kinds) =
            read_event_rows(&file, keys.offset, kinds.offset, event_count, guard)?;
        let mut binary = BTreeMap::new();
        guard.consume(WorkDelta {
            nodes: crate::index::binary_section_specs().len() as u64,
            ..WorkDelta::default()
        })?;
        for (name, _, _) in crate::index::binary_section_specs() {
            guard.consume(WorkDelta::default())?;
            let section = manifest
                .sections
                .iter()
                .find(|section| section.name == *name)
                .ok_or(ValidationFailure::Rebuild(RebuildReason::Section(
                    "schema-two exact section set",
                )))?;
            let maximum = crate::index::binary_section_max_length(name, event_count)
                .map_err(normalized_validation_failure)?;
            if section.length > maximum {
                return Err(ValidationFailure::Rebuild(RebuildReason::Section(
                    "binary section length bound",
                )));
            }
            let length = usize::try_from(section.length).map_err(|_| {
                ValidationFailure::Rebuild(RebuildReason::Section("binary section length"))
            })?;
            guard.consume(WorkDelta {
                resident_bytes: section.length,
                ..WorkDelta::default()
            })?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(length)
                .map_err(|_| allocation_error("binary section validation"))?;
            bytes.resize(length, 0);
            read_exact_at(&file, section.offset, &mut bytes, Some(guard))?;
            binary.insert((*name).to_owned(), bytes);
        }
        crate::index::validate_binary_sections(
            binary,
            &event_keys,
            &event_kinds,
            &expected.source_format,
            guard,
        )
        .map_err(normalized_validation_failure)?;
    }
    directory.verify()?;
    stamp.verify(&file)?;
    let mut sections = Vec::new();
    sections
        .try_reserve_exact(manifest.sections.len())
        .map_err(|_| allocation_error("mapped section descriptors"))?;
    sections.extend(manifest.sections.iter().cloned());
    Ok(MappedStoreView {
        file: Arc::new(file),
        stamp,
        identity: Arc::new(manifest.identity),
        event_count,
        event_keys_offset: keys.offset,
        event_kinds_offset: kinds.offset,
        sections,
    })
}

fn normalized_validation_failure(error: crate::IndexError) -> ValidationFailure {
    match error.code() {
        "job.cancelled" => ValidationFailure::Fatal(CacheError::from(OperationAbort::Cancelled)),
        "control.budget_exceeded" => ValidationFailure::Fatal(CacheError::from(
            OperationAbort::budget_exceeded(qtrace_provider::BudgetDimension::Nodes, 0, 1),
        )),
        code if code.starts_with("control.") => {
            ValidationFailure::Fatal(CacheError::resource(error.to_string()))
        }
        _ => ValidationFailure::Rebuild(RebuildReason::Section("normalized payload")),
    }
}

fn read_event_rows(
    file: &File,
    keys_offset: u64,
    kinds_offset: u64,
    event_count: usize,
    guard: &dyn WorkGuard,
) -> Result<(Vec<EventKey>, Vec<EventKind>), ValidationFailure> {
    let resident = event_count
        .checked_mul(std::mem::size_of::<EventKey>() + std::mem::size_of::<EventKind>())
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(ValidationFailure::Rebuild(RebuildReason::Section(
            "event count",
        )))?;
    guard.consume(WorkDelta {
        resident_bytes: resident,
        ..WorkDelta::default()
    })?;
    let mut keys = Vec::new();
    let mut kinds = Vec::new();
    keys.try_reserve_exact(event_count)
        .map_err(|_| allocation_error("normalized event-key validation"))?;
    kinds
        .try_reserve_exact(event_count)
        .map_err(|_| allocation_error("normalized event-kind validation"))?;
    let mut encoded_key = [0_u8; EVENT_KEY_BYTES];
    for row in 0..event_count {
        if row % 4096 == 0 {
            guard.consume(WorkDelta::default())?;
        }
        let byte_offset = row
            .checked_mul(EVENT_KEY_BYTES)
            .and_then(|value| u64::try_from(value).ok())
            .and_then(|value| keys_offset.checked_add(value))
            .ok_or(ValidationFailure::Rebuild(RebuildReason::Section(
                "event-key range",
            )))?;
        read_exact_at(file, byte_offset, &mut encoded_key, Some(guard))?;
        keys.push(
            decode_event_key(&encoded_key)
                .map_err(|_| ValidationFailure::Rebuild(RebuildReason::Section("payload")))?,
        );
        let kind_offset =
            kinds_offset
                .checked_add(row as u64)
                .ok_or(ValidationFailure::Rebuild(RebuildReason::Section(
                    "event-kind range",
                )))?;
        let mut encoded_kind = [0_u8; 1];
        read_exact_at(file, kind_offset, &mut encoded_kind, Some(guard))?;
        kinds.push(
            decode_event_kind(encoded_kind[0])
                .map_err(|_| ValidationFailure::Rebuild(RebuildReason::Section("payload")))?,
        );
    }
    Ok((keys, kinds))
}

fn validate_sections(
    file: &File,
    manifest: &CacheManifest,
    manifest_offset: u64,
    guard: &dyn WorkGuard,
) -> Result<(), ValidationFailure> {
    let mut names = HashSet::new();
    names
        .try_reserve(manifest.sections.len())
        .map_err(|_| allocation_error("section-name set"))?;
    let mut previous_end = HEADER_BYTES as u64;
    for section in &manifest.sections {
        guard.consume(WorkDelta {
            nodes: 1,
            ..WorkDelta::default()
        })?;
        if !names.insert(section.name.as_str()) {
            return Err(ValidationFailure::Rebuild(RebuildReason::Section(
                "duplicate name",
            )));
        }
        let alignment = u64::from(section.alignment);
        if alignment == 0 || !alignment.is_power_of_two() || alignment > 4096 {
            return Err(ValidationFailure::Rebuild(RebuildReason::Section(
                "alignment",
            )));
        }
        if section.offset % alignment != 0 {
            return Err(ValidationFailure::Rebuild(RebuildReason::Section(
                "misaligned offset",
            )));
        }
        if section.element_size == 0 || section.length % u64::from(section.element_size) != 0 {
            return Err(ValidationFailure::Rebuild(RebuildReason::Section(
                "element size",
            )));
        }
        if let Some((alignment, element_size)) = known_section_contract(&section.name) {
            if section.alignment != alignment {
                return Err(ValidationFailure::Rebuild(RebuildReason::Section(
                    if section.name == EVENT_KEYS_SECTION || section.name == EVENT_KINDS_SECTION {
                        "known alignment"
                    } else {
                        "known section contract"
                    },
                )));
            }
            if section.element_size != element_size {
                return Err(ValidationFailure::Rebuild(RebuildReason::Section(
                    if section.name == EVENT_KEYS_SECTION || section.name == EVENT_KINDS_SECTION {
                        "known element size"
                    } else {
                        "known section contract"
                    },
                )));
            }
        }
        let end = section
            .offset
            .checked_add(section.length)
            .ok_or(ValidationFailure::Rebuild(RebuildReason::Section(
                "range overflow",
            )))?;
        if section.offset < previous_end || end > manifest_offset {
            return Err(ValidationFailure::Rebuild(RebuildReason::Section("range")));
        }
        validate_zero_padding(file, previous_end, section.offset, guard)?;
        checksum_section(file, section, &manifest.identity, guard)?;
        previous_end = end;
    }
    validate_zero_padding(file, previous_end, manifest_offset, guard)?;
    Ok(())
}

fn validate_zero_padding(
    file: &File,
    start: u64,
    end: u64,
    guard: &dyn WorkGuard,
) -> Result<(), ValidationFailure> {
    let length = end
        .checked_sub(start)
        .ok_or(ValidationFailure::Rebuild(RebuildReason::Section("range")))?;
    let mut buffer = [0_u8; CHECKSUM_CHUNK_BYTES];
    let mut consumed = 0_u64;
    while consumed < length {
        let count = usize::try_from((length - consumed).min(CHECKSUM_CHUNK_BYTES as u64))
            .map_err(|_| ValidationFailure::Rebuild(RebuildReason::Section("padding")))?;
        read_exact_at(file, start + consumed, &mut buffer[..count], Some(guard))?;
        if buffer[..count].iter().any(|byte| *byte != 0) {
            return Err(ValidationFailure::Rebuild(RebuildReason::Section(
                "padding",
            )));
        }
        consumed += count as u64;
    }
    Ok(())
}

fn checksum_section(
    file: &File,
    section: &super::SectionDescriptor,
    identity: &CacheIdentity,
    guard: &dyn WorkGuard,
) -> Result<(), ValidationFailure> {
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; CHECKSUM_CHUNK_BYTES];
    let mut consumed = 0_u64;
    while consumed < section.length {
        let count = usize::try_from((section.length - consumed).min(CHECKSUM_CHUNK_BYTES as u64))
            .map_err(|_| ValidationFailure::Rebuild(RebuildReason::Section("length")))?;
        read_exact_at(
            file,
            section.offset + consumed,
            &mut buffer[..count],
            Some(guard),
        )?;
        validate_known_payload(section.name.as_str(), &buffer[..count], identity)?;
        digest.update(&buffer[..count]);
        consumed += count as u64;
    }
    if digest.finalize().as_slice() != section.checksum {
        return Err(ValidationFailure::Rebuild(RebuildReason::Section(
            "checksum",
        )));
    }
    Ok(())
}

fn validate_known_payload(
    name: &str,
    bytes: &[u8],
    identity: &CacheIdentity,
) -> Result<(), ValidationFailure> {
    if name == EVENT_KINDS_SECTION {
        for value in bytes {
            decode_event_kind(*value)
                .map_err(|_| ValidationFailure::Rebuild(RebuildReason::Section("payload")))?;
        }
    } else if name == EVENT_KEYS_SECTION {
        let mut rows = bytes.chunks_exact(EVENT_KEY_BYTES);
        for row in &mut rows {
            let encoded: &[u8; EVENT_KEY_BYTES] = row
                .try_into()
                .map_err(|_| ValidationFailure::Rebuild(RebuildReason::Section("payload")))?;
            let key = decode_event_key(encoded)
                .map_err(|_| ValidationFailure::Rebuild(RebuildReason::Section("payload")))?;
            if key.artifact.as_bytes() != &identity.artifact_digest {
                return Err(ValidationFailure::Rebuild(RebuildReason::Section(
                    "payload",
                )));
            }
        }
        if !rows.remainder().is_empty() {
            return Err(ValidationFailure::Rebuild(RebuildReason::Section(
                "payload",
            )));
        }
    }
    Ok(())
}

fn read_exact_at(
    file: &File,
    offset: u64,
    output: &mut [u8],
    guard: Option<&dyn WorkGuard>,
) -> Result<(), CacheError> {
    if let Some(guard) = guard {
        guard.consume(WorkDelta {
            input_bytes: output.len() as u64,
            ..WorkDelta::default()
        })?;
    }
    let mut filled = 0_usize;
    while filled < output.len() {
        let current = offset
            .checked_add(filled as u64)
            .ok_or_else(|| CacheError::access("cache read offset overflow"))?;
        match file.read_at(&mut output[filled..], current) {
            Ok(0) => return Err(CacheError::access("cache became shorter during read")),
            Ok(count) if count <= output.len() - filled => filled += count,
            Ok(_) => return Err(CacheError::access("cache read over-reported bytes")),
            Err(error) => return Err(map_io_error("cannot read cache bytes", error)),
        }
    }
    Ok(())
}

pub(crate) fn probe_identity(
    file: &File,
    guard: &dyn WorkGuard,
) -> Result<CacheIdentity, ValidationFailure> {
    let size = file
        .metadata()
        .map_err(|error| map_io_error("cannot stat cache identity", error))?
        .len();
    if size < HEADER_BYTES as u64 {
        return Err(ValidationFailure::Rebuild(RebuildReason::Header(
            "truncated",
        )));
    }
    let mut header_bytes = [0_u8; HEADER_BYTES];
    read_exact_at(file, 0, &mut header_bytes, Some(guard))?;
    let header = CacheHeader::decode(&header_bytes).map_err(ValidationFailure::Rebuild)?;
    let end = header
        .manifest_offset
        .checked_add(header.manifest_length)
        .ok_or(ValidationFailure::Rebuild(RebuildReason::Manifest(
            "range overflow",
        )))?;
    if header.manifest_length == 0 || header.manifest_length > MAX_MANIFEST_BYTES || end != size {
        return Err(ValidationFailure::Rebuild(RebuildReason::Manifest("range")));
    }
    let manifest_resident =
        header
            .manifest_length
            .checked_mul(2)
            .ok_or(ValidationFailure::Rebuild(RebuildReason::Manifest(
                "resident bound",
            )))?;
    guard.consume(WorkDelta {
        resident_bytes: manifest_resident,
        ..WorkDelta::default()
    })?;
    let length = usize::try_from(header.manifest_length)
        .map_err(|_| ValidationFailure::Rebuild(RebuildReason::Manifest("length")))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| allocation_error("cache identity manifest"))?;
    bytes.resize(length, 0);
    read_exact_at(file, header.manifest_offset, &mut bytes, Some(guard))?;
    if Sha256::digest(&bytes).as_slice() != header.manifest_checksum {
        return Err(ValidationFailure::Rebuild(RebuildReason::Manifest(
            "checksum",
        )));
    }
    let manifest: CacheManifest = serde_json::from_slice(&bytes)
        .map_err(|_| ValidationFailure::Rebuild(RebuildReason::Manifest("json")))?;
    Ok(manifest.identity)
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use qtrace_provider::{
        ArtifactDigest, EventKey, EventKind, OperationAbort, TimelineId, WorkDelta, WorkGuard,
    };
    use rustix::io::Errno;
    use tempfile::TempDir;

    use super::INJECT_PROOF_CLONE_ERRNO;
    use crate::cache::{CacheIdentity, CacheReader, CacheWriter, OwnedStoreView};

    struct AllowAll;

    impl WorkGuard for AllowAll {
        fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
            Ok(())
        }
    }

    fn identity() -> CacheIdentity {
        CacheIdentity {
            analyzer_version: "test".to_owned(),
            artifact_digest: [0x71; 32],
            build_option_digest: [0x72; 32],
            cache_schema: 1,
            endian: "little".to_owned(),
            layout_version: 1,
            source_features: 0,
            source_format: "qtrb".to_owned(),
            source_major: 1,
            source_minor: 2,
        }
    }

    #[test]
    fn proof_clone_fd_exhaustion_is_a_control_error() {
        let root = TempDir::new().expect("root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private root");
        let identity = identity();
        let store = OwnedStoreView::new(
            vec![EventKey::new(
                ArtifactDigest::new(identity.artifact_digest),
                TimelineId(0),
                0,
                1,
                None,
                None,
            )],
            vec![EventKind::Instruction],
        )
        .expect("store");
        CacheWriter::new(identity.clone(), store)
            .expect("writer")
            .publish(root.path(), &AllowAll)
            .expect("publish");

        for errno in [Errno::MFILE.raw_os_error(), Errno::NFILE.raw_os_error()] {
            INJECT_PROOF_CLONE_ERRNO.with(|injected| injected.set(Some(errno)));
            let error = CacheReader::open(root.path(), &identity, &AllowAll)
                .expect_err("injected descriptor exhaustion must fail");
            assert_eq!(error.code(), "control.resource_exhausted");
            assert!(error.is_control());
        }
    }
}
