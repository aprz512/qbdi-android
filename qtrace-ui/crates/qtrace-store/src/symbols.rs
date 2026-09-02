use std::{alloc::Layout, error::Error, fmt, mem::size_of, str};

use object::{
    Architecture, BinaryFormat, Object, ObjectKind, ObjectSection, ObjectSegment, ObjectSymbol,
    SegmentFlags, SymbolKind,
};
use qtrace_provider::{AllocationScope, ArtifactDigest, OperationAbort, WorkDelta, WorkGuard};
use sha2::{Digest, Sha256};

use crate::{AuthorizedPath, secure_path::split_selected_file};

const MAX_ELF_BYTES: u64 = 512 * 1024 * 1024;
const MAX_SYMBOLS: usize = 1_000_000;
const MAX_NAME_BYTES: usize = 4_096;
const MAX_BUILD_ID_BYTES: usize = 4_096;
const CHUNK: usize = 4_096;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_NOTE: u32 = 7;
const SHT_NOBITS: u32 = 8;
const SHT_DYNSYM: u32 = 11;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ModuleIdentity {
    name: String,
    digest: ArtifactDigest,
}

impl ModuleIdentity {
    pub fn new(name: impl Into<String>, digest: ArtifactDigest) -> Self {
        Self {
            name: name.into(),
            digest,
        }
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub const fn digest(&self) -> ArtifactDigest {
        self.digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfProducerIdentity {
    pointer_width: u8,
    little_endian: bool,
    machine: u16,
}

impl ElfProducerIdentity {
    pub const fn new(pointer_width: u8, little_endian: bool, machine: u16) -> Self {
        Self {
            pointer_width,
            little_endian,
            machine,
        }
    }
    pub const fn aarch64_android() -> Self {
        Self::new(64, true, 183)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElfLoadRequest {
    selected: AuthorizedPath,
    approved: bool,
    expected_module: ModuleIdentity,
    expected_producer: ElfProducerIdentity,
    expected_build_id: Option<Vec<u8>>,
}

impl ElfLoadRequest {
    pub fn new(
        selected: AuthorizedPath,
        approved: bool,
        expected_module: ModuleIdentity,
        expected_producer: ElfProducerIdentity,
        expected_build_id: Option<Vec<u8>>,
    ) -> Self {
        Self {
            selected,
            approved,
            expected_module,
            expected_producer,
            expected_build_id,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElfSymbolMatch {
    name: String,
    relative_address: u64,
    size: u64,
    offset: u64,
}

impl ElfSymbolMatch {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub const fn relative_address(&self) -> u64 {
        self.relative_address
    }
    pub const fn size(&self) -> u64 {
        self.size
    }
    pub const fn offset(&self) -> u64 {
        self.offset
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct IndexedSymbol {
    address: u64,
    size: u64,
    name_start: u32,
    name_len: u16,
    precedence: u8,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct LoadRange {
    start: u64,
    end: u64,
    file_offset: u64,
    file_size: u64,
    flags: u32,
}

#[derive(Clone, Copy, Debug, Default)]
struct Section {
    kind: u32,
    offset: usize,
    size: usize,
    link: usize,
    entry_size: usize,
}

struct RawElf {
    elf_kind: u16,
    image_base: u64,
    loads: Vec<LoadRange>,
    executable: Vec<LoadRange>,
    sections: Vec<Section>,
    build_id: Option<Vec<u8>>,
    symbol_count: usize,
    name_bytes: usize,
    symbol_fingerprint: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct ElfSymbolIndex {
    module: ModuleIdentity,
    build_id: Option<Vec<u8>>,
    symbols: Vec<IndexedSymbol>,
    names: Vec<u8>,
    max_end: Vec<u64>,
    tree_base: usize,
}

impl ElfSymbolIndex {
    pub fn load(request: ElfLoadRequest, guard: &dyn WorkGuard) -> Result<Self, SymbolError> {
        validate_request(&request)?;
        let (root, leaf) = split_selected_file(request.selected.as_path())
            .map_err(SymbolError::from_path_error)?;
        if leaf != request.expected_module.name {
            return Err(SymbolError::new(
                "symbol.module_identity_mismatch",
                "selected filename does not match module identity",
            ));
        }
        let source = root
            .open_source_file(&leaf)
            .map_err(SymbolError::from_path_error)?;
        let identity = source.identity().map_err(SymbolError::from_path_error)?;
        if identity.size == 0 || identity.size > MAX_ELF_BYTES {
            return Err(SymbolError::new(
                "symbol.file_too_large",
                "ELF is empty or exceeds its bound",
            ));
        }
        let bytes = source
            .read_bounded_chunked(MAX_ELF_BYTES, CHUNK, guard)
            .map_err(SymbolError::from_path_error)?;
        if guarded_digest(&bytes, guard)? != request.expected_module.digest {
            return Err(SymbolError::new(
                "symbol.module_identity_mismatch",
                "ELF digest does not match module identity",
            ));
        }
        let raw = preflight(&bytes, guard)?;
        validate_object_view(&bytes, &raw, guard)?;
        if request
            .expected_build_id
            .as_deref()
            .is_some_and(|expected| raw.build_id.as_deref() != Some(expected))
        {
            return Err(SymbolError::new(
                "symbol.build_id_mismatch",
                "GNU build-id does not match",
            ));
        }
        let mut symbols = guarded_vec(raw.symbol_count, guard)?;
        let mut names = guarded_vec(raw.name_bytes, guard)?;
        fill_symbols(&bytes, &raw, guard, &mut symbols, &mut names)?;
        radix_sort(&mut symbols, |symbol| symbol.address, guard)?;
        deduplicate(&mut symbols, guard)?;
        let (max_end, tree_base) = build_tree(&symbols, guard)?;
        Ok(Self {
            module: request.expected_module,
            build_id: raw.build_id,
            symbols,
            names,
            max_end,
            tree_base,
        })
    }

    pub const fn module_identity(&self) -> &ModuleIdentity {
        &self.module
    }
    pub fn build_id(&self) -> Option<&[u8]> {
        self.build_id.as_deref()
    }
    pub fn resolve(&self, pc: u64) -> Option<ElfSymbolMatch> {
        let upper = self.symbols.partition_point(|symbol| {
            #[cfg(test)]
            LOOKUP_COMPARISONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            symbol.address <= pc
        });
        if upper == 0 {
            return None;
        }
        let index = self.rightmost_containing(upper, pc).unwrap_or(upper - 1);
        let symbol = self.symbols[index];
        let start = symbol.name_start as usize;
        let end = start + symbol.name_len as usize;
        Some(ElfSymbolMatch {
            name: str::from_utf8(&self.names[start..end]).ok()?.to_owned(),
            relative_address: symbol.address,
            size: symbol.size,
            offset: pc - symbol.address,
        })
    }

    fn rightmost_containing(&self, upper: usize, pc: u64) -> Option<usize> {
        if self.tree_base == 0 || self.max_end[1] <= pc {
            return None;
        }
        self.rightmost_in_node(1, 0, self.tree_base, upper, pc)
    }

    fn rightmost_in_node(
        &self,
        node: usize,
        left: usize,
        right: usize,
        upper: usize,
        pc: u64,
    ) -> Option<usize> {
        #[cfg(test)]
        LOOKUP_COMPARISONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if left >= upper || self.max_end[node] <= pc {
            return None;
        }
        if right - left == 1 {
            return (left < self.symbols.len()).then_some(left);
        }
        let middle = left + (right - left) / 2;
        self.rightmost_in_node(node * 2 + 1, middle, right, upper, pc)
            .or_else(|| self.rightmost_in_node(node * 2, left, middle, upper, pc))
    }
}

fn validate_request(request: &ElfLoadRequest) -> Result<(), SymbolError> {
    if !request.approved {
        return Err(SymbolError::new(
            "symbol.approval_required",
            "ELF selection was not explicitly approved",
        ));
    }
    if request.expected_producer != ElfProducerIdentity::aarch64_android() {
        return Err(SymbolError::new(
            "symbol.producer_identity_mismatch",
            "producer is not Android AArch64",
        ));
    }
    Ok(())
}

fn guarded_digest(bytes: &[u8], guard: &dyn WorkGuard) -> Result<ArtifactDigest, SymbolError> {
    let mut hash = Sha256::new();
    for chunk in bytes.chunks(CHUNK) {
        work(guard, chunk.len())?;
        hash.update(chunk);
    }
    Ok(ArtifactDigest::new(hash.finalize().into()))
}

fn preflight(bytes: &[u8], guard: &dyn WorkGuard) -> Result<RawElf, SymbolError> {
    validate_header(bytes)?;
    let elf_kind = u16_at(bytes, 16)?;
    if !matches!(elf_kind, ET_EXEC | ET_DYN) {
        return Err(SymbolError::new(
            "symbol.elf_type_unsupported",
            "only ET_EXEC and ET_DYN are accepted",
        ));
    }
    let program_at = usize_at(u64_at(bytes, 32)?, "program offset")?;
    let program_size = u16_at(bytes, 54)? as usize;
    let program_count = u16_at(bytes, 56)? as usize;
    if program_size != 56 || program_count == 0 {
        return Err(SymbolError::segment("missing or invalid program table"));
    }
    table_bounds(bytes, program_at, program_size, program_count, "program")?;
    let mut loads = guarded_vec(program_count, guard)?;
    let mut executable = guarded_vec(program_count, guard)?;
    let mut image_base = u64::MAX;
    for first in (0..program_count).step_by(CHUNK) {
        let end = (first + CHUNK).min(program_count);
        work(guard, end - first)?;
        for index in first..end {
            let at = program_at + index * program_size;
            if u32_at(bytes, at)? != PT_LOAD {
                continue;
            }
            let flags = u32_at(bytes, at + 4)?;
            let file_offset = u64_at(bytes, at + 8)?;
            let start = u64_at(bytes, at + 16)?;
            let file_size = u64_at(bytes, at + 32)?;
            let memory_size = u64_at(bytes, at + 40)?;
            if file_size > memory_size
                || file_offset
                    .checked_add(file_size)
                    .is_none_or(|end| end > bytes.len() as u64)
            {
                return Err(SymbolError::segment("invalid PT_LOAD file range"));
            }
            let end = start
                .checked_add(memory_size)
                .ok_or_else(|| SymbolError::segment("PT_LOAD address overflow"))?;
            let range = LoadRange {
                start,
                end,
                file_offset,
                file_size,
                flags,
            };
            loads.push(range);
            image_base = image_base.min(start);
            if flags & PF_X != 0 && start != end {
                executable.push(range);
            }
        }
    }
    if loads.is_empty() || executable.is_empty() {
        return Err(SymbolError::segment("no executable PT_LOAD segment"));
    }
    radix_sort(&mut executable, |range| range.start, guard)?;
    for first in (1..executable.len()).step_by(CHUNK) {
        let end = (first + CHUNK).min(executable.len());
        work(guard, end - first)?;
        for index in first..end {
            if executable[index - 1].end > executable[index].start {
                return Err(SymbolError::segment(
                    "overlapping executable PT_LOAD ranges",
                ));
            }
        }
    }

    let section_at = usize_at(u64_at(bytes, 40)?, "section offset")?;
    let section_size = u16_at(bytes, 58)? as usize;
    let section_count = u16_at(bytes, 60)? as usize;
    if section_size != 64 || section_count == 0 {
        return Err(SymbolError::malformed("invalid section table"));
    }
    table_bounds(bytes, section_at, section_size, section_count, "section")?;
    let mut sections = guarded_vec(section_count, guard)?;
    for first in (0..section_count).step_by(CHUNK) {
        let end = (first + CHUNK).min(section_count);
        work(guard, end - first)?;
        for index in first..end {
            let at = section_at + index * section_size;
            let kind = u32_at(bytes, at + 4)?;
            let offset = usize_at(u64_at(bytes, at + 24)?, "section offset")?;
            let size = usize_at(u64_at(bytes, at + 32)?, "section size")?;
            if kind != SHT_NOBITS && offset.checked_add(size).is_none_or(|end| end > bytes.len()) {
                return Err(SymbolError::malformed("section exceeds file bounds"));
            }
            sections.push(Section {
                kind,
                offset,
                size,
                link: u32_at(bytes, at + 40)? as usize,
                entry_size: usize_at(u64_at(bytes, at + 56)?, "entry size")?,
            });
        }
    }
    validate_symbol_sections(&sections)?;
    let build_id = build_id(bytes, &sections, guard)?;
    let (symbol_count, name_bytes, symbol_fingerprint) =
        plan_symbols(bytes, &sections, &executable, image_base, guard)?;
    Ok(RawElf {
        elf_kind,
        image_base,
        loads,
        executable,
        sections,
        build_id,
        symbol_count,
        name_bytes,
        symbol_fingerprint,
    })
}

fn validate_header(bytes: &[u8]) -> Result<(), SymbolError> {
    if bytes.len() < 64 || &bytes[..4] != b"\x7fELF" {
        return Err(SymbolError::malformed("invalid ELF header"));
    }
    if bytes[4] != 2 {
        return Err(SymbolError::new(
            "symbol.elf_class_unsupported",
            "only ELF64 is supported",
        ));
    }
    if bytes[5] != 1 {
        return Err(SymbolError::new(
            "symbol.elf_endian_unsupported",
            "only little endian is supported",
        ));
    }
    if u16_at(bytes, 18)? != 183 {
        return Err(SymbolError::new(
            "symbol.elf_machine_unsupported",
            "only AArch64 is supported",
        ));
    }
    if u16_at(bytes, 52)? != 64 {
        return Err(SymbolError::malformed("invalid ELF header size"));
    }
    Ok(())
}

fn validate_symbol_sections(sections: &[Section]) -> Result<(), SymbolError> {
    let mut entries = 0_usize;
    for table in sections
        .iter()
        .filter(|section| matches!(section.kind, SHT_SYMTAB | SHT_DYNSYM))
    {
        if table.entry_size != 24 || table.size % 24 != 0 {
            return Err(SymbolError::malformed("invalid symbol table shape"));
        }
        if sections.get(table.link).map(|section| section.kind) != Some(SHT_STRTAB) {
            return Err(SymbolError::malformed("invalid symbol string-table link"));
        }
        entries = entries
            .checked_add(table.size / 24)
            .ok_or_else(|| SymbolError::resource("symbol entry count overflow"))?;
        if entries > MAX_SYMBOLS {
            return Err(SymbolError::resource("symbol entry count exceeds limit"));
        }
    }
    Ok(())
}

fn build_id(
    bytes: &[u8],
    sections: &[Section],
    guard: &dyn WorkGuard,
) -> Result<Option<Vec<u8>>, SymbolError> {
    let mut result: Option<Vec<u8>> = None;
    for section in sections.iter().filter(|section| section.kind == SHT_NOTE) {
        let (mut at, limit) = (section.offset, section.offset + section.size);
        while at < limit {
            work(guard, 1)?;
            if limit - at < 12 {
                return Err(SymbolError::malformed("truncated note"));
            }
            let name_size = u32_at(bytes, at)? as usize;
            let value_size = u32_at(bytes, at + 4)? as usize;
            let kind = u32_at(bytes, at + 8)?;
            let name_at = at + 12;
            let name_end = name_at
                .checked_add(name_size)
                .ok_or_else(|| SymbolError::malformed("note name overflow"))?;
            let value_at = align4(name_end)?;
            let value_end = value_at
                .checked_add(value_size)
                .ok_or_else(|| SymbolError::malformed("note value overflow"))?;
            let next = align4(value_end)?;
            if next > limit {
                return Err(SymbolError::malformed("note exceeds section"));
            }
            work_bytes(guard, name_size.saturating_add(value_size))?;
            if kind == 3 && bytes.get(name_at..name_end) == Some(b"GNU\0") {
                if value_size == 0 || value_size > MAX_BUILD_ID_BYTES {
                    return Err(SymbolError::resource("build-id exceeds limit"));
                }
                let value = &bytes[value_at..value_end];
                if result.as_deref().is_some_and(|existing| existing != value) {
                    return Err(SymbolError::malformed("conflicting build-id notes"));
                }
                if result.is_none() {
                    let mut copy = guarded_vec(value.len(), guard)?;
                    for chunk in value.chunks(CHUNK) {
                        work(guard, chunk.len())?;
                        copy.extend_from_slice(chunk);
                    }
                    result = Some(copy);
                }
            }
            at = next;
        }
    }
    Ok(result)
}

struct Candidate<'a> {
    name: &'a str,
    address: u64,
    size: u64,
    precedence: u8,
}

fn plan_symbols(
    bytes: &[u8],
    sections: &[Section],
    executable: &[LoadRange],
    image_base: u64,
    guard: &dyn WorkGuard,
) -> Result<(usize, usize, [u8; 32]), SymbolError> {
    let mut count = 0_usize;
    let mut names = 0_usize;
    let mut fingerprint = Sha256::new();
    visit_candidates(
        bytes,
        sections,
        executable,
        image_base,
        guard,
        |candidate| {
            count = count
                .checked_add(1)
                .ok_or_else(|| SymbolError::resource("symbol count overflow"))?;
            names = names
                .checked_add(candidate.name.len())
                .ok_or_else(|| SymbolError::resource("name arena overflow"))?;
            fingerprint_candidate(&mut fingerprint, &candidate);
            Ok(())
        },
    )?;
    if count > MAX_SYMBOLS {
        return Err(SymbolError::resource("accepted symbol count exceeds limit"));
    }
    Ok((count, names, fingerprint.finalize().into()))
}

fn visit_candidates<'a>(
    bytes: &'a [u8],
    sections: &[Section],
    executable: &[LoadRange],
    image_base: u64,
    guard: &dyn WorkGuard,
    mut visitor: impl FnMut(Candidate<'a>) -> Result<(), SymbolError>,
) -> Result<(), SymbolError> {
    for (wanted, precedence) in [(SHT_DYNSYM, 0_u8), (SHT_SYMTAB, 1_u8)] {
        for table in sections.iter().filter(|section| section.kind == wanted) {
            let strings = sections[table.link];
            let entries = table.size / 24;
            for first in (0..entries).step_by(CHUNK) {
                let end = (first + CHUNK).min(entries);
                work(guard, end - first)?;
                for index in first..end {
                    let at = table.offset + index * 24;
                    let info = bytes[at + 4];
                    let section_index = u16_at(bytes, at + 6)?;
                    if info & 0x0f != 2 || section_index == 0 || section_index >= 0xff00 {
                        continue;
                    }
                    let absolute = u64_at(bytes, at + 8)?;
                    let size = u64_at(bytes, at + 16)?;
                    if !contained(absolute, size, executable) {
                        continue;
                    }
                    let relative = absolute
                        .checked_sub(image_base)
                        .ok_or_else(|| SymbolError::malformed("symbol precedes image base"))?;
                    let Some(name) =
                        symbol_name(bytes, strings, u32_at(bytes, at)? as usize, guard)?
                    else {
                        continue;
                    };
                    visitor(Candidate {
                        name,
                        address: relative,
                        size,
                        precedence,
                    })?;
                }
            }
        }
    }
    Ok(())
}

fn symbol_name<'a>(
    bytes: &'a [u8],
    strings: Section,
    offset: usize,
    guard: &dyn WorkGuard,
) -> Result<Option<&'a str>, SymbolError> {
    if offset >= strings.size {
        return Err(SymbolError::malformed("name offset exceeds string table"));
    }
    let at = strings.offset + offset;
    let available = strings.size - offset;
    let scan = available.min(MAX_NAME_BYTES + 1);
    let value = &bytes[at..at + scan];
    let mut length = None;
    for (chunk_index, chunk) in value.chunks(CHUNK).enumerate() {
        work(guard, chunk.len())?;
        if let Some(index) = chunk.iter().position(|byte| *byte == 0) {
            length = Some(chunk_index * CHUNK + index);
            break;
        }
    }
    let Some(length) = length else {
        return if available > MAX_NAME_BYTES {
            Ok(None)
        } else {
            Err(SymbolError::malformed("unterminated symbol name"))
        };
    };
    if length == 0 || length > MAX_NAME_BYTES {
        return Ok(None);
    }
    Ok(str::from_utf8(&bytes[at..at + length]).ok())
}

fn contained(address: u64, size: u64, executable: &[LoadRange]) -> bool {
    let upper = executable.partition_point(|range| range.start <= address);
    let Some(range) = upper.checked_sub(1).map(|index| executable[index]) else {
        return false;
    };
    address < range.end
        && (size == 0
            || address
                .checked_add(size)
                .is_some_and(|end| end <= range.end))
}

fn fingerprint_candidate(hash: &mut Sha256, candidate: &Candidate<'_>) {
    hash.update([candidate.precedence]);
    hash.update(candidate.address.to_le_bytes());
    hash.update(candidate.size.to_le_bytes());
}

fn fill_symbols(
    bytes: &[u8],
    raw: &RawElf,
    guard: &dyn WorkGuard,
    output: &mut Vec<IndexedSymbol>,
    names: &mut Vec<u8>,
) -> Result<(), SymbolError> {
    visit_candidates(
        bytes,
        &raw.sections,
        &raw.executable,
        raw.image_base,
        guard,
        |candidate| {
            let name_start = u32::try_from(names.len())
                .map_err(|_| SymbolError::resource("name arena offset overflow"))?;
            let name_len = u16::try_from(candidate.name.len())
                .map_err(|_| SymbolError::resource("name length overflow"))?;
            for chunk in candidate.name.as_bytes().chunks(CHUNK) {
                work(guard, chunk.len())?;
                names.extend_from_slice(chunk);
            }
            output.push(IndexedSymbol {
                address: candidate.address,
                size: candidate.size,
                name_start,
                name_len,
                precedence: candidate.precedence,
            });
            Ok(())
        },
    )?;
    if output.len() != raw.symbol_count || names.len() != raw.name_bytes {
        return Err(SymbolError::malformed(
            "preflight/build symbol views disagree",
        ));
    }
    Ok(())
}

fn validate_object_view(
    bytes: &[u8],
    raw: &RawElf,
    guard: &dyn WorkGuard,
) -> Result<(), SymbolError> {
    let file = object::File::parse(bytes)
        .map_err(|error| SymbolError::malformed(format!("object rejected ELF: {error}")))?;
    let expected_kind = if raw.elf_kind == ET_DYN {
        ObjectKind::Dynamic
    } else {
        ObjectKind::Executable
    };
    if file.format() != BinaryFormat::Elf
        || !file.is_64()
        || !file.is_little_endian()
        || file.architecture() != Architecture::Aarch64
        || file.kind() != expected_kind
    {
        return Err(SymbolError::malformed("raw/object ELF identities disagree"));
    }
    let mut segments = file.segments();
    for expected in &raw.loads {
        work(guard, 1)?;
        let Some(actual) = segments.next() else {
            return Err(SymbolError::malformed("raw/object segment counts disagree"));
        };
        let flags = match actual.flags() {
            SegmentFlags::Elf { p_flags } => p_flags,
            _ => return Err(SymbolError::malformed("object returned non-ELF flags")),
        };
        let file_range = actual.file_range();
        if actual.address() != expected.start
            || actual.size() != expected.end - expected.start
            || file_range != (expected.file_offset, expected.file_size)
            || flags != expected.flags
        {
            return Err(SymbolError::malformed("raw/object segment views disagree"));
        }
    }
    if segments.next().is_some() {
        return Err(SymbolError::malformed("raw/object segment counts disagree"));
    }
    let mut section_count = 1_usize;
    for section in file.sections() {
        work(guard, 1)?;
        if section.file_range().is_some_and(|(offset, size)| {
            offset
                .checked_add(size)
                .is_none_or(|end| end > bytes.len() as u64)
        }) {
            return Err(SymbolError::malformed(
                "object section range exceeds the raw file",
            ));
        }
        section_count += 1;
    }
    if section_count != raw.sections.len() {
        return Err(SymbolError::malformed("raw/object section counts disagree"));
    }
    let mut count = 0_usize;
    let mut fingerprint = Sha256::new();
    object_symbols(
        file.dynamic_symbols(),
        0,
        raw,
        guard,
        &mut count,
        &mut fingerprint,
    )?;
    object_symbols(file.symbols(), 1, raw, guard, &mut count, &mut fingerprint)?;
    if count != raw.symbol_count
        || <[u8; 32]>::from(fingerprint.finalize()) != raw.symbol_fingerprint
    {
        return Err(SymbolError::malformed(
            "raw/object symbol-kind views disagree",
        ));
    }
    Ok(())
}

fn object_symbols<'data, I>(
    symbols: I,
    precedence: u8,
    raw: &RawElf,
    guard: &dyn WorkGuard,
    count: &mut usize,
    fingerprint: &mut Sha256,
) -> Result<(), SymbolError>
where
    I: Iterator<Item = object::Symbol<'data, 'data>>,
{
    for symbol in symbols {
        work(guard, 1)?;
        if symbol.kind() != SymbolKind::Text
            || !symbol.is_definition()
            || symbol.section_index().is_none()
            || !contained(symbol.address(), symbol.size(), &raw.executable)
        {
            continue;
        }
        let address = symbol
            .address()
            .checked_sub(raw.image_base)
            .ok_or_else(|| SymbolError::malformed("object symbol precedes image base"))?;
        fingerprint_candidate(
            fingerprint,
            &Candidate {
                name: "",
                address,
                size: symbol.size(),
                precedence,
            },
        );
        *count = count
            .checked_add(1)
            .ok_or_else(|| SymbolError::resource("object symbol count overflow"))?;
    }
    Ok(())
}

fn radix_sort<T: Copy + Default>(
    values: &mut Vec<T>,
    key: fn(&T) -> u64,
    guard: &dyn WorkGuard,
) -> Result<(), SymbolError> {
    if values.len() < 2 {
        return Ok(());
    }
    let mut scratch = guarded_vec(values.len(), guard)?;
    for chunk in values.chunks(CHUNK) {
        work(guard, chunk.len())?;
        scratch.extend_from_slice(chunk);
    }
    for pass in 0..8 {
        let mut counts = [0_usize; 256];
        let (source, target): (&[T], &mut Vec<T>) = if pass % 2 == 0 {
            (values.as_slice(), &mut scratch)
        } else {
            (scratch.as_slice(), values)
        };
        for chunk in source.chunks(CHUNK) {
            work(guard, chunk.len())?;
            for item in chunk {
                counts[((key(item) >> (pass * 8)) & 255) as usize] += 1;
            }
        }
        let mut positions = [0_usize; 256];
        let mut cursor = 0_usize;
        for (index, count) in counts.into_iter().enumerate() {
            positions[index] = cursor;
            cursor += count;
        }
        for chunk in source.chunks(CHUNK) {
            work(guard, chunk.len())?;
            for item in chunk {
                let bucket = ((key(item) >> (pass * 8)) & 255) as usize;
                target[positions[bucket]] = *item;
                positions[bucket] += 1;
            }
        }
    }
    Ok(())
}

fn deduplicate(symbols: &mut Vec<IndexedSymbol>, guard: &dyn WorkGuard) -> Result<(), SymbolError> {
    let mut write = 0_usize;
    let mut read = 0_usize;
    while read < symbols.len() {
        let first = read;
        let address = symbols[read].address;
        let mut selected = symbols[read];
        read += 1;
        while read < symbols.len() && symbols[read].address == address {
            let candidate = symbols[read];
            if candidate.precedence > selected.precedence
                || (candidate.precedence == selected.precedence && candidate.size > selected.size)
            {
                selected = candidate;
            }
            read += 1;
        }
        work_bytes(guard, read - first)?;
        symbols[write] = selected;
        write += 1;
    }
    symbols.truncate(write);
    Ok(())
}

fn build_tree(
    symbols: &[IndexedSymbol],
    guard: &dyn WorkGuard,
) -> Result<(Vec<u64>, usize), SymbolError> {
    if symbols.is_empty() {
        return Ok((Vec::new(), 0));
    }
    let base = symbols
        .len()
        .checked_next_power_of_two()
        .ok_or_else(|| SymbolError::resource("containment tree overflow"))?;
    let length = base
        .checked_mul(2)
        .ok_or_else(|| SymbolError::resource("containment tree overflow"))?;
    let mut tree = guarded_vec(length, guard)?;
    for first in (0..length).step_by(CHUNK) {
        let end = (first + CHUNK).min(length);
        work(guard, end - first)?;
        tree.extend(std::iter::repeat_n(0, end - first));
    }
    for first in (0..symbols.len()).step_by(CHUNK) {
        let end = (first + CHUNK).min(symbols.len());
        work(guard, end - first)?;
        for index in first..end {
            tree[base + index] = symbols[index]
                .address
                .checked_add(symbols[index].size)
                .ok_or_else(|| SymbolError::malformed("accepted symbol end overflow"))?;
        }
    }
    let mut end = base;
    while end > 1 {
        let start = end.saturating_sub(CHUNK).max(1);
        work(guard, end - start)?;
        for node in (start..end).rev() {
            tree[node] = tree[node * 2].max(tree[node * 2 + 1]);
        }
        end = start;
    }
    Ok((tree, base))
}

fn guarded_vec<T>(capacity: usize, guard: &dyn WorkGuard) -> Result<Vec<T>, SymbolError> {
    let bytes = Layout::array::<T>(capacity)
        .map_err(|_| SymbolError::resource("allocation layout overflow"))?
        .size();
    let _scope = AllocationScope::begin(
        guard,
        u64::try_from(bytes).map_err(|_| SymbolError::resource("allocation size overflow"))?,
        size_of::<T>() as u64,
    )?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| SymbolError::resource("allocation failed"))?;
    Ok(output)
}

fn work(guard: &dyn WorkGuard, count: usize) -> Result<(), SymbolError> {
    debug_assert!(count <= CHUNK);
    guard.consume(WorkDelta {
        nodes: count as u64,
        ..WorkDelta::default()
    })?;
    Ok(())
}

fn work_bytes(guard: &dyn WorkGuard, count: usize) -> Result<(), SymbolError> {
    for first in (0..count).step_by(CHUNK) {
        work(guard, (count - first).min(CHUNK))?;
    }
    Ok(())
}

fn table_bounds(
    bytes: &[u8],
    offset: usize,
    entry: usize,
    count: usize,
    label: &str,
) -> Result<(), SymbolError> {
    let end = entry
        .checked_mul(count)
        .and_then(|size| offset.checked_add(size))
        .ok_or_else(|| SymbolError::malformed(format!("{label} table overflow")))?;
    if end > bytes.len() {
        return Err(SymbolError::malformed(format!(
            "{label} table exceeds file"
        )));
    }
    Ok(())
}

fn align4(value: usize) -> Result<usize, SymbolError> {
    value
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or_else(|| SymbolError::malformed("alignment overflow"))
}

fn usize_at(value: u64, label: &str) -> Result<usize, SymbolError> {
    usize::try_from(value).map_err(|_| SymbolError::malformed(format!("{label} overflow")))
}

fn u16_at(bytes: &[u8], at: usize) -> Result<u16, SymbolError> {
    Ok(u16::from_le_bytes(
        bytes
            .get(at..at + 2)
            .ok_or_else(|| SymbolError::malformed("truncated ELF field"))?
            .try_into()
            .expect("field length checked"),
    ))
}

fn u32_at(bytes: &[u8], at: usize) -> Result<u32, SymbolError> {
    Ok(u32::from_le_bytes(
        bytes
            .get(at..at + 4)
            .ok_or_else(|| SymbolError::malformed("truncated ELF field"))?
            .try_into()
            .expect("field length checked"),
    ))
}

fn u64_at(bytes: &[u8], at: usize) -> Result<u64, SymbolError> {
    Ok(u64::from_le_bytes(
        bytes
            .get(at..at + 8)
            .ok_or_else(|| SymbolError::malformed("truncated ELF field"))?
            .try_into()
            .expect("field length checked"),
    ))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SymbolError {
    code: &'static str,
    detail: String,
}

impl SymbolError {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
    fn malformed(detail: impl Into<String>) -> Self {
        Self::new("symbol.elf_malformed", detail)
    }
    fn segment(detail: impl Into<String>) -> Self {
        Self::new("symbol.elf_segment_invalid", detail)
    }
    fn resource(detail: impl Into<String>) -> Self {
        Self::new("control.resource_exhausted", detail)
    }
    fn from_path_error(error: qtrace_provider::ProviderError) -> Self {
        let code = match error.code() {
            "control.cancelled" => "job.cancelled",
            "control.budget_exceeded" => "control.budget_exceeded",
            "control.resource_exhausted" => "control.resource_exhausted",
            _ => "symbol.path_escape",
        };
        Self::new(code, error.to_string())
    }
    pub const fn code(&self) -> &'static str {
        self.code
    }
}

impl From<OperationAbort> for SymbolError {
    fn from(error: OperationAbort) -> Self {
        match error {
            OperationAbort::Cancelled => Self::new("job.cancelled", error.to_string()),
            OperationAbort::BudgetExceeded { .. } => {
                Self::new("control.budget_exceeded", error.to_string())
            }
        }
    }
}

impl fmt::Display for SymbolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl Error for SymbolError {}

#[cfg(test)]
static LOOKUP_COMPARISONS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
mod tests {
    use qtrace_provider::{ArtifactDigest, OperationAbort, WorkDelta, WorkGuard};

    use super::{ElfSymbolIndex, IndexedSymbol, LOOKUP_COMPARISONS, ModuleIdentity, build_tree};

    struct AllowAll;

    impl WorkGuard for AllowAll {
        fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
            Ok(())
        }
    }

    #[test]
    fn million_symbol_overlap_and_zero_size_lookup_is_logarithmic() {
        let count = 1_000_000_usize;
        let mut symbols = Vec::with_capacity(count);
        for index in 0..count {
            symbols.push(IndexedSymbol {
                address: index as u64,
                size: if index % 2 == 0 {
                    ((count - index) / 2) as u64
                } else {
                    0
                },
                name_start: 0,
                name_len: 1,
                precedence: 1,
            });
        }
        let (max_end, tree_base) = build_tree(&symbols, &AllowAll).unwrap();
        let index = ElfSymbolIndex {
            module: ModuleIdentity::new("million.so", ArtifactDigest::new([7; 32])),
            build_id: None,
            symbols,
            names: vec![b'x'],
            max_end,
            tree_base,
        };
        LOOKUP_COMPARISONS.store(0, std::sync::atomic::Ordering::Relaxed);
        let resolved = index.resolve((count - 2) as u64).unwrap();
        assert_eq!(resolved.relative_address(), (count - 2) as u64);
        let nearest = index.resolve((count - 1) as u64).unwrap();
        assert_eq!(nearest.relative_address(), (count - 1) as u64);
        assert!(
            LOOKUP_COMPARISONS.load(std::sync::atomic::Ordering::Relaxed) <= 96,
            "containment/predecessor lookup exceeded its logarithmic comparison bound"
        );
    }

    #[test]
    fn containment_search_ignores_max_end_values_beyond_the_upper_bound() {
        let symbols = vec![
            IndexedSymbol {
                address: 0,
                size: 100,
                name_start: 0,
                name_len: 1,
                precedence: 1,
            },
            IndexedSymbol {
                address: 1,
                size: 0,
                name_start: 0,
                name_len: 1,
                precedence: 1,
            },
            IndexedSymbol {
                address: 2,
                size: 0,
                name_start: 0,
                name_len: 1,
                precedence: 1,
            },
            IndexedSymbol {
                address: 100,
                size: 10_000,
                name_start: 0,
                name_len: 1,
                precedence: 1,
            },
        ];
        let (max_end, tree_base) = build_tree(&symbols, &AllowAll).unwrap();
        let index = ElfSymbolIndex {
            module: ModuleIdentity::new("boundary.so", ArtifactDigest::new([8; 32])),
            build_id: None,
            symbols,
            names: vec![b'x'],
            max_end,
            tree_base,
        };
        assert_eq!(index.resolve(5).unwrap().relative_address(), 0);
    }
}
