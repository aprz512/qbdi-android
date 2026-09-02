use std::{error::Error, fmt};

use object::{Architecture, BinaryFormat, Object, ObjectSegment, ObjectSymbol};
use qtrace_provider::{ArtifactDigest, OperationAbort, WorkDelta, WorkGuard};
use sha2::{Digest, Sha256};

use crate::{AuthorizedPath, secure_path::split_selected_file};

const MAX_ELF_BYTES: u64 = 512 * 1024 * 1024;
const MAX_SYMBOLS: usize = 1_000_000;
const MAX_SYMBOL_NAME_BYTES: usize = 4_096;

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

#[derive(Clone, Debug)]
struct IndexedSymbol {
    name: String,
    relative_address: u64,
    size: u64,
    precedence: u8,
}

#[derive(Clone, Debug)]
pub struct ElfSymbolIndex {
    module: ModuleIdentity,
    build_id: Option<Vec<u8>>,
    symbols: Vec<IndexedSymbol>,
}

impl ElfSymbolIndex {
    pub fn load(request: ElfLoadRequest, guard: &dyn WorkGuard) -> Result<Self, SymbolError> {
        if !request.approved {
            return Err(SymbolError::new(
                "symbol.approval_required",
                "external ELF selection was not approved by the native picker",
            ));
        }
        if request.expected_producer != ElfProducerIdentity::aarch64_android() {
            return Err(SymbolError::new(
                "symbol.producer_identity_mismatch",
                "producer target identity is not Android AArch64",
            ));
        }
        let (root, leaf) = split_selected_file(request.selected.as_path())
            .map_err(SymbolError::from_path_error)?;
        if leaf != request.expected_module.name {
            return Err(SymbolError::new(
                "symbol.module_identity_mismatch",
                "selected ELF filename does not match the expected module name",
            ));
        }
        let source = root
            .open_source_file(&leaf)
            .map_err(SymbolError::from_path_error)?;
        let identity = source.identity().map_err(SymbolError::from_path_error)?;
        if identity.size == 0 || identity.size > MAX_ELF_BYTES {
            return Err(SymbolError::new(
                "symbol.file_too_large",
                "ELF is empty or exceeds the bounded input size",
            ));
        }
        let bytes = source
            .read_bounded(MAX_ELF_BYTES, guard)
            .map_err(SymbolError::from_path_error)?;
        let actual_digest = ArtifactDigest::new(Sha256::digest(&bytes).into());
        if actual_digest != request.expected_module.digest {
            return Err(SymbolError::new(
                "symbol.module_identity_mismatch",
                "selected ELF digest does not match the expected module identity",
            ));
        }
        validate_elf_header_and_sections(&bytes)?;
        let file = object::File::parse(bytes.as_slice())
            .map_err(|error| SymbolError::new("symbol.elf_malformed", error.to_string()))?;
        if file.format() != BinaryFormat::Elf {
            return Err(SymbolError::new(
                "symbol.elf_malformed",
                "selected object is not ELF",
            ));
        }
        if !file.is_64() {
            return Err(SymbolError::new(
                "symbol.elf_class_unsupported",
                "only ELF64 is supported",
            ));
        }
        if !file.is_little_endian() {
            return Err(SymbolError::new(
                "symbol.elf_endian_unsupported",
                "only little-endian ELF is supported",
            ));
        }
        if file.architecture() != Architecture::Aarch64 {
            return Err(SymbolError::new(
                "symbol.elf_machine_unsupported",
                "only AArch64 ELF is supported",
            ));
        }
        let raw_build_id = file
            .build_id()
            .map_err(|error| SymbolError::new("symbol.elf_malformed", error.to_string()))?;
        if request
            .expected_build_id
            .as_deref()
            .is_some_and(|expected| raw_build_id != Some(expected))
        {
            return Err(SymbolError::new(
                "symbol.build_id_mismatch",
                "GNU build-id does not match the expected module identity",
            ));
        }
        let build_id = raw_build_id
            .map(|value| guarded_copy_bytes(value, guard, "GNU build-id"))
            .transpose()?;

        let image_base = file
            .segments()
            .map(|segment| segment.address())
            .min()
            .unwrap_or(0);
        let mut raw = Vec::new();
        collect_symbols(&mut raw, file.dynamic_symbols(), image_base, 0, guard)?;
        collect_symbols(&mut raw, file.symbols(), image_base, 1, guard)?;
        raw.sort_unstable_by(|left, right| {
            left.relative_address
                .cmp(&right.relative_address)
                .then_with(|| right.precedence.cmp(&left.precedence))
                .then_with(|| right.size.cmp(&left.size))
                .then_with(|| left.name.cmp(&right.name))
        });
        let mut symbols = Vec::new();
        symbols
            .try_reserve_exact(raw.len())
            .map_err(|_| SymbolError::resource("symbol index allocation failed"))?;
        for symbol in raw {
            if symbols.last().is_some_and(|existing: &IndexedSymbol| {
                existing.relative_address == symbol.relative_address
            }) {
                continue;
            }
            symbols.push(symbol);
        }
        Ok(Self {
            module: request.expected_module,
            build_id,
            symbols,
        })
    }

    pub const fn module_identity(&self) -> &ModuleIdentity {
        &self.module
    }

    pub fn build_id(&self) -> Option<&[u8]> {
        self.build_id.as_deref()
    }

    pub fn resolve(&self, relative_pc: u64) -> Option<ElfSymbolMatch> {
        let upper = self
            .symbols
            .partition_point(|symbol| symbol.relative_address <= relative_pc);
        if upper == 0 {
            return None;
        }
        let preceding = &self.symbols[upper - 1];
        let selected = self.symbols[..upper]
            .iter()
            .rev()
            .find(|symbol| {
                symbol.size != 0
                    && relative_pc < symbol.relative_address.saturating_add(symbol.size)
            })
            .unwrap_or(preceding);
        Some(ElfSymbolMatch {
            name: selected.name.clone(),
            relative_address: selected.relative_address,
            size: selected.size,
            offset: relative_pc - selected.relative_address,
        })
    }
}

fn collect_symbols<'data, I>(
    output: &mut Vec<IndexedSymbol>,
    symbols: I,
    image_base: u64,
    precedence: u8,
    guard: &dyn WorkGuard,
) -> Result<(), SymbolError>
where
    I: Iterator<Item = object::Symbol<'data, 'data>>,
{
    for symbol in symbols {
        if !symbol.is_definition() || symbol.section_index().is_none() {
            continue;
        }
        let Ok(name) = symbol.name() else {
            continue;
        };
        if name.is_empty() || name.len() > MAX_SYMBOL_NAME_BYTES {
            continue;
        }
        let Some(relative_address) = symbol.address().checked_sub(image_base) else {
            continue;
        };
        if output.len() >= MAX_SYMBOLS {
            return Err(SymbolError::resource("ELF symbol count exceeds its limit"));
        }
        guard.consume(WorkDelta {
            nodes: 1,
            resident_bytes: u64::try_from(name.len())
                .map_err(|_| SymbolError::resource("symbol name size overflow"))?,
            ..WorkDelta::default()
        })?;
        let mut owned_name = String::new();
        owned_name
            .try_reserve_exact(name.len())
            .map_err(|_| SymbolError::resource("symbol name allocation failed"))?;
        owned_name.push_str(name);
        output
            .try_reserve(1)
            .map_err(|_| SymbolError::resource("symbol index allocation failed"))?;
        output.push(IndexedSymbol {
            name: owned_name,
            relative_address,
            size: symbol.size(),
            precedence,
        });
    }
    Ok(())
}

fn guarded_copy_bytes(
    value: &[u8],
    guard: &dyn WorkGuard,
    label: &str,
) -> Result<Vec<u8>, SymbolError> {
    guard.consume(WorkDelta {
        resident_bytes: u64::try_from(value.len())
            .map_err(|_| SymbolError::resource(format!("{label} size overflow")))?,
        ..WorkDelta::default()
    })?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(value.len())
        .map_err(|_| SymbolError::resource(format!("{label} allocation failed")))?;
    output.extend_from_slice(value);
    Ok(output)
}

fn validate_elf_header_and_sections(bytes: &[u8]) -> Result<(), SymbolError> {
    if bytes.len() < 64 || &bytes[..4] != b"\x7fELF" {
        return Err(SymbolError::new(
            "symbol.elf_malformed",
            "invalid ELF header",
        ));
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
            "only little-endian ELF is supported",
        ));
    }
    if read_u16(bytes, 18)? != 183 {
        return Err(SymbolError::new(
            "symbol.elf_machine_unsupported",
            "only AArch64 ELF is supported",
        ));
    }
    let section_offset = usize::try_from(read_u64(bytes, 40)?)
        .map_err(|_| SymbolError::malformed("section table offset overflow"))?;
    let entry_size = usize::from(read_u16(bytes, 58)?);
    let count = usize::from(read_u16(bytes, 60)?);
    if entry_size != 64 || count == 0 {
        return Err(SymbolError::malformed("invalid ELF section table shape"));
    }
    let table_bytes = entry_size
        .checked_mul(count)
        .and_then(|size| section_offset.checked_add(size))
        .ok_or_else(|| SymbolError::malformed("section table bounds overflow"))?;
    if table_bytes > bytes.len() {
        return Err(SymbolError::malformed("section table exceeds ELF bounds"));
    }
    for index in 0..count {
        let section = section_offset + index * entry_size;
        let kind = read_u32(bytes, section + 4)?;
        if kind == 8 {
            continue;
        }
        let offset = usize::try_from(read_u64(bytes, section + 24)?)
            .map_err(|_| SymbolError::malformed("section offset overflow"))?;
        let size = usize::try_from(read_u64(bytes, section + 32)?)
            .map_err(|_| SymbolError::malformed("section size overflow"))?;
        if offset.checked_add(size).is_none_or(|end| end > bytes.len()) {
            return Err(SymbolError::malformed("section exceeds ELF bounds"));
        }
    }
    Ok(())
}

fn read_u16(bytes: &[u8], at: usize) -> Result<u16, SymbolError> {
    let value = bytes
        .get(at..at + 2)
        .ok_or_else(|| SymbolError::malformed("truncated ELF field"))?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], at: usize) -> Result<u32, SymbolError> {
    let value = bytes
        .get(at..at + 4)
        .ok_or_else(|| SymbolError::malformed("truncated ELF field"))?;
    let mut raw = [0_u8; 4];
    raw.copy_from_slice(value);
    Ok(u32::from_le_bytes(raw))
}

fn read_u64(bytes: &[u8], at: usize) -> Result<u64, SymbolError> {
    let value = bytes
        .get(at..at + 8)
        .ok_or_else(|| SymbolError::malformed("truncated ELF field"))?;
    let mut raw = [0_u8; 8];
    raw.copy_from_slice(value);
    Ok(u64::from_le_bytes(raw))
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
