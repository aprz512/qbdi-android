use std::{error::Error, fmt};

use qtrace_store::{ElfSymbolIndex, LocalSymbolName, ModuleIdentity};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedSymbol {
    elf_name: Option<String>,
    display_name: String,
    relative_address: u64,
    offset: u64,
}

impl ResolvedSymbol {
    pub fn elf_name(&self) -> Option<&str> {
        self.elf_name.as_deref()
    }

    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    pub const fn relative_address(&self) -> u64 {
        self.relative_address
    }

    pub const fn offset(&self) -> u64 {
        self.offset
    }
}

#[derive(Clone, Debug)]
pub struct SymbolResolver {
    elf: ElfSymbolIndex,
    local_names: Vec<LocalSymbolName>,
}

impl SymbolResolver {
    pub fn new(
        elf: ElfSymbolIndex,
        mut local_names: Vec<LocalSymbolName>,
    ) -> Result<Self, SymbolResolveError> {
        local_names.sort_unstable_by(|left, right| {
            left.module_digest()
                .as_bytes()
                .cmp(right.module_digest().as_bytes())
                .then_with(|| left.relative_pc().cmp(&right.relative_pc()))
        });
        if local_names.windows(2).any(|pair| {
            pair[0].module_digest() == pair[1].module_digest()
                && pair[0].relative_pc() == pair[1].relative_pc()
        }) {
            return Err(SymbolResolveError::new(
                "analysis.symbol_duplicate_local_name",
                "duplicate local symbol coordinate",
            ));
        }
        Ok(Self { elf, local_names })
    }

    pub fn resolve(&self, module: &ModuleIdentity, relative_pc: u64) -> Option<ResolvedSymbol> {
        if module != self.elf.module_identity() {
            return None;
        }
        let elf = self.elf.resolve(relative_pc);
        let coordinate = elf
            .as_ref()
            .map_or(relative_pc, |symbol| symbol.relative_address());
        let local = find_local_name(&self.local_names, module.digest(), coordinate);
        match (elf, local) {
            (Some(symbol), local) => {
                let elf_name = symbol.name().to_owned();
                Some(ResolvedSymbol {
                    display_name: local
                        .map_or_else(|| elf_name.clone(), |name| name.name().to_owned()),
                    elf_name: Some(elf_name),
                    relative_address: symbol.relative_address(),
                    offset: symbol.offset(),
                })
            }
            (None, Some(local)) => Some(ResolvedSymbol {
                elf_name: None,
                display_name: local.name().to_owned(),
                relative_address: local.relative_pc(),
                offset: relative_pc.saturating_sub(local.relative_pc()),
            }),
            (None, None) => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SymbolResolveError {
    code: &'static str,
    detail: String,
}

impl SymbolResolveError {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    pub const fn code(&self) -> &'static str {
        self.code
    }
}

impl fmt::Display for SymbolResolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl Error for SymbolResolveError {}

fn find_local_name(
    names: &[LocalSymbolName],
    digest: qtrace_provider::ArtifactDigest,
    coordinate: u64,
) -> Option<&LocalSymbolName> {
    names
        .binary_search_by(|name| {
            #[cfg(test)]
            LOCAL_LOOKUP_COMPARISONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            name.module_digest()
                .as_bytes()
                .cmp(digest.as_bytes())
                .then_with(|| name.relative_pc().cmp(&coordinate))
        })
        .ok()
        .map(|index| &names[index])
}

#[cfg(test)]
static LOCAL_LOOKUP_COMPARISONS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
mod tests {
    use qtrace_provider::ArtifactDigest;
    use qtrace_store::LocalSymbolName;

    use super::{LOCAL_LOOKUP_COMPARISONS, find_local_name};

    #[test]
    fn late_local_name_lookup_is_logarithmic_at_one_million_entries() {
        let digest = ArtifactDigest::new([0x44; 32]);
        let mut names = Vec::with_capacity(1_000_000);
        for pc in 0..1_000_000_u64 {
            names.push(LocalSymbolName::new(digest, pc, "x").unwrap());
        }
        LOCAL_LOOKUP_COMPARISONS.store(0, std::sync::atomic::Ordering::Relaxed);
        let found = find_local_name(&names, digest, 999_999).unwrap();
        assert_eq!(found.relative_pc(), 999_999);
        assert!(LOCAL_LOOKUP_COMPARISONS.load(std::sync::atomic::Ordering::Relaxed) <= 21);
    }
}
