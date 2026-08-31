use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use qtrace_provider::WorkGuard;

use super::{CacheError, CacheIdentityField, RebuildReason};

pub(crate) const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
pub(crate) const MAX_SECTIONS: usize = 64;
const MAX_SECTION_NAME_BYTES: usize = 128;
const MAX_IDENTITY_TEXT_BYTES: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheIdentity {
    pub analyzer_version: String,
    pub artifact_digest: [u8; 32],
    pub build_option_digest: [u8; 32],
    pub cache_schema: u32,
    pub endian: String,
    pub layout_version: u32,
    pub source_features: u64,
    pub source_format: String,
    pub source_major: u16,
    pub source_minor: u16,
}

impl CacheIdentity {
    pub(crate) fn try_clone_guarded(&self, guard: &dyn WorkGuard) -> Result<Self, CacheError> {
        Ok(Self {
            analyzer_version: crate::allocation::try_copy_string(
                &self.analyzer_version,
                guard,
                "cache analyzer version",
            )?,
            artifact_digest: self.artifact_digest,
            build_option_digest: self.build_option_digest,
            cache_schema: self.cache_schema,
            endian: crate::allocation::try_copy_string(&self.endian, guard, "cache endian")?,
            layout_version: self.layout_version,
            source_features: self.source_features,
            source_format: crate::allocation::try_copy_string(
                &self.source_format,
                guard,
                "cache source format",
            )?,
            source_major: self.source_major,
            source_minor: self.source_minor,
        })
    }

    pub fn cache_key(&self) -> String {
        self.legacy_digest_key()
            .map(hex::encode)
            .unwrap_or_default()
    }

    pub(crate) fn cache_key_guarded(&self, guard: &dyn WorkGuard) -> Result<String, CacheError> {
        let digest = self.legacy_digest_key()?;
        let mut key = String::new();
        crate::allocation::try_reserve_string(&mut key, 64, guard, "cache identity key")?;
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in digest {
            key.push(char::from(HEX[usize::from(byte >> 4)]));
            key.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        Ok(key)
    }

    fn legacy_digest_key(&self) -> Result<[u8; 32], CacheError> {
        self.validate()?;
        let mut digest = Sha256::new();
        serde_json::to_writer(DigestWriter(&mut digest), self)
            .map_err(|_| CacheError::invalid("cannot encode canonical cache identity"))?;
        Ok(digest.finalize().into())
    }

    pub(crate) fn validate(&self) -> Result<(), CacheError> {
        if self.cache_schema == 0 || self.layout_version == 0 {
            return Err(CacheError::invalid(
                "cache schema and layout version must be non-zero",
            ));
        }
        if self.endian != "little" {
            return Err(CacheError::invalid(
                "only explicit little-endian cache layout is supported",
            ));
        }
        if self.analyzer_version.is_empty()
            || self.analyzer_version.len() > MAX_IDENTITY_TEXT_BYTES
            || self.source_format.is_empty()
            || self.source_format.len() > MAX_IDENTITY_TEXT_BYTES
        {
            return Err(CacheError::invalid(
                "cache identity text is empty or too long",
            ));
        }
        Ok(())
    }

    pub(crate) fn mismatch(&self, expected: &Self) -> Option<CacheIdentityField> {
        if self.analyzer_version != expected.analyzer_version {
            Some(CacheIdentityField::AnalyzerVersion)
        } else if self.artifact_digest != expected.artifact_digest {
            Some(CacheIdentityField::ArtifactDigest)
        } else if self.build_option_digest != expected.build_option_digest {
            Some(CacheIdentityField::BuildOptionDigest)
        } else if self.cache_schema != expected.cache_schema {
            Some(CacheIdentityField::CacheSchema)
        } else if self.endian != expected.endian {
            Some(CacheIdentityField::Endian)
        } else if self.layout_version != expected.layout_version {
            Some(CacheIdentityField::LayoutVersion)
        } else if self.source_features != expected.source_features {
            Some(CacheIdentityField::SourceFeatures)
        } else if self.source_format != expected.source_format {
            Some(CacheIdentityField::SourceFormat)
        } else if self.source_major != expected.source_major {
            Some(CacheIdentityField::SourceMajor)
        } else if self.source_minor != expected.source_minor {
            Some(CacheIdentityField::SourceMinor)
        } else {
            None
        }
    }
}

struct DigestWriter<'a>(&'a mut Sha256);

impl std::io::Write for DigestWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SectionDescriptor {
    pub alignment: u32,
    pub checksum: [u8; 32],
    pub element_size: u32,
    pub length: u64,
    pub name: String,
    pub offset: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheManifest {
    pub identity: CacheIdentity,
    pub sections: Vec<SectionDescriptor>,
}

impl CacheManifest {
    pub(crate) fn canonical_bytes(&self, guard: &dyn WorkGuard) -> Result<Vec<u8>, CacheError> {
        let bytes = canonical_manifest_json(self, guard)?;
        if bytes.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(CacheError::invalid("cache manifest exceeds its byte limit"));
        }
        Ok(bytes)
    }

    pub(crate) fn validate_shape(&self) -> Result<(), RebuildReason> {
        if self.sections.is_empty() || self.sections.len() > MAX_SECTIONS {
            return Err(RebuildReason::Manifest("section count"));
        }
        for section in &self.sections {
            if section.name.is_empty() || section.name.len() > MAX_SECTION_NAME_BYTES {
                return Err(RebuildReason::Section("name"));
            }
        }
        Ok(())
    }
}

pub(crate) fn canonical_manifest_json(
    value: &CacheManifest,
    guard: &dyn WorkGuard,
) -> Result<Vec<u8>, CacheError> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or_else(|| std::io::Error::other("manifest length overflow"))?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, value)
        .map_err(|_| CacheError::invalid("cannot size canonical cache JSON"))?;
    if counter.0 as u64 > MAX_MANIFEST_BYTES {
        return Err(CacheError::invalid("cache manifest exceeds its byte limit"));
    }
    let mut bytes = Vec::new();
    crate::allocation::try_reserve_vec(&mut bytes, counter.0, guard, "canonical cache manifest")?;
    serde_json::to_writer(&mut bytes, value)
        .map_err(|_| CacheError::invalid("cannot encode canonical cache JSON"))?;
    Ok(bytes)
}
