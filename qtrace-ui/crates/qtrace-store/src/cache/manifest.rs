use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
    pub fn cache_key(&self) -> String {
        let bytes = canonical_json(self).unwrap_or_default();
        hex::encode(Sha256::digest(bytes))
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
    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, CacheError> {
        let bytes = canonical_json(self)?;
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

pub(crate) fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, CacheError> {
    let value = serde_json::to_value(value)
        .map_err(|error| CacheError::invalid(format!("cannot materialize cache JSON: {error}")))?;
    serde_json::to_vec(&value)
        .map_err(|error| CacheError::invalid(format!("cannot encode cache JSON: {error}")))
}
