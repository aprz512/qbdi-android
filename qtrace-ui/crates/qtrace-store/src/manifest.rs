use std::collections::BTreeMap;

use qtrace_provider::{ArtifactDigest, ProviderError};
use serde::Deserialize;
use serde_json::Value;

pub(crate) const MAX_REPORT_BYTES: u64 = 1024 * 1024;
const MAX_ARTIFACTS: usize = 4_096;
const MAX_SHORT_TEXT_BYTES: usize = 1_024;
const MAX_WARNING_DETAIL_BYTES: usize = 512;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawReport {
    schema: u64,
    session_id: String,
    mode: String,
    status: String,
    stage: String,
    package: String,
    serial: String,
    pid: Option<i64>,
    started_at: String,
    finished_at: String,
    timeline: Vec<Value>,
    device: BTreeMap<String, Value>,
    tracer: BTreeMap<String, Value>,
    target: BTreeMap<String, Value>,
    effective_config: BTreeMap<String, Value>,
    native: BTreeMap<String, Value>,
    artifacts: Vec<BTreeMap<String, Value>>,
    warnings: Vec<Value>,
    error: Option<Value>,
    outputs: Vec<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct Manifest {
    pub(crate) session_id: String,
    pub(crate) package_present: bool,
    pub(crate) device_present: bool,
    pub(crate) target_present: bool,
    pub(crate) config_present: bool,
    pub(crate) artifacts: Vec<ManifestArtifact>,
    pub(crate) unavailable: Vec<ManifestWarning>,
}

#[derive(Clone, Debug)]
pub(crate) struct ManifestArtifact {
    pub(crate) local_path: String,
    pub(crate) size: u64,
    pub(crate) digest: ArtifactDigest,
}

#[derive(Clone, Debug)]
pub(crate) struct ManifestWarning {
    pub(crate) code: String,
    pub(crate) detail: String,
}

impl Manifest {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, ProviderError> {
        let raw: RawReport = serde_json::from_slice(bytes)
            .map_err(|error| manifest_error(format!("invalid schema-1 report JSON: {error}")))?;
        if raw.schema != 1 {
            return Err(manifest_error("unsupported session report schema"));
        }
        validate_short("session_id", &raw.session_id)?;
        validate_short("mode", &raw.mode)?;
        validate_short("status", &raw.status)?;
        validate_short("stage", &raw.stage)?;
        validate_short("package", &raw.package)?;
        validate_short("serial", &raw.serial)?;
        validate_short("started_at", &raw.started_at)?;
        validate_short("finished_at", &raw.finished_at)?;
        if raw.artifacts.len() > MAX_ARTIFACTS
            || raw.timeline.len() > MAX_ARTIFACTS
            || raw.warnings.len() > MAX_ARTIFACTS
            || raw.outputs.len() > MAX_ARTIFACTS
        {
            return Err(manifest_error(
                "session report collection exceeds its bound",
            ));
        }
        for output in &raw.outputs {
            validate_short("output", output)?;
        }
        let _ = raw.pid;
        let _ = raw.native;
        let _ = raw.error;

        let mut artifacts = Vec::new();
        artifacts
            .try_reserve_exact(raw.artifacts.len())
            .map_err(|_| manifest_error("artifact record allocation failed"))?;
        let mut unavailable = Vec::new();
        unavailable
            .try_reserve_exact(raw.artifacts.len().saturating_add(raw.warnings.len()))
            .map_err(|_| manifest_error("warning allocation failed"))?;

        for record in raw.artifacts {
            let Some(local_path_value) = record.get("local_path") else {
                unavailable.push(parse_warning(&record)?);
                continue;
            };
            let local_path = local_path_value
                .as_str()
                .ok_or_else(|| manifest_error("artifact local_path must be a string"))?;
            if local_path.is_empty() || local_path.len() > 4_096 {
                return Err(manifest_error("artifact local_path exceeds its bound"));
            }
            let digest_text = record
                .get("sha256")
                .and_then(Value::as_str)
                .ok_or_else(|| manifest_error("successful artifact requires sha256"))?;
            if digest_text.len() != 64
                || !digest_text
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(manifest_error(
                    "artifact sha256 must be 64 lowercase hexadecimal digits",
                ));
            }
            let digest = ArtifactDigest::from_hex(digest_text)
                .ok_or_else(|| manifest_error("artifact sha256 is malformed"))?;
            let size = record
                .get("destination_size")
                .and_then(Value::as_u64)
                .filter(|size| *size > 0)
                .ok_or_else(|| {
                    manifest_error("successful artifact requires positive destination_size")
                })?;
            artifacts.push(ManifestArtifact {
                local_path: local_path.to_owned(),
                size,
                digest,
            });
        }
        for warning in raw.warnings {
            let Value::Object(record) = warning else {
                return Err(manifest_error("report warning must be an object"));
            };
            let record = record.into_iter().collect::<BTreeMap<_, _>>();
            unavailable.push(parse_warning(&record)?);
        }

        Ok(Self {
            session_id: raw.session_id,
            package_present: !raw.package.is_empty(),
            device_present: !raw.serial.is_empty() && !raw.device.is_empty(),
            target_present: !raw.target.is_empty(),
            config_present: !raw.effective_config.is_empty() || !raw.tracer.is_empty(),
            artifacts,
            unavailable,
        })
    }
}

fn parse_warning(record: &BTreeMap<String, Value>) -> Result<ManifestWarning, ProviderError> {
    let code = record
        .get("code")
        .and_then(Value::as_str)
        .unwrap_or("session.artifact_unavailable");
    let detail = record
        .get("detail")
        .and_then(Value::as_str)
        .unwrap_or("artifact record has no local source");
    if code.is_empty()
        || code.len() > MAX_SHORT_TEXT_BYTES
        || detail.len() > MAX_WARNING_DETAIL_BYTES
    {
        return Err(manifest_error("artifact warning exceeds its bound"));
    }
    Ok(ManifestWarning {
        code: code.to_owned(),
        detail: detail.to_owned(),
    })
}

fn validate_short(name: &str, value: &str) -> Result<(), ProviderError> {
    if value.len() > MAX_SHORT_TEXT_BYTES {
        return Err(manifest_error(format!("report {name} exceeds its bound")));
    }
    Ok(())
}

fn manifest_error(detail: impl AsRef<str>) -> ProviderError {
    ProviderError::new(
        "session.manifest_invalid",
        "session.manifest",
        None,
        false,
        detail,
    )
}
