use std::{mem::size_of, path::PathBuf};

use qtrace_provider::{
    ArtifactDigest, EventCursor, EventRecord, FlightProvider, OpenMode, ProviderCapabilities,
    ProviderError, ProviderSummary, QtrbInput, QtrbProvider,
    SourceIdentity as ProviderSourceIdentity, TimelineDescriptor, TimelineId, TraceProvider,
    WorkDelta, WorkGuard,
};
use sha2::{Digest, Sha256};

use crate::{
    SourceIdentity,
    manifest::{MAX_REPORT_BYTES, Manifest, ManifestArtifact},
    secure_path::{SecureFile, split_selected_file, split_selected_report},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedPath(PathBuf);

impl AuthorizedPath {
    pub fn new(path: PathBuf) -> Self {
        Self(path)
    }

    pub fn as_path(&self) -> &std::path::Path {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenPolicy {
    qtrb_mode: OpenMode,
    defer_provider_probe: bool,
}

impl OpenPolicy {
    pub const fn recoverable_partial() -> Self {
        Self {
            qtrb_mode: OpenMode::RecoverablePartial,
            defer_provider_probe: false,
        }
    }

    pub const fn cache_aware() -> Self {
        Self {
            qtrb_mode: OpenMode::Sealed,
            defer_provider_probe: true,
        }
    }
}

impl Default for OpenPolicy {
    fn default() -> Self {
        Self {
            qtrb_mode: OpenMode::Sealed,
            defer_provider_probe: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactFormat {
    Qtrb,
    QtrbLz4,
    Flight,
}

impl ArtifactFormat {
    pub const fn is_qtrb(self) -> bool {
        matches!(self, Self::Qtrb | Self::QtrbLz4)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SessionCapability {
    Package,
    Device,
    Target,
    EffectiveConfig,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionCapabilities {
    package: bool,
    device: bool,
    target: bool,
    effective_config: bool,
}

impl SessionCapabilities {
    pub const fn has(self, capability: SessionCapability) -> bool {
        match capability {
            SessionCapability::Package => self.package,
            SessionCapability::Device => self.device,
            SessionCapability::Target => self.target,
            SessionCapability::EffectiveConfig => self.effective_config,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionWarning {
    code: String,
    detail: String,
    capability: Option<SessionCapability>,
}

impl SessionWarning {
    pub fn code(&self) -> &str {
        &self.code
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }

    pub const fn capability(&self) -> Option<SessionCapability> {
        self.capability
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactMetadata {
    local_path: String,
    identity: SourceIdentity,
}

impl ArtifactMetadata {
    pub fn local_path(&self) -> &str {
        &self.local_path
    }

    pub const fn identity(&self) -> &SourceIdentity {
        &self.identity
    }
}

#[derive(Debug)]
pub struct ArtifactFailure {
    local_path: Option<String>,
    error: ProviderError,
}

impl ArtifactFailure {
    pub fn local_path(&self) -> Option<&str> {
        self.local_path.as_deref()
    }

    pub const fn error(&self) -> &ProviderError {
        &self.error
    }
}

#[derive(Debug)]
pub struct ArtifactSource {
    local_path: String,
    format: ArtifactFormat,
    timeline_id: TimelineId,
    identity: SourceIdentity,
    source: SecureFile,
    provider_timelines: Vec<TimelineDescriptor>,
    qtrb_mode: OpenMode,
}

impl ArtifactSource {
    pub fn local_path(&self) -> &str {
        &self.local_path
    }

    pub const fn format(&self) -> ArtifactFormat {
        self.format
    }

    pub const fn timeline_id(&self) -> TimelineId {
        self.timeline_id
    }

    pub const fn identity(&self) -> &SourceIdentity {
        &self.identity
    }

    pub fn provider_timelines(&self) -> &[TimelineDescriptor] {
        &self.provider_timelines
    }

    pub fn read_all(&self, guard: &dyn WorkGuard) -> Result<Vec<u8>, ProviderError> {
        let expected = *self.identity.file();
        self.source.verify_unchanged(expected, false)?;
        let bytes = self.source.read_all_held(guard)?;
        self.source.verify_unchanged(expected, false)?;
        Ok(bytes)
    }

    pub fn open_provider(
        &self,
        guard: &dyn WorkGuard,
    ) -> Result<Box<dyn TraceProvider>, ProviderError> {
        let expected = *self.identity.file();
        self.source.verify_unchanged(expected, true)?;
        let mut provider = open_provider(
            &self.source,
            self.format,
            try_clone_provider_identity(self.identity.provider(), guard)?,
            self.qtrb_mode,
            guard,
        )?;
        self.source.verify_unchanged(expected, true)?;
        if self.format.is_qtrb() {
            provider = remap_qtrb_provider(provider, self.timeline_id, guard)?;
        }
        Ok(crate::allocation::try_box(
            IdentityCheckedProvider {
                inner: provider,
                source: self.source.try_clone_guarded(guard)?,
                expected,
            },
            guard,
            "identity-checked provider allocation",
        )
        .map_err(provider_allocation_error)?)
    }
}

#[derive(Debug)]
pub struct SessionSource {
    session_id: Option<String>,
    artifacts: Vec<ArtifactSource>,
    metadata: Vec<ArtifactMetadata>,
    failures: Vec<ArtifactFailure>,
    warnings: Vec<SessionWarning>,
    capabilities: SessionCapabilities,
}

impl SessionSource {
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    pub fn artifacts(&self) -> &[ArtifactSource] {
        &self.artifacts
    }

    pub fn available_artifacts(&self) -> impl Iterator<Item = &ArtifactSource> {
        self.artifacts.iter()
    }

    pub fn metadata(&self) -> &[ArtifactMetadata] {
        &self.metadata
    }

    pub fn failures(&self) -> &[ArtifactFailure] {
        &self.failures
    }

    pub fn warnings(&self) -> &[SessionWarning] {
        &self.warnings
    }

    pub const fn capabilities(&self) -> SessionCapabilities {
        self.capabilities
    }
}

pub struct SessionLoader;

impl SessionLoader {
    pub fn open_report(
        selected: AuthorizedPath,
        policy: OpenPolicy,
        guard: &dyn WorkGuard,
    ) -> Result<SessionSource, ProviderError> {
        let selected_path = selected.0;
        let (root, report_name, display_root) = split_selected_report(&selected_path)?;
        let report_file = root.open_report_file(report_name)?;
        let report_bytes = report_file.read_bounded(MAX_REPORT_BYTES, guard)?;
        let manifest = Manifest::parse(&report_bytes)?;
        let mut session = SessionSource {
            session_id: Some(manifest.session_id),
            artifacts: fallible_vec(manifest.artifacts.len())?,
            metadata: fallible_vec(manifest.artifacts.len())?,
            failures: fallible_vec(manifest.artifacts.len())?,
            warnings: fallible_vec(manifest.unavailable.len())?,
            capabilities: SessionCapabilities {
                package: manifest.package_present,
                device: manifest.device_present,
                target: manifest.target_present,
                effective_config: manifest.config_present,
            },
        };
        for warning in manifest.unavailable {
            session.warnings.push(SessionWarning {
                code: warning.code,
                detail: warning.detail,
                capability: None,
            });
        }

        for (record_index, record) in manifest.artifacts.into_iter().enumerate() {
            guard.consume(WorkDelta::default())?;
            let _suffix_format = match classify(&record.local_path) {
                ArtifactClass::Provider(format) => format,
                ArtifactClass::Metadata => {
                    let opened = open_and_verify(&root, &record, guard);
                    match opened {
                        Ok((_source, identity)) => session.metadata.push(ArtifactMetadata {
                            local_path: record.local_path,
                            identity: SourceIdentity::new(
                                display_root.join(&identity.0),
                                identity.1,
                                identity.2,
                            ),
                        }),
                        Err(error) if is_session_fatal(&error) => return Err(error),
                        Err(error) => session.failures.push(ArtifactFailure {
                            local_path: Some(record.local_path),
                            error,
                        }),
                    }
                    continue;
                }
                ArtifactClass::Unsupported => {
                    let local_path = record.local_path.clone();
                    match open_and_verify(&root, &record, guard) {
                        Ok(_) => session.failures.push(ArtifactFailure {
                            local_path: Some(local_path),
                            error: format_error(
                                "local artifact is not a supported analysis source",
                            ),
                        }),
                        Err(error) if is_session_fatal(&error) => return Err(error),
                        Err(error) => session.failures.push(ArtifactFailure {
                            local_path: Some(local_path),
                            error,
                        }),
                    }
                    continue;
                }
            };

            let local_path = record.local_path.clone();
            let result: Result<ArtifactSource, ProviderError> = (|| {
                let (source, (relative, file_identity, mut provider_identity)) =
                    open_and_verify(&root, &record, guard)?;
                let format = probe_artifact_format(&source, guard)?;
                let provider = open_provider(
                    &source,
                    format,
                    provider_identity.clone(),
                    policy.qtrb_mode,
                    guard,
                )
                .map_err(|error| normalize_provider_error(format, error))?;
                provider_identity = provider.identity().clone();
                let provider_timelines = session_timelines(
                    format,
                    TimelineId(record_index as u64),
                    provider.timelines(),
                    guard,
                )?;
                if !policy.defer_provider_probe {
                    probe(provider, format, guard)?;
                }
                source.verify_unchanged(file_identity, true)?;
                Ok(ArtifactSource {
                    local_path: relative.clone(),
                    format,
                    timeline_id: TimelineId(record_index as u64),
                    identity: SourceIdentity::new(
                        display_root.join(&relative),
                        file_identity,
                        provider_identity,
                    ),
                    source,
                    provider_timelines,
                    qtrb_mode: policy.qtrb_mode,
                })
            })();
            match result {
                Ok(artifact) => session.artifacts.push(artifact),
                Err(error) if is_session_fatal(&error) => return Err(error),
                Err(error) => session.failures.push(ArtifactFailure {
                    local_path: Some(local_path),
                    error,
                }),
            }
        }
        Ok(session)
    }

    pub fn open_artifact(
        selected: AuthorizedPath,
        policy: OpenPolicy,
        guard: &dyn WorkGuard,
    ) -> Result<SessionSource, ProviderError> {
        let path = selected.0;
        let (root, leaf) = split_selected_file(&path)?;
        let _suffix_format = match classify(&leaf) {
            ArtifactClass::Provider(format) => format,
            _ => {
                return Err(format_error(
                    "selected file is not a binary analysis source",
                ));
            }
        };
        let source = root.open_source_file(&leaf)?;
        let file_identity = source.identity()?;
        let digest = hash_file(&source, file_identity, guard)?;
        let format = probe_artifact_format(&source, guard)?;
        let initial_identity = ProviderSourceIdentity {
            artifact: digest,
            format: format.label().to_owned(),
            format_major: 0,
            format_minor: 0,
            source_bytes: file_identity.size,
        };
        let provider = open_provider(&source, format, initial_identity, policy.qtrb_mode, guard)
            .map_err(|error| normalize_provider_error(format, error))?;
        let provider_identity = provider.identity().clone();
        let provider_timelines =
            session_timelines(format, TimelineId(0), provider.timelines(), guard)?;
        if !policy.defer_provider_probe {
            probe(provider, format, guard)?;
        }
        source.verify_unchanged(file_identity, true)?;
        let artifact = ArtifactSource {
            local_path: leaf,
            format,
            timeline_id: TimelineId(0),
            identity: SourceIdentity::new(path, file_identity, provider_identity),
            source,
            provider_timelines,
            qtrb_mode: policy.qtrb_mode,
        };
        let missing = [
            SessionCapability::Package,
            SessionCapability::Device,
            SessionCapability::Target,
            SessionCapability::EffectiveConfig,
        ];
        let warnings = missing
            .into_iter()
            .map(|capability| SessionWarning {
                code: "session.capability_missing".to_owned(),
                detail: format!("single-artifact session lacks {capability:?} context"),
                capability: Some(capability),
            })
            .collect();
        Ok(SessionSource {
            session_id: None,
            artifacts: vec![artifact],
            metadata: Vec::new(),
            failures: Vec::new(),
            warnings,
            capabilities: SessionCapabilities {
                package: false,
                device: false,
                target: false,
                effective_config: false,
            },
        })
    }
}

impl ArtifactFormat {
    const fn label(self) -> &'static str {
        match self {
            Self::Qtrb | Self::QtrbLz4 => "QTRB",
            Self::Flight => "Flight",
        }
    }
}

enum ArtifactClass {
    Provider(ArtifactFormat),
    Metadata,
    Unsupported,
}

fn classify(path: &str) -> ArtifactClass {
    if path.ends_with(".trace.bin.lz4") {
        ArtifactClass::Provider(ArtifactFormat::QtrbLz4)
    } else if path.ends_with(".trace.bin") {
        ArtifactClass::Provider(ArtifactFormat::Qtrb)
    } else if path.ends_with(".flight.bin") {
        ArtifactClass::Provider(ArtifactFormat::Flight)
    } else if path.ends_with(".metrics")
        || path.ends_with(".crash")
        || path.ends_with(".trace.txt")
        || path.ends_with(".trace.txt.lz4")
        || path.ends_with(".flight.json")
    {
        ArtifactClass::Metadata
    } else {
        ArtifactClass::Unsupported
    }
}

fn open_and_verify(
    root: &crate::secure_path::SecureRoot,
    record: &ManifestArtifact,
    guard: &dyn WorkGuard,
) -> Result<
    (
        SecureFile,
        (String, crate::FileIdentity, ProviderSourceIdentity),
    ),
    ProviderError,
> {
    let source = root.open_source_file(&record.local_path)?;
    let file_identity = source.identity()?;
    if record.size != file_identity.size {
        return Err(ProviderError::new(
            "source.size_mismatch",
            "source.identity",
            None,
            false,
            "artifact size does not match the report",
        ));
    }
    let digest = hash_file(&source, file_identity, guard)?;
    if digest != record.digest {
        return Err(ProviderError::new(
            "source.hash_mismatch",
            "source.identity",
            None,
            false,
            "artifact SHA-256 does not match the report",
        ));
    }
    Ok((
        source,
        (
            record.local_path.clone(),
            file_identity,
            ProviderSourceIdentity {
                artifact: digest,
                format: String::new(),
                format_major: 0,
                format_minor: 0,
                source_bytes: file_identity.size,
            },
        ),
    ))
}

fn hash_file(
    source: &SecureFile,
    before: crate::FileIdentity,
    guard: &dyn WorkGuard,
) -> Result<ArtifactDigest, ProviderError> {
    const CHUNK_BYTES: usize = 64 * 1024;
    let mut hasher = Sha256::new();
    let mut offset = 0_u64;
    let mut buffer = [0_u8; CHUNK_BYTES];
    while offset < before.size {
        let count = usize::try_from((before.size - offset).min(CHUNK_BYTES as u64))
            .map_err(|_| resource_error("hash chunk length overflow"))?;
        guard.consume(WorkDelta {
            input_bytes: count as u64,
            ..WorkDelta::default()
        })?;
        source.read_exact_at_unchecked(offset, &mut buffer[..count])?;
        hasher.update(&buffer[..count]);
        offset = offset
            .checked_add(count as u64)
            .ok_or_else(|| resource_error("hash offset overflow"))?;
    }
    source.verify_unchanged(before, true)?;
    Ok(ArtifactDigest::new(hasher.finalize().into()))
}

fn open_provider(
    source: &SecureFile,
    format: ArtifactFormat,
    identity: ProviderSourceIdentity,
    mode: OpenMode,
    guard: &dyn WorkGuard,
) -> Result<Box<dyn TraceProvider>, ProviderError> {
    match format {
        ArtifactFormat::Qtrb => Ok(crate::allocation::try_box(
            QtrbProvider::open(
                source.source(identity.source_bytes, guard)?,
                ProviderSourceIdentity {
                    format: guarded_provider_string("QTRB", guard)?,
                    ..identity
                },
                mode,
                guard,
            )?,
            guard,
            "QTRB provider allocation",
        )
        .map_err(provider_allocation_error)?),
        ArtifactFormat::QtrbLz4 => {
            let decoded = QtrbInput::lz4(source.reader()).into_source(guard)?;
            Ok(crate::allocation::try_box(
                QtrbProvider::open(
                    decoded,
                    ProviderSourceIdentity {
                        format: guarded_provider_string("QTRB", guard)?,
                        ..identity
                    },
                    mode,
                    guard,
                )?,
                guard,
                "compressed QTRB provider allocation",
            )
            .map_err(provider_allocation_error)?)
        }
        ArtifactFormat::Flight => Ok(crate::allocation::try_box(
            FlightProvider::open(
                source.source(identity.source_bytes, guard)?,
                ProviderSourceIdentity {
                    format: guarded_provider_string("Flight", guard)?,
                    ..identity
                },
                guard,
            )?,
            guard,
            "Flight provider allocation",
        )
        .map_err(provider_allocation_error)?),
    }
}

fn probe_artifact_format(
    source: &SecureFile,
    guard: &dyn WorkGuard,
) -> Result<ArtifactFormat, ProviderError> {
    let identity = source.identity()?;
    if identity.size < 4 {
        return Err(format_error("binary source is shorter than its magic"));
    }
    guard.consume(WorkDelta {
        input_bytes: 4,
        nodes: 1,
        ..WorkDelta::default()
    })?;
    let mut magic = [0_u8; 4];
    source.read_exact_at_unchecked(0, &mut magic)?;
    match magic {
        [b'Q', b'T', b'R', b'B'] => Ok(ArtifactFormat::Qtrb),
        [0x04, 0x22, 0x4d, 0x18] => Ok(ArtifactFormat::QtrbLz4),
        [b'T', b'L', b'F', b'Q'] => Ok(ArtifactFormat::Flight),
        _ => Err(format_error("binary source magic is unsupported")),
    }
}

fn probe(
    provider: Box<dyn TraceProvider>,
    format: ArtifactFormat,
    guard: &dyn WorkGuard,
) -> Result<(), ProviderError> {
    let mut cursor: Box<dyn EventCursor> = provider.into_cursor()?;
    while cursor
        .next_event(guard)
        .map_err(|error| normalize_provider_error(format, error))?
        .is_some()
    {}
    let _ = cursor
        .finish()
        .map_err(|error| normalize_provider_error(format, error))?;
    Ok(())
}

fn normalize_provider_error(format: ArtifactFormat, error: ProviderError) -> ProviderError {
    if format.is_qtrb() && error.code() == "source.short_read" {
        ProviderError::new(
            "source.qtrb.truncated",
            error.stage(),
            error.source(),
            error.retryable(),
            error.detail(),
        )
    } else {
        error
    }
}

fn session_timelines(
    format: ArtifactFormat,
    timeline_id: TimelineId,
    timelines: &[TimelineDescriptor],
    guard: &dyn WorkGuard,
) -> Result<Vec<TimelineDescriptor>, ProviderError> {
    guard.consume(WorkDelta {
        nodes: timelines.len() as u64,
        ..WorkDelta::default()
    })?;
    let mut output = Vec::new();
    crate::allocation::try_reserve_vec(
        &mut output,
        timelines.len(),
        guard,
        "session timeline allocation",
    )
    .map_err(provider_allocation_error)?;
    for timeline in timelines {
        output.push(TimelineDescriptor {
            id: if format.is_qtrb() {
                timeline_id
            } else {
                timeline.id
            },
            tid: timeline.tid,
            label: timeline
                .label
                .as_deref()
                .map(|label| guarded_provider_string(label, guard))
                .transpose()?,
        });
    }
    Ok(output)
}

fn remap_qtrb_provider(
    inner: Box<dyn TraceProvider>,
    timeline_id: TimelineId,
    guard: &dyn WorkGuard,
) -> Result<Box<dyn TraceProvider>, ProviderError> {
    let identity = try_clone_provider_identity(inner.identity(), guard)?;
    let capabilities = inner.capabilities().clone();
    let timelines = session_timelines(ArtifactFormat::Qtrb, timeline_id, inner.timelines(), guard)?;
    Ok(crate::allocation::try_box(
        TimelineRemapProvider {
            inner,
            identity,
            capabilities,
            timelines,
            timeline_id,
        },
        guard,
        "timeline-remap provider allocation",
    )
    .map_err(provider_allocation_error)?)
}

fn guarded_provider_string(value: &str, guard: &dyn WorkGuard) -> Result<String, ProviderError> {
    crate::allocation::try_copy_string(value, guard, "provider identity string")
        .map_err(provider_allocation_error)
}

fn try_clone_provider_identity(
    identity: &ProviderSourceIdentity,
    guard: &dyn WorkGuard,
) -> Result<ProviderSourceIdentity, ProviderError> {
    Ok(ProviderSourceIdentity {
        artifact: identity.artifact,
        format: guarded_provider_string(&identity.format, guard)?,
        format_major: identity.format_major,
        format_minor: identity.format_minor,
        source_bytes: identity.source_bytes,
    })
}

fn provider_allocation_error(error: crate::allocation::AllocationFailure) -> ProviderError {
    match error {
        crate::allocation::AllocationFailure::Aborted(abort) => ProviderError::from(abort),
        crate::allocation::AllocationFailure::Overflow(detail)
        | crate::allocation::AllocationFailure::Failed(detail) => resource_error(detail),
    }
}

struct TimelineRemapProvider {
    inner: Box<dyn TraceProvider>,
    identity: ProviderSourceIdentity,
    capabilities: ProviderCapabilities,
    timelines: Vec<TimelineDescriptor>,
    timeline_id: TimelineId,
}

impl TraceProvider for TimelineRemapProvider {
    fn identity(&self) -> &ProviderSourceIdentity {
        &self.identity
    }

    fn capabilities(&self) -> &ProviderCapabilities {
        &self.capabilities
    }

    fn timelines(&self) -> &[TimelineDescriptor] {
        &self.timelines
    }

    fn cursor_resident_bytes(&self) -> Result<u64, ProviderError> {
        self.inner
            .cursor_resident_bytes()?
            .checked_add(size_of::<TimelineRemapCursor>() as u64)
            .ok_or_else(|| resource_error("timeline-remap cursor allocation bound overflow"))
    }

    fn into_cursor(self: Box<Self>) -> Result<Box<dyn EventCursor>, ProviderError> {
        let Self {
            inner, timeline_id, ..
        } = *self;
        Ok(Box::new(TimelineRemapCursor {
            inner: inner.into_cursor()?,
            timeline_id,
        }))
    }
}

struct TimelineRemapCursor {
    inner: Box<dyn EventCursor>,
    timeline_id: TimelineId,
}

impl EventCursor for TimelineRemapCursor {
    fn next_event(&mut self, guard: &dyn WorkGuard) -> Result<Option<EventRecord>, ProviderError> {
        let Some(mut event) = self.inner.next_event(guard)? else {
            return Ok(None);
        };
        event.key.timeline = self.timeline_id;
        Ok(Some(event))
    }

    fn finish(self: Box<Self>) -> Result<ProviderSummary, ProviderError> {
        let Self { inner, timeline_id } = *self;
        let mut summary = inner.finish()?;
        for timeline in &mut summary.timelines {
            timeline.id = timeline_id;
        }
        Ok(summary)
    }
}

struct IdentityCheckedProvider {
    inner: Box<dyn TraceProvider>,
    source: SecureFile,
    expected: crate::FileIdentity,
}

impl TraceProvider for IdentityCheckedProvider {
    fn identity(&self) -> &ProviderSourceIdentity {
        self.inner.identity()
    }

    fn capabilities(&self) -> &ProviderCapabilities {
        self.inner.capabilities()
    }

    fn timelines(&self) -> &[TimelineDescriptor] {
        self.inner.timelines()
    }

    fn cursor_resident_bytes(&self) -> Result<u64, ProviderError> {
        self.inner
            .cursor_resident_bytes()?
            .checked_add(size_of::<IdentityCheckedCursor>() as u64)
            .ok_or_else(|| resource_error("identity cursor allocation bound overflow"))
    }

    fn into_cursor(self: Box<Self>) -> Result<Box<dyn EventCursor>, ProviderError> {
        let Self {
            inner,
            source,
            expected,
        } = *self;
        Ok(Box::new(IdentityCheckedCursor {
            inner: inner.into_cursor()?,
            source,
            expected,
        }))
    }
}

struct IdentityCheckedCursor {
    inner: Box<dyn EventCursor>,
    source: SecureFile,
    expected: crate::FileIdentity,
}

impl EventCursor for IdentityCheckedCursor {
    fn next_event(&mut self, guard: &dyn WorkGuard) -> Result<Option<EventRecord>, ProviderError> {
        self.inner.next_event(guard)
    }

    fn finish(self: Box<Self>) -> Result<ProviderSummary, ProviderError> {
        let Self {
            inner,
            source,
            expected,
        } = *self;
        let summary = inner.finish()?;
        source.verify_unchanged(expected, true)?;
        Ok(summary)
    }
}

fn fallible_vec<T>(capacity: usize) -> Result<Vec<T>, ProviderError> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| resource_error("session allocation failed"))?;
    Ok(output)
}

fn format_error(detail: impl AsRef<str>) -> ProviderError {
    ProviderError::new(
        "source.format_unsupported",
        "source.probe",
        None,
        false,
        detail,
    )
}

fn is_session_fatal(error: &ProviderError) -> bool {
    error.code() == "session.path_escape" || error.code().starts_with("control.")
}

fn resource_error(detail: impl AsRef<str>) -> ProviderError {
    ProviderError::new("control.budget_exceeded", "control", None, false, detail)
}

#[cfg(test)]
mod tests {
    use qtrace_provider::ProviderError;

    use super::is_session_fatal;

    #[test]
    fn every_control_error_is_session_fatal_but_ordinary_source_errors_are_not() {
        for code in [
            "control.cancelled",
            "control.budget_exceeded",
            "control.resource_exhausted",
            "control.future_global_abort",
        ] {
            assert!(is_session_fatal(&ProviderError::new(
                code, "control", None, false, "test"
            )));
        }
        assert!(!is_session_fatal(&ProviderError::new(
            "source.io",
            "source.open",
            None,
            false,
            "test"
        )));
    }
}
