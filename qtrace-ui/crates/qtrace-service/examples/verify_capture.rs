//! Opt-in verification of a published device session through the desktop service.

use std::{
    collections::BTreeMap,
    error::Error,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use qtrace_provider::{EventKey, EventKind, EventPayload, ProviderSummary};
use qtrace_service::{
    AppError, ArtifactSummaryDto, CallTreePageQuery, EventFilterDto, EventKeyDto, OpenWorkspaceDto,
    QtraceService, ServiceBudget, ServiceLimits,
};
use qtrace_store::{
    AuthorizedPath, BuildOptions, OpenPolicy, SessionLoader, SessionSource, TraceStore,
    TraceStoreView,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
#[cfg(not(test))]
const PAGE_SIZE: u32 = 2_000;
#[cfg(test)]
const PAGE_SIZE: u32 = 2;

#[derive(Debug, PartialEq, Serialize)]
struct ArtifactEvidence {
    artifact: ArtifactSummaryDto,
    sha256: String,
    file_bytes: u64,
    provider_bytes: u64,
    event_counts: BTreeMap<String, u64>,
    timeline_sha256: String,
    analysis_sha256: String,
    provider_summary: ProviderSummary,
}

#[derive(Debug, Serialize)]
struct CaptureEvidence {
    schema: u32,
    workspace: OpenWorkspaceDto,
    artifacts: Vec<ArtifactEvidence>,
    cold_open_seconds: f64,
    warm_open_seconds: f64,
    reopen_equivalent: bool,
}

#[track_caller]
fn app<T>(result: std::result::Result<T, AppError>) -> Result<T> {
    let caller = std::panic::Location::caller();
    result.map_err(|error| {
        format!(
            "{} at {} ({}:{}): {}",
            error.code,
            error.stage,
            caller.file(),
            caller.line(),
            error.detail
        )
        .into()
    })
}

fn require(condition: bool, detail: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(detail.into())
    }
}

fn key_matches(actual: &EventKeyDto, expected: &EventKey) -> bool {
    actual.artifact_sha256 == expected.artifact.to_hex()
        && actual.timeline_id.value() == expected.timeline.0
        && actual.record_ordinal.value() == expected.record_ordinal
        && actual.source_offset.value() == expected.source_offset
        && actual.sequence.as_ref().map(|value| value.value()) == expected.sequence
        && actual.tid == expected.tid
}

fn provider_budget() -> ServiceBudget {
    ServiceBudget::new(ServiceLimits {
        deadline: Instant::now() + Duration::from_secs(300),
        input_bytes: 2 * 1024 * 1024 * 1024,
        decompressed_bytes: 16 * 1024 * 1024 * 1024,
        events: 10_000_000,
        nodes: 10_000_000,
        rows: 10_000_000,
        resident_bytes: 2 * 1024 * 1024 * 1024,
    })
}

fn verify_workspace(
    service: &QtraceService,
    opened: &OpenWorkspaceDto,
    source: &SessionSource,
    cache: &Path,
) -> Result<Vec<ArtifactEvidence>> {
    require(
        opened.artifacts.len() == source.artifacts().len(),
        "desktop service omitted a capture artifact",
    )?;
    let workspace = &opened.workspace.id;
    let mut artifacts = Vec::new();
    for (artifact, source) in opened.artifacts.iter().zip(source.artifacts()) {
        require(
            artifact.name == source.local_path(),
            "artifact order changed",
        )?;
        let budget = provider_budget();
        let store =
            TraceStore::open_or_build(cache, source, &BuildOptions::default(), &provider_budget())?;
        require(
            store.event_count() <= 10_000_000,
            "capture exceeds verification event budget",
        )?;
        let mut provider = source.open_provider(&budget)?.into_cursor()?;
        let mut event_counts = BTreeMap::new();
        for index in 0..store.event_count() {
            let event = provider
                .next_event(&budget)?
                .ok_or("index has extra events")?;
            require(
                store.event_key(index)?.as_ref() == Some(&event.key)
                    && store.event_kind(index)? == Some(event.kind())
                    && store.provenance(index)? == Some(event.provenance)
                    && serde_json::from_slice::<EventPayload>(store.payload_bytes(index)?)?
                        == event.payload,
                "indexed event facts differ from provider",
            )?;
            let kind = serde_json::from_value::<String>(serde_json::to_value(event.kind())?)?;
            *event_counts.entry(kind).or_insert(0) += 1;
        }
        require(
            provider.next_event(&budget)?.is_none(),
            "index omitted provider events",
        )?;
        let summary = provider.finish()?;
        let mut visited = vec![0_u8; store.event_count().div_ceil(8)];
        let projection =
            app(service.create_projection(workspace, artifact.index, EventFilterDto::default()))?;
        let mut cursor = None;
        let mut count = 0_u32;
        let mut digest = Sha256::new();
        let mut first_instruction = None;
        let mut last_instruction = None;
        let mut first_memory = None;
        loop {
            let page = app(service.query_timeline(
                workspace,
                &projection.projection_id,
                cursor.clone(),
                PAGE_SIZE,
            ))?;
            require(
                page.exact_total && page.total == artifact.event_count,
                "timeline total differs from artifact count",
            )?;
            require(
                page.rows.len() <= PAGE_SIZE as usize,
                "timeline page exceeds limit",
            )?;
            require(
                !page.rows.is_empty() || page.next_cursor.is_none(),
                "empty timeline page has a continuation",
            )?;
            for row in &page.rows {
                let index = row.source_row as usize;
                let expected = store
                    .event_key(index)?
                    .ok_or("timeline source row is absent")?;
                let kind = store
                    .event_kind(index)?
                    .ok_or("indexed event kind is absent")?;
                let provenance = store
                    .provenance(index)?
                    .ok_or("indexed event provenance is absent")?;
                let bit = 1_u8 << (index % 8);
                require(
                    visited[index / 8] & bit == 0 && key_matches(&row.key, &expected),
                    "timeline event identity differs from provider or repeats a row",
                )?;
                visited[index / 8] |= bit;
                require(
                    serde_json::to_value(kind)? == row.kind
                        && serde_json::to_value(provenance)? == row.provenance,
                    "timeline kind/provenance differs from provider",
                )?;
                digest.update(serde_json::to_vec(row)?);
                digest.update(b"\n");
                if kind == EventKind::Instruction {
                    first_instruction.get_or_insert(row.source_row);
                    last_instruction = Some(row.source_row);
                }
                if kind == EventKind::Memory {
                    first_memory.get_or_insert(row.source_row);
                }
                count = count.checked_add(1).ok_or("event count exceeds u32")?;
            }
            match page.next_cursor {
                Some(next) => {
                    require(
                        count < artifact.event_count && cursor.as_ref() != Some(&next),
                        "timeline cursor does not advance",
                    )?;
                    cursor = Some(next);
                }
                None => break,
            }
        }
        require(
            count == artifact.event_count && count as usize == store.event_count(),
            "timeline omitted provider events",
        )?;
        require(count > 0, "capture artifact has no events")?;

        let instructions = event_counts.get("instruction").copied().unwrap_or_default();
        let filtered = app(service.create_projection(
            workspace,
            artifact.index,
            EventFilterDto {
                kinds: vec!["instruction".into()],
                ..EventFilterDto::default()
            },
        ))?;
        let page =
            app(service.query_timeline(workspace, &filtered.projection_id, None, PAGE_SIZE))?;
        require(
            page.exact_total
                && u64::from(page.total) == instructions
                && page.rows.iter().all(|row| row.kind == "instruction"),
            "instruction filter differs from provider count",
        )?;

        let mut analysis = Sha256::new();
        for row in [first_instruction, last_instruction].into_iter().flatten() {
            let detail = app(service.get_event_detail(workspace, artifact.index, row))?;
            let state = app(service.get_register_state(workspace, artifact.index, row))?;
            require(
                detail.key == state.key && state.before.len() == 34 && state.after.len() == 34,
                "register sample identity/shape changed",
            )?;
            analysis.update(serde_json::to_vec(&(detail, state))?);
        }
        if let Some(row) = first_instruction {
            let detail = app(service.get_event_detail(workspace, artifact.index, row))?;
            if let Some(tid) = detail.key.tid {
                let tree = app(service.get_call_tree(
                    workspace,
                    artifact.index,
                    detail.key.timeline_id.value(),
                    tid,
                    CallTreePageQuery::default(),
                ))?;
                require(tree.nodes.len() <= 100, "call tree page exceeds limit")?;
                analysis.update(serde_json::to_vec(&tree)?);
            }
        }
        if let Some(row) = first_memory {
            let detail = app(service.get_event_detail(workspace, artifact.index, row))?;
            if let Some(range) = detail.memory_range {
                let start = range.start.value();
                let end = range.end_exclusive.value().min(start.saturating_add(64));
                let state =
                    app(service.get_memory_state(workspace, artifact.index, row, start, end))?;
                require(state.key == detail.key, "memory sample identity changed")?;
                analysis.update(serde_json::to_vec(&state)?);
            }
        }
        artifacts.push(ArtifactEvidence {
            artifact: artifact.clone(),
            sha256: source.identity().provider().artifact.to_hex(),
            file_bytes: source.identity().file().size,
            provider_bytes: source.identity().provider().source_bytes,
            event_counts,
            timeline_sha256: format!("{:x}", digest.finalize()),
            analysis_sha256: format!("{:x}", analysis.finalize()),
            provider_summary: summary,
        });
    }
    Ok(artifacts)
}

fn verify_capture(report: &Path, cache: &Path) -> Result<CaptureEvidence> {
    if cache.exists() {
        require(
            cache.read_dir()?.next().is_none(),
            "verification cache must be empty",
        )?;
    }
    // The same loader enforces report hashes and path confinement as the desktop app.
    let source = SessionLoader::open_report(
        AuthorizedPath::new(report.to_path_buf()),
        OpenPolicy::cache_aware(),
        &provider_budget(),
    )?;
    if let Some(failure) = source.failures().first() {
        return Err(format!("capture artifact rejected: {}", failure.error()).into());
    }
    require(
        !source.artifacts().is_empty(),
        "session has no analysis artifacts",
    )?;
    let service = QtraceService::with_cache_root(cache.to_path_buf());
    let started = Instant::now();
    let opened = app(service.open_session(AuthorizedPath::new(report.to_path_buf())))?;
    let cold_open_seconds = started.elapsed().as_secs_f64();
    let artifacts = verify_workspace(&service, &opened, &source, cache)?;
    app(service.close_workspace(&opened.workspace.id))?;
    drop(service);

    let restarted = QtraceService::with_cache_root(cache.to_path_buf());
    let started = Instant::now();
    let reopened = app(restarted.open_session(AuthorizedPath::new(report.to_path_buf())))?;
    let warm_open_seconds = started.elapsed().as_secs_f64();
    let warm_artifacts = verify_workspace(&restarted, &reopened, &source, cache)?;
    require(
        opened.context == reopened.context
            && opened.warnings == reopened.warnings
            && opened.missing_capabilities == reopened.missing_capabilities
            && artifacts == warm_artifacts,
        "cached reopen changes capture facts or analysis",
    )?;
    app(restarted.close_workspace(&reopened.workspace.id))?;
    Ok(CaptureEvidence {
        schema: 1,
        workspace: opened,
        artifacts,
        cold_open_seconds,
        warm_open_seconds,
        reopen_equivalent: true,
    })
}

fn arguments(arguments: impl Iterator<Item = String>) -> Result<(PathBuf, PathBuf)> {
    let mut arguments = arguments;
    let mut report = None;
    let mut cache = None;
    while let Some(flag) = arguments.next() {
        let slot = match flag.as_str() {
            "--report" => &mut report,
            "--cache" => &mut cache,
            _ => return Err(format!("unknown argument: {flag}").into()),
        };
        require(slot.is_none(), "duplicate argument")?;
        *slot = Some(PathBuf::from(
            arguments.next().ok_or("missing argument value")?,
        ));
    }
    Ok((
        report.ok_or("--report is required")?,
        cache.ok_or("--cache is required")?,
    ))
}

fn main() -> Result<()> {
    let (report, cache) = arguments(std::env::args().skip(1))?;
    let evidence = verify_capture(&report, &cache)?;
    println!("{}", serde_json::to_string_pretty(&evidence)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("fixtures/sessions")
            .join(name)
    }

    #[test]
    fn mixed_session_keeps_provider_facts_and_cached_analysis() {
        let cache = tempfile::tempdir().unwrap();
        let evidence = verify_capture(
            &fixture("valid-mixed").join("report.json"),
            &cache.path().join("indexes"),
        )
        .unwrap();
        assert_eq!(evidence.artifacts.len(), 3);
        assert!(evidence.reopen_equivalent);
        assert!(
            evidence
                .artifacts
                .iter()
                .all(|artifact| artifact.event_counts["instruction"] > 0)
        );
        assert!(
            evidence
                .artifacts
                .iter()
                .any(|artifact| !artifact.provider_summary.completeness.is_empty())
        );
    }

    #[test]
    fn healthy_artifacts_cannot_hide_a_rejected_artifact() {
        let cache = tempfile::tempdir().unwrap();
        let error = verify_capture(
            &fixture("one-invalid-artifact"),
            &cache.path().join("indexes"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("omitted a capture artifact"));
    }

    #[test]
    fn report_paths_remain_confined() {
        let cache = tempfile::tempdir().unwrap();
        assert!(verify_capture(&fixture("path-escape"), &cache.path().join("indexes")).is_err());
    }
}
