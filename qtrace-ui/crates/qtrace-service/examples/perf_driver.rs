//! Machine-readable production-path driver for the qtrace-ui performance gate.

use std::{
    env,
    error::Error,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use qtrace_analysis::{
    CallTreeAnalyzer, CallTreeOptions, EventFilter, QueryContext, RegisterReplay,
    TimelineProjection, query_events,
};
use qtrace_provider::{EventKind, OperationAbort, WorkDelta, WorkGuard};
use qtrace_service::{CallTreePageQuery, EventFilterDto, QtraceService};
use qtrace_store::{
    AuthorizedPath, BuildOptions, CompletenessRow, OpenPolicy, SessionLoader, TraceStore,
    TraceStoreView,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const EXPECTED_QTRB_EVENTS: usize = 10_000_000;
const EXPECTED_FLIGHT_BYTES: u64 = 512 * 1024 * 1024;
const EXPECTED_FLIGHT_EVENTS: usize = 68;
const QUERY_COUNT: usize = 200;

#[derive(Deserialize)]
struct Manifest {
    corpora: Corpora,
    correctness_digest: String,
    expected_flight_completeness: Vec<CompletenessRow>,
}

#[derive(Deserialize)]
struct Corpora {
    qtrb: Corpus,
    flight: Corpus,
}

#[derive(Deserialize)]
struct Corpus {
    path: String,
    bytes: u64,
    sha256: String,
    events: u64,
}

#[derive(Serialize)]
struct OpenOutput {
    correctness_digest: String,
    qtrb_events: usize,
    flight_events: usize,
    mapped: bool,
    flight_completeness: Vec<CompletenessRow>,
}

#[derive(Serialize)]
struct WorkloadOutput {
    viewport_seconds: Vec<f64>,
    structured_search_seconds: Vec<f64>,
    correctness_digest: String,
}

struct Opened {
    qtrb: Arc<TraceStore>,
    flight: Arc<TraceStore>,
    digest: String,
}

#[derive(Deserialize)]
struct RichManifest {
    corpora: RichCorpora,
    semantic_oracle: RichOracle,
}

#[derive(Deserialize)]
struct RichCorpora {
    raw: Corpus,
    compressed: Corpus,
}

#[derive(Deserialize)]
struct RichOracle {
    events: usize,
    instructions: usize,
    memory_events: usize,
    semantic_events: usize,
    call_frames: usize,
}

#[derive(Serialize)]
struct RichOutput {
    raw_cold_seconds: f64,
    raw_warm_seconds: f64,
    compressed_cold_seconds: f64,
    query_seconds: Vec<f64>,
    replay_build_seconds: f64,
    replay_query_seconds: Vec<f64>,
    call_tree_seconds: f64,
    event_counts: [usize; 4],
    call_frames: usize,
    ipc_query_seconds: f64,
    ipc_page_bytes: usize,
    ipc_call_tree_seconds: f64,
    ipc_call_tree_bytes: usize,
}

struct AllowAll;

impl WorkGuard for AllowAll {
    fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
        Ok(())
    }

    fn parallelism(&self) -> usize {
        2
    }
}

fn argument(arguments: &[String], name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let index = arguments
        .iter()
        .position(|value| value == name)
        .ok_or_else(|| format!("missing {name}"))?;
    Ok(PathBuf::from(
        arguments
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {name}"))?,
    ))
}

fn load_manifest(path: &Path) -> Result<Manifest, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    let manifest: Manifest = serde_json::from_slice(&bytes)?;
    Ok(manifest)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn source_path(manifest_path: &Path, corpus: &Corpus) -> Result<PathBuf, Box<dyn Error>> {
    let parent = manifest_path
        .parent()
        .ok_or("benchmark manifest has no parent")?;
    let path = parent.join(&corpus.path);
    let metadata = fs::symlink_metadata(&path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("benchmark corpus must be a regular non-symlink file".into());
    }
    if metadata.len() != corpus.bytes {
        return Err(format!("corpus identity mismatch: {}", corpus.path).into());
    }
    Ok(path)
}

fn open_store(source_path: PathBuf, cache: &Path) -> Result<TraceStore, Box<dyn Error>> {
    let session = SessionLoader::open_artifact(
        AuthorizedPath::new(source_path),
        OpenPolicy::cache_aware(),
        &AllowAll,
    )?;
    let source = session
        .artifacts()
        .first()
        .ok_or("provider returned no artifact")?;
    Ok(TraceStore::open_or_build(
        cache,
        source,
        &BuildOptions::default(),
        &AllowAll,
    )?)
}

fn correctness_digest(manifest: &Manifest, qtrb_events: usize, flight_events: usize) -> String {
    let mut digest = Sha256::new();
    digest.update(b"qtrace-ui/performance-correctness/v1\0");
    digest.update(manifest.corpora.qtrb.sha256.as_bytes());
    digest.update([0]);
    digest.update(manifest.corpora.flight.sha256.as_bytes());
    digest.update([0]);
    digest.update((qtrb_events as u64).to_le_bytes());
    digest.update((flight_events as u64).to_le_bytes());
    hex(&digest.finalize())
}

fn open_all(manifest_path: &Path, cache: &Path) -> Result<Opened, Box<dyn Error>> {
    let manifest = load_manifest(manifest_path)?;
    if manifest.corpora.qtrb.events != EXPECTED_QTRB_EVENTS as u64
        || manifest.corpora.flight.bytes != EXPECTED_FLIGHT_BYTES
    {
        return Err("benchmark corpus dimensions are not canonical".into());
    }
    let qtrb_path = source_path(manifest_path, &manifest.corpora.qtrb)?;
    let flight_path = source_path(manifest_path, &manifest.corpora.flight)?;
    let (qtrb, flight) = std::thread::scope(|scope| -> Result<_, Box<dyn Error>> {
        let qtrb_worker = scope.spawn(|| open_store(qtrb_path, cache).map_err(|e| e.to_string()));
        let flight = Arc::new(open_store(flight_path, cache)?);
        let qtrb = Arc::new(
            qtrb_worker
                .join()
                .map_err(|_| "QTRB open worker panicked")?
                .map_err(|error| format!("QTRB open failed: {error}"))?,
        );
        Ok((qtrb, flight))
    })?;
    verify_store_digest(&qtrb, &manifest.corpora.qtrb)?;
    verify_store_digest(&flight, &manifest.corpora.flight)?;
    if qtrb.event_count() != EXPECTED_QTRB_EVENTS {
        return Err(format!("QTRB provider produced {} events", qtrb.event_count()).into());
    }
    if flight.event_count() != EXPECTED_FLIGHT_EVENTS
        || flight.event_count() != manifest.corpora.flight.events as usize
    {
        return Err(format!("Flight provider produced {} events", flight.event_count()).into());
    }
    if flight.completeness() != manifest.expected_flight_completeness {
        return Err("Flight completeness oracle mismatch".into());
    }
    let digest = correctness_digest(&manifest, qtrb.event_count(), flight.event_count());
    if digest != manifest.correctness_digest {
        return Err("correctness digest mismatch".into());
    }
    Ok(Opened {
        qtrb,
        flight,
        digest,
    })
}

fn verify_store_digest(store: &TraceStore, corpus: &Corpus) -> Result<(), Box<dyn Error>> {
    let digest = store
        .event_key(0)?
        .ok_or("provider returned no events")?
        .artifact
        .to_hex();
    if digest != corpus.sha256 {
        return Err(format!("corpus identity mismatch: {}", corpus.path).into());
    }
    Ok(())
}

fn open_mode(manifest_path: &Path, cache: &Path) -> Result<(), Box<dyn Error>> {
    let opened = open_all(manifest_path, cache)?;
    println!(
        "{}",
        serde_json::to_string(&OpenOutput {
            correctness_digest: opened.digest,
            qtrb_events: opened.qtrb.event_count(),
            flight_events: opened.flight.event_count(),
            mapped: opened.qtrb.is_mapped() && opened.flight.is_mapped(),
            flight_completeness: opened.flight.completeness().to_vec(),
        })?
    );
    Ok(())
}

fn timed_pages(projection: &TimelineProjection) -> Result<Vec<f64>, Box<dyn Error>> {
    let mut samples = Vec::with_capacity(QUERY_COUNT);
    let mut cursor = None;
    for _ in 0..QUERY_COUNT {
        let started = Instant::now();
        let page = query_events(projection, cursor.as_ref(), 2_000)?;
        samples.push(started.elapsed().as_secs_f64());
        cursor = page.next;
        if cursor.is_none() {
            cursor = None;
        }
    }
    Ok(samples)
}

fn workload_mode(manifest_path: &Path, cache: &Path) -> Result<(), Box<dyn Error>> {
    let opened = open_all(manifest_path, cache)?;
    let context = Arc::new(QueryContext::new(opened.qtrb)?);
    let viewport = TimelineProjection::new(context.clone(), EventFilter::default())?;
    let viewport_seconds = timed_pages(&viewport)?;
    let structured = TimelineProjection::new(
        context,
        EventFilter {
            kinds: vec![EventKind::Memory],
            ..EventFilter::default()
        },
    )?;
    let structured_search_seconds = timed_pages(&structured)?;
    println!(
        "{}",
        serde_json::to_string(&WorkloadOutput {
            viewport_seconds,
            structured_search_seconds,
            correctness_digest: opened.digest,
        })?
    );
    Ok(())
}

fn rich_mode(manifest_path: &Path, cache: &Path) -> Result<(), Box<dyn Error>> {
    let manifest: RichManifest = serde_json::from_slice(&fs::read(manifest_path)?)?;
    let raw_path = source_path(manifest_path, &manifest.corpora.raw)?;
    let compressed_path = source_path(manifest_path, &manifest.corpora.compressed)?;
    let started = Instant::now();
    let raw = Arc::new(open_store(raw_path.clone(), cache)?);
    let raw_cold_seconds = started.elapsed().as_secs_f64();
    let started = Instant::now();
    let warm = open_store(raw_path.clone(), cache)?;
    let raw_warm_seconds = started.elapsed().as_secs_f64();
    if !warm.is_mapped() {
        return Err("rich warm open did not map the cache".into());
    }
    let started = Instant::now();
    let compressed = open_store(compressed_path, cache)?;
    let compressed_cold_seconds = started.elapsed().as_secs_f64();
    verify_store_digest(&raw, &manifest.corpora.raw)?;
    verify_store_digest(&compressed, &manifest.corpora.compressed)?;
    let mut counts = [0usize; 4];
    for row in 0..raw.event_count() {
        match raw.event_kind(row)? {
            Some(EventKind::Instruction) => counts[0] += 1,
            Some(EventKind::Memory) => counts[1] += 1,
            Some(EventKind::SemanticCall) => counts[2] += 1,
            _ => counts[3] += 1,
        }
    }
    if raw.event_count() != manifest.semantic_oracle.events
        || compressed.event_count() != raw.event_count()
        || counts[0] != manifest.semantic_oracle.instructions
        || counts[1] != manifest.semantic_oracle.memory_events
        || counts[2] != manifest.semantic_oracle.semantic_events
    {
        return Err(format!("rich semantic oracle mismatch: {counts:?}").into());
    }
    let context = Arc::new(QueryContext::new(raw.clone())?);
    let projection = TimelineProjection::new(context, EventFilter::default())?;
    let query_seconds = timed_pages(&projection)?;
    let started = Instant::now();
    let replay = RegisterReplay::new(raw.clone())?;
    let replay_build_seconds = started.elapsed().as_secs_f64();
    let mut replay_query_seconds = Vec::with_capacity(50);
    for row in (10..raw.event_count())
        .step_by(raw.event_count() / 50)
        .take(50)
    {
        let key = raw.event_key(row)?.ok_or("missing rich event key")?;
        let started = Instant::now();
        replay.state_at(&key)?;
        replay_query_seconds.push(started.elapsed().as_secs_f64());
    }
    let first_instruction = raw.event_key(5)?.ok_or("missing first instruction")?;
    let started = Instant::now();
    let tree = CallTreeAnalyzer::new(raw).build(
        first_instruction.timeline.0,
        first_instruction.tid.ok_or("missing rich thread id")?,
        &CallTreeOptions::default(),
    )?;
    let call_tree_seconds = started.elapsed().as_secs_f64();
    if tree.nodes.len() != manifest.semantic_oracle.call_frames {
        return Err(format!("rich call tree has {} frames", tree.nodes.len()).into());
    }
    let service = QtraceService::with_cache_root(cache.join("service"));
    let opened = service
        .open_artifact(AuthorizedPath::new(raw_path))
        .map_err(|error| format!("{}: {}", error.code, error.detail))?;
    let workspace = opened.workspace.id;
    let projection = service
        .create_projection(&workspace, 0, EventFilterDto::default())
        .map_err(|error| format!("{}: {}", error.code, error.detail))?;
    let started = Instant::now();
    let page = service
        .query_timeline(&workspace, &projection.projection_id, None, 2_000)
        .map_err(|error| format!("{}: {}", error.code, error.detail))?;
    let ipc_query_seconds = started.elapsed().as_secs_f64();
    let ipc_page_bytes = serde_json::to_vec(&page)?.len();
    let started = Instant::now();
    let tree_page = service
        .get_call_tree(
            &workspace,
            0,
            first_instruction.timeline.0,
            first_instruction.tid.ok_or("missing rich thread id")?,
            CallTreePageQuery::default(),
        )
        .map_err(|error| format!("{}: {}", error.code, error.detail))?;
    let ipc_call_tree_seconds = started.elapsed().as_secs_f64();
    let ipc_call_tree_bytes = serde_json::to_vec(&tree_page)?.len();
    println!(
        "{}",
        serde_json::to_string(&RichOutput {
            raw_cold_seconds,
            raw_warm_seconds,
            compressed_cold_seconds,
            query_seconds,
            replay_build_seconds,
            replay_query_seconds,
            call_tree_seconds,
            event_counts: counts,
            call_frames: tree.nodes.len(),
            ipc_query_seconds,
            ipc_page_bytes,
            ipc_call_tree_seconds,
            ipc_call_tree_bytes,
        })?
    );
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let mode = arguments.first().ok_or("missing mode")?.as_str();
    match mode {
        "index" | "open" | "verify" => {
            let manifest = argument(&arguments, "--input")?;
            let cache = argument(&arguments, "--cache")?;
            open_mode(&manifest, &cache)
        }
        "workload" => {
            let cache = argument(&arguments, "--workspace")?;
            let manifest = argument(&arguments, "--queries")?;
            workload_mode(&manifest, &cache)
        }
        "rich" => {
            let manifest = argument(&arguments, "--input")?;
            let cache = argument(&arguments, "--cache")?;
            rich_mode(&manifest, &cache)
        }
        _ => Err(format!("unknown mode: {mode}").into()),
    }
}
