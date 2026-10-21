//! Measures production service open, paged filters and joined cancellation.
use qtrace_service::{
    AddressRangeDto, DecimalU64Dto, EventFilterDto, HexU64Dto, JobState, OpenStageDto,
    QtraceService, SequenceRangeDto,
};
use qtrace_store::AuthorizedPath;
use serde_json::json;
use std::{
    env,
    error::Error,
    path::PathBuf,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

fn main() -> Result<(), Box<dyn Error>> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 3 {
        return Err("usage: flight_query_bench INPUT CACHE open|cancel|cancel-index".into());
    }
    let input = PathBuf::from(&arguments[0]).canonicalize()?;
    let service = Arc::new(QtraceService::with_cache_root(PathBuf::from(&arguments[1])));
    let started = Instant::now();
    if arguments[2] == "cancel" || arguments[2] == "cancel-index" {
        let worker_service = service.clone();
        let worker = thread::spawn(move || {
            worker_service
                .open_artifact(AuthorizedPath::new(input))
                .map_err(Box::new)
        });
        let job = loop {
            if let Some(job) = service.list_jobs().into_iter().find(|job| {
                job.state == JobState::Running
                    && (arguments[2] != "cancel-index"
                        || job.progress.detail.as_ref().is_some_and(|detail| {
                            detail.stage == OpenStageDto::BuildIndex
                                && detail.processed_events.value() > 0
                        }))
            }) {
                break job;
            }
            if worker.is_finished() || started.elapsed() > Duration::from_secs(10) {
                service.cancel_all();
                let _ = worker.join();
                return Err("open completed or failed before cancellation was observable".into());
            }
            thread::sleep(Duration::from_millis(1));
        };
        let cancelled = Instant::now();
        service.cancel_job(&job.id).map_err(|error| error.detail)?;
        let result = worker.join().map_err(|_| "open worker panicked")?;
        let error = result.err().ok_or("cancelled open published a workspace")?;
        let final_job = service
            .list_jobs()
            .into_iter()
            .find(|item| item.id == job.id)
            .unwrap();
        eprintln!(
            "{}",
            json!({"cancel_result":error, "job_state":final_job.state})
        );
        assert_eq!(final_job.state, JobState::Cancelled);
        assert_eq!(error.code, "job.cancelled");
        println!(
            "{}",
            json!({"result":"cancelled", "seconds":started.elapsed().as_secs_f64(),
            "cancellation_seconds":cancelled.elapsed().as_secs_f64(), "worker_joined":true,
            "cancel_requested_during":job.progress.detail,
            "job":final_job, "error":error.code})
        );
        return Ok(());
    }
    let opened = service
        .open_artifact(AuthorizedPath::new(input))
        .map_err(|error| {
            eprintln!("{}", json!({"failed_open_jobs": service.list_jobs()}));
            format!("{}: {}", error.code, error.detail)
        })?;
    let open_seconds = started.elapsed().as_secs_f64();
    let mut queries = Vec::new();
    let filters = [
        (
            "instructions",
            EventFilterDto {
                kinds: vec!["instruction".into()],
                ..Default::default()
            },
        ),
        (
            "calls",
            EventFilterDto {
                kinds: vec!["semantic_call".into()],
                ..Default::default()
            },
        ),
        (
            "address",
            EventFilterDto {
                kinds: vec!["instruction".into()],
                absolute_pc: vec![AddressRangeDto {
                    start: HexU64Dto::new(0x71000088),
                    end_exclusive: HexU64Dto::new(0x710000a8),
                }],
                ..Default::default()
            },
        ),
        (
            "sequence",
            EventFilterDto {
                sequence: vec![SequenceRangeDto {
                    first: DecimalU64Dto::new(100),
                    last: DecimalU64Dto::new(1000),
                }],
                ..Default::default()
            },
        ),
    ];
    for (name, filter) in filters {
        let started = Instant::now();
        let projection = service
            .create_projection(&opened.workspace.id, 0, filter)
            .map_err(|error| format!("{}: {}", error.code, error.detail))?;
        let mut cursor = None;
        let (mut count, mut pages, mut bytes, mut maximum_rows) = (0usize, 0usize, 0usize, 0usize);
        loop {
            let page = service
                .query_timeline(
                    &opened.workspace.id,
                    &projection.projection_id,
                    cursor,
                    2000,
                )
                .map_err(|error| error.detail)?;
            assert!(page.rows.len() <= 2000);
            if name == "instructions" || name == "address" {
                assert!(page.rows.iter().all(|row| row.kind == "instruction"));
            }
            if name == "calls" {
                assert!(page.rows.iter().all(|row| row.kind == "semantic_call"));
            }
            if name == "sequence" {
                assert!(page.rows.iter().all(|row| {
                    row.key
                        .sequence
                        .as_ref()
                        .is_some_and(|value| (100..=1000).contains(&value.value()))
                }));
            }
            maximum_rows = maximum_rows.max(page.rows.len());
            count += page.rows.len();
            pages += 1;
            bytes = bytes.max(serde_json::to_vec(&page)?.len());
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        assert!(count > 0);
        queries.push(
            json!({"filter":name,"rows":count,"pages":pages,"max_page_rows":maximum_rows,
                           "max_page_json_bytes":bytes,"seconds":started.elapsed().as_secs_f64()}),
        );
    }
    service
        .close_workspace(&opened.workspace.id)
        .map_err(|error| error.detail)?;
    println!(
        "{}",
        json!({"open_seconds":open_seconds,"opened":opened,"queries":queries,"workspace_closed":true,
        "time_model":"sequence ranges; wall-clock timestamps are not present on instruction events"})
    );
    Ok(())
}
