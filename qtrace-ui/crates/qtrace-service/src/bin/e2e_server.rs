#![allow(clippy::result_large_err)]

use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::Duration,
};

use qtrace_service::*;
use qtrace_store::AuthorizedPath;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

const MAX_REQUEST: u64 = 1024 * 1024;
const MAX_CONCURRENCY: usize = 8;
const REQUEST_DEADLINE: Duration = Duration::from_secs(30);

#[derive(Clone)]
struct State {
    service: Arc<Mutex<Arc<QtraceService>>>,
    runtime: Arc<tokio::runtime::Runtime>,
    fixture_root: PathBuf,
    data_root: PathBuf,
    token: String,
}

fn main() {
    let fixture_root = required_arg("--fixture-root");
    let data_root = required_arg("--xdg-root");
    let token = required_arg("--token");
    if token.len() != 32 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        fail("--token must be a random 128-bit hexadecimal value");
    }
    let fixture_root = PathBuf::from(fixture_root)
        .canonicalize()
        .unwrap_or_else(|_| fail("fixture root is invalid"));
    let data_root = PathBuf::from(data_root);
    std::fs::create_dir_all(&data_root).unwrap_or_else(|_| fail("XDG root is invalid"));
    let server =
        Server::http("127.0.0.1:0").unwrap_or_else(|_| fail("cannot bind loopback server"));
    let address = server
        .server_addr()
        .to_ip()
        .unwrap_or_else(|| fail("server is not on IP loopback"));
    println!(
        "{}",
        json!({ "url": format!("http://{address}"), "token": token })
    );
    let cache_root = data_root.join("cache/indexes");
    let runtime = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|_| fail("cannot create E2E runtime")),
    );
    let state = Arc::new(State {
        service: Arc::new(Mutex::new(Arc::new(QtraceService::with_cache_root(
            cache_root,
        )))),
        runtime,
        fixture_root,
        data_root,
        token,
    });
    let (sender, receiver) = mpsc::sync_channel::<Request>(MAX_CONCURRENCY);
    let receiver = Arc::new(Mutex::new(receiver));
    for index in 0..MAX_CONCURRENCY {
        let receiver = receiver.clone();
        let state = state.clone();
        thread::Builder::new()
            .name(format!("qtrace-e2e-{index}"))
            .spawn(move || worker(receiver, state))
            .unwrap_or_else(|_| fail("cannot start loopback worker"));
    }
    for request in server.incoming_requests() {
        if sender.send(request).is_err() {
            fail("loopback workers stopped");
        }
    }
}

fn worker(receiver: Arc<Mutex<mpsc::Receiver<Request>>>, state: Arc<State>) {
    loop {
        let request = match receiver.lock() {
            Ok(receiver) => receiver.recv(),
            Err(_) => return,
        };
        match request {
            Ok(request) => handle(request, &state),
            Err(_) => return,
        }
    }
}

fn handle(mut request: Request, state: &State) {
    if request.method() == &Method::Options {
        respond(request, StatusCode(204), Value::Null);
        return;
    }
    if request.method() != &Method::Post || !authorized(&request, &state.token) {
        respond(
            request,
            StatusCode(401),
            json!({ "error": AppError::new("e2e.unauthorized", "e2e", "request rejected") }),
        );
        return;
    }
    let mut body = Vec::new();
    let read = request
        .as_reader()
        .take(MAX_REQUEST + 1)
        .read_to_end(&mut body);
    if read.is_err() || body.len() as u64 > MAX_REQUEST {
        respond(
            request,
            StatusCode(413),
            json!({ "error": AppError::new("e2e.request_too_large", "e2e", "request exceeds 1 MiB") }),
        );
        return;
    }
    let value = serde_json::from_slice::<Value>(&body).unwrap_or_else(|_| json!({}));
    let command = request.url().trim_start_matches('/').to_owned();
    let owned_state = state.clone();
    let (sender, receiver) = mpsc::sync_channel(1);
    if thread::Builder::new()
        .name("qtrace-e2e-request".into())
        .spawn(move || {
            let _ = sender.send(dispatch(&command, value, &owned_state));
        })
        .is_err()
    {
        respond(
            request,
            StatusCode(500),
            json!({ "error": AppError::worker_failed() }),
        );
        return;
    }
    let result = match receiver.recv_timeout(REQUEST_DEADLINE) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(AppError::new(
            "e2e.deadline_exceeded",
            "e2e",
            "request exceeded 30-second deadline",
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(AppError::worker_failed()),
    };
    match result {
        Ok(value) => respond(request, StatusCode(200), json!({ "ok": value })),
        Err(error) => respond(request, StatusCode(400), json!({ "error": error })),
    }
}

fn dispatch(command: &str, value: Value, state: &State) -> Result<Value, AppError> {
    if command == "restart_service" {
        *state
            .service
            .lock()
            .map_err(|_| AppError::worker_failed())? = Arc::new(QtraceService::with_cache_root(
            state.data_root.join("cache/indexes"),
        ));
        return Ok(Value::Null);
    }
    let service = state
        .service
        .lock()
        .map_err(|_| AppError::worker_failed())?
        .clone();
    match command {
        "pick_and_open_session" => {
            let fixture =
                optional::<String>(&value, "fixture")?.unwrap_or_else(|| "valid-mixed".into());
            let member_name = match fixture.as_str() {
                "valid-mixed" => "sessions/valid-mixed",
                "one-invalid-artifact" => "sessions/one-invalid-artifact",
                _ => {
                    return Err(AppError::new(
                        "e2e.fixture_denied",
                        "e2e",
                        "fixture member is not allowed",
                    ));
                }
            };
            to_value(service.open_session(AuthorizedPath::new(member(
                &state.fixture_root,
                member_name,
            )?))?)
        }
        "pick_and_open_artifact" => {
            to_value(service.open_artifact(AuthorizedPath::new(member(
                &state.fixture_root,
                "sessions/valid-mixed/artifacts/main.trace.bin",
            )?))?)
        }
        "close_workspace" => {
            service.close_workspace(&field(&value, "workspace_id")?)?;
            Ok(Value::Null)
        }
        "get_workspace_summary" => {
            to_value(service.workspace_summary(&field(&value, "workspace_id")?)?)
        }
        "create_projection" => to_value(state.runtime.block_on(service.create_projection_task(
            field(&value, "workspace_id")?,
            number(&value, "artifact_index")?,
            field(&value, "filter")?,
        ))?),
        "query_timeline" => to_value(service.query_timeline(
            &field(&value, "workspace_id")?,
            &field(&value, "projection_id")?,
            optional(&value, "cursor")?,
            number(&value, "limit")?,
        )?),
        "get_event_detail" => to_value(service.get_event_detail(
            &field(&value, "workspace_id")?,
            number(&value, "artifact_index")?,
            number(&value, "row")?,
        )?),
        "get_register_state" => to_value(service.get_register_state(
            &field(&value, "workspace_id")?,
            number(&value, "artifact_index")?,
            number(&value, "row")?,
        )?),
        "get_memory_state" => to_value(service.get_memory_state(
            &field(&value, "workspace_id")?,
            number(&value, "artifact_index")?,
            number(&value, "row")?,
            field::<HexU64Dto>(&value, "start")?.value(),
            field::<HexU64Dto>(&value, "end_exclusive")?.value(),
        )?),
        "get_memory_history" => to_value(service.get_memory_history(
            &field(&value, "workspace_id")?,
            number(&value, "artifact_index")?,
            number(&value, "row")?,
            field::<HexU64Dto>(&value, "start")?.value(),
            field::<HexU64Dto>(&value, "end_exclusive")?.value(),
        )?),
        "get_call_tree" => to_value(service.get_call_tree(
            &field(&value, "workspace_id")?,
            number(&value, "artifact_index")?,
            field::<DecimalU64Dto>(&value, "timeline_id")?.value(),
            number(&value, "tid")?,
        )?),
        "list_symbols" => {
            let pcs = field::<Vec<HexU64Dto>>(&value, "relative_pcs")?
                .iter()
                .map(HexU64Dto::value)
                .collect::<Vec<_>>();
            to_value(service.list_symbols(
                &field(&value, "workspace_id")?,
                &field::<String>(&value, "module_name")?,
                &pcs,
            )?)
        }
        "get_annotation" => to_value(service.get_annotation(
            &field(&value, "workspace_id")?,
            AuthorizedPath::new(state.data_root.clone()),
            number(&value, "artifact_index")?,
            number(&value, "row")?,
        )?),
        "upsert_annotation" => {
            service.upsert_annotation(
                &field(&value, "workspace_id")?,
                AuthorizedPath::new(state.data_root.clone()),
                number(&value, "artifact_index")?,
                number(&value, "row")?,
                field(&value, "comment")?,
            )?;
            Ok(Value::Null)
        }
        "delete_annotation" => {
            service.delete_annotation(
                &field(&value, "workspace_id")?,
                AuthorizedPath::new(state.data_root.clone()),
                number(&value, "artifact_index")?,
                number(&value, "row")?,
            )?;
            Ok(Value::Null)
        }
        "upsert_highlight" => {
            service.upsert_highlight(
                &field(&value, "workspace_id")?,
                AuthorizedPath::new(state.data_root.clone()),
                number(&value, "artifact_index")?,
                number(&value, "row")?,
                field(&value, "value")?,
            )?;
            Ok(Value::Null)
        }
        "delete_highlight" => {
            service.delete_highlight(
                &field(&value, "workspace_id")?,
                AuthorizedPath::new(state.data_root.clone()),
                number(&value, "artifact_index")?,
                number(&value, "row")?,
            )?;
            Ok(Value::Null)
        }
        "get_local_symbol_name" => to_value(service.get_local_symbol_name(
            &field(&value, "workspace_id")?,
            AuthorizedPath::new(state.data_root.clone()),
            number(&value, "artifact_index")?,
            field(&value, "module_digest")?,
            field::<HexU64Dto>(&value, "relative_pc")?.value(),
        )?),
        "upsert_local_symbol_name" => {
            service.upsert_local_symbol_name(
                &field(&value, "workspace_id")?,
                AuthorizedPath::new(state.data_root.clone()),
                number(&value, "artifact_index")?,
                field(&value, "module_digest")?,
                field::<HexU64Dto>(&value, "relative_pc")?.value(),
                field(&value, "name")?,
            )?;
            Ok(Value::Null)
        }
        "delete_local_symbol_name" => {
            service.delete_local_symbol_name(
                &field(&value, "workspace_id")?,
                AuthorizedPath::new(state.data_root.clone()),
                number(&value, "artifact_index")?,
                field(&value, "module_digest")?,
                field::<HexU64Dto>(&value, "relative_pc")?.value(),
            )?;
            Ok(Value::Null)
        }
        "list_jobs" => to_value(service.list_jobs()),
        "cancel_job" => {
            service.cancel_job(&field(&value, "job_id")?)?;
            Ok(Value::Null)
        }
        _ => Err(AppError::new(
            "e2e.command_unknown",
            "e2e",
            "unknown command",
        )),
    }
}

fn member(root: &Path, name: &str) -> Result<PathBuf, AppError> {
    if !matches!(
        name,
        "sessions/valid-mixed"
            | "sessions/one-invalid-artifact"
            | "sessions/valid-mixed/artifacts/main.trace.bin"
    ) {
        return Err(AppError::new(
            "e2e.fixture_denied",
            "e2e",
            "fixture member is not allowed",
        ));
    }
    let path = root
        .join(name)
        .canonicalize()
        .map_err(|_| AppError::new("e2e.fixture_missing", "e2e", "fixture is missing"))?;
    if !path.starts_with(root) {
        return Err(AppError::new(
            "e2e.fixture_denied",
            "e2e",
            "fixture escaped root",
        ));
    }
    Ok(path)
}
fn field<T: DeserializeOwned>(value: &Value, name: &str) -> Result<T, AppError> {
    serde_json::from_value(value.get(name).cloned().unwrap_or(Value::Null))
        .map_err(|_| AppError::new("e2e.request_invalid", "e2e", format!("invalid {name}")))
}
fn optional<T: DeserializeOwned>(value: &Value, name: &str) -> Result<Option<T>, AppError> {
    field(value, name)
}
fn number(value: &Value, name: &str) -> Result<u32, AppError> {
    field(value, name)
}
fn to_value<T: serde::Serialize>(value: T) -> Result<Value, AppError> {
    serde_json::to_value(value).map_err(|_| AppError::worker_failed())
}
fn authorized(request: &Request, token: &str) -> bool {
    request.headers().iter().any(|header| {
        header.field.equiv("Authorization") && header.value.as_str() == format!("Bearer {token}")
    })
}
fn respond(request: Request, status: StatusCode, value: Value) {
    let header = Header::from_bytes("Content-Type", "application/json").unwrap();
    let origin =
        Header::from_bytes("Access-Control-Allow-Origin", "http://localhost:1421").unwrap();
    let headers =
        Header::from_bytes("Access-Control-Allow-Headers", "authorization,content-type").unwrap();
    let methods = Header::from_bytes("Access-Control-Allow-Methods", "POST,OPTIONS").unwrap();
    let _ = request.respond(
        Response::from_string(value.to_string())
            .with_status_code(status)
            .with_header(header)
            .with_header(origin)
            .with_header(headers)
            .with_header(methods),
    );
}
fn required_arg(name: &str) -> String {
    let mut args = std::env::args();
    while let Some(value) = args.next() {
        if value == name {
            return args
                .next()
                .unwrap_or_else(|| fail("missing argument value"));
        }
    }
    fail("missing required argument")
}
fn fail(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(2)
}
