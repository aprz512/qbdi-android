use qtrace_provider::{BudgetDimension, OperationAbort, ProviderError, SourceCoordinate};
use qtrace_service::{AppError, DecimalI64Dto, DecimalU64Dto, HexU64Dto};
use std::process::Command;

#[test]
fn integer_dtos_are_validated_strings_at_numeric_boundaries() {
    assert_eq!(
        serde_json::to_string(&DecimalU64Dto::new(u64::MAX)).unwrap(),
        format!("\"{}\"", u64::MAX)
    );
    assert_eq!(
        serde_json::to_string(&DecimalI64Dto::new(i64::MIN)).unwrap(),
        format!("\"{}\"", i64::MIN)
    );
    assert_eq!(
        serde_json::to_string(&HexU64Dto::new(u64::MAX)).unwrap(),
        "\"0xffffffffffffffff\""
    );
    assert!(serde_json::from_str::<DecimalU64Dto>("\"01\"").is_err());
    assert!(serde_json::from_str::<HexU64Dto>("\"ff\"").is_err());
}

#[test]
fn provider_and_budget_errors_map_to_stable_bounded_envelope() {
    let provider = ProviderError::new(
        "source.bad",
        "decode",
        Some(SourceCoordinate {
            offset: u64::MAX,
            record_ordinal: Some(7),
        }),
        false,
        format!("bad\n{}", "x".repeat(700)),
    );
    let error = AppError::from(provider);
    let value = serde_json::to_value(&error).unwrap();
    assert_eq!(value["code"], "source.bad");
    assert_eq!(value["stage"], "decode");
    assert_eq!(value["source"]["offset"], u64::MAX.to_string());
    assert!(!error.detail.contains('\n'));
    assert!(error.detail.len() <= 512);

    let budget = AppError::from(OperationAbort::budget_exceeded(
        BudgetDimension::ResidentBytes,
        10,
        11,
    ));
    assert_eq!(budget.code, "control.budget_exceeded");
    assert_eq!(budget.stage, "control");
}

#[test]
fn worker_panics_never_expose_debug_details() {
    let error = AppError::worker_failed();
    assert_eq!(error.code, "internal.worker_failed");
    assert_eq!(error.detail, "background worker failed");
}

#[test]
fn typescript_export_is_deterministic_and_uses_string_integers() {
    let executable = env!("CARGO_BIN_EXE_export_bindings");
    let first = Command::new(executable).output().unwrap();
    let second = Command::new(executable).output().unwrap();
    assert!(first.status.success());
    assert_eq!(first.stdout, second.stdout);
    let text = String::from_utf8(first.stdout).unwrap();
    assert!(text.contains("export type AppError"));
    assert!(text.contains("export type DecimalU64Dto = string"));
    assert!(!text.contains("offset: bigint"));

    let directory = tempfile::tempdir().unwrap();
    let generated = directory.path().join("generated.ts");
    std::fs::write(&generated, text).unwrap();
    let consumer = directory.path().join("consumer.ts");
    std::fs::write(
        &consumer,
        r#"import type { AppError, OpenWorkspaceDto } from './generated';
const opened: OpenWorkspaceDto = {
  workspace: { id: 'workspace-1', generation: 0, artifact_count: 1 },
  artifacts: [{ index: 0, name: 'trace.qtrb', status: 'indexed', event_count: 1, tids: [7], completeness: [] }],
  warnings: [],
  context: null,
  missing_capabilities: ['package', 'device', 'target', 'effective_config'],
};
const error: AppError = {
  code: 'source.bad', stage: 'decode', source: null, retryable: false, detail: 'bad',
};
const narrowed: string = error.retryable ? error.code : opened.workspace.id;
void narrowed;
"#,
    )
    .unwrap();
    let tsc = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../src-web/node_modules/.bin/tsc");
    let compiled = Command::new(tsc)
        .args(["--noEmit", "--strict", "--skipLibCheck"])
        .arg(&consumer)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
}
