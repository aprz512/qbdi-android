use crate::{DecimalU64Dto, SourceCoordinateDto};
use qtrace_provider::{OperationAbort, ProviderError};
use serde::{Deserialize, Serialize};
use ts_rs::TS;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
pub struct AppError {
    pub code: String,
    pub stage: String,
    pub source: Option<SourceCoordinateDto>,
    pub retryable: bool,
    pub detail: String,
}
impl AppError {
    pub fn new(code: impl Into<String>, stage: impl Into<String>, detail: impl AsRef<str>) -> Self {
        Self {
            code: code.into(),
            stage: stage.into(),
            source: None,
            retryable: false,
            detail: bounded(detail.as_ref()),
        }
    }
    pub fn cancelled() -> Self {
        Self::new("job.cancelled", "control", "operation cancelled")
    }
    pub fn worker_failed() -> Self {
        Self::new(
            "internal.worker_failed",
            "worker",
            "background worker failed",
        )
    }
    pub fn stale_workspace() -> Self {
        Self::new(
            "workspace.stale",
            "workspace",
            "workspace is closed or stale",
        )
    }
}
impl From<ProviderError> for AppError {
    fn from(e: ProviderError) -> Self {
        Self {
            code: e.code().into(),
            stage: e.stage().into(),
            source: e.source().map(|s| SourceCoordinateDto {
                offset: DecimalU64Dto::new(s.offset),
                record_ordinal: s.record_ordinal.map(DecimalU64Dto::new),
            }),
            retryable: e.retryable(),
            detail: bounded(e.detail()),
        }
    }
}
impl From<OperationAbort> for AppError {
    fn from(e: OperationAbort) -> Self {
        match e {
            OperationAbort::Cancelled => Self::cancelled(),
            OperationAbort::BudgetExceeded { .. } => {
                Self::new("control.budget_exceeded", "control", e.to_string())
            }
        }
    }
}

impl From<qtrace_store::IndexError> for AppError {
    fn from(error: qtrace_store::IndexError) -> Self {
        if let Some(abort) = error.operation_abort() {
            return abort.clone().into();
        }
        Self::new(error.code(), "index", error.to_string())
    }
}

impl From<qtrace_analysis::AnalysisError> for AppError {
    fn from(error: qtrace_analysis::AnalysisError) -> Self {
        Self::new(error.code(), "analysis", error.detail())
    }
}
impl From<qtrace_store::SymbolError> for AppError {
    fn from(error: qtrace_store::SymbolError) -> Self {
        Self::new(error.code(), "symbol", error.to_string())
    }
}
impl From<qtrace_store::AnnotationError> for AppError {
    fn from(error: qtrace_store::AnnotationError) -> Self {
        Self::new(error.code(), "annotation", error.to_string())
    }
}
fn bounded(value: &str) -> String {
    let mut out = String::with_capacity(value.len().min(512));
    for c in value.chars() {
        let c = if matches!(c, '\r' | '\n') { ' ' } else { c };
        if out.len() + c.len_utf8() > 512 {
            break;
        }
        out.push(c);
    }
    out
}
