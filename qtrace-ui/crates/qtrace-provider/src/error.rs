use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};

use crate::OperationAbort;

const MAX_DETAIL_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct SourceCoordinate {
    pub offset: u64,
    pub record_ordinal: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderError {
    pub code: String,
    pub stage: String,
    pub source: Option<SourceCoordinate>,
    pub retryable: bool,
    pub detail: String,
}

impl ProviderError {
    pub fn new(
        code: impl Into<String>,
        stage: impl Into<String>,
        source: Option<SourceCoordinate>,
        retryable: bool,
        detail: impl AsRef<str>,
    ) -> Self {
        Self {
            code: code.into(),
            stage: stage.into(),
            source,
            retryable,
            detail: bounded_single_line(detail.as_ref()),
        }
    }

    pub fn stream_not_drained() -> Self {
        Self::new(
            "source.stream_not_drained",
            "finish",
            None,
            false,
            "event stream must return end-of-stream before finish",
        )
    }
}

impl From<OperationAbort> for ProviderError {
    fn from(abort: OperationAbort) -> Self {
        Self::new(
            match abort {
                OperationAbort::Cancelled => "control.cancelled",
                OperationAbort::BudgetExceeded { .. } => "control.budget_exceeded",
            },
            "control",
            None,
            false,
            abort.to_string(),
        )
    }
}

impl fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} at {}: {}",
            self.code, self.stage, self.detail
        )
    }
}

impl Error for ProviderError {}

fn bounded_single_line(detail: &str) -> String {
    let mut output = String::with_capacity(detail.len().min(MAX_DETAIL_BYTES));
    for character in detail.chars() {
        let character = match character {
            '\r' | '\n' => ' ',
            character => character,
        };
        if output.len() + character.len_utf8() > MAX_DETAIL_BYTES {
            break;
        }
        output.push(character);
    }
    output
}
