use std::{borrow::Cow, error::Error, fmt};

use serde::{Deserialize, Deserializer, Serialize};

use crate::OperationAbort;

const MAX_DETAIL_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct SourceCoordinate {
    pub offset: u64,
    pub record_ordinal: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderError {
    code: Cow<'static, str>,
    stage: Cow<'static, str>,
    source: Option<SourceCoordinate>,
    retryable: bool,
    detail: ProviderErrorDetail,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(untagged)]
enum ProviderErrorDetail {
    Message(Cow<'static, str>),
    Abort(OperationAbort),
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
            code: Cow::Owned(code.into()),
            stage: Cow::Owned(stage.into()),
            source,
            retryable,
            detail: ProviderErrorDetail::Message(Cow::Owned(bounded_single_line(detail.as_ref()))),
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

    pub fn code(&self) -> &str {
        &self.code
    }

    pub fn stage(&self) -> &str {
        &self.stage
    }

    pub const fn source(&self) -> Option<SourceCoordinate> {
        self.source
    }

    pub const fn retryable(&self) -> bool {
        self.retryable
    }

    pub fn detail(&self) -> &str {
        match &self.detail {
            ProviderErrorDetail::Message(detail) => detail,
            ProviderErrorDetail::Abort(_) => "operation aborted by work guard",
        }
    }

    pub const fn operation_abort(&self) -> Option<&OperationAbort> {
        match &self.detail {
            ProviderErrorDetail::Abort(abort) => Some(abort),
            ProviderErrorDetail::Message(_) => None,
        }
    }
}

impl<'de> Deserialize<'de> for ProviderError {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SerializedProviderError {
            code: String,
            stage: String,
            source: Option<SourceCoordinate>,
            retryable: bool,
            detail: String,
        }

        let value = SerializedProviderError::deserialize(deserializer)?;
        Ok(Self::new(
            value.code,
            value.stage,
            value.source,
            value.retryable,
            value.detail,
        ))
    }
}

impl From<OperationAbort> for ProviderError {
    fn from(abort: OperationAbort) -> Self {
        let code = match abort {
            OperationAbort::Cancelled => "control.cancelled",
            OperationAbort::BudgetExceeded { .. } => "control.budget_exceeded",
        };
        Self {
            code: Cow::Borrowed(code),
            stage: Cow::Borrowed("control"),
            source: None,
            retryable: false,
            detail: ProviderErrorDetail::Abort(abort),
        }
    }
}

impl fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.detail {
            ProviderErrorDetail::Abort(abort) => {
                write!(formatter, "{} at {}: {abort}", self.code, self.stage)
            }
            ProviderErrorDetail::Message(detail) => {
                write!(formatter, "{} at {}: {}", self.code, self.stage, detail)
            }
        }
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
