use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};

pub const MAX_UNGUARDED_RECORDS: u64 = 4_096;
pub const MAX_UNGUARDED_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkDelta {
    pub input_bytes: u64,
    pub decompressed_bytes: u64,
    pub events: u64,
    pub nodes: u64,
    pub rows: u64,
    pub resident_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetDimension {
    InputBytes,
    DecompressedBytes,
    Events,
    Nodes,
    Rows,
    ResidentBytes,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationAbort {
    Cancelled,
    BudgetExceeded {
        dimension: BudgetDimension,
        limit: u64,
        consumed: u64,
    },
}

impl OperationAbort {
    pub const fn budget_exceeded(dimension: BudgetDimension, limit: u64, consumed: u64) -> Self {
        Self::BudgetExceeded {
            dimension,
            limit,
            consumed,
        }
    }
}

impl fmt::Display for OperationAbort {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("operation cancelled"),
            Self::BudgetExceeded {
                dimension,
                limit,
                consumed,
            } => write!(
                formatter,
                "{dimension:?} budget exceeded: consumed {consumed}, limit {limit}"
            ),
        }
    }
}

impl Error for OperationAbort {}

pub trait WorkGuard: Send + Sync {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort>;
}
