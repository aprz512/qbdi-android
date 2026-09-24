//! Stable application-service boundary for qtrace desktop clients.
// AppError intentionally matches the stable IPC envelope; boxing its public fields would change
// generated TypeScript and JSON-facing ergonomics.
#![allow(clippy::result_large_err)]

mod budget;
mod dto;
mod error;
mod jobs;
mod service;
mod workspace;

pub use budget::{ServiceBudget, ServiceLimits};
pub use dto::*;
pub use error::AppError;
pub use jobs::{JobCancellation, JobRegistry};
pub use service::{CallTreePageQuery, QtraceService};

pub const ANALYSIS_CRATE: &str = qtrace_analysis::STORE_CRATE;
