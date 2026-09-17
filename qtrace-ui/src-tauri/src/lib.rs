// The IPC error envelope is fixed by the public TypeScript/JSON contract.
#![allow(clippy::result_large_err)]

pub mod commands;
pub mod state;

pub use commands::*;
#[cfg(feature = "desktop")]
pub use state::TauriNativePicker;
pub use state::{CommandAdapter, NativePicker};
