use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegisterAccess {
    Read,
    Write,
    Checkpoint,
    Delta,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RegisterObservationRow {
    pub owner_row: usize,
    pub slot: u8,
    pub captured_width: u8,
    pub access: RegisterAccess,
    pub value: u64,
    pub provenance: qtrace_provider::Provenance,
}
