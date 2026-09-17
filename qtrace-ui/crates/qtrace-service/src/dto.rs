use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use ts_rs::TS;

macro_rules! string_id {
    ($name:ident) => {
        #[derive(
            Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, TS,
        )]
        #[ts(type = "string")]
        pub struct $name(String);
        impl $name {
            pub fn from_u64(value: u64) -> Self {
                Self(value.to_string())
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}
string_id!(WorkspaceId);
string_id!(JobId);
string_id!(ProjectionId);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, TS)]
#[ts(type = "string")]
pub struct DecimalU64Dto(String);
impl DecimalU64Dto {
    pub fn new(value: u64) -> Self {
        Self(value.to_string())
    }
    pub fn value(&self) -> u64 {
        self.0.parse().expect("validated decimal")
    }
}
impl<'de> Deserialize<'de> for DecimalU64Dto {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        let value = text.parse::<u64>().map_err(serde::de::Error::custom)?;
        if value.to_string() != text {
            return Err(serde::de::Error::custom("non-canonical u64"));
        }
        Ok(Self(text))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, TS)]
#[ts(type = "string")]
pub struct DecimalI64Dto(String);
impl DecimalI64Dto {
    pub fn new(value: i64) -> Self {
        Self(value.to_string())
    }
}
impl<'de> Deserialize<'de> for DecimalI64Dto {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        let value = text.parse::<i64>().map_err(serde::de::Error::custom)?;
        if value.to_string() != text {
            return Err(serde::de::Error::custom("non-canonical i64"));
        }
        Ok(Self(text))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, TS)]
#[ts(type = "string")]
pub struct HexU64Dto(String);
impl HexU64Dto {
    pub fn new(value: u64) -> Self {
        Self(format!("0x{value:x}"))
    }
    pub fn value(&self) -> u64 {
        u64::from_str_radix(&self.0[2..], 16).expect("validated hexadecimal")
    }
}
impl<'de> Deserialize<'de> for HexU64Dto {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        let digits = text
            .strip_prefix("0x")
            .ok_or_else(|| serde::de::Error::custom("hex value needs 0x"))?;
        let value = u64::from_str_radix(digits, 16).map_err(serde::de::Error::custom)?;
        if format!("0x{value:x}") != text {
            return Err(serde::de::Error::custom("non-canonical hex u64"));
        }
        Ok(Self(text))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
pub struct SourceCoordinateDto {
    pub offset: DecimalU64Dto,
    pub record_ordinal: Option<DecimalU64Dto>,
}
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize, TS)]
pub struct EventFilterDto {
    pub tids: Vec<u32>,
    pub kinds: Vec<String>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Running,
    Completed,
    Cancelled,
    Failed,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
pub struct JobProgressDto {
    pub completed: DecimalU64Dto,
    pub total: Option<DecimalU64Dto>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
pub struct JobDto {
    pub id: JobId,
    pub workspace_id: WorkspaceId,
    pub kind: String,
    pub state: JobState,
    pub progress: JobProgressDto,
    pub error: Option<crate::AppError>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
pub struct WorkspaceSummaryDto {
    pub id: WorkspaceId,
    pub generation: u32,
    pub artifact_count: u32,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
pub struct ProjectionJobDto {
    pub projection_id: ProjectionId,
    pub job_id: JobId,
    pub generation: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
pub struct ArtifactSummaryDto {
    pub index: u32,
    pub name: String,
    pub event_count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
pub struct OpenWorkspaceDto {
    pub workspace: WorkspaceSummaryDto,
    pub artifacts: Vec<ArtifactSummaryDto>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
pub struct EventKeyDto {
    pub artifact_sha256: String,
    pub timeline_id: DecimalU64Dto,
    pub record_ordinal: DecimalU64Dto,
    pub source_offset: DecimalU64Dto,
    pub sequence: Option<DecimalU64Dto>,
    pub tid: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
pub struct EventRowDto {
    pub source_row: u32,
    pub key: EventKeyDto,
    pub kind: String,
    pub provenance: String,
    pub discontinuity: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
pub struct TimelinePageDto {
    pub rows: Vec<EventRowDto>,
    pub next_cursor: Option<String>,
    pub total: u32,
    pub exact_total: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
pub struct EventDetailDto {
    pub artifact_index: u32,
    pub row: u32,
    pub key: EventKeyDto,
    pub kind: String,
    pub provenance: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
pub struct RegisterCellDto {
    pub slot: String,
    pub value: Option<HexU64Dto>,
    pub known_mask: HexU64Dto,
    pub captured_width: u8,
    pub provenance: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
pub struct RegisterStateDto {
    pub key: EventKeyDto,
    pub before: Vec<RegisterCellDto>,
    pub after: Vec<RegisterCellDto>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
pub struct MemoryByteDto {
    pub address: HexU64Dto,
    pub value: Option<u8>,
    pub provenance: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
pub struct MemoryStateDto {
    pub key: EventKeyDto,
    pub start: HexU64Dto,
    pub end_exclusive: HexU64Dto,
    pub observed: Vec<MemoryByteDto>,
    pub before: Vec<MemoryByteDto>,
    pub after: Vec<MemoryByteDto>,
    pub last_written: Vec<MemoryByteDto>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
pub struct MemoryEvidenceDto {
    pub key: EventKeyDto,
    pub tid: Option<u32>,
    pub direction: String,
    pub provenance: String,
    pub address: HexU64Dto,
    pub size: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
pub struct CallNodeDto {
    pub id: u32,
    pub parent: Option<u32>,
    pub children: Vec<u32>,
    pub tid: u32,
    pub target: Option<HexU64Dto>,
    pub display: String,
    pub source_row_start: u32,
    pub source_row_end_exclusive: u32,
    pub provenance: String,
    pub state: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
pub struct CallTreeDto {
    pub identity: String,
    pub timeline_id: DecimalU64Dto,
    pub tid: u32,
    pub roots: Vec<u32>,
    pub nodes: Vec<CallNodeDto>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
pub struct SymbolDto {
    pub module: String,
    pub name: String,
    pub relative_address: HexU64Dto,
    pub size: DecimalU64Dto,
    pub offset: DecimalU64Dto,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
pub struct AnnotationDto {
    pub key: EventKeyDto,
    pub comment: String,
}
impl fmt::Display for WorkspaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
