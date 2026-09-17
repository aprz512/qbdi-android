use qtrace_service::*;
use ts_rs::{Config, TS};

fn main() {
    let config = Config::default();
    for declaration in [
        AppError::decl(&config),
        AnnotationDto::decl(&config),
        AddressRangeDto::decl(&config),
        ArtifactSummaryDto::decl(&config),
        CompletenessRangeDto::decl(&config),
        CallNodeDto::decl(&config),
        CallTreeDto::decl(&config),
        DecimalI64Dto::decl(&config),
        DecimalU64Dto::decl(&config),
        EventFilterDto::decl(&config),
        EventDetailDto::decl(&config),
        EventKeyDto::decl(&config),
        EventRowDto::decl(&config),
        HexU64Dto::decl(&config),
        JobDto::decl(&config),
        JobId::decl(&config),
        JobProgressDto::decl(&config),
        JobState::decl(&config),
        LocalSymbolNameDto::decl(&config),
        MemoryByteDto::decl(&config),
        MemoryFilterDto::decl(&config),
        MemoryEvidenceDto::decl(&config),
        MemoryStateDto::decl(&config),
        OpenWorkspaceDto::decl(&config),
        MnemonicFilterDto::decl(&config),
        ProjectionId::decl(&config),
        ProjectionJobDto::decl(&config),
        RegisterCellDto::decl(&config),
        RegisterStateDto::decl(&config),
        SourceCoordinateDto::decl(&config),
        SequenceRangeDto::decl(&config),
        WorkspaceId::decl(&config),
        WorkspaceSummaryDto::decl(&config),
        SymbolDto::decl(&config),
        TimelineLocationDto::decl(&config),
        TimelinePageDto::decl(&config),
    ] {
        println!("export {declaration}");
    }
}
