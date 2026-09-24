use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use qtrace_analysis::{QueryContext, RegisterReplay, TimelineProjection};
use qtrace_store::{ElfSymbolIndex, TraceStore};

use crate::ProjectionId;

pub(crate) type RegisterReplaySlot = Arc<Mutex<Option<Arc<RegisterReplay>>>>;

pub(crate) struct Workspace {
    pub generation: u32,
    pub current: Option<ProjectionId>,
    pub artifacts: Vec<ArtifactWorkspace>,
    pub projections: HashMap<ProjectionId, ProjectionWorkspace>,
    pub symbols: HashMap<String, Arc<ElfSymbolIndex>>,
}

pub(crate) struct ArtifactWorkspace {
    pub name: String,
    pub store: Arc<TraceStore>,
    pub context: Arc<QueryContext>,
    pub register_replay: RegisterReplaySlot,
}

pub(crate) struct ProjectionWorkspace {
    pub projection: Arc<TimelineProjection>,
    pub generation: u32,
}

impl Workspace {
    pub fn empty() -> Self {
        Self {
            generation: 0,
            current: None,
            artifacts: Vec::new(),
            projections: HashMap::new(),
            symbols: HashMap::new(),
        }
    }
}
