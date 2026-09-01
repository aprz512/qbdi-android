mod events;
mod fragments;
mod recovery;
mod wire;

mod allocation {
    use std::{
        collections::HashMap,
        hash::{BuildHasher, Hash},
    };

    use crate::{ProviderError, WorkGuard, allocation as shared};

    pub(super) fn try_reserve_vec_exact<T>(
        values: &mut Vec<T>,
        capacity: usize,
        guard: &dyn WorkGuard,
        detail: &'static str,
    ) -> Result<(), ProviderError> {
        shared::try_reserve_vec_exact_in(
            values,
            capacity,
            guard,
            detail,
            shared::FLIGHT_RECOVERY_ALLOCATION,
        )
    }

    pub(super) fn try_vec_with_capacity<T>(
        capacity: usize,
        guard: &dyn WorkGuard,
        detail: &'static str,
    ) -> Result<Vec<T>, ProviderError> {
        shared::try_vec_with_capacity_in(
            capacity,
            guard,
            detail,
            shared::FLIGHT_RECOVERY_ALLOCATION,
        )
    }

    pub(super) fn try_push_vec<T>(
        output: &mut Vec<T>,
        value: T,
        guard: &dyn WorkGuard,
        detail: &'static str,
    ) -> Result<(), ProviderError> {
        shared::try_push_vec_in(
            output,
            value,
            guard,
            detail,
            shared::FLIGHT_RECOVERY_ALLOCATION,
        )
    }

    pub(super) fn try_copy_bytes(
        bytes: &[u8],
        guard: &dyn WorkGuard,
        detail: &'static str,
    ) -> Result<Vec<u8>, ProviderError> {
        shared::try_copy_bytes_in(bytes, guard, detail, shared::FLIGHT_RECOVERY_ALLOCATION)
    }

    pub(super) fn try_copy_string(
        value: &str,
        guard: &dyn WorkGuard,
        detail: &'static str,
    ) -> Result<String, ProviderError> {
        shared::try_copy_string_in(value, guard, detail, shared::FLIGHT_RECOVERY_ALLOCATION)
    }

    pub(super) fn try_reserve_hash_map<K, V, S>(
        values: &mut HashMap<K, V, S>,
        additional: usize,
        guard: &dyn WorkGuard,
        detail: &'static str,
    ) -> Result<(), ProviderError>
    where
        K: Eq + Hash,
        S: BuildHasher,
    {
        shared::try_reserve_hash_map_in(
            values,
            additional,
            guard,
            detail,
            shared::FLIGHT_RECOVERY_ALLOCATION,
        )
    }

    pub(super) fn try_hash_map_with_capacity<K, V>(
        capacity: usize,
        guard: &dyn WorkGuard,
        detail: &'static str,
    ) -> Result<HashMap<K, V>, ProviderError>
    where
        K: Eq + Hash,
    {
        shared::try_hash_map_with_capacity_in(
            capacity,
            guard,
            detail,
            shared::FLIGHT_RECOVERY_ALLOCATION,
        )
    }
}

use std::{fmt, sync::Arc, vec};

use crate::{
    EventCursor, EventKey, EventRecord, MAX_UNGUARDED_RECORDS, ProviderCapabilities, ProviderError,
    ProviderSummary, ReadAtSource, RegisterSnapshot, SourceIdentity, TimelineDescriptor,
    TimelineId, TraceProvider, WorkDelta, WorkGuard, allocation as shared_allocation,
};

pub use wire::{
    FLIGHT_CHUNK_HEADER_BYTES, FLIGHT_DIRECTORY_ENTRY_BYTES, FLIGHT_EMERGENCY_RECORD_BYTES,
    FLIGHT_EMERGENCY_SLOT_BYTES, FLIGHT_RECORD_HEADER_BYTES, FLIGHT_SUPERBLOCK_BYTES,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlightProjectionDescriptor {
    pub tid: u32,
    pub timeline: TimelineDescriptor,
    pub event_keys: Vec<EventKey>,
    pub final_registers: Option<RegisterSnapshot>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FlightRecoverySummary {
    pub format_version: u16,
    pub run_id: u64,
    pub pid: u32,
    pub module_generation: u32,
    pub target_module: String,
    pub pointer_width: u8,
    pub artifact_flags: u32,
    pub complete: bool,
    pub active_chunks: Vec<u32>,
    pub stale_directory_entries: Vec<u32>,
    pub rotating_directory_entries: Vec<u32>,
    pub target_pcs: Vec<u64>,
}

pub struct FlightProvider {
    identity: SourceIdentity,
    capabilities: ProviderCapabilities,
    timelines: Vec<TimelineDescriptor>,
    projections: Vec<FlightProjectionDescriptor>,
    events: Vec<EventRecord>,
    summary: ProviderSummary,
    recovery_summary: FlightRecoverySummary,
}

impl fmt::Debug for FlightProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FlightProvider")
            .field("identity", &self.identity)
            .field("timelines", &self.timelines)
            .field("event_count", &self.events.len())
            .finish_non_exhaustive()
    }
}

impl FlightProvider {
    pub const CURSOR_RESIDENT_BYTES: usize = std::mem::size_of::<FlightCursor>();

    pub fn open(
        source: Arc<dyn ReadAtSource>,
        mut identity: SourceIdentity,
        guard: &dyn WorkGuard,
    ) -> Result<Self, ProviderError> {
        let mut recovered = recovery::recover(source, identity.artifact, guard)?;
        let projection_nodes = recovered.tids.len().saturating_add(1) as u64;
        guard.consume(WorkDelta {
            nodes: projection_nodes,
            ..WorkDelta::default()
        })?;

        identity.format = fallible_string("Flight", guard)?;
        identity.format_major = 2;
        identity.format_minor = 0;
        identity.source_bytes = recovered.source_bytes;
        let mut timelines = shared_allocation::try_vec_with_capacity_in(
            recovered.tids.len().saturating_add(1),
            guard,
            "Flight timeline allocation failed",
            shared_allocation::FLIGHT_OPEN_ALLOCATION,
        )?;
        timelines.push(TimelineDescriptor {
            id: recovery::MERGED_TIMELINE_ID,
            tid: None,
            label: Some(fallible_string("Flight", guard)?),
        });
        let mut projections = shared_allocation::try_vec_with_capacity_in(
            recovered.tids.len(),
            guard,
            "Flight projection allocation failed",
            shared_allocation::FLIGHT_OPEN_ALLOCATION,
        )?;
        let mut projection_by_tid = shared_allocation::try_hash_map_with_capacity_in(
            recovered.tids.len(),
            guard,
            "Flight projection map allocation failed",
            shared_allocation::FLIGHT_OPEN_ALLOCATION,
        )?;
        for (index, tid) in recovered.tids.iter().copied().enumerate() {
            guard_checkpoint(guard, index)?;
            let timeline = TimelineDescriptor {
                id: TimelineId(
                    u64::try_from(index)
                        .ok()
                        .and_then(|value| value.checked_add(1))
                        .ok_or_else(|| resource_error("projection timeline ID overflow"))?,
                ),
                tid: Some(tid),
                label: None,
            };
            timelines.push(timeline.clone());
            projections.push(FlightProjectionDescriptor {
                tid,
                timeline,
                event_keys: Vec::new(),
                final_registers: recovered.final_registers.remove(&tid),
            });
            if projection_by_tid.insert(tid, index).is_some() {
                return Err(resource_error("duplicate Flight projection TID"));
            }
        }
        let mut projection_counts = shared_allocation::try_vec_with_capacity_in(
            projections.len(),
            guard,
            "Flight projection count allocation failed",
            shared_allocation::FLIGHT_OPEN_ALLOCATION,
        )?;
        projection_counts.resize(projections.len(), 0_usize);
        for (event_index, event) in recovered.events.iter().enumerate() {
            guard_checkpoint(guard, event_index)?;
            let Some(tid) = event.key.tid else {
                continue;
            };
            let index = projection_by_tid
                .get(&tid)
                .copied()
                .ok_or_else(|| resource_error("Flight event projection TID is missing"))?;
            let count = projection_counts
                .get_mut(index)
                .ok_or_else(|| resource_error("Flight projection count index is invalid"))?;
            *count = count
                .checked_add(1)
                .ok_or_else(|| resource_error("Flight projection event count overflow"))?;
        }
        for (index, (projection, count)) in
            projections.iter_mut().zip(projection_counts).enumerate()
        {
            guard_checkpoint(guard, index)?;
            shared_allocation::try_reserve_vec_exact_in(
                &mut projection.event_keys,
                count,
                guard,
                "Flight projection key allocation failed",
                shared_allocation::FLIGHT_OPEN_ALLOCATION,
            )?;
        }
        for (event_index, event) in recovered.events.iter().enumerate() {
            guard_checkpoint(guard, event_index)?;
            let Some(tid) = event.key.tid else {
                continue;
            };
            let index = projection_by_tid
                .get(&tid)
                .copied()
                .ok_or_else(|| resource_error("Flight event projection TID is missing"))?;
            let projection = projections
                .get_mut(index)
                .ok_or_else(|| resource_error("Flight projection index is invalid"))?;
            shared_allocation::try_push_vec_in(
                &mut projection.event_keys,
                event.key.clone(),
                guard,
                "Flight projection key growth failed",
                shared_allocation::FLIGHT_OPEN_ALLOCATION,
            )?;
        }
        let mut summary_timelines = shared_allocation::try_vec_with_capacity_in(
            timelines.len(),
            guard,
            "Flight summary timeline allocation failed",
            shared_allocation::FLIGHT_OPEN_ALLOCATION,
        )?;
        for (index, timeline) in timelines.iter().enumerate() {
            guard_checkpoint(guard, index)?;
            summary_timelines.push(TimelineDescriptor {
                id: timeline.id,
                tid: timeline.tid,
                label: timeline
                    .label
                    .as_deref()
                    .map(|label| fallible_string(label, guard))
                    .transpose()?,
            });
        }
        let summary = ProviderSummary {
            timelines: summary_timelines,
            termination: recovered.termination.clone(),
            counters: recovered.counters,
            completeness: recovered.completeness,
        };
        Ok(Self {
            identity,
            capabilities: ProviderCapabilities {
                global_ordering: true,
                per_thread_ordering: true,
                full_register_checkpoint: true,
                register_read_write_observation: true,
                memory_metadata: true,
                memory_before_after: true,
                lifecycle: true,
                signal_and_termination: true,
                loss_and_damage_ranges: true,
            },
            timelines,
            projections,
            events: recovered.events,
            summary,
            recovery_summary: recovered.recovery_summary,
        })
    }

    pub fn projections(&self) -> &[FlightProjectionDescriptor] {
        &self.projections
    }

    pub fn recovery_summary(&self) -> &FlightRecoverySummary {
        &self.recovery_summary
    }
}

impl TraceProvider for FlightProvider {
    fn identity(&self) -> &SourceIdentity {
        &self.identity
    }

    fn capabilities(&self) -> &ProviderCapabilities {
        &self.capabilities
    }

    fn timelines(&self) -> &[TimelineDescriptor] {
        &self.timelines
    }

    fn cursor_resident_bytes(&self) -> Result<u64, ProviderError> {
        u64::try_from(Self::CURSOR_RESIDENT_BYTES).map_err(|_| {
            ProviderError::new(
                "control.resource_exhausted",
                "flight.allocation",
                None,
                false,
                "Flight cursor allocation bound overflow",
            )
        })
    }

    fn into_cursor(self: Box<Self>) -> Result<Box<dyn EventCursor>, ProviderError> {
        let provider = *self;
        Ok(Box::new(FlightCursor {
            events: provider.events.into_iter(),
            summary: provider.summary,
            drained: false,
            poisoned: false,
        }))
    }
}

struct FlightCursor {
    events: vec::IntoIter<EventRecord>,
    summary: ProviderSummary,
    drained: bool,
    poisoned: bool,
}

impl EventCursor for FlightCursor {
    fn next_event(&mut self, guard: &dyn WorkGuard) -> Result<Option<EventRecord>, ProviderError> {
        if self.drained {
            return Ok(None);
        }
        if self.poisoned {
            return Err(ProviderError::new(
                "source.cursor_failed",
                "flight.cursor",
                None,
                false,
                "Flight cursor cannot continue after a prior failure",
            ));
        }
        if self.events.as_slice().is_empty() {
            self.drained = true;
            return Ok(None);
        }
        if let Err(error) = guard.consume(WorkDelta::default()) {
            self.poisoned = true;
            return Err(error.into());
        }
        Ok(self.events.next())
    }

    fn finish(self: Box<Self>) -> Result<ProviderSummary, ProviderError> {
        if !self.drained || self.poisoned {
            return Err(ProviderError::stream_not_drained());
        }
        Ok(self.summary)
    }
}

fn fallible_string(value: &str, guard: &dyn WorkGuard) -> Result<String, ProviderError> {
    shared_allocation::try_copy_string_in(
        value,
        guard,
        "Flight provider allocation failed",
        shared_allocation::FLIGHT_OPEN_ALLOCATION,
    )
}

fn resource_error(detail: &'static str) -> ProviderError {
    ProviderError::new("source.flight.resource", "flight.open", None, false, detail)
}

fn guard_checkpoint(guard: &dyn WorkGuard, index: usize) -> Result<(), ProviderError> {
    let interval = usize::try_from(MAX_UNGUARDED_RECORDS)
        .map_err(|_| resource_error("Flight checkpoint interval does not fit host"))?;
    if index % interval == 0 {
        guard.consume(WorkDelta::default())?;
    }
    Ok(())
}
