mod events;
mod fragments;
mod recovery;
mod wire;

use std::{collections::HashMap, fmt, mem::size_of, sync::Arc, vec};

use crate::{
    AllocationScope, EventCursor, EventKey, EventRecord, MAX_UNGUARDED_RECORDS,
    ProviderCapabilities, ProviderError, ProviderSummary, ReadAtSource, RegisterSnapshot,
    SourceIdentity, TimelineDescriptor, TimelineId, TraceProvider, WorkDelta, WorkGuard,
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
        let mut timelines = fallible_vec(recovered.tids.len().saturating_add(1), guard)?;
        timelines.push(TimelineDescriptor {
            id: recovery::MERGED_TIMELINE_ID,
            tid: None,
            label: Some(fallible_string("Flight", guard)?),
        });
        let mut projections = fallible_vec(recovered.tids.len(), guard)?;
        let mut projection_by_tid = fallible_hash_map(recovered.tids.len(), guard)?;
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
        let mut projection_counts = fallible_vec(projections.len(), guard)?;
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
            reserve_vec_exact(&mut projection.event_keys, count, guard)?;
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
            fallible_push(&mut projection.event_keys, event.key.clone(), guard)?;
        }
        let mut summary_timelines = fallible_vec(timelines.len(), guard)?;
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

fn fallible_vec<T>(capacity: usize, guard: &dyn WorkGuard) -> Result<Vec<T>, ProviderError> {
    let bytes = capacity
        .checked_mul(size_of::<T>())
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| resource_error("Flight vector allocation bound overflow"))?;
    let _scope = AllocationScope::begin(guard, bytes, bytes)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| resource_error("Flight provider allocation failed"))?;
    Ok(output)
}

fn fallible_hash_map<K, V>(
    capacity: usize,
    guard: &dyn WorkGuard,
) -> Result<HashMap<K, V>, ProviderError>
where
    K: Eq + std::hash::Hash,
{
    let bytes = capacity
        .checked_mul(size_of::<K>().saturating_add(size_of::<V>()))
        .and_then(|value| value.checked_mul(4))
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| resource_error("Flight hash allocation bound overflow"))?;
    let _scope = AllocationScope::begin(guard, bytes, bytes)?;
    let mut output = HashMap::new();
    output
        .try_reserve(capacity)
        .map_err(|_| resource_error("Flight provider allocation failed"))?;
    Ok(output)
}

fn fallible_push<T>(
    output: &mut Vec<T>,
    value: T,
    guard: &dyn WorkGuard,
) -> Result<(), ProviderError> {
    if output.len() == output.capacity() {
        let new_capacity = output
            .capacity()
            .checked_mul(2)
            .map(|capacity| capacity.max(4))
            .ok_or_else(|| resource_error("Flight vector capacity overflow"))?;
        let bytes = new_capacity
            .checked_mul(size_of::<T>())
            .and_then(|value| u64::try_from(value).ok())
            .ok_or_else(|| resource_error("Flight vector layout overflow"))?;
        let _scope = AllocationScope::begin(guard, bytes, bytes)?;
        output
            .try_reserve_exact(output.capacity().max(4))
            .map_err(|_| resource_error("Flight provider allocation failed"))?;
    }
    output.push(value);
    Ok(())
}

fn reserve_vec_exact<T>(
    output: &mut Vec<T>,
    capacity: usize,
    guard: &dyn WorkGuard,
) -> Result<(), ProviderError> {
    if capacity <= output.capacity() {
        return Ok(());
    }
    let bytes = capacity
        .checked_mul(size_of::<T>())
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| resource_error("Flight vector layout overflow"))?;
    let _scope = AllocationScope::begin(guard, bytes, bytes)?;
    output
        .try_reserve_exact(capacity - output.len())
        .map_err(|_| resource_error("Flight provider allocation failed"))
}

fn fallible_string(value: &str, guard: &dyn WorkGuard) -> Result<String, ProviderError> {
    let bytes = value.len() as u64;
    let _scope = AllocationScope::begin(guard, bytes, bytes)?;
    let mut output = String::new();
    output
        .try_reserve_exact(value.len())
        .map_err(|_| resource_error("Flight provider allocation failed"))?;
    output.push_str(value);
    Ok(output)
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
