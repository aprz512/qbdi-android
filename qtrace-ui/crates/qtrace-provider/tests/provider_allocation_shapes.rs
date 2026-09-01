use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    mem::size_of,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};

use qtrace_provider::{
    AllocationScope, ArtifactDigest, BudgetDimension, ByteSource, EventPayload, EventRecord,
    FLIGHT_CHUNK_HEADER_BYTES, FLIGHT_DIRECTORY_ENTRY_BYTES, FLIGHT_EMERGENCY_SLOT_BYTES,
    FLIGHT_RECORD_HEADER_BYTES, FLIGHT_SUPERBLOCK_BYTES, FlightProvider, OpenMode, OperationAbort,
    Provenance, ProviderError, ProviderSummary, QtrbProvider, SourceIdentity, TraceProvider,
    WorkDelta, WorkGuard, checked_provider_geometric_capacity,
};

const QTRB_HEADER_BYTES: usize = 16;
const QTRB_RECORD_HEADER_BYTES: usize = 8;
const FLIGHT_CHUNK_BYTES: usize = 8_192;
const FLIGHT_MAGIC: u32 = 0x5146_4c54;
const FLIGHT_VERSION: u16 = 2;
const FLIGHT_RECORD_COMMIT: u32 = 0x5143_4d54;
const REJECT_LIMIT: u64 = 0x1122;
const REJECT_CONSUMED: u64 = 0x3344;

#[derive(Clone, Copy, Default)]
struct OracleState {
    active: bool,
    scope_active: bool,
    rejected: bool,
    authorized: u64,
    allowed_slack: u64,
    authorized_bytes: u64,
    requested_bytes: u64,
    max_scope_slack: u64,
    unauthorized: u64,
    nested: u64,
    scope_violations: u64,
    post_reject: u64,
}

thread_local! {
    static ORACLE: Cell<OracleState> = const { Cell::new(OracleState {
        active: false,
        scope_active: false,
        rejected: false,
        authorized: 0,
        allowed_slack: 0,
        authorized_bytes: 0,
        requested_bytes: 0,
        max_scope_slack: 0,
        unauthorized: 0,
        nested: 0,
        scope_violations: 0,
        post_reject: 0,
    }) };
}

struct TrackingAllocator;

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_growth(layout.size());
        // SAFETY: the unchanged request is forwarded to the system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_growth(layout.size());
        // SAFETY: the unchanged request is forwarded to the system allocator.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: the matching deallocation is forwarded to the system allocator.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record_growth(new_size);
        // SAFETY: the unchanged request is forwarded to the system allocator.
        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

fn record_growth(bytes: usize) {
    if bytes == 0 {
        return;
    }
    let _ = ORACLE.try_with(|slot| {
        let mut state = slot.get();
        if !state.active {
            return;
        }
        let bytes = bytes as u64;
        state.requested_bytes = state.requested_bytes.saturating_add(bytes);
        if state.rejected {
            state.post_reject = state.post_reject.saturating_add(1);
        } else if state.scope_active && state.authorized >= bytes {
            state.authorized -= bytes;
        } else {
            state.unauthorized = state.unauthorized.saturating_add(1);
        }
        slot.set(state);
    });
}

struct AllocationGuard {
    resident_calls: AtomicUsize,
    consumed: AtomicU64,
    limit: Option<u64>,
    reject_at: Option<usize>,
}

impl AllocationGuard {
    fn counting() -> Self {
        Self {
            resident_calls: AtomicUsize::new(0),
            consumed: AtomicU64::new(0),
            limit: None,
            reject_at: None,
        }
    }

    fn limited(limit: u64) -> Self {
        Self {
            limit: Some(limit),
            ..Self::counting()
        }
    }

    fn rejecting(ordinal: usize) -> Self {
        Self {
            reject_at: Some(ordinal),
            ..Self::counting()
        }
    }
}

impl WorkGuard for AllocationGuard {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        if delta.resident_bytes == 0 {
            return Ok(());
        }
        let ordinal = self.resident_calls.fetch_add(1, Ordering::Relaxed) + 1;
        let consumed = self
            .consumed
            .load(Ordering::Relaxed)
            .saturating_add(delta.resident_bytes);
        if self.reject_at == Some(ordinal) {
            mark_rejected();
            return Err(OperationAbort::budget_exceeded(
                BudgetDimension::ResidentBytes,
                REJECT_LIMIT,
                REJECT_CONSUMED,
            ));
        }
        if self.limit.is_some_and(|limit| consumed > limit) {
            mark_rejected();
            return Err(OperationAbort::budget_exceeded(
                BudgetDimension::ResidentBytes,
                self.limit.unwrap_or(0),
                consumed,
            ));
        }
        self.consumed.store(consumed, Ordering::Relaxed);
        Ok(())
    }

    fn begin_allocation_scope(
        &self,
        delta: WorkDelta,
        allowed_slack: u64,
    ) -> Result<(), OperationAbort> {
        self.consume(delta)?;
        ORACLE.with(|slot| {
            let mut state = slot.get();
            if state.active {
                if state.scope_active {
                    state.nested = state.nested.saturating_add(1);
                }
                state.scope_active = true;
                state.authorized = delta.resident_bytes;
                state.allowed_slack = allowed_slack;
                state.authorized_bytes =
                    state.authorized_bytes.saturating_add(delta.resident_bytes);
                slot.set(state);
            }
        });
        Ok(())
    }

    fn end_allocation_scope(&self) {
        ORACLE.with(|slot| {
            let mut state = slot.get();
            if state.active {
                if !state.scope_active || state.authorized > state.allowed_slack {
                    state.scope_violations = state.scope_violations.saturating_add(1);
                }
                state.max_scope_slack = state.max_scope_slack.max(state.authorized);
                state.scope_active = false;
                state.authorized = 0;
                state.allowed_slack = 0;
                slot.set(state);
            }
        });
    }
}

fn mark_rejected() {
    ORACLE.with(|slot| {
        let mut state = slot.get();
        state.rejected = true;
        slot.set(state);
    });
}

#[derive(Clone, Copy, Debug)]
enum Shape {
    QtrbRead0,
    QtrbRead34,
    QtrbWrite0,
    QtrbWrite34,
    FlightDefinitions(usize),
    FlightStrings(usize),
    FlightFragments(usize),
}

impl Shape {
    fn label(self) -> String {
        format!("{self:?}")
    }

    fn bytes(self) -> Vec<u8> {
        match self {
            Self::QtrbRead0 => qtrb_shape(0, 1),
            Self::QtrbRead34 => qtrb_shape(34, 1),
            Self::QtrbWrite0 => qtrb_shape(1, 0),
            Self::QtrbWrite34 => qtrb_shape(1, 34),
            Self::FlightDefinitions(count) => flight_shape(FlightFamily::Definitions, count),
            Self::FlightStrings(count) => flight_shape(FlightFamily::Strings, count),
            Self::FlightFragments(count) => flight_shape(FlightFamily::Fragments, count),
        }
    }

    fn is_qtrb(self) -> bool {
        matches!(
            self,
            Self::QtrbRead0 | Self::QtrbRead34 | Self::QtrbWrite0 | Self::QtrbWrite34
        )
    }
}

struct Prepared {
    shape: Shape,
    source: Arc<ByteSource>,
    identity: SourceIdentity,
}

impl Prepared {
    fn new(shape: Shape) -> Self {
        let bytes = shape.bytes();
        let source_bytes = bytes.len() as u64;
        Self {
            shape,
            source: Arc::new(ByteSource::new(bytes)),
            identity: SourceIdentity {
                artifact: ArtifactDigest::new([0x7a; 32]),
                format: "untrusted".to_owned(),
                format_major: 0,
                format_minor: 0,
                source_bytes,
            },
        }
    }

    fn run(self, guard: &AllocationGuard) -> Result<DrainedProvider, ProviderError> {
        if self.shape.is_qtrb() {
            let provider = QtrbProvider::open(
                self.source,
                self.identity,
                OpenMode::RecoverablePartial,
                guard,
            )?;
            let boxed = {
                let _scope = AllocationScope::begin(guard, size_of::<QtrbProvider>() as u64, 0)?;
                Box::new(provider)
            };
            drain_provider(boxed, guard)
        } else {
            let provider = FlightProvider::open(self.source, self.identity, guard)?;
            let boxed = {
                let _scope = AllocationScope::begin(guard, size_of::<FlightProvider>() as u64, 0)?;
                Box::new(provider)
            };
            drain_provider(boxed, guard)
        }
    }
}

fn drain_provider(
    provider: Box<dyn TraceProvider>,
    guard: &AllocationGuard,
) -> Result<DrainedProvider, ProviderError> {
    let cursor_bytes = provider.cursor_resident_bytes()?;
    let mut cursor = {
        let _scope = AllocationScope::begin(guard, cursor_bytes, 0)?;
        provider.into_cursor()?
    };
    let mut events = Vec::new();
    while let Some(event) = cursor.next_event(guard)? {
        with_oracle_paused(|| events.push(event));
    }
    let summary = cursor.finish()?;
    Ok(DrainedProvider { events, summary })
}

#[derive(Debug)]
struct DrainedProvider {
    events: Vec<EventRecord>,
    summary: ProviderSummary,
}

fn with_oracle_paused<T>(operation: impl FnOnce() -> T) -> T {
    let active = ORACLE.with(|slot| {
        let mut state = slot.get();
        let active = state.active;
        state.active = false;
        slot.set(state);
        active
    });
    let output = operation();
    ORACLE.with(|slot| {
        let mut state = slot.get();
        state.active = active;
        slot.set(state);
    });
    output
}

fn oracle_run(
    shape: Shape,
    guard: &AllocationGuard,
) -> (Result<DrainedProvider, ProviderError>, OracleState) {
    let prepared = Prepared::new(shape);
    ORACLE.with(|slot| {
        slot.set(OracleState {
            active: true,
            ..OracleState::default()
        });
    });
    let result = prepared.run(guard);
    let state = ORACLE.with(|slot| {
        let mut state = slot.get();
        state.active = false;
        slot.set(state);
        state
    });
    (result, state)
}

fn assert_clean(state: OracleState, total_resident_work: u64, label: &str) {
    assert_eq!(state.unauthorized, 0, "{label}: unauthorized allocation");
    assert_eq!(state.nested, 0, "{label}: nested allocation scope");
    assert_eq!(state.scope_violations, 0, "{label}: scope slack/leak");
    assert!(!state.scope_active, "{label}: live allocation scope");
    assert!(
        state.requested_bytes <= total_resident_work,
        "{label}: allocator requested more than authorized"
    );
    assert!(
        state.max_scope_slack <= 15,
        "{label}: operation slack exceeded alignment bound: {}",
        state.max_scope_slack
    );
    assert!(
        total_resident_work.saturating_mul(10) <= state.requested_bytes.saturating_mul(11),
        "{label}: synthetic authorization {} requested {} slack {}",
        total_resident_work,
        state.requested_bytes,
        state.max_scope_slack,
    );
}

fn assert_exact_abort(error: &ProviderError, limit: u64, consumed: Option<u64>, label: &str) {
    match error.operation_abort() {
        Some(OperationAbort::BudgetExceeded {
            dimension: BudgetDimension::ResidentBytes,
            limit: actual_limit,
            consumed: actual_consumed,
        }) => {
            assert_eq!(*actual_limit, limit, "{label}: limit");
            if let Some(consumed) = consumed {
                assert_eq!(*actual_consumed, consumed, "{label}: consumed");
            } else {
                assert!(
                    *actual_consumed > limit,
                    "{label}: consumed did not exceed limit"
                );
            }
        }
        other => panic!("{label}: wrong abort {other:?}"),
    }
}

fn exercise_shape(shape: Shape) -> (u64, u64) {
    let label = shape.label();
    let count = AllocationGuard::counting();
    let (result, state) = oracle_run(shape, &count);
    let drained = result.unwrap_or_else(|error| panic!("{label}: baseline failed: {error}"));
    let exact = count.consumed.load(Ordering::Relaxed);
    assert_clean(state, exact, &label);
    assert_eq!(
        exact, state.authorized_bytes,
        "{label}: resident work was consumed outside an allocation scope"
    );
    assert_shape_semantics(shape, &drained);
    let measurement = (exact, state.requested_bytes);
    let ordinals = count.resident_calls.load(Ordering::Relaxed);
    assert!(exact > 0, "{label}: no resident work");
    assert!(ordinals > 0, "{label}: no resident ordinals");

    let exact_guard = AllocationGuard::limited(exact);
    let (result, state) = oracle_run(shape, &exact_guard);
    let drained = result.unwrap_or_else(|error| panic!("{label}: exact budget failed: {error}"));
    let exact_consumed = exact_guard.consumed.load(Ordering::Relaxed);
    assert_clean(state, exact_consumed, &format!("{label} exact"));
    assert_eq!(exact_consumed, exact);
    assert_eq!(exact_consumed, state.authorized_bytes);
    assert_shape_semantics(shape, &drained);

    let below = exact - 1;
    let below_guard = AllocationGuard::limited(below);
    let (result, state) = oracle_run(shape, &below_guard);
    let error = result.expect_err("one-byte-low resident budget succeeded");
    assert_exact_abort(&error, below, None, &format!("{label} budget-1"));
    assert_eq!(
        state.post_reject, 0,
        "{label}: allocation after budget rejection"
    );
    assert!(
        !state.scope_active,
        "{label}: scope leaked after budget rejection"
    );
    assert_eq!(
        state.unauthorized, 0,
        "{label}: unauthorized before budget rejection"
    );
    assert_eq!(
        state.nested, 0,
        "{label}: nested scope before budget rejection"
    );
    assert_eq!(
        state.scope_violations, 0,
        "{label}: scope violation before budget rejection"
    );

    for reject_at in 1..=ordinals {
        let reject = AllocationGuard::rejecting(reject_at);
        let (result, state) = oracle_run(shape, &reject);
        let error = result.unwrap_err_or_else(|| panic!("{label} ordinal {reject_at} succeeded"));
        assert_exact_abort(
            &error,
            REJECT_LIMIT,
            Some(REJECT_CONSUMED),
            &format!("{label} ordinal {reject_at}"),
        );
        assert_eq!(
            state.post_reject, 0,
            "{label} ordinal {reject_at}: allocation after rejection"
        );
        assert!(
            !state.scope_active,
            "{label} ordinal {reject_at}: leaked scope"
        );
        assert_eq!(
            state.unauthorized, 0,
            "{label} ordinal {reject_at}: unauthorized allocation"
        );
        assert_eq!(state.nested, 0, "{label} ordinal {reject_at}: nested scope");
        assert_eq!(
            state.scope_violations, 0,
            "{label} ordinal {reject_at}: scope violation"
        );
    }
    measurement
}

fn assert_shape_semantics(shape: Shape, drained: &DrainedProvider) {
    let DrainedProvider { events, summary } = drained;
    assert_eq!(summary.counters.events_emitted, events.len() as u64);
    assert_eq!(summary.counters.opaque_records, 0);
    assert_eq!(summary.counters.damaged_records, 0);
    assert!(events.iter().all(|event| {
        event.provenance != Provenance::Damaged
            && !matches!(event.payload, EventPayload::OpaqueOptional(_))
    }));

    match shape {
        Shape::QtrbRead0 => assert_qtrb_semantics(events, 0, 1),
        Shape::QtrbRead34 => assert_qtrb_semantics(events, 34, 1),
        Shape::QtrbWrite0 => assert_qtrb_semantics(events, 1, 0),
        Shape::QtrbWrite34 => assert_qtrb_semantics(events, 1, 34),
        Shape::FlightDefinitions(count) => {
            assert_eq!(events.len(), count + 2);
            assert_flight_base(events);
            let definitions = events
                .iter()
                .filter_map(|event| match &event.payload {
                    EventPayload::InstructionDefinition(definition) => Some(definition),
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert_eq!(definitions.len(), count);
            assert!(
                definitions.iter().all(|definition| {
                    definition.reads.is_empty() && definition.writes.is_empty()
                })
            );
            for (index, definition) in definitions.iter().enumerate() {
                assert_eq!(definition.definition_id as usize, index + 1);
            }
        }
        Shape::FlightStrings(count) => {
            assert_eq!(events.len(), count + 2);
            assert_flight_base(events);
            let strings = events
                .iter()
                .filter_map(|event| match &event.payload {
                    EventPayload::StringDefinition(value) => Some(value),
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert_eq!(strings.len(), count);
            for (index, value) in strings.iter().enumerate() {
                let id = u32::try_from(index + 1).expect("bounded string ID");
                assert_eq!(value.id, id);
                assert_eq!(value.bytes, format!("string-{id}").as_bytes());
            }
        }
        Shape::FlightFragments(fragment_count) => {
            assert_eq!(events.len(), 2 + 3 + fragment_count / 2);
            assert_flight_base(events);
            let strings = events
                .iter()
                .filter_map(|event| match &event.payload {
                    EventPayload::StringDefinition(value) => Some(value),
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert_eq!(strings.len(), 3, "fixed fragment string definitions");
            assert_eq!(strings[0].bytes, b"name");
            assert_eq!(strings[1].bytes, b"a");
            assert_eq!(strings[2].bytes, b"b");
            let semantics = events
                .iter()
                .filter_map(|event| match &event.payload {
                    EventPayload::SemanticRule(value) => Some(value),
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert_eq!(semantics.len(), fragment_count / 2);
            assert_eq!(
                semantics
                    .iter()
                    .map(|semantic| semantic.fragment_sequences.len())
                    .sum::<usize>(),
                fragment_count
            );
            assert!(semantics.iter().all(|semantic| {
                semantic.category.is_none()
                    && semantic.name == "name"
                    && semantic.detail == "ab"
                    && semantic.fragment_sequences.len() == 2
            }));
        }
    }
}

fn assert_flight_base(events: &[EventRecord]) {
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.payload, EventPayload::Begin(_)))
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.payload, EventPayload::RegisterCheckpoint(_)))
            .count(),
        1
    );
}

fn assert_qtrb_semantics(events: &[EventRecord], reads: usize, writes: usize) {
    assert_eq!(events.len(), 4);
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.payload, EventPayload::Begin(_)))
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.payload, EventPayload::ModuleDefinition(_)))
            .count(),
        1
    );
    let definition = events
        .iter()
        .find_map(|event| match &event.payload {
            EventPayload::InstructionDefinition(definition) => Some(definition),
            _ => None,
        })
        .expect("decoded instruction definition");
    assert_eq!(definition.reads.len(), reads);
    assert_eq!(definition.writes.len(), writes);
    assert_eq!(definition.read_mask, mask(reads));
    assert_eq!(definition.write_mask, mask(writes));
    let instruction = events
        .iter()
        .find_map(|event| match &event.payload {
            EventPayload::Instruction(instruction) => Some(instruction),
            _ => None,
        })
        .expect("decoded instruction event");
    assert_eq!(instruction.read_before.len(), reads);
    assert_eq!(instruction.write_after.len(), writes);
}

trait ResultExt<T, E> {
    fn unwrap_err_or_else(self, success: impl FnOnce() -> E) -> E;
}

impl<T, E> ResultExt<T, E> for Result<T, E> {
    fn unwrap_err_or_else(self, success: impl FnOnce() -> E) -> E {
        match self {
            Ok(_) => success(),
            Err(error) => error,
        }
    }
}

#[test]
fn qtrb_zero_and_full_read_write_shapes_use_only_actual_allocation_work() {
    for shape in [
        Shape::QtrbRead0,
        Shape::QtrbRead34,
        Shape::QtrbWrite0,
        Shape::QtrbWrite34,
    ] {
        exercise_shape(shape);
    }
}

#[test]
fn total_resident_accounting_detects_a_direct_precharge() {
    let guard = AllocationGuard::counting();
    ORACLE.with(|slot| {
        slot.set(OracleState {
            active: true,
            ..OracleState::default()
        });
    });
    guard
        .consume(WorkDelta {
            resident_bytes: 1,
            ..WorkDelta::default()
        })
        .expect("direct resident precharge");
    let _scope = AllocationScope::begin(&guard, 8, 0).expect("scoped allocation work");
    let state = ORACLE.with(Cell::get);
    ORACLE.with(|slot| slot.set(OracleState::default()));

    assert_ne!(
        guard.consumed.load(Ordering::Relaxed),
        state.authorized_bytes,
        "a direct resident precharge must not satisfy the scoped-accounting invariant"
    );
}

#[test]
fn flight_high_cardinality_families_scale_linearly_through_public_provider() {
    for family in [
        FlightFamily::Definitions,
        FlightFamily::Strings,
        FlightFamily::Fragments,
    ] {
        let mut measurements = Vec::new();
        for count in [8, 16, 32] {
            measurements.push(exercise_shape(family.shape(count)));
            let mut terminal = 0;
            while terminal < count {
                terminal = checked_provider_geometric_capacity(terminal, terminal + 1, 4)
                    .expect("production geometric capacity");
            }
            assert!(
                terminal < 2 * count,
                "{family:?}: terminal capacity {terminal}"
            );
        }
        for field in [0, 1] {
            let n = [measurements[0].0, measurements[0].1][field];
            let two_n = [measurements[1].0, measurements[1].1][field];
            let four_n = [measurements[2].0, measurements[2].1][field];
            let first_slope = two_n.saturating_sub(n);
            let second_slope = four_n.saturating_sub(two_n);
            let expected_second_slope = first_slope.saturating_mul(2);
            let allowance = 512_u64;
            assert!(first_slope > 0, "{family:?}: flat N→2N allocation slope");
            assert!(
                second_slope.abs_diff(expected_second_slope) <= allowance,
                "{family:?}: allocation slope {first_slope} then {second_slope}, expected {expected_second_slope} ± {allowance} bytes of alignment/hash slack"
            );
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum FlightFamily {
    Definitions,
    Strings,
    Fragments,
}

impl FlightFamily {
    const fn shape(self, count: usize) -> Shape {
        match self {
            Self::Definitions => Shape::FlightDefinitions(count),
            Self::Strings => Shape::FlightStrings(count),
            Self::Fragments => Shape::FlightFragments(count),
        }
    }
}

fn qtrb_shape(read_count: usize, write_count: usize) -> Vec<u8> {
    let mut bytes = qtrb_header();
    bytes.extend(qtrb_record(1, 0, &qtrb_begin_payload()));
    bytes.extend(qtrb_record(2, 0, &qtrb_module_payload()));
    bytes.extend(qtrb_record(
        3,
        0,
        &qtrb_definition_payload(7, read_count, write_count),
    ));
    bytes.extend(qtrb_record(
        4,
        0,
        &qtrb_instruction_payload(7, read_count, write_count),
    ));
    bytes
}

fn qtrb_header() -> Vec<u8> {
    let mut bytes = Vec::with_capacity(QTRB_HEADER_BYTES);
    bytes.extend_from_slice(b"QTRB");
    bytes.extend_from_slice(&[1, 2, 1, 8, 2, 0]);
    bytes.extend_from_slice(&(QTRB_HEADER_BYTES as u16).to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes
}

fn qtrb_record(kind: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(QTRB_RECORD_HEADER_BYTES + payload.len());
    bytes.extend_from_slice(&kind.to_le_bytes());
    bytes.extend_from_slice(&flags.to_le_bytes());
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn qtrb_string(value: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(2 + value.len());
    bytes.extend_from_slice(&(value.len() as u16).to_le_bytes());
    bytes.extend_from_slice(value);
    bytes
}

fn qtrb_begin_payload() -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&0x7100_0000_u64.to_le_bytes());
    payload.extend_from_slice(&0x100_u64.to_le_bytes());
    payload.extend_from_slice(&0x7100_0100_u64.to_le_bytes());
    payload.extend_from_slice(&4242_u32.to_le_bytes());
    payload.extend_from_slice(&7_u32.to_le_bytes());
    payload.extend_from_slice(&[2, 0]);
    payload.extend_from_slice(&4096_u64.to_le_bytes());
    payload.extend_from_slice(&1_u64.to_le_bytes());
    payload.extend(qtrb_string(b"shape"));
    payload.extend(qtrb_string(b"libtarget.so"));
    payload
}

fn qtrb_module_payload() -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&1_u32.to_le_bytes());
    payload.extend_from_slice(&0x7100_0000_u64.to_le_bytes());
    payload.extend(qtrb_string(b"libtarget.so"));
    payload
}

fn qtrb_definition_payload(id: u32, reads: usize, writes: usize) -> Vec<u8> {
    let read_mask = mask(reads);
    let write_mask = mask(writes);
    let mut payload = Vec::new();
    payload.extend_from_slice(&id.to_le_bytes());
    payload.extend_from_slice(&0xd503_201f_u32.to_le_bytes());
    payload.extend_from_slice(&read_mask.to_le_bytes());
    payload.extend_from_slice(&write_mask.to_le_bytes());
    payload.extend_from_slice(&0_i64.to_le_bytes());
    payload.extend_from_slice(&0_u32.to_le_bytes());
    payload.extend_from_slice(&[0, 0, 0, 0]);
    payload.extend(qtrb_string(b"nop"));
    payload.extend(qtrb_string(b""));
    payload.extend(qtrb_string(b"nop"));
    append_register_definitions(&mut payload, reads, b'r');
    append_register_definitions(&mut payload, writes, b'w');
    payload
}

fn append_register_definitions(output: &mut Vec<u8>, count: usize, prefix: u8) {
    for slot in 0..count {
        output.push(8);
        output.extend(qtrb_string(&[prefix, b'0' + (slot % 10) as u8]));
    }
}

fn qtrb_instruction_payload(id: u32, reads: usize, writes: usize) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&1_u64.to_le_bytes());
    payload.extend_from_slice(&1_u32.to_le_bytes());
    payload.extend_from_slice(&0x20_u64.to_le_bytes());
    payload.extend_from_slice(&id.to_le_bytes());
    payload.push(reads as u8);
    payload.push(writes as u8);
    for value in 0..reads + writes {
        payload.extend_from_slice(&(value as u64).to_le_bytes());
    }
    payload
}

const fn mask(count: usize) -> u64 {
    if count == 0 { 0 } else { (1_u64 << count) - 1 }
}

fn flight_shape(family: FlightFamily, count: usize) -> Vec<u8> {
    assert!(matches!(count, 8 | 16 | 32));
    let mut sequence = 1_u64;
    let mut records = vec![flight_record(1, sequence, &flight_begin_payload(), 0, 1)];
    sequence += 1;
    records.push(flight_record(
        9,
        sequence,
        &flight_checkpoint_payload(),
        1,
        1,
    ));
    sequence += 1;
    match family {
        FlightFamily::Definitions => {
            for id in 1..=count as u32 {
                let nested = qtrb_record(3, 0, &qtrb_definition_payload(id, 0, 0));
                records.push(flight_record(4, sequence, &nested, 1, 1));
                sequence += 1;
            }
        }
        FlightFamily::Strings => {
            for id in 1..=count as u32 {
                records.push(flight_record(
                    6,
                    sequence,
                    &flight_string_payload(id, format!("string-{id}").as_bytes()),
                    3,
                    1,
                ));
                sequence += 1;
            }
        }
        FlightFamily::Fragments => {
            for (id, value) in [(1, b"name".as_slice()), (2, b"a"), (3, b"b")] {
                records.push(flight_record(
                    6,
                    sequence,
                    &flight_string_payload(id, value),
                    3,
                    1,
                ));
                sequence += 1;
            }
            for index in 0..count {
                let event_id = (index / 2 + 1) as u64;
                let detail_id = if index % 2 == 0 { 2 } else { 3 };
                let payload = flight_fragment_payload(event_id, index % 2, 2, 1, detail_id);
                records.push(flight_record(7, sequence, &payload, 4, 1));
                sequence += 1;
            }
        }
    }
    let first = 1;
    let last = sequence - 1;
    let chunk = flight_chunk(0, 7, 1, &records);
    flight_artifact(flight_directory(7, first, last, 0, 1), chunk)
}

fn flight_begin_payload() -> Vec<u8> {
    let target = b"libtarget.so";
    let scene = b"shape";
    let mut output = Vec::new();
    output.extend_from_slice(&[2, 8]);
    output.extend_from_slice(&(target.len() as u16).to_le_bytes());
    output.extend_from_slice(&(scene.len() as u16).to_le_bytes());
    output.extend_from_slice(&0_u16.to_le_bytes());
    output.extend_from_slice(&4242_u32.to_le_bytes());
    output.extend_from_slice(&7_u32.to_le_bytes());
    output.extend_from_slice(&0x7100_0000_u64.to_le_bytes());
    output.extend_from_slice(&0x100_u64.to_le_bytes());
    output.extend_from_slice(&0x7100_0100_u64.to_le_bytes());
    output.extend_from_slice(target);
    output.extend_from_slice(scene);
    output
}

fn flight_checkpoint_payload() -> Vec<u8> {
    let mut output = Vec::with_capacity(34 * size_of::<u64>());
    for value in 0_u64..34 {
        output.extend_from_slice(&value.to_le_bytes());
    }
    output
}

fn flight_string_payload(id: u32, value: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(&id.to_le_bytes());
    output.extend_from_slice(&(value.len() as u32).to_le_bytes());
    output.extend_from_slice(value);
    output
}

fn flight_fragment_payload(
    event_id: u64,
    index: usize,
    count: u16,
    name_id: u32,
    detail_id: u32,
) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(&event_id.to_le_bytes());
    output.extend_from_slice(&2_u32.to_le_bytes());
    output.extend_from_slice(&(index as u16).to_le_bytes());
    output.extend_from_slice(&count.to_le_bytes());
    output.extend_from_slice(&name_id.to_le_bytes());
    output.extend_from_slice(&detail_id.to_le_bytes());
    output
}

fn flight_record(kind: u16, sequence: u64, payload: &[u8], flags: u16, generation: u32) -> Vec<u8> {
    let total = FLIGHT_RECORD_HEADER_BYTES + payload.len();
    let storage = align(total, 8);
    let mut output = vec![0; storage];
    put_u16(&mut output, 0, kind);
    put_u16(&mut output, 2, flags);
    put_u32(&mut output, 4, total as u32);
    put_u64(&mut output, 8, sequence);
    output[FLIGHT_RECORD_HEADER_BYTES..total].copy_from_slice(payload);
    let mut checksum_input = output[..16].to_vec();
    checksum_input.extend_from_slice(&output[FLIGHT_RECORD_HEADER_BYTES..total]);
    put_u32(&mut output, 16, fnv32(&checksum_input));
    put_u32(
        &mut output,
        20,
        FLIGHT_RECORD_COMMIT ^ total as u32 ^ generation,
    );
    output
}

fn flight_chunk(index: u32, tid: u32, generation: u32, records: &[Vec<u8>]) -> Vec<u8> {
    let committed = records.iter().map(Vec::len).sum::<usize>();
    assert!(FLIGHT_CHUNK_HEADER_BYTES + committed <= FLIGHT_CHUNK_BYTES);
    let mut output = vec![0; FLIGHT_CHUNK_BYTES];
    put_u32(&mut output, 0, FLIGHT_MAGIC);
    put_u16(&mut output, 4, FLIGHT_VERSION);
    put_u16(&mut output, 6, FLIGHT_CHUNK_HEADER_BYTES as u16);
    put_u32(&mut output, 8, index);
    put_u32(&mut output, 12, 2);
    put_u32(&mut output, 16, tid);
    put_u32(&mut output, 20, generation);
    put_u64(&mut output, 24, get_u64(&records[0], 8));
    put_u64(
        &mut output,
        32,
        get_u64(records.last().expect("last record"), 8),
    );
    put_u32(&mut output, 40, committed as u32);
    put_u32(&mut output, 44, records.len() as u32);
    let mut cursor = FLIGHT_CHUNK_HEADER_BYTES;
    for record in records {
        output[cursor..cursor + record.len()].copy_from_slice(record);
        cursor += record.len();
    }
    let checksum = fnv32(&output[FLIGHT_CHUNK_HEADER_BYTES..cursor]);
    put_u32(&mut output, 48, checksum);
    output
}

fn flight_directory(
    tid: u32,
    first: u64,
    last: u64,
    chunk_index: u32,
    generation: u32,
) -> [u8; FLIGHT_DIRECTORY_ENTRY_BYTES] {
    let mut output = [0; FLIGHT_DIRECTORY_ENTRY_BYTES];
    put_u32(&mut output, 0, tid);
    put_u32(&mut output, 4, 1);
    put_u64(&mut output, 8, first);
    put_u64(&mut output, 16, last);
    put_u32(&mut output, 24, chunk_index);
    put_u32(&mut output, 28, generation);
    output
}

fn flight_artifact(directory: [u8; FLIGHT_DIRECTORY_ENTRY_BYTES], chunk: Vec<u8>) -> Vec<u8> {
    let directory_offset = FLIGHT_SUPERBLOCK_BYTES;
    let emergency_offset = align(
        directory_offset + FLIGHT_DIRECTORY_ENTRY_BYTES,
        FLIGHT_EMERGENCY_SLOT_BYTES,
    );
    let chunk_offset = align(
        emergency_offset + 2 * FLIGHT_EMERGENCY_SLOT_BYTES,
        FLIGHT_CHUNK_BYTES,
    );
    let artifact_bytes = chunk_offset + FLIGHT_CHUNK_BYTES;
    let mut output = vec![0; artifact_bytes];
    put_u32(&mut output, 0, FLIGHT_MAGIC);
    put_u16(&mut output, 4, FLIGHT_VERSION);
    output[6] = 1;
    output[7] = 8;
    put_u16(&mut output, 8, FLIGHT_SUPERBLOCK_BYTES as u16);
    put_u64(&mut output, 16, artifact_bytes as u64);
    put_u64(&mut output, 24, directory_offset as u64);
    put_u32(&mut output, 32, FLIGHT_DIRECTORY_ENTRY_BYTES as u32);
    put_u32(&mut output, 36, 1);
    put_u64(&mut output, 40, chunk_offset as u64);
    put_u32(&mut output, 48, FLIGHT_CHUNK_BYTES as u32);
    put_u32(&mut output, 52, 1);
    put_u64(&mut output, 56, emergency_offset as u64);
    put_u32(&mut output, 64, FLIGHT_EMERGENCY_SLOT_BYTES as u32);
    put_u32(&mut output, 68, 2);
    put_u64(&mut output, 80, 1);
    put_u32(&mut output, 88, 4242);
    put_u32(&mut output, 92, 17);
    let target = b"libtarget.so";
    put_u16(&mut output, 96, target.len() as u16);
    output[98..98 + target.len()].copy_from_slice(target);
    output[directory_offset..directory_offset + FLIGHT_DIRECTORY_ENTRY_BYTES]
        .copy_from_slice(&directory);
    output[chunk_offset..chunk_offset + FLIGHT_CHUNK_BYTES].copy_from_slice(&chunk);
    output
}

fn align(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

fn fnv32(bytes: &[u8]) -> u32 {
    bytes.iter().fold(2_166_136_261_u32, |value, byte| {
        (value ^ u32::from(*byte)).wrapping_mul(16_777_619)
    })
}

fn put_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn get_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(input[offset..offset + 8].try_into().expect("u64 field"))
}
