use std::{
    alloc::{Layout, alloc},
    collections::HashMap,
    ffi::{OsStr, OsString},
    hash::{BuildHasher, Hash},
    mem::{align_of, size_of},
    os::unix::ffi::{OsStrExt, OsStringExt},
};

use qtrace_provider::{AllocationScope, EventKind, OperationAbort, WorkGuard};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AllocationFailure {
    Aborted(OperationAbort),
    Overflow(&'static str),
    Failed(&'static str),
}

impl From<OperationAbort> for AllocationFailure {
    fn from(value: OperationAbort) -> Self {
        Self::Aborted(value)
    }
}

pub(crate) fn checked_array_bytes<T>(count: usize) -> Result<u64, AllocationFailure> {
    count
        .checked_mul(size_of::<T>())
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(AllocationFailure::Overflow("allocation byte count"))
}

fn geometric_capacity(
    current: usize,
    required: usize,
    minimum: usize,
    label: &'static str,
) -> Result<usize, AllocationFailure> {
    let doubled = current
        .checked_mul(2)
        .ok_or(AllocationFailure::Overflow(label))?;
    Ok(required.max(minimum.max(doubled)))
}

pub(crate) fn scope(
    guard: &dyn WorkGuard,
    resident_bytes: u64,
    allowed_slack: u64,
) -> Result<AllocationScope<'_>, AllocationFailure> {
    AllocationScope::begin(guard, resident_bytes, allowed_slack).map_err(AllocationFailure::Aborted)
}

pub(crate) fn try_reserve_vec<T>(
    values: &mut Vec<T>,
    additional: usize,
    guard: &dyn WorkGuard,
    label: &'static str,
) -> Result<(), AllocationFailure> {
    let required = values
        .len()
        .checked_add(additional)
        .ok_or(AllocationFailure::Overflow(label))?;
    if required <= values.capacity() {
        return Ok(());
    }
    let new_capacity = geometric_capacity(values.capacity(), required, 4, label)?;
    let _scope = scope(guard, checked_array_bytes::<T>(new_capacity)?, 0)?;
    values
        .try_reserve_exact(new_capacity - values.len())
        .map_err(|_| AllocationFailure::Failed(label))
}

pub(crate) fn try_reserve_string(
    value: &mut String,
    additional: usize,
    guard: &dyn WorkGuard,
    label: &'static str,
) -> Result<(), AllocationFailure> {
    let required = value
        .len()
        .checked_add(additional)
        .ok_or(AllocationFailure::Overflow(label))?;
    if required <= value.capacity() {
        return Ok(());
    }
    let new_capacity = geometric_capacity(value.capacity(), required, 8, label)?;
    let _scope = scope(
        guard,
        u64::try_from(new_capacity).map_err(|_| AllocationFailure::Overflow(label))?,
        0,
    )?;
    value
        .try_reserve_exact(new_capacity - value.len())
        .map_err(|_| AllocationFailure::Failed(label))
}

pub(crate) fn try_copy_string(
    value: &str,
    guard: &dyn WorkGuard,
    label: &'static str,
) -> Result<String, AllocationFailure> {
    let mut output = String::new();
    try_reserve_string(&mut output, value.len(), guard, label)?;
    output.push_str(value);
    Ok(output)
}

pub(crate) fn try_hex_name(
    prefix: &str,
    bytes: &[u8],
    suffix: &str,
    guard: &dyn WorkGuard,
    label: &'static str,
) -> Result<String, AllocationFailure> {
    let length = bytes
        .len()
        .checked_mul(2)
        .and_then(|length| length.checked_add(prefix.len()))
        .and_then(|length| length.checked_add(suffix.len()))
        .ok_or(AllocationFailure::Overflow(label))?;
    let mut output = String::new();
    try_reserve_string(&mut output, length, guard, label)?;
    output.push_str(prefix);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output.push_str(suffix);
    Ok(output)
}

pub(crate) fn try_copy_os_string(
    value: &OsStr,
    guard: &dyn WorkGuard,
    label: &'static str,
) -> Result<OsString, AllocationFailure> {
    let mut bytes = Vec::new();
    try_reserve_vec(&mut bytes, value.as_bytes().len(), guard, label)?;
    bytes.extend_from_slice(value.as_bytes());
    Ok(OsString::from_vec(bytes))
}

pub(crate) fn try_box<T>(
    value: T,
    guard: &dyn WorkGuard,
    label: &'static str,
) -> Result<Box<T>, AllocationFailure> {
    let layout = Layout::new::<T>();
    let _scope = scope(
        guard,
        u64::try_from(layout.size()).map_err(|_| AllocationFailure::Overflow(label))?,
        0,
    )?;
    if layout.size() == 0 {
        return Ok(Box::new(value));
    }
    // SAFETY: `layout` is the exact layout for `T`; null is handled before writing, and ownership
    // of the initialized allocation is immediately transferred to `Box<T>`.
    let pointer = unsafe { alloc(layout).cast::<T>() };
    if pointer.is_null() {
        return Err(AllocationFailure::Failed(label));
    }
    // SAFETY: `pointer` denotes a valid, properly aligned allocation for one `T`.
    unsafe {
        pointer.write(value);
        Ok(Box::from_raw(pointer))
    }
}

fn hash_table_bound<K, V>(len: usize, additional: usize) -> Result<(u64, u64), AllocationFailure> {
    let required = len
        .checked_add(additional)
        .ok_or(AllocationFailure::Overflow("hash table entry count"))?;
    if required == 0 {
        return Ok((0, 0));
    }
    // hashbrown uses four buckets for 1--3 entries, eight for 4--7, then keeps at
    // most a 7/8 load. Its single allocation is the bucket array, alignment
    // padding, one control byte per bucket, and one SIMD control group.
    let buckets = if required < 4 {
        4
    } else if required < 8 {
        8
    } else {
        required
            .checked_mul(8)
            .and_then(|scaled| scaled.checked_add(6))
            .map(|scaled| scaled / 7)
            .and_then(usize::checked_next_power_of_two)
            .ok_or(AllocationFailure::Overflow("hash table bucket count"))?
    };
    let bucket_bytes = buckets
        .checked_mul(size_of::<(K, V)>())
        .ok_or(AllocationFailure::Overflow("hash table bucket bytes"))?;
    let alignment_slack = align_of::<(K, V)>().saturating_sub(1);
    let bytes = bucket_bytes
        .checked_add(alignment_slack)
        .and_then(|bytes| bytes.checked_add(buckets))
        .and_then(|bytes| bytes.checked_add(16))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(AllocationFailure::Overflow("hash table byte count"))?;
    Ok((
        bytes,
        u64::try_from(alignment_slack)
            .map_err(|_| AllocationFailure::Overflow("hash table alignment slack"))?,
    ))
}

pub(crate) fn try_reserve_hash_map<K, V, S>(
    values: &mut HashMap<K, V, S>,
    additional: usize,
    guard: &dyn WorkGuard,
    label: &'static str,
) -> Result<(), AllocationFailure>
where
    K: Eq + Hash,
    S: BuildHasher,
{
    if additional == 0 || values.capacity().saturating_sub(values.len()) >= additional {
        return Ok(());
    }
    let (bytes, allowed_slack) = hash_table_bound::<K, V>(values.len(), additional)?;
    let _scope = scope(guard, bytes, allowed_slack)?;
    values
        .try_reserve(additional)
        .map_err(|_| AllocationFailure::Failed(label))
}

pub(crate) fn manifest_decode_upper_bound(encoded_bytes: usize) -> Result<u64, AllocationFailure> {
    encoded_bytes
        .checked_mul(32)
        .and_then(|bytes| bytes.checked_add(4096))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(AllocationFailure::Overflow("JSON decode allocation bound"))
}

/// Conservative live-allocation bound for serde's closed `EventPayload` representation.
///
/// Derived payloads allocate only Strings and Vecs. Canonical JSON contributes at least one byte
/// per string byte and at least two bytes per scalar vector element (value plus separator). Vec
/// geometric growth is below twice its final capacity. The semantic family has the worst ratio:
/// a `Vec<u64>` can therefore use fewer than 8 decoded bytes per encoded byte, with its Strings
/// adding at most one more. Ten leaves headroom for serde's String growth. Other families have
/// larger object keys per element and use the tighter ratios below. There is deliberately no
/// fixed per-row allowance.
pub(crate) fn payload_decode_upper_bound(
    kind: EventKind,
    encoded_bytes: usize,
) -> Result<u64, AllocationFailure> {
    let multiplier = match kind {
        EventKind::SemanticCall | EventKind::SemanticRule | EventKind::SemanticError => 10,
        EventKind::InstructionDefinition | EventKind::Instruction => 5,
        EventKind::Begin
        | EventKind::Memory
        | EventKind::RegisterCheckpoint
        | EventKind::RegisterDelta => 3,
        EventKind::ModuleDefinition
        | EventKind::Termination
        | EventKind::StringDefinition
        | EventKind::OpaqueOptional => 4,
        EventKind::ThreadLifecycle
        | EventKind::Syscall
        | EventKind::Signal
        | EventKind::SignalHandlerBoundary
        | EventKind::CoverageGap
        | EventKind::Discontinuity => 1,
    };
    encoded_bytes
        .checked_mul(multiplier)
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(AllocationFailure::Overflow(
            "event payload decode allocation bound",
        ))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{
        alloc::{GlobalAlloc, Layout, System},
        cell::Cell,
        panic::{AssertUnwindSafe, catch_unwind},
        sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    };

    use super::{payload_decode_upper_bound, scope};
    use qtrace_provider::{
        BeginMetadata, CaptureBytes, CompletenessCause, CompletenessRange, CoverageGap,
        Discontinuity, DiscontinuityCause, EventKind, EventPayload, Instruction,
        InstructionDefinition, Memory, MemoryAddressMode, MemoryDirection, MemoryOperand,
        ModuleDefinition, OpaqueOptionalRecord, OperationAbort, PcRelativeKind, Provenance,
        RegisterCheckpoint, RegisterDefinition, RegisterDelta, RegisterExtend, RegisterObservation,
        RegisterSlot, RegisterValue, SemanticEvent, Signal, SignalHandlerBoundary,
        SignalHandlerPhase, StringDefinition, Syscall, Termination, ThreadLifecycle,
        ThreadLifecyclePhase, WorkDelta, WorkGuard,
    };

    #[derive(Clone, Copy, Default)]
    struct DecodeOracle {
        active: bool,
        scope_active: bool,
        credit: u64,
        allowed_slack: u64,
        unauthorized: u64,
        scope_violations: u64,
        nested_scopes: u64,
        sizes: [usize; 16],
        ordinals: [usize; 16],
        size_len: usize,
        ordinal: usize,
    }

    thread_local! {
        static DECODE_ORACLE: Cell<DecodeOracle> = const { Cell::new(DecodeOracle {
            active: false,
            scope_active: false,
            credit: 0,
            allowed_slack: 0,
            unauthorized: 0,
            scope_violations: 0,
            nested_scopes: 0,
            sizes: [0; 16],
            ordinals: [0; 16],
            size_len: 0,
            ordinal: 0,
        }) };
    }

    struct DecodeAllocator;

    unsafe impl GlobalAlloc for DecodeAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            record_decode_growth(layout.size());
            // SAFETY: forwards the unchanged layout to the system allocator.
            unsafe { System.alloc(layout) }
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            record_decode_growth(layout.size());
            // SAFETY: forwards the unchanged layout to the system allocator.
            unsafe { System.alloc_zeroed(layout) }
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            // SAFETY: forwards the matching deallocation to the system allocator.
            unsafe { System.dealloc(pointer, layout) }
        }

        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            record_decode_growth(new_size);
            // SAFETY: forwards the matching reallocation to the system allocator.
            unsafe { System.realloc(pointer, layout, new_size) }
        }
    }

    #[global_allocator]
    static DECODE_ALLOCATOR: DecodeAllocator = DecodeAllocator;

    fn record_decode_growth(bytes: usize) {
        if bytes == 0 {
            return;
        }
        let _ = DECODE_ORACLE.try_with(|slot| {
            let mut state = slot.get();
            if state.active {
                let bytes = bytes as u64;
                if state.scope_active && bytes <= state.credit {
                    state.credit -= bytes;
                } else {
                    state.unauthorized += 1;
                    if state.size_len < state.sizes.len() {
                        state.sizes[state.size_len] = bytes as usize;
                        state.ordinals[state.size_len] = state.ordinal;
                        state.size_len += 1;
                    }
                }
                slot.set(state);
            }
        });
    }

    pub(crate) struct DecodeGuard;

    impl WorkGuard for DecodeGuard {
        fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
            DECODE_ORACLE.with(|slot| {
                let mut state = slot.get();
                if delta.resident_bytes > 0 {
                    state.ordinal += 1;
                }
                slot.set(state);
            });
            Ok(())
        }

        fn begin_allocation_scope(
            &self,
            delta: WorkDelta,
            allowed_slack: u64,
        ) -> Result<(), OperationAbort> {
            self.consume(delta)?;
            DECODE_ORACLE.with(|slot| {
                let mut state = slot.get();
                if state.scope_active {
                    state.nested_scopes += 1;
                }
                state.scope_active = true;
                state.credit = delta.resident_bytes;
                state.allowed_slack = allowed_slack;
                slot.set(state);
            });
            Ok(())
        }

        fn end_allocation_scope(&self) {
            DECODE_ORACLE.with(|slot| {
                let mut state = slot.get();
                if !state.scope_active || state.credit > state.allowed_slack {
                    state.scope_violations += 1;
                }
                state.scope_active = false;
                state.credit = 0;
                state.allowed_slack = 0;
                slot.set(state);
            });
        }
    }

    pub(crate) fn activate_allocation_oracle() {
        DECODE_ORACLE.with(|slot| {
            slot.set(DecodeOracle {
                active: true,
                ..DecodeOracle::default()
            });
        });
    }

    pub(crate) fn finish_allocation_oracle() -> u64 {
        DECODE_ORACLE.with(|slot| {
            let mut state = slot.get();
            state.active = false;
            slot.set(state);
            assert_eq!(state.nested_scopes, 0, "allocation scopes must not nest");
            assert_eq!(state.scope_violations, 0, "allocation scope slack bound");
            state.unauthorized
        })
    }

    pub(crate) fn allocation_oracle_sizes() -> ([usize; 16], [usize; 16], usize) {
        DECODE_ORACLE.with(|slot| {
            let state = slot.get();
            (state.sizes, state.ordinals, state.size_len)
        })
    }

    struct CountingGuard(AtomicU64);

    impl CountingGuard {
        fn consumed(&self) -> u64 {
            self.0.load(Ordering::Relaxed)
        }
    }

    impl WorkGuard for CountingGuard {
        fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
            self.0.fetch_add(delta.resident_bytes, Ordering::Relaxed);
            Ok(())
        }
    }

    fn incremental_vec_charge(count: usize) -> (u64, usize) {
        let guard = CountingGuard(AtomicU64::new(0));
        let mut values = Vec::<u64>::new();
        for value in 0..count {
            super::try_reserve_vec(&mut values, 1, &guard, "scaling vector").expect("reserve");
            values.push(value as u64);
        }
        (guard.consumed(), values.capacity())
    }

    fn incremental_string_charge(count: usize) -> (u64, usize) {
        let guard = CountingGuard(AtomicU64::new(0));
        let mut value = String::new();
        for _ in 0..count {
            super::try_reserve_string(&mut value, 1, &guard, "scaling string").expect("reserve");
            value.push('x');
        }
        (guard.consumed(), value.capacity())
    }

    fn incremental_hash_charge(count: usize) -> u64 {
        let guard = CountingGuard(AtomicU64::new(0));
        let mut values = std::collections::HashMap::<u64, u64>::new();
        for value in 0..count {
            super::try_reserve_hash_map(&mut values, 1, &guard, "scaling hash map")
                .expect("reserve");
            values.insert(value as u64, value as u64);
        }
        guard.consumed()
    }

    #[test]
    fn incremental_capacity_authorization_is_geometric_and_linear() {
        let mut vector_charges = Vec::new();
        let mut string_charges = Vec::new();
        for count in [5_000, 10_000, 20_000] {
            let (vector_charge, vector_capacity) = incremental_vec_charge(count);
            let (string_charge, string_capacity) = incremental_string_charge(count);
            let vector_final = (vector_capacity * std::mem::size_of::<u64>()) as u64;
            let string_final = string_capacity as u64;
            assert!(
                vector_charge < vector_final * 2 + 64,
                "vector authorization must be less than twice final layout: count={count}, charge={vector_charge}, final={vector_final}"
            );
            assert!(
                string_charge < string_final * 2 + 16,
                "string authorization must be less than twice final layout: count={count}, charge={string_charge}, final={string_final}"
            );
            assert!(vector_capacity < count * 2);
            assert!(string_capacity < count * 2);
            vector_charges.push(vector_charge);
            string_charges.push(string_charge);
        }
        for charges in [&vector_charges, &string_charges] {
            assert!(
                charges[1] <= charges[0] * 2 + 128,
                "N -> 2N must stay linear"
            );
            assert!(
                charges[2] <= charges[1] * 2 + 128,
                "2N -> 4N must stay linear"
            );
        }
        assert!(
            vector_charges[2] < 20_000 * 8 * 4,
            "20k probe must not contain quadratic allocation work"
        );
        let mut capacity = 0_usize;
        let mut ten_million_series = 0_u64;
        while capacity < 10_000_000 {
            capacity = super::geometric_capacity(capacity, capacity + 1, 4, "10m geometry")
                .expect("10m capacity");
            ten_million_series = ten_million_series
                .checked_add((capacity * std::mem::size_of::<u64>()) as u64)
                .expect("10m allocation-work series");
        }
        assert_eq!(capacity, 16_777_216);
        let terminal_layout = (capacity * std::mem::size_of::<u64>()) as u64;
        assert!(ten_million_series < terminal_layout * 2);
    }

    #[test]
    fn hash_table_bound_covers_full_allocator_requests_and_scales_linearly() {
        let mut charges = Vec::new();
        for count in [5_000, 10_000, 20_000] {
            charges.push(incremental_hash_charge(count));
        }
        assert!(charges[1] <= charges[0] * 2 + 4096);
        assert!(charges[2] <= charges[1] * 2 + 4096);
        assert!(charges[2] < 64 * 1024 * 1024);
        let (ten_million, _) =
            super::hash_table_bound::<u64, u64>(0, 10_000_000).expect("10m hash-table arithmetic");
        assert!(ten_million < 512 * 1024 * 1024);

        let mut values = std::collections::HashMap::<u64, u64>::new();
        activate_allocation_oracle();
        for value in 0..20_000_u64 {
            super::try_reserve_hash_map(&mut values, 1, &DecodeGuard, "hash request proof")
                .expect("reserve");
            values.insert(value, value);
        }
        let unauthorized = finish_allocation_oracle();
        let (sizes, ordinals, length) = allocation_oracle_sizes();
        assert_eq!(
            unauthorized,
            0,
            "hash bucket/control/alignment request escaped bound: {:?}/{:?}",
            &sizes[..length],
            &ordinals[..length]
        );
        assert_eq!(values.len(), 20_000);
    }

    #[test]
    fn hash_reserve_scope_does_not_authorize_later_vec_growth() {
        let mut values = std::collections::HashMap::<u64, u64>::new();
        activate_allocation_oracle();
        super::try_reserve_hash_map(&mut values, 1, &DecodeGuard, "hash scope")
            .expect("guarded hash reserve");
        values.insert(1, 1);

        let mut unscoped = Vec::<u8>::new();
        unscoped
            .try_reserve_exact(4)
            .expect("unscoped vector reserve");

        assert_eq!(
            finish_allocation_oracle(),
            1,
            "unused hash-table authorization must be cleared when its operation ends"
        );
    }

    struct ScopeLifecycleGuard {
        begins: AtomicUsize,
        ends: AtomicUsize,
    }

    impl WorkGuard for ScopeLifecycleGuard {
        fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
            Ok(())
        }

        fn begin_allocation_scope(
            &self,
            _delta: WorkDelta,
            _allowed_slack: u64,
        ) -> Result<(), OperationAbort> {
            self.begins.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn end_allocation_scope(&self) {
            self.ends.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn allocation_scope_drop_closes_during_error_and_panic_unwind() {
        let guard = ScopeLifecycleGuard {
            begins: AtomicUsize::new(0),
            ends: AtomicUsize::new(0),
        };
        let error_path = || -> Result<(), super::AllocationFailure> {
            let _scope = super::scope(&guard, 8, 8)?;
            Err(super::AllocationFailure::Failed(
                "injected operation failure",
            ))
        };
        assert!(error_path().is_err());
        let panic = catch_unwind(AssertUnwindSafe(|| {
            let _scope = super::scope(&guard, 8, 8).expect("panic scope");
            panic!("injected operation panic");
        }));
        assert!(panic.is_err());
        assert_eq!(guard.begins.load(Ordering::Relaxed), 2);
        assert_eq!(guard.ends.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn payload_decode_bound_has_no_fixed_per_row_tax() {
        assert_eq!(
            payload_decode_upper_bound(EventKind::Discontinuity, 1).expect("bound"),
            1
        );
        let representative = payload_decode_upper_bound(EventKind::SemanticRule, 256)
            .expect("representative bound")
            .checked_mul(20_000)
            .expect("20k bound");
        assert!(representative <= 64 * 1024 * 1024);
    }

    #[test]
    fn every_closed_payload_variant_decodes_within_its_authorized_bound() {
        let escaped = "\\\"line\\n雪".repeat(32);
        let register_definitions = (0..RegisterSlot::COUNT)
            .map(|slot| RegisterDefinition {
                slot: slot as u8,
                captured_width: 8,
                name: format!("r{slot}"),
            })
            .collect::<Vec<_>>();
        let observations = (0..RegisterSlot::COUNT)
            .map(|slot| RegisterObservation {
                slot: slot as u8,
                captured_width: 8,
                name: format!("r{slot}"),
                value: slot as u64,
            })
            .collect::<Vec<_>>();
        let register_values = (0..RegisterSlot::COUNT)
            .map(|slot| RegisterValue {
                slot: RegisterSlot::from_index(slot).expect("slot"),
                value: slot as u64,
            })
            .collect::<Vec<_>>();
        let semantic = SemanticEvent {
            category: Some(escaped.clone()),
            name: escaped.clone(),
            detail: escaped.clone(),
            fragment_sequences: vec![0; 512],
        };
        let definition = InstructionDefinition {
            definition_id: u32::MAX,
            opcode: 1,
            read_mask: u64::MAX,
            write_mask: u64::MAX,
            pc_displacement: -4,
            flags: 3,
            pc_kind: PcRelativeKind::Instruction,
            condition: 1,
            slow_memory_path: true,
            mnemonic: escaped.clone(),
            operands: escaped.clone(),
            disassembly: escaped.clone(),
            reads: register_definitions.clone(),
            writes: register_definitions,
            memory_operands: vec![
                MemoryOperand {
                    base: Some(0),
                    index: Some(1),
                    extend: RegisterExtend::Sxtx,
                    mode: MemoryAddressMode::PostIndex,
                    shift: 3,
                    direction: MemoryDirection::ReadWrite,
                    writeback: true,
                    size: 16,
                    displacement: -8,
                };
                32
            ],
        };
        let payloads = vec![
            EventPayload::Begin(BeginMetadata {
                scene: escaped.clone(),
                target: escaped.clone(),
                ..BeginMetadata::default()
            }),
            EventPayload::ModuleDefinition(ModuleDefinition {
                module_id: u32::MAX,
                base: 1,
                name: escaped.clone(),
            }),
            EventPayload::InstructionDefinition(definition),
            EventPayload::Instruction(Instruction {
                definition_id: u32::MAX,
                module_id: u32::MAX,
                relative_pc: 4,
                read_before: observations.clone(),
                write_after: observations,
            }),
            EventPayload::Memory(Memory {
                before: CaptureBytes::Captured((0_u8..=255).collect()),
                after: CaptureBytes::Captured((0_u8..=255).rev().collect()),
                ..Memory::default()
            }),
            EventPayload::SemanticCall(semantic.clone()),
            EventPayload::SemanticRule(semantic.clone()),
            EventPayload::SemanticError(semantic),
            EventPayload::ThreadLifecycle(ThreadLifecycle {
                tid: 1,
                phase: ThreadLifecyclePhase::Begin,
                creator_tid: Some(2),
                start_routine: Some(3),
                module_generation: Some(4),
            }),
            EventPayload::Syscall(Syscall {
                tid: 1,
                number: 2,
                pc: 3,
                arguments: [4; 6],
                result: Some(5),
            }),
            EventPayload::Signal(Signal {
                tid: 1,
                number: 2,
                code: 3,
                pc: 4,
                sp: 5,
                fault_address: 6,
                flags: 7,
            }),
            EventPayload::SignalHandlerBoundary(SignalHandlerBoundary {
                tid: 1,
                phase: SignalHandlerPhase::Begin,
                number: 2,
                code: 3,
                pc: 4,
                sp: 5,
                fault_address: 6,
                flags: 7,
                depth: 8,
                nested_delivery_count: 9,
                begin_sequence: Some(10),
            }),
            EventPayload::Termination(Termination {
                reason: Some(escaped),
                ..Termination::default()
            }),
            EventPayload::RegisterCheckpoint(RegisterCheckpoint {
                values: register_values.clone(),
            }),
            EventPayload::RegisterDelta(RegisterDelta {
                mask: u64::MAX,
                changed: register_values,
                ancestry_reliable: true,
            }),
            EventPayload::StringDefinition(StringDefinition {
                id: u32::MAX,
                bytes: (0_u8..=255).collect(),
            }),
            EventPayload::CoverageGap(CoverageGap {
                tid: 1,
                pc: 2,
                sp: 3,
                fault_address: 4,
                reason_flags: 5,
                dropped_count: 6,
            }),
            EventPayload::Discontinuity(Discontinuity {
                cause: DiscontinuityCause::Damage,
                evidence: CompletenessRange::source_bytes_with_cause(
                    1,
                    2,
                    Provenance::Damaged,
                    CompletenessCause::Checksum,
                )
                .expect("evidence"),
            }),
            EventPayload::OpaqueOptional(OpaqueOptionalRecord {
                record_type: 1,
                flags: 2,
                bytes: (0_u8..=255).rev().collect(),
            }),
        ];
        assert_eq!(payloads.len(), 19);

        for payload in payloads {
            let encoded = serde_json::to_vec(&payload).expect("canonical payload");
            activate_allocation_oracle();
            let decoded: EventPayload = {
                let bytes =
                    payload_decode_upper_bound(payload.kind(), encoded.len()).expect("bound");
                let _scope = scope(&DecodeGuard, bytes, bytes).expect("authorize");
                serde_json::from_slice(&encoded).expect("decode")
            };
            let unauthorized = finish_allocation_oracle();
            let (sizes, ordinals, length) = allocation_oracle_sizes();
            assert_eq!(decoded, payload);
            assert_eq!(
                unauthorized,
                0,
                "variant {:?}, sizes={:?}, ordinals={:?}",
                payload.kind(),
                &sizes[..length],
                &ordinals[..length]
            );
        }
    }
}
