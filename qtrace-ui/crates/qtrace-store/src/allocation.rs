use std::{
    alloc::{Layout, alloc},
    collections::{HashMap, HashSet},
    hash::{BuildHasher, Hash},
    mem::size_of,
};

use qtrace_provider::{EventKind, OperationAbort, WorkDelta, WorkGuard};

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

pub(crate) fn authorize(
    guard: &dyn WorkGuard,
    resident_bytes: u64,
) -> Result<(), AllocationFailure> {
    guard
        .consume(WorkDelta {
            resident_bytes,
            ..WorkDelta::default()
        })
        .map_err(AllocationFailure::Aborted)
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
    authorize(guard, checked_array_bytes::<T>(required)?)?;
    values
        .try_reserve_exact(required - values.len())
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
    authorize(
        guard,
        u64::try_from(required).map_err(|_| AllocationFailure::Overflow(label))?,
    )?;
    value
        .try_reserve_exact(required - value.len())
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

pub(crate) fn try_box<T>(
    value: T,
    guard: &dyn WorkGuard,
    label: &'static str,
) -> Result<Box<T>, AllocationFailure> {
    let layout = Layout::new::<T>();
    authorize(
        guard,
        u64::try_from(layout.size()).map_err(|_| AllocationFailure::Overflow(label))?,
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

fn hash_table_bound<K, V>(len: usize, additional: usize) -> Result<u64, AllocationFailure> {
    let required = len
        .checked_add(additional)
        .ok_or(AllocationFailure::Overflow("hash table entry count"))?;
    if required == 0 {
        return Ok(0);
    }
    let buckets = required
        .checked_next_power_of_two()
        // hashbrown's smallest table has three usable buckets plus its control group; four times
        // the requested power-of-two covers that initial shape as well as later <= 7/8 load.
        .and_then(|value| value.checked_mul(4))
        .ok_or(AllocationFailure::Overflow("hash table bucket count"))?;
    let bucket_bytes = size_of::<(K, V)>()
        // One control byte per bucket plus the group sentinel and allocator alignment slack.
        .checked_add(16)
        .ok_or(AllocationFailure::Overflow("hash table bucket size"))?;
    buckets
        .checked_mul(bucket_bytes)
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(AllocationFailure::Overflow("hash table byte count"))
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
    authorize(guard, hash_table_bound::<K, V>(values.len(), additional)?)?;
    values
        .try_reserve(additional)
        .map_err(|_| AllocationFailure::Failed(label))
}

pub(crate) fn try_reserve_hash_set<K, S>(
    values: &mut HashSet<K, S>,
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
    authorize(guard, hash_table_bound::<K, ()>(values.len(), additional)?)?;
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
        | EventKind::OpaqueOptional => 2,
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
    };

    use super::{authorize, payload_decode_upper_bound};
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
        credit: u64,
        unauthorized: u64,
        sizes: [usize; 16],
        ordinals: [usize; 16],
        size_len: usize,
        ordinal: usize,
    }

    thread_local! {
        static DECODE_ORACLE: Cell<DecodeOracle> = const { Cell::new(DecodeOracle {
            active: false,
            credit: 0,
            unauthorized: 0,
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
            record_decode_growth(new_size.saturating_sub(layout.size()));
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
                if bytes <= state.credit {
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
                state.credit += delta.resident_bytes;
                slot.set(state);
            });
            Ok(())
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
            state.unauthorized
        })
    }

    pub(crate) fn allocation_oracle_sizes() -> ([usize; 16], [usize; 16], usize) {
        DECODE_ORACLE.with(|slot| {
            let state = slot.get();
            (state.sizes, state.ordinals, state.size_len)
        })
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
            authorize(
                &DecodeGuard,
                payload_decode_upper_bound(payload.kind(), encoded.len()).expect("bound"),
            )
            .expect("authorize");
            let decoded: EventPayload = serde_json::from_slice(&encoded).expect("decode");
            let unauthorized = finish_allocation_oracle();
            assert_eq!(decoded, payload);
            assert_eq!(unauthorized, 0, "variant {:?}", payload.kind());
        }
    }
}
