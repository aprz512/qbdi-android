import io
import struct
import unittest

from scripts.flight_trace import FlightTraceError, recover_flight


# These fixtures intentionally duplicate the published wire contract. They do not import
# constants, checksum helpers, or encoders from the decoder under test.
SUPERBLOCK_BYTES = 4096
DIRECTORY_BYTES = 64
CHUNK_HEADER_BYTES = 64
RECORD_HEADER_BYTES = 24
EMERGENCY_BYTES = 64
MAGIC = 0x51464C54
VERSION = 1
RECORD_COMMIT = 0x51434D54
EMERGENCY_COMMITTED = 0x80000000


def align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def fnv32(data: bytes) -> int:
    value = 2166136261
    for byte in data:
        value = ((value ^ byte) * 16777619) & 0xFFFFFFFF
    return value


def flight_record(kind: int, sequence: int, payload: bytes = b"", *, flags: int = 0,
                  generation: int = 1, committed: bool = True) -> bytes:
    total = RECORD_HEADER_BYTES + len(payload)
    storage = align(total, 8)
    raw = bytearray(storage)
    struct.pack_into("<HHIQII", raw, 0, kind, flags, total, sequence, 0, 0)
    raw[RECORD_HEADER_BYTES:total] = payload
    checksum = fnv32(bytes(raw[:16]) + bytes(raw[RECORD_HEADER_BYTES:total]))
    struct.pack_into("<I", raw, 16, checksum)
    if committed:
        struct.pack_into("<I", raw, 20, RECORD_COMMIT ^ total ^ generation)
    return bytes(raw)


def chunk_begin(tid: int, *, pointer_width: int = 8, target: bytes = b"libtarget.so",
                scene: bytes = b"worker", pid: int = 4242,
                module_base: int = 0x71000000) -> bytes:
    return struct.pack(
        "<BBHHHIIQQQ", 2, pointer_width, len(target), len(scene), 0, pid, tid,
        module_base, 0x1234, module_base + 0x1234,
    ) + target + scene


def checkpoint(*, pc: int = 0x71001000, sp: int = 0x7FFF0000) -> bytes:
    values = list(range(31)) + [sp, pc, 0x60000000]
    return struct.pack("<" + "Q" * 34, *values)


def register_delta(changes: dict[int, int]) -> bytes:
    mask = sum(1 << index for index in changes)
    return struct.pack("<Q", mask) + b"".join(
        struct.pack("<Q", changes[index]) for index in sorted(changes)
    )


def qtrb_record(kind: int, payload: bytes, flags: int = 0) -> bytes:
    return struct.pack("<HHI", kind, flags, len(payload)) + payload


def qtrb_instruction_definition(metadata_id: int = 1, opcode: int = 0xD503201F) -> bytes:
    fixed = struct.pack("<IIQQqIBBBB", metadata_id, opcode, 0, 0, 0, 0, 0, 0, 0, 0)
    strings = struct.pack("<H3sH0sH3s", 3, b"nop", 0, b"", 3, b"nop")
    return qtrb_record(3, fixed + strings)


def qtrb_instruction(metadata_id: int = 1, relative_pc: int = 0x1234) -> bytes:
    return qtrb_record(4, struct.pack("<QIQIBB", 1, 1, relative_pc, metadata_id, 0, 0))


def qtrb_zero_width_definition() -> bytes:
    fixed = struct.pack("<IIQQqIBBBB", 1, 0xD503201F, 1, 0, 0, 0, 0, 0, 1, 0)
    strings = struct.pack("<H3sH0sH3s", 3, b"nop", 0, b"", 3, b"nop")
    register = struct.pack("<BH", 0, 0)
    operand = struct.pack("<BBBBBBBIq", 0xFF, 0xFF, 0, 0, 0, 1, 0, 0, 0)
    return qtrb_record(3, fixed + strings + register + operand)


def qtrb_one_read_instruction(relative_pc: int = 0x1234) -> bytes:
    payload = struct.pack("<QIQIBB", 1, 1, relative_pc, 1, 1, 0) + struct.pack("<Q", 0)
    return qtrb_record(4, payload)


def qtrb_rich_instruction_definition() -> bytes:
    read_mask = (1 << 0) | (1 << 31)
    write_mask = (1 << 32) | (1 << 33)
    fixed = struct.pack(
        "<IIQQqIBBBB", 7, 0x14000000, read_mask, write_mask,
        -0x20, 3, 2, 14, 1, 1,
    )
    strings = (
        struct.pack("<H4s", 4, b"B.EQ")
        + struct.pack("<H8s", 8, b"x0, #0x4")
        + struct.pack("<H8s", 8, b"fallback")
    )
    registers = (
        struct.pack("<BH2s", 4, 2, b"W0")
        + struct.pack("<BH2s", 8, 2, b"SP")
        + struct.pack("<BH4s", 8, 4, b"NZCV")
        + struct.pack("<BH2s", 8, 2, b"PC")
    )
    operand = struct.pack("<BBBBBBBIq", 0, 31, 3, 1, 2, 3, 1, 16, -16)
    return qtrb_record(3, fixed + strings + registers + operand)


def qtrb_rich_instruction() -> bytes:
    payload = struct.pack("<QIQIBB", 19, 1, 0x2345, 7, 2, 2)
    payload += struct.pack("<QQQQ", 0x11, 0x22, 0x33, 0x44)
    return qtrb_record(4, payload)


def string_definition(string_id: int, value: bytes) -> bytes:
    return struct.pack("<II", string_id, len(value)) + value


def event_fragment(event_id: int, total: int, index: int, count: int,
                   *string_ids: int) -> bytes:
    return struct.pack("<QIHH", event_id, total, index, count) + struct.pack(
        "<" + "I" * len(string_ids), *string_ids
    )


def directory_entry(tid: int, first: int, last: int, chunk_index: int,
                    generation: int, *, state: int = 1) -> bytes:
    return struct.pack("<IIQQII32x", tid, state, first, last, chunk_index, generation)


def chunk(index: int, tid: int, generation: int, records: list[bytes], *,
          state: int = 2, chunk_bytes: int = 2048, corrupt_checksum: bool = False,
          suffix: bytes = b"") -> bytes:
    data = b"".join(records) + suffix
    if len(data) > chunk_bytes - CHUNK_HEADER_BYTES:
        raise AssertionError("fixture chunk overflow")
    committed = len(b"".join(records)) if state == 2 else 0
    first = min((struct.unpack_from("<Q", record, 8)[0] for record in records), default=0) \
        if state == 2 else 0
    last = max((struct.unpack_from("<Q", record, 8)[0] for record in records), default=0) \
        if state == 2 else 0
    checksum = fnv32(b"".join(records)) if state == 2 else 0
    if corrupt_checksum:
        checksum ^= 1
    header = struct.pack(
        "<IHHIIIIQQIII12x", MAGIC, VERSION, CHUNK_HEADER_BYTES, index, state, tid,
        generation, first, last, committed, len(records) if state == 2 else 0, checksum,
    )
    return (header + data).ljust(chunk_bytes, b"\0")


def emergency(kind: int, tid: int, sequence: int, *, pc: int = 0, sp: int = 0,
              fault: int = 0, signal: int = 0, code: int = 0, flags: int = 0,
              committed: bool = True, version: int = 2,
              canonical_gap_checksum: bool = True) -> bytes:
    checksum_code = 0 if kind == 15 and canonical_gap_checksum else code
    logical = struct.pack("<IIQQQQIII", kind, tid, sequence, pc, sp, fault,
                          signal, checksum_code, flags)
    checksum = fnv32(logical)
    published = flags | (EMERGENCY_COMMITTED if committed else 0)
    return struct.pack(
        "<IIQQQQIIIIII", kind, tid, sequence, pc, sp, fault, signal, code,
        published, checksum, (~checksum) & 0xFFFFFFFF, version,
    )


def artifact(*, directories: list[bytes], chunks: list[bytes], emergencies: list[bytes] | None = None,
             flags: int = 0, pointer_width: int = 8, run_id: int = 0x1020304050607080,
             pid: int = 4242, module_generation: int = 17,
             target: bytes = b"libtarget.so", chunk_bytes: int = 2048,
             wire_version: int = VERSION,
             emergency_slot_bytes: int = EMERGENCY_BYTES) -> bytes:
    directory_offset = SUPERBLOCK_BYTES
    directory_count = len(directories)
    emergency_count = directory_count + 1
    emergency_offset = align(directory_offset + directory_count * DIRECTORY_BYTES,
                             emergency_slot_bytes)
    chunk_offset = align(emergency_offset + emergency_count * emergency_slot_bytes,
                         chunk_bytes)
    artifact_bytes = chunk_offset + len(chunks) * chunk_bytes
    raw = bytearray(artifact_bytes)
    struct.pack_into("<IHBBH6xQQIIQIIQIII4xQI I H", raw, 0,
                     MAGIC, wire_version, 1, pointer_width, SUPERBLOCK_BYTES, artifact_bytes,
                     directory_offset, DIRECTORY_BYTES, directory_count, chunk_offset,
                     chunk_bytes, len(chunks), emergency_offset, emergency_slot_bytes,
                     emergency_count, flags, run_id, pid, module_generation, len(target))
    raw[98:98 + len(target)] = target
    for index, entry in enumerate(directories):
        raw[directory_offset + index * DIRECTORY_BYTES:directory_offset + (index + 1) * DIRECTORY_BYTES] = entry
    for index, slot in enumerate(emergencies or []):
        raw[emergency_offset + index * emergency_slot_bytes:
            emergency_offset + (index + 1) * emergency_slot_bytes] = slot
    for index, encoded in enumerate(chunks):
        start = chunk_offset + index * chunk_bytes
        raw[start:start + chunk_bytes] = encoded
    return bytes(raw)


def core_records(tid: int, generation: int = 1, *, start: int = 1,
                 pc: int = 0x71001000) -> list[bytes]:
    return [
        flight_record(1, start, chunk_begin(tid), generation=generation),
        flight_record(9, start + 1, checkpoint(pc=pc), flags=1, generation=generation),
    ]


class FlightRecoveryTests(unittest.TestCase):
    def test_emergency_failure_flag_can_never_recover_as_complete(self):
        raw = artifact(
            directories=[directory_entry(77, 0, 0, 0xFFFFFFFF, 0)],
            chunks=[bytes(2048)], flags=8,
        )

        recovery = recover_flight(io.BytesIO(raw))

        self.assertFalse(recovery.summary["complete"])
        self.assertEqual(8, recovery.summary["artifact_flags"])

    def test_v2_emergency_double_cell_recovers_old_or_new_publication(self):
        old = emergency(14, 77, 41, pc=0x71000100, version=2)
        torn_new = emergency(14, 77, 42, pc=0x71000200, version=5)
        raw = artifact(
            directories=[directory_entry(77, 0, 0, 0xFFFFFFFF, 0)],
            chunks=[bytes(2048)], emergencies=[old + torn_new],
            wire_version=2, emergency_slot_bytes=128,
        )

        recovered_old = recover_flight(io.BytesIO(raw))

        self.assertEqual(41, recovered_old.summary["termination"]["sequence"])
        committed_new = emergency(14, 77, 42, pc=0x71000200, version=4)
        raw = artifact(
            directories=[directory_entry(77, 0, 0, 0xFFFFFFFF, 0)],
            chunks=[bytes(2048)], emergencies=[old + committed_new],
            wire_version=2, emergency_slot_bytes=128,
        )
        recovered_new = recover_flight(io.BytesIO(raw))
        self.assertEqual(42, recovered_new.summary["termination"]["sequence"])

    def test_v2_double_cell_recovers_a_closed_signal_handler_interval(self):
        begin = emergency(
            12, 77, 1019, pc=0x71009900, sp=0x81001000,
            signal=12, code=1, flags=1, version=16,
        )
        returned = emergency(
            13, 77, 1020, pc=0x71009904, sp=0x81001008,
            fault=1019, signal=12, code=1, flags=1, version=18,
        )
        raw = artifact(
            directories=[directory_entry(77, 0, 0, 0xFFFFFFFF, 0)],
            chunks=[bytes(2048)], emergencies=[returned + begin],
            wire_version=2, emergency_slot_bytes=128,
        )

        recovery = recover_flight(io.BytesIO(raw))

        self.assertEqual(
            [(1019, "signal_handler_begin"),
             (1020, "signal_handler_return")],
            [(event.global_seq, event.kind) for event in recovery.merged],
        )
        self.assertEqual([{
            "tid": 77,
            "depth": 1,
            "nested_delivery_count": 0,
            "begin_sequence": 1019,
            "return_sequence": 1020,
            "returned": True,
            "unreturned_ancestor_count": 0,
        }], recovery.summary["signal_handler_intervals"])

    def test_v2_double_cell_keeps_one_valid_cell_and_rejects_stale_history(self):
        valid_begin = emergency(
            12, 77, 41, signal=12, flags=1, version=16,
        )
        torn_return = emergency(
            13, 77, 42, fault=41, signal=12, flags=1, version=19,
        )
        raw = artifact(
            directories=[directory_entry(77, 0, 0, 0xFFFFFFFF, 0)],
            chunks=[bytes(2048)], emergencies=[torn_return + valid_begin],
            wire_version=2, emergency_slot_bytes=128,
        )
        recovered_begin = recover_flight(io.BytesIO(raw))
        self.assertEqual(
            [(41, "signal_handler_begin")],
            [(event.global_seq, event.kind) for event in recovered_begin.merged],
        )

        torn_begin = emergency(
            12, 77, 41, signal=12, flags=1, version=15,
        )
        valid_return = emergency(
            13, 77, 42, fault=41, signal=12, flags=1, version=18,
        )
        raw = artifact(
            directories=[directory_entry(77, 0, 0, 0xFFFFFFFF, 0)],
            chunks=[bytes(2048)], emergencies=[valid_return + torn_begin],
            wire_version=2, emergency_slot_bytes=128,
        )
        recovered_return = recover_flight(io.BytesIO(raw))
        self.assertEqual(
            [(42, "signal_handler_return")],
            [(event.global_seq, event.kind) for event in recovered_return.merged],
        )

        stale = emergency(14, 77, 40, signal=9, version=2)
        newest = emergency(14, 77, 43, signal=9, version=18)
        raw = artifact(
            directories=[directory_entry(77, 0, 0, 0xFFFFFFFF, 0)],
            chunks=[bytes(2048)], emergencies=[newest + stale],
            wire_version=2, emergency_slot_bytes=128,
        )
        recovered_newest = recover_flight(io.BytesIO(raw))
        self.assertEqual(
            [(43, "termination_intent")],
            [(event.global_seq, event.kind) for event in recovered_newest.merged],
        )

    def test_v2_recovers_pre_delivery_pinned_intent_with_each_top_level_signal_kind(self):
        intent = emergency(
            14, 77, 40, signal=131, code=12, version=2,
        )
        for outcome, kind, name in (
            ("ignore", 11, "signal"),
            ("custom", 12, "signal_handler_begin"),
            ("custom_return", 13, "signal_handler_return"),
            ("default", 11, "signal"),
        ):
            with self.subTest(outcome=outcome):
                matching = emergency(
                    kind, 77, 55, fault=54 if kind == 13 else 0,
                    signal=12, flags=1, version=18,
                )
                raw = artifact(
                    directories=[directory_entry(77, 0, 0, 0xFFFFFFFF, 0)],
                    chunks=[bytes(2048)], emergencies=[intent + matching],
                    wire_version=2, emergency_slot_bytes=128,
                )
                recovered = recover_flight(io.BytesIO(raw))
                self.assertEqual(
                    [(40, "termination_intent"), (55, name)],
                    [(event.global_seq, event.kind) for event in recovered.merged],
                )

    def test_v2_pinned_pair_rejects_signal_mismatch_tid_mismatch_and_nested_depth(self):
        intent = emergency(14, 77, 40, signal=131, code=12, version=2)
        for stale, newer in (
            (emergency(14, 77, 40, signal=131, code=10, version=2),
             emergency(13, 77, 55, fault=54, signal=12,
                       flags=1, version=18)),
            (intent, emergency(12, 78, 55, signal=12, flags=1, version=18)),
            (intent, emergency(12, 77, 55, signal=12, flags=2, version=18)),
        ):
            with self.subTest(stale=stale[4:16], newer=newer[4:16]):
                raw = artifact(
                    directories=[directory_entry(77, 0, 0, 0xFFFFFFFF, 0)],
                    chunks=[bytes(2048)], emergencies=[stale + newer],
                    wire_version=2, emergency_slot_bytes=128,
                )
                recovered = recover_flight(io.BytesIO(raw))
                self.assertNotIn(
                    "termination_intent", [event.kind for event in recovered.merged]
                )

    def test_completed_ignore_and_custom_return_overwrites_do_not_recover_intent(self):
        for outcome, replacement in (
            ("ignore", emergency(11, 77, 55, signal=12, flags=1, version=18)),
            ("custom", emergency(13, 77, 55, fault=54, signal=12,
                                 flags=1, version=18)),
        ):
            with self.subTest(outcome=outcome):
                previous = emergency(12, 77, 39, signal=10, flags=1, version=2)
                raw = artifact(
                    directories=[directory_entry(77, 0, 0, 0xFFFFFFFF, 0)],
                    chunks=[bytes(2048)], emergencies=[previous + replacement],
                    wire_version=2, emergency_slot_bytes=128,
                )
                recovered = recover_flight(io.BytesIO(raw))
                self.assertNotIn(
                    "termination_intent", [event.kind for event in recovered.merged]
                )

    def test_interrupted_overwrite_does_not_resurrect_invalid_or_incomplete_intent(self):
        for interrupted in (
            emergency(14, 77, 40, signal=131, code=12,
                      committed=False, version=18),
            emergency(14, 77, 40, signal=131, code=12, version=19),
        ):
            with self.subTest(version=struct.unpack_from("<I", interrupted, 60)[0]):
                previous = emergency(11, 77, 39, signal=10, flags=1, version=2)
                raw = artifact(
                    directories=[directory_entry(77, 0, 0, 0xFFFFFFFF, 0)],
                    chunks=[bytes(2048)], emergencies=[previous + interrupted],
                    wire_version=2, emergency_slot_bytes=128,
                )
                recovered = recover_flight(io.BytesIO(raw))
                self.assertNotIn(
                    "termination_intent", [event.kind for event in recovered.merged]
                )

    def test_pinned_pair_uses_the_explicit_termination_syscall_signal_mapping(self):
        begin = emergency(12, 77, 55, signal=12, flags=1, version=18)
        rt_sigqueueinfo = emergency(
            14, 77, 40, fault=12, signal=138, code=0x7100A000, version=2,
        )
        raw = artifact(
            directories=[directory_entry(77, 0, 0, 0xFFFFFFFF, 0)],
            chunks=[bytes(2048)], emergencies=[rt_sigqueueinfo + begin],
            wire_version=2, emergency_slot_bytes=128,
        )

        recovered = recover_flight(io.BytesIO(raw))

        self.assertEqual(
            [(40, "termination_intent"), (55, "signal_handler_begin")],
            [(event.global_seq, event.kind) for event in recovered.merged],
        )

        for syscall_number in (93, 94):
            with self.subTest(syscall_number=syscall_number):
                non_signal = emergency(
                    14, 77, 40, fault=12, signal=syscall_number,
                    code=12, version=2,
                )
                raw = artifact(
                    directories=[directory_entry(77, 0, 0, 0xFFFFFFFF, 0)],
                    chunks=[bytes(2048)], emergencies=[non_signal + begin],
                    wire_version=2, emergency_slot_bytes=128,
                )
                recovered = recover_flight(io.BytesIO(raw))
                self.assertNotIn(
                    "termination_intent", [event.kind for event in recovered.merged]
                )

    def test_rt_sigqueueinfo_intent_signal_decodes_with_explicit_incomplete_gap(self):
        intent = emergency(
            14, 77, 40, fault=12, signal=138, code=0x7100A000, version=2,
        )
        gap = emergency(15, 77, 41, flags=2, version=2)
        raw = artifact(
            directories=[directory_entry(77, 0, 0, 0xFFFFFFFF, 0)],
            chunks=[bytes(2048)], emergencies=[intent, gap],
            wire_version=2, emergency_slot_bytes=128,
        )

        recovered = recover_flight(io.BytesIO(raw))

        self.assertEqual(
            "termination_intent", recovered.summary["termination"]["cause"]
        )
        self.assertEqual(138, recovered.summary["termination"]["signal_number"])
        self.assertEqual(12, recovered.summary["termination"]["fault_address"])
        self.assertFalse(recovered.summary["complete"])

    def test_excludes_an_empty_sealed_chunk_as_damaged_evidence(self):
        raw = artifact(
            directories=[directory_entry(7, 0, 0, 0, 1)],
            chunks=[chunk(0, 7, 1, [])],
        )

        recovery = recover_flight(io.BytesIO(raw))

        self.assertEqual({}, recovery.threads)
        self.assertFalse(recovery.summary["complete"])
        self.assertIn("empty sealed chunk", recovery.summary["recovery_damage"][0])

    def test_tolerates_an_empty_active_chunk_as_a_crash_prefix(self):
        raw = artifact(
            directories=[directory_entry(7, 0, 0, 0, 1)],
            chunks=[chunk(0, 7, 1, [], state=1)],
        )

        recovery = recover_flight(io.BytesIO(raw))

        self.assertEqual({}, recovery.threads)
        self.assertTrue(recovery.summary["complete"])
        self.assertEqual([0], recovery.summary["active_chunks"])
        self.assertEqual([], recovery.summary["recovery_damage"])

    def test_recovers_active_prefix_deltas_terminal_and_sequence_gap(self):
        records = core_records(321, generation=2, start=5)
        records += [
            flight_record(2, 7, b"thread-start", generation=2),
            flight_record(9, 8, register_delta({32: 0x71001234}), generation=2),
        ]
        torn = flight_record(5, 9, b"unfinished", generation=2, committed=False)
        raw = artifact(
            directories=[directory_entry(321, 5, 8, 0, 2)],
            chunks=[chunk(0, 321, 2, records, state=1, suffix=torn)],
            emergencies=[emergency(14, 321, 11, pc=0x71001234, signal=9)],
            flags=4,
        )

        recovery = recover_flight(io.BytesIO(raw))

        self.assertEqual([7, 8, 11], [event.global_seq for event in recovery.merged])
        self.assertEqual(0x71001234, recovery.threads[321].registers.pc)
        self.assertEqual(321, recovery.summary["termination"]["initiator_tid"])
        self.assertEqual("termination_intent", recovery.summary["termination"]["cause"])
        self.assertFalse(recovery.summary["complete"])
        self.assertEqual([[9, 10]], recovery.summary["lost_sequences"])
        self.assertEqual(0x1020304050607080, recovery.summary["run_id"])
        self.assertEqual(4242, recovery.summary["pid"])
        self.assertEqual(17, recovery.summary["module_generation"])
        self.assertEqual("libtarget.so", recovery.summary["target_module"])

    def test_crash_recovers_committed_active_prefix_without_terminal_marker(self):
        tid = 701
        generation = 9
        begin = struct.pack("<IIQQ", 700, tid, 0x71004568, generation)
        records = core_records(tid, generation=generation) + [
            flight_record(2, 3, begin, generation=generation),
        ]
        raw = artifact(
            directories=[directory_entry(tid, 1, 3, 0, generation)],
            chunks=[chunk(0, tid, generation, records, state=1)],
            flags=0,
            module_generation=generation,
        )

        recovery = recover_flight(io.BytesIO(raw))

        lifecycle = [event for event in recovery.merged
                     if event.kind in {"thread_begin", "thread_end"}]
        self.assertEqual([(3, "thread_begin", tid)], [
            (event.global_seq, event.kind, event.tid) for event in lifecycle
        ])
        self.assertTrue(recovery.summary["complete"])
        self.assertEqual([0], recovery.summary["active_chunks"])
        self.assertEqual([tid], recovery.summary["unterminated_threads"])

    def test_external_start_below_module_base_uses_retained_chunk_target(self):
        tid = 703
        generation = 10
        begin = struct.pack("<IIQQ", 702, tid, 0x1000, generation)
        end = struct.pack("<I", tid)
        records = core_records(tid, generation=generation) + [
            flight_record(2, 3, begin, generation=generation),
            flight_record(3, 4, end, generation=generation),
        ]
        raw = artifact(
            directories=[directory_entry(tid, 2, 4, 0, generation)],
            chunks=[chunk(0, tid, generation, records, state=2)],
            flags=0,
            module_generation=generation,
        )

        recovery = recover_flight(io.BytesIO(raw))

        self.assertTrue(recovery.summary["complete"])
        begin_event = next(event for event in recovery.merged
                           if event.kind == "thread_begin")
        self.assertEqual((702, tid, 0x1000, generation), struct.unpack(
            "<IIQQ", bytes.fromhex(begin_event.data["payload_hex"])
        ))

    def test_sealed_chunk_resolves_dictionary_and_reassembles_logical_call(self):
        generation = 3
        records = core_records(88, generation=generation)
        records += [
            flight_record(6, 3, string_definition(1, b"jni"), flags=3, generation=generation),
            flight_record(6, 4, string_definition(2, b"Lookup"), flags=3, generation=generation),
            flight_record(6, 5, string_definition(3, b"snow"), flags=3, generation=generation),
            flight_record(6, 6, event_fragment(9, 10, 0, 2, 1, 2, 3), flags=4,
                          generation=generation),
            flight_record(6, 7, string_definition(4, "man☃".encode()), flags=3,
                          generation=generation),
            flight_record(6, 8, event_fragment(9, 10, 1, 2, 1, 2, 4), flags=4,
                          generation=generation),
        ]
        raw = artifact(
            directories=[directory_entry(88, 1, 8, 0, generation)],
            chunks=[chunk(0, 88, generation, records)],
        )

        recovery = recover_flight(io.BytesIO(raw))

        calls = [event for event in recovery.merged if event.kind == "call"]
        self.assertEqual(1, len(calls))
        self.assertEqual(8, calls[0].global_seq)
        self.assertEqual("jni", calls[0].data["category"])
        self.assertEqual("Lookup", calls[0].data["name"])
        self.assertEqual("snowman☃", calls[0].data["detail"])
        self.assertEqual([6, 8], calls[0].data["fragment_sequences"])
        self.assertEqual([], recovery.summary["recovery_damage"])

    def test_chunk_local_string_ids_reset_across_a_cross_chunk_logical_event(self):
        first = core_records(88)
        first += [
            flight_record(6, 3, string_definition(1, b"jni"), flags=3),
            flight_record(6, 4, string_definition(2, b"Lookup"), flags=3),
            flight_record(6, 5, string_definition(3, b"A"), flags=3),
            flight_record(6, 6, event_fragment(9, 2, 0, 2, 1, 2, 3), flags=4),
        ]
        second = core_records(88, start=7)
        second += [
            flight_record(6, 9, string_definition(1, b"jni"), flags=3),
            flight_record(6, 10, string_definition(2, b"Lookup"), flags=3),
            flight_record(6, 11, string_definition(3, b"B"), flags=3),
            flight_record(6, 12, event_fragment(9, 2, 1, 2, 1, 2, 3), flags=4),
        ]
        raw = artifact(
            directories=[directory_entry(88, 1, 12, 1, 1)],
            chunks=[chunk(0, 88, 1, first), chunk(1, 88, 1, second)],
        )

        recovery = recover_flight(io.BytesIO(raw))

        calls = [event for event in recovery.merged if event.kind == "call"]
        self.assertEqual("AB", calls[0].data["detail"])
        self.assertEqual([6, 12], calls[0].data["fragment_sequences"])

    def test_merges_two_threads_by_sequence_not_physical_chunk_order(self):
        physically_first = core_records(10, start=3) + [
            flight_record(2, 7, b"thread-10")
        ]
        physically_second = core_records(20, start=1) + [
            flight_record(2, 6, b"thread-20")
        ]
        raw = artifact(
            directories=[
                directory_entry(10, 3, 7, 0, 1),
                directory_entry(20, 1, 6, 1, 1),
            ],
            chunks=[
                chunk(0, 10, 1, physically_first),
                chunk(1, 20, 1, physically_second),
            ],
        )

        recovery = recover_flight(io.BytesIO(raw))

        self.assertEqual([(6, 20), (7, 10)],
                         [(event.global_seq, event.tid) for event in recovery.merged])

    def test_accepts_interleaved_global_sequence_allocation_in_preamble_pair(self):
        records = [
            flight_record(1, 1, chunk_begin(88)),
            flight_record(9, 3, checkpoint(), flags=1),
        ]
        raw = artifact(
            directories=[directory_entry(88, 1, 3, 0, 1)],
            chunks=[chunk(0, 88, 1, records)],
        )

        recovery = recover_flight(io.BytesIO(raw))

        self.assertEqual([], recovery.summary["recovery_damage"])
        self.assertEqual([[2, 2]], recovery.summary["lost_sequences"])

    def test_omits_and_reports_incomplete_logical_event_at_retention_boundary(self):
        records = core_records(88)
        records += [
            flight_record(6, 3, string_definition(1, b"jni"), flags=3),
            flight_record(6, 4, string_definition(2, b"Lookup"), flags=3),
            flight_record(6, 5, string_definition(3, b"partial"), flags=3),
            flight_record(6, 6, event_fragment(9, 12, 1, 2, 1, 2, 3), flags=4),
        ]
        raw = artifact(
            directories=[directory_entry(88, 1, 6, 0, 1)],
            chunks=[chunk(0, 88, 1, records)],
        )

        recovery = recover_flight(io.BytesIO(raw))

        self.assertEqual([], [event for event in recovery.merged if event.kind == "call"])
        self.assertEqual([0], recovery.summary["incomplete_logical_events"][0]["missing_fragments"])
        self.assertEqual(9, recovery.summary["incomplete_logical_events"][0]["event_id"])
        self.assertFalse(recovery.summary["complete"])

    def test_rejects_a_committed_active_record_with_bad_checksum(self):
        records = core_records(1)
        damaged = bytearray(flight_record(7, 3, b"\0" * 8))
        damaged[16] ^= 1
        records.append(bytes(damaged))
        raw = artifact(
            directories=[directory_entry(1, 1, 3, 0, 1)],
            chunks=[chunk(0, 1, 1, records, state=1)],
        )

        with self.assertRaisesRegex(FlightTraceError, "checksum"):
            recover_flight(io.BytesIO(raw))

    def test_active_recovery_ignores_interrupted_sealing_metadata(self):
        records = core_records(1) + [flight_record(2, 3, b"thread-start")]
        interrupted = bytearray(chunk(0, 1, 1, records, state=2))
        struct.pack_into("<I", interrupted, 12, 1)
        raw = artifact(
            directories=[directory_entry(1, 1, 3, 0, 1)],
            chunks=[bytes(interrupted)],
        )

        recovery = recover_flight(io.BytesIO(raw))

        self.assertEqual([3], [event.global_seq for event in recovery.merged])

    def test_rejects_committed_active_records_with_unknown_type_or_flags(self):
        invalid_records = {
            "type": flight_record(99, 3, b"committed"),
            "flags": flight_record(2, 3, b"committed", flags=1),
        }
        for label, invalid in invalid_records.items():
            with self.subTest(label=label):
                records = core_records(1) + [invalid]
                raw = artifact(
                    directories=[directory_entry(1, 1, 3, 0, 1)],
                    chunks=[chunk(0, 1, 1, records, state=1)],
                )
                with self.assertRaisesRegex(FlightTraceError, "record (type|flags)"):
                    recover_flight(io.BytesIO(raw))

    def test_excludes_bad_sealed_chunk_and_reports_its_lost_interval(self):
        records = core_records(1) + [flight_record(3, 3, b"opaque")]
        raw = artifact(
            directories=[directory_entry(1, 1, 3, 0, 1)],
            chunks=[chunk(0, 1, 1, records, corrupt_checksum=True)],
        )

        recovery = recover_flight(io.BytesIO(raw))

        self.assertEqual((), recovery.merged)
        self.assertFalse(recovery.summary["complete"])
        self.assertEqual([[1, 3]], recovery.summary["lost_sequences"])
        self.assertIn("sealed chunk 0 checksum mismatch", recovery.summary["recovery_damage"])

    def test_uses_damaged_sealed_header_range_when_directory_is_rotating(self):
        records = core_records(1)
        raw = artifact(
            directories=[directory_entry(1, 1, 0, 0, 1, state=2)],
            chunks=[chunk(0, 1, 1, records, corrupt_checksum=True)],
        )

        recovery = recover_flight(io.BytesIO(raw))

        self.assertEqual([[1, 2]], recovery.summary["lost_sequences"])
        self.assertIn("checksum mismatch", recovery.summary["recovery_damage"][0])

    def test_rejects_duplicate_global_sequences_across_chunks(self):
        first = core_records(10, generation=1)
        second = core_records(20, generation=1, start=1)
        raw = artifact(
            directories=[
                directory_entry(10, 1, 2, 0, 1),
                directory_entry(20, 1, 2, 1, 1),
            ],
            chunks=[chunk(0, 10, 1, first), chunk(1, 20, 1, second)],
        )

        with self.assertRaisesRegex(FlightTraceError, "duplicate global sequence"):
            recover_flight(io.BytesIO(raw))

    def test_excludes_nonmonotonic_sequences_inside_one_committed_chunk(self):
        records = core_records(10) + [
            flight_record(2, 4, b"later"),
            flight_record(3, 3, b"earlier"),
        ]
        raw = artifact(
            directories=[directory_entry(10, 1, 4, 0, 1)],
            chunks=[chunk(0, 10, 1, records)],
        )

        recovery = recover_flight(io.BytesIO(raw))

        self.assertIn("sequence order", recovery.summary["recovery_damage"][0])
        self.assertFalse(recovery.summary["complete"])

    def test_excludes_a_semantically_malformed_sealed_chunk_transactionally(self):
        healthy = core_records(10) + [flight_record(2, 3, b"healthy")]
        malformed = core_records(20, start=4) + [
            flight_record(2, 6, b"must-not-leak"),
            flight_record(4, 7, qtrb_instruction(metadata_id=99)),
        ]
        raw = artifact(
            directories=[
                directory_entry(10, 1, 3, 0, 1),
                directory_entry(20, 4, 7, 1, 1),
            ],
            chunks=[chunk(0, 10, 1, healthy), chunk(1, 20, 1, malformed)],
        )

        recovery = recover_flight(io.BytesIO(raw))

        self.assertEqual([(3, 10)],
                         [(event.global_seq, event.tid) for event in recovery.merged])
        self.assertEqual([10], list(recovery.threads))
        self.assertEqual([[1, 3]], recovery.summary["retained_sequences"])
        self.assertEqual([[4, 7]], recovery.summary["lost_sequences"])
        self.assertIn("undefined instruction metadata",
                      recovery.summary["recovery_damage"][0])

    def test_reports_a_uint64_lost_interval_without_iterating_over_each_sequence(self):
        maximum = (1 << 64) - 1
        raw = artifact(
            directories=[directory_entry(7, 1, maximum, 0xFFFFFFFF, 0)],
            chunks=[chunk(0, 7, 1, [], state=1)],
        )

        recovery = recover_flight(io.BytesIO(raw))

        self.assertEqual([[1, maximum]], recovery.summary["lost_sequences"])

    def test_reports_stale_directory_generation_without_mistaking_chunk_identity(self):
        records = core_records(321, generation=3)
        raw = artifact(
            directories=[directory_entry(321, 1, 2, 0, 2)],
            chunks=[chunk(0, 321, 3, records)],
        )

        recovery = recover_flight(io.BytesIO(raw))

        self.assertEqual([0], recovery.summary["stale_directory_entries"])
        self.assertEqual(321, recovery.threads[321].tid)
        self.assertFalse(recovery.summary["complete"])

    def test_recovers_chunks_while_directory_entry_is_mid_rotation(self):
        records = core_records(321)
        raw = artifact(
            directories=[directory_entry(321, 1, 0, 0, 1, state=2)],
            chunks=[chunk(0, 321, 1, records)],
        )

        recovery = recover_flight(io.BytesIO(raw))

        self.assertEqual([0], recovery.summary["rotating_directory_entries"])
        self.assertEqual(321, recovery.threads[321].tid)
        self.assertEqual([], recovery.summary["recovery_damage"])

    def test_uses_torn_active_directory_range_only_as_an_unreliable_hint(self):
        raw = artifact(
            directories=[directory_entry(321, 1, 0, 0, 1)],
            chunks=[chunk(0, 321, 1, core_records(321), state=1)],
        )

        recovery = recover_flight(io.BytesIO(raw))

        self.assertEqual([0], recovery.summary["unreliable_directory_ranges"])
        self.assertEqual([], recovery.summary["recovery_damage"])

    def test_ignores_unpublished_nonzero_free_directory_body(self):
        raw = artifact(
            directories=[
                directory_entry(88, 1, 2, 0, 1),
                directory_entry(99, 0, 0, 0xFFFFFFFF, 0, state=0),
            ],
            chunks=[chunk(0, 88, 1, core_records(88))],
        )

        recovery = recover_flight(io.BytesIO(raw))

        self.assertEqual([88], list(recovery.threads))

    def test_ignores_unpublished_nonzero_free_chunk_header_and_stale_body(self):
        raw = artifact(
            directories=[directory_entry(88, 1, 2, 0, 1)],
            chunks=[
                chunk(0, 88, 1, core_records(88)),
                chunk(1, 99, 4, core_records(99, generation=4), state=0),
            ],
        )

        recovery = recover_flight(io.BytesIO(raw))

        self.assertEqual([88], list(recovery.threads))

    def test_recovers_explicit_coverage_gap_from_emergency_slot(self):
        raw = artifact(
            directories=[directory_entry(77, 0, 0, 0xFFFFFFFF, 0)],
            chunks=[chunk(0, 77, 1, [], state=1)],
            emergencies=[emergency(15, 77, 4, pc=0x71009900, flags=2)],
        )

        recovery = recover_flight(io.BytesIO(raw))

        self.assertEqual("coverage_gap", recovery.merged[0].kind)
        self.assertEqual(2, recovery.merged[0].data["reason_flags"])
        self.assertFalse(recovery.summary["complete"])
        self.assertEqual(77, recovery.summary["coverage_gaps"][0]["tid"])

    def test_recovers_an_unreturned_signal_handler_begin_as_an_open_interval(self):
        raw = artifact(
            directories=[directory_entry(77, 0, 0, 0xFFFFFFFF, 0)],
            chunks=[chunk(0, 77, 1, [], state=1)],
            emergencies=[emergency(
                12, 77, 41, pc=0x71009900, sp=0x81001000,
                fault=0xdeadbeef, signal=11, code=1, flags=0x00010002,
            )],
        )

        recovery = recover_flight(io.BytesIO(raw))

        self.assertEqual([{
            "tid": 77,
            "depth": 2,
            "nested_delivery_count": 1,
            "begin_sequence": 41,
            "return_sequence": None,
            "returned": False,
            "unreturned_ancestor_count": 1,
        }], recovery.summary["signal_handler_intervals"])

    def test_recovers_a_signal_handler_return_as_a_closed_interval(self):
        raw = artifact(
            directories=[directory_entry(77, 0, 0, 0xFFFFFFFF, 0)],
            chunks=[chunk(0, 77, 1, [], state=1)],
            emergencies=[emergency(
                13, 77, 44, pc=0x71009904, sp=0x81001008,
                fault=41, signal=11, code=1, flags=0x00010001,
            )],
        )

        recovery = recover_flight(io.BytesIO(raw))

        self.assertEqual([{
            "tid": 77,
            "depth": 1,
            "nested_delivery_count": 1,
            "begin_sequence": 41,
            "return_sequence": 44,
            "returned": True,
            "unreturned_ancestor_count": 0,
        }], recovery.summary["signal_handler_intervals"])

    def test_recovers_canonical_and_legacy_dropped_gap_checksums(self):
        for canonical in (True, False):
            with self.subTest(canonical=canonical):
                raw = artifact(
                    directories=[directory_entry(77, 0, 0, 0xFFFFFFFF, 0)],
                    chunks=[chunk(0, 77, 1, [], state=1)],
                    emergencies=[emergency(
                        15, 77, 4, pc=0x71009900, code=7, flags=2,
                        canonical_gap_checksum=canonical,
                    )],
                )
                recovery = recover_flight(io.BytesIO(raw))
                gap = recovery.summary["coverage_gaps"][0]
                self.assertEqual(7, gap["dropped_gap_count"])

    def test_ignores_torn_emergency_slot_during_overwrite_publication(self):
        raw = artifact(
            directories=[directory_entry(77, 0, 0, 0xFFFFFFFF, 0)],
            chunks=[chunk(0, 77, 1, [], state=1)],
            emergencies=[emergency(14, 77, 4, pc=0x71009900, version=3)],
        )

        recovery = recover_flight(io.BytesIO(raw))

        self.assertEqual((), recovery.merged)
        self.assertEqual("unknown", recovery.summary["termination"]["cause"])

    def test_rejects_undefined_chunk_local_instruction_metadata(self):
        records = core_records(12) + [flight_record(4, 3, qtrb_instruction(metadata_id=99))]
        raw = artifact(
            directories=[directory_entry(12, 1, 3, 0, 1)],
            chunks=[chunk(0, 12, 1, records, state=1)],
        )

        with self.assertRaisesRegex(FlightTraceError, "undefined instruction metadata"):
            recover_flight(io.BytesIO(raw))

    def test_accepts_zero_width_names_and_operand_sizes_emitted_by_native_encoder(self):
        records = core_records(12) + [
            flight_record(4, 3, qtrb_zero_width_definition(), flags=1),
            flight_record(4, 4, qtrb_one_read_instruction()),
        ]
        raw = artifact(
            directories=[directory_entry(12, 1, 4, 0, 1)],
            chunks=[chunk(0, 12, 1, records)],
        )

        recovery = recover_flight(io.BytesIO(raw))

        self.assertEqual([4], [event.global_seq for event in recovery.merged])

    def test_preserves_rich_instruction_definitions_in_expanded_events(self):
        records = core_records(12) + [
            flight_record(4, 3, qtrb_rich_instruction_definition(), flags=1),
            flight_record(4, 4, qtrb_rich_instruction()),
        ]
        raw = artifact(
            directories=[directory_entry(12, 1, 4, 0, 1)],
            chunks=[chunk(0, 12, 1, records)],
        )

        recovery = recover_flight(io.BytesIO(raw))

        instruction = recovery.merged[0].data
        self.assertEqual(
            (
                {"index": 0, "width": 4, "name": "W0", "value": 0x11},
                {"index": 31, "width": 8, "name": "SP", "value": 0x22},
            ),
            instruction["read_registers"],
        )
        self.assertEqual(
            (
                {"index": 32, "width": 8, "name": "NZCV", "value": 0x33},
                {"index": 33, "width": 8, "name": "PC", "value": 0x44},
            ),
            instruction["write_registers"],
        )
        self.assertEqual(
            ({
                "base": 0, "index": 31, "extend": 3, "mode": 1,
                "shift": 2, "access_kind": 3, "writeback": 1,
                "size": 16, "displacement": -16,
            },),
            instruction["memory_operands"],
        )
        self.assertEqual(-0x20, instruction["displacement"])
        self.assertEqual("B.EQ", instruction["mnemonic"])
        self.assertEqual("x0, #0x4", instruction["operands"])
        self.assertEqual("fallback", instruction["disassembly"])

    def test_rejects_mismatched_logical_fragment_metadata(self):
        records = core_records(88)
        records += [
            flight_record(6, 3, string_definition(1, b"jni"), flags=3),
            flight_record(6, 4, string_definition(2, b"Lookup"), flags=3),
            flight_record(6, 5, string_definition(3, b"a"), flags=3),
            flight_record(6, 6, event_fragment(9, 2, 0, 2, 1, 2, 3), flags=4),
            flight_record(6, 7, string_definition(4, b"b"), flags=3),
            flight_record(6, 8, event_fragment(9, 3, 1, 2, 1, 2, 4), flags=4),
        ]
        raw = artifact(
            directories=[directory_entry(88, 1, 8, 0, 1)],
            chunks=[chunk(0, 88, 1, records, state=1)],
        )

        with self.assertRaisesRegex(FlightTraceError, "fragment metadata"):
            recover_flight(io.BytesIO(raw))

    def test_rejects_logical_event_id_collisions_across_event_kinds(self):
        records = core_records(88)
        records += [
            flight_record(6, 3, string_definition(1, b"jni"), flags=3),
            flight_record(6, 4, string_definition(2, b"Lookup"), flags=3),
            flight_record(6, 5, string_definition(3, b"A"), flags=3),
            flight_record(6, 6, event_fragment(9, 2, 0, 2, 1, 2, 3), flags=4),
            flight_record(6, 7, string_definition(4, b"rule"), flags=3),
            flight_record(6, 8, string_definition(5, b"B"), flags=3),
            flight_record(7, 9, event_fragment(9, 2, 1, 2, 4, 5), flags=4),
        ]
        raw = artifact(
            directories=[directory_entry(88, 1, 9, 0, 1)],
            chunks=[chunk(0, 88, 1, records, state=1)],
        )

        with self.assertRaisesRegex(FlightTraceError, "logical fragment kind mismatch"):
            recover_flight(io.BytesIO(raw))

    def test_excludes_sealed_fragment_metadata_collision_transactionally(self):
        healthy = core_records(10) + [flight_record(2, 3, b"healthy")]
        malformed = core_records(20, start=4) + [
            flight_record(6, 6, string_definition(1, b"jni"), flags=3),
            flight_record(6, 7, string_definition(2, b"Lookup"), flags=3),
            flight_record(6, 8, string_definition(3, b"A"), flags=3),
            flight_record(6, 9, event_fragment(9, 2, 0, 2, 1, 2, 3), flags=4),
            flight_record(6, 10, string_definition(4, b"B"), flags=3),
            flight_record(6, 11, event_fragment(9, 3, 1, 2, 1, 2, 4), flags=4),
        ]
        raw = artifact(
            directories=[
                directory_entry(10, 1, 3, 0, 1),
                directory_entry(20, 4, 11, 1, 1),
            ],
            chunks=[chunk(0, 10, 1, healthy), chunk(1, 20, 1, malformed)],
        )

        recovery = recover_flight(io.BytesIO(raw))

        self.assertEqual([(3, 10)],
                         [(event.global_seq, event.tid) for event in recovery.merged])
        self.assertEqual([10], list(recovery.threads))
        self.assertEqual([[1, 3]], recovery.summary["retained_sequences"])
        self.assertEqual([[4, 11]], recovery.summary["lost_sequences"])
        self.assertIn("logical fragment metadata mismatch",
                      recovery.summary["recovery_damage"][0])

    def test_excludes_sealed_invalid_reassembled_fragment_utf8_transactionally(self):
        healthy = core_records(10) + [flight_record(2, 3, b"healthy")]
        malformed = core_records(20, start=4) + [
            flight_record(6, 6, string_definition(1, b"jni"), flags=3),
            flight_record(6, 7, string_definition(2, b"Lookup"), flags=3),
            flight_record(6, 8, string_definition(3, b"\xf0"), flags=3),
            flight_record(6, 9, event_fragment(9, 2, 0, 2, 1, 2, 3), flags=4),
            flight_record(6, 10, string_definition(4, b"("), flags=3),
            flight_record(6, 11, event_fragment(9, 2, 1, 2, 1, 2, 4), flags=4),
        ]
        raw = artifact(
            directories=[
                directory_entry(10, 1, 3, 0, 1),
                directory_entry(20, 4, 11, 1, 1),
            ],
            chunks=[chunk(0, 10, 1, healthy), chunk(1, 20, 1, malformed)],
        )

        recovery = recover_flight(io.BytesIO(raw))

        self.assertEqual([(3, 10)],
                         [(event.global_seq, event.tid) for event in recovery.merged])
        self.assertEqual([[4, 11]], recovery.summary["lost_sequences"])
        self.assertIn("UTF-8", recovery.summary["recovery_damage"][0])

    def test_rejects_fragment_collisions_with_an_active_contributor(self):
        sealed = core_records(88) + [
            flight_record(6, 3, string_definition(1, b"jni"), flags=3),
            flight_record(6, 4, string_definition(2, b"Lookup"), flags=3),
            flight_record(6, 5, string_definition(3, b"A"), flags=3),
            flight_record(6, 6, event_fragment(9, 2, 0, 2, 1, 2, 3), flags=4),
        ]
        active = core_records(88, start=7) + [
            flight_record(6, 9, string_definition(1, b"rule"), flags=3),
            flight_record(6, 10, string_definition(2, b"B"), flags=3),
            flight_record(7, 11, event_fragment(9, 2, 1, 2, 1, 2), flags=4),
        ]
        raw = artifact(
            directories=[directory_entry(88, 1, 11, 1, 1)],
            chunks=[chunk(0, 88, 1, sealed), chunk(1, 88, 1, active, state=1)],
        )

        with self.assertRaisesRegex(FlightTraceError, "logical fragment kind mismatch"):
            recover_flight(io.BytesIO(raw))

    def test_rejects_plain_calls_larger_than_the_native_3072_byte_limit(self):
        records = core_records(88)
        records += [
            flight_record(6, 3, string_definition(1, b"jni"), flags=3),
            flight_record(6, 4, string_definition(2, b"Lookup"), flags=3),
            flight_record(6, 5, string_definition(3, b"x" * 3073), flags=3),
            flight_record(6, 6, struct.pack("<III", 1, 2, 3)),
        ]
        raw = artifact(
            directories=[directory_entry(88, 1, 6, 0, 1)],
            chunks=[chunk(0, 88, 1, records, state=1, chunk_bytes=8192)],
            chunk_bytes=8192,
        )

        with self.assertRaisesRegex(FlightTraceError, "event field limit"):
            recover_flight(io.BytesIO(raw))

    def test_rejects_empty_logical_event_fragments(self):
        records = core_records(88)
        records += [
            flight_record(6, 3, string_definition(1, b"jni"), flags=3),
            flight_record(6, 4, string_definition(2, b"Lookup"), flags=3),
            flight_record(6, 5, string_definition(3, b""), flags=3),
            flight_record(6, 6, event_fragment(9, 2, 0, 2, 1, 2, 3), flags=4),
        ]
        raw = artifact(
            directories=[directory_entry(88, 1, 6, 0, 1)],
            chunks=[chunk(0, 88, 1, records, state=1)],
        )

        with self.assertRaisesRegex(FlightTraceError, "logical fragment metadata"):
            recover_flight(io.BytesIO(raw))

    def test_summary_accounts_for_hidden_records_and_checkpoint_pcs(self):
        first = core_records(10, start=1, pc=0x71001000) + [
            flight_record(9, 3, register_delta({32: 0x71001111})),
            flight_record(2, 4, b"visible"),
        ]
        second = core_records(20, start=5, pc=0x71002000) + [
            flight_record(6, 7, string_definition(1, b"hidden"), flags=3),
        ]
        raw = artifact(
            directories=[
                directory_entry(10, 1, 4, 0, 1),
                directory_entry(20, 5, 7, 1, 1),
            ],
            chunks=[chunk(0, 10, 1, first), chunk(1, 20, 1, second)],
        )

        recovery = recover_flight(io.BytesIO(raw))

        self.assertEqual([[1, 7]], recovery.summary["retained_sequences"])
        self.assertEqual([[1, 4]], recovery.summary["threads"]["10"]["retained_sequences"])
        self.assertEqual([[5, 7]], recovery.summary["threads"]["20"]["retained_sequences"])
        self.assertEqual(20, recovery.summary["last_recorded_thread"])
        self.assertEqual([0x71001000, 0x71001111, 0x71002000],
                         recovery.summary["target_pcs"])

    def test_rejects_string_events_that_exceed_task5_field_limits(self):
        records = core_records(88)
        records += [
            flight_record(6, 3, string_definition(1, b"c" * 256), flags=3),
            flight_record(6, 4, string_definition(2, b"Lookup"), flags=3),
            flight_record(6, 5, string_definition(3, b"detail"), flags=3),
            flight_record(6, 6, struct.pack("<III", 1, 2, 3)),
        ]
        raw = artifact(
            directories=[directory_entry(88, 1, 6, 0, 1)],
            chunks=[chunk(0, 88, 1, records, state=1)],
        )

        with self.assertRaisesRegex(FlightTraceError, "event field limit"):
            recover_flight(io.BytesIO(raw))

    def test_rejects_invalid_superblock_regions_identities_and_enums(self):
        records = core_records(1)
        valid = artifact(
            directories=[directory_entry(1, 1, 2, 0, 1)],
            chunks=[chunk(0, 1, 1, records)],
        )
        mutations = {
            "magic": lambda raw: struct.pack_into("<I", raw, 0, 0),
            "byte order": lambda raw: struct.pack_into("<B", raw, 6, 2),
            "pointer width": lambda raw: struct.pack_into("<B", raw, 7, 16),
            "artifact size": lambda raw: struct.pack_into("<Q", raw, 16, len(raw) + 1),
            "directory bounds": lambda raw: struct.pack_into("<Q", raw, 24, len(raw) - 8),
            "chunk bounds": lambda raw: struct.pack_into("<Q", raw, 40, len(raw)),
            "emergency bounds": lambda raw: struct.pack_into("<Q", raw, 56, len(raw)),
            "flags": lambda raw: struct.pack_into("<I", raw, 72, 0x100),
            "run ID": lambda raw: struct.pack_into("<Q", raw, 80, 0),
            "PID": lambda raw: struct.pack_into("<I", raw, 88, 0),
            "target name": lambda raw: struct.pack_into("<H", raw, 96, 0),
            "directory state": lambda raw: struct.pack_into("<I", raw, SUPERBLOCK_BYTES + 4, 9),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                damaged = bytearray(valid)
                mutate(damaged)
                with self.assertRaises(FlightTraceError):
                    recover_flight(io.BytesIO(damaged))

    def test_rejects_chunk_identity_that_disagrees_with_superblock(self):
        records = [
            flight_record(1, 1, chunk_begin(1, target=b"other.so")),
            flight_record(9, 2, checkpoint(), flags=1),
        ]
        raw = artifact(
            directories=[directory_entry(1, 1, 2, 0, 1)],
            chunks=[chunk(0, 1, 1, records, state=1)],
        )

        with self.assertRaisesRegex(FlightTraceError, "target"):
            recover_flight(io.BytesIO(raw))

    def test_rejects_values_that_exceed_a_32_bit_producer_abi(self):
        cases = {}
        cases["chunk metadata"] = [
            flight_record(1, 1, chunk_begin(1, pointer_width=4, module_base=0x171000000)),
            flight_record(9, 2, checkpoint(pc=0x71001000, sp=0x7FFF0000), flags=1),
        ]
        cases["checkpoint"] = [
            flight_record(1, 1, chunk_begin(1, pointer_width=4)),
            flight_record(9, 2, checkpoint(pc=0x171001000, sp=0x7FFF0000), flags=1),
        ]
        cases["delta"] = [
            flight_record(1, 1, chunk_begin(1, pointer_width=4)),
            flight_record(9, 2, checkpoint(pc=0x71001000, sp=0x7FFF0000), flags=1),
            flight_record(9, 3, register_delta({32: 0x171001234})),
        ]
        cases["instruction address"] = [
            flight_record(1, 1, chunk_begin(1, pointer_width=4, module_base=0xFFF00000)),
            flight_record(9, 2, checkpoint(pc=0xFFF01000, sp=0x7FFF0000), flags=1),
            flight_record(4, 3, qtrb_instruction_definition(), flags=1),
            flight_record(4, 4, qtrb_instruction(relative_pc=0x200000)),
        ]
        for label, records in cases.items():
            with self.subTest(label=label):
                raw = artifact(
                    directories=[directory_entry(1, 1, len(records), 0, 1)],
                    chunks=[chunk(0, 1, 1, records, state=1)],
                    pointer_width=4,
                )
                with self.assertRaisesRegex(FlightTraceError, "pointer width"):
                    recover_flight(io.BytesIO(raw))

        raw = artifact(
            directories=[directory_entry(1, 0, 0, 0xFFFFFFFF, 0)],
            chunks=[chunk(0, 1, 1, [], state=1)],
            emergencies=[emergency(14, 1, 3, pc=0x171001234)],
            pointer_width=4,
        )
        with self.assertRaisesRegex(FlightTraceError, "pointer width"):
            recover_flight(io.BytesIO(raw))


if __name__ == "__main__":
    unittest.main()
