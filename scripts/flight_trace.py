"""Strict, bounded host recovery for persistent QBDI flight artifacts."""

from __future__ import annotations

import dataclasses
import struct
from typing import BinaryIO


SUPERBLOCK_BYTES = 4096
DIRECTORY_ENTRY_BYTES = 64
CHUNK_HEADER_BYTES = 64
RECORD_HEADER_BYTES = 24
EMERGENCY_RECORD_BYTES = 64
EMERGENCY_SLOT_BYTES = 128
TARGET_NAME_BYTES = 128
MAGIC = 0x51464C54
LEGACY_VERSION = 1
VERSION = 2
RECORD_COMMIT = 0x51434D54
EMERGENCY_COMMITTED = 0x80000000
KNOWN_INCOMPLETE_FLAGS = 0x0F
INVALID_INDEX = 0xFFFFFFFF

SUPERBLOCK_FIXED = struct.Struct("<IHBBH6xQQIIQIIQIII4xQIIH")
DIRECTORY_ENTRY = struct.Struct("<IIQQII32x")
CHUNK_HEADER = struct.Struct("<IHHIIIIQQIII12x")
RECORD_HEADER = struct.Struct("<HHIQII")
EMERGENCY_RECORD = struct.Struct("<IIQQQQIIIIII")
CHUNK_BEGIN_FIXED = struct.Struct("<BBHHHIIQQQ")
CHECKPOINT = struct.Struct("<" + "Q" * 34)
DELTA_MASK = struct.Struct("<Q")
QTRB_HEADER = struct.Struct("<HHI")
QTRB_INSTRUCTION_DEFINITION = struct.Struct("<IIQQqIBBBB")
QTRB_MEMORY_OPERAND = struct.Struct("<BBBBBBBIq")
QTRB_INSTRUCTION = struct.Struct("<QIQIBB")
QTRB_MEMORY = struct.Struct("<IQBBHQIQ")
STRING_DEFINITION = struct.Struct("<II")
FRAGMENT = struct.Struct("<QIHH")

RECORD_NAMES = {
    1: "chunk_begin",
    2: "thread_begin",
    3: "thread_end",
    4: "instruction",
    5: "memory",
    6: "call",
    7: "rule",
    8: "error",
    9: "register_delta",
    10: "syscall",
    11: "signal",
    12: "signal_handler_begin",
    13: "signal_handler_return",
    14: "termination_intent",
    15: "coverage_gap",
}
PROFILE_NAMES = ("fast", "balanced", "full")


class FlightTraceError(RuntimeError):
    """The artifact violates the persistent flight wire contract."""


@dataclasses.dataclass(frozen=True, slots=True)
class FlightRegisters:
    x: tuple[int, ...]
    sp: int
    pc: int
    nzcv: int

    @classmethod
    def from_values(cls, values: list[int] | tuple[int, ...]) -> "FlightRegisters":
        if len(values) != 34:
            raise FlightTraceError("register snapshot must contain 34 values")
        return cls(tuple(values[:31]), values[31], values[32], values[33])


@dataclasses.dataclass(frozen=True, slots=True)
class FlightEvent:
    global_seq: int
    tid: int
    kind: str
    data: dict[str, object]
    source_offset: int | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class FlightThread:
    tid: int
    events: tuple[FlightEvent, ...]
    registers: FlightRegisters | None


@dataclasses.dataclass(frozen=True, slots=True)
class FlightRecovery:
    merged: tuple[FlightEvent, ...]
    threads: dict[int, FlightThread]
    summary: dict[str, object]


@dataclasses.dataclass(frozen=True, slots=True)
class _Superblock:
    version: int
    pointer_width: int
    artifact_bytes: int
    directory_offset: int
    directory_entries: int
    chunk_offset: int
    chunk_bytes: int
    chunk_count: int
    emergency_offset: int
    emergency_record_bytes: int
    emergency_count: int
    flags: int
    run_id: int
    pid: int
    module_generation: int
    target: str


@dataclasses.dataclass(frozen=True, slots=True)
class _Directory:
    index: int
    tid: int
    state: int
    first: int
    last: int
    chunk_index: int
    generation: int
    range_reliable: bool


@dataclasses.dataclass(frozen=True, slots=True)
class _WireRecord:
    kind: int
    flags: int
    sequence: int
    payload: bytes
    source_offset: int


@dataclasses.dataclass(frozen=True, slots=True)
class _FragmentValue:
    sequence: int
    tid: int
    chunk_index: int
    kind: int
    event_id: int
    total: int
    index: int
    count: int
    fixed: tuple[str, ...]
    detail: bytes
    source_offset: int


@dataclasses.dataclass(frozen=True, slots=True)
class _DecodedChunk:
    index: int
    tid: int
    state: int
    records: tuple[_WireRecord, ...]
    events: tuple[FlightEvent, ...]
    fragments: tuple[_FragmentValue, ...]
    registers: FlightRegisters
    last_state_sequence: int
    checkpoint_pc: int


class _FragmentGroupError(FlightTraceError):
    def __init__(self, message: str, chunk_indexes: set[int]) -> None:
        super().__init__(message)
        self.chunk_indexes = frozenset(chunk_indexes)


class _Cursor:
    def __init__(self, data: bytes, label: str) -> None:
        self.data = data
        self.offset = 0
        self.label = label

    def take(self, size: int) -> bytes:
        if size < 0 or size > len(self.data) - self.offset:
            raise FlightTraceError(f"invalid {self.label} payload length")
        result = self.data[self.offset:self.offset + size]
        self.offset += size
        return result

    def unpack(self, layout: struct.Struct) -> tuple[int, ...]:
        return layout.unpack(self.take(layout.size))

    def u16_bytes(self, maximum: int, field: str) -> bytes:
        size = struct.unpack("<H", self.take(2))[0]
        if size > maximum:
            raise FlightTraceError(f"oversized {field}")
        return self.take(size)

    def u16_text(self, maximum: int, field: str) -> str:
        return _utf8(self.u16_bytes(maximum, field), field)

    def finish(self) -> None:
        if self.offset != len(self.data):
            raise FlightTraceError(f"invalid {self.label} payload length")


def _utf8(raw: bytes, field: str) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise FlightTraceError(f"{field} is not valid UTF-8") from error


def _require_pointer(value: int, maximum: int, field: str) -> int:
    if value > maximum:
        raise FlightTraceError(f"{field} exceeds producer pointer width")
    return value


def _pointer_sum(base: int, offset: int, maximum: int, field: str) -> int:
    _require_pointer(base, maximum, field)
    _require_pointer(offset, maximum, field)
    if offset > maximum - base:
        raise FlightTraceError(f"{field} exceeds producer pointer width")
    return base + offset


def _fnv32(data: bytes) -> int:
    value = 2166136261
    for byte in data:
        value = ((value ^ byte) * 16777619) & 0xFFFFFFFF
    return value


def _checked_region(offset: int, count: int, size: int, artifact_size: int,
                    label: str) -> tuple[int, int]:
    if offset < 0 or count < 0 or size <= 0 or count > (1 << 32) - 1:
        raise FlightTraceError(f"invalid {label} region")
    extent = count * size
    end = offset + extent
    if offset > artifact_size or end > artifact_size or end < offset:
        raise FlightTraceError(f"invalid {label} region bounds")
    return offset, end


def _source_size(source: BinaryIO) -> int:
    try:
        position = source.tell()
        source.seek(0, 2)
        size = source.tell()
        source.seek(position)
    except (AttributeError, OSError) as error:
        raise FlightTraceError("flight source must be seekable") from error
    if not isinstance(size, int) or size < 0:
        raise FlightTraceError("invalid flight source size")
    return size


def _read_at(source: BinaryIO, offset: int, size: int, label: str) -> bytes:
    try:
        source.seek(offset)
    except (AttributeError, OSError) as error:
        raise FlightTraceError(f"cannot seek to {label}") from error
    chunks = bytearray()
    while len(chunks) < size:
        piece = source.read(size - len(chunks))
        if not isinstance(piece, bytes):
            raise FlightTraceError("binary source returned non-bytes data")
        if not piece:
            raise FlightTraceError(f"truncated {label}")
        chunks.extend(piece)
    return bytes(chunks)


def _parse_superblock(source: BinaryIO, source_size: int) -> _Superblock:
    raw = _read_at(source, 0, SUPERBLOCK_BYTES, "flight superblock")
    if any(raw[10:16]) or any(raw[76:80]) or any(raw[226:]):
        raise FlightTraceError("nonzero reserved superblock bytes")
    (magic, version, byte_order, pointer_width, header_bytes, artifact_bytes,
     directory_offset, directory_entry_bytes, directory_entries, chunk_offset,
     chunk_bytes, chunk_count, emergency_offset, emergency_record_bytes,
     emergency_count, flags, run_id, pid, module_generation,
     target_bytes) = SUPERBLOCK_FIXED.unpack_from(raw)
    if magic != MAGIC:
        raise FlightTraceError("invalid flight magic")
    if version not in (LEGACY_VERSION, VERSION):
        raise FlightTraceError("unsupported flight version")
    if byte_order != 1:
        raise FlightTraceError("invalid byte order")
    if pointer_width not in (4, 8):
        raise FlightTraceError("invalid pointer width")
    if header_bytes != SUPERBLOCK_BYTES:
        raise FlightTraceError("invalid superblock size")
    if artifact_bytes != source_size or artifact_bytes < SUPERBLOCK_BYTES:
        raise FlightTraceError("artifact size does not match source")
    if directory_entry_bytes != DIRECTORY_ENTRY_BYTES or directory_entries == 0:
        raise FlightTraceError("invalid directory configuration")
    expected_emergency_bytes = (EMERGENCY_RECORD_BYTES
                                if version == LEGACY_VERSION
                                else EMERGENCY_SLOT_BYTES)
    if (emergency_record_bytes != expected_emergency_bytes or
            emergency_count != directory_entries + 1):
        raise FlightTraceError("invalid emergency configuration")
    if chunk_bytes <= CHUNK_HEADER_BYTES or chunk_bytes & (chunk_bytes - 1) or chunk_count == 0:
        raise FlightTraceError("invalid chunk configuration")
    if flags & ~KNOWN_INCOMPLETE_FLAGS:
        raise FlightTraceError("unknown superblock flags")
    if run_id == 0:
        raise FlightTraceError("invalid run ID")
    if pid == 0:
        raise FlightTraceError("invalid PID")
    if target_bytes == 0 or target_bytes > TARGET_NAME_BYTES:
        raise FlightTraceError("invalid target name length")
    target_raw = raw[98:98 + target_bytes]
    if b"\0" in target_raw or any(raw[98 + target_bytes:98 + TARGET_NAME_BYTES]):
        raise FlightTraceError("invalid target name padding")
    target = _utf8(target_raw, "target module")

    directory = _checked_region(directory_offset, directory_entries,
                                directory_entry_bytes, artifact_bytes, "directory")
    emergency = _checked_region(emergency_offset, emergency_count,
                                emergency_record_bytes, artifact_bytes, "emergency")
    chunks = _checked_region(chunk_offset, chunk_count, chunk_bytes,
                            artifact_bytes, "chunk")
    if directory_offset < SUPERBLOCK_BYTES or directory[1] > emergency[0] or emergency[1] > chunks[0]:
        raise FlightTraceError("overlapping flight regions")
    if directory_offset % 8 or emergency_offset % EMERGENCY_RECORD_BYTES or chunk_offset % chunk_bytes:
        raise FlightTraceError("misaligned flight region")
    return _Superblock(version, pointer_width, artifact_bytes, directory_offset, directory_entries,
                       chunk_offset, chunk_bytes, chunk_count, emergency_offset,
                       emergency_record_bytes, emergency_count, flags, run_id, pid,
                       module_generation, target)


def _parse_directories(source: BinaryIO, superblock: _Superblock) -> list[_Directory]:
    raw = _read_at(source, superblock.directory_offset,
                   superblock.directory_entries * DIRECTORY_ENTRY_BYTES, "thread directory")
    directories = []
    seen_tids: set[int] = set()
    for index in range(superblock.directory_entries):
        entry = raw[index * DIRECTORY_ENTRY_BYTES:(index + 1) * DIRECTORY_ENTRY_BYTES]
        tid, state, first, last, chunk_index, generation = DIRECTORY_ENTRY.unpack(entry)
        if state not in (0, 1, 2):
            raise FlightTraceError(f"invalid directory state at entry {index}")
        if state == 0:
            continue
        if any(entry[32:]):
            raise FlightTraceError(f"nonzero directory reserved bytes at entry {index}")
        if tid == 0 or tid in seen_tids:
            raise FlightTraceError("invalid or duplicate directory TID")
        if state == 2:
            seen_tids.add(tid)
            directories.append(_Directory(index, tid, state, 0, 0,
                                          INVALID_INDEX, 0, False))
            continue
        range_reliable = not ((first == 0) != (last == 0) or
                              (first != 0 and first > last))
        if not range_reliable:
            first = last = 0
        if chunk_index == INVALID_INDEX:
            if generation != 0:
                raise FlightTraceError(f"invalid directory generation at entry {index}")
        elif chunk_index >= superblock.chunk_count or generation == 0:
            raise FlightTraceError(f"invalid directory chunk reference at entry {index}")
        seen_tids.add(tid)
        directories.append(_Directory(index, tid, state, first, last, chunk_index,
                                      generation, range_reliable))
    return directories


def _valid_flags(kind: int, flags: int) -> bool:
    if kind == 4:
        return flags in (0, 1)
    if kind == 6:
        return flags in (0, 3, 4)
    if kind in (7, 8):
        return flags in (0, 4)
    if kind == 9:
        return flags in (0, 1)
    return flags == 0


def _decode_wire_record(data: bytes, offset: int, generation: int, base_offset: int, *,
                        active: bool) -> tuple[_WireRecord, int] | None:
    remaining = len(data) - offset
    if remaining < RECORD_HEADER_BYTES:
        return None if active else _raise("truncated sealed record header")
    kind, flags, total, sequence, checksum, commit = RECORD_HEADER.unpack_from(data, offset)
    storage = (total + 7) & ~7
    expected_commit = RECORD_COMMIT ^ total ^ generation
    published = commit == expected_commit
    if total < RECORD_HEADER_BYTES or total > remaining or storage > remaining:
        if active and not published:
            return None
        raise FlightTraceError("invalid committed record length")
    if commit != expected_commit:
        return None if active else _raise("sealed record commit mismatch")
    if kind not in RECORD_NAMES:
        raise FlightTraceError("unknown committed record type")
    if not _valid_flags(kind, flags):
        raise FlightTraceError("unknown committed record flags")
    payload = data[offset + RECORD_HEADER_BYTES:offset + total]
    expected_checksum = _fnv32(data[offset:offset + 16] + payload)
    if checksum != expected_checksum:
        raise FlightTraceError("committed record checksum mismatch")
    if sequence == 0:
        raise FlightTraceError("record has zero global sequence")
    if any(data[offset + total:offset + storage]):
        raise FlightTraceError("nonzero record alignment padding")
    return _WireRecord(kind, flags, sequence, payload, base_offset + offset), offset + storage


def _raise(message: str):
    raise FlightTraceError(message)


def _scan_chunk_data(data: bytes, generation: int, base_offset: int, *,
                     active: bool) -> list[_WireRecord]:
    records = []
    offset = 0
    while offset < len(data):
        decoded = _decode_wire_record(data, offset, generation, base_offset, active=active)
        if decoded is None:
            break
        record, offset = decoded
        if records and record.sequence <= records[-1].sequence:
            raise FlightTraceError("invalid chunk sequence order")
        records.append(record)
    if not active and offset != len(data):
        raise FlightTraceError("sealed chunk contains an invalid suffix")
    return records


def _nested(payload: bytes, expected_kind: int) -> bytes:
    if len(payload) < QTRB_HEADER.size:
        raise FlightTraceError("truncated nested QTRB record")
    kind, flags, size = QTRB_HEADER.unpack_from(payload)
    if kind != expected_kind or flags != 0 or size != len(payload) - QTRB_HEADER.size:
        raise FlightTraceError("invalid nested QTRB record")
    return payload[QTRB_HEADER.size:]


def _instruction_definition(payload: bytes) -> tuple[int, dict[str, object]]:
    cursor = _Cursor(_nested(payload, 3), "instruction definition")
    (metadata_id, opcode, read_mask, write_mask, displacement, flags, pc_kind,
     condition, memory_count, slow_path) = cursor.unpack(QTRB_INSTRUCTION_DEFINITION)
    if metadata_id == 0 or read_mask >> 34 or write_mask >> 34 or flags & ~0xF:
        raise FlightTraceError("invalid instruction definition")
    if pc_kind not in (0, 1, 2) or memory_count > 4 or slow_path not in (0, 1):
        raise FlightTraceError("invalid instruction definition enum")
    mnemonic = cursor.u16_text(16, "mnemonic")
    operands = cursor.u16_text(96, "operands")
    disassembly = cursor.u16_text(112, "disassembly")
    register_definitions: list[tuple[dict[str, object], ...]] = []
    for mask, label in ((read_mask, "read register"), (write_mask, "write register")):
        definitions = []
        for index in range(34):
            if mask & (1 << index):
                width = cursor.take(1)[0]
                name = cursor.u16_text(16, label)
                definitions.append({"index": index, "width": width, "name": name})
        register_definitions.append(tuple(definitions))
    memory_operands = []
    for _ in range(memory_count):
        (base, index, extend, mode, shift, access, writeback, size,
         memory_displacement) = cursor.unpack(
            QTRB_MEMORY_OPERAND
        )
        if ((base >= 34 and base != 0xFF) or (index >= 34 and index != 0xFF)
                or extend > 4 or mode > 2 or access not in (1, 2, 3)
                or writeback not in (0, 1)):
            raise FlightTraceError("invalid memory operand")
        memory_operands.append({
            "base": base, "index": index, "extend": extend, "mode": mode,
            "shift": shift, "access_kind": access, "writeback": writeback,
            "size": size, "displacement": memory_displacement,
        })
    cursor.finish()
    return metadata_id, {
        "opcode": opcode, "read_mask": read_mask, "write_mask": write_mask,
        "displacement": displacement, "instruction_flags": flags,
        "pc_kind": pc_kind, "condition": condition, "mnemonic": mnemonic,
        "operands": operands, "disassembly": disassembly,
        "slow_memory_path": slow_path,
        "read_registers": register_definitions[0],
        "write_registers": register_definitions[1],
        "memory_operands": tuple(memory_operands),
    }


def _instruction_event(payload: bytes, definitions: dict[int, dict[str, object]],
                       module_base: int, pointer_maximum: int) -> dict[str, object]:
    cursor = _Cursor(_nested(payload, 4), "instruction")
    local_sequence, module_id, relative_pc, metadata_id, reads, writes = cursor.unpack(
        QTRB_INSTRUCTION
    )
    definition = definitions.get(metadata_id)
    if definition is None:
        raise FlightTraceError("undefined instruction metadata")
    if module_id != 1 or reads != int(definition["read_mask"]).bit_count() or \
            writes != int(definition["write_mask"]).bit_count():
        raise FlightTraceError("invalid instruction dictionary reference")
    read_values = tuple(struct.unpack("<Q", cursor.take(8))[0] for _ in range(reads))
    write_values = tuple(struct.unpack("<Q", cursor.take(8))[0] for _ in range(writes))
    cursor.finish()
    pc = _pointer_sum(module_base, relative_pc, pointer_maximum,
                      "instruction address")
    for value in read_values + write_values:
        _require_pointer(value, pointer_maximum, "instruction register")
    result = dict(definition)
    result["read_registers"] = tuple(
        {**item, "value": value}
        for item, value in zip(definition["read_registers"], read_values, strict=True)
    )
    result["write_registers"] = tuple(
        {**item, "value": value}
        for item, value in zip(definition["write_registers"], write_values, strict=True)
    )
    result.update({
        "local_sequence": local_sequence, "metadata_id": metadata_id,
        "module_base": module_base, "relative_pc": relative_pc,
        "pc": pc,
        "reads": read_values, "writes": write_values,
    })
    return result


def _memory_event(payload: bytes, module_base: int,
                  pointer_maximum: int) -> dict[str, object]:
    cursor = _Cursor(_nested(payload, 5), "memory")
    module_id, relative_pc, kind, metadata, flags, address, size, value = cursor.unpack(QTRB_MEMORY)
    if module_id != 1 or kind not in (1, 2, 3) or metadata not in (0, 1):
        raise FlightTraceError("invalid memory event")

    def state(label: str) -> dict[str, object]:
        state_value, count = struct.unpack("<BB", cursor.take(2))
        raw = cursor.take(count)
        if count > 64 or not ((state_value == 0 and count == 0) or state_value == 1 or
                              (state_value == 2 and count == 0)):
            raise FlightTraceError(f"invalid {label} memory state")
        return {"state": state_value, "bytes": raw.hex()}

    before = state("before")
    after = state("after")
    cursor.finish()
    pc = _pointer_sum(module_base, relative_pc, pointer_maximum, "memory PC")
    _require_pointer(address, pointer_maximum, "memory address")
    return {
        "module_base": module_base, "relative_pc": relative_pc,
        "pc": pc,
        "access_kind": kind, "metadata_available": metadata, "flags": flags,
        "address": address, "size": size, "value": value,
        "before": before, "after": after,
    }


def _validate_event_fields(kind: int, fields: tuple[bytes, ...], *,
                           logical_total: int | None = None) -> None:
    if kind == 6:
        if len(fields) != 3 or len(fields[0]) > 255 or len(fields[1]) > 255:
            raise FlightTraceError("event field limit exceeded")
        total_limit = 1 << 20
    else:
        if len(fields) != 2 or len(fields[0]) > 255:
            raise FlightTraceError("event field limit exceeded")
        total_limit = 4096
    detail_limit = 3072
    if len(fields[-1]) > detail_limit or (logical_total is not None and
                                         logical_total > total_limit):
        raise FlightTraceError("event field limit exceeded")


def _decode_chunk(records: list[_WireRecord], tid: int, chunk_index: int,
                  superblock: _Superblock,
                  events: list[FlightEvent], fragments: list[_FragmentValue]
                  ) -> tuple[FlightRegisters, int, int]:
    if len(records) < 2 or records[0].kind != 1 or records[0].flags != 0 or \
            records[1].kind != 9 or records[1].flags != 1:
        raise FlightTraceError("chunk does not begin with metadata and checkpoint")
    cursor = _Cursor(records[0].payload, "chunk begin")
    (profile, pointer_width, target_size, scene_size, reserved, pid, payload_tid,
     module_base, target_offset, target_address) = cursor.unpack(CHUNK_BEGIN_FIXED)
    if profile >= len(PROFILE_NAMES) or pointer_width != superblock.pointer_width or reserved != 0:
        raise FlightTraceError("invalid chunk metadata enum")
    if target_size > 255 or scene_size > 255:
        raise FlightTraceError("oversized chunk context")
    target = _utf8(cursor.take(target_size), "chunk target")
    scene = _utf8(cursor.take(scene_size), "chunk scene")
    cursor.finish()
    if pid != superblock.pid or payload_tid != tid or target != superblock.target:
        raise FlightTraceError("chunk target/PID/TID identity mismatch")
    pointer_maximum = (1 << (8 * superblock.pointer_width)) - 1
    expected_target = _pointer_sum(module_base, target_offset, pointer_maximum,
                                   "chunk target address")
    if _require_pointer(target_address, pointer_maximum,
                        "chunk target address") != expected_target:
        raise FlightTraceError("chunk target address mismatch")
    if len(records[1].payload) != CHECKPOINT.size:
        raise FlightTraceError("invalid register checkpoint size")
    values = list(CHECKPOINT.unpack(records[1].payload))
    for value in values:
        _require_pointer(value, pointer_maximum, "register checkpoint")
    checkpoint_pc = values[32]
    definitions: dict[int, dict[str, object]] = {}
    strings: dict[int, bytes] = {}
    for record in records[2:]:
        if record.kind == 4 and record.flags == 1:
            metadata_id, definition = _instruction_definition(record.payload)
            if metadata_id in definitions:
                raise FlightTraceError("duplicate instruction definition")
            definitions[metadata_id] = definition
            continue
        if record.kind == 6 and record.flags == 3:
            if len(record.payload) < STRING_DEFINITION.size:
                raise FlightTraceError("truncated string definition")
            string_id, size = STRING_DEFINITION.unpack_from(record.payload)
            value = record.payload[STRING_DEFINITION.size:]
            if string_id == 0 or size != len(value) or string_id in strings or size > 4096:
                raise FlightTraceError("invalid string definition")
            strings[string_id] = value
            continue
        if record.kind == 9:
            if record.flags != 0 or len(record.payload) < DELTA_MASK.size:
                raise FlightTraceError("invalid register delta")
            mask = DELTA_MASK.unpack_from(record.payload)[0]
            if mask == 0 or mask >> 34 or len(record.payload) != 8 + mask.bit_count() * 8:
                raise FlightTraceError("invalid register delta")
            cursor = _Cursor(record.payload[8:], "register delta")
            changed: dict[str, int] = {}
            for index in range(34):
                if mask & (1 << index):
                    values[index] = struct.unpack("<Q", cursor.take(8))[0]
                    _require_pointer(values[index], pointer_maximum, "register delta")
                    changed[str(index)] = values[index]
            cursor.finish()
            events.append(FlightEvent(record.sequence, tid, "register_delta", {
                "changed": changed, "pc": values[32], "sp": values[31], "nzcv": values[33],
            }, record.source_offset))
            continue
        if record.kind == 4:
            data = _instruction_event(record.payload, definitions, module_base,
                                      pointer_maximum)
            data.update({"scene": scene, "target_offset": target_offset})
            events.append(FlightEvent(record.sequence, tid, "instruction", data,
                                      record.source_offset))
            continue
        if record.kind == 5:
            events.append(FlightEvent(record.sequence, tid, "memory",
                                      _memory_event(record.payload, module_base,
                                                    pointer_maximum), record.source_offset))
            continue
        if record.kind in (6, 7, 8):
            field_count = 3 if record.kind == 6 else 2
            if record.flags == 4:
                if len(record.payload) != FRAGMENT.size + field_count * 4:
                    raise FlightTraceError("invalid logical fragment length")
                event_id, total, index, count = FRAGMENT.unpack_from(record.payload)
                ids = struct.unpack_from("<" + "I" * field_count, record.payload, FRAGMENT.size)
                if event_id == 0 or count < 2 or index >= count or total == 0:
                    raise FlightTraceError("invalid logical fragment metadata")
                try:
                    raw_fields = tuple(strings[item] for item in ids)
                except KeyError as error:
                    raise FlightTraceError("undefined string dictionary reference") from error
                detail = raw_fields[-1]
                if (not detail or total <= len(detail) or total < count or
                        total < len(detail) + count - 1):
                    raise FlightTraceError("invalid logical fragment metadata")
                _validate_event_fields(record.kind, raw_fields, logical_total=total)
                fixed_raw = raw_fields[:-1]
                fixed = tuple(_utf8(item, "event field") for item in fixed_raw)
                fragments.append(_FragmentValue(
                    record.sequence, tid, chunk_index, record.kind, event_id,
                    total, index, count, fixed, raw_fields[-1], record.source_offset
                ))
                continue
            if record.flags != 0 or len(record.payload) != field_count * 4:
                raise FlightTraceError("invalid string event")
            ids = struct.unpack("<" + "I" * field_count, record.payload)
            try:
                raw_fields = tuple(strings[item] for item in ids)
            except KeyError as error:
                raise FlightTraceError("undefined string dictionary reference") from error
            _validate_event_fields(record.kind, raw_fields)
            fields = tuple(_utf8(item, "event field") for item in raw_fields)
            if record.kind == 6:
                data = {"category": fields[0], "name": fields[1], "detail": fields[2]}
            else:
                data = {"name": fields[0], "detail": fields[1]}
            events.append(FlightEvent(record.sequence, tid, RECORD_NAMES[record.kind], data,
                                      record.source_offset))
            continue
        data = {"payload_hex": record.payload.hex()}
        if ((record.kind == 2 and
             (len(record.payload) != 24 or
              struct.unpack_from("<I", record.payload, 4)[0] != tid)) or
                (record.kind == 3 and
                 (len(record.payload) != 4 or
                  struct.unpack("<I", record.payload)[0] != tid))):
            data["typed_damage"] = True
        events.append(FlightEvent(record.sequence, tid, RECORD_NAMES[record.kind], data,
                                  record.source_offset))
    return FlightRegisters.from_values(values), records[-1].sequence, checkpoint_pc


def _decode_fragments(
        fragments: list[_FragmentValue],
) -> tuple[list[FlightEvent], list[dict[str, object]]]:
    grouped: dict[tuple[int, int], list[_FragmentValue]] = {}
    for fragment in fragments:
        grouped.setdefault((fragment.tid, fragment.event_id), []).append(fragment)
    events = []
    incomplete = []
    for values in grouped.values():
        first = values[0]
        chunk_indexes = {item.chunk_index for item in values}
        if any(item.kind != first.kind for item in values):
            raise _FragmentGroupError("logical fragment kind mismatch", chunk_indexes)
        kind = first.kind
        if any((item.total, item.count, item.fixed) !=
               (first.total, first.count, first.fixed) for item in values):
            raise _FragmentGroupError("logical fragment metadata mismatch", chunk_indexes)
        by_index = {item.index: item for item in values}
        if len(by_index) != len(values):
            raise _FragmentGroupError("duplicate logical fragment index", chunk_indexes)
        if set(by_index) != set(range(first.count)):
            incomplete.append({
                "tid": first.tid,
                "kind": RECORD_NAMES[first.kind],
                "event_id": first.event_id,
                "missing_fragments": sorted(set(range(first.count)) - set(by_index)),
                "retained_fragment_sequences": sorted(item.sequence for item in values),
            })
            continue
        detail_raw = b"".join(by_index[index].detail for index in range(first.count))
        if len(detail_raw) != first.total:
            raise _FragmentGroupError("logical fragment byte count mismatch", chunk_indexes)
        try:
            detail = _utf8(detail_raw, "logical event detail")
        except FlightTraceError as error:
            raise _FragmentGroupError(str(error), chunk_indexes) from error
        if kind == 6:
            data = {"category": first.fixed[0], "name": first.fixed[1], "detail": detail}
        else:
            data = {"name": first.fixed[0], "detail": detail}
        data["fragment_sequences"] = [by_index[index].sequence for index in range(first.count)]
        contributors = sorted(values, key=lambda item: item.source_offset)
        data["fragment_source_offsets"] = [item.source_offset for item in contributors]
        events.append(FlightEvent(max(item.sequence for item in values), first.tid,
                                  RECORD_NAMES[kind], data,
                                  contributors[0].source_offset))
    return events, incomplete


def _parse_emergencies(source: BinaryIO, superblock: _Superblock) -> list[FlightEvent]:
    raw = _read_at(source, superblock.emergency_offset,
                   superblock.emergency_count * superblock.emergency_record_bytes,
                   "emergency slots")
    events = []
    for index in range(superblock.emergency_count):
        slot = raw[index * superblock.emergency_record_bytes:
                   (index + 1) * superblock.emergency_record_bytes]
        if not any(slot):
            continue
        cells = [slot[:EMERGENCY_RECORD_BYTES]]
        if superblock.emergency_record_bytes == EMERGENCY_SLOT_BYTES:
            cells.append(slot[EMERGENCY_RECORD_BYTES:])
        candidates = []
        invalid_committed = []
        for cell_index, cell in enumerate(cells):
            if not any(cell):
                continue
            values = EMERGENCY_RECORD.unpack(cell)
            (cell_kind, cell_tid, cell_sequence, cell_pc, cell_sp, cell_fault,
             cell_signal, cell_code, cell_published_flags, cell_checksum,
             cell_inverse, cell_version) = values
            if not cell_published_flags & EMERGENCY_COMMITTED:
                continue
            if cell_version == 0 or cell_version & 1:
                continue
            cell_flags = cell_published_flags & ~EMERGENCY_COMMITTED
            checksum_code = 0 if cell_kind == 15 else cell_code
            logical = struct.pack(
                "<IIQQQQIII", cell_kind, cell_tid, cell_sequence, cell_pc,
                cell_sp, cell_fault, cell_signal, checksum_code, cell_flags,
            )
            legacy_logical = struct.pack(
                "<IIQQQQIII", cell_kind, cell_tid, cell_sequence, cell_pc,
                cell_sp, cell_fault, cell_signal, cell_code, cell_flags,
            )
            if (cell_inverse != (~cell_checksum & 0xFFFFFFFF) or
                    cell_checksum not in {_fnv32(logical), _fnv32(legacy_logical)}):
                invalid_committed.append(cell_version)
                continue
            cell_offset = (superblock.emergency_offset +
                           index * superblock.emergency_record_bytes +
                           cell_index * EMERGENCY_RECORD_BYTES)
            candidates.append((cell_version, values, cell_offset))
        if not candidates:
            if invalid_committed:
                raise FlightTraceError(
                    f"invalid committed emergency publication at slot {index}")
            continue
        newest = max(candidates, key=lambda item: item[0])
        selected = [newest]
        if len(candidates) == 2:
            older, newer = sorted(candidates, key=lambda item: item[0])
            older_sequence = int(older[1][2])
            newer_sequence = int(newer[1][2])
            # A v2 slot is a two-generation bounded history. A completed
            # publication advances the even generation exactly once and the
            # global sequence allocator is monotonic. Anything else is a stale
            # cell left outside the current old-or-new publication pair.
            older_kind, older_tid = int(older[1][0]), int(older[1][1])
            newer_kind, newer_tid = int(newer[1][0]), int(newer[1][1])
            termination_signal = _termination_intended_signal(older[1])
            pinned_pair = (
                older_kind == 14 and newer_kind in (11, 12, 13) and
                older_tid == newer_tid and
                termination_signal == int(newer[1][6]) and
                int(newer[1][8]) & 0xFFFF == 1
            )
            if (newer_sequence > older_sequence and
                    (newer[0] == older[0] + 2 or pinned_pair)):
                selected = [older, newer]
        pointer_maximum = (1 << (8 * superblock.pointer_width)) - 1
        for _, values, source_offset in selected:
            (kind, tid, sequence, pc, sp, fault, signal, code, published_flags,
             checksum, inverse, version) = values
            flags = published_flags & ~EMERGENCY_COMMITTED
            if kind not in RECORD_NAMES or tid == 0 or sequence == 0:
                raise FlightTraceError(f"invalid committed emergency slot {index}")
            if kind == 15 and flags & ~KNOWN_INCOMPLETE_FLAGS:
                raise FlightTraceError("unknown coverage gap reason")
            for value, field in ((pc, "emergency PC"), (sp, "emergency SP"),
                                 (fault, "emergency fault address")):
                _require_pointer(value, pointer_maximum, field)
            data: dict[str, object] = {
                "pc": pc, "sp": sp, "fault_address": fault,
                "signal_number": signal, "signal_code": code, "flags": flags,
            }
            if kind == 15:
                data["reason_flags"] = flags
                data["dropped_gap_count"] = code
            events.append(FlightEvent(sequence, tid, RECORD_NAMES[kind], data,
                                      source_offset))
    return events


def _termination_intended_signal(values: tuple[int, ...]) -> int | None:
    syscall_number = int(values[6])
    if syscall_number in (129, 130, 138):
        return int(values[5])
    if syscall_number == 131:
        return int(values[7])
    return None


def _ranges(values: set[int]) -> list[list[int]]:
    if not values:
        return []
    result = []
    start = previous = min(values)
    for value in sorted(values)[1:]:
        if value != previous + 1:
            result.append([start, previous])
            start = value
        previous = value
    result.append([start, previous])
    return result


def _missing_ranges(start: int, end: int, observed: set[int]) -> list[list[int]]:
    if start == 0 or end < start:
        return []
    result = []
    cursor = start
    for sequence in sorted(value for value in observed if start <= value <= end):
        if sequence > cursor:
            result.append([cursor, sequence - 1])
        cursor = sequence + 1
    if cursor <= end:
        result.append([cursor, end])
    return result


def recover_flight(source: BinaryIO) -> FlightRecovery:
    """Recover committed records without accepting damage past protocol boundaries."""
    source_size = _source_size(source)
    if source_size < SUPERBLOCK_BYTES:
        raise FlightTraceError("truncated flight superblock")
    superblock = _parse_superblock(source, source_size)
    directories = _parse_directories(source, superblock)
    directory_by_tid = {entry.tid: entry for entry in directories}
    damage: list[str] = []
    damage_details: list[dict[str, object]] = []
    stale_entries: list[int] = []
    events: list[FlightEvent] = []
    observed: set[int] = set()
    observed_by_tid: dict[int, set[int]] = {}
    thread_state: dict[int, tuple[int, FlightRegisters]] = {}
    checkpoint_pcs: set[int] = set()
    chunk_headers: dict[int, tuple[int, int, int]] = {}
    sealed_ranges: list[tuple[int, int, int]] = []
    decoded_chunks: list[_DecodedChunk] = []
    active_chunk_indexes: list[int] = []

    for index in range(superblock.chunk_count):
        offset = superblock.chunk_offset + index * superblock.chunk_bytes
        header = _read_at(source, offset, CHUNK_HEADER_BYTES, f"chunk {index} header")
        state = struct.unpack_from("<I", header, 12)[0]
        if state == 0:
            continue
        if state not in (1, 2):
            raise FlightTraceError(f"invalid chunk state at index {index}")
        (magic, version, header_bytes, encoded_index, _, tid, generation, first, last,
         committed, count, checksum) = CHUNK_HEADER.unpack(header)
        if (magic != MAGIC or version != superblock.version or
                header_bytes != CHUNK_HEADER_BYTES or encoded_index != index):
            raise FlightTraceError(f"invalid chunk header identity at index {index}")
        if tid == 0 or generation == 0 or tid not in directory_by_tid or any(header[52:]):
            raise FlightTraceError(f"invalid chunk ownership at index {index}")
        capacity = superblock.chunk_bytes - CHUNK_HEADER_BYTES
        chunk_headers[index] = (tid, generation, state)
        if state == 1:
            active_chunk_indexes.append(index)
        if state == 2:
            if (first == 0) != (last == 0) or (first != 0 and first > last):
                raise FlightTraceError(f"invalid chunk sequence range at index {index}")
            if first != 0:
                sealed_ranges.append((first, last, offset))
            if committed > capacity or committed & 7:
                raise FlightTraceError(f"invalid sealed chunk extent at index {index}")
            data = _read_at(source, offset + CHUNK_HEADER_BYTES, committed,
                            f"sealed chunk {index} data")
            if _fnv32(data) != checksum:
                damage.append(f"sealed chunk {index} checksum mismatch")
                damage_details.append({
                    "class": "checksum", "source_offset": offset,
                    "first_sequence": first, "last_sequence": last,
                })
                continue
            try:
                records = _scan_chunk_data(data, generation,
                                           offset + CHUNK_HEADER_BYTES,
                                           active=False)
                if len(records) != count:
                    raise FlightTraceError("sealed chunk record count mismatch")
                if records:
                    if records[0].sequence != first or records[-1].sequence != last:
                        raise FlightTraceError("sealed chunk sequence endpoint mismatch")
                elif first != 0 or last != 0:
                    raise FlightTraceError("empty sealed chunk has sequence endpoints")
            except FlightTraceError as error:
                damage.append(f"sealed chunk {index}: {error}")
                damage_details.append({
                    "class": ("checksum" if "checksum" in str(error) else "incomplete"),
                    "source_offset": offset,
                    "first_sequence": first, "last_sequence": last,
                })
                continue
        else:
            data = _read_at(source, offset + CHUNK_HEADER_BYTES, capacity,
                            f"active chunk {index} data")
            records = _scan_chunk_data(data, generation,
                                       offset + CHUNK_HEADER_BYTES,
                                       active=True)
        if not records:
            if state == 2:
                damage.append(f"empty sealed chunk {index}")
                damage_details.append({
                    "class": "incomplete", "source_offset": offset,
                    "first_sequence": first, "last_sequence": last,
                })
            continue
        chunk_events: list[FlightEvent] = []
        chunk_fragments: list[_FragmentValue] = []
        try:
            registers, last_state_sequence, checkpoint_pc = _decode_chunk(
                records, tid, index, superblock, chunk_events, chunk_fragments
            )
        except FlightTraceError as error:
            if state != 2:
                raise
            damage.append(f"sealed chunk {index}: {error}")
            continue
        decoded_chunks.append(_DecodedChunk(
            index, tid, state, tuple(records), tuple(chunk_events),
            tuple(chunk_fragments), registers, last_state_sequence, checkpoint_pc,
        ))

    for entry in directories:
        if entry.state == 2 or entry.chunk_index == INVALID_INDEX:
            continue
        identity = chunk_headers.get(entry.chunk_index)
        if identity != (entry.tid, entry.generation, 1) and identity != (entry.tid, entry.generation, 2):
            stale_entries.append(entry.index)

    while True:
        fragments = [
            fragment
            for decoded in decoded_chunks
            for fragment in decoded.fragments
        ]
        try:
            fragment_events, incomplete_logical_events = _decode_fragments(fragments)
            break
        except _FragmentGroupError as error:
            contributors = [
                decoded for decoded in decoded_chunks
                if decoded.index in error.chunk_indexes
            ]
            if not contributors or any(decoded.state != 2 for decoded in contributors):
                raise
            sealed = {decoded.index for decoded in contributors}
            for index in sorted(sealed):
                damage.append(f"sealed chunk {index}: {error}")
                contributor = next(item for item in contributors if item.index == index)
                damage_details.append({
                    "class": "incomplete_logical",
                    "source_offset": (superblock.chunk_offset +
                                      index * superblock.chunk_bytes),
                    "first_sequence": contributor.records[0].sequence,
                    "last_sequence": contributor.records[-1].sequence,
                })
            decoded_chunks = [
                decoded for decoded in decoded_chunks if decoded.index not in sealed
            ]

    for decoded in decoded_chunks:
        for record in decoded.records:
            if record.sequence in observed:
                raise FlightTraceError(f"duplicate global sequence {record.sequence}")
        events.extend(decoded.events)
        for record in decoded.records:
            observed.add(record.sequence)
            observed_by_tid.setdefault(decoded.tid, set()).add(record.sequence)
        checkpoint_pcs.add(decoded.checkpoint_pc)
        if decoded.last_state_sequence > thread_state.get(
                decoded.tid, (0, decoded.registers))[0]:
            thread_state[decoded.tid] = (
                decoded.last_state_sequence, decoded.registers
            )
    events.extend(fragment_events)
    emergency_events = _parse_emergencies(source, superblock)
    for event in emergency_events:
        if event.global_seq in observed:
            raise FlightTraceError(f"duplicate global sequence {event.global_seq}")
        observed.add(event.global_seq)
        observed_by_tid.setdefault(event.tid, set()).add(event.global_seq)
    events.extend(emergency_events)
    events.sort(key=lambda item: item.global_seq)

    thread_events: dict[int, list[FlightEvent]] = {}
    for event in events:
        thread_events.setdefault(event.tid, []).append(event)
    threads = {
        tid: FlightThread(tid, tuple(thread_events.get(tid, ())),
                          (thread_state[tid][1] if tid in thread_state else None))
        for tid in sorted(set(thread_events) | set(thread_state))
    }

    range_starts = [entry.first for entry in directories if entry.first]
    range_ends = [entry.last for entry in directories if entry.last]
    range_starts.extend(first for first, _, _ in sealed_ranges)
    range_ends.extend(last for _, last, _ in sealed_ranges)
    if observed:
        range_starts.append(min(observed))
        range_ends.append(max(observed))
    missing = _missing_ranges(min(range_starts) if range_starts else 0,
                              max(range_ends) if range_ends else 0, observed)
    coverage = [event for event in events if event.kind == "coverage_gap"]
    signal_handler_intervals = []
    returned_begins = {
        (event.tid, int(event.data["fault_address"]))
        for event in events if event.kind == "signal_handler_return"
    }
    for event in events:
        if event.kind not in {"signal_handler_begin", "signal_handler_return"}:
            continue
        if (event.kind == "signal_handler_begin" and
                (event.tid, event.global_seq) in returned_begins):
            continue
        encoded_flags = int(event.data["flags"])
        depth = encoded_flags & 0xFFFF
        nested_delivery_count = encoded_flags >> 16
        returned = event.kind == "signal_handler_return"
        signal_handler_intervals.append({
            "tid": event.tid,
            "depth": depth,
            "nested_delivery_count": nested_delivery_count,
            "begin_sequence": (int(event.data["fault_address"])
                               if returned else event.global_seq),
            "return_sequence": event.global_seq if returned else None,
            "returned": returned,
            "unreturned_ancestor_count": max(depth - 1, 0),
        })
    active_chunks = sorted(active_chunk_indexes)
    lifecycle_balance: dict[int, int] = {}
    for event in events:
        if event.kind == "thread_begin":
            lifecycle_balance[event.tid] = lifecycle_balance.get(event.tid, 0) + 1
        elif event.kind == "thread_end":
            lifecycle_balance[event.tid] = lifecycle_balance.get(event.tid, 0) - 1
    unterminated_threads = sorted(
        tid for tid, balance in lifecycle_balance.items() if balance > 0
    )
    terminations = [event for event in events if event.kind == "termination_intent"]
    if terminations:
        terminal = terminations[-1]
        termination: dict[str, object] = {
            "cause": "termination_intent", "initiator_tid": terminal.tid,
            "sequence": terminal.global_seq, **terminal.data,
        }
    else:
        termination = {"cause": "unknown", "initiator_tid": None}
    target_pcs = sorted(checkpoint_pcs | {
        int(event.data["pc"]) for event in events
        if int(event.data.get("pc", 0)) != 0
    })
    last_recorded_thread = max(
        ((sequence, tid) for tid, sequences in observed_by_tid.items()
         for sequence in sequences),
        default=(0, None),
    )[1]
    summary: dict[str, object] = {
        "format_version": superblock.version,
        "run_id": superblock.run_id,
        "pid": superblock.pid,
        "module_generation": superblock.module_generation,
        "target_module": superblock.target,
        "pointer_width": superblock.pointer_width,
        "artifact_flags": superblock.flags,
        "artifact_bytes": superblock.artifact_bytes,
        "directory_offset": superblock.directory_offset,
        "chunk_offset": superblock.chunk_offset,
        "chunk_bytes": superblock.chunk_bytes,
        "complete": (superblock.flags == 0 and not damage and not coverage and
                     not incomplete_logical_events and not stale_entries),
        "provider_complete": (superblock.flags == 0 and not damage and not coverage and
                              not incomplete_logical_events and not stale_entries and
                              not any(event.data.get("typed_damage") for event in events)),
        "termination": termination,
        "final_signal": next((event.data for event in reversed(events)
                              if event.kind == "signal"), None),
        "last_recorded_thread": last_recorded_thread,
        "target_pcs": target_pcs,
        "retained_sequences": _ranges(observed),
        "lost_sequences": missing,
        "overwritten_sequences": missing if not damage and not coverage else [],
        "provider_ranges": {
            "lost": (missing if (not damage and (superblock.flags != 0 or coverage or
                                                 incomplete_logical_events or stale_entries or
                                                 unterminated_threads))
                     else []),
            "overwritten": (missing if not damage and not coverage and
                             not incomplete_logical_events and not stale_entries and
                             not unterminated_threads and superblock.flags == 0 else []),
            "checksum": missing if damage else [],
        },
        "coverage_gaps": [
            {"sequence": event.global_seq, "tid": event.tid, **event.data}
            for event in coverage
        ],
        "signal_handler_intervals": signal_handler_intervals,
        "active_chunks": active_chunks,
        "unterminated_threads": unterminated_threads,
        "incomplete_logical_events": incomplete_logical_events,
        "recovery_damage": damage,
        "damage_details": damage_details + [
            {
                "class": "incomplete_logical",
                "source_offset": source_offset,
                "first_sequence": sequence,
                "last_sequence": sequence,
            }
            for item in incomplete_logical_events
            for sequence in item["retained_fragment_sequences"]
            for source_offset in [next(
                fragment.source_offset
                for decoded in decoded_chunks for fragment in decoded.fragments
                if fragment.sequence == sequence
            )]
        ] + [
            {
                "class": "incomplete", "source_offset": event.source_offset,
                "first_sequence": event.global_seq, "last_sequence": event.global_seq,
            }
            for event in events if event.data.get("typed_damage")
        ],
        "range_facts": [
            {
                "kind": "directory", "source_offset":
                superblock.directory_offset + entry.index * DIRECTORY_ENTRY_BYTES,
                "first_sequence": entry.first, "last_sequence": entry.last,
            }
            for entry in directories if entry.range_reliable and entry.first
        ] + [
            {
                "kind": "chunk", "source_offset": offset,
                "first_sequence": first, "last_sequence": last,
            }
            for first, last, offset in sealed_ranges
        ],
        "physical_records": [
            {
                "global_seq": record.sequence,
                "tid": decoded.tid,
                "kind": record.kind,
                "flags": record.flags,
                "payload_hex": record.payload.hex(),
                "source_offset": record.source_offset,
                "chunk_index": decoded.index,
                "generation": chunk_headers[decoded.index][1],
                "chunk_state": decoded.state,
            }
            for decoded in decoded_chunks
            for record in decoded.records
        ],
        "stale_directory_entries": stale_entries,
        "rotating_directory_entries": [entry.index for entry in directories
                                         if entry.state == 2],
        "unreliable_directory_ranges": [entry.index for entry in directories
                                         if not entry.range_reliable],
        "threads": {
            str(tid): {
                "events": len(thread.events),
                "last_pc": (thread.registers.pc if thread.registers is not None else None),
                "registers_known": thread.registers is not None,
                "retained_sequences": _ranges(observed_by_tid.get(tid, set())),
            }
            for tid, thread in threads.items()
        },
        "projection_tids": sorted({entry.tid for entry in directories} | set(threads)),
    }
    return FlightRecovery(tuple(events), threads, summary)
