"""Strict bounded-memory decoder and format-3 renderer for QTRB v1 traces."""

from __future__ import annotations

import dataclasses
import json
import struct
from typing import BinaryIO, TextIO


STREAM_HEADER = struct.Struct("<4sBBBBBBHI")
RECORD_HEADER = struct.Struct("<HHI")
TRACE_BEGIN_FIXED = struct.Struct("<QQQIIBBQQ")
MODULE_FIXED = struct.Struct("<IQ")
INSTRUCTION_DEFINITION_FIXED = struct.Struct("<IIQQqIBBBB")
MEMORY_OPERAND = struct.Struct("<BBBBBBB I q")
INSTRUCTION_FIXED = struct.Struct("<QIQIBB")
MEMORY_FIXED = struct.Struct("<IQBBHQIQ")
CALL_CHUNK_FIXED = struct.Struct("<QIHH")
TRACE_END_FIXED = struct.Struct("<BQQ" + "Q" * 10)

MAX_RECORD_PAYLOAD = 4612
MAX_CONTEXT_STRING = 255
MAX_MODULE_NAME = 255
MAX_CALL_CATEGORY = 255
MAX_CALL_NAME = 255
MAX_EVENT_NAME = 255
MAX_EVENT_DETAIL = 4096
MAX_CALL_CHUNK_DETAIL = 3072
MAX_LOGICAL_CALL_DETAIL = 1 << 20
MAX_MNEMONIC = 16
MAX_OPERANDS = 96
MAX_DISASSEMBLY = 112
MAX_REGISTER_NAME = 16
MAX_MEMORY_OPERANDS = 4
MAX_CAPTURED_MEMORY = 64
MAX_DICTIONARY_ENTRIES = 1 << 16
MAX_COMPATIBLE_MINOR = 1
OPTIONAL_RECORD_TYPE_MIN = 0x8000
VALID_INSTRUCTION_FLAGS = 0xF
PROFILE_NAMES = ("fast", "balanced", "full")
ACCESS_NAMES = {1: "read", 2: "write", 3: "readwrite"}
EXTEND_NAMES = ("none", "uxtw", "sxtw", "lsl", "sxtx")
ADDRESS_MODE_NAMES = ("offset", "preindex", "postindex")


class BinaryTraceError(RuntimeError):
    """The binary trace violates the supported QTRB protocol."""


@dataclasses.dataclass(frozen=True)
class ConversionStats:
    instructions: int
    converted_text_bytes: int
    partial: bool


@dataclasses.dataclass(frozen=True, slots=True)
class _RegisterDefinition:
    index: int
    width: int
    name: str


@dataclasses.dataclass(frozen=True, slots=True)
class _MemoryOperand:
    base: int
    index: int
    extend: int
    mode: int
    shift: int
    kind: int
    writeback: int
    size: int
    displacement: int


@dataclasses.dataclass(frozen=True, slots=True)
class _InstructionDefinition:
    opcode: int
    read_mask: int
    write_mask: int
    displacement: int
    flags: int
    pc_kind: int
    condition: int
    slow_memory_path: int
    mnemonic: str
    operands: str
    disassembly: str
    reads: tuple[_RegisterDefinition, ...]
    writes: tuple[_RegisterDefinition, ...]
    memory_operands: tuple[_MemoryOperand, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class _ModuleDefinition:
    base: int
    name: str


@dataclasses.dataclass(frozen=True, slots=True)
class _Footer:
    success: int
    return_value: int
    elapsed_ms: int
    instructions: int
    encoded_bytes: int
    compressed_bytes: int
    cache_hits: int
    cache_misses: int
    cache_collisions: int
    buffer_swaps: int
    producer_waits: int
    producer_wait_ns: int
    effective_buffer_bytes: int


@dataclasses.dataclass(frozen=True, slots=True)
class _ConversionDetails:
    stats: ConversionStats
    profile: str
    compression_enabled: bool
    footer: _Footer | None


@dataclasses.dataclass(slots=True)
class _PendingCall:
    event_id: int
    total: int
    count: int
    category: str
    name: str
    next_index: int
    detail: bytearray


@dataclasses.dataclass(slots=True)
class _PendingEvent:
    record_type: int
    event_id: int
    total: int
    count: int
    name: str
    next_index: int
    detail: bytearray


class _Payload:
    def __init__(self, data: bytes, label: str) -> None:
        self.data = data
        self.offset = 0
        self.label = label

    def take(self, size: int) -> bytes:
        if size < 0 or size > len(self.data) - self.offset:
            raise BinaryTraceError(f"invalid {self.label} payload length")
        result = self.data[self.offset:self.offset + size]
        self.offset += size
        return result

    def unpack(self, layout: struct.Struct) -> tuple[int, ...]:
        return layout.unpack(self.take(layout.size))

    def string_bytes(self, maximum: int, field: str) -> bytes:
        size = struct.unpack("<H", self.take(2))[0]
        if size > maximum:
            raise BinaryTraceError(f"oversized {field}")
        return self.take(size)

    def string(self, maximum: int, field: str) -> str:
        raw = self.string_bytes(maximum, field)
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise BinaryTraceError(f"{field} is not valid UTF-8") from error

    def finish(self) -> None:
        if self.offset != len(self.data):
            raise BinaryTraceError(f"invalid {self.label} payload length")


class _CountingReader:
    def __init__(self, source: BinaryIO) -> None:
        self.source = source
        self.total = 0

    def read(self, size: int) -> bytes:
        data = self.source.read(size)
        if not isinstance(data, bytes):
            raise BinaryTraceError("binary source returned non-bytes data")
        self.total += len(data)
        return data


def _read_exact(reader: _CountingReader, size: int, label: str) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        piece = reader.read(size - len(chunks))
        if not piece:
            raise BinaryTraceError(f"truncated {label}")
        chunks.extend(piece)
    return bytes(chunks)


def _read_optional_exact(reader: _CountingReader, size: int, label: str) -> bytes | None:
    first = reader.read(size)
    if not first:
        return None
    chunks = bytearray(first)
    while len(chunks) < size:
        piece = reader.read(size - len(chunks))
        if not piece:
            raise BinaryTraceError(f"truncated {label}")
        chunks.extend(piece)
    return bytes(chunks)


def _quoted(value: str) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _register_name(index: int) -> str:
    if 0 <= index <= 30:
        return f"X{index}"
    return {31: "SP", 32: "NZCV", 33: "PC"}.get(index, f"R{index}")


def _mask_indexes(mask: int) -> tuple[int, ...]:
    if mask >> 34:
        raise BinaryTraceError("register mask contains an unknown register")
    return tuple(index for index in range(34) if mask & (1 << index))


def _format_asm(definition: _InstructionDefinition, pc: int) -> str:
    if definition.mnemonic:
        if definition.pc_kind:
            base = pc & ~0xFFF if definition.pc_kind == 2 else pc
            target = (base + definition.displacement) & 0xFFFFFFFFFFFFFFFF
            prefix = ""
            if "," in definition.operands:
                prefix = definition.operands.rsplit(",", 1)[0] + ", "
            return f"{definition.mnemonic} {prefix}{_hex(target)}"
        return definition.mnemonic + (f" {definition.operands}" if definition.operands else "")
    return definition.disassembly or "<undecoded>"


def _format_registers(definitions: tuple[_RegisterDefinition, ...],
                      values: tuple[int, ...]) -> str:
    return "[" + ",".join(
        f"{item.name}:{item.width}={_hex(value)}"
        for item, value in zip(definitions, values, strict=True)
    ) + "]"


def _format_memory_operands(operands: tuple[_MemoryOperand, ...]) -> str:
    values = []
    for operand in operands:
        base = "none" if operand.base == 0xFF else _register_name(operand.base)
        index = "none" if operand.index == 0xFF else _register_name(operand.index)
        values.append(
            f"base={base},index={index},extend={EXTEND_NAMES[operand.extend]},"
            f"mode={ADDRESS_MODE_NAMES[operand.mode]},shift={operand.shift},"
            f"kind={ACCESS_NAMES[operand.kind]},writeback={operand.writeback},"
            f"size={operand.size},disp={operand.displacement}"
        )
    return "[" + ";".join(values) + "]"


def _decode_instruction_definition(payload: bytes) -> tuple[int, _InstructionDefinition]:
    cursor = _Payload(payload, "INSTRUCTION_DEF")
    (metadata_id, opcode, read_mask, write_mask, displacement, flags, pc_kind,
     condition, memory_count, slow_path) = cursor.unpack(INSTRUCTION_DEFINITION_FIXED)
    if flags & ~VALID_INSTRUCTION_FLAGS:
        raise BinaryTraceError("unknown instruction flags")
    if pc_kind not in (0, 1, 2):
        raise BinaryTraceError("invalid PC-relative kind")
    if slow_path not in (0, 1) or memory_count > MAX_MEMORY_OPERANDS:
        raise BinaryTraceError("invalid instruction definition")
    read_indexes = _mask_indexes(read_mask)
    write_indexes = _mask_indexes(write_mask)
    mnemonic = cursor.string(MAX_MNEMONIC, "mnemonic")
    operands = cursor.string(MAX_OPERANDS, "operands")
    disassembly = cursor.string(MAX_DISASSEMBLY, "disassembly")

    def registers(indexes: tuple[int, ...], field: str) -> tuple[_RegisterDefinition, ...]:
        result = []
        for index in indexes:
            width = cursor.take(1)[0]
            name = cursor.string(MAX_REGISTER_NAME, field)
            if width == 0 or width > 16 or not name:
                raise BinaryTraceError(f"invalid {field} definition")
            result.append(_RegisterDefinition(index, width, name))
        return tuple(result)

    reads = registers(read_indexes, "read register")
    writes = registers(write_indexes, "write register")
    memory = []
    for _ in range(memory_count):
        base, index, extend, mode, shift, kind, writeback, size, disp = cursor.unpack(
            MEMORY_OPERAND
        )
        if ((base >= 34 and base != 0xFF) or (index >= 34 and index != 0xFF)
                or extend >= len(EXTEND_NAMES) or mode >= len(ADDRESS_MODE_NAMES)
                or kind not in ACCESS_NAMES or writeback not in (0, 1)):
            raise BinaryTraceError("invalid memory operand")
        memory.append(_MemoryOperand(base, index, extend, mode, shift, kind,
                                     writeback, size, disp))
    cursor.finish()
    return metadata_id, _InstructionDefinition(
        opcode, read_mask, write_mask, displacement, flags, pc_kind, condition,
        slow_path, mnemonic, operands, disassembly, reads, writes, tuple(memory)
    )


def _convert_binary_stream(source: BinaryIO, output: TextIO, *,
                           allow_partial: bool) -> _ConversionDetails:
    reader = _CountingReader(source)
    header = _read_exact(reader, STREAM_HEADER.size, "stream header")
    magic, major, minor, endian, pointer_width, profile_value, reserved, size, features = (
        STREAM_HEADER.unpack(header)
    )
    if magic != b"QTRB":
        raise BinaryTraceError("invalid QTRB magic")
    if major != 1:
        raise BinaryTraceError("unsupported major version")
    if minor > MAX_COMPATIBLE_MINOR:
        raise BinaryTraceError("unsupported minor version")
    if endian != 1:
        raise BinaryTraceError("invalid endian marker")
    if pointer_width not in (4, 8):
        raise BinaryTraceError("invalid pointer width")
    if profile_value >= len(PROFILE_NAMES):
        raise BinaryTraceError("invalid trace profile")
    if reserved != 0:
        raise BinaryTraceError("nonzero reserved stream header byte")
    if size != STREAM_HEADER.size:
        raise BinaryTraceError("invalid stream header size")
    if features != 0:
        raise BinaryTraceError("unknown required features")

    modules: dict[int, _ModuleDefinition] = {}
    definitions: dict[int, _InstructionDefinition] = {}
    began = False
    ended = False
    sequence = 0
    instruction_count = 0
    text_bytes = 0
    begin_effective_buffer = 0
    begin_compression: bool | None = None
    footer: _Footer | None = None
    pending_call: _PendingCall | None = None
    pending_event: _PendingEvent | None = None

    def emit(line: str) -> None:
        nonlocal text_bytes
        rendered = line + "\n"
        output.write(rendered)
        text_bytes += len(rendered.encode("utf-8"))

    while True:
        record_header = _read_optional_exact(reader, RECORD_HEADER.size, "record header")
        if record_header is None:
            break
        record_type, flags, payload_size = RECORD_HEADER.unpack(record_header)
        if payload_size > MAX_RECORD_PAYLOAD:
            raise BinaryTraceError("record payload exceeds protocol maximum")
        payload = _read_exact(reader, payload_size, "record payload")
        if ended:
            raise BinaryTraceError("record after TRACE_END")
        is_chunk = record_type == 6 and flags == 1
        is_event_chunk = record_type in (7, 8) and flags == 1
        if pending_call is not None and not is_chunk:
            raise BinaryTraceError("CALL chunks must be contiguous")
        if pending_event is not None and not is_event_chunk:
            raise BinaryTraceError("semantic event chunks must be contiguous")
        if record_type not in (6, 7, 8) and flags != 0:
            raise BinaryTraceError("unknown flags")
        if record_type == 6 and flags not in (0, 1):
            raise BinaryTraceError("unknown flags")
        if record_type in (7, 8) and flags not in (0, 1):
            raise BinaryTraceError("unknown flags")
        if not began and record_type != 1:
            raise BinaryTraceError("TRACE_BEGIN must be first record")

        if record_type >= OPTIONAL_RECORD_TYPE_MIN:
            if minor == 0:
                raise BinaryTraceError(f"unknown record type {record_type}")
            if flags != 0:
                raise BinaryTraceError("unknown flags")
            continue
        if record_type not in range(1, 10):
            raise BinaryTraceError(f"unknown record type {record_type} (required record)")

        if record_type == 1:
            if flags or began:
                raise BinaryTraceError("invalid TRACE_BEGIN order")
            cursor = _Payload(payload, "TRACE_BEGIN")
            (module_base, target_offset, target_address, pid, tid, begin_profile,
             compression, effective_buffer, run_id) = cursor.unpack(TRACE_BEGIN_FIXED)
            scene = cursor.string(MAX_CONTEXT_STRING, "scene")
            target = cursor.string(MAX_CONTEXT_STRING, "target")
            cursor.finish()
            if begin_profile != profile_value:
                raise BinaryTraceError("TRACE_BEGIN profile does not match stream header")
            if compression not in (0, 1):
                raise BinaryTraceError("invalid TRACE_BEGIN compression state")
            began = True
            begin_effective_buffer = effective_buffer
            begin_compression = bool(compression)
            emit(
                f"TRACE_BEGIN format=3 scene={_quoted(scene)} target={_quoted(target)} "
                f"target_offset={_hex(target_offset)} base={_hex(module_base)} "
                f"address={_hex(target_address)} pid={pid} tid={tid} "
                f"profile={PROFILE_NAMES[profile_value]} compression={compression} "
                f"effective_buffer_bytes={effective_buffer} run_id={run_id}"
            )
        elif record_type == 2:
            cursor = _Payload(payload, "MODULE_DEF")
            module_id, base = cursor.unpack(MODULE_FIXED)
            name = cursor.string(MAX_MODULE_NAME, "module name")
            cursor.finish()
            definition = _ModuleDefinition(base, name)
            old = modules.get(module_id)
            if old is not None and old != definition:
                raise BinaryTraceError("conflicting module definition")
            if old is None and len(modules) >= MAX_DICTIONARY_ENTRIES:
                raise BinaryTraceError("module dictionary limit exceeded")
            modules[module_id] = definition
        elif record_type == 3:
            metadata_id, definition = _decode_instruction_definition(payload)
            old = definitions.get(metadata_id)
            if old is not None and old != definition:
                raise BinaryTraceError("conflicting instruction definition")
            if old is None and len(definitions) >= MAX_DICTIONARY_ENTRIES:
                raise BinaryTraceError("instruction dictionary limit exceeded")
            definitions[metadata_id] = definition
        elif record_type == 4:
            cursor = _Payload(payload, "INSTRUCTION")
            seq, module_id, relative_pc, metadata_id, read_count, write_count = cursor.unpack(
                INSTRUCTION_FIXED
            )
            module_definition = modules.get(module_id)
            if module_definition is None:
                raise BinaryTraceError("undefined module reference")
            definition = definitions.get(metadata_id)
            if definition is None:
                raise BinaryTraceError("undefined instruction metadata")
            if seq != sequence + 1:
                raise BinaryTraceError("instruction sequence gap")
            if read_count != len(definition.reads) or write_count != len(definition.writes):
                raise BinaryTraceError("instruction register count does not match definition")
            reads = tuple(struct.unpack("<Q", cursor.take(8))[0] for _ in range(read_count))
            writes = tuple(struct.unpack("<Q", cursor.take(8))[0] for _ in range(write_count))
            cursor.finish()
            sequence = seq
            instruction_count += 1
            pc = (module_definition.base + relative_pc) & 0xFFFFFFFFFFFFFFFF
            emit(
                f"INST seq={seq} module={_quoted(module_definition.name)} "
                f"module_base={_hex(module_definition.base)} pc={_hex(pc)} "
                f"relative_pc={_hex(relative_pc)} metadata_id={metadata_id} "
                f"opcode={_hex(definition.opcode)} asm={_quoted(_format_asm(definition, pc))} "
                f"flags={_hex(definition.flags)} condition={definition.condition} "
                f"reads={_format_registers(definition.reads, reads)} "
                f"writes={_format_registers(definition.writes, writes)} "
                f"slow_memory_path={definition.slow_memory_path} "
                f"memory_operands={_format_memory_operands(definition.memory_operands)}"
            )
        elif record_type == 5:
            cursor = _Payload(payload, "MEMORY")
            memory_fields = cursor.unpack(MEMORY_FIXED)
            (module_id, relative_pc, kind, metadata_available, memory_flags, address,
             access_size, value) = memory_fields
            module_definition = modules.get(module_id)
            if module_definition is None:
                raise BinaryTraceError("undefined module reference")
            if kind not in ACCESS_NAMES or metadata_available not in (0, 1):
                raise BinaryTraceError("invalid MEMORY metadata")

            def memory_bytes(field: str) -> str:
                state, count = struct.unpack("<BB", cursor.take(2))
                if count > MAX_CAPTURED_MEMORY:
                    raise BinaryTraceError(f"oversized {field} memory state")
                raw = cursor.take(count)
                if state == 0 and count == 0:
                    return "<not-captured>"
                if state == 1:
                    return raw.hex()
                if state == 2 and count == 0:
                    return "<unavailable>"
                raise BinaryTraceError(f"invalid {field} memory state")

            before = memory_bytes("before")
            after = memory_bytes("after")
            cursor.finish()
            pc = (module_definition.base + relative_pc) & 0xFFFFFFFFFFFFFFFF
            emit(
                f"MEMORY module={_quoted(module_definition.name)} "
                f"module_base={_hex(module_definition.base)} pc={_hex(pc)} "
                f"relative_pc={_hex(relative_pc)} kind={ACCESS_NAMES[kind]} "
                f"metadata_available={metadata_available} flags={_hex(memory_flags)} "
                f"address={_hex(address)} size={access_size} value={_hex(value)} "
                f"before={before} after={after}"
            )
        elif record_type == 6:
            cursor = _Payload(payload, "CALL")
            if flags == 0:
                category = cursor.string(MAX_CALL_CATEGORY, "CALL category")
                name = cursor.string(MAX_CALL_NAME, "CALL name")
                detail = cursor.string(MAX_EVENT_DETAIL, "CALL detail")
                cursor.finish()
                emit(
                    f"CALL category={_quoted(category)} name={_quoted(name)} "
                    f"detail={_quoted(detail)}"
                )
            else:
                event_id, total, index, count = cursor.unpack(CALL_CHUNK_FIXED)
                category_raw = cursor.string_bytes(MAX_CALL_CATEGORY, "CALL category")
                name_raw = cursor.string_bytes(MAX_CALL_NAME, "CALL name")
                detail = cursor.string_bytes(MAX_CALL_CHUNK_DETAIL, "CALL detail fragment")
                cursor.finish()
                try:
                    category = category_raw.decode("utf-8")
                    name = name_raw.decode("utf-8")
                except UnicodeDecodeError as error:
                    raise BinaryTraceError("CALL chunk metadata is not valid UTF-8") from error
                if event_id == 0:
                    raise BinaryTraceError("CALL chunk requires a nonzero event ID")
                if (count < 2 or index >= count or total > MAX_LOGICAL_CALL_DETAIL
                        or not detail or total <= len(detail) or total < count):
                    raise BinaryTraceError("invalid CALL chunk metadata")
                if pending_call is None:
                    if index != 0:
                        raise BinaryTraceError("CALL chunk index must start at zero")
                    pending_call = _PendingCall(
                        event_id, total, count, category, name, 1, bytearray(detail)
                    )
                else:
                    if (event_id, total, count, category, name) != (
                            pending_call.event_id, pending_call.total, pending_call.count,
                            pending_call.category, pending_call.name):
                        raise BinaryTraceError("CALL chunk metadata mismatch")
                    if index != pending_call.next_index:
                        raise BinaryTraceError("CALL chunk index is duplicate or out of order")
                    pending_call.detail.extend(detail)
                    pending_call.next_index += 1
                assert pending_call is not None
                if len(pending_call.detail) > pending_call.total:
                    raise BinaryTraceError("CALL chunk total detail length exceeded")
                if pending_call.next_index == pending_call.count:
                    if len(pending_call.detail) != pending_call.total:
                        raise BinaryTraceError("CALL chunk total detail length mismatch")
                    try:
                        logical_detail = bytes(pending_call.detail).decode("utf-8")
                    except UnicodeDecodeError as error:
                        raise BinaryTraceError("CALL detail is not valid UTF-8") from error
                    emit(
                        f"CALL category={_quoted(pending_call.category)} "
                        f"name={_quoted(pending_call.name)} "
                        f"detail={_quoted(logical_detail)}"
                    )
                    pending_call = None
        elif record_type in (7, 8) and flags == 0:
            cursor = _Payload(payload, "RULE" if record_type == 7 else "ERROR")
            name = cursor.string(MAX_EVENT_NAME, "event name")
            detail = cursor.string(MAX_EVENT_DETAIL, "event detail")
            cursor.finish()
            if record_type == 7:
                emit(f"RULE name={_quoted(name)} detail={_quoted(detail)}")
            else:
                emit(f"ERROR name={_quoted(name)} detail={_quoted(detail)}")
        elif record_type in (7, 8):
            cursor = _Payload(payload, "RULE chunk" if record_type == 7 else "ERROR chunk")
            event_id, total, index, count = cursor.unpack(CALL_CHUNK_FIXED)
            name_raw = cursor.string_bytes(MAX_EVENT_NAME, "event name")
            detail = cursor.string_bytes(MAX_CALL_CHUNK_DETAIL, "event detail fragment")
            cursor.finish()
            try:
                name = name_raw.decode("utf-8")
            except UnicodeDecodeError as error:
                raise BinaryTraceError("event chunk name is not valid UTF-8") from error
            if (event_id == 0 or count < 2 or index >= count or total > MAX_EVENT_DETAIL
                    or not detail or total <= len(detail) or total < count):
                raise BinaryTraceError("invalid semantic event chunk metadata")
            if pending_event is None:
                if index != 0:
                    raise BinaryTraceError("semantic event chunk index must start at zero")
                pending_event = _PendingEvent(
                    record_type, event_id, total, count, name, 1, bytearray(detail)
                )
            else:
                if (record_type, event_id, total, count, name) != (
                        pending_event.record_type, pending_event.event_id,
                        pending_event.total, pending_event.count, pending_event.name):
                    raise BinaryTraceError("semantic event chunk metadata mismatch")
                if index != pending_event.next_index:
                    raise BinaryTraceError("semantic event chunk index is duplicate or out of order")
                pending_event.detail.extend(detail)
                pending_event.next_index += 1
            assert pending_event is not None
            if len(pending_event.detail) > pending_event.total:
                raise BinaryTraceError("semantic event chunk total detail length exceeded")
            if pending_event.next_index == pending_event.count:
                if len(pending_event.detail) != pending_event.total:
                    raise BinaryTraceError("semantic event chunk total detail length mismatch")
                try:
                    logical_detail = bytes(pending_event.detail).decode("utf-8")
                except UnicodeDecodeError as error:
                    raise BinaryTraceError("event detail is not valid UTF-8") from error
                label = "RULE" if pending_event.record_type == 7 else "ERROR"
                emit(f"{label} name={_quoted(pending_event.name)} "
                     f"detail={_quoted(logical_detail)}")
                pending_event = None
        elif record_type == 9:
            if flags or len(payload) != TRACE_END_FIXED.size:
                raise BinaryTraceError("invalid TRACE_END payload")
            values = TRACE_END_FIXED.unpack(payload)
            footer = _Footer(*values)
            if footer.success not in (0, 1):
                raise BinaryTraceError("invalid TRACE_END status")
            if footer.instructions != instruction_count:
                raise BinaryTraceError("footer instruction count mismatch")
            if footer.encoded_bytes != reader.total:
                raise BinaryTraceError("footer encoded byte count mismatch")
            if footer.effective_buffer_bytes != begin_effective_buffer:
                raise BinaryTraceError("footer effective buffer mismatch")
            ended = True
            emit(
                f"TRACE_END status={'ok' if footer.success else 'failed'} "
                f"return={_hex(footer.return_value)} elapsed_ms={footer.elapsed_ms} "
                f"instructions={footer.instructions} encoded_bytes={footer.encoded_bytes} "
                f"compressed_bytes={footer.compressed_bytes} cache_hits={footer.cache_hits} "
                f"cache_misses={footer.cache_misses} cache_collisions={footer.cache_collisions} "
                f"buffer_swaps={footer.buffer_swaps} producer_waits={footer.producer_waits} "
                f"producer_wait_ns={footer.producer_wait_ns} "
                f"effective_buffer_bytes={footer.effective_buffer_bytes}"
            )
        else:
            raise BinaryTraceError(f"unknown record type {record_type}")

    if pending_call is not None:
        raise BinaryTraceError("incomplete CALL chunk group")
    if pending_event is not None:
        raise BinaryTraceError("incomplete semantic event chunk group")
    if not began:
        raise BinaryTraceError("missing TRACE_BEGIN")
    if not ended and not allow_partial:
        raise BinaryTraceError("missing TRACE_END")
    stats = ConversionStats(instruction_count, text_bytes, not ended)
    assert begin_compression is not None
    return _ConversionDetails(
        stats, PROFILE_NAMES[profile_value], begin_compression, footer
    )


def convert_binary_stream(source: BinaryIO, output: TextIO, *,
                          allow_partial: bool = False) -> ConversionStats:
    """Validate and render one already-decompressed QTRB stream."""
    return _convert_binary_stream(source, output, allow_partial=allow_partial).stats
