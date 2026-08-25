import io
import math
import struct
import tracemalloc
import unittest


from scripts.trace_binary import BinaryTraceError, convert_binary_stream


HEADER = struct.Struct("<4sBBBBBBHI")
RECORD = struct.Struct("<HHI")
TRACE_STOP = struct.Struct("<B7x" + "Q" * 11)


def text(value: bytes | str) -> bytes:
    raw = value.encode() if isinstance(value, str) else value
    return struct.pack("<H", len(raw)) + raw


def record(kind: int, payload: bytes, flags: int = 0) -> bytes:
    return RECORD.pack(kind, flags, len(payload)) + payload


def stream_header(profile: int = 2, **changes: int) -> bytes:
    values = dict(major=1, minor=0, endian=1, pointer=8, reserved=0,
                  size=16, features=0)
    values.update(changes)
    return HEADER.pack(b"QTRB", values["major"], values["minor"],
                       values["endian"], values["pointer"], profile,
                       values["reserved"], values["size"], values["features"])


def begin(profile: int = 2, *, compression: int = 1) -> bytes:
    payload = struct.pack(
        "<QQQIIBBQQ", 0x100000, 0x40, 0x100040, 12, 13, profile,
        compression, 4096, 7
    ) + text('scene\n"x') + text("lib.so")
    return record(1, payload)


def module(module_id: int = 1, name: str = "lib.so", base: int = 0x100000) -> bytes:
    return record(2, struct.pack("<IQ", module_id, base) + text(name))


def instruction_definition(metadata_id: int = 99, *, pc_kind: int = 2,
                           displacement: int = 0x1234) -> bytes:
    fixed = struct.pack(
        "<IIQQqIBBBB", metadata_id, 0x14000000, (1 << 0) | (1 << 31),
        (1 << 32) | (1 << 33), displacement, 3, pc_kind, 14, 1, 0
    )
    registers = (
        struct.pack("<B", 8) + text("X0")
        + struct.pack("<B", 8) + text("SP")
        + struct.pack("<B", 8) + text("NZCV")
        + struct.pack("<B", 8) + text("PC")
    )
    operand = struct.pack("<BBBBBBB I q", 0, 1, 3, 0, 2, 1, 0, 8, -16)
    return record(3, fixed + text("B.EQ") + text("x0, #0x4") + text("fallback")
                  + registers + operand)


def instruction(sequence: int = 1, module_id: int = 1,
                metadata_id: int = 99) -> bytes:
    payload = struct.pack("<QIQIBB", sequence, module_id, 0x2345, metadata_id, 2, 2)
    payload += struct.pack("<QQQQ", 1, 2, 3, 4)
    return record(4, payload)


def mixed_width_definition() -> bytes:
    read_mask = (1 << 1) | (1 << 30)
    write_mask = (1 << 2) | (1 << 31) | (1 << 33)
    fixed = struct.pack(
        "<IIQQqIBBBB", 123, 0xAA, read_mask, write_mask, 0, 0, 0, 0, 0, 0
    )
    registers = (
        struct.pack("<B", 4) + text("W1")
        + struct.pack("<B", 8) + text("LR")
        + struct.pack("<B", 4) + text("W2")
        + struct.pack("<B", 8) + text("SP")
        + struct.pack("<B", 8) + text("PC")
    )
    return record(3, fixed + text("ADD") + text("w2, w1, #1") + text("") + registers)


def mixed_width_instruction() -> bytes:
    payload = struct.pack("<QIQIBB", 1, 1, 0x2345, 123, 2, 3)
    return record(4, payload + struct.pack("<QQQQQ", 0x11, 0x22, 0x33, 0x44, 0x55))


def memory() -> bytes:
    fixed = struct.pack("<IQBBHQIQ", 1, 0x2345, 3, 1, 0x12, 0x2000, 4, 0xAB)
    states = struct.pack("<BB", 1, 2) + b"\x00\xff" + struct.pack("<BB", 2, 0)
    return record(5, fixed + states)


def uncaptured_memory(address: int) -> bytes:
    fixed = struct.pack("<IQBBHQIQ", 1, 0x2345, 1, 0, 0, address, 1, address)
    return record(5, fixed + b"\0\0\0\0")


def call(category: bytes | str = "jni", name: bytes | str = "Find",
         detail: bytes | str = "ok") -> bytes:
    return record(6, text(category) + text(name) + text(detail))


def chunk(event_id: int, total: int, index: int, count: int, detail: bytes,
          category: bytes = b"jni", name: bytes = b"Long") -> bytes:
    payload = struct.pack("<QIHH", event_id, total, index, count)
    return record(6, payload + text(category) + text(name) + text(detail), flags=1)


def event_chunk(kind: int, event_id: int, total: int, index: int, count: int,
                detail: bytes, name: bytes = b"rule") -> bytes:
    payload = struct.pack("<QIHH", event_id, total, index, count)
    return record(kind, payload + text(name) + text(detail), flags=1)


def event(kind: int, name: str, detail: str) -> bytes:
    return record(kind, text(name) + text(detail))


def footer(*, instructions: int = 1, encoded_bytes: int = 0,
           compressed_bytes: int = 321, effective_buffer: int = 4096) -> bytes:
    metrics = (instructions, encoded_bytes, compressed_bytes, 9, 1, 0, 2, 0, 0,
               effective_buffer)
    return record(9, struct.pack("<BQQ" + "Q" * 10, 1, 0x55, 17, *metrics))


def stopped(*, encoded_bytes: int, compressed_bytes: int) -> bytes:
    values = (1, 17, 1, encoded_bytes, compressed_bytes, 9, 1, 0, 2, 0, 0, 4096)
    return record(10, TRACE_STOP.pack(*values))


def complete_stream(*events: bytes, profile: int = 2, compression: int = 1,
                    compressed_bytes: int | None = None) -> bytes:
    prefix = (stream_header(profile) + begin(profile, compression=compression)
              + module() + b"".join(events))
    first_footer = footer(instructions=sum(item[:2] == b"\x04\x00" for item in events))
    total = len(prefix) + len(first_footer)
    return prefix + footer(
        instructions=sum(item[:2] == b"\x04\x00" for item in events),
        encoded_bytes=total,
        compressed_bytes=total if compressed_bytes is None else compressed_bytes,
    )


def stopped_stream() -> bytes:
    prefix = (stream_header(minor=2, features=1) + begin() + module()
              + instruction_definition() + instruction())
    terminal_size = len(stopped(encoded_bytes=0, compressed_bytes=0))
    total = len(prefix) + terminal_size
    return prefix + stopped(encoded_bytes=total, compressed_bytes=total)


class BinaryTraceConversionTests(unittest.TestCase):
    def convert(self, data: bytes, *, partial: bool = False):
        output = io.StringIO()
        stats = convert_binary_stream(io.BytesIO(data), output, allow_partial=partial)
        return output.getvalue(), stats

    def test_normalizes_stopped_v12_terminal_and_exposes_its_public_model(self):
        output, stats = self.convert(stopped_stream())

        self.assertIn("TRACE_BEGIN format=4", output)
        self.assertIn(
            "TRACE_END status=stopped reason=duration_elapsed return_valid=0", output
        )
        self.assertEqual("stopped", stats.termination)

    def test_rejects_malformed_stopped_terminals_and_stops_stream_parsing(self):
        complete = stopped_stream()
        header = stream_header(minor=2, features=1)
        terminal_start = len(complete) - RECORD.size - TRACE_STOP.size
        prefix = complete[:terminal_start]
        terminal_payload = complete[-TRACE_STOP.size:]
        reserved = bytearray(terminal_payload)
        reserved[1] = 1
        bad_reason = bytearray(terminal_payload)
        bad_reason[0] = 0
        cases = (
            ("invalid TRACE_STOP reason", prefix + record(10, bytes(bad_reason))),
            ("nonzero TRACE_STOP reserved bytes", prefix + record(10, bytes(reserved))),
            ("invalid TRACE_STOP payload", prefix + record(10, b"\x01")),
            ("record after TRACE_END", complete + call()),
            ("TRACE_STOP requires minor 2", complete.replace(
                header, stream_header(minor=1), 1)),
            ("unsupported minor/features", complete.replace(
                header, stream_header(minor=2), 1)),
        )
        for message, data in cases:
            with self.subTest(message=message), self.assertRaisesRegex(BinaryTraceError, message):
                self.convert(data)

    def test_rejects_failed_trace_end_for_every_supported_minor(self):
        complete = complete_stream()
        terminal_start = len(complete) - RECORD.size - 97
        failed = bytearray(complete[-97:])
        failed[0] = 0
        failed_stream = complete[:terminal_start] + record(9, bytes(failed))

        for minor, features in ((0, 0), (1, 0), (2, 1)):
            with self.subTest(minor=minor, features=features):
                output = io.StringIO()
                data = failed_stream.replace(
                    stream_header(), stream_header(minor=minor, features=features), 1
                )

                with self.assertRaisesRegex(
                        BinaryTraceError, "failed TRACE_END cannot be converted as completed"):
                    convert_binary_stream(io.BytesIO(data), output)
                self.assertNotIn("TRACE_END status=completed", output.getvalue())

    def test_legacy_completed_streams_normalize_to_format_four_and_completed(self):
        for minor in (0, 1):
            with self.subTest(minor=minor):
                output, stats = self.convert(complete_stream().replace(
                    stream_header(), stream_header(minor=minor), 1
                ))
                self.assertTrue(output.startswith("TRACE_BEGIN format=4"))
                self.assertIn("TRACE_END status=completed return_valid=1", output)
                self.assertEqual("completed", stats.termination)

    def test_renders_all_records_profiles_and_static_dynamic_semantics(self):
        data = complete_stream(
            instruction_definition(), instruction(), memory(),
            call("jni", "Find", 'line\n"quoted"'), event(7, "guard", "hit"),
            event(8, "fatal", "bad"), profile=2,
        )
        output, stats = self.convert(data)
        self.assertEqual(1, stats.instructions)
        self.assertEqual(len(output.encode()), stats.converted_text_bytes)
        self.assertFalse(stats.partial)
        self.assertEqual(
            [
                'TRACE_BEGIN format=4 scene="scene\\n\\\"x" target="lib.so" '
                'target_offset=0x40 base=0x100000 address=0x100040 pid=12 tid=13 '
                'profile=full compression=1 effective_buffer_bytes=4096 run_id=7',
                'INST seq=1 module="lib.so" module_base=0x100000 pc=0x102345 '
                'relative_pc=0x2345 metadata_id=99 opcode=0x14000000 '
                'asm="B.EQ x0, 0x103234" flags=0x3 condition=14 '
                'reads=[X0:8=0x1,SP:8=0x2] writes=[NZCV:8=0x3,PC:8=0x4] '
                'slow_memory_path=0 memory_operands=[base=X0,index=X1,extend=lsl,'
                'mode=offset,shift=2,kind=read,writeback=0,size=8,disp=-16]',
                'MEMORY module="lib.so" module_base=0x100000 pc=0x102345 '
                'relative_pc=0x2345 kind=readwrite metadata_available=1 flags=0x12 '
                'address=0x2000 size=4 value=0xab before=00ff after=<unavailable>',
                'CALL category="jni" name="Find" detail="line\\n\\\"quoted\\\""',
                'RULE name="guard" detail="hit"',
                'ERROR name="fatal" detail="bad"',
                'TRACE_END status=completed return_valid=1 return=0x55 elapsed_ms=17 instructions=1 '
                f'encoded_bytes={len(data)} compressed_bytes={len(data)} cache_hits=9 '
                'cache_misses=1 cache_collisions=0 buffer_swaps=2 producer_waits=0 '
                'producer_wait_ns=0 effective_buffer_bytes=4096',
            ],
            output.splitlines(),
        )

    def test_profile_names_are_stable_for_all_wire_values(self):
        for profile, name in enumerate(("fast", "balanced", "full")):
            with self.subTest(profile=name):
                output, _ = self.convert(complete_stream(
                    call("profile", name, "detail"), event(7, "rule", name),
                    event(8, "error", name), profile=profile,
                ))
                self.assertIn(f"profile={name}", output.splitlines()[0])
                self.assertIn(f'name="{name}"', output)

    def test_dense_register_order_preserves_w_lr_sp_and_pc_widths(self):
        output, _ = self.convert(complete_stream(
            mixed_width_definition(), mixed_width_instruction()
        ))
        line = next(line for line in output.splitlines() if line.startswith("INST "))
        self.assertIn("reads=[W1:4=0x11,LR:8=0x22]", line)
        self.assertIn("writes=[W2:4=0x33,SP:8=0x44,PC:8=0x55]", line)

    def test_more_than_eight_memory_continuations_preserve_order_and_not_captured(self):
        addresses = list(range(0x3000, 0x300A))
        output, _ = self.convert(complete_stream(
            *(uncaptured_memory(address) for address in addresses)
        ))
        lines = [line for line in output.splitlines() if line.startswith("MEMORY ")]
        self.assertEqual(10, len(lines))
        self.assertEqual(
            addresses,
            [int(line.split(" address=", 1)[1].split(" ", 1)[0], 16) for line in lines],
        )
        self.assertTrue(all("before=<not-captured> after=<not-captured>" in line
                            for line in lines))

    def test_accepts_ordinary_short_reads_at_every_stream_boundary(self):
        data = complete_stream(instruction_definition(), instruction())

        class ShortReader(io.BytesIO):
            def read(self, size=-1):
                return super().read(min(size, 3))

        output = io.StringIO()
        stats = convert_binary_stream(ShortReader(data), output)
        self.assertEqual(1, stats.instructions)
        self.assertIn("TRACE_END status=completed", output.getvalue())

    def test_current_pc_and_current_page_targets_wrap_at_64_bits(self):
        page = complete_stream(instruction_definition(displacement=-0x3000), instruction())
        current = complete_stream(
            instruction_definition(pc_kind=1, displacement=-(0x102345 + 1)), instruction()
        )
        self.assertIn('asm="B.EQ x0, 0xff000"', self.convert(page)[0])
        self.assertIn('asm="B.EQ x0, 0xffffffffffffffff"', self.convert(current)[0])

    def test_reassembles_raw_utf8_chunks_and_keeps_adjacent_identical_events_separate(self):
        detail = "A€Z".encode()
        events = (
            chunk(8, len(detail), 0, 2, detail[:2]),
            chunk(8, len(detail), 1, 2, detail[2:]),
            chunk(9, len(detail), 0, 2, detail[:1]),
            chunk(9, len(detail), 1, 2, detail[1:]),
        )
        output, _ = self.convert(complete_stream(*events))
        self.assertEqual(2, output.count('CALL category="jni" name="Long" detail="A€Z"'))

    def test_partial_stream_accepts_only_complete_records_without_footer(self):
        data = stream_header(0) + begin(0) + module() + instruction_definition() + instruction()
        output, stats = self.convert(data, partial=True)
        self.assertTrue(stats.partial)
        self.assertIsNone(stats.termination)
        self.assertEqual(1, stats.instructions)
        self.assertNotIn("TRACE_END", output)
        with self.assertRaisesRegex(BinaryTraceError, "TRACE_END"):
            self.convert(data)
        with self.assertRaisesRegex(BinaryTraceError, "truncated record payload"):
            self.convert(data[:-1], partial=True)

    def test_rejects_invalid_headers_flags_lengths_and_order(self):
        mutations = (
            ("magic", b"BAD!" + complete_stream()[4:]),
            ("major version", stream_header(major=2) + begin() + module()),
            ("unsupported minor/features", stream_header(minor=2) + begin() + module()),
            ("endian", stream_header(endian=2) + begin() + module()),
            ("pointer width", stream_header(pointer=3) + begin() + module()),
            ("reserved", stream_header(reserved=1) + begin() + module()),
            ("header size", stream_header(size=15) + begin() + module()),
            ("unsupported minor/features", stream_header(features=1) + begin() + module()),
            ("unknown flags", stream_header() + begin() + record(7, text("") + text(""), 2)),
            ("record payload exceeds", stream_header() + begin() + RECORD.pack(7, 0, 4621)),
            ("TRACE_BEGIN must be first", stream_header() + module()),
        )
        for message, data in mutations:
            with self.subTest(message=message), self.assertRaisesRegex(BinaryTraceError, message):
                self.convert(data)

    def test_rejects_conflicts_missing_references_sequence_and_footer_mismatch(self):
        conflict = complete_stream(module(name="other.so"))
        instruction_conflict = complete_stream(
            instruction_definition(), instruction_definition(displacement=8)
        )
        missing = complete_stream(instruction(metadata_id=8))
        missing_module = complete_stream(instruction_definition(), instruction(module_id=2))
        gap = complete_stream(instruction_definition(), instruction(sequence=2))
        count = complete_stream(instruction_definition(), instruction()).replace(
            struct.pack("<BQQQ", 1, 0x55, 17, 1), struct.pack("<BQQQ", 1, 0x55, 17, 2)
        )
        for message, data in (
            ("conflicting module definition", conflict),
            ("conflicting instruction definition", instruction_conflict),
            ("undefined instruction metadata", missing),
            ("undefined module reference", missing_module),
            ("instruction sequence", gap),
            ("footer instruction count", count),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(BinaryTraceError, message):
                self.convert(data)

    def test_rejects_call_chunk_ambiguity_and_invalid_utf8(self):
        good = (chunk(1, 4, 0, 2, b"ab"), chunk(1, 4, 1, 2, b"cd"))
        cases = {
            "nonzero event ID": (chunk(0, 4, 0, 2, b"ab"), good[1]),
            "chunk index": (chunk(1, 4, 1, 2, b"ab"), good[1]),
            "contiguous": (good[0], call(), good[1]),
            "metadata mismatch": (good[0], chunk(1, 4, 1, 2, b"cd", name=b"Other")),
            "total detail length": (chunk(1, 5, 0, 2, b"ab"), chunk(1, 5, 1, 2, b"cd")),
            "valid UTF-8": (chunk(1, 2, 0, 2, b"\xff"), chunk(1, 2, 1, 2, b"x")),
        }
        for message, events in cases.items():
            with self.subTest(message=message), self.assertRaisesRegex(BinaryTraceError, message):
                self.convert(complete_stream(*events))

    def test_rejects_explicit_incomplete_duplicate_out_of_order_and_oversized_calls(self):
        incomplete = stream_header() + begin() + module() + chunk(1, 4, 0, 2, b"ab")
        with self.assertRaisesRegex(BinaryTraceError, "incomplete CALL"):
            self.convert(incomplete, partial=True)
        cases = (
            ("duplicate or out of order", (
                chunk(1, 6, 0, 3, b"ab"), chunk(1, 6, 0, 3, b"cd")
            )),
            ("duplicate or out of order", (
                chunk(1, 6, 0, 3, b"ab"), chunk(1, 6, 2, 3, b"cd")
            )),
            ("invalid CALL chunk metadata", (
                chunk(1, (1 << 20) + 1, 0, 2, b"ab"),
            )),
        )
        for message, events in cases:
            with self.subTest(message=message), self.assertRaisesRegex(
                    BinaryTraceError, message):
                self.convert(complete_stream(*events))

    def test_reassembles_rule_and_error_chunks_as_one_ordered_utf8_or_raw_event(self):
        euro = "\u20ac".encode()
        version_one = complete_stream(
            event_chunk(7, 11, 6, 0, 2, b"abc"),
            event_chunk(7, 11, 6, 1, 2, euro),
            event_chunk(8, 12, 3, 0, 2, euro[:1]),
            event_chunk(8, 12, 3, 1, 2, euro[1:]),
        ).replace(stream_header(), stream_header(minor=1), 1)
        rendered, _ = self.convert(version_one)
        lines = [line for line in rendered.splitlines()
                 if line.startswith(("RULE ", "ERROR "))]
        self.assertEqual('RULE name="rule" detail="abc€"', lines[0])
        self.assertEqual('ERROR name="rule" detail="€"', lines[1])

    def test_minor_zero_rejects_event_continuation_but_keeps_legacy_rule(self):
        legacy_rule = record(7, text("legacy") + text("detail"))
        legacy, _ = self.convert(complete_stream(legacy_rule))
        self.assertIn('RULE name="legacy" detail="detail"', legacy)
        with self.assertRaisesRegex(BinaryTraceError, "minor 1"):
            self.convert(complete_stream(
                event_chunk(7, 11, 6, 0, 2, b"abc"),
                event_chunk(7, 11, 6, 1, 2, b"def"),
            ))

    def test_compatible_minor_skips_only_optional_namespace_records(self):
        optional = record(0x8000, b"opaque")
        rendered, _ = self.convert(complete_stream(optional).replace(
            stream_header(), stream_header(minor=1), 1))
        self.assertIn("TRACE_END", rendered)
        with self.assertRaisesRegex(BinaryTraceError, "TRACE_STOP requires minor 2"):
            self.convert(complete_stream(record(10, b"opaque")).replace(
                stream_header(), stream_header(minor=1), 1))
        with self.assertRaisesRegex(BinaryTraceError, "unsupported minor/features"):
            self.convert(complete_stream(optional).replace(
                stream_header(), stream_header(minor=1, features=1), 1))

    def test_rejects_record_after_footer_unknown_record_and_missing_footer(self):
        complete = complete_stream()
        for message, data in (
            ("record after TRACE_END", complete + call()),
            ("TRACE_STOP requires minor 2", stream_header() + begin() + record(10, b"")),
            ("TRACE_END", stream_header() + begin() + module()),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(BinaryTraceError, message):
                self.convert(data)

    def test_one_gib_virtual_stream_stays_below_128_mib_peak(self):
        prefix = stream_header() + begin() + module()
        repeated = call("", "", "x" * 4096)
        repetitions = math.ceil(((1 << 30) - len(prefix) - 105) / len(repeated))
        total = len(prefix) + repetitions * len(repeated) + 105
        ending = footer(instructions=0, encoded_bytes=total)

        class VirtualStream:
            def __init__(self):
                self.position = 0

            def read(self, size):
                if self.position >= total:
                    return b""
                repeat_start = len(prefix)
                repeat_end = repeat_start + repetitions * len(repeated)
                if self.position < repeat_start:
                    source = prefix
                    offset = self.position
                    available = repeat_start - self.position
                elif self.position < repeat_end:
                    source = repeated
                    offset = (self.position - repeat_start) % len(repeated)
                    available = len(repeated) - offset
                else:
                    source = ending
                    offset = self.position - repeat_end
                    available = total - self.position
                count = min(size, available)
                result = source[offset:offset + count]
                self.position += len(result)
                return result

        class NullText:
            def write(self, value):
                return len(value)

        tracemalloc.start()
        try:
            stats = convert_binary_stream(VirtualStream(), NullText())
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertGreaterEqual(total, 1 << 30)
        self.assertEqual(0, stats.instructions)
        self.assertLess(peak, 128 << 20)


if __name__ == "__main__":
    unittest.main()
