import contextlib
import io
import os
import re
import struct
import subprocess
import sys
import tempfile
import tracemalloc
import unittest
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

import scripts.trace_convert as trace_convert
import scripts.lz4_frames as lz4_frames
from scripts.trace_binary import BinaryTraceError
from scripts.trace_convert import convert_binary_file, main
from scripts.tests.test_lz4_frames import uncompressed_lz4_frame
from scripts.tests.test_trace_binary import complete_stream, stopped_stream


def raw_stream(*events):
    return complete_stream(*events, compression=0)


def compressed_artifact(*, compression=1):
    probe = complete_stream(compression=compression)
    size = len(uncompressed_lz4_frame(probe))
    return uncompressed_lz4_frame(
        complete_stream(compression=compression, compressed_bytes=size)
    )


def fake_lz4_executable(root: Path) -> Path:
    decoder = root / "lz4"
    decoder.write_text(
        "#!/usr/bin/env python3\nimport sys\ndata=sys.stdin.buffer.read(); p=0\n"
        "while p < len(data):\n"
        " m=data[p:p+4]; p+=4\n"
        " if 0x50 <= m[0] <= 0x5f:\n"
        "  n=int.from_bytes(data[p:p+4],'little'); p+=4+n; continue\n"
        " flags=data[p]; p+=2+(8 if flags&8 else 0)+(4 if flags&1 else 0)+1\n"
        " while True:\n"
        "  n=int.from_bytes(data[p:p+4],'little'); p+=4\n"
        "  if n == 0: break\n"
        "  size=n & 0x7fffffff; sys.stdout.buffer.write(data[p:p+size]); p+=size\n"
        "  if flags&16: p+=4\n"
        " if flags&4: p+=4\n",
        encoding="utf-8",
    )
    decoder.chmod(0o755)
    return decoder


def metrics_sidecar(source: Path, extra: str = "", *, termination: str = "completed",
                    return_valid: int = 1, return_value: str = "0x55",
                    instructions: int = 0) -> str:
    size = source.stat().st_size
    def fixed_six(numerator: int, denominator: int) -> str:
        whole, remainder = divmod(numerator, denominator)
        return f"{whole}.{remainder * 1_000_000 // denominator:06d}"
    return (
        "metrics_version=3\n"
        f"termination={termination}\nreturn_valid={return_valid}\n"
        f"profile=full\nreturn={return_value}\ninstructions={instructions}\n"
        f"elapsed_ms=17\ninstructions_per_second={fixed_six(instructions * 1000, 17)}\n"
        f"encoded_bytes={size}\ncompressed_bytes={size}\n"
        f"encoded_bytes_per_second={fixed_six(size * 1000, 17)}\n"
        f"disk_bytes_per_second={fixed_six(size * 1000, 17)}\n"
        "compression_ratio=1.000000\n"
        "cache_hits=9\ncache_misses=1\ncache_collisions=0\n"
        "cache_hit_rate=0.900000\n"
        "buffer_swaps=2\nproducer_waits=0\nproducer_wait_ns=0\n"
        "effective_buffer_bytes=4096\n" + extra
    )


class DocumentationContractTests(unittest.TestCase):
    @staticmethod
    def _table_after(document: str, heading: str) -> tuple[list[str], list[dict[str, str]]]:
        parts = document.split(heading, 1)
        if len(parts) != 2:
            return [], []
        section = parts[1]
        table_lines = []
        for line in section.splitlines():
            if line.startswith("|"):
                table_lines.append(line)
            elif table_lines:
                break
        if not table_lines:
            return [], []
        header = [cell.strip() for cell in table_lines[0].strip("|").split("|")]
        rows = []
        for line in table_lines[2:]:
            values = [cell.strip().strip("`") for cell in line.strip("|").split("|")]
            rows.append(dict(zip(header, values, strict=True)))
        return header, rows

    def test_user_docs_describe_binary_workflow_and_compatibility(self):
        root = Path(__file__).parents[2]
        readme = root.joinpath("README.md").read_text(encoding="utf-8")
        protocol = root.joinpath("docs", "trace-format.md").read_text(encoding="utf-8")
        pull_section = readme.split("## Pull Traces", 1)[1]
        self.assertIn(
            "python3 scripts/pull_trace.py --package com.aprz.qbdiandroid \\\n"
            "  --device 192.168.51.42:5555 --output pulled-traces",
            pull_section,
        )
        self.assertIn(
            "python3 scripts/trace_convert.py input.trace.bin.lz4 --output output.trace.txt",
            pull_section,
        )
        self.assertIn("metrics_version=3", pull_section)
        self.assertIn("QTRB 1.0/1.1 + metrics v2", pull_section)
        self.assertIn("QTRB 1.2 type 9 + metrics v3", pull_section)
        self.assertIn("QTRB 1.2 type 10 + metrics v3", pull_section)
        self.assertIn("truncated + valid crash marker", pull_section)
        self.assertNotIn("文本格式 3", readme)
        self.assertIn("app-private", pull_section)
        compatibility = protocol.split("## Artifact set", 1)[1].split("## QTRB v1 stream", 1)[0]
        self.assertIn("format-2 `.trace.txt.lz4`", compatibility)
        recovery = protocol.split("## Crash partial semantics", 1)[1].split("## Buffers", 1)[0]
        self.assertIn("<basename>.partial.trace.txt", recovery)
        self.assertIn("status 2", recovery)
        exclusions = protocol.split("## Explicit exclusions", 1)[1]
        self.assertNotIn("binary trace output", exclusions.lower())

    def test_protocol_docs_cover_wire_limits_output_order_and_exit_statuses(self):
        protocol = Path(__file__).parents[2].joinpath(
            "docs", "trace-format.md"
        ).read_text(encoding="utf-8")
        text_format = protocol.split("## Text format 4", 1)[1].split("## Profiles", 1)[0]
        rendered = [line for line in text_format.splitlines() if line.startswith((
            "TRACE_BEGIN ", "INST ", "MEMORY ", "CALL ", "RULE ", "ERROR ", "TRACE_END ",
        ))]
        self.assertEqual(8, len(rendered))
        self.assertTrue(rendered[0].startswith("TRACE_BEGIN format=4 scene="))
        self.assertIn("metadata_id=... opcode=0x...", rendered[1])
        self.assertTrue(rendered[-2].startswith(
            "TRACE_END status=completed return_valid=1 return=0x..."
        ))
        self.assertTrue(rendered[-1].startswith(
            "TRACE_END status=stopped reason=duration_elapsed return_valid=0"
        ))
        self.assertIn("String escaping is JSON string escaping", text_format)
        conversion = protocol.split("## Pulling and conversion", 1)[1].split(
            "## Crash partial semantics", 1
        )[0]
        self.assertIn(
            "status 0 for a completed or stopped terminal, status 1 for an error with no text\n"
            "publication, and status 2 for valid crash-partial recovery",
            conversion,
        )

    def test_protocol_record_and_nested_layouts_are_field_exact(self):
        protocol = Path(__file__).parents[2].joinpath(
            "docs", "trace-format.md"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'StreamHeader {\n  magic: "QTRB"[4]\n  major: u8 = 1\n  minor: u8 = 0 | 1 | 2\n'
            '  endian: u8 = 1\n  pointer_width: u8 = 4 | 8\n'
            '  profile: u8                 # fast=0, balanced=1, full=2\n'
            '  reserved: u8 = 0\n  header_bytes: u16 = 16\n'
            '  required_features: u32\n}',
            protocol,
        )
        self.assertIn("| 0 | 0 |", protocol)
        self.assertIn("| 1 | 0 |", protocol)
        self.assertIn("| 2 | 1 |", protocol)
        self.assertIn(
            "RecordHeader {\n  type: u16\n  flags: u16\n  payload_bytes: u32\n}",
            protocol,
        )
        header, rows = self._table_after(protocol, "### Record payload layouts")
        self.assertEqual(
            ["Type", "Record", "Flags", "Payload fields in little-endian wire order",
             "Fixed payload bytes", "Maximum record bytes"],
            header,
        )
        expected = {
            "TRACE_BEGIN": ("1", "0", "module_base u64; target_offset u64; target_address u64; pid u32; tid u32; profile u8; compression_enabled u8; effective_buffer_bytes u64; run_id u64; scene string; target string", "54", "572"),
            "MODULE_DEF": ("2", "0", "module_id u32; module_base u64; module_name string", "14", "277"),
            "INSTRUCTION_DEF": ("3", "0", "metadata_id u32; opcode u32; read_mask u64; write_mask u64; pc_displacement i64; instruction_flags u32; pc_kind u8; condition u8; memory_operand_count u8; slow_memory_path u8; mnemonic string; operands string; disassembly string; read register definitions; write register definitions; memory operands", "40", "1646"),
            "INSTRUCTION": ("4", "0", "sequence u64; module_id u32; module_relative_pc u64; metadata_id u32; read_count u8; write_count u8; read values u64[read_count]; write values u64[write_count]", "26", "578"),
            "MEMORY": ("5", "0", "module_id u32; module_relative_pc u64; access_kind u8; metadata_available u8; flags u16; address u64; access_size u32; value u64; before memory state; after memory state", "40", "176"),
            "CALL": ("6", "0", "category string; name string; detail string", "6", "4620"),
            "CALL_CONTINUATION": ("6", "0x0001", "event_id u64; total_detail_bytes u32; chunk_index u16; chunk_count u16; category string; name string; detail_fragment string", "22", "3612"),
            "RULE": ("7", "0", "name string; detail string", "4", "4363"),
            "RULE_CONTINUATION": ("7", "0x0001", "event_id u64; total_detail_bytes u32; chunk_index u16; chunk_count u16; name string; detail_fragment string", "20", "3355"),
            "ERROR": ("8", "0", "name string; detail string", "4", "4363"),
            "ERROR_CONTINUATION": ("8", "0x0001", "event_id u64; total_detail_bytes u32; chunk_index u16; chunk_count u16; name string; detail_fragment string", "20", "3355"),
            "TRACE_END": ("9", "0", "success u8; return_value u64; elapsed_ms u64; instructions u64; encoded_bytes u64; compressed_bytes u64; cache_hits u64; cache_misses u64; cache_collisions u64; buffer_swaps u64; producer_waits u64; producer_wait_ns u64; effective_buffer_bytes u64", "97", "105"),
            "TRACE_STOP": ("10", "0", "reason u8; reserved[7] = 0; elapsed_ms u64; instructions u64; encoded_bytes u64; compressed_bytes u64; cache_hits u64; cache_misses u64; cache_collisions u64; buffer_swaps u64; producer_waits u64; producer_wait_ns u64; effective_buffer_bytes u64", "96", "104"),
        }
        self.assertEqual(expected, {
            row["Record"]: (
                row["Type"], row["Flags"],
                row["Payload fields in little-endian wire order"],
                row["Fixed payload bytes"], row["Maximum record bytes"],
            ) for row in rows
        })

        wire_header = Path(__file__).parents[2].joinpath(
            "tracer", "src", "main", "cpp", "events", "binary_trace_format.h"
        ).read_text(encoding="utf-8")
        direct_sizes = {
            name: int(value) for name, value in re.findall(
                r"inline constexpr size_t (kBinary\w+) =\s*(\d+);", wire_header
            )
        }
        maximum_sizes = {
            name: int(value) for name, value in re.findall(
                r"static_assert\((kBinary\w+) == (\d+)\);", wire_header
            )
        }
        fixed_constants = {
            "TRACE_BEGIN": "kBinaryTraceBeginFixedPayloadBytes",
            "MODULE_DEF": "kBinaryModuleDefinitionFixedPayloadBytes",
            "INSTRUCTION_DEF": "kBinaryInstructionDefinitionFixedPayloadBytes",
            "INSTRUCTION": "kBinaryInstructionFixedPayloadBytes",
            "MEMORY": "kBinaryMemoryFixedPayloadBytes",
            "CALL": "kBinaryCallFixedPayloadBytes",
            "RULE": "kBinaryRuleErrorFixedPayloadBytes",
            "ERROR": "kBinaryRuleErrorFixedPayloadBytes",
            "TRACE_END": "kBinaryTraceEndPayloadBytes",
        }
        maximum_constants = {
            "TRACE_BEGIN": "kBinaryMaxTraceBeginRecordBytes",
            "MODULE_DEF": "kBinaryMaxModuleDefinitionRecordBytes",
            "INSTRUCTION_DEF": "kBinaryMaxInstructionDefinitionRecordBytes",
            "INSTRUCTION": "kBinaryMaxInstructionRecordBytes",
            "MEMORY": "kBinaryMaxMemoryRecordBytes",
            "CALL": "kBinaryMaxCallRecordBytes",
            "CALL_CONTINUATION": "kBinaryMaxCallChunkRecordBytes",
            "RULE_CONTINUATION": "kBinaryMaxEventChunkRecordBytes",
            "ERROR_CONTINUATION": "kBinaryMaxEventChunkRecordBytes",
            "RULE": "kBinaryMaxRuleErrorRecordBytes",
            "ERROR": "kBinaryMaxRuleErrorRecordBytes",
            "TRACE_END": "kBinaryTraceEndRecordBytes",
        }
        rows_by_record = {row["Record"]: row for row in rows}
        for record, constant in fixed_constants.items():
            self.assertEqual(direct_sizes[constant],
                             int(rows_by_record[record]["Fixed payload bytes"]))
        call_chunk_fixed = (
            direct_sizes["kBinaryCallChunkMetadataBytes"]
            + direct_sizes["kBinaryCallFixedPayloadBytes"]
        )
        self.assertEqual(call_chunk_fixed,
                         int(rows_by_record["CALL_CONTINUATION"]["Fixed payload bytes"]))
        for record, constant in maximum_constants.items():
            self.assertEqual(maximum_sizes[constant],
                             int(rows_by_record[record]["Maximum record bytes"]))

        nested_header, nested_rows = self._table_after(protocol, "### Nested wire layouts")
        self.assertEqual(["Nested value", "Exact layout", "Limit"], nested_header)
        self.assertEqual({
            "string": ("byte_length u16; bytes[byte_length]", "65,535-byte wire maximum; semantic limits below"),
            "register definition": ("width u8; name string", "34 read and 34 write definitions; ascending mask-bit order"),
            "memory operand": ("base u8; index u8; extend u8; address_mode u8; shift u8; access_kind u8; writeback u8; access_size u32; displacement i64", "19 bytes; at most 4"),
            "memory state": ("state u8; byte_count u8; bytes[byte_count]", "state 0/1/2; at most 64 bytes"),
        }, {
            row["Nested value"]: (row["Exact layout"], row["Limit"])
            for row in nested_rows
        })

    def test_committed_acceptance_has_fifteen_auditable_measured_runs(self):
        baseline = Path(__file__).parents[2].joinpath(
            "docs", "benchmarks", "binary-trace-baseline.md"
        ).read_text(encoding="utf-8")
        header, rows = self._table_after(baseline, "### Per-run measured evidence")
        self.assertEqual([
            "Profile", "Run", "Artifact", "SHA-256", "Elapsed ms", "Instructions",
            "Return", "Instructions/s", "Encoded bytes", "Compressed bytes", "Ratio",
            "Cache hits", "Cache misses", "Cache collisions", "Buffer swaps",
            "Producer waits", "Producer wait ns", "Effective buffer bytes",
            "Conversion", "Converted bytes", "Sequence", "Footer/sidecar", "Size limit",
            "Size gate",
        ], header)
        self.assertEqual(15, len(rows))

        limits = {"fast": 307925, "balanced": 365877, "full": 429199}
        encoded = {"fast": 1096964, "balanced": 1566635, "full": 1672811}
        expected_medians = {
            "fast": (16, Decimal("1357375.000000"), 267939),
            "balanced": (24, Decimal("904916.666666"), 362559),
            "full": (36, Decimal("603277.777777"), 379982),
        }
        artifact_pattern = re.compile(
            r"^\d+_\d+_\d+_benchmark_0x6e828_0\.trace\.bin\.lz4$"
        )
        hash_pattern = re.compile(r"^[0-9a-f]{64}$")
        self.assertEqual(15, len({row["Artifact"] for row in rows}))
        self.assertEqual(15, len({row["SHA-256"] for row in rows}))
        for profile in limits:
            profile_rows = [row for row in rows if row["Profile"] == profile]
            self.assertEqual(["1", "2", "3", "4", "5"],
                             [row["Run"] for row in profile_rows])
            elapsed_values = []
            compressed_values = []
            for row in profile_rows:
                self.assertRegex(row["Artifact"], artifact_pattern)
                self.assertRegex(row["SHA-256"], hash_pattern)
                elapsed_ms = int(row["Elapsed ms"])
                instructions = int(row["Instructions"])
                rate = Decimal(row["Instructions/s"])
                encoded_bytes = int(row["Encoded bytes"])
                compressed_bytes = int(row["Compressed bytes"])
                ratio = Decimal(row["Ratio"])
                self.assertEqual(21718, instructions)
                self.assertEqual("0x5745c858653f5a7f", row["Return"])
                self.assertEqual(encoded[profile], encoded_bytes)
                self.assertLessEqual(abs(rate - Decimal(instructions * 1000) / elapsed_ms),
                                     Decimal("0.000001"))
                self.assertLessEqual(abs(ratio - Decimal(compressed_bytes) / encoded_bytes),
                                     Decimal("0.000001"))
                self.assertEqual((21608, 110, 0), (
                    int(row["Cache hits"]), int(row["Cache misses"]),
                    int(row["Cache collisions"]),
                ))
                for counter in ("Buffer swaps", "Producer waits", "Producer wait ns",
                                "Effective buffer bytes", "Converted bytes"):
                    self.assertGreater(int(row[counter]), 0)
                self.assertEqual("PASS", row["Conversion"])
                self.assertEqual("1..21718", row["Sequence"])
                self.assertEqual("PASS", row["Footer/sidecar"])
                self.assertEqual(limits[profile], int(row["Size limit"]))
                self.assertLessEqual(compressed_bytes, limits[profile])
                self.assertEqual("PASS", row["Size gate"])
                elapsed_values.append(elapsed_ms)
                compressed_values.append(compressed_bytes)
            elapsed_values.sort()
            compressed_values.sort()
            expected_elapsed, expected_rate, expected_compressed = expected_medians[profile]
            self.assertEqual(expected_elapsed, elapsed_values[2])
            self.assertLessEqual(
                abs(expected_rate - Decimal(21718 * 1000) / elapsed_values[2]),
                Decimal("0.000001"),
            )
            self.assertEqual(expected_compressed, compressed_values[2])

        summary_header, summary_rows = self._table_after(
            baseline, "## Accepted QTRB v1 results"
        )
        self.assertIn("Median elapsed ms", summary_header)
        self.assertIn("Median instructions/s", summary_header)
        self.assertIn("Median compressed bytes", summary_header)
        self.assertIn("Maximum compressed bytes", summary_header)
        self.assertEqual(3, len(summary_rows))
        for summary in summary_rows:
            profile = summary["Profile"]
            profile_rows = [row for row in rows if row["Profile"] == profile]
            elapsed_values = sorted(int(row["Elapsed ms"]) for row in profile_rows)
            compressed_values = sorted(int(row["Compressed bytes"]) for row in profile_rows)
            self.assertEqual(elapsed_values[2], int(summary["Median elapsed ms"]))
            self.assertEqual(expected_medians[profile][1],
                             Decimal(summary["Median instructions/s"]))
            self.assertEqual(compressed_values[2], int(summary["Median compressed bytes"]))
            self.assertEqual(compressed_values[-1], int(summary["Maximum compressed bytes"]))
            self.assertEqual("PASS", summary["Every-size gate"])

    def test_metrics_document_execution_timing_and_completion_boundaries(self):
        protocol = Path(__file__).parents[2].joinpath(
            "docs", "trace-format.md"
        ).read_text(encoding="utf-8")
        metrics = protocol.split("## Metrics v3", 1)[1].split("## Pulling and conversion", 1)[0]
        metrics = " ".join(metrics.replace("`", "").split())
        self.assertIn(
            "elapsed_ms stops after traced target execution and producer callbacks, before final "
            "writer drain, footer, and sidecar publication",
            metrics,
        )
        self.assertIn("not end-to-end publication throughput", metrics)
        self.assertIn("termination is completed or stopped", metrics)
        self.assertIn("return_valid is respectively 1 or 0", metrics)
        self.assertIn("stopped terminal fixes return=0x0", metrics)
        self.assertIn("encoded_bytes is complete after the terminal is committed", metrics)
        self.assertIn(
            "compressed_bytes is complete after all frames, padding, drain, and close finish",
            metrics,
        )


class TraceConvertFileTests(unittest.TestCase):
    def test_converts_raw_and_refuses_to_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "run.trace.bin"
            destination = root / "run.trace.txt"
            source.write_bytes(raw_stream())
            stats = convert_binary_file(source, destination, lz4=None, crash_marked=False)
            self.assertFalse(stats.partial)
            self.assertIn("TRACE_END status=completed", destination.read_text())
            with self.assertRaisesRegex(BinaryTraceError, "already exists"):
                convert_binary_file(source, destination, lz4=None, crash_marked=False)

    def test_atomic_publish_preserves_existing_output_after_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "broken.trace.bin"
            destination = root / "output.trace.txt"
            source.write_bytes(b"broken")
            destination.write_text("keep", encoding="utf-8")
            with self.assertRaises(BinaryTraceError):
                convert_binary_file(source, destination, lz4=None,
                                    crash_marked=False, force=True)
            self.assertEqual("keep", destination.read_text(encoding="utf-8"))
            self.assertEqual([], list(root.glob(".trace-convert-*")))

    def test_raw_missing_footer_is_not_recoverable_even_with_crash_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "run.trace.bin"
            source.write_bytes(raw_stream()[:-105])
            with self.assertRaisesRegex(BinaryTraceError, "TRACE_END"):
                convert_binary_file(source, root / "partial.txt", lz4=None,
                                    crash_marked=True)

    def test_rejects_footer_artifact_size_mismatch_without_sidecar(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "run.trace.bin"
            source.write_bytes(complete_stream(compression=0, compressed_bytes=7))
            with self.assertRaisesRegex(BinaryTraceError, "artifact byte count"):
                convert_binary_file(source, root / "output.txt", lz4=None,
                                    crash_marked=False)

    def test_decodes_real_complete_lz4_frames_and_recovery_requires_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            decoder = fake_lz4_executable(root)
            source = root / "run.trace.bin.lz4"
            source.write_bytes(compressed_artifact())
            output = root / "run.trace.txt"
            self.assertFalse(convert_binary_file(source, output, lz4=str(decoder),
                                                 crash_marked=False).partial)

            partial_binary = complete_stream()[:-105]
            source.write_bytes(uncompressed_lz4_frame(partial_binary)
                               + uncompressed_lz4_frame(b"tail")[:-3])
            partial = root / "run.partial.trace.txt"
            with self.assertRaisesRegex(BinaryTraceError, "crash marker"):
                convert_binary_file(source, partial, lz4=str(decoder), crash_marked=False)
            stats = convert_binary_file(source, partial, lz4=str(decoder), crash_marked=True)
            self.assertTrue(stats.partial)
            self.assertNotIn("TRACE_END", partial.read_text())

    def test_validates_adjacent_metrics_sidecar(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "run.trace.bin"
            source.write_bytes(raw_stream())
            (root / "run.trace.bin.metrics").write_text(
                metrics_sidecar(source).replace("return=0x55", "return=0x999"),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(BinaryTraceError, "sidecar mismatch.*return"):
                convert_binary_file(source, root / "out.txt", lz4=None, crash_marked=False)

    def test_rejects_well_formed_but_inconsistent_v3_rates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "run.trace.bin"
            source.write_bytes(raw_stream())
            sidecar = Path(str(source) + ".metrics")
            sidecar.write_text(
                metrics_sidecar(source).replace(
                    "instructions_per_second=0.000000",
                    "instructions_per_second=999999999.000000",
                ), encoding="utf-8"
            )
            with self.assertRaisesRegex(BinaryTraceError, "instructions_per_second.*inconsistent"):
                convert_binary_file(source, root / "bad-rate.txt", lz4=None,
                                    crash_marked=False)

    def test_cli_help(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as caught:
            main(["--help"])
        self.assertEqual(0, caught.exception.code)
        self.assertIn("text format 4", output.getvalue())

    def test_container_compression_flag_must_match_raw_lz4_and_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            decoder = fake_lz4_executable(root)
            raw = root / "wrong.trace.bin"
            raw.write_bytes(complete_stream(compression=1))
            with self.assertRaisesRegex(BinaryTraceError, "compression flag"):
                convert_binary_file(raw, root / "raw.txt", lz4=None, crash_marked=False)

            compressed = root / "wrong.trace.bin.lz4"
            compressed.write_bytes(compressed_artifact(compression=0))
            with self.assertRaisesRegex(BinaryTraceError, "compression flag"):
                convert_binary_file(compressed, root / "compressed.txt",
                                    lz4=str(decoder), crash_marked=False)

            partial_binary = complete_stream(compression=0)[:-105]
            compressed.write_bytes(uncompressed_lz4_frame(partial_binary)
                                   + uncompressed_lz4_frame(b"tail")[:-2])
            with self.assertRaisesRegex(BinaryTraceError, "compression flag"):
                convert_binary_file(compressed, root / "partial.txt",
                                    lz4=str(decoder), crash_marked=True)

    def test_sidecar_parser_is_bounded_and_strict_about_unknown_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "run.trace.bin"
            source.write_bytes(raw_stream())
            sidecar = Path(str(source) + ".metrics")
            sidecar.write_bytes(b"x" * (64 * 1024 + 1))
            with self.assertRaisesRegex(BinaryTraceError, "sidecar.*limit"):
                convert_binary_file(source, root / "large.txt", lz4=None,
                                    crash_marked=False)
            sidecar.write_text(
                metrics_sidecar(source).replace("effective_buffer_bytes=4096", "mystery=1"),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(BinaryTraceError, "unknown metrics sidecar key"):
                convert_binary_file(source, root / "unknown.txt", lz4=None,
                                    crash_marked=False)

            sidecar.write_text(
                metrics_sidecar(source).replace(
                    "effective_buffer_bytes=4096\n", ""
                ) + "profile=full\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(BinaryTraceError, "duplicate metrics sidecar key"):
                convert_binary_file(source, root / "duplicate.txt", lz4=None,
                                    crash_marked=False)

            missing = metrics_sidecar(source).replace("producer_wait_ns=0\n", "")
            sidecar.write_text(missing, encoding="utf-8")
            with self.assertRaisesRegex(BinaryTraceError, "sidecar is missing producer_wait_ns"):
                convert_binary_file(source, root / "missing.txt", lz4=None,
                                    crash_marked=False)

            optional = (
                "instructions_per_second=0.000000\n"
                "encoded_bytes_per_second=0.000000\n"
                "disk_bytes_per_second=0.000000\n"
                "compression_ratio=0.000000\n"
                "cache_hit_rate=0.000000\n"
            )
            sidecar.write_text(
                metrics_sidecar(source, optional + "profile=full\n"), encoding="utf-8"
            )
            with self.assertRaisesRegex(BinaryTraceError, "field count limit"):
                convert_binary_file(source, root / "fields.txt", lz4=None,
                                    crash_marked=False)

            sidecar.write_text(
                metrics_sidecar(source).replace("cache_hit_rate=0.900000",
                                                "cache_hit_rate=garbage"),
                encoding="utf-8"
            )
            with self.assertRaisesRegex(BinaryTraceError, "invalid.*cache_hit_rate"):
                convert_binary_file(source, root / "rate.txt", lz4=None,
                                    crash_marked=False)

    def test_rejects_stopped_sidecar_with_terminal_counter_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            decoder = fake_lz4_executable(root)
            source = root / "stopped.trace.bin.lz4"
            binary = bytearray(stopped_stream())
            struct.pack_into("<Q", binary, len(binary) - 64, len(uncompressed_lz4_frame(binary)))
            source.write_bytes(uncompressed_lz4_frame(binary))
            Path(str(source) + ".metrics").write_text(
                metrics_sidecar(
                    source, termination="stopped", return_valid=0, return_value="0x0",
                    instructions=2,
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(BinaryTraceError, "sidecar mismatch.*instructions"):
                convert_binary_file(source, root / "out.txt", lz4=str(decoder), crash_marked=False)

    def test_many_frame_compressed_conversion_has_frame_count_independent_memory(self):
        class FakeStdin:
            def __init__(self, output):
                self.output = output
                self.data = bytearray()

            def write(self, data):
                self.data.extend(data)
                return len(data)

            def close(self):
                data = self.data
                position = 0
                while position < len(data):
                    position += 7
                    size = int.from_bytes(data[position:position + 4], "little")
                    position += 4
                    self.output.write(data[position:position + (size & 0x7FFFFFFF)])
                    position += size & 0x7FFFFFFF
                    position += 4

        class FakeProcess:
            def __init__(self, output):
                self.stdin = FakeStdin(output)
                self.stderr = io.BytesIO()

            def poll(self):
                return None

            def terminate(self):
                pass

            def wait(self):
                return 0

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "lz4"
            executable.write_text("#!/bin/sh\n", encoding="utf-8")
            executable.chmod(0o755)
            empty = uncompressed_lz4_frame(b"")
            probe = complete_stream()
            artifact_size = len(uncompressed_lz4_frame(probe)) + 50000 * len(empty)
            binary = complete_stream(compressed_bytes=artifact_size)
            artifact = uncompressed_lz4_frame(binary) + empty * 50000
            source = root / "many.trace.bin.lz4"
            source.write_bytes(artifact)
            destination = root / "many.trace.txt"

            def popen(_command, **kwargs):
                return FakeProcess(kwargs["stdout"])

            tracemalloc.start()
            try:
                original_popen = lz4_frames.subprocess.Popen
                lz4_frames.subprocess.Popen = popen
                try:
                    convert_binary_file(source, destination, lz4=str(executable),
                                        crash_marked=False)
                finally:
                    lz4_frames.subprocess.Popen = original_popen
                _, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
            self.assertLess(peak, 4 * 1024 * 1024)

    def test_cli_exit_codes_publication_and_actual_partial_naming(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            decoder = fake_lz4_executable(root)
            stdout = io.StringIO()
            stderr = io.StringIO()

            raw = root / "success.trace.bin"
            raw.write_bytes(raw_stream())
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(0, main([str(raw)]))
            self.assertTrue((root / "success.trace.txt").exists())

            broken = root / "broken.trace.bin"
            broken.write_bytes(b"bad")
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(1, main([str(broken)]))
            self.assertFalse((root / "broken.trace.txt").exists())

            complete = root / "complete.trace.bin.lz4"
            complete.write_bytes(compressed_artifact())
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(0, main([
                    str(complete), "--lz4", str(decoder), "--crash-marked"
                ]))
            self.assertTrue((root / "complete.trace.txt").exists())
            self.assertFalse((root / "complete.partial.trace.txt").exists())

            partial_binary = complete_stream()[:-105]
            partial = root / "partial.trace.bin.lz4"
            partial.write_bytes(uncompressed_lz4_frame(partial_binary)
                                + uncompressed_lz4_frame(b"tail")[:-2])
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(2, main([
                    str(partial), "--lz4", str(decoder), "--crash-marked"
                ]))
            self.assertTrue((root / "partial.partial.trace.txt").exists())
            self.assertFalse((root / "partial.trace.txt").exists())

    def test_cli_subprocess_returns_success_error_and_partial_statuses(self):
        repository = Path(__file__).resolve().parents[2]
        script = repository / "scripts/trace_convert.py"
        environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            decoder = fake_lz4_executable(root)
            raw = root / "success.trace.bin"
            raw.write_bytes(raw_stream())
            success = subprocess.run(
                [sys.executable, str(script), str(raw)], cwd=repository, env=environment,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
            )
            self.assertEqual(0, success.returncode, success.stderr)
            self.assertTrue((root / "success.trace.txt").exists())

            broken = root / "broken.trace.bin"
            broken.write_bytes(b"bad")
            failure = subprocess.run(
                [sys.executable, str(script), str(broken)], cwd=repository, env=environment,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
            )
            self.assertEqual(1, failure.returncode)
            self.assertFalse((root / "broken.trace.txt").exists())

            partial_binary = complete_stream()[:-105]
            partial = root / "partial.trace.bin.lz4"
            partial.write_bytes(uncompressed_lz4_frame(partial_binary)
                                + uncompressed_lz4_frame(b"tail")[:-2])
            recovered = subprocess.run(
                [sys.executable, str(script), str(partial), "--lz4", str(decoder),
                 "--crash-marked"],
                cwd=repository, env=environment, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, check=False,
            )
            self.assertEqual(2, recovered.returncode, recovered.stderr)
            self.assertTrue((root / "partial.partial.trace.txt").exists())

    def test_cli_normalizes_missing_and_unreadable_prescan_failures(self):
        repository = Path(__file__).resolve().parents[2]
        script = repository / "scripts/trace_convert.py"
        environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = (
                ([str(root / "missing.trace.bin.lz4"), "--crash-marked"], "missing"),
                ([str(root / "missing-explicit.trace.bin.lz4"), "--crash-marked",
                  "--output", str(root / "explicit.txt")], "explicit"),
                ([str(root / "missing.trace.bin")], "raw"),
            )
            unreadable = root / "unreadable.trace.bin.lz4"
            unreadable.mkdir()
            cases += (([str(unreadable), "--crash-marked"], "unreadable"),)

            for arguments, label in cases:
                with self.subTest(label=label):
                    completed = subprocess.run(
                        [sys.executable, str(script), *arguments], cwd=repository,
                        env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        text=True, check=False,
                    )
                    self.assertEqual(1, completed.returncode)
                    self.assertTrue(completed.stderr.startswith("trace_convert: "))
                    self.assertNotIn("Traceback", completed.stderr)
            self.assertFalse((root / "explicit.txt").exists())
            self.assertEqual([], list(root.glob(".trace-convert-*")))

    def test_main_normalizes_prescan_permission_error(self):
        stderr = io.StringIO()
        with patch.object(trace_convert, "scan_lz4_file",
                          side_effect=PermissionError("permission denied")):
            with contextlib.redirect_stderr(stderr):
                status = main(["denied.trace.bin.lz4", "--crash-marked"])
        self.assertEqual(1, status)
        self.assertTrue(stderr.getvalue().startswith("trace_convert: "))
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_publication_fsyncs_directory_after_destination_exists(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "run.trace.bin"
            destination = root / "run.trace.txt"
            source.write_bytes(raw_stream())
            observations = []

            def observe(path):
                observations.append((path, destination.exists()))

            with patch.object(trace_convert, "_fsync_directory", side_effect=observe):
                convert_binary_file(source, destination, lz4=None, crash_marked=False)
            self.assertEqual([(root, True)], observations)

    def test_temporary_path_cleans_created_file_when_close_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real_close = os.close

            def close_then_fail(descriptor):
                real_close(descriptor)
                raise OSError("close failed")

            with patch.object(trace_convert.os, "close", side_effect=close_then_fail):
                with self.assertRaisesRegex(OSError, "close failed"):
                    trace_convert._temporary_path(root, ".tmp")
            self.assertEqual([], list(root.glob(".trace-convert-*")))


if __name__ == "__main__":
    unittest.main()
