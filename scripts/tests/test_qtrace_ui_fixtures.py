import hashlib
import io
import json
from pathlib import Path
import subprocess
import struct
import sys
import tempfile
import unittest

from qtrace.report import SessionReport
from scripts.flight_trace import FlightTraceError, recover_flight
from scripts.trace_binary import BinaryTraceError, convert_binary_stream


ROOT = Path(__file__).parents[2]
EXPORTER = ROOT / "qtrace-ui" / "tools" / "export_contract_fixtures.py"
ORACLE = ROOT / "qtrace-ui" / "tools" / "oracle.py"
GENERATED_CHECK = ROOT / "qtrace-ui" / "tools" / "check_generated.py"
FIXTURES = ROOT / "qtrace-ui" / "fixtures"


EXPECTED_CLASSES = {
    "elf.aarch64-symbols",
    "flight.v2-active-chunk",
    "flight.v2-checksum-damaged-sealed",
    "flight.v2-complete",
    "flight.v2-coverage-gap",
    "flight.v2-incomplete-fragment",
    "flight.v2-overwritten-range",
    "flight.v2-stale-directory",
    "json.session-support",
    "qtrb.malformed-bad-header",
    "qtrb.malformed-oversized-record",
    "qtrb.malformed-record-after-terminal",
    "qtrb.malformed-sequence-gap",
    "qtrb.malformed-truncated-payload",
    "qtrb.malformed-undefined-metadata",
    "qtrb.malformed-unsupported-feature",
    "qtrb.v1.0-completed",
    "qtrb.v1.1-chunked-rule-error",
    "qtrb.v1.2-completed",
    "qtrb.v1.2-partial",
    "qtrb.v1.2-stopped",
    "session.one-invalid-artifact",
    "session.path-escape",
    "session.valid-mixed",
}


class QtraceUiFixtureTests(unittest.TestCase):
    def run_tool(self, *arguments: str, timeout: int = 10) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, *arguments],
            capture_output=True,
            cwd=ROOT,
            timeout=timeout,
            check=False,
        )

    def test_manifest_matches_every_generated_fixture(self):
        completed = self.run_tool(str(EXPORTER), "--check")
        self.assertEqual(0, completed.returncode, completed.stderr.decode())

    def test_all_checked_in_generated_outputs_are_current(self):
        completed = self.run_tool(str(GENERATED_CHECK), timeout=120)
        self.assertEqual(0, completed.returncode, completed.stderr.decode())

    def test_check_detects_fixture_byte_drift(self):
        fixture = FIXTURES / "qtrb" / "v1.2-completed.bin"
        original = fixture.read_bytes()
        try:
            fixture.write_bytes(original + b"drift")
            completed = self.run_tool(str(EXPORTER), "--check")
        finally:
            fixture.write_bytes(original)
        self.assertNotEqual(0, completed.returncode)
        self.assertIn(b"v1.2-completed.bin", completed.stderr)

    def test_manifest_covers_the_complete_bounded_corpus(self):
        document = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(2, document["generator_schema"])
        entries = document["fixtures"]
        self.assertEqual(EXPECTED_CLASSES, {entry["expected"]["class"] for entry in entries})

        described = set()
        for entry in entries:
            self.assertEqual(2, entry["generator_schema"])
            self.assertEqual(
                {"path", "sha256", "bytes", "format", "version", "expected",
                 "role", "session", "generator_schema"},
                set(entry),
            )
            path = FIXTURES / entry["path"]
            data = path.read_bytes()
            self.assertLessEqual(len(data), 4 * 1024 * 1024)
            self.assertEqual(len(data), entry["bytes"])
            self.assertEqual(hashlib.sha256(data).hexdigest(), entry["sha256"])
            described.add(entry["path"])

        actual = {
            path.relative_to(FIXTURES).as_posix()
            for path in FIXTURES.rglob("*")
            if path.is_file() and path.name not in {"README.md", "manifest.json"}
        }
        self.assertEqual(actual, described)

    def test_manifest_describes_session_members_by_native_decoder_outcome(self):
        entries = {
            entry["path"]: entry
            for entry in json.loads(
                (FIXTURES / "manifest.json").read_text(encoding="utf-8")
            )["fixtures"]
        }
        expected_artifacts = {
            "sessions/valid-mixed/artifacts/main.trace.bin":
                ("valid-mixed", "QTRB", "1.2", "success", "qtrb.v1.2-completed"),
            "sessions/valid-mixed/artifacts/worker.trace.bin":
                ("valid-mixed", "QTRB", "1.0", "success", "qtrb.v1.0-completed"),
            "sessions/valid-mixed/artifacts/capture.flight.bin":
                ("valid-mixed", "Flight", "2", "success", "flight.v2-complete"),
            "sessions/one-invalid-artifact/artifacts/good.trace.bin":
                ("one-invalid-artifact", "QTRB", "1.2", "success",
                 "qtrb.v1.2-completed"),
            "sessions/one-invalid-artifact/artifacts/good.flight.bin":
                ("one-invalid-artifact", "Flight", "2", "success", "flight.v2-complete"),
            "sessions/one-invalid-artifact/artifacts/broken.trace.bin":
                ("one-invalid-artifact", "QTRB", "1.2", "error",
                 "qtrb.malformed-truncated-payload"),
        }
        for path, expected in expected_artifacts.items():
            with self.subTest(path=path):
                entry = entries[path]
                data = (FIXTURES / path).read_bytes()
                if data[:4] == b"QTRB":
                    header = struct.unpack_from("<4sBBBBBBHI", data)
                    native_format = "QTRB"
                    native_version = f"{header[1]}.{header[2]}"
                elif data[:4] == b"TLFQ":
                    native_format = "Flight"
                    native_version = str(
                        recover_flight(io.BytesIO(data)).summary["format_version"]
                    )
                else:
                    self.fail(f"unrecognized session artifact magic: {data[:4]!r}")
                self.assertEqual(native_format, entry["format"])
                self.assertEqual(native_version, entry["version"])
                self.assertEqual(
                    ("session-artifact", *expected),
                    (entry.get("role"), entry.get("session"), entry["format"],
                     entry["version"], entry["expected"]["outcome"],
                     entry["expected"]["class"]),
                )
                try:
                    if entry["format"] == "QTRB":
                        convert_binary_stream(io.BytesIO(data), io.StringIO(), allow_partial=True)
                    elif entry["format"] == "Flight":
                        recover_flight(io.BytesIO(data))
                    else:
                        self.fail(f"session artifact has non-native format: {entry['format']}")
                except (BinaryTraceError, FlightTraceError) as error:
                    actual_outcome = "error"
                    actual_error = str(error)
                else:
                    actual_outcome = "success"
                    actual_error = None
                self.assertEqual(actual_outcome, entry["expected"]["outcome"])
                self.assertEqual(actual_error, entry["expected"].get("error"))

        expected_json = {
            "sessions/valid-mixed/report.json":
                ("session-root", "valid-mixed", "SessionReport/1",
                 "success", "session.valid-mixed"),
            "sessions/one-invalid-artifact/report.json":
                ("session-root", "one-invalid-artifact", "SessionReport/1",
                 "success", "session.one-invalid-artifact"),
            "sessions/path-escape/report.json":
                ("session-root", "path-escape", "SessionReport/1",
                 "error", "session.path-escape"),
            "sessions/valid-mixed/session.json":
                ("session-support", "valid-mixed", "session/1",
                 "success", "json.session-support"),
            "sessions/valid-mixed/effective-config.json":
                ("session-support", "valid-mixed", "effective-config/1",
                 "success", "json.session-support"),
            "sessions/valid-mixed/device.json":
                ("session-support", "valid-mixed", "device/1",
                 "success", "json.session-support"),
            "sessions/one-invalid-artifact/session.json":
                ("session-support", "one-invalid-artifact", "session/1",
                 "success", "json.session-support"),
            "sessions/one-invalid-artifact/effective-config.json":
                ("session-support", "one-invalid-artifact", "effective-config/1",
                 "success", "json.session-support"),
            "sessions/one-invalid-artifact/device.json":
                ("session-support", "one-invalid-artifact", "device/1",
                 "success", "json.session-support"),
        }
        for path, expected in expected_json.items():
            with self.subTest(path=path):
                entry = entries[path]
                self.assertEqual(
                    (*expected[:2], "JSON", *expected[2:]),
                    (entry.get("role"), entry.get("session"), entry["format"],
                     entry["version"], entry["expected"]["outcome"],
                     entry["expected"]["class"]),
                )
                json.loads((FIXTURES / path).read_text(encoding="utf-8"))
        self.assertEqual(
            set(expected_artifacts) | set(expected_json),
            {path for path, entry in entries.items() if entry["session"] is not None},
        )

    def test_session_reports_match_the_current_schema(self):
        reports = sorted((FIXTURES / "sessions").glob("*/report.json"))
        self.assertEqual(3, len(reports))
        for path in reports:
            with self.subTest(session=path.parent.name):
                SessionReport(**json.loads(path.read_text(encoding="utf-8")))

    def test_every_qtrb_fixture_preserves_acceptance_and_termination_semantics(self):
        accepted = {
            "qtrb/v1.0-completed.bin": (1, False, "completed", ("MEMORY ", "<not-captured>")),
            "qtrb/v1.1-chunked.bin": (0, False, "completed",
                                        ('RULE name="rule" detail="abc€"',
                                         'ERROR name="rule" detail="€"')),
            "qtrb/v1.2-completed.bin": (1, False, "completed",
                                         ("INST seq=1 ", "MEMORY ", "CALL ", "RULE ",
                                          "ERROR ", "TRACE_END status=completed")),
            "qtrb/v1.2-stopped.bin": (1, False, "stopped",
                                       ("TRACE_END status=stopped",
                                        "reason=duration_elapsed")),
            "qtrb/v1.2-partial.bin": (1, True, None, ("INST seq=1 ",)),
        }
        for path, (instructions, partial, termination, fragments) in accepted.items():
            with self.subTest(path=path):
                output = io.StringIO()
                stats = convert_binary_stream(
                    io.BytesIO((FIXTURES / path).read_bytes()), output, allow_partial=True,
                )
                self.assertEqual(instructions, stats.instructions)
                self.assertEqual(partial, stats.partial)
                self.assertEqual(termination, stats.termination)
                for fragment in fragments:
                    self.assertIn(fragment, output.getvalue())
                self.assertEqual(not partial, "TRACE_END" in output.getvalue())

        rejected = {
            "qtrb/malformed/bad-header.bin": "invalid QTRB magic",
            "qtrb/malformed/unsupported-feature.bin": "unsupported minor/features",
            "qtrb/malformed/undefined-metadata.bin": "undefined instruction metadata",
            "qtrb/malformed/sequence-gap.bin": "instruction sequence gap",
            "qtrb/malformed/oversized-record.bin":
                "record payload exceeds protocol maximum",
            "qtrb/malformed/truncated-payload.bin": "truncated record payload",
            "qtrb/malformed/record-after-terminal.bin": "record after TRACE_END",
        }
        for path, message in rejected.items():
            with self.subTest(path=path), self.assertRaisesRegex(BinaryTraceError, message):
                convert_binary_stream(
                    io.BytesIO((FIXTURES / path).read_bytes()), io.StringIO(),
                    allow_partial=True,
                )

    def test_every_flight_fixture_preserves_recovery_completeness_semantics(self):
        expected = {
            "v2-complete.bin": {
                "complete": True, "retained_sequences": [[1, 30]],
                "active_chunks": [], "threads": {101, 202},
            },
            "v2-active.bin": {
                "complete": True, "retained_sequences": [[1, 3]],
                "active_chunks": [0], "threads": {77},
            },
            "v2-checkpoint-delta.bin": {
                "complete": True, "retained_sequences": [[1, 3]],
                "active_chunks": [0], "threads": {77},
            },
            "v2-overwritten.bin": {
                "complete": True, "retained_sequences": [[5, 7]],
                "lost_sequences": [[1, 4]], "overwritten_sequences": [[1, 4]],
                "threads": {77},
            },
            "v2-coverage-gap.bin": {
                "complete": False, "retained_sequences": [[4, 4]],
                "lost_sequences": [[1, 3]], "coverage_gap_tid": 77,
                "active_chunks": [0], "threads": {77},
            },
            "v2-checksum-damaged.bin": {
                "complete": False, "retained_sequences": [],
                "lost_sequences": [[1, 2]],
                "recovery_damage": ["sealed chunk 0 checksum mismatch"],
                "threads": set(),
            },
            "v2-stale-directory.bin": {
                "complete": False, "retained_sequences": [[1, 2]],
                "stale_directory_entries": [0], "threads": {77},
            },
            "v2-incomplete-fragment.bin": {
                "complete": False, "retained_sequences": [[1, 6]],
                "incomplete_event": {
                    "tid": 77, "kind": "call", "event_id": 9,
                    "missing_fragments": [0], "retained_fragment_sequences": [6],
                },
                "threads": {77},
            },
        }
        for name, contract in expected.items():
            with self.subTest(name=name):
                recovery = recover_flight(io.BytesIO((FIXTURES / "flight" / name).read_bytes()))
                summary = recovery.summary
                self.assertEqual(contract["complete"], summary["complete"])
                self.assertEqual(contract["retained_sequences"], summary["retained_sequences"])
                self.assertEqual(contract["threads"], set(recovery.threads))
                for key in (
                    "active_chunks", "lost_sequences", "overwritten_sequences",
                    "recovery_damage", "stale_directory_entries",
                ):
                    if key in contract:
                        self.assertEqual(contract[key], summary[key])
                if "coverage_gap_tid" in contract:
                    self.assertEqual(
                        contract["coverage_gap_tid"], summary["coverage_gaps"][0]["tid"]
                    )
                if "incomplete_event" in contract:
                    self.assertEqual(
                        [contract["incomplete_event"]], summary["incomplete_logical_events"]
                    )

    def test_session_fixtures_isolate_artifact_failures_and_path_escape(self):
        sessions = FIXTURES / "sessions"

        def load_report(name: str) -> dict[str, object]:
            document = json.loads(
                (sessions / name / "report.json").read_text(encoding="utf-8")
            )
            SessionReport(**document)
            return document

        def is_contained(root: Path, local_path: str) -> bool:
            try:
                (root / local_path).resolve().relative_to(root.resolve())
            except ValueError:
                return False
            return True

        valid = load_report("valid-mixed")
        valid_root = sessions / "valid-mixed"
        self.assertEqual(3, len(valid["artifacts"]))
        for artifact in valid["artifacts"]:
            local_path = artifact["local_path"]
            self.assertTrue(is_contained(valid_root, local_path))
            data = (valid_root / local_path).read_bytes()
            if local_path.endswith(".flight.bin"):
                self.assertTrue(recover_flight(io.BytesIO(data)).summary["complete"])
            else:
                stats = convert_binary_stream(io.BytesIO(data), io.StringIO())
                self.assertEqual("completed", stats.termination)

        isolated = load_report("one-invalid-artifact")
        isolated_root = sessions / "one-invalid-artifact"
        outcomes = {}
        for artifact in isolated["artifacts"]:
            local_path = artifact["local_path"]
            self.assertTrue(is_contained(isolated_root, local_path))
            data = (isolated_root / local_path).read_bytes()
            try:
                if local_path.endswith(".flight.bin"):
                    recover_flight(io.BytesIO(data))
                else:
                    convert_binary_stream(io.BytesIO(data), io.StringIO())
            except (BinaryTraceError, FlightTraceError) as error:
                outcomes[local_path] = str(error)
            else:
                outcomes[local_path] = "success"
        self.assertEqual(
            {
                "artifacts/good.trace.bin": "success",
                "artifacts/good.flight.bin": "success",
                "artifacts/broken.trace.bin": "truncated record payload",
            },
            outcomes,
        )

        escape = load_report("path-escape")
        self.assertEqual(1, len(escape["artifacts"]))
        escaped_path = escape["artifacts"][0]["local_path"]
        self.assertIn("..", Path(escaped_path).parts)
        self.assertFalse(is_contained(sessions / "path-escape", escaped_path))

    def test_elf_fixture_has_aarch64_symbols_and_gnu_build_id_by_wire_layout(self):
        data = (FIXTURES / "elf/minimal-aarch64.elf").read_bytes()
        header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
        ident = header[0]
        self.assertEqual(b"\x7fELF", ident[:4])
        self.assertEqual((2, 1, 1), tuple(ident[4:7]))
        self.assertEqual((3, 183, 1), header[1:4])
        self.assertEqual(64, header[8])
        section_offset, section_size, section_count, names_index = (
            header[6], header[11], header[12], header[13]
        )
        self.assertEqual(64, section_size)
        self.assertEqual((8, 7), (section_count, names_index))
        section_format = "<IIQQQQIIQQ"
        sections = [
            struct.unpack_from(section_format, data, section_offset + index * section_size)
            for index in range(section_count)
        ]
        names_section = sections[names_index]
        names_data = data[names_section[4]:names_section[4] + names_section[5]]

        def string_at(blob: bytes, offset: int) -> str:
            return blob[offset:blob.index(b"\0", offset)].decode("ascii")

        by_name = {string_at(names_data, section[0]): section for section in sections[1:]}
        self.assertIn(".dynsym", by_name)
        self.assertIn(".symtab", by_name)
        self.assertIn(".note.gnu.build-id", by_name)
        for name, section_type, symbol_name in (
            (".dynsym", 11, "dyn_func"),
            (".symtab", 2, "local_func"),
        ):
            section = by_name[name]
            self.assertEqual(section_type, section[1])
            self.assertEqual(24, section[9])
            symbol = struct.unpack_from("<IBBHQQ", data, section[4] + section[9])
            string_section = sections[section[6]]
            strings = data[
                string_section[4]:string_section[4] + string_section[5]
            ]
            self.assertEqual(symbol_name, string_at(strings, symbol[0]))
            self.assertEqual((0x12, 1, 0x1000, 4),
                             (symbol[1], symbol[3], symbol[4], symbol[5]))

        note = by_name[".note.gnu.build-id"]
        self.assertEqual(7, note[1])
        note_data = data[note[4]:note[4] + note[5]]
        name_size, description_size, note_type = struct.unpack_from("<III", note_data)
        self.assertEqual((4, 20, 3), (name_size, description_size, note_type))
        self.assertEqual(b"GNU\0", note_data[12:16])
        self.assertEqual(bytes(range(1, 21)), note_data[16:36])

    def test_oracle_is_bounded_and_rejects_unknown_modes(self):
        completed = self.run_tool(str(ORACLE), "unknown", "missing.bin", timeout=5)
        self.assertNotEqual(completed.returncode, 0)
        self.assertLessEqual(len(completed.stderr), 4096)
        self.assertIn(b"unknown oracle mode", completed.stderr)

    def test_oracles_emit_one_bounded_json_document(self):
        cases = (
            ("qtrb", "qtrb/v1.2-completed.bin", {"lines", "stats"}),
            ("flight", "flight/v2-complete.bin", {"events", "threads", "summary"}),
        )
        for mode, relative, keys in cases:
            with self.subTest(mode=mode):
                completed = self.run_tool(str(ORACLE), mode, str(FIXTURES / relative))
                self.assertEqual(0, completed.returncode, completed.stderr.decode())
                self.assertLessEqual(len(completed.stdout), 16 * 1024 * 1024)
                self.assertEqual(keys, set(json.loads(completed.stdout)))

    def test_complete_flight_fixture_carries_all_representative_evidence(self):
        completed = self.run_tool(
            str(ORACLE), "flight", str(FIXTURES / "flight/v2-complete.bin")
        )
        self.assertEqual(0, completed.returncode, completed.stderr.decode())
        document = json.loads(completed.stdout)
        self.assertEqual({"101", "202"}, set(document["threads"]))
        self.assertEqual(
            {
                "thread_begin", "thread_end", "instruction", "memory", "call", "rule",
                "error", "register_delta", "syscall", "signal", "signal_handler_begin",
                "signal_handler_return", "termination_intent",
            },
            {event["kind"] for event in document["events"]},
        )
        call_event = next(event for event in document["events"] if event["kind"] == "call")
        self.assertEqual([10, 12], call_event["data"]["fragment_sequences"])
        self.assertTrue(document["summary"]["complete"])
        self.assertEqual([[1, 30]], document["summary"]["retained_sequences"])

    def test_oracle_rejects_sources_above_eight_mibibytes(self):
        with tempfile.TemporaryDirectory() as directory:
            oversized = Path(directory) / "oversized.bin"
            with oversized.open("wb") as output:
                output.seek(8 * 1024 * 1024)
                output.write(b"x")
            completed = self.run_tool(str(ORACLE), "qtrb", str(oversized))
        self.assertNotEqual(0, completed.returncode)
        self.assertLessEqual(len(completed.stderr), 4096)
        self.assertIn(b"8 MiB", completed.stderr)

    def test_oracle_rejects_non_regular_sources(self):
        completed = self.run_tool(str(ORACLE), "qtrb", "/dev/null")
        self.assertNotEqual(0, completed.returncode)
        self.assertLessEqual(len(completed.stderr), 4096)
        self.assertIn(b"regular file", completed.stderr)


if __name__ == "__main__":
    unittest.main()
