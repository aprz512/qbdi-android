import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from qtrace.report import SessionReport


ROOT = Path(__file__).parents[2]
EXPORTER = ROOT / "qtrace-ui" / "tools" / "export_contract_fixtures.py"
ORACLE = ROOT / "qtrace-ui" / "tools" / "oracle.py"
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
        self.assertEqual(1, document["generator_schema"])
        entries = document["fixtures"]
        self.assertEqual(EXPECTED_CLASSES, {entry["expected"]["class"] for entry in entries})

        described = set()
        for entry in entries:
            self.assertEqual(1, entry["generator_schema"])
            self.assertEqual(
                {"path", "sha256", "bytes", "format", "version", "expected",
                 "generator_schema"},
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

    def test_session_reports_match_the_current_schema(self):
        reports = sorted((FIXTURES / "sessions").glob("*/report.json"))
        self.assertEqual(3, len(reports))
        for path in reports:
            with self.subTest(session=path.parent.name):
                SessionReport(**json.loads(path.read_text(encoding="utf-8")))

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
