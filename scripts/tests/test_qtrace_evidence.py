import json
import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import qtrace_evidence as evidence
from scripts.qtrace_device_acceptance import (
    HISTORICAL_CANONICAL_TARGET_SHA256, HISTORICAL_COMMIT,
    _SUCCESS_MANIFEST_NAME, _SUCCESS_REPORT_DIRECTORIES,
)


RUN = "11111111-1111-4111-8111-111111111111"


class EvidenceTests(unittest.TestCase):
    def _success(self, workspace):
        run = workspace / "qtrace-acceptance-evidence" / RUN
        run.mkdir(parents=True)
        reports = {label: f"{directory}/{RUN}/report.json"
                   for label, directory in _SUCCESS_REPORT_DIRECTORIES.items()}
        for relative in reports.values():
            path = run / relative
            path.parent.mkdir(parents=True)
            path.write_text("{}", encoding="utf-8")
        document = {
            "schema": 1, "status": "passed", "exit_code": 0,
            "head_commit": "a" * 40, "device": "SERIAL",
            "started_at": "2026-10-19T00:00:00.000Z",
            "completed_at": "2026-10-19T00:01:00.000Z",
            "historical_commit": HISTORICAL_COMMIT,
            "target_canonical_sha256": HISTORICAL_CANONICAL_TARGET_SHA256,
            **{key: "b" * 64 for key in (
                "target_raw_sha256", "historical_apk_sha256", "current_apk_sha256",
                "tracer_sha256", "companion_sha256")},
            "scenario_reports": reports, "trace_backup_existed": False,
            "trace_backup_path": None,
        }
        (run / _SUCCESS_MANIFEST_NAME).write_text(json.dumps(document), encoding="utf-8")
        return run

    def _record(self, workspace):
        return evidence.inventory(workspace)["roots"][0]["runs"][0]

    def test_inventory_does_not_create_missing_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            result = evidence.inventory(workspace)
            self.assertEqual(["absent", "absent"], [root["status"] for root in result["roots"]])
            self.assertEqual([], list(workspace.iterdir()))

    def test_cli_requires_both_review_identity_and_explicit_apply(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            run = self._success(workspace)
            digest = self._record(workspace)["inventory_sha256"]
            for flags in (("--apply",), ("--delete-success", RUN),
                          ("--inventory-sha256", digest)):
                with self.subTest(flags=flags), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as caught:
                        evidence.main(["--workspace", temporary, *flags])
                    self.assertEqual(2, caught.exception.code)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(0, evidence.main([
                    "--workspace", temporary, "--delete-success", RUN,
                    "--inventory-sha256", digest]))
            self.assertEqual("preview", json.loads(output.getvalue())["action"])
            self.assertTrue(run.is_dir())

    def test_default_inventory_and_cleanup_preview_leave_every_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            run = self._success(workspace)
            before = {str(path): path.lstat() for path in workspace.rglob("*")}
            record = self._record(workspace)
            self.assertEqual("successful", record["status"])
            result = evidence.cleanup(workspace, RUN, record["inventory_sha256"])
            self.assertEqual("preview", result["action"])
            after = {str(path): path.lstat() for path in workspace.rglob("*")}
            self.assertEqual(before.keys(), after.keys())
            for name in before:
                self.assertEqual((before[name].st_ino, before[name].st_mtime_ns),
                                 (after[name].st_ino, after[name].st_mtime_ns))
            self.assertTrue(run.is_dir())

    def test_explicit_cleanup_deletes_only_the_reviewed_successful_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            run = self._success(workspace)
            failure = workspace / "qtrace-acceptance-failures" / RUN
            failure.mkdir(parents=True)
            (failure / "evidence").write_text("failure survives", encoding="utf-8")
            record = self._record(workspace)
            result = evidence.cleanup(workspace, RUN, record["inventory_sha256"], apply=True)
            self.assertEqual("deleted", result["action"])
            self.assertFalse(run.exists())
            self.assertEqual("failure survives", (failure / "evidence").read_text())

    def test_failure_marker_unknown_runs_and_links_are_protected(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            run = self._success(workspace)
            (run / "historical-benchmark-gate.json").write_text("{}")
            self.assertEqual("protected", self._record(workspace)["status"])
            (run / "historical-benchmark-gate.json").unlink()
            (run / "outside-link").symlink_to(workspace)
            self.assertEqual("protected", self._record(workspace)["status"])
            with self.assertRaises(ValueError):
                evidence.cleanup(workspace, RUN, "0" * 64, apply=True)
            self.assertTrue(run.is_dir())

    def test_stale_inventory_and_root_symlink_refuse_deletion(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            run = self._success(workspace)
            digest = self._record(workspace)["inventory_sha256"]
            (run / "late-evidence").write_text("keep")
            with self.assertRaisesRegex(ValueError, "inventory changed"):
                evidence.cleanup(workspace, RUN, digest, apply=True)
            root = run.parent
            root.rename(workspace / "kept")
            root.symlink_to(workspace / "kept")
            with self.assertRaises(OSError):
                evidence.cleanup(workspace, RUN, digest, apply=True)
            self.assertTrue((workspace / "kept" / RUN / "late-evidence").is_file())

    def test_quarantine_replacement_preserves_both_owned_and_untrusted_trees(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            run = self._success(workspace)
            digest = self._record(workspace)["inventory_sha256"]
            rename = evidence._rename_noreplace

            def replace_before_rename(parent, source, destination):
                os.rename(source, "kept-original", src_dir_fd=parent, dst_dir_fd=parent)
                os.mkdir(source, dir_fd=parent)
                (run / "unknown").write_text("must survive")
                rename(parent, source, destination)

            with patch.object(evidence, "_rename_noreplace", side_effect=replace_before_rename):
                with self.assertRaisesRegex(ValueError, "changed evidence retained"):
                    evidence.cleanup(workspace, RUN, digest, apply=True)
            self.assertTrue((run.parent / "kept-original" / _SUCCESS_MANIFEST_NAME).exists())
            quarantined = list(run.parent.glob(".qtrace-cleanup-*"))
            self.assertEqual(1, len(quarantined))
            self.assertEqual("must survive", (quarantined[0] / "unknown").read_text())
