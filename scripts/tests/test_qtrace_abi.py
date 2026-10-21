import copy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from qtrace.abi import REQUIRED_CHECKS, require_abi_acceptance, require_abi_deployment
from qtrace.cli import build_parser
from qtrace.errors import QtraceError


class Device:
    serial = "device-1"
    properties = {"ro.build.fingerprint": "test-fingerprint", "ro.product.cpu.abi": "arm64-v8a",
                  "ro.build.version.sdk": "36"}

    def shell(self, *arguments, **options):
        assert arguments[0] == "getprop"
        return (self.properties[arguments[1]] + "\n").encode()


class AbiReportTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.path = root / "report.json"
        self.artifacts = SimpleNamespace(tracer_so=root / "tracer.so", companion=root / "companion.so")
        self.artifacts.tracer_so.write_bytes(b"tracer")
        self.artifacts.companion.write_bytes(b"companion")
        self.report = {
            "schema_version": 1, "result": "pass", "cleanup": True, "process_exit_code": 0,
            "session_id": "123e4567-e89b-42d3-a456-426614174000",
            "checks": {name: True for name in REQUIRED_CHECKS},
            "device": {"serial": "device-1", "fingerprint": "test-fingerprint", "abi": "arm64-v8a", "sdk": "36"},
            "artifacts": {"libqbdi_tracer.so": hashlib.sha256(b"tracer").hexdigest(),
                          "libshadowhook_nothing.so": hashlib.sha256(b"companion").hexdigest()},
        }

    def validate(self, report=None, device=None):
        self.path.write_text(json.dumps(self.report if report is None else report))
        return require_abi_acceptance(self.path, device or Device(), self.artifacts, timeout=1)

    def test_accepts_only_the_attested_device_and_both_artifact_hashes(self):
        receipt = self.validate()
        self.assertEqual(self.report["artifacts"], receipt["artifacts"])
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).hexdigest(), receipt["report_sha256"])
        self.artifacts.tracer_so.write_bytes(b"different build")
        with self.assertRaisesRegex(QtraceError, "SHA-256 differs: libqbdi_tracer.so"):
            self.validate()

    def test_failed_unavailable_missing_checks_or_unfinished_cleanup_are_rejected(self):
        cases = [{"result": "fail"}, {"result": "unavailable"}, {"cleanup": False},
                 {"schema_version": True}, {"process_exit_code": 1}, {"process_exit_code": False},
                 {"checks": {}}, {"checks": {name: 1 for name in REQUIRED_CHECKS}},
                 {"checks": {**self.report["checks"], "platform_register": False}}]
        for change in cases:
            with self.subTest(change=change), self.assertRaises(QtraceError) as caught:
                self.validate({**self.report, **change})
            self.assertEqual("tracer.abi_rejected", caught.exception.code)

    def test_other_device_or_changed_firmware_is_rejected(self):
        for key, value in [("serial", "another-device"), ("fingerprint", "new-build"),
                           ("sdk", "35"), ("abi", "armeabi-v7a")]:
            report = copy.deepcopy(self.report)
            report["device"][key] = value
            with self.subTest(key=key), self.assertRaises(QtraceError):
                self.validate(report)

    def test_reports_without_fixed_floating_evidence_are_rejected(self):
        for check in ("fixed_floating_argument_text", "fixed_floating_return_text"):
            for value in (None, False):
                report = copy.deepcopy(self.report)
                if value is None:
                    report["checks"].pop(check)
                else:
                    report["checks"][check] = value
                with self.subTest(check=check, value=value), self.assertRaises(QtraceError) as caught:
                    self.validate(report)
                self.assertEqual("tracer.abi_rejected", caught.exception.code)

    def test_report_unavailability_duplicate_keys_and_excessive_size_are_rejected(self):
        for raw in (b'{"result":"fail","result":"pass"}', b" " * (1024 * 1024 + 1)):
            self.path.write_bytes(raw)
            with self.assertRaises(QtraceError):
                require_abi_acceptance(self.path, Device(), self.artifacts, timeout=1)
        self.path.unlink()
        with self.assertRaises(QtraceError):
            require_abi_acceptance(self.path, Device(), self.artifacts, timeout=1)

    def test_deployment_replacement_is_rejected_before_injection(self):
        receipt = self.validate()
        deployment = SimpleNamespace(tracer_so="/remote/tracer.so", companion="/remote/companion.so",
                                     sha256={"/remote/tracer.so": receipt["artifacts"]["libqbdi_tracer.so"],
                                             "/remote/companion.so": receipt["artifacts"]["libshadowhook_nothing.so"]})
        require_abi_deployment(receipt, deployment)
        deployment.sha256["/remote/tracer.so"] = hashlib.sha256(b"replaced").hexdigest()
        with self.assertRaisesRegex(QtraceError, "deployed artifact differs"):
            require_abi_deployment(receipt, deployment)

    def test_cli_exposes_gate_for_timed_and_monitored_sessions(self):
        for command in [("run", "--duration", "1s"), ("monitor",)]:
            parsed = build_parser().parse_args([*command, "--config", "target.json", "--abi-report", "report.json"])
            self.assertEqual(Path("report.json"), parsed.abi_report)


if __name__ == "__main__":
    unittest.main()
