import signal
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from scripts.pull_trace import (
    AdbArtifactClient,
    EXIT_PARTIAL,
    PullTraceError,
    classify_artifacts,
    main,
    pull_artifact_set,
    select_trace_name,
)


CRASH_MAGIC = 0x51435248


def crash_marker(signal_number=signal.SIGSEGV, tid=1234):
    return (
        CRASH_MAGIC.to_bytes(4, "little")
        + int(signal_number).to_bytes(4, "little", signed=True)
        + int(tid).to_bytes(4, "little", signed=True)
    )


class ArtifactClassificationTests(unittest.TestCase):
    def test_classifies_complete_crashed_and_incomplete_traces(self):
        artifacts = {
            "123_algorithm.trace.txt.lz4": b"",
            "123_algorithm.trace.txt.lz4.metrics": b"instructions=10\n",
            "456_algorithm.trace.txt.lz4": b"",
            "456_algorithm.trace.txt.lz4.crash": crash_marker(),
            "789_algorithm.trace.txt.lz4": b"",
        }

        traces = classify_artifacts(artifacts)

        self.assertEqual("complete", traces["123_algorithm.trace.txt.lz4"].status)
        self.assertEqual("crashed", traces["456_algorithm.trace.txt.lz4"].status)
        self.assertEqual("incomplete", traces["789_algorithm.trace.txt.lz4"].status)

    def test_rejects_nonempty_malformed_crash_markers(self):
        for marker in (b"bad", crash_marker(tid=0), crash_marker(signal_number=1)):
            with self.subTest(marker=marker), self.assertRaises(PullTraceError):
                classify_artifacts({
                    "123_algorithm.trace.txt.lz4": b"",
                    "123_algorithm.trace.txt.lz4.crash": marker,
                })

    def test_empty_crash_marker_is_not_a_crash(self):
        name = "123_algorithm.trace.txt.lz4"
        traces = classify_artifacts({name: b"", name + ".crash": b""})

        self.assertEqual("incomplete", traces[name].status)

    def test_marker_signal_numbers_follow_android_not_the_host_abi(self):
        probe = subprocess.run(
            [
                sys.executable,
                "-c",
                "import importlib, struct, sys, types; "
                "real=importlib.import_module('signal'); fake=types.ModuleType('signal'); "
                "fake.__dict__.update(real.__dict__); fake.SIGBUS=10; sys.modules['signal']=fake; "
                "import scripts.pull_trace as m; "
                "pack=lambda s: struct.pack('<Iii', 0x51435248, s, 1234); "
                "assert all(m.parse_crash_marker(pack(s)).signal == s for s in (4,6,7,8,11)); "
                "\ntry: m.parse_crash_marker(pack(10))\n"
                "except m.PullTraceError: pass\n"
                "else: raise AssertionError('accepted host-only SIGBUS')",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

        self.assertEqual(0, probe.returncode, probe.stderr)


class AdbArtifactClientTests(unittest.TestCase):
    def test_enumerates_and_streams_only_via_exec_out_run_as(self):
        calls = []

        def runner(command, **kwargs):
            calls.append((command, kwargs))
            if command[-2:] == ["-1t", "files/qbdi-traces"]:
                return subprocess.CompletedProcess(
                    command, 0,
                    stdout=b"123_algorithm.trace.txt.lz4\n123_algorithm.trace.txt.lz4.metrics\n",
                    stderr=b"",
                )
            return subprocess.CompletedProcess(command, 0, stdout=b"trace-bytes", stderr=b"")

        client = AdbArtifactClient(
            package="com.aprz.qbdiandroid", device="serial", adb="custom-adb", runner=runner
        )

        self.assertEqual(
            ["123_algorithm.trace.txt.lz4", "123_algorithm.trace.txt.lz4.metrics"],
            client.list_names(),
        )
        self.assertEqual(b"trace-bytes", client.read_file("123_algorithm.trace.txt.lz4"))
        self.assertEqual(
            ["custom-adb", "-s", "serial", "exec-out", "run-as", "com.aprz.qbdiandroid"],
            calls[0][0][:6],
        )
        self.assertEqual("ls", calls[0][0][6])
        self.assertEqual("cat", calls[1][0][6])
        self.assertNotIn("shell", calls[0][0])
        self.assertFalse(calls[0][1].get("shell", False))

    def test_streams_trace_bytes_directly_to_the_supplied_file(self):
        def runner(command, **kwargs):
            kwargs["stdout"].write(b"streamed")
            return subprocess.CompletedProcess(command, 0, stdout=None, stderr=b"")

        client = AdbArtifactClient(package="com.example.app", runner=runner)
        with tempfile.TemporaryFile() as output:
            client.stream_file("123.trace.txt.lz4", output)
            output.seek(0)
            self.assertEqual(b"streamed", output.read())

    def test_rejects_unsafe_package_and_remote_names_before_running_adb(self):
        with self.assertRaises(PullTraceError):
            AdbArtifactClient(package="com.example;id")

        client = AdbArtifactClient(package="com.example.app")
        for name in ("../trace.lz4", "subdir/trace.lz4", "trace\nother"):
            with self.subTest(name=name), self.assertRaises(PullTraceError):
                client.read_file(name)


class PullArtifactTests(unittest.TestCase):
    class FakeClient:
        def __init__(self, files):
            self.files = files
            self.streamed = []

        def read_file(self, name):
            return self.files[name]

        def stream_file(self, name, output):
            self.streamed.append(name)
            output.write(self.files[name])

    def test_pulls_compressed_trace_and_sidecars_without_decompressing(self):
        name = "123_algorithm.trace.txt.lz4"
        files = {name: b"compressed", name + ".metrics": b"instructions=1\n"}
        client = self.FakeClient(files)

        with tempfile.TemporaryDirectory() as directory:
            result = pull_artifact_set(
                client, name, files, Path(directory), compressed_only=True
            )

            self.assertEqual(0, result.exit_code)
            self.assertEqual("complete", result.status)
            self.assertEqual(b"compressed", (Path(directory) / name).read_bytes())
            self.assertEqual(
                b"instructions=1\n", (Path(directory) / (name + ".metrics")).read_bytes()
            )
            self.assertEqual([name], client.streamed)

    def test_never_overwrites_any_possible_output_without_force(self):
        name = "123_algorithm.trace.txt.lz4"
        files = {name: b"new"}
        client = self.FakeClient(files)

        with tempfile.TemporaryDirectory() as directory:
            existing = Path(directory) / "123_algorithm.partial.trace.txt"
            existing.write_bytes(b"keep")

            with self.assertRaisesRegex(PullTraceError, "already exists"):
                pull_artifact_set(client, name, files, Path(directory), lz4="lz4")

            self.assertEqual(b"keep", existing.read_bytes())
            self.assertEqual([], client.streamed)

    def test_force_allows_replacing_existing_compressed_output(self):
        name = "123_algorithm.trace.txt.lz4"
        files = {name: b"new"}
        client = self.FakeClient(files)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / name
            output.write_bytes(b"old")
            result = pull_artifact_set(
                client, name, files, Path(directory), compressed_only=True, force=True
            )

            self.assertEqual(0, result.exit_code)
            self.assertEqual(b"new", output.read_bytes())

    def test_valid_crash_plus_truncation_publishes_partial_with_distinct_exit(self):
        name = "123_algorithm.trace.txt.lz4"
        files = {name: b"truncated", name + ".crash": crash_marker()}
        client = self.FakeClient(files)

        def decoder(source, output, lz4):
            self.assertEqual(b"truncated", source.read_bytes())
            output.write_bytes(b"complete frames only")
            return True

        with tempfile.TemporaryDirectory() as directory:
            result = pull_artifact_set(
                client, name, files, Path(directory), lz4="lz4", decoder=decoder
            )

            self.assertEqual(EXIT_PARTIAL, result.exit_code)
            self.assertEqual("crashed", result.status)
            partial = Path(directory) / "123_algorithm.partial.trace.txt"
            self.assertEqual(b"complete frames only", partial.read_bytes())
            self.assertFalse((Path(directory) / "123_algorithm.trace.txt").exists())

    def test_truncation_without_valid_crash_is_an_error_and_not_partial(self):
        name = "123_algorithm.trace.txt.lz4"
        files = {name: b"truncated"}
        client = self.FakeClient(files)

        def decoder(source, output, lz4):
            output.write_bytes(b"must-not-publish")
            return True

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(PullTraceError, "crash marker"):
                pull_artifact_set(
                    client, name, files, Path(directory), lz4="lz4", decoder=decoder
                )

            self.assertFalse((Path(directory) / "123_algorithm.partial.trace.txt").exists())

    def test_empty_compressed_artifact_never_publishes_text(self):
        name = "123_algorithm.trace.txt.lz4"
        files = {name: b"", name + ".crash": crash_marker()}
        client = self.FakeClient(files)

        with tempfile.TemporaryDirectory() as directory:
            missing_cli = str(Path(directory) / "fake-lz4")
            Path(missing_cli).write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            Path(missing_cli).chmod(0o755)
            with self.assertRaisesRegex(PullTraceError, "no complete LZ4 frame"):
                pull_artifact_set(
                    client, name, files, Path(directory), lz4=missing_cli
                )

            self.assertFalse((Path(directory) / "123_algorithm.trace.txt").exists())
            self.assertFalse((Path(directory) / "123_algorithm.partial.trace.txt").exists())


class CommandLineTests(unittest.TestCase):
    def test_selects_latest_trace_or_an_explicit_existing_name(self):
        names = [
            "new.trace.txt.lz4.metrics",
            "new.trace.txt.lz4",
            "old.trace.txt.lz4",
        ]

        self.assertEqual("new.trace.txt.lz4", select_trace_name(names))
        self.assertEqual("old.trace.txt.lz4", select_trace_name(names, "old.trace.txt.lz4"))
        with self.assertRaisesRegex(PullTraceError, "does not exist"):
            select_trace_name(names, "missing.trace.txt.lz4")

    def test_compressed_only_cli_reports_outputs_and_returns_success(self):
        name = "new.trace.txt.lz4"
        client = PullArtifactTests.FakeClient({name: b"compressed"})
        client.list_names = lambda: [name]
        stdout = StringIO()
        stderr = StringIO()
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = main(
                ["--package", "com.example.app", "--output", directory, "--compressed-only"],
                client_factory=lambda **kwargs: client,
            )

        self.assertEqual(0, exit_code)
        self.assertIn("status=incomplete", stdout.getvalue())
        self.assertIn(name, stdout.getvalue())
        self.assertEqual("", stderr.getvalue())

    def test_cli_clearly_reports_missing_lz4(self):
        name = "new.trace.txt.lz4"
        client = PullArtifactTests.FakeClient({name: b"compressed"})
        client.list_names = lambda: [name]
        stderr = StringIO()
        with tempfile.TemporaryDirectory() as directory, redirect_stderr(stderr):
            exit_code = main(
                ["--package", "com.example.app", "--output", directory],
                client_factory=lambda **kwargs: client,
                lz4_finder=lambda command: None,
            )

        self.assertEqual(1, exit_code)
        self.assertIn("host lz4 CLI is required", stderr.getvalue())
        self.assertIn("--compressed-only", stderr.getvalue())

    def test_cli_translates_local_filesystem_errors_without_a_traceback(self):
        name = "new.trace.txt.lz4"
        client = PullArtifactTests.FakeClient({name: b"compressed"})
        client.list_names = lambda: [name]
        stderr = StringIO()
        with tempfile.TemporaryDirectory() as directory:
            output_file = Path(directory) / "not-a-directory"
            output_file.write_bytes(b"occupied")
            with redirect_stderr(stderr):
                exit_code = main(
                    [
                        "--package", "com.example.app", "--output", str(output_file),
                        "--compressed-only",
                    ],
                    client_factory=lambda **kwargs: client,
                )

        self.assertEqual(1, exit_code)
        self.assertIn("local filesystem", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
