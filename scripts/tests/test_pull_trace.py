import signal
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import scripts.pull_trace as pull_trace

from scripts.pull_trace import (
    AdbArtifactClient,
    EXIT_PARTIAL,
    PullTraceError,
    classify_artifacts,
    decode_lz4_file,
    decode_lz4_frames,
    main,
    pull_artifact_set,
    scan_lz4_file,
    select_trace_name,
    split_lz4_frames,
)


CRASH_MAGIC = 0x51435248


def crash_marker(signal_number=signal.SIGSEGV, tid=1234):
    return (
        CRASH_MAGIC.to_bytes(4, "little")
        + int(signal_number).to_bytes(4, "little", signed=True)
        + int(tid).to_bytes(4, "little", signed=True)
    )


def uncompressed_lz4_frame(payload):
    # The frame scanner owns framing, while a fake external decoder owns payload semantics.
    return (
        b"\x04\x22\x4d\x18"  # standard frame magic
        + b"\x60\x40\x00"  # v1, independent blocks, 64 KiB maximum, header checksum
        + (len(payload) | 0x80000000).to_bytes(4, "little")
        + payload
        + b"\x00\x00\x00\x00"
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


class Lz4FrameTests(unittest.TestCase):
    def test_splits_and_decodes_concatenated_frames_in_order(self):
        first = uncompressed_lz4_frame(b"first")
        second = uncompressed_lz4_frame(b"second")
        decoded_inputs = []

        def runner(command, **kwargs):
            decoded_inputs.append(kwargs["input"])
            frame = kwargs["input"]
            payload_size = int.from_bytes(frame[7:11], "little") & 0x7FFFFFFF
            return subprocess.CompletedProcess(
                command, 0, stdout=frame[11:11 + payload_size], stderr=b""
            )

        scan = split_lz4_frames(first + second)
        result = decode_lz4_frames(first + second, lz4="test-lz4", runner=runner)

        self.assertEqual((first, second), scan.frames)
        self.assertFalse(scan.truncated)
        self.assertEqual(b"firstsecond", result.data)
        self.assertFalse(result.truncated)
        self.assertEqual([first, second], decoded_inputs)

    def test_truncated_final_frame_preserves_only_prior_complete_frames(self):
        complete = uncompressed_lz4_frame(b"complete")
        truncated = uncompressed_lz4_frame(b"must-not-leak")[:-5]

        def runner(command, **kwargs):
            frame = kwargs["input"]
            payload_size = int.from_bytes(frame[7:11], "little") & 0x7FFFFFFF
            return subprocess.CompletedProcess(
                command, 0, stdout=frame[11:11 + payload_size], stderr=b""
            )

        result = decode_lz4_frames(complete + truncated, lz4="test-lz4", runner=runner)

        self.assertEqual(b"complete", result.data)
        self.assertTrue(result.truncated)

    def test_rejects_corrupt_frame_and_decoder_failure(self):
        with self.assertRaisesRegex(PullTraceError, "magic"):
            split_lz4_frames(b"not-lz4")

        frame = uncompressed_lz4_frame(b"payload")

        def failing_runner(command, **kwargs):
            return subprocess.CompletedProcess(command, 1, stdout=b"", stderr=b"bad frame")

        with self.assertRaisesRegex(PullTraceError, "lz4 decompression failed"):
            decode_lz4_frames(frame, lz4="test-lz4", runner=failing_runner)

    def test_memory_and_file_scanners_accept_zero_byte_raw_block_with_checksum(self):
        frame = (
            b"\x04\x22\x4d\x18"
            + b"\x70\x40\x00"  # independent blocks plus block checksum
            + b"\x00\x00\x00\x80"  # legal zero-byte raw block
            + b"\x12\x34\x56\x78"  # block checksum extent
            + b"\x00\x00\x00\x00"
        )

        self.assertEqual((frame,), split_lz4_frames(frame).frames)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "zero-raw.lz4"
            path.write_bytes(frame)
            self.assertEqual(((0, len(frame)),), scan_lz4_file(path).ranges)

    def test_empty_or_first_frame_truncated_stream_has_no_recoverable_frame(self):
        for data in (b"", b"\x04\x22"):
            with self.subTest(data=data), self.assertRaisesRegex(
                PullTraceError, "no complete LZ4 frame"
            ):
                split_lz4_frames(data)
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "empty.lz4"
                path.write_bytes(data)
                with self.assertRaisesRegex(PullTraceError, "no complete LZ4 frame"):
                    scan_lz4_file(path)

    def test_file_decoder_streams_each_complete_frame_to_cli(self):
        first = uncompressed_lz4_frame(b"first")
        second = uncompressed_lz4_frame(b"second")
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            decoder = directory_path / "fake-lz4"
            decoder.write_text(
                "#!/usr/bin/env python3\n"
                "import sys\n"
                "frame = sys.stdin.buffer.read()\n"
                "size = int.from_bytes(frame[7:11], 'little') & 0x7fffffff\n"
                "sys.stdout.buffer.write(frame[11:11 + size])\n",
                encoding="utf-8",
            )
            decoder.chmod(0o755)
            source = directory_path / "trace.lz4"
            output = directory_path / "trace.txt"
            source.write_bytes(first + second)

            truncated = decode_lz4_file(source, output, str(decoder))

            self.assertFalse(truncated)
            self.assertEqual(b"firstsecond", output.read_bytes())

    def test_file_decoder_omits_a_truncated_tail_and_reports_missing_cli(self):
        first = uncompressed_lz4_frame(b"first")
        tail = uncompressed_lz4_frame(b"second")[:-2]
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            decoder = directory_path / "fake-lz4"
            decoder.write_text(
                "#!/usr/bin/env python3\n"
                "import sys\n"
                "frame = sys.stdin.buffer.read()\n"
                "size = int.from_bytes(frame[7:11], 'little') & 0x7fffffff\n"
                "sys.stdout.buffer.write(frame[11:11 + size])\n",
                encoding="utf-8",
            )
            decoder.chmod(0o755)
            source = directory_path / "trace.lz4"
            output = directory_path / "trace.txt"
            source.write_bytes(first + tail)

            self.assertTrue(decode_lz4_file(source, output, str(decoder)))
            self.assertEqual(b"first", output.read_bytes())
            with self.assertRaisesRegex(PullTraceError, "host lz4 CLI"):
                decode_lz4_file(source, output, str(directory_path / "missing-lz4"))

    def test_file_decoder_terminates_and_reaps_started_process_on_stream_exception(self):
        class FailingStdin:
            def write(self, _data):
                raise OSError("write exploded")

            def close(self):
                pass

        class FakeStderr:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return b""

        class FakeProcess:
            def __init__(self):
                self.stdin = FailingStdin()
                self.stderr = FakeStderr()
                self.terminate_calls = 0
                self.wait_calls = 0

            def poll(self):
                return None

            def terminate(self):
                self.terminate_calls += 1

            def wait(self):
                self.wait_calls += 1
                return 0

        frame = uncompressed_lz4_frame(b"payload")
        process = FakeProcess()
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            executable = directory_path / "fake-lz4"
            executable.write_text("#!/bin/sh\n", encoding="utf-8")
            executable.chmod(0o755)
            source = directory_path / "trace.lz4"
            source.write_bytes(frame)
            with patch.object(pull_trace.subprocess, "Popen", return_value=process):
                with self.assertRaisesRegex(PullTraceError, "frame 1"):
                    decode_lz4_file(source, directory_path / "trace.txt", str(executable))

        self.assertEqual(1, process.terminate_calls)
        self.assertEqual(1, process.wait_calls)

    def test_file_decoder_reaps_when_reading_decoder_diagnostics_raises(self):
        class FakeStdin:
            def write(self, data):
                return len(data)

            def close(self):
                pass

        class FailingStderr:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                raise OSError("stderr exploded")

        class FakeProcess:
            def __init__(self):
                self.stdin = FakeStdin()
                self.stderr = FailingStderr()
                self.terminate_calls = 0
                self.wait_calls = 0

            def poll(self):
                return None

            def terminate(self):
                self.terminate_calls += 1

            def wait(self):
                self.wait_calls += 1
                return 0

        frame = uncompressed_lz4_frame(b"payload")
        process = FakeProcess()
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            executable = directory_path / "fake-lz4"
            executable.write_text("#!/bin/sh\n", encoding="utf-8")
            executable.chmod(0o755)
            source = directory_path / "trace.lz4"
            source.write_bytes(frame)
            with patch.object(pull_trace.subprocess, "Popen", return_value=process):
                with self.assertRaisesRegex(PullTraceError, "frame 1"):
                    decode_lz4_file(source, directory_path / "trace.txt", str(executable))

        self.assertEqual(1, process.terminate_calls)
        self.assertEqual(1, process.wait_calls)


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
