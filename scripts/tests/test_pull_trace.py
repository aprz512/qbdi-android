import json
import signal
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import scripts.flight_convert as flight_convert
from scripts.pull_trace import (
    AdbArtifactClient,
    EXIT_PARTIAL,
    PullTraceError,
    classify_artifacts,
    main,
    pull_artifact_set,
    select_trace_name,
)
from scripts.tests.test_flight_trace import (
    artifact as flight_artifact,
    chunk as flight_chunk,
    core_records as flight_core_records,
    directory_entry as flight_directory_entry,
)
from scripts.tests.test_lz4_frames import uncompressed_lz4_frame
from scripts.tests.test_trace_binary import (
    begin,
    complete_stream,
    instruction,
    instruction_definition,
    module,
    stopped,
    stream_header,
)
from scripts.tests.test_trace_convert import fake_lz4_executable


CRASH_MAGIC = 0x51435248


def crash_marker(signal_number=signal.SIGSEGV, tid=1234):
    return (
        CRASH_MAGIC.to_bytes(4, "little")
        + int(signal_number).to_bytes(4, "little", signed=True)
        + int(tid).to_bytes(4, "little", signed=True)
    )


def recoverable_flight_artifact(tid=321):
    return flight_artifact(
        directories=[flight_directory_entry(tid, 1, 2, 0, 1)],
        chunks=[flight_chunk(0, tid, 1, flight_core_records(tid))],
    )


def v3_sidecar(*, termination, return_valid, profile, instructions, elapsed_ms,
               encoded_bytes, compressed_bytes):
    def fixed_six(numerator, denominator):
        whole, remainder = divmod(numerator, denominator)
        return f"{whole}.{remainder * 1_000_000 // denominator:06d}"

    return (
        f"metrics_version=3\ntermination={termination}\nreturn_valid={return_valid}\n"
        f"profile={profile}\nreturn={'0x55' if return_valid else '0x0'}\n"
        f"instructions={instructions}\nelapsed_ms={elapsed_ms}\n"
        f"instructions_per_second={fixed_six(instructions * 1000, elapsed_ms)}\n"
        f"encoded_bytes={encoded_bytes}\ncompressed_bytes={compressed_bytes}\n"
        f"encoded_bytes_per_second={fixed_six(encoded_bytes * 1000, elapsed_ms)}\n"
        f"disk_bytes_per_second={fixed_six(compressed_bytes * 1000, elapsed_ms)}\n"
        f"compression_ratio={fixed_six(compressed_bytes, encoded_bytes)}\n"
        "cache_hits=9\ncache_misses=1\ncache_collisions=0\ncache_hit_rate=0.900000\n"
        "buffer_swaps=2\nproducer_waits=0\nproducer_wait_ns=0\n"
        "effective_buffer_bytes=4096\n"
    ).encode("ascii")


def stopped_binary_stream(*, compression, compressed_bytes=None):
    prefix = (
        stream_header(minor=2, features=1)
        + begin(compression=compression)
        + module()
        + instruction_definition()
        + instruction()
    )
    terminal_bytes = len(stopped(encoded_bytes=0, compressed_bytes=0))
    total = len(prefix) + terminal_bytes
    return prefix + stopped(
        encoded_bytes=total,
        compressed_bytes=total if compressed_bytes is None else compressed_bytes,
    )


def stopped_raw_stream():
    return stopped_binary_stream(compression=0)


class ArtifactClassificationTests(unittest.TestCase):
    def test_classifies_flight_artifact_without_normal_sidecars(self):
        traces = classify_artifacts({"100_target.flight.bin": b"persistent-ring"})

        self.assertEqual({"100_target.flight.bin"}, set(traces))
        self.assertEqual("incomplete", traces["100_target.flight.bin"].status)

    def test_classifies_text_compressed_binary_and_raw_binary_artifacts(self):
        artifacts = {
            "100.trace.txt.lz4": b"",
            "100.trace.txt.lz4.metrics": b"v1",
            "200.trace.bin.lz4": b"",
            "200.trace.bin.lz4.metrics": b"v2",
            "300.trace.bin": b"",
            "300.trace.bin.metrics": b"v2",
        }

        traces = classify_artifacts(artifacts)

        self.assertEqual(
            {"100.trace.txt.lz4", "200.trace.bin.lz4", "300.trace.bin"}, set(traces)
        )
        self.assertTrue(all(trace.status == "complete" for trace in traces.values()))

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

        def listing_capture(command, **kwargs):
            calls.append((command, kwargs))
            return b"123_algorithm.trace.txt.lz4\n123_algorithm.trace.txt.lz4.metrics\n"

        def runner(command, **kwargs):
            calls.append((command, kwargs))
            return subprocess.CompletedProcess(command, 0, stdout=b"trace-bytes", stderr=b"")

        client = AdbArtifactClient(
            package="com.aprz.qbdiandroid", device="serial", adb="custom-adb", runner=runner,
            listing_capture=listing_capture,
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
        self.assertEqual(1024 * 1024, calls[0][1]["maximum_bytes"])
        self.assertEqual("head", calls[1][0][6])
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

    def test_translates_adb_timeout_and_rejects_oversized_sidecars(self):
        def timeout_capture(command, **kwargs):
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])

        client = AdbArtifactClient(
            package="com.example.app", timeout=0.25, listing_capture=timeout_capture
        )
        with self.assertRaisesRegex(PullTraceError, "timed out after 0.25s"):
            client.list_names()

        client = AdbArtifactClient(
            package="com.example.app",
            runner=lambda command, **kwargs: subprocess.CompletedProcess(
                command, 0, stdout=b"12345", stderr=b""
            ),
        )
        with self.assertRaisesRegex(PullTraceError, "size limit"):
            client.read_file("run.metrics", 4)

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

        def read_file(self, name, maximum_bytes=64 * 1024):
            return self.files[name]

        def stream_file(self, name, output):
            self.streamed.append(name)
            output.write(self.files[name])

    def test_pulls_compressed_trace_and_sidecars_without_decompressing(self):
        name = "123_algorithm.trace.txt.lz4"
        metrics = (
            b"profile=fast\nreturn=0x1\ninstructions=1\nelapsed_ms=1\n"
            b"instructions_per_second=1000.000000\nraw_bytes=10\ncompressed_bytes=10\n"
            b"raw_bytes_per_second=10000.000000\ndisk_bytes_per_second=10000.000000\n"
            b"compression_ratio=1.000000\ncache_hits=1\ncache_misses=0\n"
            b"cache_collisions=0\ncache_hit_rate=1.000000\nbuffer_swaps=1\n"
            b"producer_waits=0\nproducer_wait_ns=0\neffective_buffer_bytes=4096\n"
        )
        files = {name: b"compressed", name + ".metrics": metrics}
        client = self.FakeClient(files)

        with tempfile.TemporaryDirectory() as directory:
            result = pull_artifact_set(
                client, name, files, Path(directory), compressed_only=True
            )

            self.assertEqual(0, result.exit_code)
            self.assertEqual("complete", result.status)
            self.assertEqual(b"compressed", (Path(directory) / name).read_bytes())
            self.assertEqual(
                metrics, (Path(directory) / (name + ".metrics")).read_bytes()
            )
            self.assertEqual([name], client.streamed)

    def test_rejects_mixed_generation_sidecar_before_publication(self):
        name = "123_algorithm.trace.txt.lz4"
        sidecar = (
            b"metrics_version=2\nprofile=fast\nreturn=0x1\ninstructions=0\n"
            b"elapsed_ms=1\ninstructions_per_second=0.000000\nencoded_bytes=1\n"
            b"compressed_bytes=1\nencoded_bytes_per_second=1000.000000\n"
            b"disk_bytes_per_second=1000.000000\ncompression_ratio=1.000000\n"
            b"cache_hits=0\ncache_misses=0\ncache_collisions=0\ncache_hit_rate=0.000000\n"
            b"buffer_swaps=1\nproducer_waits=0\nproducer_wait_ns=0\n"
            b"effective_buffer_bytes=4096\n"
        )
        files = {name: b"compressed", name + ".metrics": sidecar}
        client = self.FakeClient(files)
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(
                PullTraceError, "metrics v2"):
            pull_artifact_set(client, name, files, Path(directory), compressed_only=True)
        self.assertEqual([], client.streamed)

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

    def test_pulls_raw_binary_and_optionally_converts_it_atomically(self):
        name = "123_algorithm.trace.bin"
        binary = complete_stream(compression=0)
        files = {name: binary}
        client = self.FakeClient(files)

        with tempfile.TemporaryDirectory() as directory:
            result = pull_artifact_set(client, name, files, Path(directory))

            self.assertEqual(0, result.exit_code)
            self.assertEqual(binary, (Path(directory) / name).read_bytes())
            text = Path(directory) / "123_algorithm.trace.txt"
            self.assertIn("TRACE_END status=completed", text.read_text(encoding="utf-8"))

    def test_pulls_stopped_binary_as_successful_stopped_artifact(self):
        name = "123_algorithm.trace.bin"
        binary = stopped_raw_stream()
        sidecar = v3_sidecar(
            termination="stopped", return_valid=0, profile="full", instructions=1,
            elapsed_ms=17, encoded_bytes=len(binary), compressed_bytes=len(binary),
        )
        client = self.FakeClient({name: binary, name + ".metrics": sidecar})

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = pull_artifact_set(client, name, client.files, root)

            self.assertEqual(0, result.exit_code)
            self.assertEqual("stopped", result.status)
            self.assertIn("status=stopped", (root / "123_algorithm.trace.txt").read_text())

    def test_rejects_stopped_sidecar_for_completed_binary(self):
        name = "123_algorithm.trace.bin"
        binary = complete_stream(compression=0)
        sidecar = v3_sidecar(
            termination="stopped", return_valid=0, profile="full", instructions=0,
            elapsed_ms=17, encoded_bytes=len(binary), compressed_bytes=len(binary),
        )
        client = self.FakeClient({name: binary, name + ".metrics": sidecar})

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            retained = root / "retain.txt"
            retained.write_bytes(b"keep")

            with self.assertRaisesRegex(PullTraceError, "sidecar mismatch for termination"):
                pull_artifact_set(client, name, client.files, root)

            self.assertEqual(b"keep", retained.read_bytes())
            self.assertEqual({"retain.txt"}, {path.name for path in root.iterdir()})

    def test_compressed_only_rejects_stopped_sidecar_for_completed_binary(self):
        name = "123_algorithm.trace.bin"
        binary = complete_stream(compression=0)
        sidecar = v3_sidecar(
            termination="stopped", return_valid=0, profile="full", instructions=0,
            elapsed_ms=17, encoded_bytes=len(binary), compressed_bytes=len(binary),
        )
        client = self.FakeClient({name: binary, name + ".metrics": sidecar})

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(PullTraceError, "sidecar mismatch for termination"):
                pull_artifact_set(client, name, client.files, root, compressed_only=True)

            self.assertEqual([], list(root.iterdir()))

    def test_compressed_only_pulls_matching_stopped_binary_without_text(self):
        name = "123_algorithm.trace.bin"
        binary = stopped_raw_stream()
        sidecar = v3_sidecar(
            termination="stopped", return_valid=0, profile="full", instructions=1,
            elapsed_ms=17, encoded_bytes=len(binary), compressed_bytes=len(binary),
        )
        client = self.FakeClient({name: binary, name + ".metrics": sidecar})

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = pull_artifact_set(client, name, client.files, root, compressed_only=True)

            self.assertEqual(0, result.exit_code)
            self.assertEqual("stopped", result.status)
            self.assertEqual({name, name + ".metrics"}, {path.name for path in result.outputs})
            self.assertFalse((root / "123_algorithm.trace.txt").exists())

    def test_compressed_only_rejects_stopped_sidecar_for_completed_lz4_binary(self):
        name = "123_algorithm.trace.bin.lz4"
        probe = complete_stream(compression=1)
        compressed_bytes = len(uncompressed_lz4_frame(probe))
        binary = complete_stream(compression=1, compressed_bytes=compressed_bytes)
        artifact = uncompressed_lz4_frame(binary)
        sidecar = v3_sidecar(
            termination="stopped", return_valid=0, profile="full", instructions=0,
            elapsed_ms=17, encoded_bytes=len(binary), compressed_bytes=len(artifact),
        )
        client = self.FakeClient({name: artifact, name + ".metrics": sidecar})

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            decoder = fake_lz4_executable(root)
            with self.assertRaisesRegex(PullTraceError, "sidecar mismatch for termination"):
                pull_artifact_set(
                    client, name, client.files, root, compressed_only=True, lz4=str(decoder)
                )

            self.assertEqual({"lz4"}, {path.name for path in root.iterdir()})

    def test_pulls_compressed_binary_and_routes_sidecar_through_converter(self):
        name = "123_algorithm.trace.bin.lz4"
        probe = complete_stream(compression=1)
        artifact_size = len(uncompressed_lz4_frame(probe))
        binary = complete_stream(compression=1, compressed_bytes=artifact_size)
        artifact = uncompressed_lz4_frame(binary)

        def fixed_six(numerator, denominator):
            whole, remainder = divmod(numerator, denominator)
            return f"{whole}.{remainder * 1_000_000 // denominator:06d}"

        sidecar = (
            "metrics_version=3\ntermination=completed\nreturn_valid=1\n"
            "profile=full\nreturn=0x55\ninstructions=0\n"
            f"elapsed_ms=17\ninstructions_per_second=0.000000\nencoded_bytes={len(binary)}\n"
            f"compressed_bytes={len(artifact)}\n"
            f"encoded_bytes_per_second={fixed_six(len(binary) * 1000, 17)}\n"
            f"disk_bytes_per_second={fixed_six(len(artifact) * 1000, 17)}\n"
            f"compression_ratio={fixed_six(len(artifact), len(binary))}\n"
            "cache_hits=9\ncache_misses=1\ncache_collisions=0\ncache_hit_rate=0.900000\n"
            "buffer_swaps=2\nproducer_waits=0\nproducer_wait_ns=0\n"
            "effective_buffer_bytes=4096\n"
        ).encode("ascii")
        client = self.FakeClient({name: artifact, name + ".metrics": sidecar})

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            decoder = fake_lz4_executable(root)
            result = pull_artifact_set(
                client, name, client.files, root, lz4=str(decoder)
            )

            self.assertEqual(0, result.exit_code)
            self.assertEqual("complete", result.status)
            self.assertIn("TRACE_END status=completed", (root / "123_algorithm.trace.txt").read_text())

    def test_compressed_binary_crash_truncation_routes_to_partial_output(self):
        name = "123_algorithm.trace.bin.lz4"
        partial_binary = complete_stream(compression=1)[:-105]
        artifact = (
            uncompressed_lz4_frame(partial_binary)
            + uncompressed_lz4_frame(b"incomplete-tail")[:-3]
        )
        files = {name: artifact, name + ".crash": crash_marker()}
        client = self.FakeClient(files)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            decoder = fake_lz4_executable(root)
            result = pull_artifact_set(client, name, files, root, lz4=str(decoder))

            self.assertEqual(EXIT_PARTIAL, result.exit_code)
            self.assertTrue((root / "123_algorithm.partial.trace.txt").is_file())
            self.assertFalse((root / "123_algorithm.trace.txt").exists())

    def test_binary_conversion_failure_never_publishes_readable_output(self):
        name = "123_algorithm.trace.bin"
        client = self.FakeClient({name: b"not-qtrb"})

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(PullTraceError):
                pull_artifact_set(client, name, client.files, Path(directory))
            self.assertFalse((Path(directory) / "123_algorithm.trace.txt").exists())

    def test_stream_error_removes_temporary_and_publishes_no_artifact(self):
        name = "123_algorithm.trace.bin"

        class FailingClient(self.FakeClient):
            def stream_file(self, artifact, output):
                output.write(b"partial")
                raise PullTraceError("adb stream failed")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(PullTraceError, "stream failed"):
                pull_artifact_set(FailingClient({name: b"ignored"}), name, [name], root)
            self.assertEqual([], list(root.iterdir()))

    def test_streams_flight_without_lz4_and_publishes_recovery_outputs(self):
        name = "123_target.flight.bin"
        binary = recoverable_flight_artifact()
        client = self.FakeClient({name: binary})

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = pull_artifact_set(client, name, client.files, root)

            self.assertEqual("complete", result.status)
            self.assertEqual(binary, (root / name).read_bytes())
            self.assertEqual(
                {
                    name,
                    "123_target.merged.trace.txt",
                    "123_target.tid-321.trace.txt",
                    "123_target.flight.json",
                },
                {path.name for path in result.outputs},
            )
            self.assertEqual([name], client.streamed)
            summary = json.loads((root / "123_target.flight.json").read_text())
            self.assertEqual("unknown", summary["termination"]["cause"])

    def test_compressed_only_flight_skips_recovery_outputs(self):
        name = "123_target.flight.bin"
        binary = recoverable_flight_artifact()
        client = self.FakeClient({name: binary})

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = pull_artifact_set(
                client, name, client.files, root, compressed_only=True
            )

            self.assertEqual("complete", result.status)
            self.assertEqual((root / name,), result.outputs)
            self.assertEqual([name], [path.name for path in root.iterdir()])

    def test_flight_no_overwrite_checks_every_derived_output(self):
        name = "123_target.flight.bin"
        binary = recoverable_flight_artifact()
        derived = (
            name,
            "123_target.merged.trace.txt",
            "123_target.tid-321.trace.txt",
            "123_target.flight.json",
        )

        for occupied in derived:
            with self.subTest(occupied=occupied), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                existing = root / occupied
                existing.write_bytes(b"keep")
                client = self.FakeClient({name: binary})

                with self.assertRaisesRegex((PullTraceError, FileExistsError), "already exists"):
                    pull_artifact_set(client, name, client.files, root)

                self.assertEqual(b"keep", existing.read_bytes())
                self.assertEqual([occupied], [path.name for path in root.iterdir()])

    def test_flight_no_overwrite_rejects_dangling_source_symlink_before_stream(self):
        name = "123_target.flight.bin"
        client = self.FakeClient({name: recoverable_flight_artifact()})

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / name
            destination.symlink_to("missing-artifact")

            with self.assertRaisesRegex(PullTraceError, "already exists"):
                pull_artifact_set(client, name, client.files, root)

            self.assertTrue(destination.is_symlink())
            self.assertEqual([], client.streamed)

    def test_flight_conversion_failure_cleans_staging_and_publishes_nothing(self):
        name = "123_target.flight.bin"
        client = self.FakeClient({name: b"not-a-flight-artifact"})

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(PullTraceError):
                pull_artifact_set(client, name, client.files, root)

            self.assertEqual([], list(root.iterdir()))

    def test_flight_publication_failure_rolls_back_source_and_all_derived_outputs(self):
        name = "123_target.flight.bin"
        client = self.FakeClient({name: recoverable_flight_artifact()})
        real_link = flight_convert.os.link
        calls = 0

        def fail_source_link(src, dst, *args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 5:
                raise OSError("injected artifact publication failure")
            return real_link(src, dst, *args, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(flight_convert.os, "link", side_effect=fail_source_link), \
                    self.assertRaises((PullTraceError, OSError)):
                pull_artifact_set(client, name, client.files, root)

            self.assertEqual([], list(root.iterdir()))


class CommandLineTests(unittest.TestCase):
    def test_script_remains_directly_executable(self):
        root = Path(__file__).resolve().parents[2]
        probe = subprocess.run(
            [sys.executable, "scripts/pull_trace.py", "--help"],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

        self.assertEqual(0, probe.returncode, probe.stderr)

    def test_selects_latest_or_explicit_flight_artifact(self):
        names = [
            "new.flight.bin",
            "older.trace.bin.lz4",
            "old.flight.bin",
        ]

        self.assertEqual("new.flight.bin", select_trace_name(names))
        self.assertEqual("old.flight.bin", select_trace_name(names, "old.flight.bin"))

    def test_spawn_trace_contains_exact_flight_defaults(self):
        root = Path(__file__).resolve().parents[2]
        spawn_config = (root / "scripts/spawn_trace.js").read_text(encoding="utf-8")

        for field in (
            "enabled: true",
            "entryScene: 'init'",
            "capacityMb: 512",
            "chunkKb: 256",
            "maxThreads: 256",
            "protectedChunks: 4",
        ):
            with self.subTest(field=field):
                self.assertIn(field, spawn_config)

    def test_spawn_trace_contains_demo_scene_locations(self):
        root = Path(__file__).resolve().parents[2]
        spawn_config = (root / "scripts/spawn_trace.js").read_text(encoding="utf-8")

        self.assertIn("name: 'init'", spawn_config)
        self.assertIn("location: { offset: '0x6ac90' }", spawn_config)
        self.assertIn("name: 'algorithm'", spawn_config)
        self.assertIn("imageBase: '0x0'", spawn_config)
        self.assertIn("address: '0x6db38'", spawn_config)

    def test_flight_cli_recovers_missing_terminal_without_lz4(self):
        name = "new.flight.bin"
        client = PullArtifactTests.FakeClient({name: recoverable_flight_artifact()})
        client.list_names = lambda: [name]
        stdout = StringIO()

        with tempfile.TemporaryDirectory() as directory, redirect_stdout(stdout):
            exit_code = main(
                ["--package", "com.example.app", "--output", directory],
                client_factory=lambda **kwargs: client,
                lz4_finder=lambda command: None,
            )

            self.assertEqual(0, exit_code)
            self.assertTrue((Path(directory) / "new.flight.json").is_file())
        self.assertIn("status=complete", stdout.getvalue())

    def test_selects_binary_by_listing_order_without_suffix_priority(self):
        names = [
            "300_benchmark.trace.bin.lz4.metrics",
            "300_benchmark.trace.bin.lz4",
            "200_benchmark.trace.txt.lz4",
        ]

        self.assertEqual("300_benchmark.trace.bin.lz4", select_trace_name(names))

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

    def test_compressed_only_cli_validates_v3_lz4_stopped_artifact(self):
        name = "new.trace.bin.lz4"
        probe = stopped_binary_stream(compression=1, compressed_bytes=0)
        compressed_bytes = len(uncompressed_lz4_frame(probe))
        binary = stopped_binary_stream(compression=1, compressed_bytes=compressed_bytes)
        artifact = uncompressed_lz4_frame(binary)
        sidecar = v3_sidecar(
            termination="stopped", return_valid=0, profile="full", instructions=1,
            elapsed_ms=17, encoded_bytes=len(binary), compressed_bytes=len(artifact),
        )
        client = PullArtifactTests.FakeClient({name: artifact, name + ".metrics": sidecar})
        client.list_names = lambda: [name, name + ".metrics"]
        stdout = StringIO()

        with tempfile.TemporaryDirectory() as directory, redirect_stdout(stdout):
            root = Path(directory)
            decoder = fake_lz4_executable(root)
            exit_code = main(
                ["--package", "com.example.app", "--output", directory, "--compressed-only"],
                client_factory=lambda **kwargs: client,
                lz4_finder=lambda command: str(decoder),
            )

            self.assertEqual(0, exit_code)
            self.assertIn(f"trace={name} status=stopped", stdout.getvalue())
            self.assertTrue((root / name).is_file())
            self.assertTrue((root / (name + ".metrics")).is_file())
            self.assertFalse((root / "new.trace.txt").exists())

    def test_raw_binary_cli_pulls_and_converts_end_to_end_without_lz4(self):
        name = "new.trace.bin"
        client = PullArtifactTests.FakeClient({name: complete_stream(compression=0)})
        client.list_names = lambda: [name]
        stdout = StringIO()
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(stdout):
            exit_code = main(
                ["--package", "com.example.app", "--output", directory],
                client_factory=lambda **kwargs: client,
                lz4_finder=lambda command: None,
            )

            self.assertEqual(0, exit_code)
            self.assertIn("TRACE_END status=completed", (Path(directory) / "new.trace.txt").read_text())
        self.assertIn("output=", stdout.getvalue())

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
