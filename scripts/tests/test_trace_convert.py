import contextlib
import io
import os
import subprocess
import sys
import tempfile
import tracemalloc
import unittest
from pathlib import Path
from unittest.mock import patch

import scripts.trace_convert as trace_convert
import scripts.lz4_frames as lz4_frames
from scripts.trace_binary import BinaryTraceError
from scripts.trace_convert import convert_binary_file, main
from scripts.tests.test_lz4_frames import uncompressed_lz4_frame
from scripts.tests.test_trace_binary import complete_stream


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


def metrics_sidecar(source: Path, extra: str = "") -> str:
    size = source.stat().st_size
    return (
        "metrics_version=2\nprofile=full\nreturn=0x55\ninstructions=0\n"
        f"elapsed_ms=17\nencoded_bytes={size}\ncompressed_bytes={size}\n"
        "cache_hits=9\ncache_misses=1\ncache_collisions=0\n"
        "buffer_swaps=2\nproducer_waits=0\nproducer_wait_ns=0\n"
        "effective_buffer_bytes=4096\n" + extra
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
            self.assertIn("TRACE_END status=ok", destination.read_text())
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
                "metrics_version=2\nprofile=full\nreturn=0x999\ninstructions=0\n"
                "elapsed_ms=17\nencoded_bytes=0\ncompressed_bytes=0\n"
                "cache_hits=9\ncache_misses=1\ncache_collisions=0\n"
                "buffer_swaps=2\nproducer_waits=0\nproducer_wait_ns=0\n"
                "effective_buffer_bytes=4096\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(BinaryTraceError, "sidecar mismatch.*return"):
                convert_binary_file(source, root / "out.txt", lz4=None, crash_marked=False)

    def test_cli_help(self):
        with self.assertRaises(SystemExit) as caught:
            main(["--help"])
        self.assertEqual(0, caught.exception.code)

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
            sidecar.write_text(metrics_sidecar(source, "mystery=1\n"), encoding="utf-8")
            with self.assertRaisesRegex(BinaryTraceError, "unknown metrics sidecar key"):
                convert_binary_file(source, root / "unknown.txt", lz4=None,
                                    crash_marked=False)

            sidecar.write_text(metrics_sidecar(source, "profile=full\n"), encoding="utf-8")
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
                metrics_sidecar(source, "cache_hit_rate=garbage\n"), encoding="utf-8"
            )
            with self.assertRaisesRegex(BinaryTraceError, "invalid.*cache_hit_rate"):
                convert_binary_file(source, root / "rate.txt", lz4=None,
                                    crash_marked=False)

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
