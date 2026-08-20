import io
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


from scripts.trace_binary import BinaryTraceError
from scripts.trace_convert import convert_binary_file, main
from scripts.tests.test_lz4_frames import uncompressed_lz4_frame
from scripts.tests.test_trace_binary import complete_stream


class TraceConvertFileTests(unittest.TestCase):
    def test_converts_raw_and_refuses_to_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "run.trace.bin"
            destination = root / "run.trace.txt"
            source.write_bytes(complete_stream())
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
            source.write_bytes(complete_stream()[:-105])
            with self.assertRaisesRegex(BinaryTraceError, "TRACE_END"):
                convert_binary_file(source, root / "partial.txt", lz4=None,
                                    crash_marked=True)

    def test_rejects_footer_artifact_size_mismatch_without_sidecar(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "run.trace.bin"
            source.write_bytes(complete_stream(compressed_bytes=7))
            with self.assertRaisesRegex(BinaryTraceError, "artifact byte count"):
                convert_binary_file(source, root / "output.txt", lz4=None,
                                    crash_marked=False)

    def test_decodes_real_complete_lz4_frames_and_recovery_requires_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            decoder = root / "lz4"
            decoder.write_text(
                "#!/usr/bin/env python3\nimport sys\nf=sys.stdin.buffer.read()\n"
                "n=int.from_bytes(f[7:11],'little') & 0x7fffffff\n"
                "sys.stdout.buffer.write(f[11:11+n])\n", encoding="utf-8"
            )
            decoder.chmod(0o755)
            probe = complete_stream()
            binary = complete_stream(compressed_bytes=len(probe) + 15)
            source = root / "run.trace.bin.lz4"
            source.write_bytes(uncompressed_lz4_frame(binary))
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
            source.write_bytes(complete_stream())
            (root / "run.trace.bin.metrics").write_text(
                "metrics_version=2\nprofile=full\nreturn=0x999\ninstructions=0\n"
                "elapsed_ms=17\nencoded_bytes=0\ncompressed_bytes=0\n"
                "cache_hits=9\ncache_misses=1\ncache_collisions=0\n"
                "buffer_swaps=2\nproducer_waits=0\nproducer_wait_ns=0\n"
                "effective_buffer_bytes=4096\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(BinaryTraceError, "sidecar mismatch.*return"):
                convert_binary_file(source, root / "out.txt", lz4=None, crash_marked=False)

    def test_cli_help_and_partial_exit_status(self):
        with self.assertRaises(SystemExit) as caught:
            main(["--help"])
        self.assertEqual(0, caught.exception.code)


if __name__ == "__main__":
    unittest.main()
