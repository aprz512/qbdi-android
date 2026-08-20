import subprocess
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import scripts.lz4_frames as lz4_frames

from scripts.lz4_frames import (
    PullTraceError,
    decode_lz4_file,
    decode_lz4_frames,
    scan_lz4_file,
    split_lz4_frames,
)


def uncompressed_lz4_frame(
    payload,
    *,
    flags=0x60,
    content_size=None,
    dictionary_id=None,
    block_checksum=b"",
    content_checksum=b"",
):
    optional = b""
    if flags & 0x08:
        optional += int(content_size).to_bytes(8, "little")
    if flags & 0x01:
        optional += int(dictionary_id).to_bytes(4, "little")
    return (
        b"\x04\x22\x4d\x18"
        + bytes((flags, 0x40))
        + optional
        + b"\x00"  # Header checksum is validated by the real decoder, not the scanner.
        + (len(payload) | 0x80000000).to_bytes(4, "little")
        + payload
        + block_checksum
        + b"\x00\x00\x00\x00"
        + content_checksum
    )


def fake_decode_runner(command, **kwargs):
    frame = kwargs["input"]
    flags = frame[4]
    payload_offset = 7 + (8 if flags & 0x08 else 0) + (4 if flags & 0x01 else 0)
    payload_size = int.from_bytes(frame[payload_offset:payload_offset + 4], "little")
    payload_size &= 0x7FFFFFFF
    return subprocess.CompletedProcess(
        command,
        0,
        stdout=frame[payload_offset + 4:payload_offset + 4 + payload_size],
        stderr=b"",
    )


class Lz4FrameTests(unittest.TestCase):
    def assert_memory_file_scan(self, artifact, expected_ranges, *, truncated=False):
        memory = split_lz4_frames(artifact)
        self.assertEqual(
            tuple(artifact[start:end] for start, end in expected_ranges), memory.frames
        )
        self.assertEqual(truncated, memory.truncated)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.lz4"
            path.write_bytes(artifact)
            file_scan = scan_lz4_file(path)
        expected_complete = expected_ranges[-1][1] if truncated else len(artifact)
        self.assertEqual(expected_complete, file_scan.complete_bytes)
        self.assertEqual(len(expected_ranges), file_scan.standard_frames)
        self.assertEqual(truncated, file_scan.truncated)

    def test_all_skippable_magics_are_ignored_between_standard_frames(self):
        first = uncompressed_lz4_frame(b"first")
        second = uncompressed_lz4_frame(b"second")
        for tag in range(16):
            with self.subTest(tag=tag):
                padding = bytes((0x50 + tag, 0x2A, 0x4D, 0x18)) + (7).to_bytes(
                    4, "little"
                ) + b"\0" * 7
                artifact = first + padding + second
                expected = ((0, len(first)), (len(first) + len(padding), len(artifact)))
                self.assert_memory_file_scan(artifact, expected)
                decoded = decode_lz4_frames(
                    artifact, lz4="test-lz4", runner=fake_decode_runner
                )
                self.assertEqual(b"firstsecond", decoded.data)

    def test_truncated_skippable_padding_preserves_prior_standard_frame_only(self):
        first = uncompressed_lz4_frame(b"first")
        padding = b"\x5f\x2a\x4d\x18" + (7).to_bytes(4, "little") + b"\0" * 6
        self.assert_memory_file_scan(first + padding, ((0, len(first)),), truncated=True)

    def test_splits_and_decodes_concatenated_frames_in_order(self):
        first = uncompressed_lz4_frame(b"first")
        second = uncompressed_lz4_frame(b"second")
        decoded_inputs = []

        def runner(command, **kwargs):
            decoded_inputs.append(kwargs["input"])
            return fake_decode_runner(command, **kwargs)

        artifact = first + second
        self.assert_memory_file_scan(artifact, ((0, len(first)), (len(first), len(artifact))))
        result = decode_lz4_frames(artifact, lz4="test-lz4", runner=runner)

        self.assertEqual(b"firstsecond", result.data)
        self.assertFalse(result.truncated)
        self.assertEqual([first, second], decoded_inputs)

    def test_truncated_final_frame_preserves_only_prior_complete_frames(self):
        complete = uncompressed_lz4_frame(b"complete")
        truncated = uncompressed_lz4_frame(b"must-not-leak")[:-5]
        artifact = complete + truncated

        self.assert_memory_file_scan(artifact, ((0, len(complete)),), truncated=True)
        result = decode_lz4_frames(artifact, lz4="test-lz4", runner=fake_decode_runner)

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

    def test_scanners_cover_raw_blocks_optional_headers_and_checksums(self):
        flags = 0x60 | 0x10 | 0x08 | 0x04 | 0x01
        frame = uncompressed_lz4_frame(
            b"payload",
            flags=flags,
            content_size=7,
            dictionary_id=0x12345678,
            block_checksum=b"\x12\x34\x56\x78",
            content_checksum=b"\x9a\xbc\xde\xf0",
        )
        self.assert_memory_file_scan(frame, ((0, len(frame)),))

    def test_scanner_directly_validates_flg_and_bd_grammar(self):
        frame = bytearray(uncompressed_lz4_frame(b"payload"))
        for byte, message in ((0x20, "flags"), (0x62, "flags")):
            with self.subTest(flg=byte), self.assertRaisesRegex(PullTraceError, message):
                candidate = bytearray(frame)
                candidate[4] = byte
                split_lz4_frames(bytes(candidate))
        for byte, message in ((0x30, "descriptor"), (0x41, "descriptor"),
                              (0xC0, "descriptor")):
            with self.subTest(bd=byte), self.assertRaisesRegex(PullTraceError, message):
                candidate = bytearray(frame)
                candidate[5] = byte
                split_lz4_frames(bytes(candidate))

    def test_scanner_directly_accounts_for_block_and_content_checksums(self):
        first = uncompressed_lz4_frame(b"first")
        checked = uncompressed_lz4_frame(
            b"payload", flags=0x74, block_checksum=b"1234", content_checksum=b"5678"
        )
        self.assert_memory_file_scan(first + checked, ((0, len(first)),
                                                       (len(first), len(first + checked))))
        for removed in (1, 5):
            with self.subTest(removed=removed):
                self.assert_memory_file_scan(
                    first + checked[:-removed], ((0, len(first)),), truncated=True
                )

    def test_scanners_accept_zero_byte_raw_block_with_checksum(self):
        frame = uncompressed_lz4_frame(
            b"", flags=0x70, block_checksum=b"\x12\x34\x56\x78"
        )
        self.assert_memory_file_scan(frame, ((0, len(frame)),))

    def test_empty_first_frame_truncation_and_skippable_only_have_no_recoverable_frame(self):
        inputs = (
            b"",
            b"\x04\x22",
            b"\x50\x2a\x4d\x18" + (0).to_bytes(4, "little"),
        )
        for data in inputs:
            with self.subTest(data=data), self.assertRaisesRegex(
                PullTraceError, "no complete LZ4 frame"
            ):
                split_lz4_frames(data)
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "empty.lz4"
                path.write_bytes(data)
                with self.assertRaisesRegex(PullTraceError, "no complete LZ4 frame"):
                    scan_lz4_file(path)

    def test_rejects_malformed_skippable_length_and_oversized_block_without_overflow(self):
        complete = uncompressed_lz4_frame(b"first")
        huge_padding = b"\x50\x2a\x4d\x18\xff\xff\xff\xff"
        self.assert_memory_file_scan(
            complete + huge_padding, ((0, len(complete)),), truncated=True
        )

        oversized_block = (
            b"\x04\x22\x4d\x18\x60\x40\x00"
            + (64 * 1024 + 1).to_bytes(4, "little")
        )
        for scanner in (split_lz4_frames,):
            with self.assertRaisesRegex(PullTraceError, "block size"):
                scanner(oversized_block)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oversized.lz4"
            path.write_bytes(oversized_block)
            with self.assertRaisesRegex(PullTraceError, "block size"):
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
            with patch.object(lz4_frames.subprocess, "Popen", return_value=process):
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
            with patch.object(lz4_frames.subprocess, "Popen", return_value=process):
                with self.assertRaisesRegex(PullTraceError, "frame 1"):
                    decode_lz4_file(source, directory_path / "trace.txt", str(executable))

        self.assertEqual(1, process.terminate_calls)
        self.assertEqual(1, process.wait_calls)


class VendoredLz4IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("cc")
        if compiler is None:
            raise unittest.SkipTest("C compiler is required for vendored LZ4 integration")
        cls.temporary = tempfile.TemporaryDirectory()
        temporary_path = Path(cls.temporary.name)
        source = temporary_path / "lz4_test_cli.c"
        cls.executable = temporary_path / "lz4-test-cli"
        source.write_text(
            r'''#include "lz4frame.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char *read_all(size_t *size) {
    size_t used = 0, capacity = 4096;
    unsigned char *data = (unsigned char *)malloc(capacity);
    if (data == NULL) return NULL;
    for (;;) {
        if (used == capacity) {
            capacity *= 2;
            unsigned char *grown = (unsigned char *)realloc(data, capacity);
            if (grown == NULL) { free(data); return NULL; }
            data = grown;
        }
        size_t count = fread(data + used, 1, capacity - used, stdin);
        used += count;
        if (count == 0) break;
    }
    if (ferror(stdin)) { free(data); return NULL; }
    *size = used;
    return data;
}

static int compress_input(const unsigned char *input, size_t input_size) {
    LZ4F_preferences_t preferences = LZ4F_INIT_PREFERENCES;
    preferences.frameInfo.blockMode = LZ4F_blockIndependent;
    preferences.frameInfo.blockChecksumFlag = LZ4F_blockChecksumEnabled;
    preferences.frameInfo.contentChecksumFlag = LZ4F_contentChecksumEnabled;
    preferences.frameInfo.contentSize = input_size;
    preferences.frameInfo.dictID = 0x12345678U;
    size_t capacity = LZ4F_compressFrameBound(input_size, &preferences);
    unsigned char *output = (unsigned char *)malloc(capacity);
    if (output == NULL) return 2;
    size_t written = LZ4F_compressFrame(output, capacity, input, input_size, &preferences);
    if (LZ4F_isError(written)) { free(output); return 3; }
    int failed = fwrite(output, 1, written, stdout) != written;
    free(output);
    return failed ? 4 : 0;
}

static int decompress_input(const unsigned char *input, size_t input_size) {
    LZ4F_dctx *context = NULL;
    size_t status = LZ4F_createDecompressionContext(&context, LZ4F_VERSION);
    if (LZ4F_isError(status)) return 5;
    size_t position = 0, hint = 1;
    unsigned char output[65536];
    while (hint != 0) {
        size_t source_size = input_size - position;
        size_t output_size = sizeof(output);
        hint = LZ4F_decompress(context, output, &output_size,
                               input + position, &source_size, NULL);
        if (LZ4F_isError(hint)) { LZ4F_freeDecompressionContext(context); return 6; }
        position += source_size;
        if (fwrite(output, 1, output_size, stdout) != output_size) {
            LZ4F_freeDecompressionContext(context); return 7;
        }
        if (hint != 0 && source_size == 0 && output_size == 0) {
            LZ4F_freeDecompressionContext(context); return 8;
        }
    }
    LZ4F_freeDecompressionContext(context);
    return position == input_size ? 0 : 9;
}

int main(int argc, char **argv) {
    size_t input_size = 0;
    unsigned char *input = read_all(&input_size);
    if (input == NULL) return 1;
    int result = argc > 1 && strcmp(argv[1], "--compress") == 0
        ? compress_input(input, input_size)
        : decompress_input(input, input_size);
    free(input);
    return result;
}
''',
            encoding="utf-8",
        )
        repository = Path(__file__).resolve().parents[2]
        library = repository / "tracer/src/main/cpp/third_party/lz4/lib"
        completed = subprocess.run(
            [
                compiler,
                "-std=c11",
                "-O2",
                f"-I{library}",
                str(source),
                str(library / "lz4frame.c"),
                str(library / "lz4.c"),
                str(library / "lz4hc.c"),
                str(library / "xxhash.c"),
                "-o",
                str(cls.executable),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            cls.temporary.cleanup()
            raise AssertionError(completed.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def compress(self, payload):
        completed = subprocess.run(
            [str(self.executable), "--compress"],
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        return completed.stdout

    def test_real_frames_decode_with_optional_fields_checksums_raw_blocks_and_padding(self):
        # Xorshift output is deterministic and incompressible enough to force a raw LZ4 block.
        state = 0x12345678
        payload = bytearray()
        for _ in range(70000):
            state ^= state << 13 & 0xFFFFFFFF
            state ^= state >> 17
            state ^= state << 5 & 0xFFFFFFFF
            payload.append(state & 0xFF)
        first = self.compress(bytes(payload))
        second_payload = b"second-real-frame"
        second = self.compress(second_payload)
        flags = first[4]
        self.assertEqual(0x1D, flags & 0x1D)  # content size, dict ID, both checksums
        header_bytes = 7 + 8 + 4
        first_block_word = int.from_bytes(first[header_bytes:header_bytes + 4], "little")
        self.assertNotEqual(0, first_block_word & 0x80000000)

        leading = b"\x51\x2a\x4d\x18" + (0).to_bytes(4, "little")
        trailing = b"\x5e\x2a\x4d\x18" + (3).to_bytes(4, "little") + b"\0" * 3
        artifact = leading + first + second + trailing
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            source = directory_path / "real.lz4"
            output = directory_path / "real.bin"
            source.write_bytes(artifact)
            scan = scan_lz4_file(source)
            self.assertEqual(len(artifact), scan.complete_bytes)
            self.assertEqual(2, scan.standard_frames)
            self.assertFalse(decode_lz4_file(source, output, str(self.executable)))
            self.assertEqual(bytes(payload) + second_payload, output.read_bytes())

            corrupted = bytearray(first)
            corrupted[-1] ^= 0xFF
            source.write_bytes(corrupted)
            with self.assertRaisesRegex(PullTraceError, "frame 1"):
                decode_lz4_file(source, output, str(self.executable))


if __name__ == "__main__":
    unittest.main()
