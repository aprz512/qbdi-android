import hashlib
import os
from pathlib import Path
import tempfile
import time
import unittest

from scripts.qtrace_historical_benchmark import canonical_elf_sha256


class CanonicalIdentityTests(unittest.TestCase):
    def canonical(self, value: bytes) -> str:
        calls: list[list[str]] = []

        def fake_objcopy(argv, *, maximum_bytes, timeout):
            self.assertEqual(1024 * 1024, maximum_bytes)
            self.assertGreater(timeout, 0)
            self.assertEqual("llvm-objcopy", Path(argv[0]).name)
            self.assertEqual(
                ["--strip-debug", "--remove-section=.note.gnu.build-id"], argv[1:3]
            )
            self.assertTrue(Path(argv[3]).is_file())
            self.assertTrue(Path(argv[4]).is_file())
            Path(argv[4]).write_bytes(Path(argv[3]).read_bytes().split(b"|DBG|", 1)[0])
            calls.append(argv)
            return b""

        with tempfile.TemporaryDirectory() as directory:
            tool = (Path(directory) / "ndk" / "26.1.10909125" / "toolchains" /
                    "llvm" / "prebuilt" / "linux-x86_64" / "bin" / "llvm-objcopy")
            tool.parent.mkdir(parents=True)
            tool.write_text("#! /bin/sh\n", encoding="utf-8")
            tool.chmod(0o700)
            canonical = canonical_elf_sha256(
                value, deadline=time.monotonic() + 2,
                android_home=Path(directory), capture=fake_objcopy,
            )
        self.assertEqual(1, len(calls))
        return canonical

    def test_debug_and_build_id_changes_share_one_canonical_hash(self):
        a = b"\x7fELFRUNTIME|DBG|/private/build-one|BUILD-ID|1111"
        b = b"\x7fELFRUNTIME|DBG|/private/build-two|BUILD-ID|2222"
        self.assertNotEqual(hashlib.sha256(a).digest(), hashlib.sha256(b).digest())
        self.assertEqual(self.canonical(a), self.canonical(b))

    def test_runtime_byte_mutation_changes_canonical_hash(self):
        self.assertNotEqual(self.canonical(b"\x7fELFRUNTIME-A|DBG|x"),
                            self.canonical(b"\x7fELFRUNTIME-B|DBG|x"))

    def test_canonicalizer_rejects_missing_tool_empty_non_elf_oversized_and_expired_output(self):
        def no_output(*_args, **_kwargs):
            return b""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "tool"):
                canonical_elf_sha256(b"\x7fELFok", deadline=time.monotonic() + 1,
                                     android_home=root, capture=no_output)
            tool = (root / "ndk" / "26.1.10909125" / "toolchains" / "llvm" /
                    "prebuilt" / "linux-x86_64" / "bin" / "llvm-objcopy")
            tool.parent.mkdir(parents=True)
            tool.write_text("#! /bin/sh\n", encoding="utf-8")
            tool.chmod(0o700)
            for value, deadline, message in (
                (b"", time.monotonic() + 1, "empty"),
                (b"not an elf", time.monotonic() + 1, "ELF"),
                (b"\x7fELF" + b"x" * (64 * 1024 * 1024), time.monotonic() + 1, "64 MiB"),
                (b"\x7fELFok", time.monotonic() - 1, "deadline"),
            ):
                with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                    canonical_elf_sha256(value, deadline=deadline, android_home=root,
                                         capture=no_output)
