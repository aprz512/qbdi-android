import hashlib
import io
import os
from pathlib import Path
import shutil
import stat
import tarfile
import tempfile
import time
import unittest
import zipfile
from unittest.mock import patch

from scripts.qtrace_historical_benchmark import canonical_elf_sha256
import scripts.qtrace_historical_benchmark as historical_benchmark


PINNED_PAX_VALUE = (
    b"comment=2d6b1022a14ae554804a57e267544c12dea29353\n"
)


def _pax_body(value=PINNED_PAX_VALUE):
    size = len(value) + 3
    while True:
        body = f"{size} ".encode("ascii") + value
        if len(body) == size:
            return body
        size = len(body)


def _raw_tar_member(name, *, type_flag=b"0", payload=b"", prefix=b""):
    header = _raw_tar_header(
        name, type_flag=type_flag, size=len(payload), prefix=prefix
    )[:512]
    return header + payload + b"\0" * ((-len(payload)) % 512)


def _with_pax(archive_bytes, *, value=PINNED_PAX_VALUE):
    body = _pax_body(value)
    return _raw_tar_member(
        b"pax_global_header", type_flag=b"g", payload=body
    ) + archive_bytes


def _tar_bytes(members):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, kind, payload in members:
            info = tarfile.TarInfo(name)
            if kind == "directory":
                info.type = tarfile.DIRTYPE
                info.mode = 0o777
                archive.addfile(info)
            elif kind == "file":
                info.size = len(payload)
                info.mode = 0o777
                archive.addfile(info, io.BytesIO(payload))
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = "build.gradle"
                archive.addfile(info)
            elif kind == "hardlink":
                info.type = tarfile.LNKTYPE
                info.linkname = "build.gradle"
                archive.addfile(info)
            elif kind == "fifo":
                info.type = tarfile.FIFOTYPE
                archive.addfile(info)
            elif kind == "character":
                info.type = tarfile.CHRTYPE
                archive.addfile(info)
            else:
                raise AssertionError(kind)
    return output.getvalue()


def _minimal_source_archive():
    return _with_pax(_tar_bytes([
        ("app", "directory", b""),
        ("app/build.gradle", "file", b"android {}\n"),
        ("build.gradle", "file", b"plugins {}\n"),
        ("settings.gradle", "file", b"include ':app'\n"),
        ("gradle.properties", "file", b"org.gradle.daemon=false\n"),
        ("gradlew", "file", b"#!/bin/sh\n"),
        ("gradle", "directory", b""),
        ("gradle/wrapper", "directory", b""),
        ("gradle/wrapper/gradle-wrapper.properties", "file", b"distributionUrl=file:test\n"),
    ]))


def _apk_bytes(target=b"\x7fELFhistorical-target", *, abi="arm64-v8a", extra=()):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(f"lib/{abi}/libdemo_target.so", target)
        for name, payload in extra:
            archive.writestr(name, payload)
    return output.getvalue()


def _raw_tar_header(name_field, *, type_flag=b"0", size=0, prefix=b""):
    header = bytearray(512)
    header[:len(name_field)] = name_field
    header[100:108] = b"0000700\0"
    header[108:116] = b"0000000\0"
    header[116:124] = b"0000000\0"
    header[124:136] = f"{size:011o}\0".encode("ascii")
    header[136:148] = b"00000000000\0"
    header[148:156] = b"        "
    header[156:157] = type_flag
    header[257:263] = b"ustar\0"
    header[263:265] = b"00"
    header[345:345 + len(prefix)] = prefix
    checksum = sum(header)
    header[148:156] = f"{checksum:06o}\0 ".encode("ascii")
    return bytes(header) + b"\0" * 1024


def _zip_with_declared_sizes(apk_bytes, declared_sizes):
    patched = bytearray(apk_bytes)
    offset = 0
    while True:
        offset = patched.find(b"PK\x01\x02", offset)
        if offset < 0:
            break
        name_size = int.from_bytes(patched[offset + 28:offset + 30], "little")
        extra_size = int.from_bytes(patched[offset + 30:offset + 32], "little")
        comment_size = int.from_bytes(patched[offset + 32:offset + 34], "little")
        name = bytes(patched[offset + 46:offset + 46 + name_size]).decode("utf-8")
        if name in declared_sizes:
            patched[offset + 24:offset + 28] = int(declared_sizes[name]).to_bytes(4, "little")
        offset += 46 + name_size + extra_size + comment_size
    return bytes(patched)


def _blocking_inspection_worker(_path, _descriptor, _sender):
    time.sleep(10)


def _result_then_linger_worker(sender):
    sender.send((True, {"result": "published"}))
    time.sleep(10)


def _success_then_nonzero_worker(sender):
    sender.send((True, {"result": "published"}))
    sender.close()
    raise SystemExit(7)


class _RecordingSender:
    def __init__(self):
        self.messages = []
        self.closed = False

    def send(self, message):
        self.messages.append(message)

    def close(self):
        self.closed = True


class HistoricalArchiveTests(unittest.TestCase):
    def assert_rejected_without_regular_publication(self, archive_bytes):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent_before = {path.name for path in root.parent.iterdir()}
            with self.assertRaises(historical_benchmark.HistoricalBenchmarkError):
                historical_benchmark._extract_historical_archive(archive_bytes, root)
            self.assertEqual(parent_before, {path.name for path in root.parent.iterdir()})
            self.assertFalse(any(path.is_file() for path in root.rglob("*")))

    def test_archive_rejects_every_path_type_duplicate_and_collision_boundary(self):
        invalid = [
            _with_pax(_tar_bytes([(name, "file", b"x")]))
            for name in (
                "../escape", "/absolute", "app//empty", "app/./dot",
                "app\\backslash", "outside.txt", "gradle/not-wrapper.txt",
            )
        ]
        invalid.extend([
            _with_pax(_tar_bytes([("app/link", kind, b"")]))
            for kind in ("symlink", "hardlink", "character", "fifo")
        ])
        invalid.extend([
            _with_pax(_tar_bytes([("app/build.gradle", "file", b"a"),
                                  ("app/build.gradle", "file", b"b")])),
            _with_pax(_tar_bytes([("app/node", "file", b"a"),
                                  ("app/node/child", "file", b"b")])),
            _with_pax(_tar_bytes([("app/node/child", "file", b"b"),
                                  ("app/node", "file", b"a")])),
            _with_pax(_raw_tar_header(b"app/invalid-\xff")),
            _with_pax(_raw_tar_header(b"app/nul\0alias")),
            _with_pax(_raw_tar_header(b"app/sparse", type_flag=b"S")),
            _with_pax(_raw_tar_header(b"app/file/", type_flag=b"0")),
            _with_pax(_raw_tar_header(b"", type_flag=b"5", prefix=b"app")),
        ])
        invalid.extend(
            _with_pax(_raw_tar_header(b"app/other-type", type_flag=kind))
            for kind in (b"3", b"4", b"7", b"x", b"L", b"K")
        )
        for index, archive_bytes in enumerate(invalid):
            with self.subTest(index=index):
                self.assert_rejected_without_regular_publication(archive_bytes)

    def test_archive_counts_pax_in_256_member_limit_and_rejects_every_size_boundary(self):
        accepted = _with_pax(_tar_bytes([
            (f"app/directory-{index}", "directory", b"") for index in range(255)
        ]))
        with tempfile.TemporaryDirectory() as directory:
            manifest = historical_benchmark._extract_historical_archive(
                accepted, Path(directory)
            )
        self.assertEqual(256, len(manifest))

        cases = [
            _with_pax(_tar_bytes([(f"app/directory-{index}", "directory", b"")
                                  for index in range(256)])),
            _with_pax(_tar_bytes([("app/large", "file",
                                   b"x" * (2 * 1024 * 1024 + 1))])),
            _with_pax(_tar_bytes([(f"app/total-{index}", "file",
                                   b"x" * (2 * 1024 * 1024))
                                  for index in range(4)]
                                 + [("app/total-last", "file", b"x")])),
            _with_pax(_tar_bytes([("app/" + "a" * 509, "file", b"")])),
            _with_pax(_tar_bytes([("app/" + "/".join(["a"] * 32),
                                   "file", b"")])),
        ]
        for index, archive_bytes in enumerate(cases):
            with self.subTest(index=index):
                self.assert_rejected_without_regular_publication(archive_bytes)

    def test_archive_extracts_only_the_allowlist_with_canonical_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = historical_benchmark._extract_historical_archive(
                _minimal_source_archive(), root
            )
            self.assertEqual(
                {
                    "type": "global_pax",
                    "size": len(_pax_body()),
                    "sha256": hashlib.sha256(_pax_body()).hexdigest(),
                },
                {key: manifest[0][key] for key in ("type", "size", "sha256")},
            )
            self.assertFalse((root / "pax_global_header").exists())
            self.assertEqual(0o700, stat.S_IMODE(root.stat().st_mode))
            for path in root.rglob("*"):
                expected = 0o700 if path.is_dir() or path.name == "gradlew" else 0o600
                self.assertEqual(expected, stat.S_IMODE(path.stat().st_mode), path)
            extracted = [item for item in manifest if item["type"] != "global_pax"]
            self.assertEqual(len(extracted), len({item["path"] for item in extracted}))
            self.assertEqual(
                {"path", "type", "size", "sha256"}, set(extracted[0])
            )

    def test_archive_requires_one_first_pinned_global_pax_envelope(self):
        raw_pax_body = _pax_body()
        wrapped = _minimal_source_archive()
        with tempfile.TemporaryDirectory() as directory:
            manifest = historical_benchmark._extract_historical_archive(
                wrapped, Path(directory)
            )
            self.assertFalse((Path(directory) / "pax_global_header").exists())
        self.assertEqual(
            {
                "type": "global_pax",
                "size": len(raw_pax_body),
                "sha256": hashlib.sha256(raw_pax_body).hexdigest(),
            },
            {key: manifest[0][key] for key in ("type", "size", "sha256")},
        )

        renamed = _raw_tar_member(
            b"metadata-name-is-not-a-path", type_flag=b"g", payload=raw_pax_body
        ) + _tar_bytes([("app", "directory", b"")])
        with tempfile.TemporaryDirectory() as directory:
            renamed_manifest = historical_benchmark._extract_historical_archive(
                renamed, Path(directory)
            )
            self.assertFalse(
                (Path(directory) / "metadata-name-is-not-a-path").exists()
            )
        self.assertEqual("global_pax", renamed_manifest[0]["type"])

        ordinary = _tar_bytes([("app", "directory", b"")])
        pax_member = _raw_tar_member(
            b"pax_global_header", type_flag=b"g", payload=raw_pax_body
        )
        malformed = _pax_body(PINNED_PAX_VALUE + b"extra=value\n")
        cases = [
            b"\0" * 1024,
            ordinary,
            pax_member + wrapped,
            _raw_tar_member(b"app", type_flag=b"5") + pax_member + b"\0" * 1024,
            _raw_tar_member(b"pax_global_header", type_flag=b"g",
                            payload=b"51 " + PINNED_PAX_VALUE),
            _raw_tar_member(b"pax_global_header", type_flag=b"g",
                            payload=b"9" * 5000 + b" " + PINNED_PAX_VALUE),
            _raw_tar_member(b"pax_global_header", type_flag=b"g",
                            payload=raw_pax_body[:-1]),
            _raw_tar_member(b"pax_global_header", type_flag=b"g", payload=malformed),
            _with_pax(ordinary, value=b"comment=" + b"0" * 40 + b"\n"),
        ]
        cases.extend(
            pax_member + _raw_tar_header(b"app/forbidden", type_flag=kind)
            for kind in (b"x", b"g", b"L", b"K", b"S", b"1", b"2", b"3", b"4", b"6", b"7")
        )
        for index, archive_bytes in enumerate(cases):
            with self.subTest(index=index):
                self.assert_rejected_without_regular_publication(archive_bytes)

    def test_builder_uses_exact_commit_allowlist_private_cwd_and_offline_gradle(self):
        target = b"\x7fELFhistorical-target"
        apk = _apk_bytes(target)
        calls = []
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repository"
            repository.mkdir()
            android_home = Path(directory) / "android"
            aapt2 = android_home / "build-tools" / "35.0.0" / "aapt2"
            objcopy = (android_home / "ndk" / historical_benchmark.NDK_VERSION /
                       "toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-objcopy")
            for tool in (aapt2, objcopy):
                tool.parent.mkdir(parents=True, exist_ok=True)
                tool.write_text("#!/bin/sh\n", encoding="utf-8")
                tool.chmod(0o700)

            def recording_capture(argv, **kwargs):
                calls.append((list(argv), dict(kwargs)))
                if argv[:4] == ["git", "-C", str(repository), "cat-file"]:
                    return b""
                if argv[:4] == ["git", "-C", str(repository), "archive"]:
                    return _minimal_source_archive()
                if argv[0] == "./gradlew":
                    output = kwargs["cwd"] / "app/build/outputs/apk/debug/app-debug.apk"
                    output.parent.mkdir(parents=True)
                    output.write_bytes(apk)
                    return b""
                if Path(argv[0]) == aapt2:
                    return b"package: name='com.aprz.qbdiandroid' versionCode='1'\n"
                raise AssertionError(argv)

            with patch.dict(os.environ, {"ANDROID_HOME": str(android_home)}), \
                 patch.object(historical_benchmark, "capture_bounded", recording_capture), \
                 patch.object(historical_benchmark, "canonical_elf_sha256",
                              return_value=historical_benchmark.HISTORICAL_CANONICAL_TARGET_SHA256):
                result = historical_benchmark.build_historical_benchmark_apk(
                    repository, deadline=time.monotonic() + 10
                )
            try:
                self.assertEqual(hashlib.sha256(apk).hexdigest(), result.apk_sha256)
                self.assertEqual(hashlib.sha256(target).hexdigest(), result.target_raw_sha256)
                expected_root = Path(directory) / "expected-manifest"
                expected_root.mkdir()
                expected_manifest = historical_benchmark._extract_historical_archive(
                    _minimal_source_archive(), expected_root,
                )
                self.assertEqual(
                    tuple(tuple(item.items()) for item in expected_manifest),
                    getattr(result, "archive_manifest", None),
                )
                self.assertEqual(
                    hashlib.sha256(_minimal_source_archive()).hexdigest(),
                    getattr(result, "archive_sha256", None),
                )
                result.verify_path()
            finally:
                result.close()

        self.assertEqual([
            ["git", "-C", str(repository), "cat-file", "-e",
             f"{historical_benchmark.HISTORICAL_COMMIT}^{{commit}}"],
            ["git", "-C", str(repository), "archive", "--format=tar",
             historical_benchmark.HISTORICAL_COMMIT, "--", "app", "build.gradle",
             "settings.gradle", "gradle.properties", "gradlew", "gradle/wrapper"],
            ["./gradlew", ":app:assembleDebug", "--no-daemon", "--offline"],
            [str(aapt2), "dump", "badging", calls[3][0][3]],
        ], [call[0] for call in calls])
        self.assertNotEqual(repository, calls[2][1]["cwd"])
        self.assertLessEqual(calls[2][1]["timeout"], 900)


class HistoricalApkTests(unittest.TestCase):
    def _validate(self, root, apk_bytes, *, canonical=None, badging=None):
        apk_path = root / "app-debug.apk"
        apk_path.write_bytes(apk_bytes)
        android_home = root / "android"
        aapt2 = android_home / "build-tools/35.0.0/aapt2"
        aapt2.parent.mkdir(parents=True)
        aapt2.write_text("#!/bin/sh\n", encoding="utf-8")
        aapt2.chmod(0o700)
        observed = []

        def capture(argv, **kwargs):
            observed.append(list(argv))
            return badging or b"package: name='com.aprz.qbdiandroid' versionCode='1'\n"

        with patch.object(historical_benchmark, "capture_bounded", capture), \
             patch.object(historical_benchmark, "canonical_elf_sha256", return_value=(
                 canonical or historical_benchmark.HISTORICAL_CANONICAL_TARGET_SHA256
             )):
            validated = historical_benchmark._validate_historical_apk(
                apk_path, deadline=time.monotonic() + 5, android_home=android_home
            )
        return apk_path, validated, observed

    def test_validator_accepts_exact_pinned_aapt2_package_arm64_entry_and_canonical_identity(self):
        target = b"\x7fELFtarget"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apk = _apk_bytes(target)
            apk_path, validated, observed = self._validate(root, apk)
            self.assertEqual(
                [[str(root / "android/build-tools/35.0.0/aapt2"), "dump", "badging",
                  str(apk_path)]], observed
            )
            self.assertEqual(hashlib.sha256(apk).hexdigest(), validated["apk_sha256"])
            self.assertEqual(hashlib.sha256(target).hexdigest(), validated["target_raw_sha256"])
            self.assertEqual(historical_benchmark.HISTORICAL_CANONICAL_TARGET_SHA256,
                             validated["target_canonical_sha256"])

    def test_validator_rejects_wrong_package_missing_or_extra_abi_duplicate_target_bad_crc_and_runtime_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            missing_output = io.BytesIO()
            with zipfile.ZipFile(missing_output, "w") as archive:
                archive.writestr("assets/only", b"x")
            duplicate_output = io.BytesIO()
            with zipfile.ZipFile(duplicate_output, "w") as archive:
                archive.writestr("lib/arm64-v8a/libdemo_target.so", b"\x7fELFa")
                with self.assertWarns(UserWarning):
                    archive.writestr("lib/arm64-v8a/libdemo_target.so", b"\x7fELFb")
            corrupt = bytearray(_apk_bytes(b"\x7fELFcrc-target"))
            target_offset = corrupt.index(b"\x7fELFcrc-target")
            corrupt[target_offset + 5] ^= 1
            cases = [
                (_apk_bytes(b"\x7fELFx", abi="x86_64"), None),
                (_apk_bytes(b"\x7fELFx", extra=(("lib/x86_64/libdemo_target.so", b"x"),)), None),
                (_apk_bytes(b"\x7fELFx"), b"package: name='wrong.package'\n"),
                (missing_output.getvalue(), None),
                (duplicate_output.getvalue(), None),
                (bytes(corrupt), None),
                (_apk_bytes(b""), None),
            ]
            for index, (apk, badging) in enumerate(cases):
                with self.subTest(index=index), self.assertRaises(
                    historical_benchmark.HistoricalBenchmarkError
                ):
                    self._validate(root, apk, badging=badging)
                (root / "app-debug.apk").unlink(missing_ok=True)
                android = root / "android"
                if android.exists():
                    shutil.rmtree(android)

            runtime_path = root / "runtime.apk"
            runtime_path.write_bytes(_apk_bytes(b"\x7fELFruntime"))
            android_home = root / "runtime-android"
            aapt2 = android_home / "build-tools/35.0.0/aapt2"
            aapt2.parent.mkdir(parents=True)
            aapt2.write_text("#!/bin/sh\n", encoding="utf-8")
            aapt2.chmod(0o700)

            def mutate_after_badging(argv, **_kwargs):
                Path(argv[-1]).write_bytes(_apk_bytes(b"\x7fELFmutated"))
                return b"package: name='com.aprz.qbdiandroid'\n"

            with patch.object(historical_benchmark, "capture_bounded", mutate_after_badging), \
                 self.assertRaises(historical_benchmark.HistoricalBenchmarkError):
                historical_benchmark._validate_historical_apk(
                    runtime_path, deadline=time.monotonic() + 2,
                    android_home=android_home,
                )

    def test_validator_rejects_4097_entries_512_mib_plus_one_entry_128_mib_plus_one_and_target_64_mib_plus_one(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = _apk_bytes(b"\x7fELFx", extra=((f"assets/{index}", b"")
                                                    for index in range(5)))
            cases = [
                _apk_bytes(b"\x7fELFx", extra=((f"assets/{index}", b"")
                                                for index in range(4096))),
                _zip_with_declared_sizes(base, {"assets/0": 128 * 1024 * 1024 + 1}),
                _zip_with_declared_sizes(base, {
                    f"assets/{index}": 128 * 1024 * 1024 for index in range(4)
                } | {"assets/4": 1}),
                _apk_bytes(b"\x7fELF" + b"x" * (64 * 1024 * 1024 - 3)),
            ]
            for index, apk in enumerate(cases):
                with self.subTest(index=index), self.assertRaises(
                    historical_benchmark.HistoricalBenchmarkError
                ):
                    self._validate(root, apk)
                (root / "app-debug.apk").unlink(missing_ok=True)
                shutil.rmtree(root / "android")

    def test_held_apk_rejects_path_rebind_growth_symlink_empty_and_nonregular_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot = root / "snapshot"
            snapshot.mkdir()
            apk_path = snapshot / "historical.apk"
            apk = _apk_bytes(b"\x7fELFx")
            apk_path.write_bytes(apk)
            result = historical_benchmark.HistoricalBenchmarkApk(
                apk_path, hashlib.sha256(apk).hexdigest(), "a" * 64,
                historical_benchmark.HISTORICAL_CANONICAL_TARGET_SHA256,
            )
            replacement = root / "replacement.apk"
            replacement.write_bytes(apk)
            apk_path.rename(root / "original.apk")
            replacement.rename(apk_path)
            with self.assertRaises(historical_benchmark.HistoricalBenchmarkError):
                result.verify_path()
            result.close()
            result.close()
            self.assertFalse(snapshot.exists())

        for mutation in ("growth", "symlink", "empty", "fifo"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                snapshot = root / "snapshot"
                snapshot.mkdir()
                apk_path = snapshot / "historical.apk"
                apk = _apk_bytes(b"\x7fELFx")
                apk_path.write_bytes(apk)
                result = historical_benchmark.HistoricalBenchmarkApk(
                    apk_path, hashlib.sha256(apk).hexdigest(), "a" * 64,
                    historical_benchmark.HISTORICAL_CANONICAL_TARGET_SHA256,
                )
                if mutation == "growth":
                    with apk_path.open("ab") as output:
                        output.write(b"growth")
                else:
                    apk_path.unlink()
                    if mutation == "symlink":
                        apk_path.symlink_to(root / "missing")
                    elif mutation == "empty":
                        apk_path.write_bytes(b"")
                    else:
                        os.mkfifo(apk_path)
                with self.assertRaises(historical_benchmark.HistoricalBenchmarkError):
                    result.verify_path()
                result.close()

    def test_held_apk_blocking_open_and_read_hit_deadline_and_reap_workers(self):
        with tempfile.TemporaryDirectory() as directory:
            snapshot = Path(directory) / "snapshot"
            snapshot.mkdir()
            apk_path = snapshot / "historical.apk"
            apk = _apk_bytes(b"\x7fELFx")
            apk_path.write_bytes(apk)
            children_before = {child.pid for child in historical_benchmark.multiprocessing.active_children()}
            started = time.monotonic()
            with patch.object(historical_benchmark, "_worker_inspect_path",
                              _blocking_inspection_worker), \
                 patch.object(historical_benchmark, "FILE_WORKER_TIMEOUT", 0.05), \
                 self.assertRaisesRegex(
                     historical_benchmark.HistoricalBenchmarkError, "deadline"
                 ):
                historical_benchmark.HistoricalBenchmarkApk(
                    apk_path, hashlib.sha256(apk).hexdigest(), "a" * 64,
                    historical_benchmark.HISTORICAL_CANONICAL_TARGET_SHA256,
                )
            self.assertLess(time.monotonic() - started, 1)
            self.assertEqual(
                children_before,
                {child.pid for child in historical_benchmark.multiprocessing.active_children()},
            )

        started = time.monotonic()
        with self.assertRaises(historical_benchmark.HistoricalBenchmarkError):
            historical_benchmark._run_file_worker(
                _result_then_linger_worker, (), 0.05, phase="linger-probe"
            )
        self.assertLess(time.monotonic() - started, 0.3)

    def test_held_inspection_rejects_growth_and_truncation_during_hash(self):
        for mutation in ("growth", "truncation"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "held.apk"
                path.write_bytes(b"ab")
                descriptor = os.open(path, os.O_RDONLY)
                sender = _RecordingSender()
                original_pread = os.pread
                calls = 0

                def racing_pread(fd, size, offset):
                    nonlocal calls
                    data = original_pread(fd, size, offset)
                    calls += 1
                    if mutation == "growth" and calls == 1:
                        with path.open("ab") as output:
                            output.write(b"c")
                    if mutation == "truncation" and calls == 2:
                        os.truncate(path, 1)
                    return data

                try:
                    with patch.object(historical_benchmark.os, "pread",
                                      side_effect=racing_pread):
                        historical_benchmark._worker_inspect_path(
                            str(path), descriptor, sender
                        )
                finally:
                    os.close(descriptor)
                self.assertTrue(sender.closed)
                self.assertEqual(False, sender.messages[-1][0], sender.messages)

    def test_workers_cleanup_before_success_and_reject_nonzero_exit_after_message(self):
        started = time.monotonic()
        with self.assertRaisesRegex(
            historical_benchmark.HistoricalBenchmarkError, "exit"
        ):
            historical_benchmark._run_file_worker(
                _success_then_nonzero_worker, (), 0.5, phase="nonzero-probe"
            )
        self.assertLess(time.monotonic() - started, 1)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.apk"
            destination = root / "snapshot.apk"
            source.write_bytes(b"apk")
            descriptor = os.open(source, os.O_RDONLY)
            identity = os.fstat(descriptor)
            os.close(descriptor)
            original_close = historical_benchmark.os.close

            for worker, arguments in (
                (historical_benchmark._worker_inspect_path, (str(source), os.open(source, os.O_RDONLY))),
                (historical_benchmark._worker_copy_path, (str(source), str(destination))),
            ):
                with self.subTest(worker=worker.__name__):
                    sender = _RecordingSender()
                    failed = False

                    def fail_owned_close(owned_descriptor):
                        nonlocal failed
                        details = os.fstat(owned_descriptor)
                        original_close(owned_descriptor)
                        if (not failed and details.st_dev == identity.st_dev
                                and details.st_ino == identity.st_ino):
                            failed = True
                            raise OSError("injected worker descriptor cleanup failure")

                    try:
                        with patch.object(historical_benchmark.os, "close",
                                          side_effect=fail_owned_close):
                            worker(*arguments, sender)
                    finally:
                        if worker is historical_benchmark._worker_inspect_path:
                            original_close(arguments[1])
                        destination.unlink(missing_ok=True)
                    self.assertTrue(sender.closed)
                    self.assertEqual(False, sender.messages[-1][0], sender.messages)
                    self.assertIn("cleanup", sender.messages[-1][1])

    def test_apk_primary_validation_and_hold_errors_survive_descriptor_close_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apk_path = root / "app.apk"
            apk = _apk_bytes(b"\x7fELFx")
            apk_path.write_bytes(apk)
            identity = apk_path.stat()
            android_home = root / "android"
            aapt2 = android_home / "build-tools/35.0.0/aapt2"
            aapt2.parent.mkdir(parents=True)
            aapt2.write_text("#!/bin/sh\n", encoding="utf-8")
            aapt2.chmod(0o700)
            original_close = historical_benchmark.os.close
            parent_pid = os.getpid()

            def close_failure_once():
                failed = False

                def close(descriptor):
                    nonlocal failed
                    details = os.fstat(descriptor)
                    original_close(descriptor)
                    if (not failed and os.getpid() == parent_pid
                            and details.st_dev == identity.st_dev
                            and details.st_ino == identity.st_ino):
                        failed = True
                        raise OSError("injected APK descriptor close failure")
                return close

            with patch.object(
                historical_benchmark, "capture_bounded",
                return_value=b"package: name='com.aprz.qbdiandroid'\n",
            ), patch.object(
                historical_benchmark, "canonical_elf_sha256", return_value="0" * 64,
            ), patch.object(
                historical_benchmark.os, "close", side_effect=close_failure_once(),
            ), self.assertRaisesRegex(
                historical_benchmark.HistoricalBenchmarkError, "canonical"
            ) as validation:
                historical_benchmark._validate_historical_apk(
                    apk_path, deadline=time.monotonic() + 2,
                    android_home=android_home,
                )
            self.assertIn("cleanup", " ".join(validation.exception.report))

            apk_path.write_bytes(apk)
            with patch.object(
                historical_benchmark.os, "close", side_effect=close_failure_once(),
            ), self.assertRaisesRegex(
                historical_benchmark.HistoricalBenchmarkError, "SHA-256"
            ) as held:
                historical_benchmark.HistoricalBenchmarkApk(
                    apk_path, "0" * 64, "a" * 64,
                    historical_benchmark.HISTORICAL_CANONICAL_TARGET_SHA256,
                )
            self.assertIn("cleanup", " ".join(held.exception.report))

    def test_builder_preserves_primary_and_all_descriptor_tree_and_command_cleanup_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repository"
            repository.mkdir()
            original_close = historical_benchmark.os.close
            original_rmtree = historical_benchmark.shutil.rmtree
            repository_identity = repository.stat()

            def capture(argv, **_kwargs):
                if argv[3] == "cat-file":
                    return b""
                if argv[3] == "archive":
                    return _minimal_source_archive()
                raise RuntimeError("offline dependency missing")

            close_failed = False
            tree_failed = False

            def fail_repository_close(descriptor):
                nonlocal close_failed
                details = os.fstat(descriptor)
                original_close(descriptor)
                if (not close_failed and details.st_dev == repository_identity.st_dev
                        and details.st_ino == repository_identity.st_ino):
                    close_failed = True
                    raise OSError("injected repository close failure")

            def fail_build_tree(path, *args, **kwargs):
                nonlocal tree_failed
                original_rmtree(path, *args, **kwargs)
                if not tree_failed and Path(path).name.startswith("qtrace-historical-build-"):
                    tree_failed = True
                    raise OSError("injected build tree cleanup failure")

            with patch.object(historical_benchmark, "capture_bounded", capture), \
                 patch.object(historical_benchmark.os, "close",
                              side_effect=fail_repository_close), \
                 patch.object(historical_benchmark.shutil, "rmtree",
                              side_effect=fail_build_tree), \
                 self.assertRaisesRegex(
                historical_benchmark.HistoricalBenchmarkError,
                "offline dependency missing",
            ) as caught:
                historical_benchmark.build_historical_benchmark_apk(
                    repository, deadline=time.monotonic() + 1
                )
            self.assertEqual("gradle", caught.exception.report["phase"])
            diagnostics = caught.exception.report["cleanup_failures"]
            self.assertTrue(any("repository close" in item for item in diagnostics))
            self.assertTrue(any("build tree cleanup" in item for item in diagnostics))
            self.assertTrue(close_failed and tree_failed)

    def test_builder_success_does_not_hide_repository_descriptor_cleanup_failure(self):
        target = b"\x7fELFhistorical-target"
        apk = _apk_bytes(target)
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repository"
            repository.mkdir()
            repository_identity = repository.stat()
            android_home = Path(directory) / "android"
            aapt2 = android_home / "build-tools/35.0.0/aapt2"
            aapt2.parent.mkdir(parents=True)
            aapt2.write_text("#!/bin/sh\n", encoding="utf-8")
            aapt2.chmod(0o700)
            original_close = historical_benchmark.os.close
            close_failed = False

            def capture(argv, **kwargs):
                if argv[3] == "cat-file":
                    return b""
                if argv[3] == "archive":
                    return _minimal_source_archive()
                if argv[0] == "./gradlew":
                    output = kwargs["cwd"] / "app/build/outputs/apk/debug/app-debug.apk"
                    output.parent.mkdir(parents=True)
                    output.write_bytes(apk)
                    return b""
                if Path(argv[0]) == aapt2:
                    return b"package: name='com.aprz.qbdiandroid'\n"
                raise AssertionError(argv)

            def fail_repository_close(descriptor):
                nonlocal close_failed
                details = os.fstat(descriptor)
                original_close(descriptor)
                if (not close_failed and details.st_dev == repository_identity.st_dev
                        and details.st_ino == repository_identity.st_ino):
                    close_failed = True
                    raise OSError("injected successful-build repository close failure")

            with patch.dict(os.environ, {"ANDROID_HOME": str(android_home)}), \
                 patch.object(historical_benchmark, "capture_bounded", capture), \
                 patch.object(historical_benchmark, "canonical_elf_sha256",
                              return_value=historical_benchmark.HISTORICAL_CANONICAL_TARGET_SHA256), \
                 patch.object(historical_benchmark.os, "close",
                              side_effect=fail_repository_close), \
                 self.assertRaisesRegex(
                     historical_benchmark.HistoricalBenchmarkError, "cleanup"
                 ) as caught:
                historical_benchmark.build_historical_benchmark_apk(
                    repository, deadline=time.monotonic() + 5
                )
            self.assertTrue(close_failed)
            self.assertIn("repository descriptor", caught.exception.report["cleanup_failures"][0])

    def test_missing_commit_pinned_tools_or_offline_dependency_fails_without_installable_result(self):
        temporary_root = Path(tempfile.gettempdir())

        def private_roots():
            return {
                path for pattern in ("qtrace-historical-build-*", "qtrace-historical-apk-*")
                for path in temporary_root.glob(pattern)
            }

        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repository"
            repository.mkdir()
            android_home = Path(directory) / "android"
            apk = _apk_bytes(b"\x7fELFhistorical-target")

            def capture(*, fail_gradle=False):
                def run(argv, **kwargs):
                    if argv[3] == "cat-file":
                        return b""
                    if argv[3] == "archive":
                        return _minimal_source_archive()
                    if argv[0] == "./gradlew":
                        if fail_gradle:
                            raise RuntimeError("offline dependency unavailable")
                        output = kwargs["cwd"] / "app/build/outputs/apk/debug/app-debug.apk"
                        output.parent.mkdir(parents=True)
                        output.write_bytes(apk)
                        return b""
                    if argv[1:3] == ["dump", "badging"]:
                        return b"package: name='com.aprz.qbdiandroid'\n"
                    raise AssertionError(argv)
                return run

            scenarios = [
                (RuntimeError("missing commit"), android_home, "missing commit"),
                (capture(fail_gradle=True), android_home, "offline dependency"),
                (capture(), android_home, "pinned aapt2"),
            ]
            for fake_capture, configured_home, message in scenarios:
                before = private_roots()
                with self.subTest(message=message), patch.dict(
                    os.environ, {"ANDROID_HOME": str(configured_home)}
                ), patch.object(
                    historical_benchmark, "capture_bounded",
                    side_effect=(fake_capture if isinstance(fake_capture, BaseException) else None),
                    wraps=(fake_capture if callable(fake_capture) else None),
                ), self.assertRaisesRegex(
                    historical_benchmark.HistoricalBenchmarkError, message
                ):
                    historical_benchmark.build_historical_benchmark_apk(
                        repository, deadline=time.monotonic() + 5
                    )
                self.assertEqual(before, private_roots())

            aapt2 = android_home / "build-tools/35.0.0/aapt2"
            aapt2.parent.mkdir(parents=True)
            aapt2.write_text("#!/bin/sh\n", encoding="utf-8")
            aapt2.chmod(0o700)
            before = private_roots()
            with patch.dict(os.environ, {"ANDROID_HOME": str(android_home)}), \
                 patch.object(historical_benchmark, "capture_bounded",
                              side_effect=capture()), \
                 self.assertRaisesRegex(
                     historical_benchmark.HistoricalBenchmarkError, "llvm-objcopy"
                 ):
                historical_benchmark.build_historical_benchmark_apk(
                    repository, deadline=time.monotonic() + 5
                )
            self.assertEqual(before, private_roots())


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

    def test_missing_android_home_does_not_select_a_cwd_relative_tool(self):
        with patch.dict(os.environ, {"ANDROID_HOME": ""}, clear=False), \
             self.assertRaisesRegex(ValueError, "ANDROID_HOME is required"):
            historical_benchmark._pinned_objcopy(None)

    def test_invalid_canonical_outputs_raise_and_cleanup_the_temporary_directory(self):
        for output, message in (
                (b"", "empty"), (b"not elf", "ELF"),
                (b"\x7fELF" + b"x" * (64 * 1024 * 1024 - 3), "64 MiB")):
            with self.subTest(message=message), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                tool = (root / "ndk" / "26.1.10909125" / "toolchains" / "llvm" /
                        "prebuilt" / "linux-x86_64" / "bin" / "llvm-objcopy")
                tool.parent.mkdir(parents=True)
                tool.write_text("#! /bin/sh\n", encoding="utf-8")
                tool.chmod(0o700)
                destinations: list[Path] = []

                def write_output(argv, **_kwargs):
                    destination = Path(argv[-1])
                    destinations.append(destination.parent)
                    destination.write_bytes(output)
                    return b""

                with self.assertRaisesRegex(ValueError, message):
                    canonical_elf_sha256(b"\x7fELFinput", deadline=time.monotonic() + 1,
                                         android_home=root, capture=write_output)
                self.assertTrue(destinations)
                self.assertFalse(destinations[0].exists())

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tool = (root / "ndk" / "26.1.10909125" / "toolchains" / "llvm" /
                    "prebuilt" / "linux-x86_64" / "bin" / "llvm-objcopy")
            tool.parent.mkdir(parents=True)
            tool.write_text("#! /bin/sh\n", encoding="utf-8")
            tool.chmod(0o700)
            destinations: list[Path] = []

            def valid_output(argv, **_kwargs):
                destination = Path(argv[-1])
                destinations.append(destination.parent)
                destination.write_bytes(b"\x7fELFcanonical")
                return b""

            with patch.object(historical_benchmark.time, "monotonic",
                              side_effect=[100.0, 100.0, 101.0]), \
                 self.assertRaisesRegex(ValueError, "deadline"):
                canonical_elf_sha256(b"\x7fELFinput", deadline=101.0,
                                     android_home=root, capture=valid_output)
            self.assertTrue(destinations)
            self.assertFalse(destinations[0].exists())
