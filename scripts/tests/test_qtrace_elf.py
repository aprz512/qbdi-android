import math
import stat
import tempfile
import unittest
import zipfile
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from qtrace.elf import ElfInspector, TargetResolver
from qtrace.errors import QtraceError
from qtrace.models import (
    AppConfig,
    ElfIdentity,
    OffsetScene,
    ResolvedScene,
    SymbolScene,
    TargetConfig,
    TracerConfig,
    UserConfig,
)


ARM64_READELF = """\
ELF Header:
  Class:                             ELF64
  Machine:                           AArch64

Displaying notes found in: .note.gnu.build-id
  Owner                Data size  Description
  GNU                  0x00000014 NT_GNU_BUILD_ID (unique build ID bitstring)
    Build ID: AABBCCDDEEFF00112233445566778899AABBCCDD

Program Headers:
  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
  LOAD           0x000000 0x0000000000000000 0x0000000000000000 0x000100 0x000100 R   0x1000
  LOAD           0x000100 0x0000000000000100 0x0000000000000100 0x000300 0x000300 R E 0x1000
  LOAD           0x000400 0x0000000000000400 0x0000000000000400 0x000100 0x000180 RW  0x1000
"""

NONZERO_BIAS_READELF = """\
ELF Header:
  Class:                             ELF64
  Machine:                           AArch64

Displaying notes found in: .note.gnu.build-id
  Owner                Data size  Description
  GNU                  0x00000014 NT_GNU_BUILD_ID (unique build ID bitstring)
    Build ID: AABBCCDDEEFF00112233445566778899AABBCCDD

Program Headers:
  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
  LOAD           0x000000 0x0000000000010000 0x0000000000010000 0x000100 0x000100 R   0x1000
  LOAD           0x000100 0x0000000000010100 0x0000000000010100 0x000300 0x000300 R E 0x1000
"""

NDK28_READELF = """\
ELF Header:
  Class:                             ELF64
  Machine:                           AArch64

Displaying notes found in: .note.gnu.build-id
  Owner                Data size  Description
  GNU                  0x00000014 NT_GNU_BUILD_ID (unique build ID bitstring)
    Build ID: AABBCCDDEEFF00112233445566778899AABBCCDD

Program Headers:
  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
  LOAD           0x000000 0x0000000000000000 0x0000000000000000 0x000400 0x000400 R   0x1000
  LOAD           0x001000 0x0000000000001000 0x0000000000001000 0x000400 0x000400 R E 0x1000
  LOAD           0x002000 0x0000000000006000 0x0000000000006000 0x000200 0x000300 RW  0x1000
  LOAD           0x003000 0x000000000000b000 0x000000000000b000 0x000100 0x000180 RW  0x1000
"""


@dataclass(frozen=True)
class RunnerCall:
    command: tuple[str, ...]
    maximum_bytes: int
    timeout: float


class FakeRunner:
    def __init__(
        self,
        *,
        readelf=ARM64_READELF,
        nm="do_work T 120 40\n",
        readelf_by_content=None,
        nm_by_content=None,
    ):
        self._readelf = self._outputs(readelf)
        self._nm = self._outputs(nm)
        self._readelf_by_content = dict(readelf_by_content or {})
        self._nm_by_content = dict(nm_by_content or {})
        self.calls: list[RunnerCall] = []

    @staticmethod
    def _outputs(value):
        values = value if isinstance(value, (list, tuple)) else [value]
        return deque(item.encode("utf-8") if isinstance(item, str) else item for item in values)

    @staticmethod
    def _take(queue, tool):
        if not queue:
            raise AssertionError(f"unexpected extra {tool} command")
        if len(queue) == 1:
            return queue[0]
        return queue.popleft()

    def capture(self, command, *, maximum_bytes, timeout):
        if isinstance(command, (str, bytes)):
            raise AssertionError("commands must be argument arrays")
        command = tuple(command)
        if not isinstance(maximum_bytes, int) or not 0 < maximum_bytes <= 1_048_576:
            raise AssertionError("command output must have a finite bound")
        if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise AssertionError("command timeout must be finite")
        self.calls.append(RunnerCall(command, maximum_bytes, float(timeout)))

        if len(command) < 2:
            raise AssertionError(f"unexpected command: {command!r}")
        binary = Path(command[-1])
        try:
            marker = binary.read_bytes()
        except OSError:
            marker = None
        if command[:-1] == ("/ndk bin/llvm-readelf", "-h", "-n", "-lW"):
            if marker in self._readelf_by_content:
                return self._readelf_by_content[marker]
            return self._take(self._readelf, "readelf")
        if command[:-1] == (
            "/ndk bin/llvm-nm",
            "-S",
            "--defined-only",
            "--format=posix",
        ):
            if marker in self._nm_by_content:
                return self._nm_by_content[marker]
            return self._take(self._nm, "nm")
        raise AssertionError(f"unexpected command: {command!r}")


class FakeDevice:
    def __init__(self, members=None, *, paths=None):
        self.member = "lib/arm64-v8a/libtarget.so"
        if members is None:
            members = {"/data/app/base.apk": {self.member: b"device"}}
        self.members = members
        self.paths = tuple(paths if paths is not None else members)
        self.package_calls: list[str] = []
        self.pull_calls: list[tuple[str, str, Path]] = []

    def package_apk_paths(self, package):
        self.package_calls.append(package)
        return self.paths

    def pull_member(self, apk_path, member, destination):
        self.pull_calls.append((apk_path, member, destination))
        content = self.members.get(apk_path, {}).get(member)
        if content is None:
            raise FileNotFoundError(member)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
        return destination


class ProviderBoundaryFake:
    def __init__(
        self,
        *,
        package_result=("/data/app/base.apk",),
        package_error=None,
        pull_result=None,
        pull_error=None,
    ):
        self.package_result = package_result
        self.package_error = package_error
        self.pull_result = pull_result
        self.pull_error = pull_error

    def package_apk_paths(self, _package):
        if self.package_error is not None:
            raise self.package_error
        return self.package_result

    def pull_member(self, _apk_path, _member, _destination):
        if self.pull_error is not None:
            raise self.pull_error
        return self.pull_result


def config_with_scene(scene, *, binary=None, apk=None):
    return UserConfig(
        schema_version=1,
        app=AppConfig(package="com.example.external", apk=apk),
        target=TargetConfig(module="libtarget.so", binary=binary),
        tracer=TracerConfig(
            profile="fast",
            compression=True,
            flight_enabled=False,
            flight_entry_scene=None,
            library=None,
            companion=None,
        ),
        scenes=(scene,),
    )


def readelf_with(*, elf_class="ELF64", machine="AArch64", build_id=None):
    text = ARM64_READELF.replace("ELF64", elf_class, 1).replace("AArch64", machine, 1)
    if build_id is not None:
        text = text.replace("AABBCCDDEEFF00112233445566778899AABBCCDD", build_id)
    return text


class ElfInspectorTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="qtrace elf tests ")
        self.addCleanup(self.directory.cleanup)
        self.binary = Path(self.directory.name) / "target binary.so"
        self.binary.write_bytes(b"target")

    def inspector(self, **runner_arguments):
        runner = FakeRunner(**runner_arguments)
        return ElfInspector(runner, Path("/ndk bin")), runner

    def assert_error(self, code, callback):
        with self.assertRaises(QtraceError) as caught:
            callback()
        self.assertEqual(code, caught.exception.code)
        self.assertTrue(caught.exception.stage.startswith("target."))

    def test_inspect_parses_normalized_identity_and_exact_bounded_command(self):
        inspector, runner = self.inspector()

        identity = inspector.inspect(self.binary)

        self.assertEqual(
            ElfIdentity(
                elf_class="ELF64",
                machine="AArch64",
                build_id="aabbccddeeff00112233445566778899aabbccdd",
                executable_ranges=((0x100, 0x400),),
            ),
            identity,
        )
        self.assertEqual(
            ("/ndk bin/llvm-readelf", "-h", "-n", "-lW", str(self.binary)),
            runner.calls[0].command,
        )
        self.assertGreater(runner.calls[0].timeout, 0)
        self.assertGreater(runner.calls[0].maximum_bytes, 0)

    def test_nonzero_elf_load_bias_is_removed_from_ranges_and_symbols(self):
        inspector, _runner = self.inspector(
            readelf=[NONZERO_BIAS_READELF, NONZERO_BIAS_READELF],
            nm="biased T 10120 40\n",
        )

        self.assertEqual(((0x100, 0x400),), inspector.inspect(self.binary).executable_ranges)
        self.assertEqual((0x120, 0x160), inspector.symbol_range(self.binary, "biased"))

    def test_ndk28_nonexecuting_segment_biases_do_not_change_scene_offsets(self):
        inspector, _runner = self.inspector(
            readelf=[NDK28_READELF, NDK28_READELF],
            nm="work T 1120 40\n",
        )

        self.assertEqual(((0x1000, 0x1400),), inspector.inspect(self.binary).executable_ranges)
        self.assertEqual((0x1120, 0x1160), inspector.symbol_range(self.binary, "work"))

    def test_symbol_types_t_and_weak_text_are_accepted(self):
        for symbol_type in ("T", "t", "W", "w"):
            with self.subTest(symbol_type=symbol_type):
                inspector, _runner = self.inspector(
                    readelf=ARM64_READELF,
                    nm=f"work {symbol_type} 120 40\n",
                )
                self.assertEqual((0x120, 0x160), inspector.symbol_range(self.binary, "work"))

    def test_symbol_lookup_rejects_missing_undefined_data_and_zero_size(self):
        cases = (
            ("other T 120 40\n", "target.symbol_not_found"),
            ("work U 120 40\n", "target.symbol_type_invalid"),
            ("work D 120 40\n", "target.symbol_type_invalid"),
            ("work T 120 0\n", "target.symbol_size_invalid"),
        )
        for nm, code in cases:
            with self.subTest(nm=nm):
                inspector, _runner = self.inspector(nm=nm)
                self.assert_error(code, lambda: inspector.symbol_range(self.binary, "work"))

    def test_symbol_lookup_rejects_duplicate_and_malformed_matching_rows(self):
        for nm, code in (
            ("work T 120 40\nwork t 160 20\n", "target.symbol_ambiguous"),
            ("work T xyz 40\n", "target.nm_malformed"),
            ("work T 120\n", "target.nm_malformed"),
        ):
            with self.subTest(nm=nm):
                inspector, _runner = self.inspector(nm=nm)
                self.assert_error(code, lambda: inspector.symbol_range(self.binary, "work"))

    def test_symbol_lookup_rejects_unaligned_overflow_and_outside_executable_range(self):
        cases = (
            ("work T 121 40\n", "target.symbol_alignment_invalid"),
            ("work T 120 41\n", "target.symbol_alignment_invalid"),
            ("work T fffffffffffffffc 8\n", "target.symbol_overflow"),
            ("work T 3e0 40\n", "target.scene_not_executable"),
        )
        for nm, code in cases:
            with self.subTest(nm=nm):
                inspector, _runner = self.inspector(nm=nm)
                self.assert_error(code, lambda: inspector.symbol_range(self.binary, "work"))

    def test_symbol_range_may_touch_both_executable_boundaries(self):
        inspector, _runner = self.inspector(nm="work T 100 300\n")
        self.assertEqual((0x100, 0x400), inspector.symbol_range(self.binary, "work"))

    def test_inspect_rejects_wrong_architecture_missing_or_repeated_build_id(self):
        missing = ARM64_READELF.replace(
            "    Build ID: AABBCCDDEEFF00112233445566778899AABBCCDD\n", ""
        )
        repeated = ARM64_READELF.replace(
            "    Build ID: AABBCCDDEEFF00112233445566778899AABBCCDD",
            "    Build ID: AABB\n    Build ID: CCDD",
        )
        cases = (
            (readelf_with(elf_class="ELF32"), "target.elf_class_unsupported"),
            (readelf_with(machine="ARM"), "target.machine_unsupported"),
            (missing, "target.build_id_missing"),
            (repeated, "target.build_id_ambiguous"),
        )
        for output, code in cases:
            with self.subTest(code=code):
                inspector, _runner = self.inspector(readelf=output)
                self.assert_error(code, lambda: inspector.inspect(self.binary))

    def test_inspect_normalizes_lowercase_and_uppercase_build_ids(self):
        for build_id in ("abcdef012345", "ABCDEF012345"):
            with self.subTest(build_id=build_id):
                inspector, _runner = self.inspector(readelf=readelf_with(build_id=build_id))
                self.assertEqual("abcdef012345", inspector.inspect(self.binary).build_id)

    def test_inspect_rejects_invalid_utf8_and_malformed_or_repeated_fields(self):
        repeated_class = ARM64_READELF.replace(
            "  Class:                             ELF64",
            "  Class:                             ELF64\n  Class: ELF64",
        )
        repeated_note = ARM64_READELF.replace(
            "  GNU                  0x00000014 NT_GNU_BUILD_ID (unique build ID bitstring)",
            "  GNU 0x14 NT_GNU_BUILD_ID\n  GNU 0x14 NT_GNU_BUILD_ID",
        )
        malformed_load = ARM64_READELF.replace(
            "  LOAD           0x000100 0x0000000000000100 0x0000000000000100 0x000300 0x000300 R E 0x1000",
            "  LOAD           0x000100 0x0000000000000100 broken",
        )
        repeated_load = ARM64_READELF.replace(
            "  LOAD           0x000000 0x0000000000000000 0x0000000000000000 0x000100 0x000100 R   0x1000",
            "  LOAD           0x000000 0x0000000000000000 0x0000000000000000 0x000100 0x000100 R   0x1000\n"
            "  LOAD           0x000000 0x0000000000000000 0x0000000000000000 0x000100 0x000100 R   0x1000",
        )
        ambiguous_executable_bias = ARM64_READELF.replace(
            "0x0000000000000400 0x0000000000000400 0x000100 0x000180 RW",
            "0x0000000000001400 0x0000000000001400 0x000100 0x000180 R E",
        )
        cases = (
            (b"\xff\xfe", "target.tool_output_invalid"),
            (repeated_class, "target.header_ambiguous"),
            (repeated_note, "target.build_id_ambiguous"),
            (malformed_load, "target.program_header_malformed"),
            (repeated_load, "target.program_header_ambiguous"),
            (ambiguous_executable_bias, "target.load_bias_ambiguous"),
        )
        for output, code in cases:
            with self.subTest(code=code):
                inspector, _runner = self.inspector(readelf=output)
                self.assert_error(code, lambda: inspector.inspect(self.binary))

    def test_inspect_rejects_executable_range_overflow_and_empty_ranges(self):
        overflow = ARM64_READELF.replace(
            "0x0000000000000100 0x0000000000000100 0x000300 0x000300 R E",
            "0xfffffffffffffff0 0xfffffffffffffff0 0x000010 0x000020 R E",
        )
        empty = ARM64_READELF.replace("0x000300 R E 0x1000", "0x000300 R   0x1000")
        for output, code in (
            (overflow, "target.program_header_overflow"),
            (empty, "target.executable_range_missing"),
        ):
            with self.subTest(code=code):
                inspector, _runner = self.inspector(readelf=output)
                self.assert_error(code, lambda: inspector.inspect(self.binary))


class TargetResolverTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="qtrace resolver tests ")
        self.addCleanup(self.directory.cleanup)
        self.host_binary = Path(self.directory.name) / "host symbols.so"
        self.host_binary.write_bytes(b"host")

    def resolver(self, runner=None, device=None):
        runner = runner or FakeRunner()
        device = device or FakeDevice()
        return TargetResolver(ElfInspector(runner, Path("/ndk bin")), device), runner, device

    def assert_error(self, code, callback):
        with self.assertRaises(QtraceError) as caught:
            callback()
        self.assertEqual(code, caught.exception.code)
        self.assertTrue(caught.exception.stage.startswith("target."))

    def test_unique_text_symbol_resolves_to_half_open_module_offsets(self):
        runner = FakeRunner(readelf=ARM64_READELF, nm="do_work T 120 40\n")
        resolved = TargetResolver(
            ElfInspector(runner, Path("/ndk bin")), FakeDevice()
        ).resolve(config_with_scene(SymbolScene("work", "do_work")))

        self.assertEqual((ResolvedScene("work", 0x120, 0x160),), resolved.scenes)
        self.assertEqual("com.example.external", resolved.package)
        self.assertEqual("libtarget.so", resolved.module)
        self.assertEqual(
            "/data/app/base.apk!/lib/arm64-v8a/libtarget.so", resolved.device_binary
        )
        self.assertTrue(resolved.host_binary.is_file())

    def test_scene_order_is_preserved_for_symbol_and_explicit_ranges(self):
        resolver, _runner, _device = self.resolver(
            FakeRunner(nm="second T 180 20\n")
        )
        config = config_with_scene(OffsetScene("first", 0x100, 0x120))
        config = UserConfig(
            schema_version=config.schema_version,
            app=config.app,
            target=config.target,
            tracer=config.tracer,
            scenes=(
                OffsetScene("first", 0x100, 0x120),
                SymbolScene("second", "second"),
                OffsetScene("third", 0x3E0, 0x400),
            ),
        )

        resolved = resolver.resolve(config)

        self.assertEqual(
            (
                ResolvedScene("first", 0x100, 0x120),
                ResolvedScene("second", 0x180, 0x1A0),
                ResolvedScene("third", 0x3E0, 0x400),
            ),
            resolved.scenes,
        )

    def test_explicit_range_must_be_wholly_contained_and_aligned(self):
        cases = (
            (OffsetScene("outside", 0x0FC, 0x120), "target.scene_not_executable"),
            (OffsetScene("outside", 0x3E0, 0x404), "target.scene_not_executable"),
            (OffsetScene("unaligned", 0x101, 0x120), "target.scene_alignment_invalid"),
            (OffsetScene("reversed", 0x180, 0x180), "target.scene_range_invalid"),
        )
        for scene, code in cases:
            with self.subTest(scene=scene):
                resolver, _runner, _device = self.resolver()
                self.assert_error(code, lambda: resolver.resolve(config_with_scene(scene)))

    def test_host_binary_and_installed_device_identity_match_before_resolution(self):
        runner = FakeRunner(
            readelf_by_content={
                b"host": ARM64_READELF.encode(),
                b"device": readelf_with(build_id="aabbccddeeff00112233445566778899aabbccdd").encode(),
            },
            nm_by_content={b"host": b"work T 120 40\n"},
        )
        resolver, _runner, device = self.resolver(runner)

        resolved = resolver.resolve(
            config_with_scene(SymbolScene("work", "work"), binary=self.host_binary)
        )

        self.assertEqual(self.host_binary, resolved.host_binary)
        self.assertEqual(["com.example.external"], device.package_calls)
        self.assertEqual(1, len(device.pull_calls))
        self.assertEqual(
            "aabbccddeeff00112233445566778899aabbccdd", resolved.identity.build_id
        )

    def test_identity_rejects_class_machine_and_build_id_mismatches(self):
        device_outputs = (
            readelf_with(elf_class="ELF32"),
            readelf_with(machine="ARM"),
            readelf_with(build_id="001122334455"),
        )
        for device_output in device_outputs:
            with self.subTest(device_output=device_output.splitlines()[2]):
                runner = FakeRunner(
                    readelf_by_content={
                        b"host": ARM64_READELF.encode(),
                        b"device": device_output.encode(),
                    }
                )
                resolver, _runner, _device = self.resolver(runner)
                self.assert_error(
                    "target.identity_mismatch",
                    lambda: resolver.resolve(
                        config_with_scene(
                            OffsetScene("range", 0x100, 0x120),
                            binary=self.host_binary,
                        )
                    ),
                )

    def test_missing_device_build_id_uses_stable_error(self):
        missing_build = ARM64_READELF.replace(
            "    Build ID: AABBCCDDEEFF00112233445566778899AABBCCDD\n", ""
        )
        runner = FakeRunner(
            readelf_by_content={b"host": ARM64_READELF.encode(), b"device": missing_build.encode()}
        )
        resolver, _runner, _device = self.resolver(runner)
        self.assert_error(
            "target.build_id_missing",
            lambda: resolver.resolve(
                config_with_scene(
                    OffsetScene("range", 0x100, 0x120), binary=self.host_binary
                )
            ),
        )

    def test_installed_split_apk_selects_the_unique_matching_member(self):
        member = "lib/arm64-v8a/libtarget.so"
        device = FakeDevice(
            {
                "/data/app/base.apk": {},
                "/data/app/split_config.arm64_v8a.apk": {member: b"split-device"},
            }
        )
        runner = FakeRunner(
            readelf_by_content={b"split-device": ARM64_READELF.encode()},
            nm_by_content={b"split-device": b"work T 120 40\n"},
        )
        resolver, _runner, _device = self.resolver(runner, device)

        resolved = resolver.resolve(config_with_scene(SymbolScene("work", "work")))

        self.assertEqual(
            "/data/app/split_config.arm64_v8a.apk!/lib/arm64-v8a/libtarget.so",
            resolved.device_binary,
        )

    def test_installed_module_rejects_no_match_and_multiple_matches(self):
        member = "lib/arm64-v8a/libtarget.so"
        cases = (
            (FakeDevice({"/data/app/base.apk": {}}), "target.module_not_found"),
            (
                FakeDevice(
                    {
                        "/data/app/base.apk": {member: b"one"},
                        "/data/app/split.apk": {member: b"two"},
                    }
                ),
                "target.module_ambiguous",
            ),
        )
        for device, code in cases:
            with self.subTest(code=code):
                resolver, _runner, _device = self.resolver(FakeRunner(), device)
                self.assert_error(
                    code,
                    lambda: resolver.resolve(
                        config_with_scene(OffsetScene("range", 0x100, 0x120))
                    ),
                )

    def write_apk(self, name, entries):
        apk = Path(self.directory.name) / name
        with zipfile.ZipFile(apk, "w") as archive:
            for entry in entries:
                archive.writestr(entry[0], entry[1])
        return apk

    def test_configured_apk_arm64_member_is_host_source_and_survives_resolution(self):
        apk = self.write_apk(
            "configured app.apk", [("lib/arm64-v8a/libtarget.so", b"apk-host")]
        )
        runner = FakeRunner(
            readelf_by_content={
                b"apk-host": ARM64_READELF.encode(),
                b"device": ARM64_READELF.encode(),
            },
            nm_by_content={b"apk-host": b"work T 120 40\n"},
        )
        resolver, _runner, _device = self.resolver(runner)

        resolved = resolver.resolve(
            config_with_scene(SymbolScene("work", "work"), apk=apk)
        )

        self.assertTrue(resolved.host_binary.is_file())
        self.assertEqual(b"apk-host", resolved.host_binary.read_bytes())
        self.assertNotEqual(apk, resolved.host_binary)

    def test_configured_apk_rejects_wrong_abi_traversal_symlink_and_corruption(self):
        wrong_abi = self.write_apk(
            "wrong.apk", [("lib/armeabi-v7a/libtarget.so", b"wrong")]
        )
        traversal = self.write_apk(
            "traversal.apk",
            [
                ("../outside", b"bad"),
                ("lib/arm64-v8a/libtarget.so", b"target"),
            ],
        )
        symlink = Path(self.directory.name) / "symlink.apk"
        with zipfile.ZipFile(symlink, "w") as archive:
            info = zipfile.ZipInfo("lib/arm64-v8a/libtarget.so")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, "../../outside")
        corrupt = Path(self.directory.name) / "corrupt.apk"
        corrupt.write_bytes(b"not a zip")

        for apk, code in (
            (wrong_abi, "target.module_wrong_abi"),
            (traversal, "target.apk_member_unsafe"),
            (symlink, "target.apk_member_unsafe"),
            (corrupt, "target.apk_invalid"),
        ):
            with self.subTest(apk=apk.name):
                resolver, _runner, _device = self.resolver()
                self.assert_error(
                    code,
                    lambda: resolver.resolve(
                        config_with_scene(
                            OffsetScene("range", 0x100, 0x120), apk=apk
                        )
                    ),
                )

    def test_rejects_unsafe_module_name_before_device_access(self):
        config = config_with_scene(OffsetScene("range", 0x100, 0x120))
        config = UserConfig(
            schema_version=config.schema_version,
            app=config.app,
            target=TargetConfig(module="../libtarget.so", binary=None),
            tracer=config.tracer,
            scenes=config.scenes,
        )
        resolver, _runner, device = self.resolver()

        self.assert_error("target.module_name_invalid", lambda: resolver.resolve(config))
        self.assertEqual([], device.package_calls)

    def test_device_provider_paths_and_returned_files_are_validated(self):
        invalid_path = FakeDevice(paths=("/data/app/base.apk\nmalicious",))
        resolver, _runner, _device = self.resolver(FakeRunner(), invalid_path)
        self.assert_error(
            "target.device_query_failed",
            lambda: resolver.resolve(
                config_with_scene(OffsetScene("range", 0x100, 0x120))
            ),
        )

    def test_device_package_query_exceptions_and_invalid_returns_are_stable(self):
        invalid_results = (None, "/data/app/base.apk", 7, ["/data/app/base.apk"], (None,))
        for package_result in invalid_results:
            with self.subTest(package_result=package_result):
                resolver, _runner, _device = self.resolver(
                    FakeRunner(), ProviderBoundaryFake(package_result=package_result)
                )
                self.assert_error(
                    "target.device_query_failed",
                    lambda: resolver.resolve(
                        config_with_scene(OffsetScene("range", 0x100, 0x120))
                    ),
                )

        for package_error in (ValueError("bad paths"), TypeError("bad paths")):
            with self.subTest(package_error=type(package_error).__name__):
                resolver, _runner, _device = self.resolver(
                    FakeRunner(), ProviderBoundaryFake(package_error=package_error)
                )
                self.assert_error(
                    "target.device_query_failed",
                    lambda: resolver.resolve(
                        config_with_scene(OffsetScene("range", 0x100, 0x120))
                    ),
                )

    def test_device_member_exceptions_and_invalid_returns_are_stable(self):
        for pull_error in (ValueError("bad member"), TypeError("bad member")):
            with self.subTest(pull_error=type(pull_error).__name__):
                resolver, _runner, _device = self.resolver(
                    FakeRunner(), ProviderBoundaryFake(pull_error=pull_error)
                )
                self.assert_error(
                    "target.device_member_invalid",
                    lambda: resolver.resolve(
                        config_with_scene(OffsetScene("range", 0x100, 0x120))
                    ),
                )

        for pull_result in (None, object()):
            with self.subTest(pull_result=type(pull_result).__name__):
                resolver, _runner, _device = self.resolver(
                    FakeRunner(), ProviderBoundaryFake(pull_result=pull_result)
                )
                self.assert_error(
                    "target.device_member_invalid",
                    lambda: resolver.resolve(
                        config_with_scene(OffsetScene("range", 0x100, 0x120))
                    ),
                )


if __name__ == "__main__":
    unittest.main()
