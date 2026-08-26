from __future__ import annotations

import atexit
import math
import re
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Protocol, Sequence

from qtrace.errors import QtraceError
from qtrace.models import (
    ElfIdentity,
    OffsetScene,
    ResolvedScene,
    ResolvedTarget,
    SymbolScene,
    UserConfig,
)


_MAX_TOOL_BYTES = 1_048_576
_TOOL_TIMEOUT_SECONDS = 30.0
_MAX_ELF_BYTES = 512 * 1024 * 1024
_MAX_U64 = (1 << 64) - 1
_HEX = re.compile(r"0x[0-9a-fA-F]+\Z")
_NM_HEX = re.compile(r"[0-9a-fA-F]+\Z")
_SAFE_MODULE = re.compile(r"[A-Za-z0-9._+-]+\Z")
_BUILD_ID_LINE = re.compile(r"\s*Build ID:\s*([0-9a-fA-F]+)\s*\Z")
_DEVICE_QUERY_ERRORS = (QtraceError, OSError, TimeoutError, ValueError, TypeError)
_DEVICE_MEMBER_ERRORS = _DEVICE_QUERY_ERRORS + (zipfile.BadZipFile,)


class CommandRunner(Protocol):
    def capture(
        self,
        command: Sequence[str],
        *,
        maximum_bytes: int,
        timeout: float,
    ) -> bytes: ...


class DeviceFileProvider(Protocol):
    def package_apk_paths(self, package: str) -> tuple[str, ...]: ...

    def pull_member(self, apk_path: str, member: str, destination: Path) -> Path: ...


def _fail(code: str, stage: str, detail: str) -> None:
    raise QtraceError(code, stage, detail)


def _decode(output: bytes, tool: str) -> str:
    if not isinstance(output, bytes):
        _fail("target.tool_output_invalid", "target.inspect", f"{tool} returned non-byte output")
    try:
        return output.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        _fail("target.tool_output_invalid", "target.inspect", f"{tool} output is not UTF-8")


def _hex_u64(value: str, code: str, stage: str, field: str, *, prefixed: bool) -> int:
    pattern = _HEX if prefixed else _NM_HEX
    if pattern.fullmatch(value) is None:
        _fail(code, stage, f"{field} is not hexadecimal")
    parsed = int(value, 16)
    if parsed > _MAX_U64:
        _fail(code, stage, f"{field} exceeds uint64")
    return parsed


def _contains(ranges: tuple[tuple[int, int], ...], start: int, end: int) -> bool:
    return start < end and any(lower <= start and end <= upper for lower, upper in ranges)


class ElfInspector:
    def __init__(self, runner: CommandRunner, ndk_bin: Path):
        self._runner = runner
        self._readelf = Path(ndk_bin) / "llvm-readelf"
        self._nm = Path(ndk_bin) / "llvm-nm"

    def _capture(self, command: Sequence[str], tool: str) -> str:
        try:
            output = self._runner.capture(
                tuple(command),
                maximum_bytes=_MAX_TOOL_BYTES,
                timeout=_TOOL_TIMEOUT_SECONDS,
            )
        except QtraceError:
            raise
        except (OSError, TimeoutError) as error:
            _fail("target.tool_failed", "target.inspect", f"{tool} failed: {error}")
        return _decode(output, tool)

    @staticmethod
    def _single_header(text: str, name: str) -> str:
        matches: list[str] = []
        marker = f"{name}:"
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped.startswith(marker):
                continue
            value = stripped[len(marker):].strip()
            if not value or len(value.split()) != 1:
                _fail("target.header_malformed", "target.inspect", f"malformed ELF {name}")
            matches.append(value)
        if len(matches) != 1:
            code = "target.header_missing" if not matches else "target.header_ambiguous"
            _fail(code, "target.inspect", f"expected exactly one ELF {name}")
        return matches[0]

    @staticmethod
    def _build_id(text: str) -> str:
        note_rows = [
            line for line in text.splitlines()
            if "NT_GNU_BUILD_ID" in line and line.strip().startswith("GNU")
        ]
        build_rows = [line for line in text.splitlines() if "Build ID:" in line]
        if not note_rows or not build_rows:
            _fail("target.build_id_missing", "target.inspect", "GNU build ID is missing")
        if len(note_rows) != 1 or len(build_rows) != 1:
            _fail("target.build_id_ambiguous", "target.inspect", "GNU build ID is ambiguous")
        match = _BUILD_ID_LINE.fullmatch(build_rows[0])
        if match is None:
            _fail("target.build_id_invalid", "target.inspect", "GNU build ID is malformed")
        build_id = match.group(1)
        if len(build_id) % 2 != 0:
            _fail("target.build_id_invalid", "target.inspect", "GNU build ID has an odd hex length")
        return build_id.lower()

    @staticmethod
    def _program_headers(text: str) -> tuple[int, tuple[tuple[int, int], ...]]:
        loads: list[tuple[int, int, int, int, str, int]] = []
        for line in text.splitlines():
            fields = line.split()
            if not fields or fields[0] != "LOAD":
                continue
            if len(fields) < 8:
                _fail(
                    "target.program_header_malformed",
                    "target.inspect",
                    "PT_LOAD row has missing fields",
                )
            offset_text, vaddr_text, physical_text, file_size_text, mem_size_text = fields[1:6]
            flags_text = "".join(fields[6:-1])
            align_text = fields[-1]
            if not flags_text or any(flag not in "RWE" for flag in flags_text):
                _fail(
                    "target.program_header_malformed",
                    "target.inspect",
                    "PT_LOAD flags are malformed",
                )
            if len(set(flags_text)) != len(flags_text):
                _fail(
                    "target.program_header_malformed",
                    "target.inspect",
                    "PT_LOAD flags are repeated",
                )
            offset = _hex_u64(
                offset_text, "target.program_header_malformed", "target.inspect", "PT_LOAD offset",
                prefixed=True,
            )
            vaddr = _hex_u64(
                vaddr_text, "target.program_header_malformed", "target.inspect", "PT_LOAD vaddr",
                prefixed=True,
            )
            _hex_u64(
                physical_text, "target.program_header_malformed", "target.inspect", "PT_LOAD paddr",
                prefixed=True,
            )
            file_size = _hex_u64(
                file_size_text,
                "target.program_header_malformed",
                "target.inspect",
                "PT_LOAD file size",
                prefixed=True,
            )
            mem_size = _hex_u64(
                mem_size_text,
                "target.program_header_malformed",
                "target.inspect",
                "PT_LOAD memory size",
                prefixed=True,
            )
            align = _hex_u64(
                align_text,
                "target.program_header_malformed",
                "target.inspect",
                "PT_LOAD alignment",
                prefixed=True,
            )
            if file_size > mem_size:
                _fail(
                    "target.program_header_malformed",
                    "target.inspect",
                    "PT_LOAD file size exceeds memory size",
                )
            if mem_size > _MAX_U64 - vaddr:
                _fail(
                    "target.program_header_overflow",
                    "target.inspect",
                    "PT_LOAD virtual range overflows uint64",
                )
            if align not in (0, 1) and (align & (align - 1)) != 0:
                _fail(
                    "target.program_header_malformed",
                    "target.inspect",
                    "PT_LOAD alignment is not a power of two",
                )
            if align > 1 and vaddr % align != offset % align:
                _fail(
                    "target.program_header_malformed",
                    "target.inspect",
                    "PT_LOAD address and file offset are incongruent",
                )
            if vaddr < offset:
                _fail(
                    "target.load_bias_invalid",
                    "target.inspect",
                    "PT_LOAD has negative load bias",
                )
            load = (offset, vaddr, file_size, mem_size, flags_text, align)
            if load in loads:
                _fail(
                    "target.program_header_ambiguous",
                    "target.inspect",
                    "PT_LOAD record is repeated",
                )
            loads.append(load)

        if not loads:
            _fail("target.program_header_missing", "target.inspect", "ELF has no PT_LOAD records")
        executable_loads = [
            load for load in loads if "E" in load[4] and load[3] != 0
        ]
        if not executable_loads:
            _fail(
                "target.executable_range_missing",
                "target.inspect",
                "ELF has no executable PT_LOAD range",
            )
        biases = {
            vaddr - offset
            for offset, vaddr, _file, _mem, _flags, _align in executable_loads
        }
        if len(biases) != 1:
            _fail(
                "target.load_bias_ambiguous",
                "target.inspect",
                "executable PT_LOAD records do not share one ELF load bias",
            )
        load_bias = next(iter(biases))
        executable: list[tuple[int, int]] = []
        for _offset, vaddr, _file_size, mem_size, _flags, _align in executable_loads:
            start = vaddr - load_bias
            end = vaddr + mem_size - load_bias
            if start >= end:
                _fail(
                    "target.program_header_malformed",
                    "target.inspect",
                    "executable PT_LOAD range is empty",
                )
            executable.append((start, end))
        executable.sort()
        for previous, current in zip(executable, executable[1:]):
            if current[0] < previous[1]:
                _fail(
                    "target.executable_range_ambiguous",
                    "target.inspect",
                    "executable PT_LOAD ranges overlap",
                )
        return load_bias, tuple(executable)

    def _inspect_details(self, binary: Path) -> tuple[ElfIdentity, int]:
        text = self._capture(
            (str(self._readelf), "-h", "-n", "-lW", str(binary)),
            "llvm-readelf",
        )
        elf_class = self._single_header(text, "Class")
        machine = self._single_header(text, "Machine")
        if elf_class != "ELF64":
            _fail("target.elf_class_unsupported", "target.inspect", "target must be ELF64")
        if machine != "AArch64":
            _fail("target.machine_unsupported", "target.inspect", "target must be AArch64")
        build_id = self._build_id(text)
        load_bias, executable_ranges = self._program_headers(text)
        return (
            ElfIdentity(
                elf_class=elf_class,
                machine=machine,
                build_id=build_id,
                executable_ranges=executable_ranges,
            ),
            load_bias,
        )

    def inspect(self, binary: Path) -> ElfIdentity:
        return self._inspect_details(Path(binary))[0]

    def symbol_range(self, binary: Path, symbol: str) -> tuple[int, int]:
        identity, load_bias = self._inspect_details(Path(binary))
        text = self._capture(
            (
                str(self._nm),
                "-S",
                "--defined-only",
                "--format=posix",
                str(binary),
            ),
            "llvm-nm",
        )
        matching: list[tuple[str, str, str, str]] = []
        for line in text.splitlines():
            if not line.strip():
                continue
            fields = line.split()
            if len(fields) != 4:
                _fail("target.nm_malformed", "target.symbol", "llvm-nm row is malformed")
            if fields[0] == symbol:
                matching.append((fields[0], fields[1], fields[2], fields[3]))
        if not matching:
            _fail("target.symbol_not_found", "target.symbol", f"symbol {symbol!r} is not defined")
        if len(matching) != 1:
            _fail("target.symbol_ambiguous", "target.symbol", f"symbol {symbol!r} is ambiguous")
        _name, symbol_type, value_text, size_text = matching[0]
        if symbol_type not in {"T", "t", "W", "w"}:
            _fail(
                "target.symbol_type_invalid",
                "target.symbol",
                f"symbol {symbol!r} is not a text symbol",
            )
        value = _hex_u64(
            value_text, "target.nm_malformed", "target.symbol", "symbol value", prefixed=False
        )
        size = _hex_u64(
            size_text, "target.nm_malformed", "target.symbol", "symbol size", prefixed=False
        )
        if size == 0:
            _fail(
                "target.symbol_size_invalid",
                "target.symbol",
                f"symbol {symbol!r} has zero size",
            )
        if size > _MAX_U64 - value:
            _fail("target.symbol_overflow", "target.symbol", f"symbol {symbol!r} range overflows")
        absolute_end = value + size
        if value < load_bias or absolute_end < load_bias:
            _fail(
                "target.symbol_overflow",
                "target.symbol",
                f"symbol {symbol!r} precedes load bias",
            )
        start = value - load_bias
        end = absolute_end - load_bias
        if start % 4 != 0 or end % 4 != 0:
            _fail(
                "target.symbol_alignment_invalid",
                "target.symbol",
                f"symbol {symbol!r} is not four-byte aligned",
            )
        if not _contains(identity.executable_ranges, start, end):
            _fail(
                "target.scene_not_executable",
                "target.symbol",
                f"symbol {symbol!r} is outside executable PT_LOAD ranges",
            )
        return start, end


class TargetResolver:
    def __init__(self, inspector: ElfInspector, device: DeviceFileProvider):
        self._inspector = inspector
        self._device = device

    def _new_staging(self) -> Path:
        directory = Path(tempfile.mkdtemp(prefix="qtrace-target-"))
        atexit.register(shutil.rmtree, directory, True)
        return directory

    @staticmethod
    def _member(module: str) -> str:
        if _SAFE_MODULE.fullmatch(module) is None or module in {".", ".."}:
            _fail(
                "target.module_name_invalid",
                "target.resolve",
                "target module must be a safe basename",
            )
        return f"lib/arm64-v8a/{module}"

    @staticmethod
    def _valid_device_path(path: object) -> str:
        if not isinstance(path, str) or not path or any(
            ord(character) < 32 or ord(character) == 127 for character in path
        ):
            _fail(
                "target.device_query_failed",
                "target.resolve",
                "installed APK path is invalid",
            )
        return path

    def _installed_member(self, package: str, member: str) -> tuple[Path, str]:
        try:
            paths = self._device.package_apk_paths(package)
        except _DEVICE_QUERY_ERRORS as error:
            _fail(
                "target.device_query_failed",
                "target.resolve",
                f"cannot query package APKs: {error}",
            )
        if not isinstance(paths, tuple):
            _fail(
                "target.device_query_failed",
                "target.resolve",
                "package APK paths must be a tuple",
            )
        staging = self._new_staging()
        matches: list[tuple[Path, str]] = []
        for index, raw_path in enumerate(paths):
            apk_path = self._valid_device_path(raw_path)
            destination = staging / f"installed-{index}-{Path(member).name}"
            try:
                pulled = self._device.pull_member(apk_path, member, destination)
            except FileNotFoundError:
                continue
            except _DEVICE_MEMBER_ERRORS as error:
                _fail(
                    "target.device_member_invalid",
                    "target.resolve",
                    f"cannot pull installed target member: {error}",
                )
            try:
                pulled_path = Path(pulled)
                valid = (
                    pulled_path == destination
                    and not pulled_path.is_symlink()
                    and pulled_path.is_file()
                )
            except _DEVICE_MEMBER_ERRORS as error:
                _fail(
                    "target.device_member_invalid",
                    "target.resolve",
                    f"device provider returned an invalid target member: {error}",
                )
            if not valid:
                _fail(
                    "target.device_member_invalid",
                    "target.resolve",
                    "device provider returned an invalid target member",
                )
            matches.append((pulled_path, f"{apk_path}!/{member}"))
        if not matches:
            _fail(
                "target.module_not_found",
                "target.resolve",
                f"installed package has no {member}",
            )
        if len(matches) != 1:
            _fail(
                "target.module_ambiguous",
                "target.resolve",
                f"installed package contains {member} in multiple APKs",
            )
        return matches[0]

    @staticmethod
    def _unsafe_zip_info(info: zipfile.ZipInfo) -> bool:
        name = info.filename
        path = PurePosixPath(name)
        mode = info.external_attr >> 16
        return (
            not name
            or "\\" in name
            or "\x00" in name
            or path.is_absolute()
            or ".." in path.parts
            or stat.S_ISLNK(mode)
        )

    def _extract_configured_apk(self, apk: Path, module: str, member: str) -> Path:
        if apk.is_symlink() or not apk.is_file():
            _fail("target.apk_invalid", "target.extract", "configured APK is not a regular file")
        try:
            with zipfile.ZipFile(apk, "r") as archive:
                infos = archive.infolist()
                if any(self._unsafe_zip_info(info) for info in infos):
                    _fail(
                        "target.apk_member_unsafe",
                        "target.extract",
                        "configured APK contains an unsafe member",
                    )
                matches = [info for info in infos if info.filename == member]
                if len(matches) > 1:
                    _fail(
                        "target.module_ambiguous",
                        "target.extract",
                        f"configured APK contains duplicate {member}",
                    )
                if not matches:
                    wrong_abi = any(
                        len(PurePosixPath(info.filename).parts) == 3
                        and PurePosixPath(info.filename).parts[0] == "lib"
                        and PurePosixPath(info.filename).parts[-1] == module
                        for info in infos
                    )
                    code = "target.module_wrong_abi" if wrong_abi else "target.module_not_found"
                    _fail(code, "target.extract", f"configured APK has no {member}")
                selected = matches[0]
                if (
                    selected.is_dir()
                    or selected.file_size <= 0
                    or selected.file_size > _MAX_ELF_BYTES
                ):
                    _fail(
                        "target.apk_member_invalid",
                        "target.extract",
                        "configured APK target member has an invalid size",
                    )
                destination = self._new_staging() / Path(member).name
                try:
                    with archive.open(selected, "r") as source, destination.open("xb") as target:
                        remaining = selected.file_size
                        while remaining:
                            chunk = source.read(min(1024 * 1024, remaining))
                            if not chunk:
                                _fail(
                                    "target.apk_member_invalid",
                                    "target.extract",
                                    "configured APK target member is truncated",
                                )
                            target.write(chunk)
                            remaining -= len(chunk)
                        if source.read(1):
                            _fail(
                                "target.apk_member_invalid",
                                "target.extract",
                                "configured APK target member exceeds declared size",
                            )
                except (OSError, RuntimeError, zipfile.BadZipFile) as error:
                    _fail(
                        "target.apk_invalid",
                        "target.extract",
                        f"cannot extract configured APK target: {error}",
                    )
                return destination
        except QtraceError:
            raise
        except (OSError, RuntimeError, zipfile.BadZipFile) as error:
            _fail("target.apk_invalid", "target.extract", f"cannot read configured APK: {error}")

    @staticmethod
    def _local_binary(binary: Path) -> Path:
        if binary.is_symlink() or not binary.is_file():
            _fail(
                "target.binary_invalid",
                "target.resolve",
                "target.binary is not a regular file",
            )
        return binary

    @staticmethod
    def _identity_matches(host: ElfIdentity, device: ElfIdentity) -> bool:
        return (
            host.elf_class == device.elf_class
            and host.machine == device.machine
            and host.build_id == device.build_id
        )

    @staticmethod
    def _resolved_scene(
        scene: OffsetScene | SymbolScene,
        host_binary: Path,
        inspector: ElfInspector,
        device_identity: ElfIdentity,
    ) -> ResolvedScene:
        if isinstance(scene, SymbolScene):
            start, end = inspector.symbol_range(host_binary, scene.symbol)
        elif isinstance(scene, OffsetScene):
            start, end = scene.start_offset, scene.end_offset
            if start <= 0 or start >= end or end > _MAX_U64:
                _fail(
                    "target.scene_range_invalid",
                    "target.resolve",
                    f"scene {scene.name!r} is not a valid half-open range",
                )
            if start % 4 != 0 or end % 4 != 0:
                _fail(
                    "target.scene_alignment_invalid",
                    "target.resolve",
                    f"scene {scene.name!r} is not four-byte aligned",
                )
        else:
            _fail("target.scene_invalid", "target.resolve", "unknown scene model")
        if not _contains(device_identity.executable_ranges, start, end):
            _fail(
                "target.scene_not_executable",
                "target.resolve",
                f"scene {scene.name!r} is outside installed executable PT_LOAD ranges",
            )
        return ResolvedScene(scene.name, start, end)

    def resolve(self, config: UserConfig) -> ResolvedTarget:
        member = self._member(config.target.module)
        device_host, device_binary = self._installed_member(config.app.package, member)
        if config.target.binary is not None:
            host_binary = self._local_binary(config.target.binary)
        elif config.app.apk is not None:
            host_binary = self._extract_configured_apk(
                config.app.apk, config.target.module, member
            )
        else:
            host_binary = device_host

        host_identity = self._inspector.inspect(host_binary)
        if host_binary == device_host:
            device_identity = host_identity
        else:
            try:
                device_identity = self._inspector.inspect(device_host)
            except QtraceError as error:
                if error.code in {
                    "target.elf_class_unsupported",
                    "target.machine_unsupported",
                }:
                    _fail(
                        "target.identity_mismatch",
                        "target.resolve",
                        "installed target architecture differs from host ELF",
                    )
                raise
        if not self._identity_matches(host_identity, device_identity):
            _fail(
                "target.identity_mismatch",
                "target.resolve",
                "host and installed target ELF identity differ",
            )
        scenes = tuple(
            self._resolved_scene(
                scene, host_binary, self._inspector, device_identity
            )
            for scene in config.scenes
        )
        return ResolvedTarget(
            package=config.app.package,
            module=config.target.module,
            host_binary=host_binary,
            device_binary=device_binary,
            identity=device_identity,
            scenes=scenes,
        )
