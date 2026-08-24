#!/usr/bin/env python3
"""Seeded Android flight-recorder acceptance runner and result checks."""

from __future__ import annotations

import dataclasses
import argparse
import hashlib
import json
import re
import signal
import struct
import subprocess
import sys
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

try:
    from scripts.flight_trace import recover_flight
    from scripts.pull_trace import AdbArtifactClient
except ModuleNotFoundError:
    from flight_trace import recover_flight  # type: ignore[no-redef]
    from pull_trace import AdbArtifactClient  # type: ignore[no-redef]


WORKER_COUNT = 16
SCENE_SYMBOLS = {
    "init": "demo_init_stage",
    "jni": "demo_jni_case",
    "libc": "demo_libc_case",
    "algorithm": "demo_algorithm_case",
    "integrity": "demo_integrity_case",
}
MODES = (
    "direct_tgkill",
    "exit_group",
    "sync_fault",
    "target_sigkill",
    "external_sigkill",
)
_SAFE_PACKAGE = re.compile(r"[A-Za-z0-9_.]+\Z")
_SAFE_RELATIVE = re.compile(r"[A-Za-z0-9_.][A-Za-z0-9_./-]*\Z")
_WORKERS = re.compile(
    r"QBDI_FLIGHT_WORKERS seed=(\d+) tids=([0-9,]+) rotations=(\d+)"
)


class AcceptanceError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True, slots=True)
class AcceptanceCase:
    seed: int
    mode: str
    terminator: int | None


@dataclasses.dataclass(frozen=True, slots=True)
class AcceptanceOracle:
    seed: int
    mode: str
    tid: int | None
    original_pc: int | None

    @classmethod
    def parse(cls, line: str) -> "AcceptanceOracle":
        prefix = "QBDI_FLIGHT_ORACLE "
        if not line.startswith(prefix):
            raise AcceptanceError("missing acceptance oracle prefix")
        fields = dict(part.split("=", 1) for part in line[len(prefix):].split()
                      if "=" in part)
        try:
            seed = int(fields["seed"], 0)
            mode = fields["mode"]
            phase = fields["phase"]
            raw_tid = fields["tid"]
            raw_pc = fields["pc"]
        except (KeyError, ValueError) as error:
            raise AcceptanceError("oracle lacks seed, mode, TID, PC, or phase") from error
        if phase != "ready" or mode not in MODES:
            raise AcceptanceError("invalid acceptance oracle")
        if raw_tid == "none" and raw_pc == "none":
            tid = original_pc = None
        else:
            try:
                tid = int(raw_tid, 0)
                original_pc = int(raw_pc, 0)
            except ValueError as error:
                raise AcceptanceError("oracle TID/PC is invalid") from error
            if tid <= 0 or original_pc <= 0:
                raise AcceptanceError("oracle TID/PC must be positive")
        return cls(seed, mode, tid, original_pc)


@dataclasses.dataclass(frozen=True, slots=True)
class AcceptanceResult:
    mode: str
    oracle: AcceptanceOracle
    observed_tid: int | None
    observed_pc: int | None
    chunks_by_tid: dict[int, int]
    relevant_tids: frozenset[int]
    coverage_gaps: int = 0
    decode_complete: bool = True
    guest_visible_tracer_addresses: tuple[int, ...] = ()


def _seed_word(seed: int, mode_index: int) -> int:
    value = (seed & 0xFFFFFFFFFFFFFFFF) ^ (
        0x9E3779B97F4A7C15 * (mode_index + 1)
    )
    value ^= value >> 30
    value = (value * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
    value ^= value >> 27
    value = (value * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
    return value ^ (value >> 31)


def expand_cases(seeds: Iterable[int]) -> list[AcceptanceCase]:
    cases = []
    for mode_index, seed in enumerate(seeds):
        if seed < 0 or seed > 0xFFFFFFFFFFFFFFFF:
            raise AcceptanceError("seed is outside uint64 range")
        mode = MODES[mode_index % len(MODES)]
        terminator = None if mode == "external_sigkill" else (
            _seed_word(seed, mode_index) % WORKER_COUNT
        )
        cases.append(AcceptanceCase(seed, mode, terminator))
    return cases


def run_as_command(package: str, relative_path: str) -> list[str]:
    if not _SAFE_PACKAGE.fullmatch(package):
        raise AcceptanceError("unsafe Android package name")
    path = Path(relative_path)
    if (not _SAFE_RELATIVE.fullmatch(relative_path) or path.is_absolute()
            or ".." in path.parts or path.parts[:2] != ("files", "qbdi_trace")):
        raise AcceptanceError("unsafe run-as artifact path")
    return ["run-as", package, "cat", relative_path]


def run_as_kill_command(package: str, pid: int) -> list[str]:
    if not _SAFE_PACKAGE.fullmatch(package):
        raise AcceptanceError("unsafe Android package name")
    if not isinstance(pid, int) or pid <= 0:
        raise AcceptanceError("invalid Android process ID")
    return ["run-as", package, "kill", "-9", str(pid)]


def exact_artifact(directory: Path, pid: int) -> Path:
    if pid <= 0:
        raise AcceptanceError("artifact PID must be positive")
    matches = sorted(
        path for path in directory.glob("*.flight.bin")
        if len(path.name.split("_", 2)) >= 3 and path.name.split("_", 2)[1] == str(pid)
    )
    if len(matches) != 1:
        raise AcceptanceError(
            f"expected exactly one flight artifact for PID {pid}, found {len(matches)}"
        )
    return matches[0]


_INCOMPLETE_SUMMARY_DIMENSIONS = (
    "stale_directory_entries",
    "incomplete_logical_events",
    "coverage_gaps",
    "recovery_damage",
)


def decode_status(summary: dict[str, object]) -> str:
    if summary.get("complete") is not True or summary.get("artifact_flags") != 0:
        return "incomplete"
    if any(field not in summary or bool(summary[field])
           for field in _INCOMPLETE_SUMMARY_DIMENSIONS):
        return "incomplete"
    return "complete"


def validate_result(result: AcceptanceResult) -> None:
    if result.coverage_gaps:
        raise AcceptanceError(f"coverage gap count is {result.coverage_gaps}")
    if not result.decode_complete:
        raise AcceptanceError("flight artifact decode is incomplete")
    if result.guest_visible_tracer_addresses:
        raise AcceptanceError("guest-visible tracer address was observed")
    deficient = sorted(
        tid for tid in result.relevant_tids if result.chunks_by_tid.get(tid, 0) < 4
    )
    if deficient:
        raise AcceptanceError(f"relevant TIDs lack four chunks: {deficient}")
    external = result.mode == "external_sigkill"
    if external:
        if any(value is not None for value in (
            result.oracle.tid, result.oracle.original_pc,
            result.observed_tid, result.observed_pc,
        )):
            raise AcceptanceError("external SIGKILL must have no initiator")
    elif (result.observed_tid, result.observed_pc) != (
        result.oracle.tid, result.oracle.original_pc
    ):
        raise AcceptanceError("observed termination does not match oracle")


def _adb(serial: str, *arguments: str, timeout: float = 60.0,
         binary: bool = False, check: bool = True) -> subprocess.CompletedProcess[Any]:
    if not serial or any(character.isspace() for character in serial):
        raise AcceptanceError("unsafe adb serial")
    try:
        return subprocess.run(
            ["adb", "-s", serial, *arguments], check=check,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=not binary, timeout=timeout, shell=False,
        )
    except (FileNotFoundError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as error:
        raise AcceptanceError(f"adb command failed: {arguments!r}: {error}") from error


def _agent_source(case: AcceptanceCase, scene_offsets: dict[str, int],
                  artifact_mb: int) -> str:
    if set(scene_offsets) != set(SCENE_SYMBOLS) or any(
            offset <= 0 for offset in scene_offsets.values()):
        raise AcceptanceError("all acceptance scene offsets must be nonzero")
    selected = case.terminator if case.terminator is not None else 0
    encoded_scenes = f"scene=init,0x{scene_offsets['init']:x}"
    return f"""'use strict';
const targetName = 'libdemo_target.so';
const helperPath = '/data/data/com.aprz.qbdiandroid/files/libshadowhook_nothing.so';
const tracer = Module.load('/data/data/com.aprz.qbdiandroid/files/libqbdi_tracer.so');
function exported(name) {{
  if (typeof tracer.getExportByName === 'function') return tracer.getExportByName(name);
  return Module.getGlobalExportByName(name);
}}
const configure = new NativeFunction(exported('qbdi_tracer_configure'), 'void', ['pointer']);
const setHelper = new NativeFunction(
  exported('qbdi_tracer_set_shadowhook_helper_path'), 'int', ['pointer']);
if (setHelper(Memory.allocUtf8String(helperPath)) !== 0) {{
  throw new Error('failed to configure ShadowHook companion path: ' + helperPath);
}}
const encoded = 'package=com.aprz.qbdiandroid;target=' + targetName +
  ';scenes=replace;{encoded_scenes};profile=full;compression=0;flight=1;' +
  'flight_mb={artifact_mb};flight_chunk_kb=256;flight_max_threads=256;' +
  'flight_protected_chunks=4';
configure(Memory.allocUtf8String(encoded));
let launched = false;
Process.attachModuleObserver({{
  onAdded(module) {{
    if (launched || module.name !== targetName) return;
    launched = true;
    send({{type: 'acceptance-installed', target_base: module.base.toString(),
          target_size: module.size, tracer_base: tracer.base.toString(),
          tracer_size: tracer.size, config: encoded}});
    setTimeout(() => {{
      try {{
        const start = new NativeFunction(
          module.getExportByName('demo_flight_acceptance_start'),
          'uint64', ['uint64', 'uint32', 'uint32']);
        const snapshot = new NativeFunction(
          module.getExportByName('demo_flight_acceptance_snapshot'),
          'int', ['pointer']);
        const release = new NativeFunction(
          module.getExportByName('demo_flight_acceptance_release'),
          'int', ['uint64']);
        const output = Memory.alloc(120);
        const generation = start(new UInt64('{case.seed}'),
                                 {MODES.index(case.mode)}, {selected});
        if (generation.equals(0)) throw new Error('acceptance start failed');
        let sent = false;
        const poll = setInterval(() => {{
          if (sent || snapshot(output) === 0) return;
          const workerCount = output.add(48).readU32();
          const tids = [];
          for (let index = 0; index < workerCount; ++index) {{
            tids.push(output.add(56 + index * 4).readU32());
          }}
          const modeIndex = output.add(28).readU32();
          const selectedTid = output.add(36).readU32();
          const originalPc = output.add(16).readU64();
          sent = true;
          clearInterval(poll);
          send({{type: 'acceptance-oracle',
                generation: output.readU64().toString(),
                seed: output.add(8).readU64().toString(),
                mode: {list(MODES)!r}[modeIndex],
                selected_worker: output.add(32).readU32(),
                tid: modeIndex === 4 ? null : selectedTid,
                pc: modeIndex === 4 ? null : '0x' + originalPc.toString(16),
                probe: output.add(40).readU32(),
                rotations: output.add(44).readU32(),
                state: output.add(24).readU32(), tids: tids}});
        }}, 20);
        const armRelease = () => recv('acceptance-release', message => {{
          const requested = new UInt64(String(message.payload.generation));
          if (release(requested) !== 1) {{
            send({{type: 'acceptance-error', error: 'acceptance release failed'}});
          }}
          armRelease();
        }});
        armRelease();
      }} catch (error) {{
        send({{type: 'acceptance-error', error: String(error)}});
      }}
    }}, 500);
  }}
}});
"""


def _symbol_value(apk: Path, symbol: str) -> int:
    import tempfile
    import zipfile

    with tempfile.TemporaryDirectory(prefix="qbdi-flight-symbol-") as directory:
        library = Path(directory) / "libdemo_target.so"
        with zipfile.ZipFile(apk) as archive:
            library.write_bytes(archive.read("lib/arm64-v8a/libdemo_target.so"))
        tool = Path.home() / "Android/sdk/ndk/26.1.10909125/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf"
        command = [str(tool), "--symbols", "--wide", str(library)]
        try:
            output = subprocess.run(
                command, check=True, capture_output=True, text=True,
                timeout=30, shell=False,
            ).stdout
        except (FileNotFoundError, subprocess.CalledProcessError,
                subprocess.TimeoutExpired) as error:
            raise AcceptanceError(f"cannot inspect APK symbol {symbol}") from error
    matches = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[-1] == symbol:
            matches.append(int(fields[1], 16))
    if len(set(matches)) != 1 or not matches[0]:
        raise AcceptanceError(f"expected one nonzero {symbol} symbol, found {matches}")
    return matches[0]


def _artifact_chunk_counts(path: Path) -> Counter[int]:
    header = struct.Struct("<IHHIIIIQQIII12x")
    counts: Counter[int] = Counter()
    with path.open("rb") as source:
        superblock = source.read(128)
        if len(superblock) != 128:
            raise AcceptanceError("truncated flight superblock")
        chunk_offset = struct.unpack_from("<Q", superblock, 40)[0]
        chunk_bytes = struct.unpack_from("<I", superblock, 48)[0]
        chunk_count = struct.unpack_from("<I", superblock, 52)[0]
        for index in range(chunk_count):
            source.seek(chunk_offset + index * chunk_bytes)
            raw = source.read(header.size)
            if len(raw) != header.size:
                raise AcceptanceError("truncated flight chunk table")
            (_magic, _version, _bytes, _index, state, tid, _generation,
             _first, _last, _committed, _records, _checksum) = header.unpack(raw)
            if state in (1, 2) and tid:
                counts[tid] += 1
    return counts


def _parse_log_oracles(text: str, seed: int) -> tuple[AcceptanceOracle, frozenset[int], int]:
    oracle_lines = [line[line.index("QBDI_FLIGHT_ORACLE "):]
                    for line in text.splitlines()
                    if "QBDI_FLIGHT_ORACLE " in line and f"seed={seed} " in line]
    worker_matches = [_WORKERS.search(line) for line in text.splitlines()
                      if f"QBDI_FLIGHT_WORKERS seed={seed} " in line]
    workers = [match for match in worker_matches if match is not None]
    if len(oracle_lines) != 1 or len(workers) != 1:
        raise AcceptanceError("expected exactly one oracle and worker record")
    oracle = AcceptanceOracle.parse(oracle_lines[0])
    probe = re.search(r"(?:^| )probe=(0x[0-9a-fA-F]+)(?: |$)", oracle_lines[0])
    if probe is None or int(probe.group(1), 16) != 0x17:
        raise AcceptanceError("guest signal virtualization probe failed")
    tids = frozenset(int(value) for value in workers[0].group(2).split(","))
    rotations = int(workers[0].group(3))
    if len(tids) != WORKER_COUNT or rotations < 5:
        raise AcceptanceError("worker oracle is incomplete")
    return oracle, tids, rotations


def _observed_termination(recovery: Any, mode: str,
                          module_base: int) -> tuple[int | None, int | None]:
    if mode == "external_sigkill":
        return None, None
    if mode == "sync_fault":
        events = [
            event for event in reversed(recovery.merged)
            if event.kind in {"signal", "signal_handler_begin"}
            and int(event.data.get("signal_number", 0)) == signal.SIGSEGV
            and (int(event.data.get("flags", 0)) & 0xFFFF) == 1
        ]
        if not events:
            raise AcceptanceError("synchronous fault has no top-level SIGSEGV record")
        event = events[0]
        return event.tid, int(event.data["pc"]) - module_base
    termination = recovery.summary["termination"]
    if termination.get("cause") != "termination_intent":
        raise AcceptanceError("target termination has no durable intent")
    return int(termination["initiator_tid"]), int(termination["pc"]) - module_base


class OracleMailbox:
    def __init__(self, case: AcceptanceCase) -> None:
        self._case = case
        self._event = threading.Event()
        self._lock = threading.Lock()
        self._value: tuple[AcceptanceOracle, frozenset[int], int, int] | None = None
        self._error: str | None = None
        self._diagnostics: list[dict[str, Any]] = []

    def handle(self, message: dict[str, Any]) -> int | None:
        with self._lock:
            self._diagnostics.append(message)
            payload = message.get("payload")
            if message.get("type") != "send" or not isinstance(payload, dict):
                return None
            message_type = payload.get("type")
            if message_type == "acceptance-error":
                self._error = f"Frida acceptance error: {payload.get('error')}"
                self._event.set()
                return None
            if message_type != "acceptance-oracle":
                return None
            if self._value is not None:
                self._error = "duplicate acceptance oracle"
                self._event.set()
                return None
            try:
                generation = int(payload["generation"], 0)
                seed = int(payload["seed"], 0)
                mode = str(payload["mode"])
                selected_worker = int(payload["selected_worker"])
                state = int(payload["state"])
                probe = int(payload["probe"])
                rotations = int(payload["rotations"])
                tids = frozenset(int(tid) for tid in payload["tids"])
                raw_tid = payload["tid"]
                raw_pc = payload["pc"]
                tid = None if raw_tid is None else int(raw_tid)
                pc = None if raw_pc is None else int(raw_pc, 0)
            except (KeyError, TypeError, ValueError) as error:
                self._error = f"incomplete acceptance oracle: {error}"
                self._event.set()
                return None
            expected_worker = self._case.terminator
            if self._case.mode == "external_sigkill":
                expected_worker = 0
            if (generation <= 0 or seed != self._case.seed or mode != self._case.mode or
                    selected_worker != expected_worker or state != 2 or probe != 0x17 or
                    len(tids) != WORKER_COUNT or any(tid_value <= 0 for tid_value in tids) or
                    rotations < 5 or
                    ((tid is None or pc is None) != (mode == "external_sigkill")) or
                    (tid is not None and (tid <= 0 or tid not in tids)) or
                    (pc is not None and pc <= 0)):
                self._error = "acceptance oracle fields do not match the requested case"
                self._event.set()
                return None
            oracle = AcceptanceOracle(seed, mode, tid, pc)
            self._value = (oracle, tids, rotations, generation)
            self._event.set()
            return generation

    def fail(self, error: Exception) -> None:
        with self._lock:
            self._error = f"Frida oracle transport failed: {error}"
            self._event.set()

    def wait(self, timeout: float) -> tuple[AcceptanceOracle, frozenset[int], int, int]:
        if not self._event.wait(timeout):
            with self._lock:
                diagnostics = json.dumps(self._diagnostics, sort_keys=True, default=str)
            raise AcceptanceError(f"oracle timeout; Frida messages={diagnostics}")
        with self._lock:
            if self._error is not None:
                raise AcceptanceError(self._error)
            if self._value is None:
                raise AcceptanceError("oracle event has no value")
            return self._value


def _bounded_call(callback: Any, timeout: float) -> None:
    thread = threading.Thread(target=lambda: _ignore_cleanup_error(callback), daemon=True)
    thread.start()
    thread.join(max(0.0, timeout))


def _ignore_cleanup_error(callback: Any) -> None:
    try:
        callback()
    except Exception:
        pass


def _cleanup_frida(script: Any, session: Any, serial: str, package: str,
                   timeout: float) -> None:
    if script is not None:
        _bounded_call(script.unload, timeout)
    if session is not None:
        _bounded_call(session.detach, timeout)
    try:
        _adb(serial, "shell", "am", "force-stop", package, check=False,
             timeout=timeout)
    except AcceptanceError:
        pass


def _wait_artifact(client: AdbArtifactClient, before: set[str], pid: int,
                   timeout: float) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        created = [name for name in client.list_names()
                   if name not in before and name.endswith(".flight.bin") and
                   len(name.split("_", 2)) >= 3 and name.split("_", 2)[1] == str(pid)]
        if len(created) == 1:
            return created[0]
        if len(created) > 1:
            raise AcceptanceError(f"multiple artifacts for PID {pid}: {created}")
        time.sleep(0.1)
    raise AcceptanceError(f"artifact timeout for PID {pid}")


def run_case(args: argparse.Namespace, case: AcceptanceCase,
             scene_offsets: dict[str, int],
             output_dir: Path) -> dict[str, object]:
    try:
        import frida  # type: ignore[import-not-found]
    except ImportError as error:
        raise AcceptanceError("Frida Python bindings are required") from error

    client = AdbArtifactClient(args.package, args.device, timeout=args.adb_timeout)
    before = set(client.list_names())
    _adb(args.device, "shell", "am", "force-stop", args.package)
    _adb(args.device, "forward", f"tcp:{args.frida_port}", f"tcp:{args.frida_port}")
    device = frida.get_device_manager().add_remote_device(
        f"127.0.0.1:{args.frida_port}"
    )
    session = None
    script = None
    messages: list[dict[str, Any]] = []
    mailbox = OracleMailbox(case)
    try:
        pid = device.spawn([args.package])
        session = device.attach(pid)
        script = session.create_script(
            _agent_source(case, scene_offsets, args.artifact_mb)
        )

        def on_message(message: dict[str, Any], _data: Any) -> None:
            messages.append(message)
            generation = mailbox.handle(message)
            if generation is None:
                return
            try:
                script.post({"type": "acceptance-release",
                             "payload": {"generation": str(generation)}})
            except Exception as error:
                mailbox.fail(error)

        script.on("message", on_message)
        script.load()
        device.resume(pid)
        oracle, relevant_tids, rotations, _generation = mailbox.wait(args.timeout)
        installed = next((message["payload"] for message in messages
                          if message.get("type") == "send" and
                          isinstance(message.get("payload"), dict) and
                          message["payload"].get("type") == "acceptance-installed"), None)
        if installed is None:
            raise AcceptanceError("agent did not confirm production installation")
        if case.mode == "external_sigkill":
            _adb(args.device, "shell", *run_as_kill_command(args.package, pid))
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            if _adb(args.device, "shell", "test", "-d", f"/proc/{pid}",
                    check=False).returncode != 0:
                break
            time.sleep(0.1)
        else:
            raise AcceptanceError(f"process {pid} did not terminate")

        name = _wait_artifact(client, before, pid, args.timeout)
        local = output_dir / name
        with local.open("wb") as output:
            client.stream_file(name, output)
        if exact_artifact(output_dir, pid) != local:
            raise AcceptanceError("local artifact selection is not exact")
        with local.open("rb") as source:
            recovery = recover_flight(source)
        module_bases = {int(event.data["module_base"])
                        for event in recovery.merged if "module_base" in event.data}
        if len(module_bases) != 1:
            raise AcceptanceError(f"cannot derive one target module base: {module_bases}")
        module_base = module_bases.pop()
        observed_tid, observed_pc = _observed_termination(recovery, case.mode, module_base)
        tracer_start = int(str(installed["tracer_base"]), 16)
        tracer_end = tracer_start + int(installed["tracer_size"])
        exposed = tuple(sorted({int(event.data.get("pc", 0))
                                for event in recovery.merged
                                if event.kind in {"signal", "signal_handler_begin",
                                                  "signal_handler_return"} and
                                tracer_start <= int(event.data.get("pc", 0)) < tracer_end}))
        summary = recovery.summary
        status = decode_status(summary)
        decode_complete = status == "complete"
        counts = _artifact_chunk_counts(local)
        result = AcceptanceResult(
            case.mode, oracle, observed_tid, observed_pc, dict(counts), relevant_tids,
            len(summary["coverage_gaps"]), decode_complete, exposed,
        )
        validate_result(result)
        return {
            "seed": case.seed, "mode": case.mode, "pid": pid,
            "terminator_worker": case.terminator,
            "expected_tid": oracle.tid, "expected_pc": oracle.original_pc,
            "observed_tid": observed_tid, "observed_pc": observed_pc,
            "worker_tids": sorted(relevant_tids), "worker_count": len(relevant_tids),
            "rotations": rotations, "chunks_by_tid": dict(sorted(counts.items())),
            "artifact": name, "artifact_bytes": local.stat().st_size,
            "artifact_sha256": _sha256(local),
            "decode_status": status, "coverage_gaps": 0,
            "guest_visible_tracer_addresses": [], "status": "passed",
        }
    finally:
        _cleanup_frida(script, session, args.device, args.package,
                       min(2.0, max(0.05, args.adb_timeout)))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", default="com.aprz.qbdiandroid")
    parser.add_argument("--device", required=True)
    parser.add_argument("--seeds", required=True)
    parser.add_argument("--artifact-mb", type=int, default=512)
    parser.add_argument("--apk", type=Path,
                        default=Path("app/build/outputs/apk/debug/app-debug.apk"))
    parser.add_argument("--tracer", type=Path,
                        default=Path("out/arm64-v8a/libqbdi_tracer.so"))
    parser.add_argument("--companion", type=Path,
                        default=Path("out/arm64-v8a/libshadowhook_nothing.so"))
    parser.add_argument("--output-dir", type=Path,
                        default=Path("artifacts/flight-acceptance"))
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--adb-timeout", type=float, default=120.0)
    parser.add_argument("--frida-port", type=int, default=27042)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.artifact_mb < 64 or args.artifact_mb > 2048:
        raise AcceptanceError("--artifact-mb must be in [64, 2048]")
    seeds = [int(value, 0) for value in args.seeds.split(",") if value]
    if len(seeds) != len(MODES):
        raise AcceptanceError("acceptance requires exactly five seeds, one per mode")
    if (not args.apk.is_file() or not args.tracer.is_file() or
            not args.companion.is_file()):
        raise AcceptanceError("debug APK, tracer, and ShadowHook companion must exist")
    if not _SAFE_PACKAGE.fullmatch(args.package):
        raise AcceptanceError("unsafe Android package name")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    _adb(args.device, "shell", "mkdir", "-p", "/data/local/tmp/qbdi-android")
    _adb(args.device, "push", str(args.tracer),
         "/data/local/tmp/qbdi-android/libqbdi_tracer.so", timeout=args.adb_timeout)
    _adb(args.device, "push", str(args.companion),
         "/data/local/tmp/qbdi-android/libshadowhook_nothing.so",
         timeout=args.adb_timeout)
    _adb(args.device, "shell", "run-as", args.package, "cp",
         "/data/local/tmp/qbdi-android/libshadowhook_nothing.so",
         "files/libshadowhook_nothing.so")
    _adb(args.device, "shell", "run-as", args.package, "cp",
         "/data/local/tmp/qbdi-android/libqbdi_tracer.so", "files/libqbdi_tracer.so")
    _adb(args.device, "shell", "run-as", args.package, "chmod", "700",
         "files/libshadowhook_nothing.so")
    _adb(args.device, "shell", "run-as", args.package, "chmod", "700",
         "files/libqbdi_tracer.so")
    scene_offsets = {
        name: _symbol_value(args.apk, symbol)
        for name, symbol in SCENE_SYMBOLS.items()
    }
    results = []
    for case in expand_cases(seeds):
        print(f"[flight-acceptance] seed={case.seed} mode={case.mode}", flush=True)
        results.append(run_case(args, case, scene_offsets, args.output_dir))
        print(f"[flight-acceptance] mode={case.mode} passed", flush=True)
    report = {
        "device": args.device, "package": args.package,
        "artifact_mb": args.artifact_mb, "apk_sha256": _sha256(args.apk),
        "tracer_sha256": _sha256(args.tracer),
        "companion_sha256": _sha256(args.companion), "runs": results,
    }
    encoded = json.dumps(report, indent=2, sort_keys=True)
    (args.output_dir / "acceptance.json").write_text(encoded + "\n", encoding="utf-8")
    print(encoded)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AcceptanceError as error:
        print(f"flight acceptance failed: {error}", file=sys.stderr)
        raise SystemExit(1)
