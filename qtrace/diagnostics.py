"""Explicit, bounded snapshots of a live process with an already loaded tracer.

Frida runs in a disposable host worker. A timeout ends that worker only: an ART
operation already entered in the target may still finish later, so never retry
the operation or terminate the target on the caller's behalf.
"""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import re
import sys
import tempfile
from types import SimpleNamespace

from qtrace.errors import QtraceError
from qtrace.injector import FridaProvider
from qtrace.process import BoundedRunner

MAXIMUM_BYTES = 64 * 1024
_SECTION_KEYS = {"status", "reason", "truncated", "rows"}
_SCRIPT = r"""
rpc.exports = {
  snapshot: function (request) {
    if (Process.id !== request.expectedPid) throw new Error('process_identity_mismatch');
    const module = Process.findModuleByName('libqbdi_tracer.so');
    if (module === null) throw new Error('tracer_not_loaded');
    const symbol = module.findExportByName('qbdi_tracer_snapshot_json');
    if (symbol === null) throw new Error('snapshot_export_unavailable');
    const capture = new NativeFunction(symbol, 'int',
      ['pointer', 'uint64', 'pointer', 'uint64', 'pointer'], {exceptions: 'propagate'});
    const text = JSON.stringify(request);
    const input = Memory.allocUtf8String(text);
    const output = Memory.alloc(65536);
    const size = Memory.alloc(8);
    size.writeU64(0);
    const code = capture(input, text.length, output, 65536, size);
    const length = size.readU64().toNumber();
    if (code !== 0 || length < 2 || length > 65536)
      throw new Error('snapshot_transport_' + code);
    if (output.add(length - 1).readU8() !== 0) throw new Error('snapshot_missing_nul');
    return JSON.parse(output.readUtf8String(length - 1));
  }
};
"""


def _fail(detail: str, code: str = "snapshot.invalid_response") -> None:
    raise QtraceError(code, "snapshot", detail)


def _object(value: object, keys: set[str]) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        _fail("snapshot object fields do not match schema 1")
    return value


def _integer(value: object, minimum: int, maximum: int) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _text(value: object, maximum: int) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return len(value.encode("utf-8")) <= maximum
    except UnicodeError:
        return False


def _loads(raw: bytes) -> object:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
    except (UnicodeError, ValueError, RecursionError) as error:
        _fail(f"invalid snapshot JSON: {error}")


def validate_snapshot(value: object, pid: int, starttime: str, *,
                      include_java: bool = True, max_threads: int = 32,
                      max_frames: int = 32) -> dict:
    """Validate every returned field before a snapshot becomes an artifact."""
    if not isinstance(value, dict) or type(value.get("ok")) is not bool:
        _fail("snapshot response has no boolean outcome")
    if not value["ok"]:
        _object(value, {"schema", "ok", "reason"})
        if type(value["schema"]) is not int or value["schema"] != 1 or not isinstance(value["reason"], str) or value["reason"] not in {
                "process_identity_mismatch", "process_identity_changed"}:
            _fail("invalid identity rejection")
        _fail(value["reason"], "snapshot.identity_mismatch")
    _object(value, {"schema", "ok", "reason", "pid", "starttime", "startedMonotonicNs",
                    "finishedMonotonicNs", "mappings", "nativeThreads", "java"})
    if (type(value["schema"]) is not int or value["schema"] != 1 or value["reason"] != "" or
            type(value["pid"]) is not int or value["pid"] != pid or value["starttime"] != starttime):
        _fail("snapshot process identity or schema differs from the request")
    if (not _integer(value["startedMonotonicNs"], 1, 2**64 - 1) or
            not _integer(value["finishedMonotonicNs"], value["startedMonotonicNs"], 2**64 - 1)):
        _fail("invalid snapshot time interval")
    for name, maximum in (("mappings", 64), ("nativeThreads", max_threads), ("java", max_threads)):
        section = _object(value[name], _SECTION_KEYS)
        if (not isinstance(section["status"], str) or section["status"] not in {"available", "unavailable", "disabled"} or
                not _text(section["reason"], 128) or type(section["truncated"]) is not bool or
                not isinstance(section["rows"], list) or len(section["rows"]) > maximum or
                (section["status"] == "available") != (section["reason"] == "")):
            _fail(f"invalid {name} availability or bound")
        if section["status"] == "disabled" and (name != "java" or include_java):
            _fail("unexpected disabled snapshot section")
        if name == "java" and not include_java and section["status"] != "disabled":
            _fail("Java collection was not requested")
        if section["status"] != "available" and section["rows"]:
            _fail("unavailable snapshot section contains rows")
        identities = set()
        for row in section["rows"]:
            if name == "mappings":
                _object(row, {"start", "end", "offset", "permissions", "path", "classification"})
                if (any(not isinstance(row[key], str) or not re.fullmatch(r"0x[0-9a-f]{1,16}", row[key])
                        for key in ("start", "end", "offset")) or
                        int(row["start"], 16) >= int(row["end"], 16) or
                        not isinstance(row["permissions"], str) or
                        not re.fullmatch(r"[r-][w-][x-][ps]", row["permissions"]) or
                        not _text(row["path"], 12288) or not isinstance(row["classification"], str) or row["classification"] not in {
                            "jit_name_match", "art_runtime_name_match", "java_image_name_match"}):
                    _fail("invalid runtime mapping")
            elif name == "nativeThreads":
                _object(row, {"tid", "name", "nameAvailable"})
                if (not _integer(row["tid"], 1, 2**31 - 1) or not _text(row["name"], 384) or
                        type(row["nameAvailable"]) is not bool or row["tid"] in identities):
                    _fail("invalid native thread")
                identities.add(row["tid"])
            else:
                _object(row, {"javaId", "name", "nameTruncated", "frames", "framesTruncated"})
                if (not isinstance(row["javaId"], str) or not re.fullmatch(r"[1-9][0-9]{0,18}", row["javaId"]) or
                        int(row["javaId"]) > 2**63 - 1 or row["javaId"] in identities or
                        not _text(row["name"], 512) or type(row["nameTruncated"]) is not bool or
                        type(row["framesTruncated"]) is not bool or not isinstance(row["frames"], list) or
                        len(row["frames"]) > max_frames or any(not _text(frame, 512) for frame in row["frames"])):
                    _fail("invalid Java thread or frames")
                identities.add(row["javaId"])
    if len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) >= MAXIMUM_BYTES:
        _fail("snapshot exceeds the response limit")
    return value


def _publish(path: Path, payload: bytes) -> None:
    """Publish a complete regular file without replacing any existing path."""
    temporary = None
    failure = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(prefix=".qtrace-snapshot-", dir=path.parent,
                                         delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    except OSError as error:
        failure = error
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError as error:
                prefix = f"cannot publish snapshot: {failure}; " if failure is not None else "snapshot published; "
                _fail(prefix + f"temporary file cleanup failed: {error}", "snapshot.output_failed")
    if failure is not None:
        _fail(f"cannot publish snapshot: {failure}", "snapshot.output_failed")


def capture_snapshot(device: object, pid: int, starttime: str, output: Path, *,
                     include_java: bool = True, max_threads: int = 32,
                     max_frames: int = 32, timeout: float = 10.0,
                     runner: BoundedRunner | None = None) -> dict:
    if (not _integer(pid, 1, 2**31 - 1) or not isinstance(starttime, str) or
            not re.fullmatch(r"[1-9][0-9]{0,31}", starttime) or type(include_java) is not bool or
            not _integer(max_threads, 1, 32) or not _integer(max_frames, 1, 32) or
            isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or
            not math.isfinite(timeout) or timeout <= 0):
        _fail("invalid snapshot identity, limits or deadline", "snapshot.invalid_request")
    if output.exists() or output.is_symlink():
        _fail("snapshot output already exists", "snapshot.output_failed")
    FridaProvider.check_host()
    command = [sys.executable, "-m", "qtrace.diagnostics", "--serial", device.serial,
               "--pid", str(pid), "--starttime", starttime, "--max-threads", str(max_threads),
               "--max-frames", str(max_frames), "--timeout", str(timeout)]
    if not include_java:
        command.append("--no-java-stacks")
    try:
        raw = (runner or BoundedRunner()).capture(command, timeout=timeout, maximum_bytes=MAXIMUM_BYTES + 4096)
    except QtraceError as error:
        if error.code == "process.timeout":
            _fail("snapshot worker deadline expired; target completion is unconfirmed; operation was not retried",
                  "snapshot.timeout")
        raise
    envelope = _object(_loads(raw), {"snapshot", "error", "cleanupErrors"})
    if (not isinstance(envelope["cleanupErrors"], list) or len(envelope["cleanupErrors"]) > 2 or
            any(not _text(item, 512) for item in envelope["cleanupErrors"])):
        _fail("invalid worker cleanup status")
    if envelope["error"] is not None:
        if not _text(envelope["error"], 512):
            _fail("invalid worker error")
        suffix = "; cleanup incomplete" if envelope["cleanupErrors"] else ""
        _fail(envelope["error"] + suffix, "snapshot.capture_failed")
    if envelope["cleanupErrors"]:
        _fail("snapshot obtained, but Frida unload/detach is unconfirmed: " + "; ".join(envelope["cleanupErrors"]),
              "snapshot.cleanup_incomplete")
    value = validate_snapshot(envelope["snapshot"], pid, starttime, include_java=include_java,
                              max_threads=max_threads, max_frames=max_frames)
    _publish(output, json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n")
    return value


def _worker(arguments: argparse.Namespace, provider: object | None = None) -> dict:
    session = script = None
    result = {"snapshot": None, "error": None, "cleanupErrors": []}
    try:
        remote = (provider or FridaProvider()).get_device(SimpleNamespace(serial=arguments.serial), arguments.timeout)
        session = remote.attach(arguments.pid)
        script = session.create_script(_SCRIPT)
        script.load()
        result["snapshot"] = script.exports_sync.snapshot({"schema": 1, "expectedPid": arguments.pid,
            "expectedStarttime": arguments.starttime, "includeJava": not arguments.no_java_stacks,
            "maxThreads": arguments.max_threads, "maxFrames": arguments.max_frames})
    except Exception as error:
        result["error"] = str(error).encode("utf-8", errors="replace")[:512].decode("utf-8", errors="ignore")
    finally:
        for resource, method in ((script, "unload"), (session, "detach")):
            if resource is not None:
                try:
                    getattr(resource, method)()
                except Exception as error:
                    result["cleanupErrors"].append(str(error).encode("utf-8", errors="replace")[:512].decode("utf-8", errors="ignore"))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--starttime", required=True)
    parser.add_argument("--max-threads", required=True, type=int)
    parser.add_argument("--max-frames", required=True, type=int)
    parser.add_argument("--no-java-stacks", action="store_true")
    parser.add_argument("--timeout", required=True, type=float)
    print(json.dumps(_worker(parser.parse_args()), ensure_ascii=False, separators=(",", ":")))
