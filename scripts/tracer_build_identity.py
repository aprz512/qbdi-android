#!/usr/bin/env python3
"""Capture build inputs and bind completed tracer artifacts to their SHA-256."""
from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

try:
    from scripts.bounded_process import capture_bounded
except ModuleNotFoundError:
    from bounded_process import capture_bounded

INPUTS = ("tracer/src/main/cpp", "tracer/build.gradle", "build.gradle", "settings.gradle",
          "gradle", "gradlew", "scripts/tracer_build_identity.py")


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as binary:
        before = os.fstat(binary.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > 512 * 1024**2:
            raise ValueError(f"build identity requires a regular file <=512 MiB: {path}")
        while block := binary.read(1024 * 1024):
            digest.update(block)
        after = os.fstat(binary.fileno())
        if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError(f"file changed while hashing: {path}")
    return digest.hexdigest()


def _git(root, *arguments):
    return capture_bounded(("git", "-C", str(root), *arguments),
                           maximum_bytes=4 * 1024**2, timeout=10.0)


def source_snapshot(repository):
    root = Path(repository).resolve()
    revision = _git(root, "rev-parse", "HEAD").decode("ascii").strip()
    entries = _git(root, "ls-files", "--stage", "-z", "--", *INPUTS).split(b"\0")
    manifest, submodules = {}, {}
    for entry in entries:
        if not entry:
            continue
        metadata, raw_name = entry.split(b"\t", 1)
        mode, expected, stage = metadata.decode("ascii").split()
        if stage != "0":
            raise ValueError("cannot identify a build with unmerged source inputs")
        name = os.fsdecode(raw_name)
        path = root / name
        if mode == "160000":
            actual = None
            dirty = None
            extra = {}
            if (path / ".git").exists():
                actual = _git(path, "rev-parse", "HEAD").decode("ascii").strip()
                dirty = hashlib.sha256(_git(path, "diff", "--binary", "HEAD")).hexdigest()
                names = _git(path, "ls-files", "--others", "--exclude-standard", "-z").split(b"\0")
                extra = {os.fsdecode(name): file_sha256(path / os.fsdecode(name))
                         for name in filter(None, names)}
            submodules[name] = {"expected_revision": expected, "revision": actual,
                                "dirty_diff_sha256": dirty, "untracked_input_count": len(extra),
                                "untracked_inputs_sha256": hashlib.sha256(
                                    json.dumps(extra, sort_keys=True).encode()).hexdigest()}
            manifest[name] = submodules[name]
        elif path.exists() or path.is_symlink():
            manifest[name] = {"sha256": file_sha256(path),
                              "symlink": os.readlink(path) if path.is_symlink() else None}
        else:
            manifest[name] = {"deleted": True}
    untracked = _git(root, "ls-files", "--others", "--exclude-standard", "-z", "--", *INPUTS).split(b"\0")
    for raw_name in filter(None, untracked):
        name = os.fsdecode(raw_name)
        manifest[name] = {"sha256": file_sha256(root / name)}
    parameters = {key: os.environ.get(key) for key in (
        "ANDROID_NDK_HOME", "ANDROID_HOME", "CC", "CXX", "CFLAGS", "CXXFLAGS",
        "QTRACE_USER_RULES_SOURCE", "QTRACE_USER_RULES_SAMPLE_SHA256")}
    external = parameters.get("QTRACE_USER_RULES_SOURCE")
    if external:
        parameters["user_rules_source_sha256"] = file_sha256(Path(external))
    return {"repository": str(root), "revision": revision,
        "source_tree_sha256": hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest(),
        "dirty_diff_sha256": hashlib.sha256(_git(root, "diff", "--binary", "HEAD", "--", *INPUTS)).hexdigest(),
        "untracked_input_count": len(list(filter(None, untracked))),
        "submodules": submodules, "build_parameters": parameters}


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".build-identity-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, sort_keys=True, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def publish_identity(repository, before, tracer, companion, output):
    current = source_snapshot(repository)
    if current != before:
        raise ValueError("tracer source identity changed during the build; rebuild before publishing")
    configurations = []
    for cache in Path(repository).glob("tracer/.cxx/Debug/*/arm64-v8a/CMakeCache.txt"):
        values = {}
        for line in cache.read_text().splitlines():
            if "=" not in line or line.startswith(("//", "#")):
                continue
            name, value = line.split("=", 1)
            key = name.split(":", 1)[0]
            if key in {"CMAKE_CXX_COMPILER", "CMAKE_BUILD_TYPE", "CMAKE_CXX_FLAGS",
                       "CMAKE_SHARED_LINKER_FLAGS", "ANDROID_NDK", "ANDROID_PLATFORM"}:
                values[key] = value
        configurations.append({"path": str(cache.relative_to(repository)), "values": values,
                               "sha256": file_sha256(cache)})
    identity = {"schema_version": 1, "created_utc": datetime.now(UTC).isoformat(),
        "source": current, "build": {"task": ":tracer:copyTracerDebug", "abi": "arm64-v8a",
        "cmake_configurations": configurations}, "artifacts": {
            "libqbdi_tracer.so": file_sha256(tracer),
            "libshadowhook_nothing.so": file_sha256(companion)}}
    write_json(output, identity)
    return identity


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("capture", "publish"))
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--tracer", type=Path)
    parser.add_argument("--companion", type=Path)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    if arguments.command == "capture":
        write_json(arguments.snapshot, source_snapshot(arguments.repository))
    else:
        if any(value is None for value in (arguments.tracer, arguments.companion, arguments.output)):
            parser.error("publish requires --tracer, --companion and --output")
        publish_identity(arguments.repository, json.loads(arguments.snapshot.read_text()),
                         arguments.tracer, arguments.companion, arguments.output)


if __name__ == "__main__":
    main()
