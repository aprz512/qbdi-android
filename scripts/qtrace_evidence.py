#!/usr/bin/env python3
"""Read-only acceptance inventory and explicit cleanup of reviewed successful runs.

Failed, incomplete, unknown, linked, and changed evidence is always retained.
Cleanup requires an exact run name, a fresh inventory digest, and --apply.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import uuid
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from qtrace._artifact_publication import _remove_tree_at, _rename_noreplace
from scripts.qtrace_device_acceptance import (
    _SUCCESS_MANIFEST_NAME, _validate_success_gate_document,
)

_ROOTS = ("qtrace-acceptance-evidence", "qtrace-acceptance-failures")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_MAX_ENTRIES = 200_000
_MAX_DEPTH = 64


def _open_directory(path: Path) -> int:
    """Open each component without following symlinks and without creating anything."""
    path = path.absolute()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open(path.anchor, flags)
    try:
        for component in path.parts[1:]:
            if component in {"", ".", ".."}:
                raise ValueError("evidence root contains an unsafe component")
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _measure(directory: int) -> dict[str, object]:
    rows: list[tuple[object, ...]] = []
    byte_count = 0
    allocated_bytes = 0
    unsafe = False

    def visit(parent: int, prefix: str, depth: int) -> None:
        nonlocal byte_count, allocated_bytes, unsafe
        if depth > _MAX_DEPTH:
            raise ValueError("evidence inventory exceeds depth bound")
        for name in sorted(os.listdir(parent)):
            if len(rows) >= _MAX_ENTRIES:
                raise ValueError("evidence inventory exceeds entry bound")
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            relative = prefix + name
            rows.append((relative, info.st_mode, info.st_dev, info.st_ino,
                         info.st_size, info.st_mtime_ns, info.st_ctime_ns))
            allocated_bytes += info.st_blocks * 512
            if stat.S_ISREG(info.st_mode):
                byte_count += info.st_size
            elif stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=parent)
                try:
                    held = os.fstat(child)
                    if (held.st_dev, held.st_ino) != (info.st_dev, info.st_ino):
                        raise ValueError("evidence changed during inventory")
                    visit(child, relative + "/", depth + 1)
                finally:
                    os.close(child)
            else:
                unsafe = True
    visit(directory, "", 0)
    info = os.fstat(directory)
    digest = hashlib.sha256(json.dumps(
        [(info.st_dev, info.st_ino), rows], ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")).hexdigest()
    return {"entries": len(rows), "bytes": byte_count,
            "allocated_bytes": allocated_bytes, "inventory_sha256": digest,
            "unsafe_members": unsafe, "identity": [info.st_dev, info.st_ino]}


def _inspect(parent: int, name: str, *, failure_root: bool) -> dict[str, object]:
    info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    record: dict[str, object] = {"name": name, "status": "protected", "reason": "not a directory"}
    if not stat.S_ISDIR(info.st_mode):
        return record
    directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        held = os.fstat(directory)
        if (held.st_dev, held.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError("evidence changed during open")
        record.update(_measure(directory))
        if failure_root:
            record["reason"] = "failure evidence is always retained"
            return record
        if _UUID.fullmatch(name) is None or record["unsafe_members"]:
            record["reason"] = "unknown run name or unsafe member"
            return record
        try:
            failure = os.stat("historical-benchmark-gate.json", dir_fd=directory,
                              follow_symlinks=False)
        except FileNotFoundError:
            failure = None
        if failure is not None:
            record["reason"] = "failure diagnostic is present"
            return record
        descriptor = os.open(_SUCCESS_MANIFEST_NAME, os.O_RDONLY | os.O_NOFOLLOW,
                             dir_fd=directory)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 64 * 1024:
                raise ValueError("success manifest is not a bounded regular file")
            with os.fdopen(os.dup(descriptor), "rb") as stream:
                raw = stream.read(64 * 1024 + 1)
            if len(raw) > 64 * 1024:
                raise ValueError("success manifest exceeds bound")
            from qtrace.status import load_strict_json
            document = load_strict_json(raw, maximum_bytes=64 * 1024)
            if type(document) is not dict:
                raise ValueError("success manifest is not an object")
            # The trailing slash keeps the final open on the held directory,
            # rather than on the procfs descriptor symlink.
            _validate_success_gate_document(f"/proc/self/fd/{directory}/", document)
        finally:
            os.close(descriptor)
        record.update(status="successful", reason="validated success manifest",
                      head_commit=document["head_commit"], device=document["device"],
                      completed_at=document["completed_at"])
        return record
    except (OSError, RuntimeError, ValueError) as error:
        record.update(status="protected", reason=str(error))
        return record
    finally:
        os.close(directory)


def inventory(workspace: Path) -> dict[str, object]:
    roots = []
    for root_name in _ROOTS:
        root = workspace / root_name
        try:
            descriptor = _open_directory(root)
        except FileNotFoundError:
            roots.append({"root": root_name, "status": "absent", "runs": []})
            continue
        try:
            runs = [_inspect(descriptor, name, failure_root=root_name == _ROOTS[1])
                    for name in sorted(os.listdir(descriptor))]
            roots.append({"root": root_name, "status": "present", "runs": runs})
        finally:
            os.close(descriptor)
    return {"schema": 1, "workspace": str(workspace.absolute()), "roots": roots}


def cleanup(workspace: Path, name: str, expected_digest: str, *, apply: bool = False) -> dict[str, object]:
    if _UUID.fullmatch(name) is None or re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None:
        raise ValueError("cleanup requires an exact successful UUID and inventory SHA-256")
    parent = _open_directory(workspace / _ROOTS[0])
    try:
        record = _inspect(parent, name, failure_root=False)
        if record["status"] != "successful" or record.get("inventory_sha256") != expected_digest:
            raise ValueError("cleanup refused: evidence is protected or inventory changed")
        if not apply:
            return {"action": "preview", "run": record}
        quarantine = ".qtrace-cleanup-" + uuid.uuid4().hex
        _rename_noreplace(parent, name, quarantine)
        quarantined = _inspect(parent, quarantine, failure_root=False)
        # Renaming changes the root ctime only; the digest binds root inode and
        # every member's metadata. The exact held tree must still match review.
        if quarantined.get("inventory_sha256") != expected_digest:
            raise ValueError(f"cleanup refused: changed evidence retained as {quarantine}")
        _remove_tree_at(parent, quarantine, expected_identity=tuple(record["identity"]))
        os.fsync(parent)
        return {"action": "deleted", "name": name, "inventory_sha256": expected_digest}
    finally:
        os.close(parent)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    parser.add_argument("--delete-success", metavar="UUID")
    parser.add_argument("--inventory-sha256", metavar="SHA256")
    parser.add_argument("--apply", action="store_true", help="delete the explicitly reviewed successful run")
    args = parser.parse_args(argv)
    if bool(args.delete_success) != bool(args.inventory_sha256) or (args.apply and not args.delete_success):
        parser.error("--delete-success and --inventory-sha256 are required together; --apply requires both")
    try:
        result = (cleanup(args.workspace, args.delete_success, args.inventory_sha256, apply=args.apply)
                  if args.delete_success else inventory(args.workspace))
    except (OSError, RuntimeError, ValueError) as error:
        parser.exit(1, f"qtrace evidence: {error}\n")
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
