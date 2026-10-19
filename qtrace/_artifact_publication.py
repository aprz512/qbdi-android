"""Held directory identities, atomic stage publication, and recovery quarantine."""

from __future__ import annotations

import ctypes
import errno
import os
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, TYPE_CHECKING

from qtrace._artifact_common import _cleanup_exhaustively, _close_descriptor, _error
from qtrace.errors import QtraceError

if TYPE_CHECKING:
    from qtrace._artifact_reports import _PublicationToken


@dataclass
class _OutputDirectory:
    """A held output-directory identity, not a path that can be swapped mid-pull."""
    path: Path
    descriptor: int
    device: int
    inode: int

    def assert_identity(self) -> None:
        try:
            current = os.stat(self.path, follow_symlinks=False)
        except OSError as error:
            raise _error("artifact.destination_replaced", "output directory is no longer available") from error
        if (not stat.S_ISDIR(current.st_mode)
                or (current.st_dev, current.st_ino) != (self.device, self.inode)):
            raise _error("artifact.destination_replaced", "output directory identity changed during pull")
    def result_path(self, child: str) -> Path:
        self.assert_identity()
        return self.path / child

    def close(self) -> None:
        descriptor, self.descriptor = self.descriptor, -1
        _cleanup_exhaustively([("output directory", lambda: _close_descriptor(descriptor))])


def _safe_output(path: Path) -> Path:
    output = _open_output(path)
    try:
        return output.path
    finally:
        output.close()


def _open_output(path: Path) -> _OutputDirectory:
    """Create/open output components once with openat no-follow semantics."""
    path = Path(path)
    internal_fd = path.is_absolute() and path.parts[:4] == ("/", "proc", "self", "fd")
    if internal_fd:
        try:
            source = int(path.parts[4])
        except (IndexError, ValueError) as error:
            raise _error("artifact.destination_invalid", "output descriptor path is invalid") from error
        parts = path.parts[5:]
    else:
        parts = path.parts[1:] if path.is_absolute() else path.parts
    if any(component in {"", ".", ".."} for component in parts):
        raise _error("artifact.destination_invalid", "output contains an unsafe component")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = -1
    try:
        descriptor = os.dup(source) if internal_fd else os.open(
            path.anchor if path.is_absolute() else ".", flags)
        for component in parts:
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                try:
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode):
            raise _error("artifact.destination_invalid", "output must be a directory")
        return _OutputDirectory(path, descriptor, info.st_dev, info.st_ino)
    except QtraceError:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise _error("artifact.destination_invalid", "output contains a symlink or non-directory") from error


def _rename_noreplace(parent: int, stage_name: str, final_name: str) -> None:
    """Atomically publish a complete staging directory without replacing anything."""
    if os.name != "posix":
        raise _error("artifact.atomic_unsupported", "atomic no-replace publication is unavailable")
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise _error("artifact.atomic_unsupported", "Linux renameat2 is unavailable")
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    result = renameat2(parent, stage_name.encode(), parent, final_name.encode(), 1)
    if result != 0:
        failure = ctypes.get_errno()
        if failure == errno.EEXIST:
            raise _error("artifact.destination_exists", "session destination already exists")
        raise OSError(failure, os.strerror(failure))


def _remove_tree_at(parent: int, name: str,
                    expected_identity: tuple[int, int] | None = None) -> None:
    """Remove a tree only while its parent entry names the opened directory inode."""
    try:
        root = os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                       getattr(os, "O_NOFOLLOW", 0), dir_fd=parent)
    except FileNotFoundError:
        if expected_identity is not None:
            raise OSError("tree identity changed before opening")
        return
    except OSError as error:
        if expected_identity is not None:
            raise OSError("tree identity changed before opening") from error
        raise
    try:
        root_info = os.fstat(root)
        root_identity = (root_info.st_dev, root_info.st_ino)
        if (not stat.S_ISDIR(root_info.st_mode)
                or (expected_identity is not None and root_identity != expected_identity)):
            raise OSError("tree identity changed after opening")
        for child in os.listdir(root):
            info = os.stat(child, dir_fd=root, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                _remove_tree_at(root, child, expected_identity=(info.st_dev, info.st_ino))
            else:
                os.unlink(child, dir_fd=root)
    finally:
        os.close(root)
    current = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if (not stat.S_ISDIR(current.st_mode)
            or (current.st_dev, current.st_ino) != root_identity):
        raise OSError("tree identity changed before final rmdir")
    os.rmdir(name, dir_fd=parent)


def _reclaim_parent_fallback_sibling(parent: int, name: str,
                                     expected_identity: tuple[int, int]) -> None:
    """Quarantine a parent fallback as a recovery file without deleting by name."""
    quarantine = ""
    for _ in range(32):
        candidate = ".qtrace-reclaim-sibling-" + uuid.uuid4().hex
        try:
            _rename_noreplace(parent, name, candidate)
        except QtraceError as error:
            if error.code == "artifact.destination_exists":
                continue
            raise OSError(f"parent fallback identity changed before quarantine rename: {error}") from error
        except OSError as error:
            raise OSError(f"parent fallback identity changed before quarantine rename: {error}") from error
        quarantine = candidate
        break
    if not quarantine:
        raise OSError("parent fallback quarantine allocation exhausted")

    probe = -1
    try:
        probe = os.open(quarantine, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                        getattr(os, "O_CLOEXEC", 0), dir_fd=parent)
        quarantined = os.fstat(probe)
    except BaseException as error:
        raise OSError(
            f"parent fallback recovery file={quarantine}; unable to verify identity: {error}") from error
    finally:
        _close_descriptor(probe)
    if (not stat.S_ISREG(quarantined.st_mode)
            or (quarantined.st_dev, quarantined.st_ino) != expected_identity):
        raise OSError(f"parent fallback recovery file={quarantine}; identity changed")
    try:
        os.fsync(parent)
    except BaseException as error:
        raise OSError(f"parent fallback recovery file={quarantine}; parent fsync failed: {error}") from error
    raise OSError(f"parent fallback recovery file={quarantine}")


def _note_parent_fallback_cleanup_failure(primary: BaseException,
                                          failure: BaseException) -> None:
    detail = f"parent fallback sibling cleanup failed: {failure}"
    if isinstance(primary, QtraceError):
        normalized = QtraceError(primary.code, primary.stage,
                                 f"{primary.detail}; {detail}", exit_code=primary.exit_code)
        primary.detail = normalized.detail
        primary.args = (primary.detail,)
    if hasattr(primary, "add_note"):
        primary.add_note(detail)


def _reclaim_committed_session(parent: int, directory: int, session_id: str) -> None:
    """Quarantine a held committed directory as recovery without recursive deletion."""
    expected = os.fstat(directory)
    if not stat.S_ISDIR(expected.st_mode):
        raise OSError("committed session identity changed before reclaim")
    expected_identity = (expected.st_dev, expected.st_ino)
    quarantine = ""
    for _ in range(32):
        candidate = ".qtrace-reclaim-" + uuid.uuid4().hex
        try:
            _rename_noreplace(parent, session_id, candidate)
        except QtraceError as error:
            if error.code == "artifact.destination_exists":
                continue
            raise OSError(f"committed session identity changed before quarantine rename: {error}") from error
        except OSError as error:
            raise OSError(f"committed session identity changed before quarantine rename: {error}") from error
        quarantine = candidate
        break
    if not quarantine:
        raise OSError("committed session quarantine allocation exhausted")

    probe = -1
    try:
        probe = os.open(quarantine, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                        getattr(os, "O_NOFOLLOW", 0), dir_fd=parent)
        quarantined = os.fstat(probe)
    except BaseException as error:
        raise OSError(
            f"committed session recovery directory={quarantine}; unable to verify identity: {error}") from error
    finally:
        _close_descriptor(probe)
    if (not stat.S_ISDIR(quarantined.st_mode)
            or (quarantined.st_dev, quarantined.st_ino) != expected_identity):
        raise OSError(f"committed session recovery directory={quarantine}; identity changed")
    try:
        os.fsync(parent)
    except BaseException as error:
        raise OSError(
            f"committed session recovery directory={quarantine}; parent fsync failed: {error}") from error
    raise OSError(f"committed session recovery directory={quarantine}")


def _note_committed_cleanup_failure(primary: BaseException, failure: BaseException) -> None:
    """Keep a destination replacement primary while making any orphan risk explicit."""
    detail = f"committed session cleanup failed: {failure}"
    if isinstance(primary, QtraceError):
        normalized = QtraceError(primary.code, primary.stage,
                                 f"{primary.detail}; {detail}", exit_code=primary.exit_code)
        primary.detail = normalized.detail
        primary.args = (primary.detail,)
    if hasattr(primary, "add_note"):
        primary.add_note(detail)


def _close_token_and_reclaim(parent: int, directory: int, session_id: str,
                             token: _PublicationToken | None,
                             primary: BaseException | None = None) -> None:
    """Close result capabilities, then reclaim the held committed directory if still ours."""
    failures: list[BaseException] = []
    if token is not None:
        try:
            token.close()
        except BaseException as error:
            failures.append(error)
    try:
        _reclaim_committed_session(parent, directory, session_id)
    except BaseException as error:
        failures.append(error)
    if primary is None:
        if failures:
            raise failures[0]
        return
    for failure in failures:
        _note_committed_cleanup_failure(primary, failure)


def _new_stage(output: _OutputDirectory) -> tuple[Path, int, int, str]:
    """Create stage and artifacts using one trusted output directory descriptor."""
    parent = os.dup(output.descriptor)
    try:
        for _ in range(32):
            name = ".qtrace-stage-" + uuid.uuid4().hex
            try:
                os.mkdir(name, 0o700, dir_fd=parent)
            except FileExistsError:
                continue
            try:
                stage_fd = os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                                   getattr(os, "O_NOFOLLOW", 0), dir_fd=parent)
            except BaseException:
                _remove_tree_at(parent, name)
                raise
            try:
                os.mkdir("artifacts", 0o700, dir_fd=stage_fd)
            except BaseException:
                os.close(stage_fd)
                _remove_tree_at(parent, name)
                raise
            # Keep every subsequent Path operation rooted at the held descriptor;
            # the proc fd remains valid even if an attacker swaps output names.
            return Path(f"/proc/self/fd/{stage_fd}"), parent, stage_fd, name
        raise _error("artifact.stage_failed", "unable to allocate a unique staging directory")
    except BaseException:
        os.close(parent)
        raise


def publish_stage(stage: Path, output: _OutputDirectory, session_id: str, files: list[Path],
             errors: list[Mapping[str, str]], records: list[Mapping[str, object]],
             *, parent: int | None = None, stage_fd: int | None = None,
             stage_name: str | None = None) -> Path:
    owned_parent = parent is None
    if parent is None:
        parent = os.dup(output.descriptor)
    if stage_name is None:
        stage_name = stage.name
    committed = False
    try:
        for directory_name in (".", "artifacts"):
            if stage_fd is not None and directory_name == ".":
                descriptor = stage_fd
            elif stage_fd is not None:
                descriptor = os.open(directory_name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                                      getattr(os, "O_NOFOLLOW", 0), dir_fd=stage_fd)
            else:
                descriptor = os.open(stage if directory_name == "." else stage / directory_name,
                                     os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                                     getattr(os, "O_NOFOLLOW", 0))
            try:
                os.fsync(descriptor)
            finally:
                if not (directory_name == "." and stage_fd is not None):
                    os.close(descriptor)
        output.assert_identity()
        _rename_noreplace(parent, stage_name, session_id)
        committed = True
        final = output.result_path(session_id)
        descriptor = os.open(session_id, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                             getattr(os, "O_NOFOLLOW", 0), dir_fd=parent)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(parent)
    except BaseException as error:
        if committed and isinstance(error, QtraceError) and error.code == "artifact.destination_replaced":
            if stage_fd is not None:
                _close_token_and_reclaim(parent, stage_fd, session_id, None, error)
            raise
        if committed:
            failure = {"name": "", "code": "artifact.commit_durable",
                       "detail": f"published session durability is uncertain: {error}"[:256]}
            errors.append(failure)
            records.append(failure)
            return output.result_path(session_id)
        raise
    finally:
        if owned_parent and parent is not None:
            os.close(parent)
    return final
