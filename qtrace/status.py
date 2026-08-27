"""Shared structural validation for native qtrace status snapshots."""

from __future__ import annotations

import json
import unicodedata


STATUS_KEYS = frozenset({
    "schemaVersion", "sessionId", "generation", "packageName", "pid", "state", "reason",
    "transitionMonotonicNs", "normalizedScenes", "activeScenes", "artifacts",
    "stopAcknowledged", "warnings", "errors",
})
STATE_ORDER = {
    "installed": 0,
    "running": 1,
    "stop_requested": 2,
    "stopping": 3,
    "sealed": 4,
    "stop_incomplete": 4,
}


class NativeStatusValidationError(ValueError):
    """A native-status shape violation with stable, non-input-derived detail."""

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(detail)


class StrictJsonLoadError(ValueError):
    """A strict JSON decoding violation with a non-input-derived detail."""

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(detail)


def load_strict_json(raw: object, maximum_bytes: int | None = None) -> object:
    """Decode exact bytes as UTF-8 JSON, rejecting duplicate keys and non-finite values."""
    if type(raw) is not bytes:
        raise StrictJsonLoadError("JSON input must be exact bytes")
    if maximum_bytes is not None and (type(maximum_bytes) is not int or maximum_bytes < 0):
        raise StrictJsonLoadError("JSON byte bound is invalid")
    if maximum_bytes is not None and len(raw) > maximum_bytes:
        raise StrictJsonLoadError("JSON input exceeds byte bound")

    def reject_constant(_value: str) -> object:
        raise StrictJsonLoadError("JSON input contains a non-finite number")

    def reject_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise StrictJsonLoadError("JSON input contains a duplicate key")
            result[key] = value
        return result

    try:
        return json.loads(raw.decode("utf-8"), parse_constant=reject_constant,
                          object_pairs_hook=reject_duplicate)
    except StrictJsonLoadError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise StrictJsonLoadError("JSON input is not strict UTF-8 JSON") from error


def _invalid(detail: str) -> NativeStatusValidationError:
    return NativeStatusValidationError(detail)


def _safe_text(value: object, limit: int) -> bool:
    if type(value) is not str:
        return False
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return len(encoded) <= limit and not any(
        unicodedata.category(character) in {"Cc", "Cf", "Zl", "Zp"} for character in value)


def _issues(value: object) -> bool:
    if type(value) is not list or len(value) > 256:
        return False
    return all(
        type(issue) is dict and set(issue) == {"code", "path", "message"}
        and all(_safe_text(issue[key], 1024) for key in issue)
        for issue in value
    )


def validate_status_shape(value: object) -> dict[str, object]:
    """Return an exact native status after validating every context-independent field."""
    if type(value) is not dict or set(value) != STATUS_KEYS:
        raise _invalid("status schema is not exact")
    if type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1:
        raise _invalid("status schema version is invalid")
    if (type(value["generation"]) is not int or value["generation"] <= 0
            or type(value["pid"]) is not int or value["pid"] <= 0
            or type(value["transitionMonotonicNs"]) is not int
            or value["transitionMonotonicNs"] < 0):
        raise _invalid("status numeric fields are invalid")
    if (not _safe_text(value["sessionId"], 64) or not _safe_text(value["packageName"], 256)
            or not _safe_text(value["state"], 64) or not _safe_text(value["reason"], 256)):
        raise _invalid("status text fields are invalid")
    state = value["state"]
    if state not in STATE_ORDER:
        raise _invalid("status state is invalid")
    if type(value["stopAcknowledged"]) is not bool:
        raise _invalid("status terminal fields are invalid")
    if state in {"installed", "running"}:
        terminal_valid = value["reason"] == "" and value["stopAcknowledged"] is False
    elif state in {"stop_requested", "stopping", "stop_incomplete"}:
        terminal_valid = value["reason"] == "duration_elapsed" and value["stopAcknowledged"] is False
    else:
        terminal_valid = value["reason"] == "duration_elapsed" and value["stopAcknowledged"] is True
    if not terminal_valid:
        raise _invalid("status reason/acknowledgement does not match state")

    scenes = value["normalizedScenes"]
    if type(scenes) is not list or len(scenes) > 256 or any(
            type(scene) is not dict or set(scene) != {"name", "startOffset", "endOffset"}
            or not _safe_text(scene["name"], 128)
            or type(scene["startOffset"]) is not int or type(scene["endOffset"]) is not int
            or scene["startOffset"] < 0 or scene["endOffset"] <= scene["startOffset"]
            for scene in scenes):
        raise _invalid("status normalized scenes are invalid")
    if len({scene["name"] for scene in scenes}) != len(scenes):
        raise _invalid("status normalized scene names are duplicated")

    active = value["activeScenes"]
    if type(active) is not list or len(active) > 256 or any(
            type(scene) is not dict or set(scene) != {"sceneIndex", "tid", "sealed"}
            or type(scene["sceneIndex"]) is not int or scene["sceneIndex"] < 0
            or type(scene["tid"]) is not int or scene["tid"] <= 0
            or type(scene["sealed"]) is not bool
            for scene in active):
        raise _invalid("status active scenes are invalid")
    identities = [(scene["sceneIndex"], scene["tid"]) for scene in active]
    if len(set(identities)) != len(identities) or any(index >= len(scenes) for index, _ in identities):
        raise _invalid("status active scene identities are invalid")

    artifacts = value["artifacts"]
    if (type(artifacts) is not list or len(artifacts) > 256
            or any(type(item) is not str for item in artifacts)
            or len(set(artifacts)) != len(artifacts)):
        raise _invalid("status artifacts are invalid")
    if not _issues(value["warnings"]) or not _issues(value["errors"]):
        raise _invalid("status issues are invalid")
    return dict(value)
