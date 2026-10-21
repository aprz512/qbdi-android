"""Describe target lifecycle separately from capture/file completeness."""
from __future__ import annotations

from collections.abc import Mapping, Sequence


def summarize_lifecycle(status: Mapping[str, object] | None,
                        artifacts: Sequence[Mapping[str, object]], *,
                        process_exited: bool = False) -> dict[str, object]:
    status = status or {}
    scenes = status.get("normalizedScenes", [])
    opened = []
    for active in status.get("activeScenes", []):
        index = active["sceneIndex"]
        name = scenes[index]["name"] if index < len(scenes) else None
        opened.append({"scene": name, "scene_index": index, "tid": active["tid"],
                       "state": "process_exited" if process_exited else "open_at_snapshot",
                       "capture_sealed": active["sealed"], "target_returned": None})
    captured = []
    for artifact in artifacts:
        if artifact.get("decoder") not in {"qtrb", "flight"}:
            continue
        returned = artifact.get("target_returned_in_capture")
        boundary_state = {"thread_exit": "thread_exited", "process_exit": "process_exit_boundary",
                          "exec_boundary": "exec_boundary"}.get(artifact.get("target_stop_reason"))
        state = ("returned" if returned is True else boundary_state or
                 ("capture_stopped" if artifact.get("termination") == "stopped" else "unknown"))
        captured.append({"artifact": artifact.get("remote_name"),
                         "scene": artifact.get("scene_name"), "tid": artifact.get("tid"),
                         "state": state, "target_returned": True if returned is True else None,
                         "scene_lifecycle": artifact.get("scene_lifecycle", [])})
    return {"capture_state": status.get("state", "unknown"),
            "process_state": "exited" if process_exited else "unknown",
            "snapshot_monotonic_ns": status.get("transitionMonotonicNs"),
            "deadline_monotonic_ns": status.get("deadlineMonotonicNs"),
            "open_scenes": opened, "captures": captured}
