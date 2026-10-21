"""Bounded human summaries of already validated capture evidence."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from qtrace.errors import _single_line_utf8


_MAX_CAPTURES = 8
_MAX_OPEN_SCENES = 4
_OUTCOMES = {0: "complete", 1: "failed", 2: "partial recovery", 3: "stop incomplete", 130: "interrupted"}


def _label(value: object) -> str:
    return "unknown" if value is None else _single_line_utf8(value, max_bytes=160)


def _count(value: object) -> str:
    return str(value) if type(value) is int and value >= 0 else "unknown"


def format_capture_summary(exit_code: int, records: Sequence[Mapping[str, object]], *,
                           lifecycle: object = None) -> tuple[str, ...]:
    """Keep collection, status snapshots, and recorded target returns distinct."""
    lines = [f"Collection: {_OUTCOMES.get(exit_code, 'unknown')} (exit {exit_code})"]
    if isinstance(lifecycle, Mapping):
        lines.append(f"Capture: {_label(lifecycle.get('capture_state'))}; "
                     f"process: {_label(lifecycle.get('process_state'))}")
        opened = lifecycle.get("open_scenes", [])
        for scene in opened[:_MAX_OPEN_SCENES]:
            capture = ("sealed" if scene.get("capture_sealed") is True else
                       "open" if scene.get("capture_sealed") is False else "unknown")
            state = "process exited" if scene.get("state") == "process_exited" else "open at status snapshot"
            lines.append(f"Target {_label(scene.get('scene'))} (TID {_label(scene.get('tid'))}): "
                         f"{state}; capture {capture}; return unknown")
        if len(opened) > _MAX_OPEN_SCENES:
            lines.append(f"{len(opened) - _MAX_OPEN_SCENES} more target scenes; see report")

    captures = [record for record in records if record.get("decoder") not in {None, "sidecar"}]
    has_unknown = not captures
    for record in captures[:_MAX_CAPTURES]:
        prefix = f"Capture {_label(record.get('remote_name'))}: "
        if record.get("decoder") == "flight":
            scenes = record.get("scene_lifecycle", [])
            returned = sum(scene.get("target_returned") is True for scene in scenes)
            lines.append(prefix + f"retained data {_label(record.get('recovery_status'))}; "
                         f"scene returns observed {returned}; unconfirmed {len(scenes) - returned}; "
                         f"omitted {_count(record.get('scene_lifecycle_omitted'))}; "
                         f"invalid {_count(record.get('scene_lifecycle_invalid'))}; "
                         f"missing sequence ranges {_count(record.get('missing_sequence_ranges'))}; "
                         f"coverage gaps {_count(record.get('coverage_gap_count'))}")
            has_unknown = True
        else:
            returned = record.get("target_returned_in_capture") is True
            lines.append(prefix + f"target return {'observed' if returned else 'unknown'}; "
                         f"{_label(record.get('target_stop_reason') or record.get('termination'))}")
            has_unknown = has_unknown or not returned
    if len(captures) > _MAX_CAPTURES:
        lines.append(f"{len(captures) - _MAX_CAPTURES} more captures; see report")
    issues = sum(record.get("code") is not None for record in records)
    if issues:
        lines.append(f"Artifact issues: {issues}; see report")
    if not captures:
        lines.append("Target return: unknown (no decoded capture evidence)")
    if has_unknown:
        lines.append("File completeness does not prove target return.")
    return tuple(lines)
