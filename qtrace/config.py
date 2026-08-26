import json
import re
import unicodedata
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from qtrace.errors import ConfigError
from qtrace.models import (
    AppConfig,
    OffsetScene,
    SceneSpec,
    SymbolScene,
    TargetConfig,
    TracerConfig,
    UserConfig,
)


_DURATION_RE = re.compile(r"([0-9]+(?:\.[0-9]+)?)(ms|s|m)\Z")
_OFFSET_RE = re.compile(r"0x[0-9a-fA-F]+\Z")
_DURATION_FACTORS = {"ms": Decimal(1), "s": Decimal(1000), "m": Decimal(60_000)}
_MIN_DURATION_MS = 100
_MAX_DURATION_MS = 24 * 60 * 60 * 1000
_PROFILES = frozenset(("fast", "balanced", "full"))


class _StrictJsonError(ValueError):
    pass


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _StrictJsonError(f"duplicate object key {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise _StrictJsonError(f"non-finite JSON constant {value}")


def _fail(code: str, detail: str) -> None:
    raise ConfigError(code, detail)


def parse_duration_ms(text: str) -> int:
    if type(text) is not str:
        _fail("DURATION_INVALID", "duration must be a decimal string with ms, s, or m")
    match = _DURATION_RE.fullmatch(text)
    if match is None:
        _fail("DURATION_INVALID", "duration must be a decimal string with ms, s, or m")
    try:
        milliseconds = Decimal(match.group(1)) * _DURATION_FACTORS[match.group(2)]
    except InvalidOperation:
        _fail("DURATION_INVALID", "duration is not finite decimal milliseconds")
    if milliseconds != milliseconds.to_integral_value():
        _fail("DURATION_INVALID", "duration must resolve to whole milliseconds")
    value = int(milliseconds)
    if not _MIN_DURATION_MS <= value <= _MAX_DURATION_MS:
        _fail("DURATION_INVALID", "duration must be between 100 ms and 24 h")
    return value


def _expect_object(value: Any, location: str) -> dict[str, Any]:
    if type(value) is not dict:
        _fail("CONFIG_TYPE_INVALID", f"{location} must be an object")
    return value


def _check_keys(
    value: dict[str, Any],
    location: str,
    *,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
) -> None:
    unknown = set(value) - required - optional
    if unknown:
        _fail("CONFIG_UNKNOWN_FIELD", f"{location} contains unknown field {sorted(unknown)[0]}")
    missing = required - set(value)
    if missing:
        _fail("CONFIG_MISSING_FIELD", f"{location} is missing field {sorted(missing)[0]}")


def _string(value: Any, location: str) -> str:
    if type(value) is not str:
        _fail("CONFIG_TYPE_INVALID", f"{location} must be a string")
    if not value:
        _fail("CONFIG_VALUE_INVALID", f"{location} must not be empty")
    _validate_unicode_text(value, location, "CONFIG_VALUE_INVALID")
    return value


def _validate_unicode_text(value: str, location: str, code: str) -> None:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        _fail(code, f"{location} must contain valid Unicode")
    if any(unicodedata.category(character) == "Cc" for character in value):
        _fail(code, f"{location} must not contain control characters")


def _optional_path(value: dict[str, Any], key: str, location: str, base: Path) -> Path | None:
    if key not in value:
        return None
    raw = _string(value[key], f"{location}.{key}")
    try:
        return (base / raw).resolve()
    except (OSError, RuntimeError, ValueError):
        _fail("CONFIG_VALUE_INVALID", f"{location}.{key} cannot be resolved")


def _boolean(value: dict[str, Any], key: str, default: bool) -> bool:
    if key not in value:
        return default
    selected = value[key]
    if type(selected) is not bool:
        _fail("CONFIG_TYPE_INVALID", f"tracer.{key} must be a boolean")
    return selected


def _scene_name(value: Any) -> str:
    if type(value) is not str or not value:
        _fail("SCENE_NAME_INVALID", "scene name must be a nonempty string")
    _validate_unicode_text(value, "scene name", "SCENE_NAME_INVALID")
    byte_length = len(value.encode("utf-8"))
    if byte_length > 128:
        _fail("SCENE_NAME_INVALID", "scene name must be at most 128 UTF-8 bytes")
    return value


def _offset(value: Any, field: str) -> int:
    if type(value) is not str or _OFFSET_RE.fullmatch(value) is None:
        _fail("SCENE_OFFSET_INVALID", f"{field} must be a 0x-prefixed hexadecimal string")
    parsed = int(value, 16)
    if parsed == 0 or parsed % 4 != 0:
        _fail("SCENE_OFFSET_INVALID", f"{field} must be nonzero and four-byte aligned")
    return parsed


def _scene(value: Any, index: int) -> SceneSpec:
    location = f"scenes[{index}]"
    scene = _expect_object(value, location)
    keys = set(scene)
    symbol_form = keys == {"name", "symbol"}
    offset_form = keys == {"name", "startOffset", "endOffset"}
    if not symbol_form and not offset_form:
        _fail(
            "SCENE_FORM_INVALID",
            f"{location} must contain name plus symbol or startOffset and endOffset",
        )
    name = _scene_name(scene["name"])
    if symbol_form:
        symbol = _string(scene["symbol"], f"{location}.symbol")
        return SymbolScene(name=name, symbol=symbol)
    start_offset = _offset(scene["startOffset"], f"{location}.startOffset")
    end_offset = _offset(scene["endOffset"], f"{location}.endOffset")
    if start_offset >= end_offset:
        _fail("SCENE_OFFSET_INVALID", f"{location} must be a strict half-open range")
    return OffsetScene(name=name, start_offset=start_offset, end_offset=end_offset)


def _load_app(value: Any, base: Path) -> AppConfig:
    app = _expect_object(value, "app")
    _check_keys(
        app,
        "app",
        required=frozenset(("package",)),
        optional=frozenset(("apk",)),
    )
    return AppConfig(
        package=_string(app["package"], "app.package"),
        apk=_optional_path(app, "apk", "app", base),
    )


def _load_target(value: Any, base: Path) -> TargetConfig:
    target = _expect_object(value, "target")
    _check_keys(
        target,
        "target",
        required=frozenset(("module",)),
        optional=frozenset(("binary",)),
    )
    return TargetConfig(
        module=_string(target["module"], "target.module"),
        binary=_optional_path(target, "binary", "target", base),
    )


def _load_tracer(value: Any, base: Path, scene_names: frozenset[str]) -> TracerConfig:
    tracer = _expect_object(value, "tracer")
    _check_keys(
        tracer,
        "tracer",
        required=frozenset(),
        optional=frozenset((
            "profile",
            "compression",
            "flightEnabled",
            "flightEntryScene",
            "library",
            "companion",
        )),
    )
    profile = tracer.get("profile", "fast")
    if type(profile) is not str:
        _fail("CONFIG_TYPE_INVALID", "tracer.profile must be a string")
    if profile not in _PROFILES:
        _fail("CONFIG_VALUE_INVALID", "tracer.profile must be fast, balanced, or full")
    compression = _boolean(tracer, "compression", True)
    flight_enabled = _boolean(tracer, "flightEnabled", False)
    library = _optional_path(tracer, "library", "tracer", base)
    companion = _optional_path(tracer, "companion", "tracer", base)
    if (library is None) != (companion is None):
        _fail("TRACER_PATH_PAIR_INVALID", "tracer library and companion must be provided together")

    entry_present = "flightEntryScene" in tracer
    if flight_enabled:
        if not entry_present or type(tracer["flightEntryScene"]) is not str:
            _fail("FLIGHT_ENTRY_SCENE_INVALID", "Flight requires a named entry scene")
        flight_entry_scene = tracer["flightEntryScene"]
        if not flight_entry_scene:
            _fail("FLIGHT_ENTRY_SCENE_INVALID", "Flight requires a named entry scene")
        _validate_unicode_text(
            flight_entry_scene,
            "tracer.flightEntryScene",
            "FLIGHT_ENTRY_SCENE_INVALID",
        )
        if flight_entry_scene not in scene_names:
            _fail("FLIGHT_ENTRY_SCENE_INVALID", "Flight entry scene does not name a configured scene")
    else:
        if entry_present:
            _fail("FLIGHT_ENTRY_SCENE_INVALID", "flightEntryScene is forbidden when Flight is disabled")
        flight_entry_scene = None

    return TracerConfig(
        profile=profile,
        compression=compression,
        flight_enabled=flight_enabled,
        flight_entry_scene=flight_entry_scene,
        library=library,
        companion=companion,
    )


def load_config(path: Path) -> UserConfig:
    try:
        config_path = Path(path).resolve()
    except (OSError, RuntimeError, TypeError, ValueError):
        _fail("CONFIG_JSON_INVALID", "config path cannot be resolved")
    try:
        root_value = json.loads(
            config_path.read_text(encoding="utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, _StrictJsonError) as error:
        _fail("CONFIG_JSON_INVALID", f"cannot read strict JSON config: {error}")
    root = _expect_object(root_value, "root")
    _check_keys(
        root,
        "root",
        required=frozenset(("schemaVersion", "app", "target", "scenes")),
        optional=frozenset(("tracer",)),
    )
    if type(root["schemaVersion"]) is not int or root["schemaVersion"] != 1:
        _fail("CONFIG_SCHEMA_INVALID", "schemaVersion must be integer 1")

    scenes_value = root["scenes"]
    if type(scenes_value) is not list or not 1 <= len(scenes_value) <= 256:
        _fail("SCENE_COUNT_INVALID", "scenes must contain between 1 and 256 entries")
    scenes = tuple(_scene(value, index) for index, value in enumerate(scenes_value))
    scene_names = [scene.name for scene in scenes]
    if len(set(scene_names)) != len(scene_names):
        _fail("SCENE_NAME_DUPLICATE", "scene names must be unique")

    base = config_path.parent
    tracer_value = root.get("tracer", {})
    return UserConfig(
        schema_version=1,
        app=_load_app(root["app"], base),
        target=_load_target(root["target"], base),
        tracer=_load_tracer(tracer_value, base, frozenset(scene_names)),
        scenes=scenes,
    )
