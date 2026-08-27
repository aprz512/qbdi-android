"""Host contracts for the manual qtrace device-acceptance gate."""

from __future__ import annotations

import copy
import json
import re
import subprocess
import tempfile
import time
import unicodedata
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from qtrace.config import load_config
from qtrace.artifacts import ArtifactProcessor, PullMode, PullSelection
from qtrace.errors import ConfigError, QtraceError
from qtrace.models import ResolvedScene
from qtrace.session import parse_status
from qtrace.status import STATUS_KEYS, validate_status_shape
from scripts.tests.test_pull_trace import stopped_binary_stream
from scripts.tests.test_qtrace_artifacts import COMPLETE_TERMINAL, FakeClient
from scripts.tests.test_trace_convert import fake_lz4_executable
from scripts.tests.test_lz4_frames import uncompressed_lz4_frame
from scripts.tests.test_pull_trace import recoverable_flight_artifact
from scripts.tests.test_trace_convert import metrics_sidecar


ROOT = Path(__file__).resolve().parents[2]
SESSION = "123e4567-e89b-42d3-a456-426614174000"


class ProjectSchemaValidationError(ValueError):
    pass


class QtraceProjectSchemaEvaluator:
    """Evaluate only the JSON Schema subset and x-rules used by qtrace docs.

    This deliberately is not a general JSON Schema validator. Unknown keywords,
    remote references, formats, and runtime predicates fail closed so the tests
    cannot silently claim support for contracts that they did not execute.
    """

    _SUPPORTED_KEYS = frozenset({
        "$schema", "$id", "$ref", "$defs", "title", "type", "const", "enum",
        "required", "properties", "additionalProperties", "minItems", "maxItems",
        "items", "uniqueItems", "minLength", "maxLength", "pattern", "format",
        "minimum", "maximum", "oneOf", "allOf", "if", "then", "else", "not",
        "x-qtrace-runtime-invariants",
    })

    def __init__(self, schema: dict[str, object]) -> None:
        schema_id = schema.get("$id")
        if schema_id not in {
            "https://qbdi-android.local/schema/qtrace-config.schema.json",
            "https://qbdi-android.local/schema/qtrace-session-status.schema.json",
        }:
            raise ProjectSchemaValidationError("unsupported qtrace schema")
        self.schema = schema

    def accepts(self, value: object) -> bool:
        try:
            self._validate(value, self.schema)
        except ProjectSchemaValidationError:
            return False
        return True

    def _matches(self, value: object, schema: dict[str, object]) -> bool:
        try:
            self._validate(value, schema)
        except ProjectSchemaValidationError:
            return False
        return True

    def _validate(self, value: object, schema: dict[str, object]) -> None:
        unknown = set(schema) - self._SUPPORTED_KEYS
        if unknown:
            raise ProjectSchemaValidationError(
                f"unsupported project schema keyword {sorted(unknown)[0]}"
            )
        if "$ref" in schema:
            reference = schema["$ref"]
            if type(reference) is not str or not reference.startswith("#/$defs/"):
                raise ProjectSchemaValidationError("unsupported schema reference")
            name = reference.removeprefix("#/$defs/")
            definitions = self.schema.get("$defs")
            if type(definitions) is not dict or type(definitions.get(name)) is not dict:
                raise ProjectSchemaValidationError("missing schema definition")
            self._validate(value, definitions[name])

        expected_type = schema.get("type")
        type_matches = {
            "object": type(value) is dict,
            "array": type(value) is list,
            "string": type(value) is str,
            "integer": type(value) is int,
            "boolean": type(value) is bool,
        }
        if expected_type is not None:
            if expected_type not in type_matches:
                raise ProjectSchemaValidationError("unsupported schema type")
            if not type_matches[expected_type]:
                raise ProjectSchemaValidationError("schema type mismatch")
        if "const" in schema and (type(value) is not type(schema["const"])
                                  or value != schema["const"]):
            raise ProjectSchemaValidationError("schema const mismatch")
        if "enum" in schema and not any(
            type(value) is type(candidate) and value == candidate
            for candidate in schema["enum"]
        ):
            raise ProjectSchemaValidationError("schema enum mismatch")

        if type(value) is dict:
            required = schema.get("required", [])
            if any(key not in value for key in required):
                raise ProjectSchemaValidationError("schema required property missing")
            properties = schema.get("properties", {})
            if type(properties) is not dict:
                raise ProjectSchemaValidationError("invalid project properties")
            if schema.get("additionalProperties") is False and set(value) - set(properties):
                raise ProjectSchemaValidationError("schema additional property")
            for key, child_schema in properties.items():
                if key in value:
                    self._validate(value[key], child_schema)
        if type(value) is list:
            if "minItems" in schema and len(value) < schema["minItems"]:
                raise ProjectSchemaValidationError("schema array too short")
            if "maxItems" in schema and len(value) > schema["maxItems"]:
                raise ProjectSchemaValidationError("schema array too long")
            if schema.get("uniqueItems") is True:
                serialized = [json.dumps(item, sort_keys=True, ensure_ascii=True) for item in value]
                if len(set(serialized)) != len(serialized):
                    raise ProjectSchemaValidationError("schema array items are duplicated")
            if "items" in schema:
                for item in value:
                    self._validate(item, schema["items"])
        if type(value) is str:
            if "minLength" in schema and len(value) < schema["minLength"]:
                raise ProjectSchemaValidationError("schema string too short")
            if "maxLength" in schema and len(value) > schema["maxLength"]:
                raise ProjectSchemaValidationError("schema string too long")
            if "pattern" in schema and re.search(schema["pattern"], value) is None:
                raise ProjectSchemaValidationError("schema string pattern mismatch")
            if "format" in schema and schema["format"] != "uuid":
                raise ProjectSchemaValidationError("unsupported project format")
        if type(value) is int and type(value) is not bool:
            if "minimum" in schema and value < schema["minimum"]:
                raise ProjectSchemaValidationError("schema number below minimum")
            if "maximum" in schema and value > schema["maximum"]:
                raise ProjectSchemaValidationError("schema number above maximum")

        if "oneOf" in schema:
            if sum(self._matches(value, candidate) for candidate in schema["oneOf"]) != 1:
                raise ProjectSchemaValidationError("schema oneOf mismatch")
        for candidate in schema.get("allOf", []):
            self._validate(value, candidate)
        if "if" in schema:
            branch = "then" if self._matches(value, schema["if"]) else "else"
            if branch in schema:
                self._validate(value, schema[branch])
        if "not" in schema and self._matches(value, schema["not"]):
            raise ProjectSchemaValidationError("schema not mismatch")
        if "x-qtrace-runtime-invariants" in schema:
            self._validate_runtime_rules(value, schema["x-qtrace-runtime-invariants"])

    @staticmethod
    def _pointer_values(root: object, pointer: str) -> list[object]:
        if not pointer.startswith("/"):
            raise ProjectSchemaValidationError("runtime rule path is not a JSON pointer")
        current = [root]
        for encoded in pointer.split("/")[1:]:
            token = encoded.replace("~1", "/").replace("~0", "~")
            following: list[object] = []
            for value in current:
                if token == "*":
                    if type(value) is list:
                        following.extend(value)
                    elif type(value) is dict:
                        following.extend(value.values())
                elif type(value) is dict and token in value:
                    following.append(value[token])
                elif type(value) is list and token.isdecimal() and int(token) < len(value):
                    following.append(value[int(token)])
            current = following
        return current

    def _single_pointer(self, root: object, pointer: str) -> object | None:
        values = self._pointer_values(root, pointer)
        if len(values) > 1:
            raise ProjectSchemaValidationError("runtime rule pointer is not singular")
        return values[0] if values else None

    def _validate_runtime_rules(self, root: object, rules: object) -> None:
        if type(rules) is not list:
            raise ProjectSchemaValidationError("runtime rules must be an array")
        identifiers: list[str] = []
        for rule in rules:
            if type(rule) is not dict or set(rule) != {"id", "paths", "predicate", "args"}:
                raise ProjectSchemaValidationError("runtime rule shape is not exact")
            if (type(rule["id"]) is not str or type(rule["paths"]) is not list
                    or not rule["paths"] or not all(type(path) is str for path in rule["paths"])
                    or type(rule["predicate"]) is not str or type(rule["args"]) is not dict):
                raise ProjectSchemaValidationError("runtime rule fields are invalid")
            identifiers.append(rule["id"])
            predicate = getattr(self, f"_rule_{rule['predicate'].replace('-', '_')}", None)
            if predicate is None:
                raise ProjectSchemaValidationError("unsupported runtime predicate")
            predicate(root, rule["paths"], rule["args"])
        if len(set(identifiers)) != len(identifiers):
            raise ProjectSchemaValidationError("runtime rule ids are duplicated")

    def _rule_utf8_text(self, root: object, paths: list[str], args: dict[str, object]) -> None:
        if set(args) != {"minBytes", "maxBytes", "forbiddenCategories"}:
            raise ProjectSchemaValidationError("utf8-text args are not exact")
        for path in paths:
            for value in self._pointer_values(root, path):
                if type(value) is not str:
                    raise ProjectSchemaValidationError("runtime text is not a string")
                try:
                    encoded = value.encode("utf-8")
                except UnicodeEncodeError as error:
                    raise ProjectSchemaValidationError("runtime text is not UTF-8") from error
                if len(encoded) < args["minBytes"]:
                    raise ProjectSchemaValidationError("runtime text is too short")
                if args["maxBytes"] is not None and len(encoded) > args["maxBytes"]:
                    raise ProjectSchemaValidationError("runtime text is too long")
                if any(unicodedata.category(character) in args["forbiddenCategories"]
                       for character in value):
                    raise ProjectSchemaValidationError("runtime text category is forbidden")

    def _rule_unique_field(self, root: object, paths: list[str], args: dict[str, object]) -> None:
        if set(args) != {"field", "caseSensitive"} or args["caseSensitive"] is not True:
            raise ProjectSchemaValidationError("unique-field args are not exact")
        values = [value for path in paths for value in self._pointer_values(root, path)]
        if len(set(values)) != len(values):
            raise ProjectSchemaValidationError("runtime field values are duplicated")

    def _rule_ordered_hex_fields(self, root: object, paths: list[str], args: dict[str, object]) -> None:
        if set(args) != {"startField", "endField", "minimumExclusive", "alignment"}:
            raise ProjectSchemaValidationError("ordered-hex-fields args are not exact")
        for path in paths:
            for value in self._pointer_values(root, path):
                if type(value) is not dict or args["startField"] not in value:
                    continue
                try:
                    start_text = value[args["startField"]]
                    end_text = value[args["endField"]]
                    if (type(start_text) is not str or type(end_text) is not str
                            or re.fullmatch(r"0x[0-9a-fA-F]+", start_text) is None
                            or re.fullmatch(r"0x[0-9a-fA-F]+", end_text) is None):
                        raise ValueError("offset syntax")
                    start = int(start_text, 16)
                    end = int(end_text, 16)
                except (KeyError, TypeError, ValueError) as error:
                    raise ProjectSchemaValidationError("runtime offset is invalid") from error
                if (start <= args["minimumExclusive"] or end <= args["minimumExclusive"]
                        or start % args["alignment"] or end % args["alignment"]
                        or start >= end):
                    raise ProjectSchemaValidationError("runtime offset range is invalid")

    def _rule_conditional_member(self, root: object, _paths: list[str], args: dict[str, object]) -> None:
        expected = {"conditionPath", "conditionEquals", "valuePath", "membersPath",
                    "requiredWhenTrue", "forbiddenWhenFalse"}
        if set(args) != expected:
            raise ProjectSchemaValidationError("conditional-member args are not exact")
        enabled = self._single_pointer(root, args["conditionPath"])
        enabled = False if enabled is None else enabled == args["conditionEquals"]
        selected = self._single_pointer(root, args["valuePath"])
        if enabled:
            members = self._pointer_values(root, args["membersPath"])
            if args["requiredWhenTrue"] is True and selected is None:
                raise ProjectSchemaValidationError("runtime member is missing")
            if selected not in members:
                raise ProjectSchemaValidationError("runtime member does not exist")
        elif args["forbiddenWhenFalse"] is True and selected is not None:
            raise ProjectSchemaValidationError("runtime member is forbidden")

    def _rule_ordered_integer_fields(self, root: object, paths: list[str], args: dict[str, object]) -> None:
        if set(args) != {"startField", "endField", "minimumStart", "strict"}:
            raise ProjectSchemaValidationError("ordered-integer-fields args are not exact")
        for path in paths:
            for value in self._pointer_values(root, path):
                start, end = value[args["startField"]], value[args["endField"]]
                if (type(start) is not int or type(end) is not int
                        or start < args["minimumStart"] or end <= start):
                    raise ProjectSchemaValidationError("runtime integer range is invalid")

    def _rule_unique_pair(self, root: object, paths: list[str], args: dict[str, object]) -> None:
        if set(args) != {"fields"} or len(args["fields"]) != 2:
            raise ProjectSchemaValidationError("unique-pair args are not exact")
        pairs = []
        for path in paths:
            pairs.extend(tuple(value[field] for field in args["fields"])
                         for value in self._pointer_values(root, path))
        if len(set(pairs)) != len(pairs):
            raise ProjectSchemaValidationError("runtime pairs are duplicated")

    def _rule_index_within_array(self, root: object, paths: list[str], args: dict[str, object]) -> None:
        if set(args) != {"indexField", "arrayPath", "minimum"}:
            raise ProjectSchemaValidationError("index-within-array args are not exact")
        target = self._single_pointer(root, args["arrayPath"])
        if type(target) is not list:
            raise ProjectSchemaValidationError("runtime index target is not an array")
        for path in paths:
            for value in self._pointer_values(root, path):
                index = value[args["indexField"]]
                if type(index) is not int or not args["minimum"] <= index < len(target):
                    raise ProjectSchemaValidationError("runtime index is out of range")

    def _rule_safe_artifact_basename(self, root: object, paths: list[str], args: dict[str, object]) -> None:
        expected = {"minBytes", "maxBytes", "forbiddenNames", "forbiddenSeparators",
                    "forbiddenCategoryPrefixes", "allowedSuffixes", "embeddedUuidPattern",
                    "embeddedUuidMustEqualPath"}
        if set(args) != expected:
            raise ProjectSchemaValidationError("safe-artifact-basename args are not exact")
        owner = self._single_pointer(root, args["embeddedUuidMustEqualPath"])
        uuid_pattern = re.compile(args["embeddedUuidPattern"])
        for path in paths:
            for value in self._pointer_values(root, path):
                if type(value) is not str:
                    raise ProjectSchemaValidationError("runtime artifact is not text")
                try:
                    encoded = value.encode("utf-8")
                except UnicodeEncodeError as error:
                    raise ProjectSchemaValidationError("runtime artifact is not UTF-8") from error
                if (not args["minBytes"] <= len(encoded) <= args["maxBytes"]
                        or value in args["forbiddenNames"]
                        or any(separator in value for separator in args["forbiddenSeparators"])
                        or any(any(unicodedata.category(character).startswith(prefix)
                                   for prefix in args["forbiddenCategoryPrefixes"])
                               for character in value)
                        or not value.endswith(tuple(args["allowedSuffixes"]))
                        or any(found.group(0) != owner for found in uuid_pattern.finditer(value))):
                    raise ProjectSchemaValidationError("runtime artifact basename is unsafe")


def status(state: str) -> dict[str, object]:
    terminal = state in {"sealed"}
    stopping = state in {"stop_requested", "stopping", "stop_incomplete"}
    return {
        "schemaVersion": 1,
        "sessionId": SESSION,
        "generation": 1,
        "packageName": "com.aprz.qbdiandroid",
        "pid": 4242,
        "state": state,
        "reason": "duration_elapsed" if terminal or stopping else "",
        "transitionMonotonicNs": 100,
        "deadlineMonotonicNs": 2_000_000_000,
        "normalizedScenes": [{"name": "fixture-entry", "startOffset": 16, "endOffset": 32}],
        "activeScenes": [],
        "artifacts": [f"{SESSION}.trace.bin.lz4"],
        "stopAcknowledged": terminal,
        "warnings": [],
        "errors": [],
    }


class SchemaContractsTests(unittest.TestCase):
    def load_schema(self, name: str) -> dict[str, object]:
        return json.loads((ROOT / "docs" / name).read_text(encoding="utf-8"))

    def config_runtime_accepts(self, document: object) -> bool:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            try:
                load_config(path)
            except ConfigError:
                return False
        return True

    def status_runtime_accepts(self, document: object) -> bool:
        try:
            parse_status(
                document,
                SESSION,
                "com.aprz.qbdiandroid",
                1,
                4242,
                (ResolvedScene("fixture-entry", 16, 32),),
                None,
            )
        except (ValueError, QtraceError):
            return False
        return True

    def test_config_schema_matches_the_strict_configuration_field_sets(self):
        schema = self.load_schema("qtrace-config.schema.json")
        self.assertEqual(1, schema["properties"]["schemaVersion"]["const"])
        self.assertEqual({"schemaVersion", "app", "target", "tracer", "scenes"}, set(schema["properties"]))
        self.assertEqual(["schemaVersion", "app", "target", "scenes"], schema["required"])
        self.assertFalse(schema["additionalProperties"])
        definitions = schema["$defs"]
        self.assertEqual({"package", "apk"}, set(definitions["app"]["properties"]))
        self.assertEqual(["package"], definitions["app"]["required"])
        self.assertFalse(definitions["app"]["additionalProperties"])
        self.assertEqual({"module", "binary"}, set(definitions["target"]["properties"]))
        self.assertEqual(["module"], definitions["target"]["required"])
        self.assertFalse(definitions["target"]["additionalProperties"])
        tracer = definitions["tracer"]
        self.assertEqual(
            {"profile", "compression", "flightEnabled", "flightEntryScene", "library", "companion"},
            set(tracer["properties"]),
        )
        self.assertFalse(tracer["additionalProperties"])
        self.assertEqual(["fast", "balanced", "full"], tracer["properties"]["profile"]["enum"])
        self.assertEqual(1, schema["properties"]["scenes"]["minItems"])
        self.assertEqual(256, schema["properties"]["scenes"]["maxItems"])
        forms = definitions["scene"]["oneOf"]
        self.assertEqual({"name", "symbol"}, set(forms[0]["properties"]))
        self.assertEqual({"name", "startOffset", "endOffset"}, set(forms[1]["properties"]))
        self.assertTrue(all(not form["additionalProperties"] for form in forms))
        rules = schema["x-qtrace-runtime-invariants"]
        self.assertTrue(all(set(rule) == {"id", "paths", "predicate", "args"} for rule in rules))
        self.assertEqual(len(rules), len({rule["id"] for rule in rules}))
        self.assertEqual(
            {"config.text.utf8", "config.scene-name.utf8-bytes",
             "config.scene-name.unique", "config.offset-range.ordered",
             "config.flight-entry.member"},
            {rule["id"] for rule in rules},
        )

    def test_status_schema_matches_the_strict_native_status_parser(self):
        schema = self.load_schema("qtrace-session-status.schema.json")
        self.assertEqual(set(STATUS_KEYS), set(schema["properties"]))
        self.assertEqual(set(STATUS_KEYS), set(schema["required"]))
        self.assertFalse(schema["additionalProperties"])
        properties = schema["properties"]
        self.assertEqual(1, properties["schemaVersion"]["const"])
        self.assertEqual("uuid", properties["sessionId"]["format"])
        self.assertEqual(1, properties["generation"]["minimum"])
        self.assertEqual(1, properties["pid"]["minimum"])
        self.assertEqual(0, properties["transitionMonotonicNs"]["minimum"])
        self.assertEqual(0, properties["deadlineMonotonicNs"]["minimum"])
        self.assertEqual(
            ["installed", "running", "stop_requested", "stopping", "sealed", "stop_incomplete"],
            properties["state"]["enum"],
        )
        self.assertFalse(properties["normalizedScenes"]["items"]["additionalProperties"])
        self.assertFalse(properties["activeScenes"]["items"]["additionalProperties"])
        issue = schema["$defs"]["issue"]
        self.assertFalse(issue["additionalProperties"])
        self.assertEqual({"code", "path", "message"}, set(issue["properties"]))
        rules = schema["x-qtrace-runtime-invariants"]
        self.assertTrue(all(set(rule) == {"id", "paths", "predicate", "args"} for rule in rules))
        self.assertEqual(len(rules), len({rule["id"] for rule in rules}))
        self.assertEqual(
            {"status.session-id.utf8-bytes", "status.package-name.utf8-bytes",
             "status.state.utf8-bytes", "status.reason.utf8-bytes",
             "status.scene-name.utf8-bytes", "status.issue-text.utf8-bytes",
             "status.scene-range.ordered", "status.scene-name.unique",
             "status.active-scene.unique-pair", "status.active-scene.index-bound",
             "status.artifact.safe-basename"},
            {rule["id"] for rule in rules},
        )

    def test_config_runtime_and_documented_schema_accept_exactly_the_same_corpus(self):
        minimal = {
            "schemaVersion": 1,
            "app": {"package": "com.example.app"},
            "target": {"module": "libx.so"},
            "scenes": [{"name": "entry", "startOffset": "0x4", "endOffset": "0x8"}],
        }
        symbol = copy.deepcopy(minimal)
        symbol["scenes"] = [{"name": "入口", "symbol": "demo_entry"}]
        symbol_boundaries = copy.deepcopy(minimal)
        symbol_boundaries["scenes"] = [
            {"name": "界" * 42 + "ab", "symbol": "s" * 2048}
        ]
        flight = copy.deepcopy(minimal)
        flight["tracer"] = {
            "profile": "full", "compression": False, "flightEnabled": True,
            "flightEntryScene": "entry", "library": "tracer.so", "companion": "agent.js",
        }
        corpus = {
            "minimal-offset": minimal,
            "symbol-unicode": symbol,
            "symbol-unbounded-scene-name-128-bytes": symbol_boundaries,
            "flight-paired": flight,
        }

        mutations = {
            "offset-zero": ("scenes", 0, "startOffset", "0x0"),
            "offset-misaligned": ("scenes", 0, "startOffset", "0x2"),
            "offset-reversed": ("scenes", 0, "startOffset", "0xc"),
            "offset-trailing-control": ("scenes", 0, "startOffset", "0x4\n"),
            "scene-name-byte-limit": ("scenes", 0, "name", "界" * 43),
            "scene-name-control": ("scenes", 0, "name", "bad\nname"),
            "scene-name-surrogate": ("scenes", 0, "name", "bad\ud800"),
        }
        for name, (array, index, field, value) in mutations.items():
            candidate = copy.deepcopy(minimal)
            candidate[array][index][field] = value
            corpus[name] = candidate
        duplicate = copy.deepcopy(minimal)
        duplicate["scenes"].append({"name": "entry", "symbol": "other"})
        corpus["duplicate-scene-name"] = duplicate
        for name, symbol_value in {
            "symbol-empty": "",
            "symbol-control": "bad\nname",
            "symbol-formatting": "bad\u200bname",
            "symbol-surrogate": "bad\ud800",
        }.items():
            candidate = copy.deepcopy(symbol)
            candidate["scenes"][0]["symbol"] = symbol_value
            corpus[name] = candidate
        for name, tracer in {
            "tracer-library-only": {"library": "tracer.so"},
            "tracer-companion-only": {"companion": "agent.js"},
            "flight-missing-entry": {"flightEnabled": True},
            "flight-unknown-entry": {"flightEnabled": True, "flightEntryScene": "missing"},
            "flight-entry-while-disabled": {"flightEnabled": False, "flightEntryScene": "entry"},
            "flight-entry-control": {"flightEnabled": True, "flightEntryScene": "entry\n"},
            "flight-entry-surrogate": {"flightEnabled": True, "flightEntryScene": "entry\ud800"},
        }.items():
            candidate = copy.deepcopy(minimal)
            candidate["tracer"] = tracer
            corpus[name] = candidate

        expected = {
            "minimal-offset", "symbol-unicode",
            "symbol-unbounded-scene-name-128-bytes", "flight-paired",
        }
        runtime_accepted = {name for name, value in corpus.items() if self.config_runtime_accepts(value)}
        schema = QtraceProjectSchemaEvaluator(self.load_schema("qtrace-config.schema.json"))
        schema_accepted = {name for name, value in corpus.items() if schema.accepts(value)}
        self.assertEqual(expected, runtime_accepted)
        self.assertEqual(runtime_accepted, schema_accepted)

    def test_status_runtime_and_documented_schema_accept_exactly_the_same_corpus(self):
        corpus = {state_name: status(state_name) for state_name in (
            "installed", "running", "stop_requested", "stopping", "sealed", "stop_incomplete"
        )}
        active_valid = status("running")
        active_valid["activeScenes"] = [{"sceneIndex": 0, "tid": 7, "sealed": False}]
        corpus["active-valid"] = active_valid
        issue_boundary = status("running")
        issue_boundary["warnings"] = [{"code": "界" * 341, "path": "", "message": "x"}]
        corpus["issue-1023-bytes"] = issue_boundary
        artifact_boundary = status("running")
        artifact_boundary["artifacts"] = ["a" * 245 + ".trace.bin"]
        corpus["artifact-255-bytes"] = artifact_boundary

        def mutated(name: str, update) -> None:
            candidate = copy.deepcopy(status("running"))
            update(candidate)
            corpus[name] = candidate

        mutated("uuid-not-v4", lambda value: value.update(sessionId="123e4567-e89b-12d3-a456-426614174000"))
        mutated("uuid-uppercase", lambda value: value.update(sessionId=SESSION.upper()))
        mutated("generation-zero", lambda value: value.update(generation=0))
        mutated("generation-bool", lambda value: value.update(generation=True))
        mutated("pid-zero", lambda value: value.update(pid=0))
        mutated("pid-bool", lambda value: value.update(pid=True))
        mutated("timestamp-negative", lambda value: value.update(transitionMonotonicNs=-1))
        mutated("timestamp-bool", lambda value: value.update(transitionMonotonicNs=True))
        mutated("deadline-negative", lambda value: value.update(deadlineMonotonicNs=-1))
        mutated("deadline-bool", lambda value: value.update(deadlineMonotonicNs=True))
        mutated("scene-start-negative", lambda value: value["normalizedScenes"][0].update(startOffset=-1))
        mutated("scene-empty-range", lambda value: value["normalizedScenes"][0].update(endOffset=16))
        mutated("scene-reversed", lambda value: value["normalizedScenes"][0].update(startOffset=32))
        mutated("scene-name-byte-limit", lambda value: value["normalizedScenes"][0].update(name="界" * 43))
        mutated("scene-name-control", lambda value: value["normalizedScenes"][0].update(name="bad\u200bname"))
        mutated("scene-name-surrogate", lambda value: value["normalizedScenes"][0].update(name="bad\ud800"))
        mutated("scene-name-duplicate", lambda value: value["normalizedScenes"].append(
            {"name": "fixture-entry", "startOffset": 40, "endOffset": 44}))
        mutated("active-pair-duplicate", lambda value: value.update(activeScenes=[
            {"sceneIndex": 0, "tid": 7, "sealed": False},
            {"sceneIndex": 0, "tid": 7, "sealed": True},
        ]))
        mutated("active-index-outside", lambda value: value.update(activeScenes=[
            {"sceneIndex": 1, "tid": 7, "sealed": False}]))
        mutated("active-tid-zero", lambda value: value.update(activeScenes=[
            {"sceneIndex": 0, "tid": 0, "sealed": False}]))
        mutated("active-index-bool", lambda value: value.update(activeScenes=[
            {"sceneIndex": False, "tid": 7, "sealed": False}]))
        mutated("artifact-traversal", lambda value: value.update(artifacts=["../escape.trace.bin"]))
        mutated("artifact-backslash", lambda value: value.update(artifacts=["bad\\name.trace.bin"]))
        mutated("artifact-byte-limit", lambda value: value.update(artifacts=["a" * 246 + ".trace.bin"]))
        mutated("artifact-control", lambda value: value.update(artifacts=["bad\nname.trace.bin"]))
        mutated("artifact-surrogate", lambda value: value.update(artifacts=["bad\ud800.trace.bin"]))
        mutated("artifact-foreign-uuid", lambda value: value.update(
            artifacts=["223e4567-e89b-42d3-a456-426614174000.trace.bin"]))
        mutated("artifact-wrong-suffix", lambda value: value.update(artifacts=[SESSION + ".txt"]))
        mutated("artifact-duplicate", lambda value: value.update(
            artifacts=[SESSION + ".trace.bin", SESSION + ".trace.bin"]))
        mutated("state-reason-ack", lambda value: value.update(
            state="sealed", reason="duration_elapsed", stopAcknowledged=False))
        mutated("running-terminal-fields", lambda value: value.update(
            state="running", reason="duration_elapsed", stopAcknowledged=True))
        mutated("stop-requested-empty-reason", lambda value: value.update(
            state="stop_requested", reason="", stopAcknowledged=False))
        mutated("warning-byte-limit", lambda value: value.update(warnings=[
            {"code": "界" * 342, "path": "", "message": ""}]))
        mutated("error-control", lambda value: value.update(errors=[
            {"code": "E", "path": "/x", "message": "bad\nmessage"}]))
        mutated("error-surrogate", lambda value: value.update(errors=[
            {"code": "E", "path": "/x", "message": "bad\ud800"}]))

        expected = {
            "installed", "running", "stop_requested", "stopping", "sealed",
            "stop_incomplete", "active-valid", "issue-1023-bytes", "artifact-255-bytes",
        }
        runtime_accepted = {name for name, value in corpus.items() if self.status_runtime_accepts(value)}
        schema = QtraceProjectSchemaEvaluator(
            self.load_schema("qtrace-session-status.schema.json")
        )
        schema_accepted = {name for name, value in corpus.items() if schema.accepts(value)}
        self.assertEqual(expected, runtime_accepted)
        self.assertEqual(runtime_accepted, schema_accepted)

    def test_every_native_status_state_has_a_valid_golden_document(self):
        for state_name in ("installed", "running", "stop_requested", "stopping", "sealed", "stop_incomplete"):
            with self.subTest(state=state_name):
                self.assertEqual(status(state_name), validate_status_shape(status(state_name)))

    def test_status_state_reason_acknowledgement_corpus_is_rejected(self):
        invalid = (
            ("running", "duration_elapsed", True),
            ("stop_requested", "", False),
            ("sealed", "duration_elapsed", False),
        )
        for state_name, reason, acknowledgement in invalid:
            with self.subTest(state=state_name):
                document = status(state_name)
                document["reason"] = reason
                document["stopAcknowledged"] = acknowledgement
                with self.assertRaises(ValueError):
                    validate_status_shape(document)

    def test_status_invariant_corpus_matches_runtime(self):
        documents = []
        end = status("running"); end["normalizedScenes"] = [{"name": "x", "startOffset": 4, "endOffset": 4}]; documents.append(end)
        duplicate = status("running"); duplicate["activeScenes"] = [{"sceneIndex": 0, "tid": 1, "sealed": False}, {"sceneIndex": 0, "tid": 1, "sealed": False}]; documents.append(duplicate)
        outside = status("running"); outside["activeScenes"] = [{"sceneIndex": 1, "tid": 1, "sealed": False}]; documents.append(outside)
        for document in documents:
            with self.assertRaises(ValueError):
                validate_status_shape(document)

    def test_runtime_corpus_rejects_offset_zero_misalignment_and_reversed_ranges(self):
        for start, end in (("0x0", "0x4"), ("0x2", "0x4"), ("0x8", "0x4")):
            with self.subTest(start=start, end=end), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "config.json"
                path.write_text(json.dumps({"schemaVersion": 1, "app": {"package": "com.example.app"}, "target": {"module": "libx.so"}, "scenes": [{"name": "x", "startOffset": start, "endOffset": end}]}))
                with self.assertRaises(ConfigError):
                    load_config(path)


class FakeRunner:
    def __init__(self, *, fail_first_read: bool = False):
        self.commands: list[tuple[str, ...]] = []
        self.fail_first_read = fail_first_read
        self.reads = 0
        self.offset_root: Path | None = None

    def run(self, command, *, timeout, cwd=None, allowed=(0,)):
        self.commands.append(tuple(command))
        if "--output" in command and "qtrace" in command and "demo" in command:
            output = Path(command[command.index("--output") + 1])
            output.mkdir(parents=True, exist_ok=True)
            if output.name == "offset":
                self.offset_root = output
            report = str(output / SESSION / "report.json") + "\n"
            if "flight-crash" in command:
                return __import__("scripts.qtrace_device_acceptance", fromlist=["CommandResult"]).CommandResult(report, "", 2)
            return __import__("scripts.qtrace_device_acceptance", fromlist=["CommandResult"]).CommandResult(report, "", 0)
        if "--output" in command and "qtrace" in command and "pull" in command:
            output = Path(command[command.index("--output") + 1])
            return __import__("scripts.qtrace_device_acceptance", fromlist=["CommandResult"]).CommandResult(
                str(output / SESSION / "report.json") + "\n", "", 0,
            )
        if "flight-crash" in command:
            return __import__("scripts.qtrace_device_acceptance", fromlist=["CommandResult"]).CommandResult("", "", 2)
        return __import__("scripts.qtrace_device_acceptance", fromlist=["CommandResult"]).CommandResult("", "", 0)

    def read_text(self, path: Path, *, timeout: float) -> str:
        self.reads += 1
        if self.fail_first_read and self.reads == 1:
            raise ConnectionError("injected one-shot ADB read failure")
        if path.name == "qtrace-acceptance-baseline.json":
            return json.dumps({"iterations": 30, "seed": 5855319310239641971, "result": "0x42"})
        if path.name == "qtrace-acceptance-timed.json":
            return json.dumps({"iterations": 30, "seed": 5855319310239641971, "result": "0x42"})
        if path.name == "qtrace-acceptance-receipt.json":
            return json.dumps({"sessionId": SESSION, "nonce": SESSION, "entryMonotonicNs": 101})
        if path.name == "qtrace-acceptance-entry-status.json":
            return json.dumps(status("running"))
        if path.name == "fixture.trace.txt":
            return "TRACE_BEGIN format=4 scene=fixture-entry\nTRACE_END status=stopped reason=duration_elapsed return_valid=0 elapsed_ms=2000\n"
        if path.name == "report.json":
            parent_names = {parent.name for parent in path.parents}
            if parent_names & {"latest", "name", "all", "compressed"}:
                return json.dumps({"schema": 1, "sessionId": SESSION, "artifacts": [
                    {
                        "remote_name": "fixture.trace.bin.lz4",
                        "local_path": "artifacts/fixture.trace.bin.lz4",
                        "source_size": len(b"pulled artifact"),
                        "destination_size": len(b"pulled artifact"),
                        "sha256": "0" * 64,
                        "decoder": "qtrb",
                        "termination": "completed",
                        "stop_reason": None,
                        "metrics_schema": None,
                        "producer_waits": None,
                        "producer_wait_ns": None,
                        "conversion_ms": 0.0,
                        "native_stop_acknowledged": None,
                        "host_observed_ack_ms": None,
                    }], "errors": []})
            report_status = "sealed"
            if "exit" in parent_names:
                report_status = "process_exited"
            elif "crash" in parent_names:
                report_status = "crash_recovered"
            return json.dumps({
                "schema": 1, "session_id": SESSION, "status": report_status, "stage": "completed",
                "package": "com.aprz.qbdiandroid", "pid": 4242,
                "device": {}, "effective_config": {}, "error": None, "finished_at": 1,
                "mode": "run", "serial": "SERIAL", "started_at": 0, "target": {},
                "tracer": {}, "warnings": [],
                "timeline": [{"stage": "installing_hooks", "cleanup_detached": True}, {"stage": "running"}],
                "native": {"status": status("sealed")},
                "outputs": ["fixture.trace.bin.lz4", "fixture.trace.bin.lz4.metrics", str((self.offset_root or Path("/tmp")) / "fixture.trace.txt")],
                "artifacts": [{"remote_name": "fixture.trace.bin.lz4", "local_path": "artifacts/fixture.trace.bin.lz4", "termination": "stopped", "metrics_schema": 3, "native_stop_acknowledged": True}, {"remote_name": "fixture.trace.bin.lz4.metrics", "decoder": "sidecar"}],
            })
        if path.exists():
            return path.read_text(encoding="utf-8")
        return ""

    def read_text_beneath(self, root: Path, relative: Path, *, timeout: float) -> str:
        return self.read_text(getattr(root, "path", root) / relative, timeout=timeout)


class FakeArtifactClient:
    def __init__(self, root: Path):
        self.root = root
        self.calls: list[tuple[str, int]] = []
        self.evidence_present_during_retry: list[bool] = []

    def read_file(self, name: str, *, maximum_bytes: int) -> bytes:
        self.calls.append((name, maximum_bytes))
        path = self.root / "artifacts" / name
        self.evidence_present_during_retry.append(path.is_file())
        return path.read_bytes()


class AcceptanceHarnessTests(unittest.TestCase):
    def test_timed_entry_evidence_requires_running_native_snapshot_before_entry(self):
        from scripts.qtrace_device_acceptance import _validate_timed_fixture_receipt

        report = {
            "session_id": SESSION,
            "pid": 4242,
            "timeline": [{"stage": "installing_hooks", "cleanup_detached": True}],
            "native": {"status": status("sealed")},
        }
        receipt = {
            "sessionId": SESSION,
            "nonce": "123e4567-e89b-42d3-a456-426614174000",
            "entryMonotonicNs": 101,
        }
        entry = status("running")
        entry["transitionMonotonicNs"] = 100
        _validate_timed_fixture_receipt(
            report, json.dumps(receipt), json.dumps(entry),
        )

        invalid = {
            "missing": "",
            "non-running": json.dumps(status("installed")),
            "session-mismatch": json.dumps({**entry, "sessionId": "223e4567-e89b-42d3-a456-426614174001"}),
            "transition-after-entry": json.dumps({**entry, "transitionMonotonicNs": 102}),
        }
        for name, raw in invalid.items():
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                _validate_timed_fixture_receipt(report, json.dumps(receipt), raw)

    def test_report_path_returns_only_a_lexical_token(self):
        from scripts.qtrace_device_acceptance import _published_report_path, _report_path

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "output"
            root.mkdir()
            self.assertEqual(
                Path("report.json"),
                _report_path(str(root / "report.json"), root),
            )
            for unsafe in ("../report.json", str(root.parent / "report.json")):
                with self.subTest(unsafe=unsafe), self.assertRaisesRegex(
                        RuntimeError, "outside"):
                    _report_path(unsafe, root)
            self.assertEqual(
                Path(SESSION) / "report.json",
                _published_report_path(str(root / SESSION / "report.json"), root),
            )
            with self.assertRaisesRegex(RuntimeError, "did not publish"):
                _published_report_path("", root)

    def test_local_session_report_uses_rooted_read_after_parent_swap(self):
        from scripts.qtrace_device_acceptance import _report_path, _strict_session_report

        document = json.dumps({
            "schema": 1, "session_id": SESSION, "status": "sealed", "stage": "completed",
            "package": "com.aprz.qbdiandroid", "pid": 4242,
            "device": {}, "effective_config": {}, "error": None, "finished_at": 1,
            "mode": "run", "serial": "SERIAL", "started_at": 0, "target": {},
            "tracer": {}, "warnings": [], "timeline": [], "native": {}, "outputs": [],
            "artifacts": [],
        })

        class Runner:
            def read_text(self, *_args, **_kwargs):
                raise AssertionError("local reports must not use read_text")

            def read_text_beneath(self, root, relative, *, timeout):
                self.root = root
                self.relative = relative
                return document

        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "output"
            root.mkdir()
            token = _report_path(str(root / "report.json"), root)
            moved = parent / "moved-output"
            root.rename(moved)
            outside = parent / "outside"
            outside.mkdir()
            (outside / "report.json").write_text("external legal report", encoding="utf-8")
            root.symlink_to(outside, target_is_directory=True)
            runner = Runner()
            self.assertEqual(document, json.dumps(_strict_session_report(runner, root, token)))
            self.assertEqual(root, runner.root)
            self.assertEqual(Path("report.json"), runner.relative)

    def test_beneath_read_rejects_final_and_parent_symlinks(self):
        from scripts.qtrace_device_acceptance import SubprocessRunner
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"; root.mkdir()
            outside = Path(temporary) / "outside"; outside.mkdir(); (outside / "x").write_text("x")
            (root / "x").symlink_to(outside / "x")
            runner = SubprocessRunner("SERIAL", inject_first_read_failure=False)
            with self.assertRaises(RuntimeError): runner.read_text_beneath(root, Path("x"), timeout=1)
            (root / "x").unlink(); (root / "dir").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(RuntimeError): runner.read_text_beneath(root, Path("dir/x"), timeout=1)

    def test_beneath_read_rejects_traversal_root_escape_and_parent_swap(self):
        from scripts.qtrace_device_acceptance import SubprocessRunner, _report_path

        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "output"
            nested = root / "nested"
            nested.mkdir(parents=True)
            outside = parent / "outside"
            outside.mkdir()
            (outside / "report.json").write_text("external but legal", encoding="utf-8")
            runner = SubprocessRunner("SERIAL", inject_first_read_failure=False)
            token = _report_path(str(nested / "report.json"), root)
            nested.rename(parent / "original-nested")
            nested.symlink_to(outside, target_is_directory=True)
            for candidate in (token, Path("../outside/report.json"), outside / "report.json"):
                with self.subTest(candidate=candidate), self.assertRaises(RuntimeError):
                    runner.read_text_beneath(root, candidate, timeout=1.0)
    def test_subprocess_runner_uses_bounded_capture_for_allowed_crash_exit(self):
        from scripts.bounded_process import BoundedProcessError
        from scripts.qtrace_device_acceptance import SubprocessRunner

        with patch("scripts.qtrace_device_acceptance.capture_bounded", side_effect=BoundedProcessError(
                "crashed", returncode=2, stderr=b"recovering")) as capture:
            result = SubprocessRunner("SERIAL", inject_first_read_failure=False).run(
                ("qtrace", "demo"), timeout=3.0, allowed=(0, 2),
            )
        self.assertEqual(("", "recovering", 2), (result.stdout, result.stderr, result.returncode))
        self.assertEqual(1_048_576, capture.call_args.kwargs["maximum_bytes"])

    def test_allowed_crash_exit_preserves_bounded_report_stdout(self):
        from scripts.bounded_process import BoundedProcessError
        from scripts.qtrace_device_acceptance import SubprocessRunner

        failure = BoundedProcessError("crashed", returncode=2, stderr=b"recovering")
        failure.stdout = b"/tmp/output/" + SESSION.encode("ascii") + b"/report.json\n"
        with patch("scripts.qtrace_device_acceptance.capture_bounded", side_effect=failure):
            result = SubprocessRunner("SERIAL", inject_first_read_failure=False).run(
                ("qtrace", "demo"), timeout=3.0, allowed=(0, 2),
            )
        self.assertEqual(failure.stdout.decode("utf-8"), result.stdout)
        self.assertEqual(2, result.returncode)

    def test_host_reads_are_nofollow_bounded_and_timeout_checked(self):
        from scripts.qtrace_device_acceptance import SubprocessRunner

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            oversized = root / "oversized.json"
            oversized.write_bytes(b"x" * (1_048_576 + 1))
            safe = root / "safe.json"
            safe.write_text("safe")
            link = root / "link.json"
            link.symlink_to(safe)
            runner = SubprocessRunner("SERIAL", inject_first_read_failure=False)
            with self.assertRaisesRegex(RuntimeError, "bounded regular file"):
                runner.read_text(oversized, timeout=1.0)
            with self.assertRaisesRegex(RuntimeError, "bounded regular file"):
                runner.read_text(link, timeout=1.0)

    def test_retry_clips_second_read_to_the_shared_deadline(self):
        from scripts.qtrace_device_acceptance import _read_retry

        class Runner:
            def __init__(self): self.timeouts = []
            def read_text(self, _path, *, timeout):
                self.timeouts.append(timeout)
                if len(self.timeouts) == 1:
                    raise ConnectionError("once")
                return "ok"

        runner = Runner()
        with patch("scripts.qtrace_device_acceptance.time.monotonic", side_effect=(100.0, 100.0, 101.5)):
            self.assertEqual("ok", _read_retry(runner, Path("result"), timeout=5.0))
        self.assertEqual([5.0, 3.5], runner.timeouts)

    def test_baseline_sleep_is_clipped_to_the_absolute_deadline(self):
        from scripts.qtrace_device_acceptance import _wait_for_baseline

        class Runner:
            def read_text(self, _path, *, timeout):
                raise ValueError("not ready")

        with patch("scripts.qtrace_device_acceptance.time.monotonic", side_effect=(
                100.0, 100.0, 100.0, 100.0, 114.95, 115.0)), \
                patch("scripts.qtrace_device_acceptance.time.sleep") as sleep:
            with self.assertRaisesRegex(RuntimeError, "within 15 seconds"):
                _wait_for_baseline(Runner())
        sleep.assert_called_once_with(0.04999999999999716)

    def test_baseline_retries_a_nonzero_second_adb_read_until_ready(self):
        from scripts.qtrace_device_acceptance import AcceptanceNotReadyError, _wait_for_baseline

        class Runner:
            def __init__(self):
                self.calls = 0

            def read_text(self, _path, *, timeout):
                self.calls += 1
                if self.calls == 1:
                    raise ConnectionError("first injected disconnect")
                if self.calls == 2:
                    raise AcceptanceNotReadyError("adb run-as cat exited 1: not published yet")
                return json.dumps({
                    "iterations": 30, "seed": 5855319310239641971, "result": "0x42",
                })

        runner = Runner()
        self.assertEqual("0x42", _wait_for_baseline(runner)["result"])
        self.assertEqual(3, runner.calls)

    def test_baseline_adb_failure_is_typed_as_not_ready(self):
        from scripts.qtrace_device_acceptance import (
            AcceptanceNotReadyError, BASELINE_PATH, SubprocessRunner,
        )

        runner = SubprocessRunner("SERIAL", inject_first_read_failure=False)
        with patch.object(runner, "run", side_effect=RuntimeError("adb exited 1")):
            with self.assertRaises(AcceptanceNotReadyError):
                runner.read_text(Path(BASELINE_PATH), timeout=1.0)

    def test_timed_semantics_reparses_a_real_stopped_qtrb_and_metrics_v3_sidecar(self):
        from scripts.qtrace_device_acceptance import _validate_timed_artifact_semantics

        report = {"artifacts": [{
            "remote_name": "fixture.trace.bin",
            "local_path": "artifacts/fixture.trace.bin",
            "termination": "stopped",
            "metrics_schema": 3,
            "native_stop_acknowledged": True,
        }, {"remote_name": "fixture.trace.bin.metrics", "decoder": "sidecar"}]}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = root / "artifacts"
            artifacts.mkdir()
            source = artifacts / "fixture.trace.bin"
            source.write_bytes(stopped_binary_stream(compression=0))
            (artifacts / "fixture.trace.bin.metrics").write_text(
                metrics_sidecar(source, termination="stopped", return_valid=0,
                                return_value="0x0", instructions=1),
                encoding="utf-8",
            )

            _validate_timed_artifact_semantics(FakeRunner(), report, root)

            self.assertEqual([], list(root.glob(".qtrace-acceptance-validate-*.trace.txt")))

    def test_timed_semantics_reconverts_trusted_binary_and_removes_validation_text(self):
        from scripts.qtrace_device_acceptance import _validate_timed_artifact_semantics

        runner = FakeRunner()
        report = {
            "artifacts": [{
                "remote_name": "fixture.trace.bin.lz4",
                "local_path": "artifacts/fixture.trace.bin.lz4",
                "termination": "stopped",
                "metrics_schema": 3,
                "native_stop_acknowledged": True,
            }, {"remote_name": "fixture.trace.bin.lz4.metrics", "decoder": "sidecar"}],
        }
        calls: list[tuple[Path, Path, str | None, bool]] = []
        snapshots: list[bytes] = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = root / "artifacts"
            artifacts.mkdir()
            source = artifacts / "fixture.trace.bin.lz4"
            source.write_bytes(b"fixture qtrb bytes")
            (artifacts / "fixture.trace.bin.lz4.metrics").write_text("metrics")

            def converter(binary: Path, destination: Path, *, lz4: str | None,
                          crash_marked: bool):
                calls.append((binary, destination, lz4, crash_marked))
                snapshots.append(binary.read_bytes())
                destination.write_text(
                    "TRACE_BEGIN format=4 scene=fixture-entry\n"
                    "TRACE_END status=stopped reason=duration_elapsed return_valid=0 elapsed_ms=2000\n",
                    encoding="utf-8",
                )
                return SimpleNamespace(termination="stopped", partial=False)

            _validate_timed_artifact_semantics(runner, report, root, converter=converter)

            self.assertEqual(1, len(calls))
            self.assertNotEqual(source, calls[0][0])
            self.assertEqual(source.read_bytes(), snapshots[0])
            self.assertEqual("lz4", calls[0][2])
            self.assertFalse(calls[0][3])
            self.assertFalse(calls[0][0].exists())

    def test_timed_semantics_propagates_binary_conversion_failure(self):
        from scripts.qtrace_device_acceptance import _validate_timed_artifact_semantics

        report = {"artifacts": [{
            "remote_name": "fixture.trace.bin",
            "local_path": "artifacts/fixture.trace.bin",
            "termination": "stopped",
            "metrics_schema": 3,
            "native_stop_acknowledged": True,
        }, {"remote_name": "fixture.trace.bin.metrics", "decoder": "sidecar"}]}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = root / "artifacts"
            artifacts.mkdir()
            (artifacts / "fixture.trace.bin").write_bytes(b"fixture qtrb bytes")
            (artifacts / "fixture.trace.bin.metrics").write_text("metrics")
            with self.assertRaisesRegex(RuntimeError, "invalid qtrb"):
                _validate_timed_artifact_semantics(
                    FakeRunner(), report, root,
                    converter=lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("invalid qtrb")),
                )

    def test_one_shot_artifact_read_preserves_evidence_for_retry(self):
        from scripts.qtrace_device_acceptance import OneShotArtifactRead
        class Client:
            def __init__(self): self.calls = []
            def read_file(self, name, *, maximum_bytes):
                self.calls.append((name, maximum_bytes)); return b"evidence"
        client = Client()
        wrapped = OneShotArtifactRead(client)
        with self.assertRaises(ConnectionError):
            wrapped.read_file("fixture.trace.bin.lz4", maximum_bytes=1)
        self.assertEqual([], client.calls)
        self.assertEqual(b"evidence", wrapped.read_file("fixture.trace.bin.lz4", maximum_bytes=1))
        self.assertEqual([("fixture.trace.bin.lz4", 1)], client.calls)

    def test_artifact_recovery_uses_rooted_bounded_reads_for_local_metrics(self):
        from scripts.qtrace_device_acceptance import _verify_artifact_read_recovery

        report = {"artifacts": [{
            "remote_name": "fixture.trace.bin.lz4",
            "local_path": "artifacts/fixture.trace.bin.lz4",
        }]}

        class Client:
            def read_file(self, _name, *, maximum_bytes):
                self.maximum_bytes = maximum_bytes
                return b"metrics"

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = root / "artifacts"
            artifacts.mkdir()
            (artifacts / "fixture.trace.bin.lz4").write_bytes(b"binary")
            (artifacts / "fixture.trace.bin.lz4.metrics").write_bytes(b"metrics")
            with patch.object(Path, "read_bytes", side_effect=AssertionError("unbounded read")):
                _verify_artifact_read_recovery(
                    "SERIAL", report, root, artifact_client_factory=lambda **_kwargs: Client(),
                )
    def test_trusted_output_rejects_escape_and_symlink(self):
        from scripts.qtrace_device_acceptance import _trusted_output
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            root.mkdir()
            outside = Path(temporary) / "outside"
            outside.write_text("x")
            link = root / "link"
            link.symlink_to(outside)
            with self.assertRaises(RuntimeError):
                _trusted_output(outside, root)
            with self.assertRaises(RuntimeError):
                _trusted_output(link, root)

    def test_held_root_reader_survives_a_legal_output_directory_rebind(self):
        from scripts.qtrace_device_acceptance import RootedReader

        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            output = parent / "output"
            report = output / SESSION / "report.json"
            report.parent.mkdir(parents=True)
            report.write_text('{"trusted":true}', encoding="utf-8")
            outside = parent / "outside"
            (outside / SESSION).mkdir(parents=True)
            (outside / SESSION / "report.json").write_text('{"trusted":false}', encoding="utf-8")
            with RootedReader(output) as held:
                output.rename(parent / "original-output")
                output.symlink_to(outside, target_is_directory=True)
                self.assertEqual(b'{"trusted":true}', held.read_bytes(Path(SESSION) / "report.json"))

    def test_timed_snapshot_and_converter_share_a_hard_deadline(self):
        from scripts.qtrace_device_acceptance import RootedReader, _convert_snapshot_bounded

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "artifact").write_bytes(b"fixture")
            with RootedReader(root) as held, self.assertRaisesRegex(RuntimeError, "exceeded deadline"):
                held.read_bytes("artifact", deadline=0.0)
            with patch("scripts.qtrace_device_acceptance.capture_bounded",
                       side_effect=subprocess.TimeoutExpired(["decoder"], 1.0)) as bounded, \
                    self.assertRaisesRegex(RuntimeError, "failed within deadline"):
                _convert_snapshot_bounded(root / "artifact", root / "converted", lz4="lz4",
                                          deadline=time.monotonic() + 1.0)
            self.assertEqual(64 * 1024, bounded.call_args.kwargs["maximum_bytes"])
    def test_strict_report_rejects_duplicate_keys_and_nonfinite_numbers(self):
        from scripts.qtrace_device_acceptance import _strict_json

        for payload in ('{"schema":1,"schema":1}', '{"schema":NaN}'):
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    _strict_json(payload)

    def test_timed_report_selects_one_binary_root_among_sidecars(self):
        from scripts.qtrace_device_acceptance import _validated_timed_report

        runner = FakeRunner()
        document = json.loads(runner.read_text(Path("report.json"), timeout=1))
        document["artifacts"].extend([
            {"remote_name": "fixture.trace.bin.lz4.metrics", "decoder": "sidecar"},
            {"remote_name": "fixture.trace.txt", "decoder": "qtrb"},
        ])
        runner.read_text = lambda _path, *, timeout: json.dumps(document)  # type: ignore[method-assign]
        report, artifact = _validated_timed_report(
            runner, Path("output"), Path(SESSION) / "report.json",
        )
        self.assertEqual(document, report)
        self.assertEqual("fixture.trace.bin.lz4", artifact)

    def test_timed_report_rejects_extra_key_before_artifact_reads(self):
        from scripts.qtrace_device_acceptance import _validated_timed_report

        runner = FakeRunner()
        document = json.loads(runner.read_text(Path("report.json"), timeout=1))
        document["unexpected"] = True
        reads: list[Path] = []
        runner.read_text = lambda path, *, timeout: (reads.append(path), json.dumps(document))[1]  # type: ignore[method-assign]
        with self.assertRaisesRegex(RuntimeError, "unexpected fields"):
            _validated_timed_report(runner, Path("output"), Path("report.json"))
        self.assertEqual([Path("output") / "report.json"], reads)

    def test_pull_report_requires_clean_production_records_and_local_artifacts(self):
        from scripts.qtrace_device_acceptance import _validated_pull_report

        artifact_bytes = b"pulled artifact"
        record = {
            "remote_name": "fixture.trace.bin.lz4",
            "local_path": "artifacts/fixture.trace.bin.lz4",
            "source_size": len(artifact_bytes),
            "destination_size": len(artifact_bytes),
            "sha256": "0" * 64,
            "decoder": "qtrb",
            "termination": "completed",
            "stop_reason": None,
            "metrics_schema": 3,
            "producer_waits": 0,
            "producer_wait_ns": 0,
            "conversion_ms": 1.25,
            "native_stop_acknowledged": True,
            "host_observed_ack_ms": 2.5,
        }

        class PullRunner:
            def __init__(self, document):
                self.document = document

            def read_text_beneath(self, _root, _relative, *, timeout):
                return json.dumps(self.document)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "pull"
            artifact = root / SESSION / "artifacts" / record["remote_name"]
            artifact.parent.mkdir(parents=True)
            artifact.write_bytes(artifact_bytes)
            good = {"schema": 1, "sessionId": SESSION, "artifacts": [record], "errors": []}
            _validated_pull_report(PullRunner(good), str(root / SESSION / "report.json"), root)
            invalid_cases = (
                ({**good, "errors": [{"code": "artifact.invalid"}]}, "contains errors"),
                ({**good, "artifacts": [{key: value for key, value in record.items() if key != "sha256"}]},
                 "invalid artifact record"),
                ({**good, "artifacts": [{**record, "local_path": "artifacts/../fixture.trace.bin.lz4"}]},
                 "unsafe artifact path"),
            )
            for document, expected in invalid_cases:
                with self.subTest(expected=expected), self.assertRaisesRegex(RuntimeError, expected):
                    _validated_pull_report(PullRunner(document), str(root / SESSION / "report.json"), root)
            artifact.unlink()
            with self.assertRaisesRegex(RuntimeError, "outside the trusted directory"):
                _validated_pull_report(PullRunner(good), str(root / SESSION / "report.json"), root)

    def test_pull_validator_accepts_reports_written_by_every_production_pull_mode(self):
        from scripts.qtrace_device_acceptance import (
            RootedReader,
            SubprocessRunner,
            _validated_pull_report,
        )

        package = "com.example.app"
        status_document = {
            "schemaVersion": 1,
            "sessionId": SESSION,
            "generation": 1,
            "packageName": package,
            "pid": 123,
            "state": "sealed",
            "reason": "duration_elapsed",
            "transitionMonotonicNs": 1,
            "deadlineMonotonicNs": 2,
            "normalizedScenes": [],
            "activeScenes": [],
            "artifacts": ["run.trace.txt"],
            "stopAcknowledged": True,
            "warnings": [],
            "errors": [],
        }
        status_name = f"session-{SESSION}.status.json"
        runner = SubprocessRunner("SERIAL", inject_first_read_failure=False)
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            selections = (
                ("latest", PullSelection(PullMode.LATEST), None, False),
                ("name", PullSelection(PullMode.NAME, "run.trace.txt"),
                 "run.trace.txt", False),
                ("all", PullSelection(PullMode.ALL), None, False),
            )
            for label, selection, named, compressed_only in selections:
                client = FakeClient({
                    status_name: json.dumps(status_document).encode(),
                    "run.trace.txt": COMPLETE_TERMINAL,
                })
                output = parent / label
                result = ArtifactProcessor(client_factory=lambda _d, _p, c=client: c).pull_manual(
                    "SERIAL", package, selection, output, 1.0,
                )
                self.assertEqual(0, result.exit_code)
                with RootedReader(output) as held:
                    _validated_pull_report(
                        runner,
                        str(result.output_dir / "report.json"),
                        held,
                        named=named,
                        compressed_only=compressed_only,
                    )

            lz4 = fake_lz4_executable(parent)
            compressed_status = {
                **status_document,
                "artifacts": ["run.trace.txt.lz4"],
            }
            compressed_client = FakeClient({
                status_name: json.dumps(compressed_status).encode(),
                "run.trace.txt.lz4": uncompressed_lz4_frame(COMPLETE_TERMINAL),
            })
            output = parent / "compressed"
            with patch("qtrace.artifacts.shutil.which", return_value=str(lz4)):
                result = ArtifactProcessor(
                    client_factory=lambda _d, _p: compressed_client,
                ).pull_manual(
                    "SERIAL", package,
                    PullSelection(PullMode.ALL, compressed_only=True),
                    output, 1.0,
                )
            self.assertEqual(0, result.exit_code)
            with RootedReader(output) as held:
                _validated_pull_report(
                    runner,
                    str(result.output_dir / "report.json"),
                    held,
                    compressed_only=True,
                )

    def test_pull_validator_accepts_real_complete_flight_union_record(self):
        from scripts.qtrace_device_acceptance import (
            RootedReader,
            SubprocessRunner,
            _validated_pull_report,
        )

        client = FakeClient({"run.flight.bin": recoverable_flight_artifact()})
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "flight"
            result = ArtifactProcessor(client_factory=lambda _d, _p: client).pull_manual(
                "SERIAL", "com.example.app",
                PullSelection(PullMode.NAME, "run.flight.bin"), output, 1.0,
            )
            self.assertEqual(0, result.exit_code)
            with RootedReader(output) as held:
                _validated_pull_report(
                    SubprocessRunner("SERIAL", inject_first_read_failure=False),
                    str(result.output_dir / "report.json"),
                    held,
                    named="run.flight.bin",
                )

    def test_pull_validator_stats_large_artifacts_without_reading_them(self):
        from scripts.qtrace_device_acceptance import RootedReader, _validated_pull_report

        record = {
            "remote_name": "large.trace.bin",
            "local_path": "artifacts/large.trace.bin",
            "source_size": 2 * 1024 * 1024,
            "destination_size": 2 * 1024 * 1024,
            "sha256": "0" * 64,
            "decoder": "qtrb",
            "termination": "completed",
            "stop_reason": None,
            "metrics_schema": None,
            "producer_waits": None,
            "producer_wait_ns": None,
            "conversion_ms": 0.0,
            "native_stop_acknowledged": None,
            "host_observed_ack_ms": None,
        }

        class PullRunner:
            def read_text_beneath(self, _root, _relative, *, timeout):
                return json.dumps({
                    "schema": 1,
                    "sessionId": SESSION,
                    "artifacts": [record],
                    "errors": [],
                })

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / SESSION / "artifacts" / record["remote_name"]
            artifact.parent.mkdir(parents=True)
            with artifact.open("wb") as output:
                output.truncate(record["destination_size"])
            with RootedReader(root) as held:
                _validated_pull_report(
                    PullRunner(), str(root / SESSION / "report.json"), held,
                )
                record["destination_size"] += 1
                with self.assertRaisesRegex(RuntimeError, "destination size"):
                    _validated_pull_report(
                        PullRunner(), str(root / SESSION / "report.json"), held,
                    )

    def test_report_parent_is_bound_to_the_report_session_id(self):
        from scripts.qtrace_device_acceptance import (
            _validated_pull_report,
            _validated_timed_report,
        )

        pull_record = {
            "remote_name": "fixture.trace.bin",
            "local_path": "artifacts/fixture.trace.bin",
            "source_size": 1,
            "destination_size": 1,
            "sha256": "0" * 64,
            "decoder": "qtrb",
            "termination": "completed",
            "stop_reason": None,
            "metrics_schema": None,
            "producer_waits": None,
            "producer_wait_ns": None,
            "conversion_ms": 0.0,
            "native_stop_acknowledged": None,
            "host_observed_ack_ms": None,
        }

        class PullRunner:
            def read_text_beneath(self, _root, _relative, *, timeout):
                return json.dumps({
                    "schema": 1, "sessionId": SESSION,
                    "artifacts": [pull_record], "errors": [],
                })

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wrong = "223e4567-e89b-42d3-a456-426614174001"
            artifact = root / wrong / "artifacts" / pull_record["remote_name"]
            artifact.parent.mkdir(parents=True)
            artifact.write_bytes(b"x")
            with self.assertRaisesRegex(RuntimeError, "session directory"):
                _validated_pull_report(
                    PullRunner(), str(root / wrong / "report.json"), root,
                )

        runner = FakeRunner()
        with self.assertRaisesRegex(RuntimeError, "session directory"):
            _validated_timed_report(
                runner, Path("output"),
                Path("223e4567-e89b-42d3-a456-426614174001") / "report.json",
            )

    def test_acceptance_closes_each_held_root_after_mid_setup_failure(self):
        from scripts.qtrace_device_acceptance import CommandResult, run_acceptance

        class FailureRunner(FakeRunner):
            def __init__(self, failure):
                super().__init__()
                self.failure = failure
                self.demo_count = 0

            def run(self, command, *, timeout, cwd=None, allowed=(0,)):
                if "qtrace" in command and "demo" in command:
                    self.demo_count += 1
                    if self.failure == "command" and self.demo_count == 2:
                        raise RuntimeError("second demo failed")
                    result = super().run(
                        command, timeout=timeout, cwd=cwd, allowed=allowed,
                    )
                    if self.failure == "path" and self.demo_count == 1:
                        return CommandResult("not-a-report\n", "", 0)
                    return result
                return super().run(command, timeout=timeout, cwd=cwd, allowed=allowed)

            def read_text(self, path, *, timeout):
                if self.failure == "evidence" and path.name == "qtrace-acceptance-receipt.json":
                    raise RuntimeError("receipt read failed")
                return super().read_text(path, timeout=timeout)

        def descriptor_count():
            return len(list(Path("/proc/self/fd").iterdir()))

        for failure in ("command", "path", "evidence"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                before = descriptor_count()
                with self.assertRaises(RuntimeError):
                    run_acceptance(
                        "SERIAL", Path(temporary), runner=FailureRunner(failure),
                    )
                self.assertEqual(before, descriptor_count())

    def test_requires_an_explicit_device(self):
        from scripts.qtrace_device_acceptance import main

        self.assertEqual(2, main([]))

    def test_failure_retains_generated_evidence_after_main_returns(self):
        from scripts.qtrace_device_acceptance import main

        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            actual_temporary_directory = tempfile.TemporaryDirectory
            captured: dict[str, object] = {}

            def tracked_temporary_directory(*args, **kwargs):
                captured.update(kwargs)
                return actual_temporary_directory(*args, **kwargs)

            with patch("scripts.qtrace_device_acceptance.Path.cwd", return_value=workspace), \
                    patch("scripts.qtrace_device_acceptance.tempfile.TemporaryDirectory",
                          side_effect=tracked_temporary_directory), \
                    patch("scripts.qtrace_device_acceptance.run_acceptance",
                          side_effect=RuntimeError("fixture failure")):
                self.assertEqual(1, main(["--device", "SERIAL"]))
            retained = list((workspace / "qtrace-acceptance-failures").iterdir())
            self.assertEqual(1, len(retained))
            self.assertTrue(retained[0].is_dir())
            self.assertEqual(workspace / "qtrace-acceptance-failures", captured["dir"])

    def test_acceptance_runs_bounded_workflow_and_retries_one_read(self):
        from scripts.qtrace_device_acceptance import run_acceptance

        runner = FakeRunner(fail_first_read=True)
        with tempfile.TemporaryDirectory() as temporary:
            (Path(temporary) / "offset").mkdir()
            (Path(temporary) / "offset" / "fixture.trace.txt").write_text("fixture")
            artifacts = Path(temporary) / "offset" / "artifacts"
            artifacts.mkdir()
            (artifacts / "fixture.trace.bin.lz4").write_bytes(b"fixture qtrb bytes")
            (artifacts / "fixture.trace.bin.lz4.metrics").write_text("metrics")
            artifact_client = FakeArtifactClient(Path(temporary) / "offset")
            for name in ("latest", "name", "all", "compressed"):
                artifacts = Path(temporary) / name / SESSION / "artifacts"
                artifacts.mkdir(parents=True)
                (artifacts / "fixture.trace.bin.lz4").write_bytes(b"pulled artifact")
            def converter(_source, destination, *, lz4, crash_marked):
                self.assertEqual("lz4", lz4)
                self.assertFalse(crash_marked)
                destination.write_text(
                    "TRACE_BEGIN format=4 scene=fixture-entry\n"
                    "TRACE_END status=stopped reason=duration_elapsed return_valid=0 elapsed_ms=2000\n",
                    encoding="utf-8",
                )
                return SimpleNamespace(termination="stopped", partial=False)
            self.assertEqual(0, run_acceptance(
                "SERIAL", Path(temporary), runner=runner, converter=converter,
                artifact_client_factory=lambda **_kwargs: artifact_client,
            ))
            self.assertEqual([("fixture.trace.bin.lz4.metrics", 64 * 1024)], artifact_client.calls)
            self.assertEqual([True], artifact_client.evidence_present_during_retry)
        commands = runner.commands
        self.assertEqual(("./gradlew", "nativeHostTest", "--no-daemon"), commands[0])
        self.assertEqual(("python3", "-m", "unittest", "discover", "-s", "scripts/tests", "-p", "test_*.py"), commands[1])
        self.assertEqual(("./gradlew", ":app:assembleDebug", "--no-daemon"), commands[2])
        self.assertEqual(("adb", "-s", "SERIAL", "install", "-r", "app/build/outputs/apk/debug/app-debug.apk"), commands[3])
        self.assertEqual(("adb", "-s", "SERIAL", "shell", "am", "force-stop", "com.aprz.qbdiandroid"), commands[4])
        self.assertEqual(
            ("adb", "-s", "SERIAL", "shell", "am", "start", "-n", "com.aprz.qbdiandroid/.MainActivity",
             "--ez", "qtrace_acceptance", "true", "--es", "qtrace_acceptance_mode", "timed",
             "--el", "qtrace_acceptance_seed", "5855319310239641971", "--el", "qtrace_acceptance_iterations", "30"),
            commands[5],
        )
        self.assertEqual(("python3", "scripts/benchmark_trace.py", "--device", "SERIAL", "--profile", "fast", "--runs", "5", "--candidate-tracer", "out/arm64-v8a/libqbdi_tracer.so", "--compare", "docs/benchmarks/binary-trace-baseline.md"), commands[6])
        self.assertEqual(16, len(commands))
        self.assertEqual(15, runner.reads)  # baseline retry, per-run entry evidence, reports, oracle, pulls
        self.assertEqual(("adb", "-s", "SERIAL", "shell", "kill", "-0", "4242"), commands[11])
        self.assertIn("--name", commands[13])
        self.assertIn("fixture.trace.bin.lz4", commands[13])
        self.assertEqual("--compressed-only", commands[15][-5])


if __name__ == "__main__":
    unittest.main()
