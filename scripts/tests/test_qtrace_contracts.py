"""Host contracts for the manual qtrace device-acceptance gate."""

from __future__ import annotations

import copy
import contextlib
from contextlib import contextmanager
import hashlib
import io
import json
import math
import os
import re
import signal
import stat
import subprocess
import sys
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


@contextmanager
def held_tracer_pair(binaries):
    from scripts.qtrace_device_acceptance import (
        HeldTracerPair,
        _snapshot_host_binary,
    )

    with tempfile.TemporaryDirectory(prefix="qtrace-test-held-pair-") as temporary:
        root = Path(temporary)
        deadline = time.monotonic() + 2.0
        tracer = _snapshot_host_binary(
            binaries[0][0], root / "libqbdi_tracer.so",
            maximum_bytes=64 * 1024 * 1024, deadline=deadline,
        )
        try:
            companion = _snapshot_host_binary(
                binaries[1][0], root / "libshadowhook_nothing.so",
                maximum_bytes=64 * 1024 * 1024, deadline=deadline,
            )
        except BaseException:
            tracer.close()
            raise
        pair = HeldTracerPair(tracer, companion)
        try:
            yield pair
        finally:
            pair.close()


class ProjectSchemaValidationError(ValueError):
    pass


class _InstanceSchemaMismatch(Exception):
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
        "minimum", "maximum", "oneOf", "anyOf", "allOf", "if", "then", "else", "not",
        "x-qtrace-runtime-invariants",
    })
    _SCHEMA_IDS = frozenset({
        "https://qbdi-android.local/schema/qtrace-config.schema.json",
        "https://qbdi-android.local/schema/qtrace-session-status.schema.json",
    })
    _SCHEMA_TYPES = frozenset({"object", "array", "string", "integer", "boolean"})
    _RUNTIME_PREDICATES = frozenset({
        "utf8-text", "unique-field", "ordered-hex-fields", "conditional-member",
        "ordered-integer-fields", "unique-pair", "index-within-array",
        "safe-artifact-basename",
    })
    _UNICODE_CATEGORIES = frozenset({
        "Lu", "Ll", "Lt", "Lm", "Lo", "Mn", "Mc", "Me", "Nd", "Nl", "No",
        "Pc", "Pd", "Ps", "Pe", "Pi", "Pf", "Po", "Sm", "Sc", "Sk", "So",
        "Zs", "Zl", "Zp", "Cc", "Cf", "Cs", "Co", "Cn",
    })
    _UNICODE_CATEGORY_PREFIXES = frozenset("LMNPSZC")

    def __init__(self, schema: dict[str, object]) -> None:
        if type(schema) is not dict:
            self._contract_error("#", "root must be an object")
        self._validate_json_ast(schema, "#")
        self.schema = schema
        if type(schema.get("$id")) is not str or schema["$id"] not in self._SCHEMA_IDS:
            self._contract_error("#/$id", "unsupported qtrace schema id")
        self._validate_schema_node(schema, "#", root=True)

    @staticmethod
    def _contract_error(path: str, message: str) -> None:
        raise ProjectSchemaValidationError(
            f"invalid qtrace schema contract at {path}: {message}"
        )

    @staticmethod
    def _child_path(path: str, token: object) -> str:
        encoded = str(token).replace("~", "~0").replace("/", "~1")
        return f"{path}/{encoded}"

    @classmethod
    def _validate_json_ast(cls, value: object, path: str) -> None:
        if value is None or type(value) in {str, int, bool}:
            return
        if type(value) is float:
            if not math.isfinite(value):
                cls._contract_error(path, "schema JSON number must be finite")
            return
        if type(value) is list:
            for index, item in enumerate(value):
                cls._validate_json_ast(item, cls._child_path(path, index))
            return
        if type(value) is dict:
            for key, item in value.items():
                if type(key) is not str:
                    cls._contract_error(path, "schema object keys must be strings")
                cls._validate_json_ast(item, cls._child_path(path, key))
            return
        cls._contract_error(path, "schema must contain only JSON values")

    @staticmethod
    def _is_nonnegative_integer(value: object) -> bool:
        return type(value) is int and value >= 0

    @classmethod
    def _validate_string_list(
        cls,
        value: object,
        path: str,
        *,
        allow_empty_strings: bool = False,
        allow_empty_list: bool = True,
    ) -> list[str]:
        if (type(value) is not list or (not allow_empty_list and not value)
                or not all(type(item) is str for item in value)
                or (not allow_empty_strings and any(not item for item in value))
                or len(set(value)) != len(value)):
            cls._contract_error(path, "must be a unique string array")
        return value

    @classmethod
    def _validate_pointer(cls, pointer: object, path: str) -> None:
        if type(pointer) is not str or not pointer.startswith("/"):
            cls._contract_error(path, "must be an absolute project JSON pointer")
        encoded_tokens = pointer.split("/")[1:]
        if not encoded_tokens or any(token == "" for token in encoded_tokens):
            cls._contract_error(path, "must contain non-empty pointer tokens")
        for token in encoded_tokens:
            index = 0
            while index < len(token):
                if token[index] == "~":
                    if index + 1 >= len(token) or token[index + 1] not in "01":
                        cls._contract_error(path, "contains an invalid JSON pointer escape")
                    index += 2
                else:
                    index += 1

    @classmethod
    def _validate_field_name(cls, value: object, path: str) -> None:
        if type(value) is not str or not value:
            cls._contract_error(path, "must be a non-empty field name")

    def _validate_schema_node(self, schema: object, path: str, *, root: bool = False) -> None:
        if type(schema) is bool:
            return
        if type(schema) is not dict:
            self._contract_error(path, "schema node must be an object or boolean")
        unknown = set(schema) - self._SUPPORTED_KEYS
        if unknown:
            self._contract_error(
                self._child_path(path, sorted(unknown)[0]),
                "unsupported project schema keyword",
            )

        if root and schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            self._contract_error(self._child_path(path, "$schema"), "unsupported dialect")
        if "$schema" in schema and not root:
            self._contract_error(self._child_path(path, "$schema"), "nested dialect is unsupported")
        if "$id" in schema:
            if not root or schema["$id"] not in self._SCHEMA_IDS:
                self._contract_error(self._child_path(path, "$id"), "unsupported schema id")
        if "title" in schema and type(schema["title"]) is not str:
            self._contract_error(self._child_path(path, "title"), "title must be a string")
        if "type" in schema and (
            type(schema["type"]) is not str or schema["type"] not in self._SCHEMA_TYPES
        ):
            self._contract_error(self._child_path(path, "type"), "unsupported schema type")

        if "$defs" in schema:
            definitions = schema["$defs"]
            if type(definitions) is not dict or not all(
                type(name) is str and name for name in definitions
            ):
                self._contract_error(self._child_path(path, "$defs"), "must be an object")
            for name, child in definitions.items():
                self._validate_schema_node(
                    child,
                    self._child_path(self._child_path(path, "$defs"), name),
                )

        if "properties" in schema:
            properties = schema["properties"]
            if type(properties) is not dict or not all(type(name) is str for name in properties):
                self._contract_error(self._child_path(path, "properties"), "must be an object")
            for name, child in properties.items():
                self._validate_schema_node(
                    child,
                    self._child_path(self._child_path(path, "properties"), name),
                )

        if "$ref" in schema:
            reference = schema["$ref"]
            if (type(reference) is not str
                    or re.fullmatch(r"#/\$defs/[^~/]+", reference) is None):
                self._contract_error(self._child_path(path, "$ref"), "unsupported reference")
            name = reference.removeprefix("#/$defs/")
            root_definitions = self.schema.get("$defs")
            if type(root_definitions) is not dict or name not in root_definitions:
                self._contract_error(self._child_path(path, "$ref"), "missing definition")
            if type(root_definitions[name]) not in {dict, bool}:
                self._contract_error(self._child_path(path, "$ref"), "target is not a schema")

        if "required" in schema:
            self._validate_string_list(schema["required"], self._child_path(path, "required"))
        if "additionalProperties" in schema and type(schema["additionalProperties"]) is not bool:
            self._contract_error(
                self._child_path(path, "additionalProperties"),
                "must be a boolean in the project subset",
            )

        for minimum_key, maximum_key in (
            ("minItems", "maxItems"),
            ("minLength", "maxLength"),
        ):
            for key in (minimum_key, maximum_key):
                if key in schema and not self._is_nonnegative_integer(schema[key]):
                    self._contract_error(self._child_path(path, key), "must be a non-negative integer")
            if (minimum_key in schema and maximum_key in schema
                    and schema[minimum_key] > schema[maximum_key]):
                self._contract_error(path, f"{minimum_key} must not exceed {maximum_key}")

        if "uniqueItems" in schema and type(schema["uniqueItems"]) is not bool:
            self._contract_error(self._child_path(path, "uniqueItems"), "must be a boolean")
        if "pattern" in schema:
            if type(schema["pattern"]) is not str:
                self._contract_error(self._child_path(path, "pattern"), "must be a string")
            try:
                re.compile(schema["pattern"])
            except re.error as error:
                self._contract_error(self._child_path(path, "pattern"), f"invalid regex: {error}")
        if "format" in schema and schema["format"] != "uuid":
            self._contract_error(self._child_path(path, "format"), "unsupported format")
        for key in ("minimum", "maximum"):
            if key in schema and type(schema[key]) is not int:
                self._contract_error(self._child_path(path, key), "must be an integer")
        if ("minimum" in schema and "maximum" in schema
                and schema["minimum"] > schema["maximum"]):
            self._contract_error(path, "minimum must not exceed maximum")
        if "enum" in schema:
            enum = schema["enum"]
            if type(enum) is not list or not enum:
                self._contract_error(self._child_path(path, "enum"), "must be a non-empty array")
            serialized = [json.dumps(item, sort_keys=True, ensure_ascii=True) for item in enum]
            if len(set(serialized)) != len(serialized):
                self._contract_error(self._child_path(path, "enum"), "values must be unique")

        if "items" in schema:
            self._validate_schema_node(schema["items"], self._child_path(path, "items"))
        for key in ("allOf", "anyOf", "oneOf"):
            if key not in schema:
                continue
            candidates = schema[key]
            if type(candidates) is not list or (key != "allOf" and not candidates):
                self._contract_error(self._child_path(path, key), "must be a schema array")
            for index, child in enumerate(candidates):
                self._validate_schema_node(
                    child,
                    self._child_path(self._child_path(path, key), index),
                )
        for key in ("not", "if", "then", "else"):
            if key in schema:
                self._validate_schema_node(schema[key], self._child_path(path, key))
        if ("then" in schema or "else" in schema) and "if" not in schema:
            self._contract_error(path, "then/else require if in the project subset")

        if "x-qtrace-runtime-invariants" in schema:
            self._validate_runtime_rule_contracts(
                schema["x-qtrace-runtime-invariants"],
                self._child_path(path, "x-qtrace-runtime-invariants"),
            )

    def accepts(self, value: object) -> bool:
        try:
            self._validate_instance(value, self.schema)
        except _InstanceSchemaMismatch:
            return False
        return True

    def _matches(self, value: object, schema: object) -> bool:
        try:
            self._validate_instance(value, schema)
        except _InstanceSchemaMismatch:
            return False
        return True

    def _validate_instance(self, value: object, schema: object) -> None:
        if schema is True:
            return
        if schema is False:
            raise _InstanceSchemaMismatch("false schema")
        assert type(schema) is dict
        if "$ref" in schema:
            reference = schema["$ref"]
            name = reference.removeprefix("#/$defs/")
            definitions = self.schema.get("$defs")
            assert type(definitions) is dict
            self._validate_instance(value, definitions[name])

        expected_type = schema.get("type")
        type_matches = {
            "object": type(value) is dict,
            "array": type(value) is list,
            "string": type(value) is str,
            "integer": type(value) is int,
            "boolean": type(value) is bool,
        }
        if expected_type is not None:
            if not type_matches[expected_type]:
                raise _InstanceSchemaMismatch("schema type mismatch")
        if "const" in schema and (type(value) is not type(schema["const"])
                                  or value != schema["const"]):
            raise _InstanceSchemaMismatch("schema const mismatch")
        if "enum" in schema and not any(
            type(value) is type(candidate) and value == candidate
            for candidate in schema["enum"]
        ):
            raise _InstanceSchemaMismatch("schema enum mismatch")

        if type(value) is dict:
            required = schema.get("required", [])
            if any(key not in value for key in required):
                raise _InstanceSchemaMismatch("schema required property missing")
            properties = schema.get("properties", {})
            if schema.get("additionalProperties") is False and set(value) - set(properties):
                raise _InstanceSchemaMismatch("schema additional property")
            for key, child_schema in properties.items():
                if key in value:
                    self._validate_instance(value[key], child_schema)
        if type(value) is list:
            if "minItems" in schema and len(value) < schema["minItems"]:
                raise _InstanceSchemaMismatch("schema array too short")
            if "maxItems" in schema and len(value) > schema["maxItems"]:
                raise _InstanceSchemaMismatch("schema array too long")
            if schema.get("uniqueItems") is True:
                serialized = [json.dumps(item, sort_keys=True, ensure_ascii=True) for item in value]
                if len(set(serialized)) != len(serialized):
                    raise _InstanceSchemaMismatch("schema array items are duplicated")
            if "items" in schema:
                for item in value:
                    self._validate_instance(item, schema["items"])
        if type(value) is str:
            if "minLength" in schema and len(value) < schema["minLength"]:
                raise _InstanceSchemaMismatch("schema string too short")
            if "maxLength" in schema and len(value) > schema["maxLength"]:
                raise _InstanceSchemaMismatch("schema string too long")
            if "pattern" in schema and re.search(schema["pattern"], value) is None:
                raise _InstanceSchemaMismatch("schema string pattern mismatch")
        if type(value) is int and type(value) is not bool:
            if "minimum" in schema and value < schema["minimum"]:
                raise _InstanceSchemaMismatch("schema number below minimum")
            if "maximum" in schema and value > schema["maximum"]:
                raise _InstanceSchemaMismatch("schema number above maximum")

        if "oneOf" in schema:
            if sum(self._matches(value, candidate) for candidate in schema["oneOf"]) != 1:
                raise _InstanceSchemaMismatch("schema oneOf mismatch")
        if "anyOf" in schema:
            if not any(self._matches(value, candidate) for candidate in schema["anyOf"]):
                raise _InstanceSchemaMismatch("schema anyOf mismatch")
        for candidate in schema.get("allOf", []):
            self._validate_instance(value, candidate)
        if "if" in schema:
            branch = "then" if self._matches(value, schema["if"]) else "else"
            if branch in schema:
                self._validate_instance(value, schema[branch])
        if "not" in schema and self._matches(value, schema["not"]):
            raise _InstanceSchemaMismatch("schema not mismatch")
        if "x-qtrace-runtime-invariants" in schema:
            self._evaluate_runtime_rules(value, schema["x-qtrace-runtime-invariants"])

    def _validate_runtime_rule_contracts(self, rules: object, path: str) -> None:
        if type(rules) is not list:
            self._contract_error(path, "runtime rules must be an array")
        identifiers: list[str] = []
        for index, rule in enumerate(rules):
            rule_path = self._child_path(path, index)
            if type(rule) is not dict or set(rule) != {"id", "paths", "predicate", "args"}:
                self._contract_error(rule_path, "runtime rule shape must be exact")
            if type(rule["id"]) is not str or not rule["id"]:
                self._contract_error(self._child_path(rule_path, "id"), "must be non-empty text")
            identifiers.append(rule["id"])
            paths_path = self._child_path(rule_path, "paths")
            paths = self._validate_string_list(
                rule["paths"],
                paths_path,
                allow_empty_list=False,
            )
            for path_index, pointer in enumerate(paths):
                self._validate_pointer(pointer, self._child_path(paths_path, path_index))
            predicate = rule["predicate"]
            if type(predicate) is not str or predicate not in self._RUNTIME_PREDICATES:
                self._contract_error(
                    self._child_path(rule_path, "predicate"),
                    "unsupported runtime predicate",
                )
            self._validate_runtime_rule_args(
                predicate,
                rule["args"],
                self._child_path(rule_path, "args"),
            )
        if len(set(identifiers)) != len(identifiers):
            self._contract_error(path, "runtime rule ids must be unique")

    def _validate_runtime_rule_args(
        self,
        predicate: str,
        args: object,
        path: str,
    ) -> None:
        expected_keys = {
            "utf8-text": {"minBytes", "maxBytes", "forbiddenCategories"},
            "unique-field": {"field", "caseSensitive"},
            "ordered-hex-fields": {
                "startField", "endField", "minimumExclusive", "alignment",
            },
            "conditional-member": {
                "conditionPath", "conditionEquals", "valuePath", "membersPath",
                "requiredWhenTrue", "forbiddenWhenFalse",
            },
            "ordered-integer-fields": {
                "startField", "endField", "minimumStart", "strict",
            },
            "unique-pair": {"fields"},
            "index-within-array": {"indexField", "arrayPath", "minimum"},
            "safe-artifact-basename": {
                "minBytes", "maxBytes", "forbiddenNames", "forbiddenSeparators",
                "forbiddenCategoryPrefixes", "allowedSuffixes", "embeddedUuidPattern",
                "embeddedUuidMustEqualPath",
            },
        }[predicate]
        if type(args) is not dict or set(args) != expected_keys:
            self._contract_error(path, f"{predicate} arguments must be exact")

        if predicate == "utf8-text":
            minimum = args["minBytes"]
            maximum = args["maxBytes"]
            if (not self._is_nonnegative_integer(minimum)
                    or (maximum is not None and (
                        not self._is_nonnegative_integer(maximum) or maximum < minimum
                    ))):
                self._contract_error(path, "UTF-8 byte bounds are invalid")
            categories = self._validate_string_list(
                args["forbiddenCategories"],
                self._child_path(path, "forbiddenCategories"),
            )
            if any(category not in self._UNICODE_CATEGORIES for category in categories):
                self._contract_error(path, "unknown Unicode category")
            return

        if predicate == "unique-field":
            self._validate_field_name(args["field"], self._child_path(path, "field"))
            if args["caseSensitive"] is not True:
                self._contract_error(
                    self._child_path(path, "caseSensitive"),
                    "only exact case-sensitive comparison is supported",
                )
            return

        if predicate in {"ordered-hex-fields", "ordered-integer-fields"}:
            self._validate_field_name(
                args["startField"], self._child_path(path, "startField")
            )
            self._validate_field_name(args["endField"], self._child_path(path, "endField"))
            if args["startField"] == args["endField"]:
                self._contract_error(path, "ordered field names must differ")
            if predicate == "ordered-hex-fields":
                if (not self._is_nonnegative_integer(args["minimumExclusive"])
                        or type(args["alignment"]) is not int or args["alignment"] <= 0):
                    self._contract_error(path, "ordered hex bounds are invalid")
            elif (not self._is_nonnegative_integer(args["minimumStart"])
                  or args["strict"] is not True):
                self._contract_error(path, "ordered integer bounds are invalid")
            return

        if predicate == "conditional-member":
            for key in ("conditionPath", "valuePath", "membersPath"):
                self._validate_pointer(args[key], self._child_path(path, key))
            if (type(args["conditionEquals"]) is not bool
                    or type(args["requiredWhenTrue"]) is not bool
                    or type(args["forbiddenWhenFalse"]) is not bool):
                self._contract_error(path, "conditional-member flags must be booleans")
            return

        if predicate == "unique-pair":
            fields = self._validate_string_list(
                args["fields"],
                self._child_path(path, "fields"),
                allow_empty_list=False,
            )
            if len(fields) != 2:
                self._contract_error(path, "unique-pair requires exactly two fields")
            return

        if predicate == "index-within-array":
            self._validate_field_name(
                args["indexField"], self._child_path(path, "indexField")
            )
            self._validate_pointer(args["arrayPath"], self._child_path(path, "arrayPath"))
            if not self._is_nonnegative_integer(args["minimum"]):
                self._contract_error(self._child_path(path, "minimum"), "must be non-negative")
            return

        if predicate == "safe-artifact-basename":
            minimum = args["minBytes"]
            maximum = args["maxBytes"]
            if (not self._is_nonnegative_integer(minimum)
                    or not self._is_nonnegative_integer(maximum)
                    or minimum > maximum):
                self._contract_error(path, "artifact byte bounds are invalid")
            self._validate_string_list(
                args["forbiddenNames"],
                self._child_path(path, "forbiddenNames"),
                allow_empty_strings=True,
            )
            self._validate_string_list(
                args["forbiddenSeparators"],
                self._child_path(path, "forbiddenSeparators"),
                allow_empty_list=False,
            )
            prefixes = self._validate_string_list(
                args["forbiddenCategoryPrefixes"],
                self._child_path(path, "forbiddenCategoryPrefixes"),
            )
            if any(prefix not in self._UNICODE_CATEGORY_PREFIXES for prefix in prefixes):
                self._contract_error(path, "unknown Unicode category prefix")
            self._validate_string_list(
                args["allowedSuffixes"],
                self._child_path(path, "allowedSuffixes"),
                allow_empty_list=False,
            )
            pattern = args["embeddedUuidPattern"]
            if type(pattern) is not str:
                self._contract_error(
                    self._child_path(path, "embeddedUuidPattern"),
                    "must be a regex string",
                )
            try:
                re.compile(pattern)
            except re.error as error:
                self._contract_error(
                    self._child_path(path, "embeddedUuidPattern"),
                    f"invalid regex: {error}",
                )
            self._validate_pointer(
                args["embeddedUuidMustEqualPath"],
                self._child_path(path, "embeddedUuidMustEqualPath"),
            )

    @staticmethod
    def _pointer_values(root: object, pointer: str) -> list[object]:
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
            raise _InstanceSchemaMismatch("runtime rule pointer is not singular")
        return values[0] if values else None

    def _evaluate_runtime_rules(self, root: object, rules: list[object]) -> None:
        for rule in rules:
            assert type(rule) is dict
            predicate = getattr(self, f"_rule_{rule['predicate'].replace('-', '_')}", None)
            assert predicate is not None
            predicate(root, rule["paths"], rule["args"])

    def _rule_utf8_text(self, root: object, paths: list[str], args: dict[str, object]) -> None:
        for path in paths:
            for value in self._pointer_values(root, path):
                if type(value) is not str:
                    raise _InstanceSchemaMismatch("runtime text is not a string")
                try:
                    encoded = value.encode("utf-8")
                except UnicodeEncodeError as error:
                    raise _InstanceSchemaMismatch("runtime text is not UTF-8") from error
                if len(encoded) < args["minBytes"]:
                    raise _InstanceSchemaMismatch("runtime text is too short")
                if args["maxBytes"] is not None and len(encoded) > args["maxBytes"]:
                    raise _InstanceSchemaMismatch("runtime text is too long")
                if any(unicodedata.category(character) in args["forbiddenCategories"]
                       for character in value):
                    raise _InstanceSchemaMismatch("runtime text category is forbidden")

    def _rule_unique_field(self, root: object, paths: list[str], args: dict[str, object]) -> None:
        values = [value for path in paths for value in self._pointer_values(root, path)]
        if len(set(values)) != len(values):
            raise _InstanceSchemaMismatch("runtime field values are duplicated")

    def _rule_ordered_hex_fields(self, root: object, paths: list[str], args: dict[str, object]) -> None:
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
                    raise _InstanceSchemaMismatch("runtime offset is invalid") from error
                if (start <= args["minimumExclusive"] or end <= args["minimumExclusive"]
                        or start % args["alignment"] or end % args["alignment"]
                        or start >= end):
                    raise _InstanceSchemaMismatch("runtime offset range is invalid")

    def _rule_conditional_member(self, root: object, _paths: list[str], args: dict[str, object]) -> None:
        enabled = self._single_pointer(root, args["conditionPath"])
        enabled = False if enabled is None else enabled == args["conditionEquals"]
        selected = self._single_pointer(root, args["valuePath"])
        if enabled:
            members = self._pointer_values(root, args["membersPath"])
            if args["requiredWhenTrue"] is True and selected is None:
                raise _InstanceSchemaMismatch("runtime member is missing")
            if selected not in members:
                raise _InstanceSchemaMismatch("runtime member does not exist")
        elif args["forbiddenWhenFalse"] is True and selected is not None:
            raise _InstanceSchemaMismatch("runtime member is forbidden")

    def _rule_ordered_integer_fields(self, root: object, paths: list[str], args: dict[str, object]) -> None:
        for path in paths:
            for value in self._pointer_values(root, path):
                start, end = value[args["startField"]], value[args["endField"]]
                if (type(start) is not int or type(end) is not int
                        or start < args["minimumStart"] or end <= start):
                    raise _InstanceSchemaMismatch("runtime integer range is invalid")

    def _rule_unique_pair(self, root: object, paths: list[str], args: dict[str, object]) -> None:
        pairs = []
        for path in paths:
            pairs.extend(tuple(value[field] for field in args["fields"])
                         for value in self._pointer_values(root, path))
        if len(set(pairs)) != len(pairs):
            raise _InstanceSchemaMismatch("runtime pairs are duplicated")

    def _rule_index_within_array(self, root: object, paths: list[str], args: dict[str, object]) -> None:
        target = self._single_pointer(root, args["arrayPath"])
        if type(target) is not list:
            raise _InstanceSchemaMismatch("runtime index target is not an array")
        for path in paths:
            for value in self._pointer_values(root, path):
                index = value[args["indexField"]]
                if type(index) is not int or not args["minimum"] <= index < len(target):
                    raise _InstanceSchemaMismatch("runtime index is out of range")

    def _rule_safe_artifact_basename(self, root: object, paths: list[str], args: dict[str, object]) -> None:
        owner = self._single_pointer(root, args["embeddedUuidMustEqualPath"])
        uuid_pattern = re.compile(args["embeddedUuidPattern"])
        for path in paths:
            for value in self._pointer_values(root, path):
                if type(value) is not str:
                    raise _InstanceSchemaMismatch("runtime artifact is not text")
                try:
                    encoded = value.encode("utf-8")
                except UnicodeEncodeError as error:
                    raise _InstanceSchemaMismatch("runtime artifact is not UTF-8") from error
                if (not args["minBytes"] <= len(encoded) <= args["maxBytes"]
                        or value in args["forbiddenNames"]
                        or any(separator in value for separator in args["forbiddenSeparators"])
                        or any(any(unicodedata.category(character).startswith(prefix)
                                   for prefix in args["forbiddenCategoryPrefixes"])
                               for character in value)
                        or not value.endswith(tuple(args["allowedSuffixes"]))
                        or any(found.group(0) != owner for found in uuid_pattern.finditer(value))):
                    raise _InstanceSchemaMismatch("runtime artifact basename is unsafe")


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

    def test_schema_contract_validation_rejects_inactive_invalid_nodes(self):
        base = self.load_schema("qtrace-config.schema.json")
        valid_document = {
            "schemaVersion": 1,
            "app": {"package": "com.example.app"},
            "target": {"module": "libx.so"},
            "scenes": [{"name": "entry", "startOffset": "0x4", "endOffset": "0x8"}],
        }

        invalid_contracts: dict[str, dict[str, object]] = {}

        invalid_if = copy.deepcopy(base)
        invalid_if["allOf"] = [{"if": {"unknownKeyword": True}, "else": True}]
        invalid_contracts["if-unknown-keyword"] = invalid_if

        inactive_then = copy.deepcopy(base)
        inactive_then["allOf"] = [
            {"if": {"const": "never"}, "then": {"unknownKeyword": True}}
        ]
        invalid_contracts["inactive-then-unknown-keyword"] = inactive_then

        inactive_else = copy.deepcopy(base)
        inactive_else["allOf"] = [
            {
                "if": {"const": valid_document},
                "then": True,
                "else": {"minLength": "one"},
            }
        ]
        invalid_contracts["inactive-else-malformed-standard-keyword"] = inactive_else

        losing_one_of = copy.deepcopy(base)
        losing_one_of["$defs"]["unused"] = {
            "oneOf": [True, {"type": "string", "unknownKeyword": True}]
        }
        invalid_contracts["losing-one-of-unknown-keyword"] = losing_one_of

        unknown_predicate = copy.deepcopy(base)
        unknown_predicate["allOf"] = [
            {
                "if": {"const": "never"},
                "then": {
                    "x-qtrace-runtime-invariants": [{
                        "id": "invalid.predicate",
                        "paths": ["/scenes/*/name"],
                        "predicate": "not-supported",
                        "args": {},
                    }],
                },
            }
        ]
        invalid_contracts["inactive-unknown-predicate"] = unknown_predicate

        malformed_paths = copy.deepcopy(base)
        malformed_paths["$defs"]["unused"] = {
            "x-qtrace-runtime-invariants": [{
                "id": "invalid.path",
                "paths": ["scenes/*/name"],
                "predicate": "utf8-text",
                "args": {
                    "minBytes": 1,
                    "maxBytes": 128,
                    "forbiddenCategories": ["Cc"],
                },
            }],
        }
        invalid_contracts["unused-malformed-path"] = malformed_paths

        malformed_args = copy.deepcopy(base)
        malformed_args["allOf"] = [
            {
                "if": {"const": valid_document},
                "then": True,
                "else": {
                    "x-qtrace-runtime-invariants": [{
                        "id": "invalid.args",
                        "paths": ["/scenes/*/name"],
                        "predicate": "utf8-text",
                        "args": {
                            "minBytes": "one",
                            "maxBytes": 128,
                            "forbiddenCategories": ["Cc"],
                        },
                    }],
                },
            }
        ]
        invalid_contracts["inactive-malformed-args"] = malformed_args

        missing_reference = copy.deepcopy(base)
        missing_reference["$defs"]["unused"] = {"$ref": "#/$defs/missing"}
        invalid_contracts["unused-missing-reference"] = missing_reference

        for name, schema in invalid_contracts.items():
            with self.subTest(contract=name):
                with self.assertRaisesRegex(
                    ProjectSchemaValidationError,
                    "invalid qtrace schema contract",
                ):
                    QtraceProjectSchemaEvaluator(schema)

    def test_schema_contract_validation_supports_prevalidated_boolean_combinators(self):
        schema = self.load_schema("qtrace-config.schema.json")
        schema["allOf"] = [True, {"anyOf": [False, True]}, {"not": False}]
        document = {
            "schemaVersion": 1,
            "app": {"package": "com.example.app"},
            "target": {"module": "libx.so"},
            "scenes": [{"name": "entry", "startOffset": "0x4", "endOffset": "0x8"}],
        }

        evaluator = QtraceProjectSchemaEvaluator(schema)

        self.assertTrue(evaluator.accepts(document))
        invalid_document = copy.deepcopy(document)
        invalid_document["schemaVersion"] = 2
        self.assertFalse(evaluator.accepts(invalid_document))

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
        self.trace_directory_exists = False

    def run(self, command, *, timeout, cwd=None, allowed=(0,)):
        self.commands.append(tuple(command))
        if tuple(command[4:]) == (
            "run-as", "com.aprz.qbdiandroid", "mkdir", "files/qbdi-traces",
        ):
            self.trace_directory_exists = True
            return __import__(
                "scripts.qtrace_device_acceptance", fromlist=["CommandResult"],
            ).CommandResult("", "", 0)
        if (tuple(command[4:9]) ==
                ("run-as", "com.aprz.qbdiandroid", "stat", "-c", "%d:%i:%F") and
                str(command[-1]).startswith("files/qbdi-traces")):
            if command[-1] == "files/qbdi-traces" and self.trace_directory_exists:
                return __import__(
                    "scripts.qtrace_device_acceptance", fromlist=["CommandResult"],
                ).CommandResult("65082:900:directory\n", "", 0)
            return __import__(
                "scripts.qtrace_device_acceptance", fromlist=["CommandResult"],
            ).CommandResult(
                "", f"stat: '{command[-1]}': No such file or directory\n", 1,
            )
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
                "timeline": [{"stage": "installing_hooks", "cleanup_detached": True,
                              "action_nonce": SESSION}, {"stage": "running"}],
                "native": {"status": status("sealed")},
                "outputs": ["fixture.trace.bin.lz4", "fixture.trace.bin.lz4.metrics", str((self.offset_root or Path("/tmp")) / "fixture.trace.txt")],
                "artifacts": [{"remote_name": "fixture.trace.bin.lz4", "local_path": "artifacts/fixture.trace.bin.lz4", "termination": "stopped", "metrics_schema": 3, "native_stop_acknowledged": True}, {"remote_name": "fixture.trace.bin.lz4.metrics", "decoder": "sidecar"}],
            })
        if path.exists():
            return path.read_text(encoding="utf-8")
        return ""

    def read_text_beneath(self, root: Path, relative: Path, *, timeout: float) -> str:
        return self.read_text(getattr(root, "path", root) / relative, timeout=timeout)


class TraceIsolationRunner:
    """Stateful fake for the fixed demo app-private trace directory."""

    def __init__(self, nodes=None, *, rename_failure: bool = False,
                 mkdir_failure: bool = False):
        self.nodes = dict(nodes or {})
        self.rename_failure = rename_failure
        self.mkdir_failure = mkdir_failure
        self.next_inode = 900
        self.commands: list[tuple[tuple[str, ...], tuple[int, ...]]] = []

    def run(self, command, *, timeout, cwd=None, allowed=(0,)):
        from scripts.qtrace_device_acceptance import CommandResult

        command = tuple(command)
        self.commands.append((command, allowed))
        operation = command[6]
        if operation == "stat":
            path = command[-1]
            node = self.nodes.get(path)
            if node is None:
                return CommandResult(
                    "", f"stat: '{path}': No such file or directory\n", 1,
                )
            device, inode, kind = node
            return CommandResult(f"{device}:{inode}:{kind}\n", "", 0)
        if operation == "mv":
            source, destination = command[-2:]
            if self.rename_failure:
                raise RuntimeError("injected app-private trace rename failure")
            if destination not in self.nodes and source in self.nodes:
                self.nodes[destination] = self.nodes.pop(source)
            return CommandResult("", "", 0)
        if operation == "mkdir":
            path = command[-1]
            if self.mkdir_failure:
                raise RuntimeError("injected app-private trace mkdir failure")
            if path in self.nodes:
                raise RuntimeError("injected app-private trace mkdir collision")
            self.nodes[path] = (65082, self.next_inode, "directory")
            self.next_inode += 1
            return CommandResult("", "", 0)
        raise AssertionError(f"unexpected trace isolation command: {command!r}")


class StagingDeviceRunner(FakeRunner):
    """Stateful fake for the external ADB filesystem boundary."""

    def __init__(self, *, fail_first_read: bool = False,
                 primary_failure: str | None = None,
                 cleanup_failures: frozenset[str] = frozenset(),
                 forged_stale_companion: bool = False,
                 wrong_types: frozenset[str] = frozenset(),
                 wrong_hashes: frozenset[str] = frozenset(),
                 wrong_modes: frozenset[str] = frozenset(),
                 before_first_push=None,
                 app_parent_kind: str | None = "directory",
                 app_parent_mode: int = 0o777,
                 parent_chmod_result_mode: int = 0o771):
        super().__init__(fail_first_read=fail_first_read)
        self.shell_files: dict[str, tuple[str, bytes | str]] = {}
        self.app_files: dict[str, tuple[str, bytes | str]] = {}
        self.app_modes: dict[str, int] = {}
        self.push_source_parent_modes: list[int] = []
        self.app_parent_kind = app_parent_kind
        self.app_parent_mode = None if app_parent_kind is None else app_parent_mode
        self.parent_chmod_result_mode = parent_chmod_result_mode
        self.primary_failure = primary_failure
        self.cleanup_failures = set(cleanup_failures)
        self.primary_triggered = False
        self.forged_stale_companion = forged_stale_companion
        self.wrong_types = wrong_types
        self.wrong_hashes = wrong_hashes
        self.wrong_modes = wrong_modes
        self.before_first_push = before_first_push

    @staticmethod
    def _role(path: str) -> str:
        return "companion" if path.endswith("libshadowhook_nothing.so") else "tracer"

    @staticmethod
    def _is_app_stage(path: str) -> bool:
        return path.startswith("files/.qtrace-acceptance-")

    def _label(self, operation: str, path: str) -> str:
        role = self._role(path)
        if operation in {"stat", "hash", "mode"}:
            phase = "stage" if self._is_app_stage(path) else "final"
            return f"{operation}:{phase}:{role}"
        if operation == "rm":
            if path.startswith("/data/local/tmp/"):
                phase = "host-stage"
            elif self._is_app_stage(path):
                phase = "app-stage"
            else:
                phase = "final"
            if self.primary_triggered:
                return f"cleanup:{phase}:{role}"
            return f"remove:{phase}:{role}"
        return f"{operation}:{role}"

    def _fail_if_requested(self, label: str) -> None:
        if not self.primary_triggered and label == self.primary_failure:
            self.primary_triggered = True
            raise RuntimeError(f"injected primary failure at {label}")
        if self.primary_triggered and label in self.cleanup_failures:
            raise RuntimeError(f"injected cleanup failure at {label}")

    @staticmethod
    def _result(stdout: str = ""):
        return __import__(
            "scripts.qtrace_device_acceptance", fromlist=["CommandResult"],
        ).CommandResult(stdout, "", 0)

    def _remove(self, files: dict[str, tuple[str, bytes | str]], path: str) -> None:
        label = self._label("rm", path)
        self._fail_if_requested(label)
        files.pop(path, None)
        if files is self.app_files:
            self.app_modes.pop(path, None)

    def _read_app(self, path: str) -> bytes:
        kind, value = self.app_files[path]
        if kind == "symlink":
            kind, value = self.app_files[str(value)]
        if kind != "regular file" or not isinstance(value, bytes):
            raise RuntimeError(f"cannot read non-regular fake path {path}")
        return value

    def run(self, command, *, timeout, cwd=None, allowed=(0,)):
        command = tuple(command)
        self.commands.append(command)
        if not command or command[0] != "adb":
            self.commands.pop()
            return super().run(command, timeout=timeout, cwd=cwd, allowed=allowed)
        if command[:4] == ("adb", "-s", "SERIAL", "push"):
            if self.before_first_push is not None:
                callback, self.before_first_push = self.before_first_push, None
                callback()
            self.push_source_parent_modes.append(
                stat.S_IMODE(Path(command[4]).parent.stat().st_mode)
            )
            label = self._label("push", command[4])
            self._fail_if_requested(label)
            self.shell_files[command[5]] = ("regular file", Path(command[4]).read_bytes())
            return self._result()
        if command[:4] != ("adb", "-s", "SERIAL", "shell"):
            return self._result()
        arguments = command[4:]
        if arguments[:2] != ("run-as", "com.aprz.qbdiandroid"):
            if arguments[:2] == ("rm", "-f"):
                for path in arguments[2:]:
                    self._remove(self.shell_files, path)
            return self._result()
        operation, arguments = arguments[2], arguments[3:]
        if operation == "mkdir":
            if arguments == ("files/qbdi-traces",):
                self.trace_directory_exists = True
                return self._result()
            self._fail_if_requested("mkdir:files")
            if arguments != ("-p", "files"):
                raise RuntimeError(f"unexpected app-private mkdir arguments: {arguments}")
            if self.app_parent_kind is None:
                self.app_parent_kind = "directory"
                self.app_parent_mode = 0o777
            return self._result()
        if operation == "cp":
            source, destination = arguments
            if self.app_parent_kind != "directory":
                raise RuntimeError("app-private files parent is not a directory")
            if not self._is_app_stage(destination):
                raise RuntimeError(f"copy bypassed app-private staging: {destination}")
            label = self._label("copy", destination)
            self._fail_if_requested(label)
            data = self.shell_files[source][1]
            existing = self.app_files.get(destination)
            if existing is not None and existing[0] == "symlink":
                self.app_files[str(existing[1])] = ("regular file", data)
                self.app_modes[str(existing[1])] = 0o600
            else:
                self.app_files[destination] = ("regular file", data)
                self.app_modes[destination] = 0o600
            return self._result()
        if operation == "chmod":
            if arguments == ("771", "files"):
                self._fail_if_requested("chmod:files")
                if self.app_parent_kind != "directory":
                    raise RuntimeError("app-private files parent is not a directory")
                self.app_parent_mode = self.parent_chmod_result_mode
                return self._result()
            self._fail_if_requested("chmod")
            if (len(arguments) != 3 or arguments[0] != "700" or
                    {self._role(path) for path in arguments[1:]} !=
                    {"tracer", "companion"}):
                raise RuntimeError(f"unexpected app-private chmod arguments: {arguments}")
            for path in arguments[1:]:
                if (not self._is_app_stage(path) or path not in self.app_files or
                        self.app_files[path][0] != "regular file"):
                    raise RuntimeError(f"chmod target is not staged regular file: {path}")
                self.app_modes[path] = 0o700
            return self._result()
        if operation == "stat":
            path = arguments[-1]
            if (arguments[:-1] == ("-c", "%d:%i:%F") and
                    path.startswith("files/qbdi-traces")):
                if path == "files/qbdi-traces" and self.trace_directory_exists:
                    return self._result("65082:900:directory\n")
                return __import__(
                    "scripts.qtrace_device_acceptance", fromlist=["CommandResult"],
                ).CommandResult(
                    "", f"stat: '{path}': No such file or directory\n", 1,
                )
            if arguments[:-1] not in (("-c", "%F"), ("-c", "%a")):
                raise RuntimeError(f"unexpected app-private stat arguments: {arguments}")
            if path == "files":
                if self.app_parent_kind is None:
                    raise RuntimeError("app-private files parent is missing")
                if arguments[1] == "%F":
                    self._fail_if_requested("stat:files")
                    return self._result(self.app_parent_kind + "\n")
                self._fail_if_requested("stat-mode:files")
                return self._result(f"{self.app_parent_mode:o}\n")
            if arguments[1] == "%a":
                label = self._label("mode", path)
                mode = 0o777 if label in self.wrong_modes else self.app_modes[path]
                return self._result(f"{mode:o}\n")
            if arguments[1] != "%F":
                raise RuntimeError(f"unexpected app-private stat arguments: {arguments}")
            if self.app_parent_kind != "directory":
                raise RuntimeError("app-private files parent is not a directory")
            label = self._label("stat", path)
            self._fail_if_requested(label)
            if label in self.wrong_types:
                return self._result("symbolic link\n")
            kind = self.app_files[path][0]
            return self._result(kind + "\n")
        if operation == "sha256sum":
            path = arguments[0]
            if self.app_parent_kind != "directory":
                raise RuntimeError("app-private files parent is not a directory")
            label = self._label("hash", path)
            self._fail_if_requested(label)
            payload = b"wrong hash" if label in self.wrong_hashes else self._read_app(path)
            digest = hashlib.sha256(payload).hexdigest()
            return self._result(f"{digest}  {path}\n")
        if operation == "rm" and arguments[0] == "-f":
            if self.app_parent_kind != "directory":
                raise RuntimeError("refusing to traverse untrusted app-private parent")
            for path in arguments[1:]:
                self._remove(self.app_files, path)
            return self._result()
        if operation == "mv":
            source, destination = arguments
            role = self._role(destination)
            self._fail_if_requested(f"move:{role}")
            node = self.app_files.pop(source)
            mode = self.app_modes.pop(source)
            if role == "companion" and self.forged_stale_companion:
                node = ("regular file", b"forged stale companion")
            self.app_files[destination] = node
            self.app_modes[destination] = mode
            return self._result()
        return self._result()


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


class RecordingHeldInput:
    def __init__(self, path: Path, sha256: str, *, label: str = "held"):
        self.path = path
        self.sha256 = sha256
        self.label = label
        self.verify_calls = 0
        self.close_calls = 0
        self.close_failure: str | BaseException | None = None

    def verify_path(self):
        self.verify_calls += 1

    def close(self):
        self.close_calls += 1
        if self.close_failure is not None:
            if isinstance(self.close_failure, BaseException):
                raise self.close_failure
            raise RuntimeError(self.close_failure)


class RecordingHistoricalInput(RecordingHeldInput):
    def __init__(self, path: Path, apk_sha256: str, *, report=None):
        super().__init__(path, apk_sha256, label="historical APK")
        self.apk_sha256 = apk_sha256
        self.target_raw_sha256 = "5" * 64
        self.target_canonical_sha256 = "0" * 64
        self.report = {} if report is None else report
        manifest = self.report.get("manifest", [])
        self.archive_manifest = tuple(
            tuple(item.items()) for item in manifest if isinstance(item, dict)
        )
        self.archive_sha256 = self.report.get("archive_sha256", "")


class RecordingHeldPair:
    def __init__(self, tracer, companion):
        self.tracer = tracer
        self.companion = companion

    def verify_paths(self):
        self.tracer.verify_path()
        self.companion.verify_path()

    def close(self):
        failures = []
        for held in (self.tracer, self.companion):
            try:
                held.close()
            except BaseException as error:
                failures.append(error)
        if failures:
            raise RuntimeError("; ".join(str(error) for error in failures))


class AcceptanceHarnessTests(unittest.TestCase):
    @staticmethod
    def _recording_acceptance_inputs(root: Path):
        current = RecordingHeldInput(root / "held-current.apk", "c" * 64,
                                     label="current APK")
        tracer = RecordingHeldInput(root / "held-tracer.so", "t" * 64,
                                    label="tracer")
        companion = RecordingHeldInput(root / "held-companion.so", "p" * 64,
                                       label="companion")
        for held, payload in ((current, b"current"), (tracer, b"tracer"),
                              (companion, b"companion")):
            held.path.write_bytes(payload)
        pair = RecordingHeldPair(tracer, companion)
        return current, pair

    def _run_real_current_cleanup_recovery(self, root: Path, *, failure: str):
        from scripts import qtrace_device_acceptance as acceptance

        payload = b"production current APK recovery bytes"
        source = root / "current-source.apk"
        source.write_bytes(payload)
        snapshot_root = Path(tempfile.mkdtemp(
            prefix="qtrace-current-inputs-", dir=root,
        ))
        current = acceptance._snapshot_host_binary(
            source, snapshot_root / "current.apk", maximum_bytes=1024,
            deadline=time.monotonic() + 5.0,
        )
        tracer = RecordingHeldInput(snapshot_root / "tracer.so", "t" * 64,
                                    label="tracer")
        companion = RecordingHeldInput(snapshot_root / "companion.so", "p" * 64,
                                       label="companion")
        tracer.path.write_bytes(b"tracer")
        companion.path.write_bytes(b"companion")
        pair = RecordingHeldPair(tracer, companion)
        historical = RecordingHistoricalInput(root / "historical.apk", "h" * 64)
        historical.path.write_bytes(b"historical")
        current_installs = []
        real_close = acceptance.HostBinarySnapshot.close
        real_tree_cleanup = acceptance._current_snapshot_tree_cleanup
        close_failed = False
        tree_calls = 0

        class LifecycleRunner(FakeRunner):
            def run(self, command, *, timeout, cwd=None, allowed=(0,)):
                if tuple(command[:4]) == ("adb", "-s", "SERIAL", "install"):
                    installed = Path(command[-1])
                    if installed.read_bytes() == payload:
                        current_installs.append((installed, installed.stat().st_ino))
                return super().run(command, timeout=timeout, cwd=cwd,
                                   allowed=allowed)

        def failing_close(snapshot):
            nonlocal close_failed
            if snapshot is current and failure == "close" and not close_failed:
                close_failed = True
                real_close(snapshot)
                raise OSError("current descriptor close after tree deletion")
            return real_close(snapshot)

        def failing_tree_cleanup(snapshot):
            nonlocal tree_calls
            if snapshot is current:
                tree_calls += 1
                if failure == "tree" and tree_calls == 1:
                    snapshot.path.unlink()
                    raise OSError("partial tree cleanup removed current APK")
            return real_tree_cleanup(snapshot)

        with patch.object(acceptance, "_snapshot_current_inputs",
                          return_value=(current, pair)), \
                patch.object(acceptance, "_stage_app_private_binaries"), \
                patch.object(acceptance, "_run_current_fixture_phase"), \
                patch.object(acceptance.HostBinarySnapshot, "close", failing_close), \
                patch.object(acceptance, "_current_snapshot_tree_cleanup",
                             failing_tree_cleanup), \
                self.assertRaises(RuntimeError):
            acceptance.run_acceptance(
                "SERIAL", root, runner=LifecycleRunner(),
                historical_builder=lambda *_args, **_kwargs: historical,
            )
        return current_installs, tree_calls

    def _run_real_recovery_disposal_failure(self, root: Path, *, failure: str):
        from scripts import qtrace_device_acceptance as acceptance

        source = root / "disposal-current-source.apk"
        source.write_bytes(b"disposal current APK")
        snapshot_root = Path(tempfile.mkdtemp(
            prefix="qtrace-current-inputs-", dir=root,
        ))
        current = acceptance._snapshot_host_binary(
            source, snapshot_root / "current.apk", maximum_bytes=1024,
            deadline=time.monotonic() + 5.0,
        )
        tracer = RecordingHeldInput(snapshot_root / "tracer.so", "t" * 64,
                                    label="tracer")
        companion = RecordingHeldInput(snapshot_root / "companion.so", "p" * 64,
                                       label="companion")
        tracer.path.write_bytes(b"tracer")
        companion.path.write_bytes(b"companion")
        pair = RecordingHeldPair(tracer, companion)
        historical = RecordingHistoricalInput(root / "historical.apk", "h" * 64)
        historical.path.write_bytes(b"historical")
        unrelated_path = root / "unrelated-open-fd"
        unrelated_path.write_bytes(b"unrelated")
        real_os_close = acceptance.os.close
        real_recovery_tree_cleanup = acceptance._recovery_snapshot_tree_cleanup
        unrelated_descriptors = []
        recovery_tree_calls = 0
        installs = []

        class LifecycleRunner(FakeRunner):
            def run(self, command, *, timeout, cwd=None, allowed=(0,)):
                if tuple(command[:4]) == ("adb", "-s", "SERIAL", "install"):
                    installs.append(Path(command[-1]))
                return super().run(command, timeout=timeout, cwd=cwd,
                                   allowed=allowed)

        def failing_os_close(descriptor):
            try:
                held_path = Path(os.readlink(f"/proc/self/fd/{descriptor}"))
            except OSError:
                held_path = Path()
            if (failure == "close" and not unrelated_descriptors and
                    held_path.parent.name.startswith("qtrace-current-recovery-")):
                real_os_close(descriptor)
                reused = os.open(unrelated_path, os.O_RDWR)
                if reused != descriptor:
                    os.dup2(reused, descriptor)
                    real_os_close(reused)
                unrelated_descriptors.append(descriptor)
                raise OSError("recovery snapshot close after descriptor disposal")
            return real_os_close(descriptor)

        def failing_recovery_tree_cleanup(recovery):
            nonlocal recovery_tree_calls
            recovery_tree_calls += 1
            if failure == "tree" and recovery_tree_calls == 1:
                recovery.path.unlink()
                raise OSError("partial recovery tree cleanup removed APK")
            if failure == "tree" and recovery_tree_calls == 2:
                real_recovery_tree_cleanup(recovery)
                raise OSError("recovery tree cleanup retry diagnostic")
            return real_recovery_tree_cleanup(recovery)

        runner = LifecycleRunner()
        with patch.object(acceptance, "_snapshot_current_inputs",
                          return_value=(current, pair)), \
                patch.object(acceptance, "_stage_app_private_binaries"), \
                patch.object(acceptance, "_run_current_fixture_phase"), \
                patch.object(acceptance.os, "close", failing_os_close), \
                patch.object(acceptance, "_recovery_snapshot_tree_cleanup",
                             failing_recovery_tree_cleanup), \
                self.assertRaises(RuntimeError):
            acceptance.run_acceptance(
                "SERIAL", root, runner=runner,
                historical_builder=lambda *_args, **_kwargs: historical,
            )
        report = json.loads(
            (root / "historical-benchmark-gate.json").read_text(encoding="utf-8")
        )
        force_stops = [
            command for command in runner.commands
            if command[4:7] == ("am", "force-stop", acceptance.PACKAGE)
        ]
        unrelated_descriptor = (
            unrelated_descriptors[0] if unrelated_descriptors else None
        )
        return installs, force_stops, recovery_tree_calls, report, unrelated_descriptor

    def test_direct_acceptance_script_loads_repo_packages_without_pythonpath(self):
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)

        completed = subprocess.run(
            [sys.executable, "scripts/qtrace_device_acceptance.py", "--help"],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10.0,
            check=False,
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn("--device DEVICE", completed.stdout)

    def test_demo_trace_isolation_records_absence_without_renaming(self):
        from scripts import qtrace_device_acceptance as acceptance

        self.assertTrue(hasattr(acceptance, "_isolate_demo_trace_directory"))
        runner = TraceIsolationRunner()

        result = acceptance._isolate_demo_trace_directory(
            "SERIAL", runner, token="a" * 32,
        )

        self.assertFalse(result.existed)
        self.assertIsNone(result.backup_path)
        self.assertIn("files/qbdi-traces", runner.nodes)
        self.assertEqual((65082, 900, "directory"), runner.nodes["files/qbdi-traces"])
        self.assertFalse(any(command[0][6] == "mv" for command in runner.commands))

    def test_demo_trace_isolation_atomically_renames_only_the_fixed_directory(self):
        from scripts import qtrace_device_acceptance as acceptance

        self.assertTrue(hasattr(acceptance, "_isolate_demo_trace_directory"))
        source = "files/qbdi-traces"
        backup = f"{source}.pre-acceptance-{'b' * 32}"
        original = (65082, 153076, "directory")
        runner = TraceIsolationRunner({source: original})

        result = acceptance._isolate_demo_trace_directory(
            "SERIAL", runner, token="b" * 32,
        )

        self.assertTrue(result.existed)
        self.assertEqual(backup, result.backup_path)
        self.assertIn(source, runner.nodes)
        self.assertEqual((65082, 900, "directory"), runner.nodes[source])
        self.assertEqual(original, runner.nodes[backup])
        self.assertEqual([
            (("adb", "-s", "SERIAL", "shell", "run-as", acceptance.PACKAGE,
              "stat", "-c", "%d:%i:%F", source), (0, 1)),
            (("adb", "-s", "SERIAL", "shell", "run-as", acceptance.PACKAGE,
              "stat", "-c", "%d:%i:%F", backup), (0, 1)),
            (("adb", "-s", "SERIAL", "shell", "run-as", acceptance.PACKAGE,
              "mv", "-n", source, backup), (0,)),
            (("adb", "-s", "SERIAL", "shell", "run-as", acceptance.PACKAGE,
              "stat", "-c", "%d:%i:%F", source), (0, 1)),
            (("adb", "-s", "SERIAL", "shell", "run-as", acceptance.PACKAGE,
              "stat", "-c", "%d:%i:%F", backup), (0, 1)),
            (("adb", "-s", "SERIAL", "shell", "run-as", acceptance.PACKAGE,
              "mkdir", source), (0,)),
            (("adb", "-s", "SERIAL", "shell", "run-as", acceptance.PACKAGE,
              "stat", "-c", "%d:%i:%F", source), (0, 1)),
        ], runner.commands)

    def test_repeated_demo_trace_isolation_retains_each_unique_backup(self):
        from scripts import qtrace_device_acceptance as acceptance

        self.assertTrue(hasattr(acceptance, "_isolate_demo_trace_directory"))
        source = "files/qbdi-traces"
        first = (65082, 101, "directory")
        second = (65082, 202, "directory")
        runner = TraceIsolationRunner({source: first})

        initial = acceptance._isolate_demo_trace_directory(
            "SERIAL", runner, token="c" * 32,
        )
        runner.nodes[source] = second
        repeated = acceptance._isolate_demo_trace_directory(
            "SERIAL", runner, token="d" * 32,
        )

        self.assertEqual(first, runner.nodes[initial.backup_path])
        self.assertEqual(second, runner.nodes[repeated.backup_path])
        self.assertNotEqual(initial.backup_path, repeated.backup_path)
        self.assertIn(source, runner.nodes)
        self.assertEqual((65082, 901, "directory"), runner.nodes[source])

    def test_demo_trace_isolation_rejects_a_symlink_without_renaming(self):
        from scripts import qtrace_device_acceptance as acceptance

        self.assertTrue(hasattr(acceptance, "_isolate_demo_trace_directory"))
        source = "files/qbdi-traces"
        runner = TraceIsolationRunner({source: (65082, 303, "symbolic link")})

        with self.assertRaisesRegex(RuntimeError, "not a directory"):
            acceptance._isolate_demo_trace_directory(
                "SERIAL", runner, token="e" * 32,
            )

        self.assertIn(source, runner.nodes)
        self.assertFalse(any(command[0][6] == "mv" for command in runner.commands))

    def test_demo_trace_isolation_fails_closed_on_backup_collision(self):
        from scripts import qtrace_device_acceptance as acceptance

        self.assertTrue(hasattr(acceptance, "_isolate_demo_trace_directory"))
        source = "files/qbdi-traces"
        backup = f"{source}.pre-acceptance-{'f' * 32}"
        runner = TraceIsolationRunner({
            source: (65082, 404, "directory"),
            backup: (65082, 405, "directory"),
        })

        with self.assertRaisesRegex(RuntimeError, "backup path already exists"):
            acceptance._isolate_demo_trace_directory(
                "SERIAL", runner, token="f" * 32,
            )

        self.assertIn(source, runner.nodes)
        self.assertFalse(any(command[0][6] == "mv" for command in runner.commands))

    def test_demo_trace_isolation_rename_failure_retains_the_source(self):
        from scripts import qtrace_device_acceptance as acceptance

        self.assertTrue(hasattr(acceptance, "_isolate_demo_trace_directory"))
        source = "files/qbdi-traces"
        runner = TraceIsolationRunner(
            {source: (65082, 505, "directory")}, rename_failure=True,
        )

        with self.assertRaisesRegex(RuntimeError, "injected app-private trace rename"):
            acceptance._isolate_demo_trace_directory(
                "SERIAL", runner, token="1" * 32,
            )

        self.assertEqual((65082, 505, "directory"), runner.nodes[source])

    def test_demo_trace_isolation_mkdir_failure_retains_the_recoverable_backup(self):
        from scripts import qtrace_device_acceptance as acceptance

        source = "files/qbdi-traces"
        backup = f"{source}.pre-acceptance-{'2' * 32}"
        original = (65082, 606, "directory")
        runner = TraceIsolationRunner(
            {source: original}, mkdir_failure=True,
        )

        with self.assertRaisesRegex(RuntimeError, "injected app-private trace mkdir"):
            acceptance._isolate_demo_trace_directory(
                "SERIAL", runner, token="2" * 32,
            )

        self.assertNotIn(source, runner.nodes)
        self.assertEqual(original, runner.nodes[backup])

    def test_gate_evidence_records_recoverable_demo_trace_backup(self):
        from scripts import qtrace_device_acceptance as acceptance

        state = acceptance._HistoricalGateState(phase="current-fixtures")
        state.trace_backup_path = (
            "files/qbdi-traces.pre-acceptance-1234567890abcdef1234567890abcdef"
        )
        state.trace_backup_existed = True

        evidence = acceptance._gate_evidence(
            state, RuntimeError("fixture failure"), [],
        )

        self.assertEqual(state.trace_backup_path, evidence["trace_backup_path"])
        self.assertIs(True, evidence["trace_backup_existed"])

    def test_timed_entry_evidence_requires_running_native_snapshot_before_entry(self):
        from scripts.qtrace_device_acceptance import _validate_timed_fixture_receipt

        report = {
            "session_id": SESSION,
            "package": "com.aprz.qbdiandroid",
            "pid": 4242,
            "timeline": [{"stage": "installing_hooks", "cleanup_detached": True,
                          "action_nonce": "123e4567-e89b-42d3-a456-426614174000"}],
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
            "entry-after-deadline": json.dumps({**entry, "deadlineMonotonicNs": 100}),
            "wrong-package": json.dumps({**entry, "packageName": "com.other.app"}),
        }
        for name, raw in invalid.items():
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                _validate_timed_fixture_receipt(report, json.dumps(receipt), raw)

        for name, changed_report in {
            "wrong-action-nonce": {
                **report,
                "timeline": [{"stage": "installing_hooks", "cleanup_detached": True,
                              "action_nonce": "223e4567-e89b-42d3-a456-426614174001"}],
            },
            "wrong-report-package": {**report, "package": "com.other.app"},
        }.items():
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                _validate_timed_fixture_receipt(
                    changed_report, json.dumps(receipt), json.dumps(entry),
                )

    def test_timed_entry_evidence_polls_past_stale_receipt_from_prior_action(self):
        from scripts.qtrace_device_acceptance import _wait_for_timed_fixture_evidence

        expected_nonce = "123e4567-e89b-42d3-a456-426614174000"
        report = {
            "session_id": SESSION,
            "package": "com.aprz.qbdiandroid",
            "pid": 4242,
            "timeline": [{"stage": "installing_hooks", "cleanup_detached": True,
                          "action_nonce": expected_nonce}],
            "native": {"status": status("sealed")},
        }

        class DelayedRunner:
            def __init__(self):
                self.receipt_reads = 0

            def read_text(self, path, *, timeout):
                self.assert_positive(timeout)
                if path.name == "qtrace-acceptance-receipt.json":
                    self.receipt_reads += 1
                    nonce = ("223e4567-e89b-42d3-a456-426614174001"
                             if self.receipt_reads == 1 else expected_nonce)
                    return json.dumps({
                        "sessionId": SESSION, "nonce": nonce,
                        "entryMonotonicNs": 101,
                    })
                return json.dumps(status("running"))

            @staticmethod
            def assert_positive(timeout):
                if timeout <= 0:
                    raise AssertionError("poll read received an expired timeout")

        runner = DelayedRunner()
        receipt, entry = _wait_for_timed_fixture_evidence(
            runner, report, timeout=1.0,
        )

        self.assertEqual(2, runner.receipt_reads)
        self.assertEqual(expected_nonce, json.loads(receipt)["nonce"])
        self.assertEqual("running", json.loads(entry)["state"])

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

        report = {"session_id": SESSION, "artifacts": [{
            "remote_name": "fixture.trace.bin",
            "local_path": "artifacts/fixture.trace.bin",
            "termination": "stopped",
            "metrics_schema": 3,
            "native_stop_acknowledged": True,
        }, {"remote_name": "fixture.trace.bin.metrics", "decoder": "sidecar"}]}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = root / SESSION / "artifacts"
            artifacts.mkdir(parents=True)
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
            "session_id": SESSION,
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
            artifacts = root / SESSION / "artifacts"
            artifacts.mkdir(parents=True)
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

        report = {"session_id": SESSION, "artifacts": [{
            "remote_name": "fixture.trace.bin",
            "local_path": "artifacts/fixture.trace.bin",
            "termination": "stopped",
            "metrics_schema": 3,
            "native_stop_acknowledged": True,
        }, {"remote_name": "fixture.trace.bin.metrics", "decoder": "sidecar"}]}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = root / SESSION / "artifacts"
            artifacts.mkdir(parents=True)
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

        report = {"session_id": SESSION, "artifacts": [{
            "remote_name": "fixture.trace.bin.lz4",
            "local_path": "artifacts/fixture.trace.bin.lz4",
        }]}

        class Client:
            def read_file(self, _name, *, maximum_bytes):
                self.maximum_bytes = maximum_bytes
                return b"metrics"

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = root / SESSION / "artifacts"
            artifacts.mkdir(parents=True)
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

    def test_held_root_reader_kills_and_reaps_a_truly_blocking_read_worker(self):
        from scripts.qtrace_device_acceptance import RootedReader

        blocked_read, blocked_write = os.pipe()
        pid_read, pid_write = os.pipe()
        child_pid = None
        try:
            def blocking_read(_descriptor, _size):
                os.write(pid_write, str(os.getpid()).encode("ascii"))
                return os.read(blocked_read, 1)

            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "artifact").write_bytes(b"fixture")
                started = time.monotonic()
                with RootedReader(root, _read_hook=blocking_read) as held, \
                        self.assertRaisesRegex(RuntimeError, "exceeded deadline"):
                    held.read_bytes("artifact", deadline=started + 0.1)
                self.assertLess(time.monotonic() - started, 1.0)

            child_pid = int(os.read(pid_read, 64).decode("ascii"))
            with self.assertRaises(ChildProcessError):
                os.waitpid(child_pid, os.WNOHANG)
            child_pid = None

        finally:
            if child_pid is not None:
                try:
                    os.kill(child_pid, 9)
                except ProcessLookupError:
                    pass
                try:
                    cleanup_deadline = time.monotonic() + 1.0
                    while time.monotonic() < cleanup_deadline:
                        finished, _status = os.waitpid(child_pid, os.WNOHANG)
                        if finished == child_pid:
                            break
                        time.sleep(0.01)
                except ChildProcessError:
                    pass
            for descriptor in (blocked_read, blocked_write, pid_read, pid_write):
                os.close(descriptor)

    def test_worker_cleanup_reports_unreaped_pid_without_blocking_past_deadline(self):
        import scripts.qtrace_device_acceptance as acceptance

        now = [100.0]
        wait_options = []

        def monotonic():
            return now[0]

        def pause(seconds):
            now[0] += seconds

        def never_reaped(_pid, options):
            wait_options.append(options)
            if len(wait_options) % 2 == 0:
                raise InterruptedError("injected signal interruption")
            return 0, 0

        started = time.monotonic()
        with patch.object(acceptance.os, "kill"), \
                patch.object(acceptance.os, "waitpid", side_effect=never_reaped), \
                patch.object(acceptance.time, "monotonic", side_effect=monotonic), \
                patch.object(acceptance.time, "sleep", side_effect=pause), \
                self.assertRaisesRegex(
                    RuntimeError,
                    r"worker PID 4242.*cleanup deadline 100\.050000.*unreaped",
                ):
            acceptance._kill_and_reap(4242)

        self.assertLess(time.monotonic() - started, 0.5)
        self.assertTrue(wait_options)
        self.assertEqual({os.WNOHANG}, set(wait_options))

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
                root = Path(temporary)
                current, pair = self._recording_acceptance_inputs(root)
                historical = RecordingHistoricalInput(root / "historical.apk", "h" * 64)
                historical.path.write_bytes(b"historical")
                before = descriptor_count()
                with patch("scripts.qtrace_device_acceptance._snapshot_current_inputs",
                           return_value=(current, pair)), \
                        patch("scripts.qtrace_device_acceptance._install_held_apk"), \
                        patch("scripts.qtrace_device_acceptance._stage_app_private_binaries"), \
                        self.assertRaises(RuntimeError):
                    run_acceptance(
                        "SERIAL", root, runner=FailureRunner(failure),
                        historical_builder=lambda *_args, **_kwargs: historical,
                    )
                self.assertEqual(before, descriptor_count())

    def test_requires_an_explicit_device(self):
        from scripts.qtrace_device_acceptance import main

        self.assertEqual(2, main([]))

    def test_failure_retains_generated_evidence_after_main_returns(self):
        from scripts.qtrace_device_acceptance import main

        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            captured: dict[str, object] = {}
            real_mkdtemp = tempfile.mkdtemp

            def tracked_mkdtemp(*args, **kwargs):
                captured.update(kwargs)
                return real_mkdtemp(*args, **kwargs)

            with patch("scripts.qtrace_device_acceptance.Path.cwd", return_value=workspace), \
                    patch("scripts.qtrace_device_acceptance.tempfile.mkdtemp",
                          side_effect=tracked_mkdtemp), \
                    patch("scripts.qtrace_device_acceptance._head_commit",
                          return_value="a" * 40), \
                    patch("scripts.qtrace_device_acceptance.run_acceptance",
                          side_effect=RuntimeError("fixture failure")):
                self.assertEqual(1, main(["--device", "SERIAL"]))
            retained = list((workspace / "qtrace-acceptance-failures").iterdir())
            self.assertEqual(1, len(retained))
            self.assertTrue(retained[0].is_dir())
            self.assertEqual(workspace / "qtrace-acceptance-failures", captured["dir"])

    @staticmethod
    def _successful_gate_document() -> dict[str, object]:
        reports = {
            "timed-offset": f"offset/{SESSION}/report.json",
            "timed-symbol": f"symbol/{SESSION}/report.json",
            "pull-latest": f"latest/{SESSION}/report.json",
            "pull-name": f"name/{SESSION}/report.json",
            "pull-all": f"all/{SESSION}/report.json",
            "pull-compressed": f"compressed/{SESSION}/report.json",
            "monitor-exit": f"exit/{SESSION}/report.json",
            "flight-crash": f"crash/{SESSION}/report.json",
        }
        return {
            "schema": 1,
            "status": "passed",
            "exit_code": 0,
            "head_commit": "a" * 40,
            "device": "SERIAL",
            "started_at": "2026-08-29T01:00:00.000Z",
            "completed_at": "2026-08-29T01:05:00.000Z",
            "historical_commit": "2d6b1022a14ae554804a57e267544c12dea29353",
            "target_canonical_sha256": "0d8e856c819fb3cd7ae5917053172b4b75a7924784c43e09cb2855a298647169",
            "target_raw_sha256": "b" * 64,
            "historical_apk_sha256": "d" * 64,
            "current_apk_sha256": "a" * 64,
            "tracer_sha256": "e" * 64,
            "companion_sha256": "f" * 64,
            "scenario_reports": reports,
            "trace_backup_path": "files/qbdi-traces.pre-acceptance-" + "f" * 32,
            "trace_backup_existed": True,
        }

    def test_success_retains_manifest_and_prints_absolute_evidence_path(self):
        from scripts.qtrace_device_acceptance import main

        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            document = self._successful_gate_document()

            def succeed(_device, directory, *, success_evidence, **_kwargs):
                for relative in document["scenario_reports"].values():
                    report = directory / relative
                    report.parent.mkdir(parents=True, exist_ok=True)
                    report.write_text("{}", encoding="utf-8")
                success_evidence.update(document)
                return 0

            output = io.StringIO()
            with patch("scripts.qtrace_device_acceptance.Path.cwd", return_value=workspace), \
                    patch("scripts.qtrace_device_acceptance._head_commit",
                          return_value="a" * 40), \
                    patch("scripts.qtrace_device_acceptance.run_acceptance",
                          side_effect=succeed), \
                    contextlib.redirect_stdout(output):
                self.assertEqual(0, main(["--device", "SERIAL"]))

            retained = list((workspace / "qtrace-acceptance-evidence").iterdir())
            self.assertEqual(1, len(retained))
            self.assertRegex(retained[0].name, r"[0-9a-f-]{36}\Z")
            manifest = retained[0] / "historical-benchmark-gate.success.json"
            self.assertEqual(document, json.loads(manifest.read_text(encoding="utf-8")))
            self.assertEqual(
                f"qtrace acceptance passed; evidence remains at: {retained[0].resolve()}",
                output.getvalue().strip(),
            )
            self.assertEqual([], list((workspace / "qtrace-acceptance-failures").iterdir()))

    def test_success_publish_collision_keeps_both_directories(self):
        from scripts.qtrace_device_acceptance import _publish_success_directory

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            failures, evidence = root / "qtrace-acceptance-failures", root / "qtrace-acceptance-evidence"
            failures.mkdir(mode=0o700)
            evidence.mkdir(mode=0o700)
            scratch = Path(tempfile.mkdtemp(prefix=".qtrace-device-acceptance-", dir=failures))
            (scratch / "scratch").write_text("held", encoding="utf-8")
            collision = evidence / SESSION
            collision.mkdir()
            (collision / "owner").write_text("other", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "already exists"):
                _publish_success_directory(scratch, evidence, token=SESSION)
            self.assertEqual("held", (scratch / "scratch").read_text(encoding="utf-8"))
            self.assertEqual("other", (collision / "owner").read_text(encoding="utf-8"))

    def test_success_publish_rename_failure_keeps_scratch(self):
        from scripts import qtrace_device_acceptance as acceptance

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            failures = root / "qtrace-acceptance-failures"
            failures.mkdir(mode=0o700)
            scratch = Path(tempfile.mkdtemp(prefix=".qtrace-device-acceptance-", dir=failures))
            evidence = root / "qtrace-acceptance-evidence"

            with patch.object(acceptance, "_rename_evidence_noreplace",
                              side_effect=OSError("rename failure")), \
                    self.assertRaisesRegex(OSError, "rename failure"):
                acceptance._publish_success_directory(scratch, evidence, token=SESSION)
            self.assertTrue(scratch.is_dir())
            self.assertFalse((evidence / SESSION).exists())

    def test_success_publish_rejects_scratch_identity_swap_before_rename(self):
        from scripts import qtrace_device_acceptance as acceptance

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            failures = root / "qtrace-acceptance-failures"
            failures.mkdir(mode=0o700)
            scratch = Path(tempfile.mkdtemp(prefix=".qtrace-device-acceptance-", dir=failures))
            (scratch / "owner").write_text("gate", encoding="utf-8")
            evidence = root / "qtrace-acceptance-evidence"
            original = failures / "held-original"
            real_rename = acceptance._rename_evidence_noreplace

            def swap_then_rename(source_parent, source, destination_parent, destination):
                scratch.rename(original)
                scratch.mkdir(mode=0o700)
                (scratch / "owner").write_text("attacker", encoding="utf-8")
                real_rename(source_parent, source, destination_parent, destination)

            with patch.object(acceptance, "_rename_evidence_noreplace",
                              side_effect=swap_then_rename), \
                    self.assertRaisesRegex(RuntimeError, "identity changed") as caught:
                acceptance._publish_success_directory(scratch, evidence, token=SESSION)
            self.assertEqual(evidence / SESSION, caught.exception.retained_path)
            self.assertEqual("gate", (original / "owner").read_text(encoding="utf-8"))
            self.assertEqual(
                "attacker",
                (evidence / SESSION / "owner").read_text(encoding="utf-8"),
            )

    def test_success_publish_fsync_failure_exposes_retained_destination(self):
        from scripts import qtrace_device_acceptance as acceptance

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            failures = root / "qtrace-acceptance-failures"
            failures.mkdir(mode=0o700)
            scratch = Path(tempfile.mkdtemp(prefix=".qtrace-device-acceptance-", dir=failures))
            evidence = root / "qtrace-acceptance-evidence"

            with patch.object(acceptance, "_fsync_directory",
                              side_effect=OSError("directory fsync failure")), \
                    self.assertRaisesRegex(RuntimeError, "directory fsync failure") as caught:
                acceptance._publish_success_directory(scratch, evidence, token=SESSION)
            destination = evidence / SESSION
            self.assertEqual(destination, caught.exception.retained_path)
            self.assertTrue(destination.is_dir())
            self.assertFalse(scratch.exists())

    def test_success_manifest_failure_is_retained_as_gate_failure(self):
        from scripts import qtrace_device_acceptance as acceptance

        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            document = self._successful_gate_document()

            def succeed(_device, directory, *, success_evidence, **_kwargs):
                (directory / "run.marker").write_text("retained", encoding="utf-8")
                success_evidence.update(document)
                return 0

            with patch.object(acceptance.Path, "cwd", return_value=workspace), \
                    patch.object(acceptance, "_head_commit", return_value="a" * 40), \
                    patch.object(acceptance, "run_acceptance", side_effect=succeed), \
                    patch.object(acceptance, "_write_success_manifest",
                                 side_effect=OSError("manifest failure")):
                self.assertEqual(1, acceptance.main(["--device", "SERIAL"]))
            retained = list((workspace / "qtrace-acceptance-failures").iterdir())
            self.assertEqual(1, len(retained))
            self.assertEqual("retained", (retained[0] / "run.marker").read_text(encoding="utf-8"))
            self.assertFalse((workspace / "qtrace-acceptance-evidence").exists())

    def test_success_publication_occurs_only_after_gate_cleanup_returns(self):
        from scripts import qtrace_device_acceptance as acceptance

        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            events: list[str] = []
            document = self._successful_gate_document()

            def succeed(_device, _directory, *, success_evidence, **_kwargs):
                events.append("gate-cleanup-complete")
                success_evidence.update(document)
                return 0

            def manifest(*_args, **_kwargs):
                events.append("manifest")

            def publish(_scratch, parent, *, token):
                events.append("publish")
                return parent / token

            with patch.object(acceptance.Path, "cwd", return_value=workspace), \
                    patch.object(acceptance, "_head_commit", return_value="a" * 40), \
                    patch.object(acceptance, "run_acceptance", side_effect=succeed), \
                    patch.object(acceptance, "_write_success_manifest",
                                 side_effect=manifest), \
                    patch.object(acceptance, "_publish_success_directory",
                                 side_effect=publish):
                self.assertEqual(0, acceptance.main(["--device", "SERIAL"]))
            self.assertEqual(["gate-cleanup-complete", "manifest", "publish"], events)

    def test_failure_preservation_reports_post_rename_retained_path(self):
        from scripts import qtrace_device_acceptance as acceptance

        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            success_path = workspace / "qtrace-acceptance-evidence" / SESSION
            failure_path = workspace / "qtrace-acceptance-failures" / SESSION

            def succeed(_device, _directory, *, success_evidence, **_kwargs):
                success_evidence.update(self._successful_gate_document())
                return 0

            calls = 0

            def publish(source, parent, *, token):
                nonlocal calls
                calls += 1
                destination = success_path if calls == 1 else failure_path
                destination.parent.mkdir(mode=0o700, exist_ok=True)
                source.rename(destination)
                raise acceptance._SuccessPublicationError(
                    "directory fsync failure", destination,
                )

            errors = io.StringIO()
            with patch.object(acceptance.Path, "cwd", return_value=workspace), \
                    patch.object(acceptance, "_head_commit", return_value="a" * 40), \
                    patch.object(acceptance, "run_acceptance", side_effect=succeed), \
                    patch.object(acceptance, "_write_success_manifest"), \
                    patch.object(acceptance, "_publish_success_directory",
                                 side_effect=publish), \
                    contextlib.redirect_stderr(errors):
                self.assertEqual(1, acceptance.main(["--device", "SERIAL"]))
            self.assertEqual(2, calls)
            self.assertTrue(failure_path.is_dir())
            self.assertFalse(success_path.exists())
            self.assertIn(str(failure_path), errors.getvalue())

    def test_host_binary_snapshot_is_bounded_nofollow_and_path_swap_safe(self):
        from scripts.qtrace_device_acceptance import _snapshot_host_binary

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.so"
            source.write_bytes(b"fresh tracer")
            snapshot = _snapshot_host_binary(
                source, root / "snapshot.so",
                maximum_bytes=64, deadline=time.monotonic() + 1.0,
            )
            try:
                source.unlink()
                source.write_bytes(b"attacker replacement")
                snapshot.verify_path()
                self.assertEqual(
                    "7c510872935123c9b6c917085d182b7dd57e7a5ba2cfe64ee273d475ee980925",
                    snapshot.sha256,
                )
                self.assertEqual(b"fresh tracer", snapshot.path.read_bytes())
            finally:
                snapshot.close()

            directory = root / "directory"
            directory.mkdir()
            symlink = root / "symlink.so"
            symlink.symlink_to(source)
            fifo = root / "fifo.so"
            os.mkfifo(fifo)
            empty = root / "empty.so"
            empty.touch()
            oversized = root / "oversized.so"
            oversized.write_bytes(b"12345")
            for name, candidate in (
                ("directory", directory),
                ("symlink", symlink),
                ("fifo", fifo),
                ("device", Path("/dev/null")),
                ("empty", empty),
                ("oversized", oversized),
            ):
                with self.subTest(case=name), self.assertRaisesRegex(
                    RuntimeError, "bounded regular file",
                ):
                    _snapshot_host_binary(
                        candidate, root / f"rejected-{name}.so",
                        maximum_bytes=4, deadline=time.monotonic() + 0.2,
                    )

            growing = root / "growing.so"
            growing.write_bytes(b"grow")

            def growing_read(descriptor, size):
                block = os.read(descriptor, size)
                return b"x" if not block else block

            with self.assertRaisesRegex(RuntimeError, "changed while being read"):
                _snapshot_host_binary(
                    growing, root / "growing-snapshot.so",
                    maximum_bytes=64, deadline=time.monotonic() + 1.0,
                    _read_hook=growing_read,
                )

    def test_host_binary_snapshot_kills_and_reaps_a_blocking_worker(self):
        from scripts.qtrace_device_acceptance import _snapshot_host_binary

        blocked_read, blocked_write = os.pipe()
        pid_read, pid_write = os.pipe()
        child_pid = None
        try:
            def blocking_read(_descriptor, _size):
                os.write(pid_write, str(os.getpid()).encode("ascii"))
                return os.read(blocked_read, 1)

            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / "source.so"
                source.write_bytes(b"fixture")
                started = time.monotonic()
                with self.assertRaisesRegex(RuntimeError, "exceeded deadline"):
                    _snapshot_host_binary(
                        source, root / "snapshot.so",
                        maximum_bytes=64, deadline=started + 0.1,
                        _read_hook=blocking_read,
                    )
                self.assertLess(time.monotonic() - started, 1.0)

            child_pid = int(os.read(pid_read, 64).decode("ascii"))
            with self.assertRaises(ChildProcessError):
                os.waitpid(child_pid, os.WNOHANG)
            child_pid = None

            def blocking_open(_path, _flags):
                os.write(pid_write, str(os.getpid()).encode("ascii"))
                os.read(blocked_read, 1)
                raise AssertionError("blocking open unexpectedly resumed")

            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / "source.so"
                source.write_bytes(b"fixture")
                started = time.monotonic()
                with self.assertRaisesRegex(RuntimeError, "exceeded deadline"):
                    _snapshot_host_binary(
                        source, root / "snapshot.so",
                        maximum_bytes=64, deadline=started + 0.1,
                        _open_hook=blocking_open,
                    )
                self.assertLess(time.monotonic() - started, 1.0)

            child_pid = int(os.read(pid_read, 64).decode("ascii"))
            with self.assertRaises(ChildProcessError):
                os.waitpid(child_pid, os.WNOHANG)
            child_pid = None
        finally:
            if child_pid is not None:
                try:
                    os.kill(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(child_pid, 0)
                except ChildProcessError:
                    pass
            for descriptor in (blocked_read, blocked_write, pid_read, pid_write):
                os.close(descriptor)

    def test_host_binary_snapshot_rejects_completion_at_or_after_work_deadline(self):
        from scripts.qtrace_device_acceptance import _snapshot_host_binary

        for observed_at in (1000.95, 1000.950001):
            with self.subTest(observed_at=observed_at), \
                    tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / "source.so"
                snapshot_path = root / "snapshot.so"
                source.write_bytes(b"fixture")
                clock = [1000.0]
                reaped_pids = []
                real_waitpid = os.waitpid

                def observe_completed_worker(pid, _options):
                    finished, status = real_waitpid(pid, 0)
                    reaped_pids.append(pid)
                    clock[0] = observed_at
                    return finished, status

                result = None
                caught = None
                with patch(
                    "scripts.qtrace_device_acceptance.time.monotonic",
                    side_effect=lambda: clock[0],
                ), patch(
                    "scripts.qtrace_device_acceptance.os.waitpid",
                    side_effect=observe_completed_worker,
                ):
                    try:
                        result = _snapshot_host_binary(
                            source, snapshot_path,
                            maximum_bytes=64, deadline=1001.0,
                        )
                    except RuntimeError as error:
                        caught = error
                if result is not None:
                    result.close()

                self.assertIsNotNone(caught)
                self.assertRegex(str(caught), "exceeded deadline")
                self.assertFalse(snapshot_path.exists())
                self.assertEqual(1, len(reaped_pids))
                with self.assertRaises(ChildProcessError):
                    real_waitpid(reaped_pids[0], os.WNOHANG)

    def test_host_binary_snapshot_preserves_primary_and_all_cleanup_failures(self):
        from scripts.qtrace_device_acceptance import _snapshot_host_binary

        blocked_read, blocked_write = os.pipe()
        parent_pid = os.getpid()
        cleanup_started = [False]
        failed_close = [False]
        pipe_descriptors = []
        destination_descriptors = []
        tracked_descriptors = set()
        real_close = os.close
        real_open = os.open
        real_pipe2 = os.pipe2
        real_waitpid = os.waitpid

        def blocking_read(_descriptor, _size):
            return os.read(blocked_read, 1)

        def record_open(path, flags, mode=0o777, *, dir_fd=None):
            descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
            if flags & os.O_CREAT:
                destination_descriptors.append(descriptor)
                tracked_descriptors.add(descriptor)
            return descriptor

        def record_pipe(flags):
            descriptors = real_pipe2(flags)
            pipe_descriptors.extend(descriptors)
            tracked_descriptors.update(descriptors)
            return descriptors

        def reap_then_fail(pid, *, cleanup_deadline):
            os.kill(pid, signal.SIGKILL)
            real_waitpid(pid, 0)
            cleanup_started[0] = True
            raise RuntimeError("kill cleanup exploded")

        def fail_first_cleanup_close(descriptor):
            if (os.getpid() == parent_pid and cleanup_started[0] and
                    pipe_descriptors and descriptor == pipe_descriptors[0] and
                    not failed_close[0]):
                failed_close[0] = True
                raise OSError("close cleanup exploded")
            real_close(descriptor)
            tracked_descriptors.discard(descriptor)

        try:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / "source.so"
                snapshot_path = root / "snapshot.so"
                source.write_bytes(b"fixture")
                with patch(
                    "scripts.qtrace_device_acceptance.os.open",
                    side_effect=record_open,
                ), patch(
                    "scripts.qtrace_device_acceptance.os.pipe2",
                    side_effect=record_pipe,
                ), patch(
                    "scripts.qtrace_device_acceptance.os.close",
                    side_effect=fail_first_cleanup_close,
                ), patch(
                    "scripts.qtrace_device_acceptance._kill_and_reap",
                    side_effect=reap_then_fail,
                ), self.assertRaises(RuntimeError) as caught:
                    _snapshot_host_binary(
                        source, snapshot_path,
                        maximum_bytes=64, deadline=time.monotonic() + 0.1,
                        _read_hook=blocking_read,
                    )

                diagnostics = str(caught.exception)
                self.assertIn("host tracer input exceeded deadline", diagnostics)
                self.assertIn("kill cleanup exploded", diagnostics)
                self.assertIn("close cleanup exploded", diagnostics)
                self.assertTrue(failed_close[0])
                self.assertFalse(snapshot_path.exists())
                with self.assertRaises(OSError):
                    os.fstat(destination_descriptors[0])
        finally:
            for descriptor in (*tracked_descriptors, blocked_read, blocked_write):
                try:
                    real_close(descriptor)
                except OSError:
                    pass

    def test_staging_pushes_private_snapshots_not_rebound_build_paths(self):
        from scripts.qtrace_device_acceptance import _stage_app_private_binaries

        with tempfile.TemporaryDirectory() as temporary:
            tracer = Path(temporary) / "libqbdi_tracer.so"
            companion = Path(temporary) / "libshadowhook_nothing.so"
            tracer.write_bytes(b"fresh tracer")
            companion.write_bytes(b"fresh companion")
            binaries = (
                (tracer, "files/libqbdi_tracer.so"),
                (companion, "files/libshadowhook_nothing.so"),
            )

            def replace_build_outputs():
                tracer.write_bytes(b"attacker tracer")
                companion.write_bytes(b"attacker companion")

            runner = StagingDeviceRunner(before_first_push=replace_build_outputs)
            with held_tracer_pair(binaries) as pair, \
                    patch("scripts.qtrace_device_acceptance._APP_PRIVATE_BINARIES", binaries):
                _stage_app_private_binaries(
                    "SERIAL", runner, token="f" * 32, pair=pair,
                )

        self.assertEqual(("regular file", b"fresh tracer"),
                         runner.app_files["files/libqbdi_tracer.so"])
        self.assertEqual(("regular file", b"fresh companion"),
                         runner.app_files["files/libshadowhook_nothing.so"])
        pushed_sources = [Path(command[4]) for command in runner.commands
                          if command[:4] == ("adb", "-s", "SERIAL", "push")]
        self.assertEqual(2, len(pushed_sources))
        self.assertNotIn(tracer, pushed_sources)
        self.assertNotIn(companion, pushed_sources)
        self.assertEqual([0o700, 0o700], runner.push_source_parent_modes)
        self.assertTrue(all(not source.exists() for source in pushed_sources))

    def test_staging_rejects_snapshot_rebinding_during_adb_push(self):
        from scripts.qtrace_device_acceptance import _stage_app_private_binaries

        with tempfile.TemporaryDirectory() as temporary:
            tracer = Path(temporary) / "libqbdi_tracer.so"
            companion = Path(temporary) / "libshadowhook_nothing.so"
            tracer.write_bytes(b"fresh tracer")
            companion.write_bytes(b"fresh companion")
            binaries = (
                (tracer, "files/libqbdi_tracer.so"),
                (companion, "files/libshadowhook_nothing.so"),
            )
            runner = StagingDeviceRunner()

            def replace_snapshot():
                snapshot = Path(runner.commands[-1][4])
                snapshot.unlink()
                snapshot.write_bytes(b"replacement during push")

            runner.before_first_push = replace_snapshot
            with held_tracer_pair(binaries) as pair, \
                    patch("scripts.qtrace_device_acceptance._APP_PRIVATE_BINARIES", binaries), \
                    self.assertRaisesRegex(RuntimeError, "snapshot identity changed"):
                _stage_app_private_binaries(
                    "SERIAL", runner, token="4" * 32, pair=pair,
                )

        self.assertNotIn("files/libqbdi_tracer.so", runner.app_files)
        self.assertNotIn("files/libshadowhook_nothing.so", runner.app_files)

    def test_fresh_install_creates_and_validates_app_private_files_directory(self):
        from scripts.qtrace_device_acceptance import _stage_app_private_binaries

        with tempfile.TemporaryDirectory() as temporary:
            tracer = Path(temporary) / "libqbdi_tracer.so"
            companion = Path(temporary) / "libshadowhook_nothing.so"
            tracer.write_bytes(b"fresh tracer")
            companion.write_bytes(b"fresh companion")
            binaries = (
                (tracer, "files/libqbdi_tracer.so"),
                (companion, "files/libshadowhook_nothing.so"),
            )
            runner = StagingDeviceRunner(app_parent_kind=None)
            with held_tracer_pair(binaries) as pair, \
                    patch("scripts.qtrace_device_acceptance._APP_PRIVATE_BINARIES", binaries):
                _stage_app_private_binaries(
                    "SERIAL", runner, token="1" * 32, pair=pair,
                )

        self.assertEqual("directory", runner.app_parent_kind)
        self.assertEqual(0o771, runner.app_parent_mode)
        mkdir_index = next(index for index, command in enumerate(runner.commands)
                           if len(command) > 6 and command[6] == "mkdir")
        first_copy_index = next(index for index, command in enumerate(runner.commands)
                                if len(command) > 6 and command[6] == "cp")
        self.assertLess(mkdir_index, first_copy_index)

    def test_app_private_files_parent_symlink_is_rejected_without_traversal(self):
        from scripts.qtrace_device_acceptance import _stage_app_private_binaries

        with tempfile.TemporaryDirectory() as temporary:
            tracer = Path(temporary) / "libqbdi_tracer.so"
            companion = Path(temporary) / "libshadowhook_nothing.so"
            tracer.write_bytes(b"fresh tracer")
            companion.write_bytes(b"fresh companion")
            binaries = (
                (tracer, "files/libqbdi_tracer.so"),
                (companion, "files/libshadowhook_nothing.so"),
            )
            runner = StagingDeviceRunner(app_parent_kind="symbolic link")
            runner.app_files["outside/victim"] = ("regular file", b"victim")
            with held_tracer_pair(binaries) as pair, \
                    patch("scripts.qtrace_device_acceptance._APP_PRIVATE_BINARIES", binaries), \
                    self.assertRaisesRegex(RuntimeError, "not a real directory"):
                _stage_app_private_binaries(
                    "SERIAL", runner, token="2" * 32, pair=pair,
                )

        self.assertEqual(("regular file", b"victim"), runner.app_files["outside/victim"])
        self.assertFalse(any(command[6] in {"cp", "chmod", "mv"}
                             for command in runner.commands if len(command) > 6))

    def test_app_private_files_parent_mode_is_verified_before_traversal(self):
        from scripts.qtrace_device_acceptance import _stage_app_private_binaries

        with tempfile.TemporaryDirectory() as temporary:
            tracer = Path(temporary) / "libqbdi_tracer.so"
            companion = Path(temporary) / "libshadowhook_nothing.so"
            tracer.write_bytes(b"fresh tracer")
            companion.write_bytes(b"fresh companion")
            binaries = (
                (tracer, "files/libqbdi_tracer.so"),
                (companion, "files/libshadowhook_nothing.so"),
            )
            runner = StagingDeviceRunner(parent_chmod_result_mode=0o777)
            with held_tracer_pair(binaries) as pair, \
                    patch("scripts.qtrace_device_acceptance._APP_PRIVATE_BINARIES", binaries), \
                    self.assertRaisesRegex(RuntimeError, "canonical mode 771"):
                _stage_app_private_binaries(
                    "SERIAL", runner, token="5" * 32, pair=pair,
                )

        self.assertFalse(any(command[6] in {"cp", "mv"}
                             for command in runner.commands if len(command) > 6))

    def test_files_parent_probe_failure_cleans_host_scratch_with_diagnostics(self):
        from scripts.qtrace_device_acceptance import _stage_app_private_binaries

        for primary in ("mkdir:files", "stat:files", "chmod:files", "stat-mode:files"):
            with self.subTest(primary=primary), tempfile.TemporaryDirectory() as temporary:
                tracer = Path(temporary) / "libqbdi_tracer.so"
                companion = Path(temporary) / "libshadowhook_nothing.so"
                tracer.write_bytes(b"fresh tracer")
                companion.write_bytes(b"fresh companion")
                binaries = (
                    (tracer, "files/libqbdi_tracer.so"),
                    (companion, "files/libshadowhook_nothing.so"),
                )
                cleanup_failures = frozenset((
                    "cleanup:host-stage:tracer",
                    "cleanup:host-stage:companion",
                ))
                runner = StagingDeviceRunner(
                    primary_failure=primary,
                    cleanup_failures=cleanup_failures,
                )
                with held_tracer_pair(binaries) as pair, \
                        patch("scripts.qtrace_device_acceptance._APP_PRIVATE_BINARIES", binaries), \
                        self.assertRaisesRegex(RuntimeError, primary) as caught:
                    _stage_app_private_binaries(
                        "SERIAL", runner, token="3" * 32, pair=pair,
                    )

                diagnostics = str(caught.exception)
                for cleanup in cleanup_failures:
                    self.assertIn(cleanup, diagnostics)
                self.assertFalse(any(
                    command[4:8] ==
                    ("run-as", "com.aprz.qbdiandroid", "rm", "-f")
                    for command in runner.commands
                ))

    def test_verified_pair_replaces_final_symlinks_with_tracer_as_activation_marker(self):
        from scripts.qtrace_device_acceptance import _stage_app_private_binaries

        with tempfile.TemporaryDirectory() as temporary:
            tracer = Path(temporary) / "libqbdi_tracer.so"
            companion = Path(temporary) / "libshadowhook_nothing.so"
            tracer.write_bytes(b"fresh tracer")
            companion.write_bytes(b"fresh companion")
            binaries = (
                (tracer, "files/libqbdi_tracer.so"),
                (companion, "files/libshadowhook_nothing.so"),
            )
            runner = StagingDeviceRunner()
            runner.app_files.update({
                "files/libqbdi_tracer.so": ("symlink", "files/tracer-victim"),
                "files/libshadowhook_nothing.so": ("symlink", "files/companion-victim"),
                "files/tracer-victim": ("regular file", b"tracer victim"),
                "files/companion-victim": ("regular file", b"companion victim"),
            })
            with held_tracer_pair(binaries) as pair, \
                    patch("scripts.qtrace_device_acceptance._APP_PRIVATE_BINARIES", binaries):
                _stage_app_private_binaries(
                    "SERIAL", runner, token="a" * 32, pair=pair,
                )

        self.assertEqual(("regular file", b"fresh tracer"),
                         runner.app_files["files/libqbdi_tracer.so"])
        self.assertEqual(("regular file", b"fresh companion"),
                         runner.app_files["files/libshadowhook_nothing.so"])
        self.assertEqual(0o700, runner.app_modes["files/libqbdi_tracer.so"])
        self.assertEqual(0o700, runner.app_modes["files/libshadowhook_nothing.so"])
        self.assertEqual(("regular file", b"tracer victim"),
                         runner.app_files["files/tracer-victim"])
        self.assertEqual(("regular file", b"companion victim"),
                         runner.app_files["files/companion-victim"])
        self.assertEqual({}, runner.shell_files)
        self.assertFalse(any(path.startswith("files/.qtrace-acceptance-")
                             for path in runner.app_files))
        move_roles = [
            StagingDeviceRunner._role(command[-1])
            for command in runner.commands
            if len(command) > 6 and command[6] == "mv"
        ]
        final_removal_roles = [
            StagingDeviceRunner._role(command[-1])
            for command in runner.commands
            if command[4:8] == ("run-as", "com.aprz.qbdiandroid", "rm", "-f")
            and command[-1] in {
                "files/libqbdi_tracer.so", "files/libshadowhook_nothing.so",
            }
        ]
        self.assertEqual(["tracer", "companion"], final_removal_roles)
        self.assertEqual(["companion", "tracer"], move_roles)
        self.assertTrue(any(command[6:8] == ("stat", "-c") for command in runner.commands))
        self.assertTrue(any(command[6] == "sha256sum" for command in runner.commands
                            if len(command) > 6))

    def test_forged_successful_companion_move_fails_final_hash_and_removes_pair(self):
        from scripts.qtrace_device_acceptance import _stage_app_private_binaries

        with tempfile.TemporaryDirectory() as temporary:
            tracer = Path(temporary) / "libqbdi_tracer.so"
            companion = Path(temporary) / "libshadowhook_nothing.so"
            tracer.write_bytes(b"fresh tracer")
            companion.write_bytes(b"fresh companion")
            binaries = (
                (tracer, "files/libqbdi_tracer.so"),
                (companion, "files/libshadowhook_nothing.so"),
            )
            runner = StagingDeviceRunner(forged_stale_companion=True)
            with held_tracer_pair(binaries) as pair, \
                    patch("scripts.qtrace_device_acceptance._APP_PRIVATE_BINARIES", binaries), \
                    self.assertRaisesRegex(RuntimeError, "SHA-256 mismatch"):
                _stage_app_private_binaries(
                    "SERIAL", runner, token="c" * 32, pair=pair,
                )

        self.assertNotIn("files/libqbdi_tracer.so", runner.app_files)
        self.assertNotIn("files/libshadowhook_nothing.so", runner.app_files)

    def test_final_pair_mode_is_revalidated_after_activation(self):
        from scripts.qtrace_device_acceptance import _stage_app_private_binaries

        with tempfile.TemporaryDirectory() as temporary:
            tracer = Path(temporary) / "libqbdi_tracer.so"
            companion = Path(temporary) / "libshadowhook_nothing.so"
            tracer.write_bytes(b"fresh tracer")
            companion.write_bytes(b"fresh companion")
            binaries = (
                (tracer, "files/libqbdi_tracer.so"),
                (companion, "files/libshadowhook_nothing.so"),
            )
            runner = StagingDeviceRunner(
                wrong_modes=frozenset(("mode:final:companion",)),
            )
            with held_tracer_pair(binaries) as pair, \
                    patch("scripts.qtrace_device_acceptance._APP_PRIVATE_BINARIES", binaries), \
                    self.assertRaisesRegex(RuntimeError, "canonical mode 700"):
                _stage_app_private_binaries(
                    "SERIAL", runner, token="9" * 32, pair=pair,
                )

        self.assertNotIn("files/libqbdi_tracer.so", runner.app_files)
        self.assertNotIn("files/libshadowhook_nothing.so", runner.app_files)

    def test_each_pair_staging_boundary_fails_closed_without_final_files(self):
        from scripts.qtrace_device_acceptance import _stage_app_private_binaries

        command_failures = (
            "push:tracer", "push:companion", "copy:tracer", "copy:companion", "chmod",
            "stat:stage:tracer", "stat:stage:companion",
            "hash:stage:tracer", "hash:stage:companion",
            "move:companion", "move:tracer",
            "stat:final:tracer", "stat:final:companion",
            "hash:final:tracer", "hash:final:companion",
        )
        malformed_types = (
            "stat:stage:tracer", "stat:stage:companion",
            "stat:final:tracer", "stat:final:companion",
        )
        mismatched_hashes = (
            "hash:stage:tracer", "hash:stage:companion",
            "hash:final:tracer", "hash:final:companion",
        )
        cases = [
            (f"command-{label}", {"primary_failure": label})
            for label in command_failures
        ] + [
            (f"type-{label}", {"wrong_types": frozenset((label,))})
            for label in malformed_types
        ] + [
            (f"digest-{label}", {"wrong_hashes": frozenset((label,))})
            for label in mismatched_hashes
        ]
        for name, options in cases:
            with self.subTest(case=name), tempfile.TemporaryDirectory() as temporary:
                tracer = Path(temporary) / "libqbdi_tracer.so"
                companion = Path(temporary) / "libshadowhook_nothing.so"
                tracer.write_bytes(b"fresh tracer")
                companion.write_bytes(b"fresh companion")
                binaries = (
                    (tracer, "files/libqbdi_tracer.so"),
                    (companion, "files/libshadowhook_nothing.so"),
                )
                runner = StagingDeviceRunner(**options)
                runner.app_files.update({
                    "files/libqbdi_tracer.so": ("regular file", b"stale tracer"),
                    "files/libshadowhook_nothing.so": ("regular file", b"stale companion"),
                })
                with held_tracer_pair(binaries) as pair, \
                        patch("scripts.qtrace_device_acceptance._APP_PRIVATE_BINARIES", binaries), \
                        self.assertRaises(RuntimeError):
                    _stage_app_private_binaries(
                        "SERIAL", runner, token="d" * 32, pair=pair,
                    )
                self.assertNotIn("files/libqbdi_tracer.so", runner.app_files)
                self.assertNotIn("files/libshadowhook_nothing.so", runner.app_files)
                self.assertFalse(any(path.startswith("files/.qtrace-acceptance-")
                                     for path in runner.app_files))
                self.assertEqual({}, runner.shell_files)

    def test_staging_failure_force_stops_first_and_never_starts_or_benchmarks(self):
        from scripts.qtrace_device_acceptance import run_acceptance

        with tempfile.TemporaryDirectory() as temporary:
            tracer = Path(temporary) / "libqbdi_tracer.so"
            companion = Path(temporary) / "libshadowhook_nothing.so"
            tracer.write_bytes(b"fresh tracer")
            companion.write_bytes(b"fresh companion")
            binaries = (
                (tracer, "files/libqbdi_tracer.so"),
                (companion, "files/libshadowhook_nothing.so"),
            )
            current_apk = Path(temporary) / "app-debug.apk"
            current_apk.write_bytes(b"current APK")
            historical = RecordingHistoricalInput(
                Path(temporary) / "historical.apk", "h" * 64,
            )
            historical.path.write_bytes(b"historical APK")
            runner = StagingDeviceRunner(primary_failure="copy:companion")
            with patch("scripts.qtrace_device_acceptance._APP_PRIVATE_BINARIES", binaries), \
                    patch("scripts.qtrace_device_acceptance.TRACER_PATH", tracer), \
                    patch("scripts.qtrace_device_acceptance.COMPANION_PATH", companion), \
                    patch("scripts.qtrace_device_acceptance._CURRENT_APK_PATH", current_apk), \
                    self.assertRaisesRegex(RuntimeError, "copy:companion"):
                run_acceptance(
                    "SERIAL", Path(temporary) / "results", runner=runner,
                    historical_builder=lambda *_args, **_kwargs: historical,
                )

        push_index = next(index for index, command in enumerate(runner.commands)
                          if command[:4] == ("adb", "-s", "SERIAL", "push"))
        force_stop_index = next(index for index, command in enumerate(runner.commands)
                                if command[4:7] == ("am", "force-stop",
                                                   "com.aprz.qbdiandroid"))
        self.assertLess(force_stop_index, push_index)
        self.assertFalse(any(command[4:6] == ("am", "start")
                             for command in runner.commands))
        self.assertFalse(any("scripts/benchmark_trace.py" in command
                             for command in runner.commands))

    def test_primary_and_every_cleanup_failure_remain_in_diagnostics(self):
        from scripts.qtrace_device_acceptance import _stage_app_private_binaries

        cleanup_failures = frozenset((
            "cleanup:final:tracer",
            "cleanup:final:companion",
            "cleanup:app-stage:tracer",
            "cleanup:host-stage:companion",
        ))
        for primary in ("push:companion", "copy:companion", "chmod"):
            with self.subTest(primary=primary), tempfile.TemporaryDirectory() as temporary:
                tracer = Path(temporary) / "libqbdi_tracer.so"
                companion = Path(temporary) / "libshadowhook_nothing.so"
                tracer.write_bytes(b"fresh tracer")
                companion.write_bytes(b"fresh companion")
                binaries = (
                    (tracer, "files/libqbdi_tracer.so"),
                    (companion, "files/libshadowhook_nothing.so"),
                )
                runner = StagingDeviceRunner(
                    primary_failure=primary,
                    cleanup_failures=cleanup_failures,
                )
                with held_tracer_pair(binaries) as pair, \
                        patch("scripts.qtrace_device_acceptance._APP_PRIVATE_BINARIES", binaries), \
                        self.assertRaisesRegex(RuntimeError, primary) as caught:
                    _stage_app_private_binaries(
                        "SERIAL", runner, token="e" * 32, pair=pair,
                    )

                diagnostics = str(caught.exception)
                self.assertIsNotNone(caught.exception.__cause__)
                self.assertIn(primary, str(caught.exception.__cause__))
                final_cleanup_roles = [
                    StagingDeviceRunner._role(command[-1])
                    for command in runner.commands
                    if command[4:8] ==
                    ("run-as", "com.aprz.qbdiandroid", "rm", "-f")
                    and command[-1] in {
                        "files/libqbdi_tracer.so", "files/libshadowhook_nothing.so",
                    }
                ]
                self.assertEqual(["tracer", "companion"], final_cleanup_roles)
                for cleanup in cleanup_failures:
                    self.assertIn(cleanup, diagnostics)

    def test_acceptance_runs_bounded_workflow_and_retries_one_read(self):
        from scripts.qtrace_device_acceptance import run_acceptance

        ordering: list[str] = []

        class OrderingRunner(StagingDeviceRunner):
            def run(self, command, *, timeout, cwd=None, allowed=(0,)):
                command = tuple(command)
                if "qtrace" in command and "demo" in command:
                    ordering.append(f"demo:{command[command.index('--scenario') + 1]}")
                elif command[4:7] == ("su", "-c", f"kill -0 {4242}"):
                    ordering.append(f"alive:{4242}")
                return super().run(command, timeout=timeout, cwd=cwd, allowed=allowed)

            def read_text(self, path: Path, *, timeout: float) -> str:
                if path.name == "qtrace-acceptance-timed.json":
                    ordering.append("timed-result")
                return super().read_text(path, timeout=timeout)

        runner = OrderingRunner(fail_first_read=True)
        with tempfile.TemporaryDirectory() as temporary:
            tracer = Path(temporary) / "libqbdi_tracer.so"
            companion = Path(temporary) / "libshadowhook_nothing.so"
            tracer.write_bytes(b"fresh tracer")
            companion.write_bytes(b"fresh companion")
            binaries = (
                (tracer, "files/libqbdi_tracer.so"),
                (companion, "files/libshadowhook_nothing.so"),
            )
            current_apk = Path(temporary) / "app-debug.apk"
            current_apk.write_bytes(b"current APK")
            historical = RecordingHistoricalInput(
                Path(temporary) / "historical.apk", "h" * 64,
            )
            historical.path.write_bytes(b"historical APK")
            (Path(temporary) / "offset").mkdir()
            (Path(temporary) / "offset" / "fixture.trace.txt").write_text("fixture")
            artifacts = Path(temporary) / "offset" / SESSION / "artifacts"
            artifacts.mkdir(parents=True)
            (artifacts / "fixture.trace.bin.lz4").write_bytes(b"fixture qtrb bytes")
            (artifacts / "fixture.trace.bin.lz4.metrics").write_text("metrics")
            artifact_client = FakeArtifactClient(Path(temporary) / "offset" / SESSION)
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
            with patch("scripts.qtrace_device_acceptance._APP_PRIVATE_BINARIES", binaries), \
                    patch("scripts.qtrace_device_acceptance.TRACER_PATH", tracer), \
                    patch("scripts.qtrace_device_acceptance.COMPANION_PATH", companion), \
                    patch("scripts.qtrace_device_acceptance._CURRENT_APK_PATH", current_apk):
                self.assertEqual(0, run_acceptance(
                    "SERIAL", Path(temporary), runner=runner, converter=converter,
                    artifact_client_factory=lambda **_kwargs: artifact_client,
                    historical_builder=lambda *_args, **_kwargs: historical,
                ))
            self.assertEqual([("fixture.trace.bin.lz4.metrics", 64 * 1024)], artifact_client.calls)
            self.assertEqual([True], artifact_client.evidence_present_during_retry)
        self.assertLess(ordering.index(f"alive:{4242}"), ordering.index("demo:timed", 1))
        self.assertLess(ordering.index("timed-result"), ordering.index("demo:timed", 1))
        commands = runner.commands
        self.assertIn(
            ("adb", "-s", "SERIAL", "shell", "su", "-c", "kill -0 4242"),
            commands,
        )
        self.assertNotIn(
            ("adb", "-s", "SERIAL", "shell", "kill", "-0", "4242"),
            commands,
        )
        self.assertEqual(
            (
                "./gradlew", "nativeHostTest", ":app:testDebugUnitTest",
                ":app:assembleDebug", ":tracer:assembleDebug",
                ":tracer:copyTracerDebug", "--no-daemon",
            ),
            commands[0],
        )
        self.assertEqual(("python3", "-m", "unittest", "discover", "-s", "scripts/tests", "-p", "test_*.py"), commands[1])
        self.assertNotEqual("./gradlew", commands[2][0])
        installs = [command for command in commands
                    if command[:4] == ("adb", "-s", "SERIAL", "install")]
        self.assertEqual(2, len(installs))
        self.assertEqual(str(historical.path), installs[0][-1])
        self.assertNotEqual(str(current_apk), installs[1][-1])
        force_stop_index = commands.index(
            ("adb", "-s", "SERIAL", "shell", "am", "force-stop", "com.aprz.qbdiandroid")
        )
        push_indices = [index for index, command in enumerate(commands)
                        if command[:4] == ("adb", "-s", "SERIAL", "push")]
        move_indices = [index for index, command in enumerate(commands)
                        if len(command) > 6 and command[6] == "mv"]
        start_index = next(index for index, command in enumerate(commands)
                           if command[4:6] == ("am", "start"))
        benchmark_index = next(index for index, command in enumerate(commands)
                               if "scripts/benchmark_trace.py" in command)
        self.assertLess(force_stop_index, min(push_indices))
        pushed_sources = [Path(commands[index][4]) for index in push_indices]
        self.assertEqual({"libqbdi_tracer.so", "libshadowhook_nothing.so"},
                         {source.name for source in pushed_sources})
        self.assertNotIn(tracer, pushed_sources)
        self.assertNotIn(companion, pushed_sources)
        self.assertTrue(all(not source.exists() for source in pushed_sources))
        self.assertEqual(["companion", "tracer", "companion", "tracer"],
                         [StagingDeviceRunner._role(commands[index][-1])
                          for index in move_indices])
        self.assertLess(max(move_indices), start_index)
        self.assertLess(benchmark_index, start_index)
        candidate_index = commands[benchmark_index].index("--candidate-tracer")
        candidate_path = Path(commands[benchmark_index][candidate_index + 1])
        self.assertNotEqual(tracer, candidate_path)
        self.assertEqual("libqbdi_tracer.so", candidate_path.name)
        self.assertEqual(15, runner.reads)  # baseline retry, per-run entry evidence, reports, oracle, pulls
        self.assertIn(
            ("adb", "-s", "SERIAL", "shell", "su", "-c", "kill -0 4242"),
            commands,
        )
        named_pull = next(command for command in commands if "--name" in command)
        self.assertIn("fixture.trace.bin.lz4", named_pull)
        compressed_pull = next(command for command in commands if "--compressed-only" in command)
        self.assertEqual("--compressed-only", compressed_pull[-5])

    def _recorded_two_phase_workflow(self):
        from scripts import qtrace_device_acceptance as acceptance

        events = []
        stage_calls = []
        compare_commands = []

        class RecordingRunner(FakeRunner):
            def run(self, command, *, timeout, cwd=None, allowed=(0,)):
                command = tuple(command)
                if command == (
                    "./gradlew", "nativeHostTest", ":app:testDebugUnitTest",
                    ":app:assembleDebug", ":tracer:assembleDebug",
                    ":tracer:copyTracerDebug", "--no-daemon",
                ):
                    events.append("complete-host-gradle")
                elif command[:5] == ("python3", "-m", "unittest", "discover", "-s"):
                    events.append("full-python")
                elif command[4:7] == ("am", "force-stop", acceptance.PACKAGE):
                    events.append("force-stop-historical" if events[-1] == "install-historical"
                                  else "force-stop-current")
                elif command[4:6] == ("am", "start"):
                    events.append("start-timed-baseline")
                elif command[:2] == ("python3", "scripts/benchmark_trace.py"):
                    events.append("compare-historical")
                    compare_commands.append(command)
                elif "qtrace" in command and "demo" in command:
                    scenario = command[command.index("--scenario") + 1]
                    if scenario == "timed":
                        form = command[command.index("--scene-form") + 1]
                        events.append(f"timed-{form}")
                    else:
                        events.append(scenario)
                elif "qtrace" in command and "pull" in command:
                    output = Path(command[command.index("--output") + 1])
                    output.mkdir()
                    (output / SESSION).mkdir()
                    if "--latest" in command:
                        events.append("pull-latest")
                    elif "--name" in command:
                        events.append("pull-name")
                    elif "--compressed-only" in command:
                        events.append("pull-all-compressed-only")
                    else:
                        events.append("pull-all")
                return super().run(command, timeout=timeout, cwd=cwd, allowed=allowed)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            current, pair = self._recording_acceptance_inputs(root)
            historical = RecordingHistoricalInput(root / "held-historical.apk", "h" * 64)
            historical.path.write_bytes(b"historical")
            runner = RecordingRunner()

            def snapshot_current_inputs(*, deadline):
                self.assertGreater(deadline, time.monotonic())
                events.append("snapshot-current-apk-and-pair")
                return current, pair

            def historical_builder(repository, *, deadline):
                self.assertEqual(ROOT, repository)
                self.assertGreater(deadline, time.monotonic())
                events.append("build-historical-2d6b1022a14ae554804a57e267544c12dea29353")
                return historical

            def install(_device, _runner, apk):
                events.append("install-historical" if apk is historical else "install-current")

            def stage(_device, _runner, *, token, pair: object, package):
                self.assertRegex(token, r"[0-9a-f]{32}\Z")
                stage_calls.append((pair, pair.tracer.sha256, pair.companion.sha256))
                events.append("stage-historical-held-pair" if len(stage_calls) == 1
                              else "restage-current-same-held-pair")

            def isolate(_device, _runner, *, token):
                self.assertRegex(token, r"[0-9a-f]{32}\Z")
                events.append("isolate-current-traces")
                return SimpleNamespace(
                    existed=True,
                    backup_path=f"files/qbdi-traces.pre-acceptance-{token}",
                )

            def wait_baseline(_runner):
                events.append("wait-timed-baseline")
                return {"iterations": 30, "seed": 5855319310239641971,
                        "result": "0x42"}

            expected_compare = (
                "python3", "scripts/benchmark_trace.py", "--device", "SERIAL",
                "--profile", "fast", "--runs", "5", "--candidate-tracer",
                str(pair.tracer.path), "--expected-installed-apk-sha256",
                historical.apk_sha256, "--compare",
                "docs/benchmarks/binary-trace-baseline.md",
            )
            with patch.object(acceptance, "_snapshot_current_inputs",
                              side_effect=snapshot_current_inputs, create=True), \
                    patch.object(acceptance, "_install_held_apk", side_effect=install,
                                 create=True), \
                    patch.object(acceptance, "_stage_app_private_binaries",
                                 side_effect=stage), \
                    patch.object(acceptance, "_isolate_demo_trace_directory",
                                 side_effect=isolate, create=True), \
                    patch.object(acceptance, "_wait_for_baseline",
                                 side_effect=wait_baseline), \
                    patch.object(acceptance, "_validated_timed_report",
                                 side_effect=[({"native": {"status": {"normalizedScenes": []}},
                                                "pid": 4242}, "fixture.trace.bin.lz4"),
                                              ({"native": {"status": {"normalizedScenes": []}},
                                                "pid": 4242}, "fixture.trace.bin.lz4")]), \
                    patch.object(acceptance, "_wait_for_timed_fixture_evidence",
                                 return_value=("receipt", "entry")), \
                    patch.object(acceptance, "_validate_timed_fixture_receipt"), \
                    patch.object(acceptance, "_validate_timed_artifact_semantics"), \
                    patch.object(acceptance, "_verify_artifact_read_recovery"), \
                    patch.object(acceptance, "_validated_monitor_report"), \
                    patch.object(acceptance, "_wait_for_timed_result",
                                 return_value={"iterations": 30,
                                               "seed": 5855319310239641971,
                                               "result": "0x42"}), \
                    patch.object(acceptance, "_validated_pull_report"), \
                    patch.object(acceptance, "_verify_pull_outputs"):
                try:
                    result = acceptance.run_acceptance(
                        "SERIAL", root, runner=runner,
                        historical_builder=historical_builder,
                    )
                except TypeError as error:
                    self.fail(f"run_acceptance lacks the two-phase contract: {error}")

        self.assertEqual(0, result)
        self.assertEqual([
            "complete-host-gradle", "full-python",
            "snapshot-current-apk-and-pair",
            "build-historical-2d6b1022a14ae554804a57e267544c12dea29353",
            "install-historical", "force-stop-historical",
            "stage-historical-held-pair", "compare-historical", "install-current",
            "force-stop-current", "isolate-current-traces",
            "restage-current-same-held-pair",
            "start-timed-baseline", "wait-timed-baseline", "timed-offset",
            "timed-symbol", "pull-latest", "pull-name", "pull-all",
            "pull-all-compressed-only", "monitor-exit", "flight-crash",
        ], events)
        self.assertEqual([(pair, "t" * 64, "p" * 64),
                          (pair, "t" * 64, "p" * 64)], stage_calls)
        self.assertIs(stage_calls[0][0], stage_calls[1][0])
        self.assertEqual([expected_compare], compare_commands)
        return runner.commands

    def test_acceptance_installs_historical_then_current_and_reuses_one_held_pair(self):
        self._recorded_two_phase_workflow()

    def test_current_apk_and_tracer_pair_are_snapshotted_before_historical_build(self):
        from scripts import qtrace_device_acceptance as acceptance

        events = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            current, pair = self._recording_acceptance_inputs(root)
            historical = RecordingHistoricalInput(root / "historical.apk", "h" * 64)
            historical.path.write_bytes(b"historical")

            def snapshot(*, deadline):
                events.append("snapshot")
                return current, pair

            def build(_repository, *, deadline):
                events.append("build-historical")
                raise RuntimeError("stop after ordering probe")

            with patch.object(acceptance, "_snapshot_current_inputs", side_effect=snapshot,
                              create=True):
                try:
                    acceptance.run_acceptance("SERIAL", root, runner=FakeRunner(),
                                              historical_builder=build)
                except TypeError as error:
                    self.fail(f"run_acceptance lacks historical_builder injection: {error}")
                except RuntimeError as error:
                    self.assertIn("stop after ordering probe", str(error))
        self.assertEqual(["snapshot", "build-historical"], events)

    def test_each_adb_install_revalidates_the_same_held_apk_before_and_after_path_use(self):
        from scripts import qtrace_device_acceptance as acceptance

        class MutatingInstallRunner(FakeRunner):
            def __init__(self, held):
                super().__init__()
                self.held = held

            def run(self, command, *, timeout, cwd=None, allowed=(0,)):
                result = super().run(command, timeout=timeout, cwd=cwd,
                                     allowed=allowed)
                if tuple(command[:4]) == ("adb", "-s", "SERIAL", "install"):
                    self.held.path.unlink()
                    self.held.path.write_bytes(b"rebound")
                return result

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.apk"
            source.write_bytes(b"original")
            snapshot = acceptance._snapshot_host_binary(
                source, root / "held.apk", maximum_bytes=128,
                deadline=time.monotonic() + 1.0,
            )
            runner = MutatingInstallRunner(snapshot)
            try:
                with self.assertRaisesRegex(RuntimeError, "identity changed"):
                    try:
                        acceptance._install_held_apk("SERIAL", runner, snapshot)
                    except AttributeError as error:
                        self.fail(f"missing held APK installer: {error}")
            finally:
                snapshot.close()
        self.assertEqual(2, len(runner.commands) + 1)

    def test_second_stage_uses_held_pair_after_mutable_build_outputs_are_rebound(self):
        from scripts import qtrace_device_acceptance as acceptance

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tracer = root / "libqbdi_tracer.so"
            companion = root / "libshadowhook_nothing.so"
            current_apk = root / "app-debug.apk"
            tracer.write_bytes(b"held tracer")
            companion.write_bytes(b"held companion")
            current_apk.write_bytes(b"held current")
            with patch.object(acceptance, "TRACER_PATH", tracer), \
                    patch.object(acceptance, "COMPANION_PATH", companion), \
                    patch.object(acceptance, "_CURRENT_APK_PATH", current_apk,
                                 create=True):
                try:
                    current, pair = acceptance._snapshot_current_inputs(
                        deadline=time.monotonic() + 2.0,
                    )
                except AttributeError as error:
                    self.fail(f"missing current input snapshot contract: {error}")
            try:
                tracer.write_bytes(b"rebound tracer")
                companion.write_bytes(b"rebound companion")
                current_apk.write_bytes(b"rebound current")
                runner = StagingDeviceRunner()
                acceptance._stage_app_private_binaries(
                    "SERIAL", runner, token="7" * 32, pair=pair,
                )
                acceptance._stage_app_private_binaries(
                    "SERIAL", runner, token="8" * 32, pair=pair,
                )
                self.assertEqual(("regular file", b"held tracer"),
                                 runner.app_files["files/libqbdi_tracer.so"])
                self.assertEqual(("regular file", b"held companion"),
                                 runner.app_files["files/libshadowhook_nothing.so"])
            finally:
                current.close()
                pair.close()
                __import__("shutil").rmtree(current.path.parent, ignore_errors=True)

    def test_historical_compare_failure_never_starts_current_fixture_or_semantic_fallback(self):
        from scripts import qtrace_device_acceptance as acceptance

        class CompareFailureRunner(FakeRunner):
            def run(self, command, *, timeout, cwd=None, allowed=(0,)):
                if tuple(command[:2]) == ("python3", "scripts/benchmark_trace.py"):
                    self.commands.append(tuple(command))
                    raise RuntimeError("compare-historical")
                return super().run(command, timeout=timeout, cwd=cwd, allowed=allowed)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            current, pair = self._recording_acceptance_inputs(root)
            historical = RecordingHistoricalInput(root / "historical.apk", "h" * 64)
            historical.path.write_bytes(b"historical")
            runner = CompareFailureRunner()
            with patch.object(acceptance, "_snapshot_current_inputs",
                              return_value=(current, pair), create=True), \
                    patch.object(acceptance, "_install_held_apk", create=True), \
                    patch.object(acceptance, "_stage_app_private_binaries"):
                try:
                    with self.assertRaisesRegex(RuntimeError, "compare-historical"):
                        acceptance.run_acceptance(
                            "SERIAL", root, runner=runner,
                            historical_builder=lambda *_args, **_kwargs: historical,
                        )
                except TypeError as error:
                    self.fail(f"run_acceptance lacks historical_builder injection: {error}")
        self.assertFalse(any(command[4:6] == ("am", "start")
                             for command in runner.commands))
        compares = [command for command in runner.commands
                    if "scripts/benchmark_trace.py" in command]
        self.assertEqual(1, len(compares))
        self.assertIn("--compare", compares[0])

    def test_current_qtrace_start_and_pull_commands_receive_no_historical_arguments(self):
        recorded = [
            command for command in self._recorded_two_phase_workflow()
            if ((len(command) > 5 and command[4:6] == ("am", "start")) or
                ("qtrace" in command and ("demo" in command or "pull" in command)))
        ]
        forbidden = {"historical", "2d6b1022a14ae554804a57e267544c12dea29353",
                     "--expected-installed-apk-sha256"}
        self.assertEqual(9, len(recorded))  # one start, four demos, four pulls
        self.assertTrue(all(not (set(command) & forbidden) for command in recorded))

    def test_every_post_historical_install_failure_recovers_current_apk_and_force_stops(self):
        from scripts import qtrace_device_acceptance as acceptance

        boundaries = (
            "force-stop-historical", "stage-historical", "compare-historical",
            "install-current", "force-stop-current", "restage-current",
            "start-timed-baseline",
        )
        for boundary in boundaries:
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                current, pair = self._recording_acceptance_inputs(root)
                historical = RecordingHistoricalInput(root / "historical.apk", "h" * 64)
                historical.path.write_bytes(b"historical")
                events = []
                force_stops = 0
                stages = 0
                normal_force_stops = (2 if boundary in {
                    "force-stop-current", "restage-current", "start-timed-baseline",
                } else 1)

                class BoundaryRunner(FakeRunner):
                    def run(self, command, *, timeout, cwd=None, allowed=(0,)):
                        nonlocal force_stops
                        command = tuple(command)
                        if command[4:7] == ("am", "force-stop", acceptance.PACKAGE):
                            force_stops += 1
                            if force_stops <= normal_force_stops:
                                label = ("force-stop-historical" if force_stops == 1
                                         else "force-stop-current")
                            else:
                                label = (f"recovery-force-stop-"
                                         f"{force_stops - normal_force_stops}")
                            events.append(label)
                            if label == boundary:
                                raise RuntimeError(boundary)
                        elif command[:2] == ("python3", "scripts/benchmark_trace.py"):
                            events.append("compare-historical")
                            if boundary == "compare-historical":
                                raise RuntimeError(boundary)
                        elif command[4:6] == ("am", "start"):
                            events.append("start-timed-baseline")
                            if boundary == "start-timed-baseline":
                                raise RuntimeError(boundary)
                        return super().run(command, timeout=timeout, cwd=cwd,
                                           allowed=allowed)

                runner = BoundaryRunner()

                def install(_device, _runner, apk):
                    label = ("install-historical" if apk is historical
                             else "recovery-install-current"
                             if force_stops > normal_force_stops
                             else "install-current")
                    events.append(label)
                    if ((boundary == "install-current" and label == "install-current") or
                            (label == "install-historical" and False)):
                        raise RuntimeError(boundary)

                def stage(_device, _runner, *, token, pair, package):
                    nonlocal stages
                    stages += 1
                    label = "stage-historical" if stages == 1 else "restage-current"
                    events.append(label)
                    if label == boundary:
                        raise RuntimeError(boundary)

                with patch.object(acceptance, "_snapshot_current_inputs",
                                  return_value=(current, pair), create=True), \
                        patch.object(acceptance, "_install_held_apk",
                                     side_effect=install, create=True), \
                        patch.object(acceptance, "_stage_app_private_binaries",
                                     side_effect=stage):
                    try:
                        with self.assertRaises(RuntimeError) as caught:
                            acceptance.run_acceptance(
                                "SERIAL", root, runner=runner,
                                historical_builder=lambda *_args, **_kwargs: historical,
                            )
                    except TypeError as error:
                        self.fail(f"run_acceptance lacks recovery contract: {error}")
                primary = caught.exception.__cause__ or caught.exception
                self.assertIn(boundary, str(primary))
                primary_index = next(index for index, event in enumerate(events)
                                     if event == boundary)
                self.assertEqual(
                    ["recovery-force-stop-1", "recovery-install-current",
                     "recovery-force-stop-2"],
                    events[primary_index + 1:primary_index + 4],
                )
                self.assertFalse(any(event.startswith(("timed-", "pull-"))
                                     for event in events[primary_index + 1:]))

    def test_primary_and_every_recovery_snapshot_descriptor_tree_and_report_failure_are_visible(self):
        from scripts import qtrace_device_acceptance as acceptance

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            current, pair = self._recording_acceptance_inputs(root)
            historical = RecordingHistoricalInput(root / "historical.apk", "h" * 64)
            historical.path.write_bytes(b"historical")
            current.close_failure = "current-apk-close"
            pair.tracer.close_failure = "tracer-close"
            pair.companion.close_failure = "companion-close"
            historical.close_failure = "historical-apk-close"
            recovery_calls = 0

            class FailureRunner(FakeRunner):
                def run(self, command, *, timeout, cwd=None, allowed=(0,)):
                    nonlocal recovery_calls
                    if tuple(command[:2]) == ("python3", "scripts/benchmark_trace.py"):
                        raise RuntimeError("compare-primary")
                    if command[4:7] == ("am", "force-stop", acceptance.PACKAGE):
                        recovery_calls += 1
                        if recovery_calls > 1:
                            raise RuntimeError(f"recovery-force-stop-{recovery_calls - 1}")
                    return super().run(command, timeout=timeout, cwd=cwd, allowed=allowed)

            installs = 0

            def install(_device, _runner, _apk):
                nonlocal installs
                installs += 1
                if installs > 1:
                    raise RuntimeError("recovery-install-current")

            with patch.object(acceptance, "_snapshot_current_inputs",
                              return_value=(current, pair), create=True), \
                    patch.object(acceptance, "_install_held_apk", side_effect=install,
                                 create=True), \
                    patch.object(acceptance, "_stage_app_private_binaries"), \
                    patch.object(acceptance, "_publish_gate_failure_evidence",
                                 side_effect=RuntimeError("evidence-publication"),
                                 create=True):
                try:
                    with self.assertRaises(RuntimeError) as caught:
                        acceptance.run_acceptance(
                            "SERIAL", root, runner=FailureRunner(),
                            historical_builder=lambda *_args, **_kwargs: historical,
                        )
                except TypeError as error:
                    self.fail(f"run_acceptance lacks exhaustive failure contract: {error}")

        diagnostics = str(caught.exception)
        labels = (
            "compare-primary", "recovery-force-stop-1", "recovery-install-current",
            "recovery-force-stop-2", "historical-apk-close", "current-apk-close",
            "tracer-close", "companion-close", "evidence-publication",
        )
        positions = []
        for label in labels:
            self.assertEqual(1, diagnostics.count(label), diagnostics)
            positions.append(diagnostics.index(label))
        self.assertEqual(sorted(positions), positions)
        self.assertEqual(1, historical.close_calls)
        self.assertEqual(1, current.close_calls)
        self.assertEqual(1, pair.tracer.close_calls)
        self.assertEqual(1, pair.companion.close_calls)

    def test_failure_report_is_bounded_atomic_and_retained_with_exact_phase_and_hashes(self):
        from scripts import qtrace_device_acceptance as acceptance

        raw_pax_body = b"52 comment=2d6b1022a14ae554804a57e267544c12dea29353\n"
        manifest = [{
            "type": "global_pax", "size": len(raw_pax_body),
            "sha256": hashlib.sha256(raw_pax_body).hexdigest(),
        }, {"path": "app/build.gradle", "type": "file", "size": 1,
            "sha256": "a" * 64}]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            current, pair = self._recording_acceptance_inputs(root)
            historical = RecordingHistoricalInput(
                root / "historical.apk", "h" * 64,
                report={"manifest": manifest, "archive_sha256": "a" * 64},
            )
            historical.path.write_bytes(b"historical")
            historical.close_failure = "historical-close-evidence"
            current.close_failure = "current-close-evidence"
            pair.tracer.close_failure = "tracer-close-evidence"
            pair.companion.close_failure = "companion-close-evidence"

            class CompareFailureRunner(FakeRunner):
                def run(self, command, *, timeout, cwd=None, allowed=(0,)):
                    if tuple(command[:2]) == ("python3", "scripts/benchmark_trace.py"):
                        raise RuntimeError("compare-primary")
                    return super().run(command, timeout=timeout, cwd=cwd,
                                       allowed=allowed)

            with patch.object(acceptance, "_snapshot_current_inputs",
                              return_value=(current, pair), create=True), \
                    patch.object(acceptance, "_install_held_apk", create=True), \
                    patch.object(acceptance, "_stage_app_private_binaries"):
                try:
                    with self.assertRaises(RuntimeError):
                        acceptance.run_acceptance(
                            "SERIAL", root, runner=CompareFailureRunner(),
                            historical_builder=lambda *_args, **_kwargs: historical,
                        )
                except TypeError as error:
                    self.fail(f"run_acceptance lacks retained evidence contract: {error}")

            report_path = root / "historical-benchmark-gate.json"
            self.assertTrue(report_path.is_file())
            self.assertLessEqual(report_path.stat().st_size, 1024 * 1024)
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual("compare-historical", report["phase"])
            self.assertEqual("2d6b1022a14ae554804a57e267544c12dea29353",
                             report["historical_commit"])
            self.assertEqual("h" * 64, report["historical_apk_sha256"])
            self.assertEqual("c" * 64, report["current_apk_sha256"])
            self.assertEqual("5" * 64, report["target_raw_sha256"])
            self.assertEqual("0" * 64, report["target_canonical_sha256"])
            self.assertEqual("t" * 64, report["tracer_sha256"])
            self.assertEqual("p" * 64, report["companion_sha256"])
            self.assertEqual(manifest, report["archive_manifest"])
            self.assertEqual([
                {"label": "historical APK close", "type": "RuntimeError",
                 "message": "historical-close-evidence"},
                {"label": "current APK close", "type": "RuntimeError",
                 "message": "current-close-evidence"},
                {"label": "tracer snapshot close", "type": "RuntimeError",
                 "message": "tracer-close-evidence"},
                {"label": "companion snapshot close", "type": "RuntimeError",
                 "message": "companion-close-evidence"},
            ], report["cleanup_errors"])
            self.assertEqual(
                {"type": "global_pax", "size": len(raw_pax_body),
                 "sha256": hashlib.sha256(raw_pax_body).hexdigest()},
                {key: report["archive_manifest"][0][key]
                 for key in ("type", "size", "sha256")},
            )
            self.assertFalse(any(item.get("path") == "pax_global_header"
                                 for item in report["archive_manifest"]))
            self.assertEqual([], list(root.glob(".historical-benchmark-gate.*.tmp")))

    def test_production_historical_result_retains_provenance_on_compare_failure(self):
        from scripts import qtrace_device_acceptance as acceptance
        from scripts.qtrace_historical_benchmark import HistoricalBenchmarkApk

        manifest = (
            (("type", "global_pax"), ("size", 52), ("sha256", "a" * 64)),
            (("path", "app/build.gradle"), ("type", "file"), ("size", 1),
             ("sha256", "b" * 64)),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = root / "historical-snapshot"
            snapshot.mkdir()
            apk_path = snapshot / "historical.apk"
            apk_bytes = b"historical APK"
            apk_path.write_bytes(apk_bytes)
            try:
                historical = HistoricalBenchmarkApk(
                    apk_path, hashlib.sha256(apk_bytes).hexdigest(), "5" * 64,
                    "0" * 64, archive_manifest=manifest,
                    archive_sha256="d" * 64,
                )
            except TypeError as error:
                self.fail(f"successful historical result lacks provenance: {error}")
            current, pair = self._recording_acceptance_inputs(root)

            class CompareFailureRunner(FakeRunner):
                def run(self, command, *, timeout, cwd=None, allowed=(0,)):
                    if tuple(command[:2]) == ("python3", "scripts/benchmark_trace.py"):
                        raise RuntimeError("production-shaped compare failure")
                    return super().run(command, timeout=timeout, cwd=cwd,
                                       allowed=allowed)

            with patch.object(acceptance, "_snapshot_current_inputs",
                              return_value=(current, pair)), \
                    patch.object(acceptance, "_install_held_apk"), \
                    patch.object(acceptance, "_stage_app_private_binaries"), \
                    self.assertRaisesRegex(RuntimeError, "production-shaped compare failure"):
                acceptance.run_acceptance(
                    "SERIAL", root, runner=CompareFailureRunner(),
                    historical_builder=lambda *_args, **_kwargs: historical,
                )

            report = json.loads(
                (root / "historical-benchmark-gate.json").read_text(encoding="utf-8")
            )
            self.assertEqual([dict(item) for item in manifest], report["archive_manifest"])
            self.assertEqual("d" * 64, report["archive_sha256"])

    def test_every_success_cleanup_failure_recovers_and_publishes_evidence(self):
        from scripts import qtrace_device_acceptance as acceptance

        boundaries = ("historical", "current", "tracer", "companion", "tree")
        for boundary in boundaries:
            with self.subTest(boundary=boundary), \
                    tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                current, pair = self._recording_acceptance_inputs(root)
                historical = RecordingHistoricalInput(root / "historical.apk", "h" * 64)
                historical.path.write_bytes(b"historical")
                held = {
                    "historical": historical,
                    "current": current,
                    "tracer": pair.tracer,
                    "companion": pair.companion,
                }
                if boundary in held:
                    held[boundary].close_failure = f"success-cleanup-{boundary}"
                installs = []

                def install(_device, _runner, apk):
                    installs.append(apk)

                tree_patch = patch.object(
                    acceptance, "_current_snapshot_tree_cleanup",
                    side_effect=RuntimeError("success-cleanup-tree"),
                ) if boundary == "tree" else patch.object(
                    acceptance, "_current_snapshot_tree_cleanup",
                    return_value=None,
                )
                runner = FakeRunner()
                with patch.object(acceptance, "_snapshot_current_inputs",
                                  return_value=(current, pair)), \
                        patch.object(acceptance, "_install_held_apk",
                                     side_effect=install), \
                        patch.object(acceptance, "_stage_app_private_binaries"), \
                        patch.object(acceptance, "_run_current_fixture_phase"), \
                        tree_patch, self.assertRaises(RuntimeError) as caught:
                    acceptance.run_acceptance(
                        "SERIAL", root, runner=runner,
                        historical_builder=lambda *_args, **_kwargs: historical,
                    )

                primary = caught.exception.__cause__ or caught.exception
                self.assertIn("acceptance resource cleanup failed", str(primary))
                force_stops = [
                    command for command in runner.commands
                    if command[4:7] == ("am", "force-stop", acceptance.PACKAGE)
                ]
                self.assertEqual(4, len(force_stops))
                self.assertEqual([historical, current], installs[:2])
                self.assertIsNot(current, installs[2])
                self.assertEqual(hashlib.sha256(b"current").hexdigest(),
                                 installs[2].sha256)
                report = json.loads(
                    (root / "historical-benchmark-gate.json").read_text(encoding="utf-8")
                )
                self.assertEqual("cleanup-success", report["phase"])
                self.assertTrue(any(
                    item["message"] == f"success-cleanup-{boundary}"
                    for item in report["cleanup_errors"]
                ))

    def test_late_success_cleanup_recovers_with_open_production_current_snapshot(self):
        from scripts import qtrace_device_acceptance as acceptance

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "current-source.apk"
            source.write_bytes(b"production current APK")
            snapshot_root = Path(tempfile.mkdtemp(
                prefix="qtrace-current-inputs-", dir=root,
            ))
            current = acceptance._snapshot_host_binary(
                source, snapshot_root / "current.apk",
                maximum_bytes=1024,
                deadline=time.monotonic() + 5.0,
            )
            tracer = RecordingHeldInput(snapshot_root / "tracer.so", "t" * 64,
                                        label="tracer")
            companion = RecordingHeldInput(snapshot_root / "companion.so", "p" * 64,
                                           label="companion")
            tracer.path.write_bytes(b"tracer")
            companion.path.write_bytes(b"companion")
            tracer.close_failure = "late tracer cleanup failure"
            pair = RecordingHeldPair(tracer, companion)
            historical = RecordingHistoricalInput(root / "historical.apk", "h" * 64)
            historical.path.write_bytes(b"historical")
            current_installs = []
            current_verifications = []
            current_closes = []
            real_verify = acceptance.HostBinarySnapshot.verify_path
            real_close = acceptance.HostBinarySnapshot.close

            class LifecycleRunner(FakeRunner):
                def run(self, command, *, timeout, cwd=None, allowed=(0,)):
                    if tuple(command[:4]) == ("adb", "-s", "SERIAL", "install"):
                        installed = Path(command[-1])
                        if installed.read_bytes() == b"production current APK":
                            current_installs.append(tuple(command))
                    return super().run(command, timeout=timeout, cwd=cwd,
                                       allowed=allowed)

            def recording_verify(snapshot):
                result = real_verify(snapshot)
                if snapshot is current:
                    current_verifications.append(len(current_installs))
                return result

            def recording_close(snapshot):
                if snapshot is current:
                    current_closes.append(len(current_installs))
                return real_close(snapshot)

            with patch.object(acceptance, "_snapshot_current_inputs",
                              return_value=(current, pair)), \
                    patch.object(acceptance, "_stage_app_private_binaries"), \
                    patch.object(acceptance, "_run_current_fixture_phase"), \
                    patch.object(acceptance.HostBinarySnapshot, "verify_path",
                                 recording_verify), \
                    patch.object(acceptance.HostBinarySnapshot, "close",
                                 recording_close), \
                    self.assertRaisesRegex(RuntimeError,
                                           "late tracer cleanup failure"):
                acceptance.run_acceptance(
                    "SERIAL", root, runner=LifecycleRunner(),
                    historical_builder=lambda *_args, **_kwargs: historical,
                )

            self.assertEqual(2, len(current_installs))
            self.assertEqual([0, 1], current_verifications[-2:])
            self.assertEqual([2], current_closes)
            self.assertEqual(-1, current.descriptor)

    def test_current_close_failure_recovers_from_independent_held_apk(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            installs, _tree_calls = self._run_real_current_cleanup_recovery(
                root, failure="close",
            )

            self.assertEqual(2, len(installs))
            self.assertNotEqual(installs[0][0], installs[1][0])
            self.assertNotEqual(installs[0][1], installs[1][1])
            self.assertEqual([], list(root.glob("qtrace-current-inputs-*")))
            self.assertEqual([], list(root.glob("qtrace-current-recovery-*")))

    def test_partial_current_tree_failure_recovers_then_removes_every_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            installs, tree_calls = self._run_real_current_cleanup_recovery(
                root, failure="tree",
            )

            self.assertEqual(2, len(installs))
            self.assertNotEqual(installs[0][0], installs[1][0])
            self.assertNotEqual(installs[0][1], installs[1][1])
            self.assertEqual(2, tree_calls)
            self.assertEqual([], list(root.glob("qtrace-current-inputs-*")))
            self.assertEqual([], list(root.glob("qtrace-current-recovery-*")))

    def test_recovery_snapshot_close_failure_does_not_reinstall_damaged_backup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            installs, force_stops, tree_calls, report, unrelated_descriptor = (
                self._run_real_recovery_disposal_failure(root, failure="close")
            )

            try:
                self.assertIsNotNone(unrelated_descriptor)
                try:
                    os.fstat(unrelated_descriptor)
                except OSError as error:
                    self.fail(f"cleanup retry closed unrelated reused fd: {error}")
                os.write(unrelated_descriptor, b" still-open")
                self.assertEqual(2, len(installs))
                self.assertEqual(2, len(force_stops))
                self.assertEqual(2, tree_calls)
                self.assertEqual("cleanup-success", report["phase"])
                self.assertTrue(any(
                    item["message"] ==
                    "recovery snapshot close after descriptor disposal"
                    for item in report["cleanup_errors"]
                ))
                self.assertFalse(any(
                    item["label"].startswith("recovery force-stop") or
                    item["label"] == "recovery current APK install"
                    for item in report["cleanup_errors"]
                ))
                self.assertEqual([], list(root.glob("qtrace-current-recovery-*")))
            finally:
                if unrelated_descriptor is not None:
                    try:
                        os.close(unrelated_descriptor)
                    except OSError:
                        pass

    def test_partial_recovery_tree_disposal_is_retried_without_device_reinstall(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            installs, force_stops, tree_calls, report, unrelated_descriptor = (
                self._run_real_recovery_disposal_failure(root, failure="tree")
            )

            self.assertIsNone(unrelated_descriptor)
            self.assertEqual(2, len(installs))
            self.assertEqual(2, len(force_stops))
            self.assertEqual(2, tree_calls)
            self.assertEqual("cleanup-success", report["phase"])
            messages = [item["message"] for item in report["cleanup_errors"]]
            self.assertIn("partial recovery tree cleanup removed APK", messages)
            self.assertIn("recovery tree cleanup retry diagnostic", messages)
            self.assertFalse(any(
                item["label"].startswith("recovery force-stop") or
                item["label"] == "recovery current APK install"
                for item in report["cleanup_errors"]
            ))
            self.assertEqual([], list(root.glob("qtrace-current-recovery-*")))

    def test_oversized_builder_report_is_bounded_with_truncation_evidence(self):
        from scripts import qtrace_device_acceptance as acceptance
        from scripts.qtrace_historical_benchmark import HistoricalBenchmarkError

        raw = "x" * (4 * 1024 * 1024)
        primary = HistoricalBenchmarkError(
            "builder failed",
            report={
                "phase": "gradle", "commit": "2" * 40,
                "manifest": [{"type": "global_pax", "size": 52,
                              "sha256": "a" * 64}],
                "archive_sha256": "b" * 64,
                "command": {"argv": ["./gradlew"], "stdout": raw,
                            "stderr": raw},
                "details": {"diagnostic": raw},
            },
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = acceptance._HistoricalGateState(
                phase="build-historical", builder_report=primary.report,
            )
            try:
                acceptance._publish_gate_failure_evidence(root, state, primary, [])
            except RuntimeError as error:
                self.fail(f"oversized structured evidence was rejected: {error}")
            path = root / "historical-benchmark-gate.json"
            self.assertLessEqual(path.stat().st_size, 1024 * 1024)
            report = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual("build-historical", report["phase"])
            self.assertEqual("a" * 64, report["archive_manifest"][0]["sha256"])
            truncated = report["historical_report"]["command"]["stdout"]
            self.assertEqual(True, truncated["truncated"])
            self.assertEqual(len(raw.encode("utf-8")), truncated["original_bytes"])
            self.assertEqual(hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                             truncated["sha256"])

    def test_historical_cleanup_error_retains_structured_multi_failure_report(self):
        from scripts import qtrace_device_acceptance as acceptance
        from scripts.qtrace_historical_benchmark import HistoricalBenchmarkError

        structured = {
            "phase": "close-apk",
            "cleanup_failures": ["descriptor close failed", "snapshot tree failed"],
            "details": {"descriptor": 17, "tree": "/private/snapshot"},
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            current, pair = self._recording_acceptance_inputs(root)
            historical = RecordingHistoricalInput(root / "historical.apk", "h" * 64)
            historical.path.write_bytes(b"historical")
            historical.close_failure = HistoricalBenchmarkError(
                "historical APK cleanup failed", report=structured,
            )

            class CompareFailureRunner(FakeRunner):
                def run(self, command, *, timeout, cwd=None, allowed=(0,)):
                    if tuple(command[:2]) == ("python3", "scripts/benchmark_trace.py"):
                        raise RuntimeError("compare failure before structured cleanup")
                    return super().run(command, timeout=timeout, cwd=cwd,
                                       allowed=allowed)

            with patch.object(acceptance, "_snapshot_current_inputs",
                              return_value=(current, pair)), \
                    patch.object(acceptance, "_install_held_apk"), \
                    patch.object(acceptance, "_stage_app_private_binaries"), \
                    self.assertRaises(RuntimeError):
                acceptance.run_acceptance(
                    "SERIAL", root, runner=CompareFailureRunner(),
                    historical_builder=lambda *_args, **_kwargs: historical,
                )
            report = json.loads(
                (root / "historical-benchmark-gate.json").read_text(encoding="utf-8")
            )
            cleanup = next(item for item in report["cleanup_errors"]
                           if item["label"] == "historical APK close")
            self.assertEqual(structured, cleanup.get("report"))

    def test_evidence_temp_close_and_unlink_failures_are_both_visible_and_no_partial_remains(self):
        from scripts import qtrace_device_acceptance as acceptance

        real_close = acceptance.os.close
        real_unlink = Path.unlink

        def close_then_fail(descriptor):
            real_close(descriptor)
            raise OSError("evidence descriptor close failure")

        def unlink_then_fail(path, *args, **kwargs):
            real_unlink(path, *args, **kwargs)
            raise OSError("evidence temp unlink failure")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = acceptance._HistoricalGateState(phase="compare-historical")
            with patch.object(acceptance.os, "write",
                              side_effect=OSError("evidence write primary")), \
                    patch.object(acceptance.os, "close",
                                 side_effect=close_then_fail), \
                    patch.object(Path, "unlink", autospec=True,
                                 side_effect=unlink_then_fail), \
                    self.assertRaises(BaseException) as caught:
                acceptance._publish_gate_failure_evidence(
                    root, state, RuntimeError("compare primary"), [],
                )
            diagnostics = str(caught.exception)
            self.assertIn("evidence write primary", diagnostics)
            self.assertIn("evidence descriptor close failure", diagnostics)
            self.assertIn("evidence temp unlink failure", diagnostics)
            self.assertEqual([], list(root.glob(".historical-benchmark-gate.*.tmp")))


if __name__ == "__main__":
    unittest.main()
