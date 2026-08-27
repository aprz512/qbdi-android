"""Host contracts for the manual qtrace device-acceptance gate."""

from __future__ import annotations

import copy
import json
import math
import os
import re
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

    def test_app_private_tracer_pair_is_staged_through_unique_temporary_paths(self):
        from scripts.qtrace_device_acceptance import _stage_app_private_binaries

        runner = FakeRunner()
        _stage_app_private_binaries("SERIAL", runner, token="a" * 32)

        tracer_stage = "/data/local/tmp/qtrace-acceptance-" + "a" * 32 + "-libqbdi_tracer.so"
        companion_stage = (
            "/data/local/tmp/qtrace-acceptance-" + "a" * 32 + "-libshadowhook_nothing.so"
        )
        self.assertEqual([
            ("adb", "-s", "SERIAL", "push", "out/arm64-v8a/libqbdi_tracer.so", tracer_stage),
            ("adb", "-s", "SERIAL", "push", "out/arm64-v8a/libshadowhook_nothing.so", companion_stage),
            ("adb", "-s", "SERIAL", "shell", "run-as", "com.aprz.qbdiandroid", "cp",
             tracer_stage, "files/libqbdi_tracer.so"),
            ("adb", "-s", "SERIAL", "shell", "run-as", "com.aprz.qbdiandroid", "cp",
             companion_stage, "files/libshadowhook_nothing.so"),
            ("adb", "-s", "SERIAL", "shell", "run-as", "com.aprz.qbdiandroid", "chmod", "700",
             "files/libqbdi_tracer.so", "files/libshadowhook_nothing.so"),
            ("adb", "-s", "SERIAL", "shell", "rm", "-f", tracer_stage, companion_stage),
        ], runner.commands)

    def test_app_private_staging_aborts_and_cleans_up_when_companion_push_fails(self):
        from scripts.qtrace_device_acceptance import _stage_app_private_binaries

        class FailingCompanionRunner(FakeRunner):
            def run(self, command, *, timeout, cwd=None, allowed=(0,)):
                if command[:4] == ("adb", "-s", "SERIAL", "push"):
                    self.commands.append(tuple(command))
                    if command[4].endswith("libshadowhook_nothing.so"):
                        raise RuntimeError("injected companion push failure")
                    return __import__(
                        "scripts.qtrace_device_acceptance", fromlist=["CommandResult"],
                    ).CommandResult("", "", 0)
                return super().run(command, timeout=timeout, cwd=cwd, allowed=allowed)

        runner = FailingCompanionRunner()
        with self.assertRaisesRegex(RuntimeError, "companion push failure"):
            _stage_app_private_binaries("SERIAL", runner, token="b" * 32)

        self.assertEqual("push", runner.commands[0][3])
        self.assertEqual("push", runner.commands[1][3])
        self.assertEqual(("adb", "-s", "SERIAL", "shell", "rm", "-f"), runner.commands[2][:6])
        self.assertFalse(any("run-as" in command for command in runner.commands))

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
        self.assertEqual(
            ("./gradlew", ":app:assembleDebug", ":tracer:copyTracerDebug", "--no-daemon"),
            commands[2],
        )
        self.assertEqual(("adb", "-s", "SERIAL", "install", "-r", "app/build/outputs/apk/debug/app-debug.apk"), commands[3])
        self.assertEqual(
            {"out/arm64-v8a/libqbdi_tracer.so", "out/arm64-v8a/libshadowhook_nothing.so"},
            {commands[4][4], commands[5][4]},
        )
        self.assertTrue(all(command[:4] == ("adb", "-s", "SERIAL", "push")
                            for command in commands[4:6]))
        self.assertTrue(all(command[:7] ==
                            ("adb", "-s", "SERIAL", "shell", "run-as",
                             "com.aprz.qbdiandroid", "cp")
                            for command in commands[6:8]))
        self.assertEqual("chmod", commands[8][6])
        self.assertEqual(("adb", "-s", "SERIAL", "shell", "rm", "-f"), commands[9][:6])
        self.assertEqual(("adb", "-s", "SERIAL", "shell", "am", "force-stop", "com.aprz.qbdiandroid"), commands[10])
        self.assertEqual(
            ("adb", "-s", "SERIAL", "shell", "am", "start", "-n", "com.aprz.qbdiandroid/.MainActivity",
             "--ez", "qtrace_acceptance", "true", "--es", "qtrace_acceptance_mode", "timed",
             "--el", "qtrace_acceptance_seed", "5855319310239641971", "--el", "qtrace_acceptance_iterations", "30"),
            commands[11],
        )
        self.assertEqual(("python3", "scripts/benchmark_trace.py", "--device", "SERIAL", "--profile", "fast", "--runs", "5", "--candidate-tracer", "out/arm64-v8a/libqbdi_tracer.so", "--compare", "docs/benchmarks/binary-trace-baseline.md"), commands[12])
        self.assertEqual(22, len(commands))
        self.assertEqual(15, runner.reads)  # baseline retry, per-run entry evidence, reports, oracle, pulls
        self.assertEqual(("adb", "-s", "SERIAL", "shell", "kill", "-0", "4242"), commands[17])
        self.assertIn("--name", commands[19])
        self.assertIn("fixture.trace.bin.lz4", commands[19])
        self.assertEqual("--compressed-only", commands[21][-5])


if __name__ == "__main__":
    unittest.main()
