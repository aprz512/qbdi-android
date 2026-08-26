import json
import tempfile
import unittest
from pathlib import Path

from qtrace.config import load_config, parse_duration_ms
from qtrace.errors import ConfigError
from qtrace.models import OffsetScene, SymbolScene


class DurationTests(unittest.TestCase):
    def test_accepts_ms_seconds_and_minutes(self):
        self.assertEqual(parse_duration_ms("30s"), 30_000)
        self.assertEqual(parse_duration_ms("250ms"), 250)
        self.assertEqual(parse_duration_ms("1.5m"), 90_000)
        self.assertEqual(parse_duration_ms("0.1s"), 100)
        self.assertEqual(parse_duration_ms("1440m"), 86_400_000)

    def test_rejects_out_of_range_nonfinite_and_unknown_units(self):
        for value in ("30", "99ms", "-1s", "nan", "inf", "1441m", "2h", ""):
            with self.subTest(value=value), self.assertRaises(ConfigError):
                parse_duration_ms(value)

    def test_rejects_values_that_do_not_resolve_to_whole_milliseconds(self):
        for value in ("100.1ms", "0.1001s", "0.00101m"):
            with self.subTest(value=value), self.assertRaises(ConfigError):
                parse_duration_ms(value)

    def test_rejects_non_string_and_noncanonical_decimals(self):
        for value in (100, None, "1e3ms", " 100ms", "100ms ", ".1s"):
            with self.subTest(value=value), self.assertRaises(ConfigError):
                parse_duration_ms(value)  # type: ignore[arg-type]


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

    def write_json(self, name: str, payload: object) -> Path:
        path = Path(self.directory.name) / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    @staticmethod
    def valid_payload() -> dict[str, object]:
        return {
            "schemaVersion": 1,
            "app": {"package": "com.example.external"},
            "target": {"module": "libexternal.so"},
            "scenes": [{"name": "one", "symbol": "do_work"}],
        }

    def test_loads_offset_and_symbol_scenes_with_tracer_defaults(self):
        config = load_config(self.write_json("valid-qtrace.json", {
            "schemaVersion": 1,
            "app": {"package": "com.example.external"},
            "target": {"module": "libexternal.so"},
            "scenes": [
                {"name": "offset", "startOffset": "0x120", "endOffset": "0x180"},
                {"name": "symbol", "symbol": "do_work"},
            ],
        }))

        self.assertEqual(config.app.package, "com.example.external")
        self.assertIsInstance(config.scenes[0], OffsetScene)
        self.assertEqual(config.scenes[0].start_offset, 0x120)
        self.assertIsInstance(config.scenes[1], SymbolScene)
        self.assertEqual(config.scenes[1].symbol, "do_work")
        self.assertEqual(config.tracer.profile, "fast")
        self.assertTrue(config.tracer.compression)
        self.assertFalse(config.tracer.flight_enabled)
        self.assertIsNone(config.tracer.flight_entry_scene)

    def test_resolves_relative_paths_against_config_directory(self):
        payload = self.valid_payload()
        payload["app"] = {"package": "com.example.external", "apk": "artifacts/app.apk"}
        payload["target"] = {"module": "libexternal.so", "binary": "symbols/libexternal.so"}
        payload["tracer"] = {
            "library": "prebuilt/libqbdi_tracer.so",
            "companion": "prebuilt/libshadowhook-companion.so",
        }
        path = self.write_json("paths.json", payload)

        config = load_config(path)

        base = path.parent.resolve()
        self.assertEqual(config.app.apk, base / "artifacts/app.apk")
        self.assertEqual(config.target.binary, base / "symbols/libexternal.so")
        self.assertEqual(config.tracer.library, base / "prebuilt/libqbdi_tracer.so")
        self.assertEqual(config.tracer.companion, base / "prebuilt/libshadowhook-companion.so")

    def test_loads_explicit_tracer_options_and_valid_flight_entry(self):
        payload = self.valid_payload()
        payload["tracer"] = {
            "profile": "balanced",
            "compression": False,
            "flightEnabled": True,
            "flightEntryScene": "one",
        }

        config = load_config(self.write_json("flight.json", payload))

        self.assertEqual(config.tracer.profile, "balanced")
        self.assertFalse(config.tracer.compression)
        self.assertTrue(config.tracer.flight_enabled)
        self.assertEqual(config.tracer.flight_entry_scene, "one")

    def test_rejects_unknown_keys_and_mixed_scene_forms(self):
        payload = self.valid_payload()
        payload["unknown"] = True
        with self.assertRaisesRegex(ConfigError, "CONFIG_UNKNOWN_FIELD"):
            load_config(self.write_json("unknown-key.json", payload))

        mixed = self.valid_payload()
        mixed["scenes"] = [{
            "name": "mixed", "symbol": "do_work",
            "startOffset": "0x120", "endOffset": "0x180",
        }]
        with self.assertRaisesRegex(ConfigError, "SCENE_FORM_INVALID"):
            load_config(self.write_json("mixed-scene.json", mixed))

    def test_rejects_unknown_nested_keys(self):
        cases = (
            ("app", {"package": "com.example.external", "extra": True}),
            ("target", {"module": "libexternal.so", "extra": True}),
            ("tracer", {"extra": True}),
        )
        for section, replacement in cases:
            payload = self.valid_payload()
            payload[section] = replacement
            with self.subTest(section=section), self.assertRaisesRegex(
                ConfigError, "CONFIG_UNKNOWN_FIELD"
            ):
                load_config(self.write_json(f"unknown-{section}.json", payload))

    def test_rejects_schema_versions_other_than_integer_one(self):
        for value in (0, 2, "1", True, None):
            payload = self.valid_payload()
            payload["schemaVersion"] = value
            with self.subTest(value=value), self.assertRaisesRegex(
                ConfigError, "CONFIG_SCHEMA_INVALID"
            ):
                load_config(self.write_json("schema.json", payload))

    def test_rejects_duplicate_too_many_too_long_and_empty_scene_names(self):
        invalid_scenes = (
            [
                {"name": "same", "symbol": "first"},
                {"name": "same", "symbol": "second"},
            ],
            [{"name": f"scene-{index}", "symbol": "work"} for index in range(257)],
            [{"name": "界" * 43, "symbol": "work"}],
            [{"name": "", "symbol": "work"}],
        )
        expected_codes = (
            "SCENE_NAME_DUPLICATE",
            "SCENE_COUNT_INVALID",
            "SCENE_NAME_INVALID",
            "SCENE_NAME_INVALID",
        )
        for scenes, code in zip(invalid_scenes, expected_codes):
            payload = self.valid_payload()
            payload["scenes"] = scenes
            with self.subTest(code=code), self.assertRaisesRegex(ConfigError, code):
                load_config(self.write_json(f"{code}.json", payload))

    def test_accepts_scene_name_at_128_utf8_bytes(self):
        payload = self.valid_payload()
        payload["scenes"] = [{"name": "界" * 42 + "ab", "symbol": "work"}]

        config = load_config(self.write_json("name-boundary.json", payload))

        self.assertEqual(len(config.scenes[0].name.encode("utf-8")), 128)

    def test_rejects_empty_or_non_array_scenes(self):
        for scenes in ([], None, {}, "one"):
            payload = self.valid_payload()
            payload["scenes"] = scenes
            with self.subTest(scenes=scenes), self.assertRaisesRegex(
                ConfigError, "SCENE_COUNT_INVALID"
            ):
                load_config(self.write_json("scene-count.json", payload))

    def test_rejects_non_string_package_module_binary_path_and_symbol_values(self):
        cases = (
            ("app", {"package": 7}),
            ("app", {"package": "com.example.external", "apk": 7}),
            ("target", {"module": 7}),
            ("target", {"module": "libexternal.so", "binary": 7}),
            ("tracer", {"library": 7, "companion": "companion.so"}),
            ("tracer", {"library": "tracer.so", "companion": 7}),
            ("scenes", [{"name": "one", "symbol": 7}]),
        )
        for index, (section, replacement) in enumerate(cases):
            payload = self.valid_payload()
            payload[section] = replacement
            with self.subTest(index=index), self.assertRaisesRegex(
                ConfigError, "CONFIG_TYPE_INVALID"
            ):
                load_config(self.write_json(f"type-{index}.json", payload))

    def test_rejects_integer_non_hex_zero_unaligned_and_reversed_offsets(self):
        cases = (
            {"startOffset": 0x120, "endOffset": "0x180"},
            {"startOffset": "288", "endOffset": "0x180"},
            {"startOffset": "0x0", "endOffset": "0x180"},
            {"startOffset": "0x122", "endOffset": "0x180"},
            {"startOffset": "0x120", "endOffset": "0x182"},
            {"startOffset": "0x180", "endOffset": "0x180"},
            {"startOffset": "0x184", "endOffset": "0x180"},
        )
        for index, offsets in enumerate(cases):
            payload = self.valid_payload()
            payload["scenes"] = [{"name": "offset", **offsets}]
            with self.subTest(index=index), self.assertRaisesRegex(
                ConfigError, "SCENE_OFFSET_INVALID"
            ):
                load_config(self.write_json(f"offset-{index}.json", payload))

    def test_rejects_incomplete_or_unknown_scene_forms(self):
        cases = (
            {"name": "one"},
            {"name": "one", "startOffset": "0x120"},
            {"name": "one", "endOffset": "0x180"},
            {"name": "one", "symbol": "work", "extra": True},
        )
        for index, scene in enumerate(cases):
            payload = self.valid_payload()
            payload["scenes"] = [scene]
            with self.subTest(index=index), self.assertRaisesRegex(
                ConfigError, "SCENE_FORM_INVALID"
            ):
                load_config(self.write_json(f"form-{index}.json", payload))

    def test_rejects_missing_unknown_or_forbidden_flight_entry_scene(self):
        tracer_cases = (
            {"flightEnabled": True},
            {"flightEnabled": True, "flightEntryScene": "missing"},
            {"flightEnabled": False, "flightEntryScene": "one"},
            {"flightEntryScene": "one"},
        )
        for index, tracer in enumerate(tracer_cases):
            payload = self.valid_payload()
            payload["tracer"] = tracer
            with self.subTest(index=index), self.assertRaisesRegex(
                ConfigError, "FLIGHT_ENTRY_SCENE_INVALID"
            ):
                load_config(self.write_json(f"flight-entry-{index}.json", payload))

    def test_rejects_unpaired_prebuilt_tracer_paths(self):
        for tracer in ({"library": "tracer.so"}, {"companion": "companion.so"}):
            payload = self.valid_payload()
            payload["tracer"] = tracer
            with self.subTest(tracer=tracer), self.assertRaisesRegex(
                ConfigError, "TRACER_PATH_PAIR_INVALID"
            ):
                load_config(self.write_json("tracer-pair.json", payload))

    def test_rejects_invalid_profile_and_boolean_tracer_options(self):
        for tracer in (
            {"profile": "debug"},
            {"profile": 1},
            {"compression": 1},
            {"flightEnabled": "true", "flightEntryScene": "one"},
        ):
            payload = self.valid_payload()
            payload["tracer"] = tracer
            with self.subTest(tracer=tracer), self.assertRaises(ConfigError):
                load_config(self.write_json("tracer-option.json", payload))

    def test_rejects_invalid_json_and_non_object_sections(self):
        invalid_json = Path(self.directory.name) / "invalid.json"
        invalid_json.write_text("{", encoding="utf-8")
        with self.assertRaisesRegex(ConfigError, "CONFIG_JSON_INVALID"):
            load_config(invalid_json)

        for payload in ([], None, "config"):
            with self.subTest(payload=payload), self.assertRaisesRegex(
                ConfigError, "CONFIG_TYPE_INVALID"
            ):
                load_config(self.write_json("root-type.json", payload))

        for section in ("app", "target", "tracer"):
            payload = self.valid_payload()
            payload[section] = []
            with self.subTest(section=section), self.assertRaisesRegex(
                ConfigError, "CONFIG_TYPE_INVALID"
            ):
                load_config(self.write_json(f"section-{section}.json", payload))


if __name__ == "__main__":
    unittest.main()
