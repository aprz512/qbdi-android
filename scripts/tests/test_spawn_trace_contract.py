import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPAWN_TRACE = ROOT / "scripts/spawn_trace.js"
RETENTION_ACCEPTANCE = ROOT / "scripts/config_retention_acceptance.py"


class SpawnTraceContractTests(unittest.TestCase):
    def test_spawn_trace_is_the_only_interactive_configuration_source(self):
        source = SPAWN_TRACE.read_text(encoding="utf-8")

        self.assertFalse((ROOT / "scripts/trace_config.js").exists())
        self.assertIn("JSON.stringify(config.tracer)", source)
        self.assertIn("qbdi_tracer_configure_json", source)
        self.assertIn("qbdi_tracer_get_status_json", source)
        self.assertNotIn("function encodeConfig", source)
        self.assertNotIn("scene=", source)

    def test_spawn_trace_uses_the_structured_abi_signatures(self):
        source = SPAWN_TRACE.read_text(encoding="utf-8")

        self.assertIn(
            "'int32', ['pointer', 'uint64', 'pointer', 'uint64', 'pointer']",
            source,
        )
        self.assertIn(
            "'int32', ['uint64', 'pointer', 'uint64', 'pointer']", source
        )
        self.assertIn("const INITIAL_RESPONSE_CAPACITY = 16 * 1024", source)
        self.assertIn("const MAX_JSON_BYTES = 1024 * 1024", source)

    def test_spawn_trace_exposes_testable_helpers_without_changing_startup(self):
        source = SPAWN_TRACE.read_text(encoding="utf-8")

        for helper in (
            "utf8ByteLength",
            "callJsonAbi",
            "validateConfigureResponse",
            "validateStatusResponse",
            "renderConfigureResponse",
            "renderStatusResponse",
            "pollGeneration",
        ):
            with self.subTest(helper=helper):
                self.assertIn(f"function {helper}", source)
        self.assertIn("if (globalThis.__QTRACE_TEST__ !== true) {", source)
        self.assertIn("setImmediate(main);", source)

    def test_retention_acceptance_reuses_spawn_configuration(self):
        spawn_source = SPAWN_TRACE.read_text(encoding="utf-8")
        self.assertTrue(RETENTION_ACCEPTANCE.is_file())
        harness_source = RETENTION_ACCEPTANCE.read_text(encoding="utf-8")

        self.assertIn("function runConfigurationRetentionAcceptance", spawn_source)
        self.assertIn("scripts/spawn_trace.js", harness_source)
        self.assertIn("globalThis.__QTRACE_TEST__ = true", harness_source)
        self.assertIn("runConfigurationRetentionAcceptance()", harness_source)
        self.assertNotIn("schemaVersion", harness_source)


if __name__ == "__main__":
    unittest.main()
