import unittest

from qtrace.errors import (
    EXIT_ERROR,
    EXIT_INTERRUPTED,
    EXIT_OK,
    EXIT_PARTIAL,
    EXIT_STOP_INCOMPLETE,
    ConfigError,
    ErrorCode,
    QtraceError,
)


class ExitCodeTests(unittest.TestCase):
    def test_stable_exit_codes(self):
        self.assertEqual((EXIT_OK, EXIT_ERROR, EXIT_PARTIAL, EXIT_STOP_INCOMPLETE), (0, 1, 2, 3))
        self.assertEqual(EXIT_INTERRUPTED, 130)


class QtraceErrorTests(unittest.TestCase):
    def test_formats_enum_code_as_one_stable_line(self):
        error = QtraceError(
            ErrorCode.DEVICE_NOT_FOUND,
            "preflight",
            "device serial is unavailable",
        )

        self.assertEqual(error.code, "DEVICE_NOT_FOUND")
        self.assertEqual(error.stage, "preflight")
        self.assertEqual(error.detail, "device serial is unavailable")
        self.assertEqual(error.exit_code, EXIT_ERROR)
        self.assertEqual(
            str(error),
            "qtrace: stage=preflight code=DEVICE_NOT_FOUND detail=device serial is unavailable",
        )

    def test_preserves_plain_string_code_and_custom_exit_code(self):
        error = QtraceError("CONFIG_UNKNOWN_FIELD", "config", "unknown root key", exit_code=7)

        self.assertEqual(error.code, "CONFIG_UNKNOWN_FIELD")
        self.assertEqual(error.exit_code, 7)
        self.assertIn("code=CONFIG_UNKNOWN_FIELD", str(error))

    def test_replaces_newlines_in_stored_and_formatted_detail(self):
        error = QtraceError("BROKEN", "test", "first\r\nsecond\nthird\rfourth")

        self.assertEqual(error.detail, "first  second third fourth")
        self.assertNotIn("\n", str(error))
        self.assertNotIn("\r", str(error))

    def test_truncates_detail_to_512_utf8_bytes_without_splitting_codepoint(self):
        error = QtraceError("BROKEN", "test", "a" * 510 + "界界")

        self.assertEqual(error.detail, "a" * 510)
        self.assertLessEqual(len(error.detail.encode("utf-8")), 512)
        self.assertTrue(str(error).endswith("detail=" + "a" * 510))

    def test_config_error_uses_config_stage_and_plain_string_code(self):
        error = ConfigError("CONFIG_VALUE_INVALID", "bad value")

        self.assertEqual(error.stage, "config")
        self.assertEqual(error.code, "CONFIG_VALUE_INVALID")
        self.assertEqual(error.exit_code, EXIT_ERROR)


class ErrorCodeTests(unittest.TestCase):
    def test_declares_required_stable_codes(self):
        self.assertEqual(
            {code.value for code in ErrorCode},
            {
                "DEVICE_NOT_FOUND",
                "SESSION_BUSY",
                "FRIDA_VERSION_MISMATCH",
                "PACKAGE_NOT_INSTALLED",
                "UNSUPPORTED_ABI",
                "TARGET_MODULE_NOT_FOUND",
                "SYMBOL_NOT_FOUND",
                "SYMBOL_SIZE_INVALID",
                "TARGET_IDENTITY_MISMATCH",
                "TRACER_LOAD_FAILED",
                "HOOK_INSTALL_FAILED",
                "PROCESS_EXITED_DURING_SETUP",
                "STOP_NOT_ACKNOWLEDGED",
                "ARTIFACT_INCOMPLETE",
                "ARTIFACT_INTEGRITY_FAILED",
                "ADB_UNAVAILABLE",
                "ADB_PULL_FAILED",
            },
        )


if __name__ == "__main__":
    unittest.main()
