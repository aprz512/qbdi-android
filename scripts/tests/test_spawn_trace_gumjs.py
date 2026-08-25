import json
import os
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUN_HOST_TESTS = os.environ.get("QTRACE_RUN_FRIDA_HOST_TESTS") == "1"


@unittest.skipUnless(
    RUN_HOST_TESTS, "set QTRACE_RUN_FRIDA_HOST_TESTS=1 to run Frida host tests"
)
class SpawnTraceGumJsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import frida

        source = (ROOT / "scripts/spawn_trace.js").read_text(encoding="utf-8")
        wrappers = r"""
rpc.exports = {
  utf8bytes(value) {
    return utf8ByteLength(value);
  },

  retryonce() {
    let calls = 0;
    const payload = JSON.stringify({ok: true, value: 'retried'});
    const response = callJsonAbi((buffer, capacity, responseSize) => {
      calls += 1;
      if (calls === 1) {
        responseSize.writeU64(new UInt64(20000));
        return QTRACE_JSON_RESPONSE_TOO_SMALL;
      }
      buffer.writeUtf8String(payload);
      responseSize.writeU64(new UInt64(utf8ByteLength(payload) + 1));
      return QTRACE_JSON_OK;
    });
    return {calls, response};
  },

  retrylimit() {
    let calls = 0;
    let error = null;
    try {
      callJsonAbi((buffer, capacity, responseSize) => {
        calls += 1;
        if (calls <= 2) {
          responseSize.writeU64(new UInt64(calls === 1 ? 20000 : 30000));
          return QTRACE_JSON_RESPONSE_TOO_SMALL;
        }
        const payload = JSON.stringify({ok: true});
        buffer.writeUtf8String(payload);
        responseSize.writeU64(new UInt64(utf8ByteLength(payload) + 1));
        return QTRACE_JSON_OK;
      });
    } catch (caught) {
      error = String(caught);
    }
    return {calls, error};
  },

  invalidresponses() {
    const accepted = {
      responseSchemaVersion: 1,
      ok: true,
      generation: 7,
      state: 'waiting_for_module',
      targetModule: 'libdemo_target.so',
      scenes: [{name: 'init', offset: '0x6ac90', endOffset: null}],
      warnings: []
    };
    const status = {
      responseSchemaVersion: 1,
      ok: true,
      generation: 7,
      state: 'installing',
      targetModule: 'libdemo_target.so',
      moduleBase: '0x70000000',
      scenes: [{
        name: 'init',
        offset: '0x6ac90',
        runtimeAddress: '0x7006ac90',
        runtimeEnd: null,
        state: 'installing',
        warnings: []
      }],
      warnings: []
    };
    const cases = [
      ['configure', {...accepted, responseSchemaVersion: 2}],
      ['configure', {...accepted, ok: 'false'}],
      ['configure', {...accepted, generation: undefined}],
      ['configure', {...accepted, state: undefined}],
      ['configure', {...accepted, scenes: {}}],
      ['configure', {...accepted, warnings: {}}],
      ['configure', {
        responseSchemaVersion: 1,
        ok: false,
        error: {code: 'BAD', path: '$'}
      }],
      ['status', {...status, responseSchemaVersion: 2}],
      ['status', {...status, scenes: undefined}],
      ['status', {...status, warnings: undefined}]
    ];
    return cases.map(([kind, response]) => {
      try {
        if (kind === 'configure') renderConfigureResponse(response);
        else renderStatusResponse(response);
        return null;
      } catch (error) {
        return String(error);
      }
    });
  },

  renderwarnings() {
    return renderConfigureResponse({
      responseSchemaVersion: 1,
      ok: true,
      generation: 7,
      state: 'waiting_for_module',
      targetModule: 'libdemo_target.so',
      scenes: [{name: 'init', offset: '0x6ac90', endOffset: null}],
      warnings: [{code: 'CONFIG_WARNING', message: 'configuration warning'}]
    }).concat(renderStatusResponse({
      responseSchemaVersion: 1,
      ok: true,
      generation: 7,
      state: 'installing',
      targetModule: 'libdemo_target.so',
      moduleBase: '0x70000000',
      warnings: [{code: 'STATUS_WARNING', message: 'status warning'}],
      scenes: [{
        name: 'init',
        offset: '0x6ac90',
        runtimeAddress: '0x7006ac90',
        runtimeEnd: null,
        state: 'installing',
        warnings: [
          {code: 'SCENE_WARNING_ONE', message: 'first scene warning'},
          {code: 'SCENE_WARNING_TWO', message: 'second scene warning'}
        ]
      }]
    }));
  },

  renderrollback() {
    return renderStatusResponse({
      responseSchemaVersion: 1,
      ok: true,
      generation: 11,
      state: 'hook_failed',
      targetModule: 'libdemo_target.so',
      moduleBase: '0x70000000',
      warnings: [],
      scenes: [
        {
          name: 'init',
          offset: '0x6ac90',
          runtimeAddress: '0x7006ac90',
          runtimeEnd: null,
          state: 'rolled_back',
          warnings: []
        },
        {
          name: 'algorithm',
          offset: '0x6db38',
          runtimeAddress: '0x7006db38',
          runtimeEnd: null,
          state: 'hook_failed',
          warnings: [],
          error: {code: 'HOOK_INSTALL_FAILED', hookError: 73}
        }
      ]
    });
  },

  pollstatuses(payloads) {
    let calls = 0;
    const scheduled = [];
    const emitted = [];
    const getStatus = () => payloads[calls++];
    const schedule = callback => scheduled.push(callback);
    pollGeneration(getStatus, schedule, line => emitted.push(line));
    while (scheduled.length !== 0 && calls < 20) scheduled.shift()();
    return {calls, emitted, pending: scheduled.length};
  }
};
"""
        cls.session = frida.get_local_device().attach(os.getpid())
        cls.script = cls.session.create_script(
            "globalThis.__QTRACE_TEST__ = true;\n" + source + "\n" + wrappers
        )
        cls.script.load()
        cls.exports = cls.script.exports_sync

    @classmethod
    def tearDownClass(cls):
        cls.script.unload()
        cls.session.detach()

    def test_counts_multibyte_utf8_without_address_number_conversion(self):
        value = "Aé中😀"

        self.assertEqual(len(value.encode("utf-8")), self.exports.utf8bytes(value))

    def test_retries_once_with_the_reported_response_capacity(self):
        result = self.exports.retryonce()

        self.assertEqual(2, result["calls"])
        self.assertEqual(
            {"ok": True, "value": "retried"}, json.loads(result["response"])
        )

    def test_refuses_a_second_response_too_small_result(self):
        result = self.exports.retrylimit()

        self.assertEqual(2, result["calls"])
        self.assertIn("more than once", result["error"])

    def test_rejects_malformed_or_unsupported_responses_before_rendering(self):
        errors = self.exports.invalidresponses()

        self.assertEqual(10, len(errors))
        for error in errors:
            with self.subTest(error=error):
                self.assertIn("invalid JSON ABI response", error)

    def test_renders_every_warning_with_warning_prefix(self):
        lines = self.exports.renderwarnings()
        warning_lines = [line for line in lines if line.startswith("[!]")]

        self.assertEqual(4, len(warning_lines))
        self.assertTrue(any("configuration warning" in line for line in warning_lines))
        self.assertTrue(any("status warning" in line for line in warning_lines))
        self.assertTrue(any("first scene warning" in line for line in warning_lines))
        self.assertTrue(any("second scene warning" in line for line in warning_lines))

    def test_renders_rolled_back_scenes_and_completed_rollback(self):
        lines = self.exports.renderrollback()

        self.assertIn("[+] scene init rolled back", lines)
        self.assertTrue(
            any("scene algorithm hook_failed" in line for line in lines)
        )
        self.assertIn(
            "[-] generation 11 finished with hook_failed; rollback complete", lines
        )

    def test_suppresses_unchanged_status_and_stops_at_terminal_state(self):
        waiting = {
            "responseSchemaVersion": 1,
            "ok": True,
            "generation": 9,
            "state": "waiting_for_module",
            "targetModule": "libdemo_target.so",
            "moduleBase": None,
            "scenes": [],
            "warnings": [],
        }
        installed = {
            **waiting,
            "state": "installed",
            "moduleBase": "0x70000000",
        }
        unreachable = {**waiting, "state": "hook_failed"}
        payloads = [
            json.dumps(waiting, separators=(",", ":")),
            json.dumps(waiting, separators=(",", ":")),
            json.dumps(installed, separators=(",", ":")),
            json.dumps(unreachable, separators=(",", ":")),
        ]

        result = self.exports.pollstatuses(payloads)

        self.assertEqual(3, result["calls"])
        self.assertEqual(0, result["pending"])
        self.assertEqual(
            1,
            sum("waiting for libdemo_target.so" in line for line in result["emitted"]),
        )
        self.assertEqual(
            1,
            sum("generation 9 installed" in line for line in result["emitted"]),
        )


if __name__ == "__main__":
    unittest.main()
