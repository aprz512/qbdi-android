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
        state: 'installing',
        warnings: [
          {code: 'SCENE_WARNING_ONE', message: 'first scene warning'},
          {code: 'SCENE_WARNING_TWO', message: 'second scene warning'}
        ]
      }]
    }));
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

    def test_renders_every_warning_with_warning_prefix(self):
        lines = self.exports.renderwarnings()
        warning_lines = [line for line in lines if line.startswith("[!]")]

        self.assertEqual(4, len(warning_lines))
        self.assertTrue(any("configuration warning" in line for line in warning_lines))
        self.assertTrue(any("status warning" in line for line in warning_lines))
        self.assertTrue(any("first scene warning" in line for line in warning_lines))
        self.assertTrue(any("second scene warning" in line for line in warning_lines))

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
