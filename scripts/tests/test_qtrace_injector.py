import copy
import json
import math
import multiprocessing
import os
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from qtrace.errors import ErrorCode, QtraceError
from qtrace.injector import FridaInjector, FridaProvider, InjectionRequest
from qtrace.models import ResolvedScene


SESSION_ID = "7d5807cf-cf09-4f21-92de-1ad92802610a"
PACKAGE = "com.example.external"
TRACER_SO = "/data/user/0/com.example.external/files/qtrace/libqbdi_tracer.so"
COMPANION = "/data/user/0/com.example.external/files/qtrace/libshadowhook_nothing.so"
TARGET_MODULE = "libexternal_target.so"
AGENT_PATH = Path(__file__).resolve().parents[2] / "qtrace" / "agent.js"


def native_request():
    return {
        "schemaVersion": 1,
        "packageName": PACKAGE,
        "targetModule": TARGET_MODULE,
        "trace": {
            "profile": "fast",
            "compression": True,
            "lz4Level": 2,
            "autoBuffer": True,
            "bufferMb": 0,
            "hexdumpLimit": 32,
        },
        "flight": {
            "enabled": False,
            "entryScene": "",
            "capacityMb": 512,
            "chunkKb": 256,
            "maxThreads": 256,
            "protectedChunks": 4,
        },
        "scenes": [
            {
                "name": "entry",
                "location": {"offset": "0x100", "endOffset": "0x140"},
            },
            {
                "name": "worker",
                "location": {"offset": "0x200", "endOffset": "0x280"},
            },
        ],
        "session": {"id": SESSION_ID, "durationMs": 500},
    }


def initialization_status(*, generation=7, state="waiting_for_module"):
    return {
        "responseSchemaVersion": 1,
        "ok": True,
        "generation": generation,
        "state": state,
        "targetModule": TARGET_MODULE,
        "session": {"id": SESSION_ID, "durationMs": 500},
        "scenes": [
            {"name": "entry", "offset": "0x100", "endOffset": "0x140"},
            {"name": "worker", "offset": "0x200", "endOffset": "0x280"},
        ],
        "warnings": [],
    }


def final_status(*, generation=7, state="installed"):
    scene_state = "installed" if state == "installed" else state
    return {
        "responseSchemaVersion": 1,
        "ok": True,
        "generation": generation,
        "state": state,
        "targetModule": TARGET_MODULE,
        "moduleBase": "0x71000000",
        "session": {"id": SESSION_ID, "durationMs": 500},
        "scenes": [
            {
                "name": "entry",
                "offset": "0x100",
                "runtimeAddress": "0x71000100",
                "runtimeEnd": "0x71000140",
                "state": scene_state,
                "warnings": [],
            },
            {
                "name": "worker",
                "offset": "0x200",
                "runtimeAddress": "0x71000200",
                "runtimeEnd": "0x71000280",
                "state": scene_state,
                "warnings": [],
            },
        ],
        "warnings": [],
    }


def initialized_message(status=None, *, session_id=SESSION_ID, generation=7):
    return {
        "type": "send",
        "payload": {
            "type": "initialized",
            "sessionId": session_id,
            "generation": generation,
            "status": initialization_status() if status is None else status,
        },
    }


def installed_message(status=None, *, session_id=SESSION_ID, generation=7):
    return {
        "type": "send",
        "payload": {
            "type": "installed",
            "sessionId": session_id,
            "generation": generation,
            "status": final_status() if status is None else status,
        },
    }


def error_message(code, *, stage="load", detail="agent rejected startup"):
    return {
        "type": "send",
        "payload": {"type": "error", "stage": stage, "code": code, "detail": detail},
    }


class SharedLog:
    """One-writer-at-a-time observation log that survives the worker fork."""

    def __init__(self):
        self._reader, self._writer = multiprocessing.get_context("fork").Pipe(duplex=False)
        self._items = []

    def append(self, item):
        self._writer.send(item)

    def extend(self, items):
        for item in items:
            self.append(item)

    def snapshot(self):
        while self._reader.poll():
            self._items.append(self._reader.recv())
        return list(self._items)

    def __contains__(self, item):
        return item in self.snapshot()

    def __getitem__(self, item):
        return self.snapshot()[item]

    def __iter__(self):
        return iter(self.snapshot())

    def __len__(self):
        return len(self.snapshot())

    def index(self, item):
        return self.snapshot().index(item)


class Scenario:
    def __init__(self):
        self.post_messages = [initialized_message()]
        self.resume_messages = [installed_message()]
        self.resume_messages_synchronous = False
        self.resume_detached = None
        self.spawn_error = None
        self.attach_error = None
        self.load_error = None
        self.post_error = None
        self.resume_error = None
        self.unload_error = None
        self.detach_error = None
        self.kill_error = None
        self.kill_sleeps_for_timeout = False


class FakeScript:
    def __init__(self, scenario, events):
        self.scenario = scenario
        self.events = events
        self.handler = None
        self.posts = SharedLog()

    def on(self, event, handler):
        self.events.append(("on", event))
        if event != "message":
            raise AssertionError(f"unexpected script event {event!r}")
        self.handler = handler

    def load(self):
        self.events.append("load")
        if self.scenario.load_error:
            raise self.scenario.load_error

    def post(self, message):
        self.events.append("post")
        self.posts.append(message)
        if self.scenario.post_error:
            raise self.scenario.post_error
        for item in self.scenario.post_messages:
            payload = item.get("payload") if isinstance(item, dict) else None
            if isinstance(payload, dict) and payload.get("type") == "initialized":
                self.events.extend(("set-companion", "configure", "initialized"))
            elif isinstance(payload, dict) and payload.get("type") == "error":
                self.events.append("agent-error")
            self.handler(item, None)

    def unload(self):
        self.events.append("unload")
        if self.scenario.unload_error:
            raise self.scenario.unload_error


class FakeSession:
    def __init__(self, scenario, events, script):
        self.scenario = scenario
        self.events = events
        self.script = script
        self.detached_handler = None
        self.sources = SharedLog()

    def on(self, event, handler):
        self.events.append(("session-on", event))
        if event != "detached":
            raise AssertionError(f"unexpected session event {event!r}")
        self.detached_handler = handler

    def create_script(self, source):
        self.events.append("create")
        self.sources.append(source)
        return self.script

    def detach(self):
        self.events.append("detach")
        if self.scenario.detach_error:
            raise self.scenario.detach_error


class FakeFridaDevice:
    def __init__(self, scenario, events):
        self.scenario = scenario
        self.events = events
        self.script = FakeScript(scenario, events)
        self.session = FakeSession(scenario, events, self.script)

    def spawn(self, argv):
        self.events.append(("spawn", tuple(argv)))
        if self.scenario.spawn_error:
            raise self.scenario.spawn_error
        return 4242

    def attach(self, pid):
        self.events.append(("attach", pid))
        if self.scenario.attach_error:
            raise self.scenario.attach_error
        return self.session

    def resume(self, pid):
        self.events.append(("resume", pid))
        if self.scenario.resume_error:
            raise self.scenario.resume_error
        if self.scenario.resume_detached is not None:
            reason, crash = self.scenario.resume_detached
            self.session.detached_handler(reason, crash)
        if not self.scenario.resume_messages:
            return
        if self.scenario.resume_messages_synchronous:
            self._deliver_resume_messages()
            return
        delivery = threading.Thread(
            target=self._deliver_resume_messages_after_return,
            name="fake-frida-resume-message",
            daemon=True,
        )
        delivery.start()

    def _deliver_resume_messages_after_return(self):
        mailbox = self.script.handler.__self__
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            with mailbox.lock:
                resumed = mailbox.resume_phase == "resumed"
            if resumed:
                self._deliver_resume_messages()
                return
            time.sleep(0.001)

    def _deliver_resume_messages(self):
        for item in self.scenario.resume_messages:
            payload = item.get("payload") if isinstance(item, dict) else None
            if isinstance(payload, dict) and payload.get("type") == "installed":
                self.events.extend(("status", "installed"))
            elif isinstance(payload, dict) and payload.get("type") == "error":
                self.events.append("agent-error")
            self.script.handler(item, None)


class FakeProvider:
    def __init__(self, scenario, events, *, error=None):
        self.events = events
        self.error = error
        self.device = FakeFridaDevice(scenario, events)
        self.calls = []

    def get_device(self, adb_device, timeout):
        self.events.append("provider")
        self.calls.append((adb_device, timeout))
        if self.error:
            raise self.error
        return self.device


class FakeAdbDevice:
    serial = "SERIAL"
    package = PACKAGE

    def __init__(self, scenario, events):
        self.scenario = scenario
        self.events = events
        self.kill_calls = []
        self.kill_timeouts = []

    def shell(self, *args, timeout, maximum_bytes):
        self.events.append(("adb", tuple(args)))
        if args != ("am", "force-stop", PACKAGE):
            raise AssertionError(f"unexpected ADB shell call {args!r}")
        if not math.isfinite(timeout) or timeout <= 0 or maximum_bytes <= 0:
            raise AssertionError("force-stop must be bounded")
        return b""

    def target_shell(self, *args, timeout, maximum_bytes):
        self.events.append(("target", tuple(args)))
        self.kill_calls.append(tuple(args))
        self.kill_timeouts.append(timeout)
        if self.scenario.kill_error:
            raise self.scenario.kill_error
        if self.scenario.kill_sleeps_for_timeout:
            time.sleep(timeout)
        return b""


class InjectorHarness:
    def __init__(self, scenario=None):
        self.scenario = scenario or Scenario()
        self.events = SharedLog()
        self.adb = FakeAdbDevice(self.scenario, self.events)
        self.provider = FakeProvider(self.scenario, self.events)
        self.injector = FridaInjector(self.adb, self.provider)

    def request(self, **changes):
        values = {
            "package": PACKAGE,
            "session_id": SESSION_ID,
            "tracer_so": TRACER_SO,
            "companion": COMPANION,
            "native_request": native_request(),
            "setup_timeout": 5.0,
        }
        values.update(changes)
        return InjectionRequest(**values)

    def install(self, request=None):
        return self.injector.install(request or self.request())


class FridaInjectorTests(unittest.TestCase):
    def test_installs_in_exact_order_posts_one_static_envelope_and_detaches(self):
        harness = InjectorHarness()

        result = harness.install()

        self.assertEqual(
            [
                ("adb", ("am", "force-stop", PACKAGE)),
                "provider",
                ("spawn", (PACKAGE,)),
                ("attach", 4242),
                ("session-on", "detached"),
                "create",
                ("on", "message"),
                "load",
                "post",
                "set-companion",
                "configure",
                "initialized",
                ("resume", 4242),
                "status",
                "installed",
                "unload",
                "detach",
            ],
            harness.events.snapshot(),
        )
        script = harness.provider.device.script
        self.assertEqual(1, len(script.posts))
        self.assertEqual("qtrace-startup", script.posts[0]["type"])
        envelope = script.posts[0]["payload"]
        self.assertEqual(PACKAGE, envelope["package"])
        self.assertEqual(SESSION_ID, envelope["sessionId"])
        self.assertEqual(TRACER_SO, envelope["tracerSo"])
        self.assertEqual(COMPANION, envelope["companion"])
        self.assertEqual(native_request(), envelope["nativeRequest"])
        self.assertIs(type(envelope["setupTimeoutMs"]), int)
        self.assertTrue(0 < envelope["setupTimeoutMs"] <= 5000)
        sources = harness.provider.device.session.sources
        self.assertEqual([AGENT_PATH.read_text(encoding="utf-8")], sources.snapshot())
        self.assertNotIn(PACKAGE, sources[0])
        self.assertNotIn(SESSION_ID, sources[0])
        self.assertEqual(
            (
                ResolvedScene("entry", 0x100, 0x140),
                ResolvedScene("worker", 0x200, 0x280),
            ),
            result.normalized_scenes,
        )
        self.assertEqual((4242, SESSION_ID, 7), (result.pid, result.session_id, result.generation))
        self.assertEqual([], harness.adb.kill_calls)

    def test_rejects_invalid_request_fields_before_any_side_effect(self):
        cases = []
        bad_package_request = native_request()
        bad_package_request["packageName"] = "com.example.other"
        bad_session_request = native_request()
        bad_session_request["session"]["id"] = "8df7c64a-648e-4787-94ad-6fd4ad04a4d4"
        nonfinite = native_request()
        nonfinite["trace"]["bufferMb"] = math.nan
        non_string_key = native_request()
        non_string_key[1] = "bad"
        cases.extend(
            (
                {"package": "invalid"},
                {"session_id": SESSION_ID.upper()},
                {"tracer_so": "relative.so"},
                {"tracer_so": "/data/local/tmp/../tracer.so"},
                {"companion": "/data/local/tmp/helper so"},
                {"setup_timeout": 0},
                {"setup_timeout": math.inf},
                {"native_request": bad_package_request},
                {"native_request": bad_session_request},
                {"native_request": nonfinite},
                {"native_request": non_string_key},
                {"native_request": {"packageName": PACKAGE, "session": {"id": SESSION_ID}}},
            )
        )
        for changes in cases:
            harness = InjectorHarness()
            with self.subTest(changes=changes), self.assertRaises(QtraceError):
                harness.install(harness.request(**changes))
            self.assertEqual([], harness.events.snapshot())

        harness = InjectorHarness()
        oversized = native_request()
        oversized["padding"] = "x" * (1024 * 1024)
        with self.assertRaises(QtraceError):
            harness.install(harness.request(native_request=oversized))
        self.assertEqual([], harness.events.snapshot())

    def test_module_load_is_authoritative_for_ok_and_deferred_deployments(self):
        for load_probe_status in ("ok", "deferred"):
            scenario = Scenario()
            scenario.post_messages = [error_message(
                ErrorCode.TRACER_LOAD_FAILED.value,
                detail=f"authoritative load failed after {load_probe_status} probe",
            )]
            harness = InjectorHarness(scenario)

            with self.subTest(load_probe_status=load_probe_status), self.assertRaises(
                QtraceError
            ) as caught:
                harness.install()

            self.assertEqual(ErrorCode.TRACER_LOAD_FAILED.value, caught.exception.code)
            self.assertEqual([("kill", "-9", "4242")], harness.adb.kill_calls)
            self.assertIn("unload", harness.events)
            self.assertIn("detach", harness.events)
            self.assertFalse(any(event == ("resume", 4242) for event in harness.events))

    def test_agent_native_transport_rejection_and_malformed_response_are_stable_errors(self):
        for code in (
            "NATIVE_CONFIG_TRANSPORT_FAILED",
            "NATIVE_CONFIG_REJECTED",
            "NATIVE_RESPONSE_MALFORMED",
        ):
            scenario = Scenario()
            scenario.post_messages = [error_message(code, stage="configure")]
            harness = InjectorHarness(scenario)
            with self.subTest(code=code), self.assertRaises(QtraceError) as caught:
                harness.install()
            self.assertEqual(code, caught.exception.code)
            self.assertEqual([("kill", "-9", "4242")], harness.adb.kill_calls)

    def test_rejects_malformed_outer_messages_data_and_script_errors(self):
        cases = (
            {"payload": initialized_message()["payload"]},
            {"type": "send", "payload": "not-an-object"},
            {"type": "log", "payload": initialized_message()["payload"]},
            {"type": "send", "payload": {"type": "unknown"}},
            {"type": "error", "description": "agent exploded\nstack"},
        )
        for message in cases:
            scenario = Scenario()
            scenario.post_messages = [message]
            harness = InjectorHarness(scenario)
            with self.subTest(message=message), self.assertRaises(QtraceError):
                harness.install()
            self.assertEqual([("kill", "-9", "4242")], harness.adb.kill_calls)

        scenario = Scenario()
        harness = InjectorHarness(scenario)
        original_post = harness.provider.device.script.post

        def post_with_data(message):
            harness.provider.device.script.posts.append(message)
            harness.provider.device.script.handler(initialized_message(), b"unexpected")

        harness.provider.device.script.post = post_with_data
        with self.assertRaises(QtraceError):
            harness.install()
        self.assertEqual([("kill", "-9", "4242")], harness.adb.kill_calls)
        self.assertTrue(callable(original_post))

    def test_rejects_message_order_duplicates_and_identity_mismatches(self):
        wrong_generation_status = initialization_status(generation=8)
        wrong_session_status = initialization_status()
        wrong_session_status["session"]["id"] = "8df7c64a-648e-4787-94ad-6fd4ad04a4d4"
        wrong_module_status = initialization_status()
        wrong_module_status["targetModule"] = "libother.so"
        wrong_scenes_status = initialization_status()
        wrong_scenes_status["scenes"].reverse()
        cases = (
            [installed_message()],
            [initialized_message(), initialized_message()],
            [initialized_message(session_id="8df7c64a-648e-4787-94ad-6fd4ad04a4d4")],
            [initialized_message(generation=0)],
            [initialized_message(status=wrong_generation_status)],
            [initialized_message(status=wrong_session_status)],
            [initialized_message(status=wrong_module_status)],
            [initialized_message(status=wrong_scenes_status)],
        )
        for messages in cases:
            scenario = Scenario()
            scenario.post_messages = messages
            harness = InjectorHarness(scenario)
            with self.subTest(messages=messages), self.assertRaises(QtraceError):
                harness.install()
            self.assertEqual([("kill", "-9", "4242")], harness.adb.kill_calls)

        scenario = Scenario()
        scenario.resume_messages = [installed_message(), installed_message()]
        scenario.resume_messages_synchronous = True
        harness = InjectorHarness(scenario)
        with self.assertRaises(QtraceError):
            harness.install()
        self.assertEqual([], harness.adb.kill_calls)

    def test_rejects_installed_message_that_arrived_before_resume_started(self):
        scenario = Scenario()
        scenario.post_messages = [initialized_message(), installed_message()]
        scenario.resume_messages = []
        harness = InjectorHarness(scenario)

        with self.assertRaises(QtraceError) as caught:
            harness.install()

        self.assertEqual("inject.protocol_invalid", caught.exception.code)
        self.assertFalse(any(event == ("resume", 4242) for event in harness.events))
        self.assertEqual([("kill", "-9", "4242")], harness.adb.kill_calls)

    def test_rejects_installed_message_that_arrived_before_resume_returned(self):
        scenario = Scenario()
        scenario.resume_messages_synchronous = True
        harness = InjectorHarness(scenario)

        with self.assertRaises(QtraceError) as caught:
            harness.install()

        self.assertEqual("inject.protocol_invalid", caught.exception.code)
        self.assertEqual([], harness.adb.kill_calls)

    def test_rejects_final_generation_session_module_and_scene_mismatches(self):
        status_cases = []
        wrong_generation = final_status(generation=8)
        status_cases.append(wrong_generation)
        wrong_session = final_status()
        wrong_session["session"]["id"] = "8df7c64a-648e-4787-94ad-6fd4ad04a4d4"
        status_cases.append(wrong_session)
        wrong_module = final_status()
        wrong_module["targetModule"] = "libother.so"
        status_cases.append(wrong_module)
        wrong_scene = final_status()
        wrong_scene["scenes"][0]["offset"] = "0x104"
        status_cases.append(wrong_scene)
        wrong_scene_state = final_status()
        wrong_scene_state["scenes"][0]["state"] = "installing"
        status_cases.append(wrong_scene_state)
        malformed_schema = final_status()
        malformed_schema["responseSchemaVersion"] = 2
        status_cases.append(malformed_schema)
        for status in status_cases:
            scenario = Scenario()
            scenario.resume_messages = [installed_message(status=status)]
            harness = InjectorHarness(scenario)
            with self.subTest(status=status), self.assertRaises(QtraceError):
                harness.install()
            self.assertEqual([], harness.adb.kill_calls)

    def test_terminal_native_states_map_to_hook_install_failed_without_post_resume_kill(self):
        for state in ("hook_failed", "rollback_failed", "superseded"):
            scenario = Scenario()
            scenario.resume_messages = [error_message(
                ErrorCode.HOOK_INSTALL_FAILED.value,
                stage="status",
                detail=f"generation ended as {state}",
            )]
            harness = InjectorHarness(scenario)
            with self.subTest(state=state), self.assertRaises(QtraceError) as caught:
                harness.install()
            self.assertEqual(ErrorCode.HOOK_INSTALL_FAILED.value, caught.exception.code)
            self.assertEqual([], harness.adb.kill_calls)

    def test_one_deadline_bounds_pre_and_post_resume_waits(self):
        pre_resume = Scenario()
        pre_resume.post_messages = []
        harness = InjectorHarness(pre_resume)
        started = time.monotonic()
        with self.assertRaises(QtraceError) as caught:
            harness.install(harness.request(setup_timeout=0.25))
        self.assertEqual("inject.timeout", caught.exception.code)
        self.assertLess(time.monotonic() - started, 0.75)
        self.assertEqual([("kill", "-9", "4242")], harness.adb.kill_calls)

        post_resume = Scenario()
        post_resume.resume_messages = []
        harness = InjectorHarness(post_resume)
        started = time.monotonic()
        with self.assertRaises(QtraceError) as caught:
            harness.install(harness.request(setup_timeout=0.25))
        self.assertEqual("inject.timeout", caught.exception.code)
        self.assertLess(time.monotonic() - started, 0.75)
        self.assertEqual([], harness.adb.kill_calls)

    def test_pre_resume_kill_uses_budget_reserved_inside_setup_deadline(self):
        scenario = Scenario()
        scenario.post_messages = []
        scenario.kill_sleeps_for_timeout = True
        harness = InjectorHarness(scenario)
        setup_timeout = 0.15

        started = time.monotonic()
        with self.assertRaises(QtraceError) as caught:
            harness.install(harness.request(setup_timeout=setup_timeout))
        elapsed = time.monotonic() - started

        self.assertEqual("inject.timeout", caught.exception.code)
        self.assertEqual([("kill", "-9", "4242")], harness.adb.kill_calls)
        self.assertEqual(1, len(harness.adb.kill_timeouts))
        self.assertLessEqual(harness.adb.kill_timeouts[0], setup_timeout * 0.4)
        self.assertLess(elapsed, setup_timeout + 0.1)

    def test_process_exit_uses_spawned_pid_and_never_kills_after_resume(self):
        scenario = Scenario()
        scenario.resume_messages = []
        scenario.resume_detached = ("process-terminated", None)
        harness = InjectorHarness(scenario)
        with self.assertRaises(QtraceError) as caught:
            harness.install()
        self.assertEqual(ErrorCode.PROCESS_EXITED_DURING_SETUP.value, caught.exception.code)
        self.assertIn("4242", caught.exception.detail)
        self.assertEqual([], harness.adb.kill_calls)

    def test_process_termination_wins_race_with_installed_message(self):
        scenario = Scenario()
        scenario.resume_detached = ("process-terminated", None)
        harness = InjectorHarness(scenario)

        with self.assertRaises(QtraceError) as caught:
            harness.install()

        self.assertEqual(ErrorCode.PROCESS_EXITED_DURING_SETUP.value, caught.exception.code)
        self.assertIn("4242", caught.exception.detail)
        self.assertEqual([], harness.adb.kill_calls)

    def test_non_process_detach_reason_is_not_reported_as_process_exit(self):
        scenario = Scenario()
        scenario.resume_messages = []
        scenario.resume_detached = ("device-lost", None)
        harness = InjectorHarness(scenario)

        with self.assertRaises(QtraceError) as caught:
            harness.install()

        self.assertEqual("frida.session_detached", caught.exception.code)
        self.assertIn("device-lost", caught.exception.detail)
        self.assertEqual([], harness.adb.kill_calls)

    def test_pre_resume_frida_failure_kills_only_exact_spawned_pid(self):
        scenario = Scenario()
        scenario.load_error = RuntimeError("load failed\nraw")
        harness = InjectorHarness(scenario)
        with self.assertRaises(QtraceError) as caught:
            harness.install()
        self.assertEqual("frida.load_failed", caught.exception.code)
        self.assertNotIn("\n", str(caught.exception))
        self.assertEqual([("kill", "-9", "4242")], harness.adb.kill_calls)
        self.assertNotIn(("adb", ("am", "force-stop", PACKAGE)), harness.events[1:])

    def test_keyboard_interrupt_is_preserved_after_stage_aware_cleanup(self):
        scenario = Scenario()
        scenario.load_error = KeyboardInterrupt()
        harness = InjectorHarness(scenario)

        with self.assertRaises(KeyboardInterrupt):
            harness.install()

        self.assertEqual([("kill", "-9", "4242")], harness.adb.kill_calls)
        self.assertIn("unload", harness.events)
        self.assertIn("detach", harness.events)

    def test_cleanup_is_best_effort_and_never_masks_primary_error(self):
        scenario = Scenario()
        scenario.post_messages = [error_message(ErrorCode.TRACER_LOAD_FAILED.value)]
        scenario.unload_error = RuntimeError("unload failed")
        scenario.detach_error = RuntimeError("detach failed")
        scenario.kill_error = QtraceError("device.kill_failed", "inject.cleanup", "kill failed")
        harness = InjectorHarness(scenario)
        with self.assertRaises(QtraceError) as caught:
            harness.install()
        self.assertEqual(ErrorCode.TRACER_LOAD_FAILED.value, caught.exception.code)
        self.assertIn("unload", harness.events)
        self.assertIn("detach", harness.events)
        self.assertEqual([("kill", "-9", "4242")], harness.adb.kill_calls)

    def test_cleanup_failure_without_a_primary_error_is_reported_after_both_attempts(self):
        scenario = Scenario()
        scenario.unload_error = RuntimeError("unload failed")
        scenario.detach_error = RuntimeError("detach failed")
        harness = InjectorHarness(scenario)
        with self.assertRaises(QtraceError) as caught:
            harness.install()
        self.assertEqual("frida.cleanup_failed", caught.exception.code)
        self.assertLess(harness.events.index("unload"), harness.events.index("detach"))
        self.assertEqual([], harness.adb.kill_calls)

    def test_raw_provider_and_frida_errors_are_stable_one_line_qtrace_errors(self):
        scenario = Scenario()
        events = SharedLog()
        provider = FakeProvider(scenario, events, error=OSError("provider\nfailed"))
        adb = FakeAdbDevice(scenario, events)
        injector = FridaInjector(adb, provider)
        with self.assertRaises(QtraceError) as caught:
            injector.install(InjectorHarness().request())
        self.assertEqual("frida.device_failed", caught.exception.code)
        self.assertNotIn("\n", str(caught.exception))

    def test_importing_injector_does_not_import_frida(self):
        probe = subprocess.run(
            [
                sys.executable,
                "-c",
                "import builtins; real=builtins.__import__; "
                "builtins.__import__=lambda name,*a,**k: "
                "(_ for _ in ()).throw(AssertionError('eager frida import')) "
                "if name == 'frida' else real(name,*a,**k); "
                "import qtrace.injector",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(0, probe.returncode, probe.stderr)

    @unittest.skipUnless(hasattr(os, "fork"), "Frida isolation requires POSIX fork")
    def test_blocked_frida_calls_are_killed_and_reaped_inside_the_setup_bound(self):
        context = multiprocessing.get_context("fork")
        blocked_read, blocked_write = os.pipe()
        observed = {}

        def probe(stage, channel):
            scenario = Scenario()
            events = []

            class BlockingScript(FakeScript):
                def unload(self):
                    self.events.append("unload")
                    if stage == "unload":
                        os.read(blocked_read, 1)
                    return super().unload()

            class BlockingSession(FakeSession):
                def __init__(self, scenario, events, script):
                    super().__init__(scenario, events, script)

                def detach(self):
                    self.events.append("detach")
                    if stage == "detach":
                        os.read(blocked_read, 1)

            class BlockingFridaDevice(FakeFridaDevice):
                def __init__(self, scenario, events):
                    self.scenario = scenario
                    self.events = events
                    self.script = BlockingScript(scenario, events)
                    self.session = BlockingSession(scenario, events, self.script)

                def attach(self, pid):
                    self.events.append(("attach", pid))
                    if stage == "attach":
                        os.read(blocked_read, 1)
                    return self.session

                def resume(self, pid):
                    self.events.append(("resume", pid))
                    if stage == "resume":
                        os.read(blocked_read, 1)
                    return super().resume(pid)

            class BlockingProvider(FakeProvider):
                def __init__(self):
                    self.events = events
                    self.error = None
                    self.device = BlockingFridaDevice(scenario, events)
                    self.calls = []

            adb = FakeAdbDevice(scenario, events)
            injector = FridaInjector(adb, BlockingProvider())
            request = InjectorHarness().request(setup_timeout=0.05)
            started = time.monotonic()
            try:
                injector.install(request)
            except QtraceError as error:
                outcome = ("error", error.code)
            except BaseException as error:
                outcome = ("raw", type(error).__name__)
            else:
                outcome = ("success", None)
            channel.send({
                "outcome": outcome,
                "elapsed": time.monotonic() - started,
                "children": [child.pid for child in multiprocessing.active_children()],
                "kills": adb.kill_calls,
            })
            channel.close()

        try:
            for stage in ("attach", "resume", "unload", "detach"):
                receiver, sender = context.Pipe(duplex=False)
                process = context.Process(target=probe, args=(stage, sender))
                process.start()
                sender.close()
                process.join(0.75)
                if process.is_alive():
                    process.kill()
                    process.join(0.2)
                    observed[stage] = {"outcome": ("hung", None)}
                elif receiver.poll(0.1):
                    observed[stage] = receiver.recv()
                else:
                    observed[stage] = {"outcome": ("missing", process.exitcode)}
                receiver.close()
                process.close()
        finally:
            os.close(blocked_read)
            os.close(blocked_write)

        self.assertEqual(
            {stage: "error" for stage in ("attach", "resume", "unload", "detach")},
            {stage: result["outcome"][0] for stage, result in observed.items()},
            observed,
        )
        for stage, result in observed.items():
            self.assertLess(result["elapsed"], 0.7, (stage, result))
            self.assertEqual([], result["children"], (stage, result))
        self.assertEqual([("kill", "-9", "4242")], observed["attach"]["kills"])
        self.assertEqual([("kill", "-9", "4242")], observed["resume"]["kills"])
        self.assertEqual([], observed["unload"]["kills"])
        self.assertEqual([], observed["detach"]["kills"])


class FridaProviderTests(unittest.TestCase):
    def test_usb_lookup_uses_seconds_without_double_conversion(self):
        calls = []
        frida = SimpleNamespace(
            get_device=lambda serial, timeout: calls.append((serial, timeout)) or object()
        )

        with patch.dict(sys.modules, {"frida": frida}):
            selected = FridaProvider().get_device(SimpleNamespace(serial="USB-SERIAL"), 5.0)

        self.assertIsNotNone(selected)
        self.assertEqual([("USB-SERIAL", 5.0)], calls)

    def test_wifi_and_ipv6_adb_serials_map_to_explicit_remote_frida_endpoint(self):
        endpoints = []
        manager = SimpleNamespace(
            add_remote_device=lambda endpoint: endpoints.append(endpoint) or object()
        )
        frida = SimpleNamespace(get_device_manager=lambda: manager)

        with patch.dict(sys.modules, {"frida": frida}):
            for serial in ("192.0.2.8:5555", "[2001:db8::8]:5555"):
                with self.subTest(serial=serial):
                    self.assertIsNotNone(
                        FridaProvider().get_device(SimpleNamespace(serial=serial), 5.0)
                    )

        self.assertEqual(["192.0.2.8:27042", "[2001:db8::8]:27042"], endpoints)

    def test_provider_normalizes_frida_specific_errors(self):
        class InvalidArgumentError(Exception):
            pass

        def fail_lookup(_serial, timeout):
            self.assertGreater(timeout, 0)
            raise InvalidArgumentError("bad device\nargument")

        frida = SimpleNamespace(
            InvalidArgumentError=InvalidArgumentError,
            get_device=fail_lookup,
        )
        with patch.dict(sys.modules, {"frida": frida}), self.assertRaises(QtraceError) as caught:
            FridaProvider().get_device(SimpleNamespace(serial="USB-SERIAL"), 5.0)

        self.assertEqual("frida.device_failed", caught.exception.code)
        self.assertNotIn("\n", str(caught.exception))


class AgentSourceTests(unittest.TestCase):
    def test_agent_is_static_startup_only_and_names_the_native_abi(self):
        source = AGENT_PATH.read_text(encoding="utf-8")

        for expected in (
            "Module.load",
            "qbdi_tracer_set_shadowhook_helper_path",
            "qbdi_tracer_configure_json",
            "qbdi_tracer_get_status_json",
            'recv("qtrace-startup"',
            'type: "initialized"',
            'type: "installed"',
            'type: "error"',
        ):
            self.assertIn(expected, source)
        for forbidden in (
            PACKAGE,
            SESSION_ID,
            TARGET_MODULE,
            "libdemo_target.so",
            "com.aprz.qbdiandroid",
            "rpc.exports",
            "qtrace-stop",
            "acceptance-release",
        ):
            self.assertNotIn(forbidden, source)
        self.assertEqual(1, source.count('recv("qtrace-startup"'))


if __name__ == "__main__":
    unittest.main()
