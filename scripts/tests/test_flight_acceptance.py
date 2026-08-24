import tempfile
import threading
import time
import unittest
import types
import sys
from unittest.mock import patch
from pathlib import Path

from scripts.flight_acceptance import (
    AcceptanceError,
    AcceptanceCase,
    AcceptanceOracle,
    AcceptanceResult,
    OracleMailbox,
    _agent_source,
    _cleanup_frida,
    _observed_termination,
    decode_status,
    expand_cases,
    exact_artifact,
    run_as_command,
    run_as_kill_command,
    run_case,
    validate_result,
)

ROOT = Path(__file__).resolve().parents[2]


class FlightAcceptanceTests(unittest.TestCase):
    def test_sync_fault_uses_top_level_handler_begin_as_original_fault_site(self):
        recovery = types.SimpleNamespace(merged=[
            types.SimpleNamespace(
                kind="signal_handler_begin",
                tid=51,
                data={"pc": 0x7080, "signal_number": 11, "flags": 1},
            ),
            types.SimpleNamespace(
                kind="signal_handler_return",
                tid=51,
                data={"pc": 0x7090, "signal_number": 11, "flags": 1},
            ),
        ])

        self.assertEqual(
            (51, 0x80),
            _observed_termination(recovery, "sync_fault", 0x7000),
        )

    def test_decode_status_allows_expected_crash_and_ring_recovery_dimensions(self):
        complete = {
            "complete": True,
            "artifact_flags": 0,
            "lost_sequences": [],
            "overwritten_sequences": [],
            "stale_directory_entries": [],
            "unterminated_threads": [],
            "active_chunks": [],
            "incomplete_logical_events": [],
            "coverage_gaps": [],
            "recovery_damage": [],
        }
        self.assertEqual("complete", decode_status(complete))

        expected_crash = dict(complete)
        expected_crash.update({
            "lost_sequences": [[2, 3]],
            "overwritten_sequences": [[2, 3]],
            "unterminated_threads": [731],
            "active_chunks": [2],
        })
        self.assertEqual("complete", decode_status(expected_crash))

        for field, value in (
            ("complete", False),
            ("artifact_flags", 8),
            ("stale_directory_entries", [1]),
            ("incomplete_logical_events", [{"event_id": 7}]),
            ("coverage_gaps", [{"tid": 731}]),
            ("recovery_damage", ["invalid committed emergency"]),
        ):
            with self.subTest(field=field):
                summary = dict(complete)
                summary[field] = value
                self.assertEqual("incomplete", decode_status(summary))

    def test_decode_status_rejects_emergency_failure_flag_without_gap_or_damage(self):
        summary = {
            "complete": False,
            "artifact_flags": 8,
            "lost_sequences": [],
            "overwritten_sequences": [],
            "stale_directory_entries": [],
            "unterminated_threads": [],
            "active_chunks": [],
            "incomplete_logical_events": [],
            "coverage_gaps": [],
            "recovery_damage": [],
        }

        self.assertEqual("incomplete", decode_status(summary))

    def test_fixture_uses_bounded_mutation_work_without_weakening_rotations_gate(self):
        fixture = (ROOT / "app/src/main/cpp/demo_target/demo_scenes.cpp").read_text()
        runner = (ROOT / "scripts/flight_acceptance.py").read_text()

        self.assertIn(
            "constexpr uint32_t kAcceptanceMutationIterations = 2048;",
            fixture,
        )
        self.assertIn("const uint32_t completed_rotations = acceptance_mutate", fixture)
        self.assertIn("minimum_rotations", fixture)
        self.assertIn("rotations < 5", runner)

    def test_init_only_capture_retains_all_target_worker_start_sessions(self):
        fixture = (ROOT / "app/src/main/cpp/demo_target/demo_scenes.cpp").read_text()
        coordinator = (ROOT / "tracer/src/main/cpp/core/capture_coordinator.cpp").read_text()

        self.assertIn("constexpr uint32_t kAcceptanceWorkers = 16;", fixture)
        self.assertIn("pthread_create(&g_acceptance_workers[index].thread", fixture)
        self.assertIn("acceptance_worker,", fixture)
        self.assertIn("*control = {logical_entry, range.start,", coordinator)

    def test_agent_replaces_defaults_with_only_the_nonzero_init_scene(self):
        offsets = {
            "init": 0x100,
            "jni": 0x200,
            "libc": 0x300,
            "algorithm": 0x400,
            "integrity": 0x500,
        }

        source = _agent_source(
            AcceptanceCase(101, "direct_tgkill", 3), offsets, 512
        )

        self.assertEqual(source.count("scene="), 1)
        self.assertIn("scenes=replace;", source)
        self.assertLess(source.index("scenes=replace;"), source.index("scene=init,"))
        self.assertIn("scene=init,0x100", source)
        for name in ("jni", "libc", "algorithm", "integrity"):
            self.assertNotIn(f"scene={name},", source)
        self.assertNotIn("benchmark", source)
        self.assertNotRegex(source, r"scene=[^,;]+,0x0(?:;|')")
        self.assertLess(
            source.index("files/libshadowhook_nothing.so"),
            source.index("files/libqbdi_tracer.so"),
        )

    def test_agent_uses_nonblocking_snapshot_messages_and_never_logcat(self):
        source = _agent_source(
            AcceptanceCase(101, "direct_tgkill", 3),
            {"init": 0x100, "jni": 0x200, "libc": 0x300,
             "algorithm": 0x400, "integrity": 0x500},
            512,
        )

        self.assertIn("demo_flight_acceptance_start", source)
        self.assertIn("demo_flight_acceptance_snapshot", source)
        self.assertIn("demo_flight_acceptance_release", source)
        self.assertIn("setInterval", source)
        self.assertIn("type: 'acceptance-oracle'", source)
        self.assertIn("generation.equals(0)", source)
        self.assertNotIn("generation.isZero()", source)
        self.assertNotIn("demo_flight_acceptance_case", source)
        runner = (ROOT / "scripts/flight_acceptance.py").read_text()
        self.assertNotIn('"logcat"', runner)
        self.assertNotIn("def _wait_oracle", runner)

    @staticmethod
    def _oracle_message(seed=101, mode="direct_tgkill", generation="7",
                        tids=None, rotations=5):
        if tids is None:
            tids = list(range(31000, 31016))
        return {
            "type": "send",
            "payload": {
                "type": "acceptance-oracle", "generation": generation,
                "seed": str(seed), "mode": mode, "selected_worker": 3,
                "tid": 31003, "pc": "0x1234", "probe": 0x17,
                "tids": tids, "rotations": rotations, "state": 2,
            },
        }

    def test_valid_frida_oracle_message_unlocks_exactly_once(self):
        mailbox = OracleMailbox(AcceptanceCase(101, "direct_tgkill", 3))
        release = mailbox.handle(self._oracle_message())
        oracle, tids, rotations, generation = mailbox.wait(0.01)

        self.assertEqual(release, 7)
        self.assertEqual(oracle, AcceptanceOracle(101, "direct_tgkill", 31003, 0x1234))
        self.assertEqual(tids, frozenset(range(31000, 31016)))
        self.assertEqual(rotations, 5)
        self.assertEqual(generation, 7)

        external = OracleMailbox(AcceptanceCase(505, "external_sigkill", None))
        message = self._oracle_message(seed=505, mode="external_sigkill")
        message["payload"].update(selected_worker=0, tid=None, pc=None)
        self.assertEqual(external.handle(message), 7)
        self.assertEqual(external.wait(0.01)[0],
                         AcceptanceOracle(505, "external_sigkill", None, None))

    def test_wrong_duplicate_and_incomplete_oracle_messages_fail_closed(self):
        bad_messages = [
            self._oracle_message(seed=202),
            self._oracle_message(tids=list(range(31000, 31015))),
            self._oracle_message(rotations=4),
        ]
        for message in bad_messages:
            with self.subTest(message=message):
                mailbox = OracleMailbox(AcceptanceCase(101, "direct_tgkill", 3))
                self.assertIsNone(mailbox.handle(message))
                with self.assertRaises(AcceptanceError):
                    mailbox.wait(0.01)

        mailbox = OracleMailbox(AcceptanceCase(101, "direct_tgkill", 3))
        self.assertEqual(mailbox.handle(self._oracle_message()), 7)
        self.assertIsNone(mailbox.handle(self._oracle_message()))
        with self.assertRaisesRegex(AcceptanceError, "duplicate"):
            mailbox.wait(0.01)

    def test_oracle_timeout_retains_message_diagnostics(self):
        mailbox = OracleMailbox(AcceptanceCase(101, "direct_tgkill", 3))
        mailbox.handle({"type": "send", "payload": {"type": "acceptance-installed"}})
        with self.assertRaisesRegex(AcceptanceError, "acceptance-installed"):
            mailbox.wait(0.001)

    def test_cleanup_is_bounded_when_frida_detach_hangs(self):
        blocker = threading.Event()

        class Blocking:
            def unload(self):
                blocker.wait()

            def detach(self):
                blocker.wait()

        started = time.monotonic()
        with patch("scripts.flight_acceptance._adb") as adb:
            _cleanup_frida(Blocking(), Blocking(), "serial", "pkg", 0.01)
        self.assertLess(time.monotonic() - started, 0.2)
        adb.assert_called_once_with(
            "serial", "shell", "am", "force-stop", "pkg", check=False,
            timeout=0.01,
        )

    def test_script_load_failure_force_stops_and_detaches_the_spawned_app(self):
        class Script:
            def __init__(self):
                self.unloaded = False

            def on(self, *_args):
                pass

            def load(self):
                raise RuntimeError("injected script load failure")

            def unload(self):
                self.unloaded = True

        class Session:
            def __init__(self, script):
                self.script = script
                self.detached = False

            def create_script(self, _source):
                return self.script

            def detach(self):
                self.detached = True

        script = Script()
        session = Session(script)

        class Device:
            def spawn(self, _package):
                return 4242

            def attach(self, pid):
                self.assert_pid = pid
                return session

            def resume(self, _pid):
                raise AssertionError("resume must not run after load failure")

        device = Device()
        frida = types.SimpleNamespace(
            get_device_manager=lambda: types.SimpleNamespace(
                add_remote_device=lambda _address: device
            )
        )
        client = types.SimpleNamespace(list_names=lambda: [])
        args = types.SimpleNamespace(
            package="com.aprz.qbdiandroid", device="serial", frida_port=27042,
            artifact_mb=512, adb_timeout=0.01, timeout=0.01,
        )
        offsets = {name: index + 1 for index, name in enumerate(
            ("init", "jni", "libc", "algorithm", "integrity"))}

        with patch.dict(sys.modules, {"frida": frida}), \
                patch("scripts.flight_acceptance.AdbArtifactClient",
                      return_value=client), \
                patch("scripts.flight_acceptance._adb") as adb, \
                self.assertRaisesRegex(RuntimeError, "script load failure"):
            run_case(args, AcceptanceCase(101, "direct_tgkill", 3),
                     offsets, Path(tempfile.mkdtemp()))

        self.assertTrue(script.unloaded)
        self.assertTrue(session.detached)
        self.assertTrue(any(call.args[1:] ==
                            ("shell", "am", "force-stop", args.package)
                            for call in adb.call_args_list))

    def test_seed_expansion_is_deterministic_and_selects_one_terminator(self):
        seeds = [101, 202, 303, 404, 505]
        first = expand_cases(seeds)
        second = expand_cases(seeds)

        self.assertEqual(first, second)
        self.assertEqual(
            [case.mode for case in first],
            ["direct_tgkill", "exit_group", "sync_fault", "target_sigkill",
             "external_sigkill"],
        )
        for case in first:
            selected = [worker for worker in range(16) if worker == case.terminator]
            if case.mode == "external_sigkill":
                self.assertEqual(selected, [])
            else:
                self.assertEqual(len(selected), 1)
                self.assertIn(case.terminator, range(16))

    def test_oracle_requires_tid_and_original_target_pc_before_termination(self):
        oracle = AcceptanceOracle.parse(
            'QBDI_FLIGHT_ORACLE seed=101 mode=direct_tgkill tid=31337 pc=0x1234 phase=ready'
        )

        self.assertEqual(oracle.tid, 31337)
        self.assertEqual(oracle.original_pc, 0x1234)
        with self.assertRaises(AcceptanceError):
            AcceptanceOracle.parse(
                'QBDI_FLIGHT_ORACLE seed=101 mode=direct_tgkill tid=31337 phase=ready'
            )

    def test_run_as_command_rejects_shell_metacharacters_and_unsafe_paths(self):
        self.assertEqual(
            run_as_command("com.aprz.qbdiandroid", "files/qbdi_trace/run.flight.bin"),
            ["run-as", "com.aprz.qbdiandroid", "cat",
             "files/qbdi_trace/run.flight.bin"],
        )
        for unsafe in ("../run.flight.bin", "/data/local/tmp/run.flight.bin", "x;id"):
            with self.subTest(unsafe=unsafe), self.assertRaises(AcceptanceError):
                run_as_command("com.aprz.qbdiandroid", unsafe)
        with self.assertRaises(AcceptanceError):
            run_as_command("com.aprz.qbdiandroid;id", "files/qbdi_trace/run.flight.bin")

    def test_external_sigkill_uses_the_debuggable_app_uid(self):
        self.assertEqual(
            ["run-as", "com.aprz.qbdiandroid", "kill", "-9", "29636"],
            run_as_kill_command("com.aprz.qbdiandroid", 29636),
        )
        for package, pid in (("com.aprz.qbdiandroid;id", 29636),
                             ("com.aprz.qbdiandroid", 0)):
            with self.subTest(package=package, pid=pid), self.assertRaises(
                AcceptanceError
            ):
                run_as_kill_command(package, pid)

    def test_exact_artifact_requires_one_pid_matching_flight_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wanted = root / "123_4242_libdemo_target.so.flight.bin"
            wanted.write_bytes(b"flight")
            (root / "123_7_libdemo_target.so.flight.bin").write_bytes(b"other")
            (root / "123_4242_libdemo_target.so.qtrb").write_bytes(b"normal")
            self.assertEqual(exact_artifact(root, 4242), wanted)

            (root / "duplicate_4242_libdemo_target.so.flight.bin").write_bytes(b"duplicate")
            with self.assertRaises(AcceptanceError):
                exact_artifact(root, 4242)

    def test_validation_requires_four_chunks_for_every_relevant_tid(self):
        result = AcceptanceResult(
            mode="direct_tgkill",
            oracle=AcceptanceOracle(101, "direct_tgkill", 12, 0x1234),
            observed_tid=12,
            observed_pc=0x1234,
            chunks_by_tid={12: 4, 13: 3},
            relevant_tids=frozenset({12, 13}),
        )

        with self.assertRaisesRegex(AcceptanceError, "four chunks"):
            validate_result(result)

    def test_external_sigkill_has_no_initiator(self):
        valid = AcceptanceResult(
            mode="external_sigkill",
            oracle=AcceptanceOracle(101, "external_sigkill", None, None),
            observed_tid=None,
            observed_pc=None,
            chunks_by_tid={12: 4},
            relevant_tids=frozenset({12}),
        )
        validate_result(valid)

        with self.assertRaisesRegex(AcceptanceError, "initiator"):
            validate_result(AcceptanceResult(
                mode="external_sigkill",
                oracle=AcceptanceOracle(101, "external_sigkill", 12, 0x1234),
                observed_tid=12,
                observed_pc=0x1234,
                chunks_by_tid={12: 4},
                relevant_tids=frozenset({12}),
            ))

    def test_validation_rejects_gap_incomplete_decode_or_tracer_address(self):
        base = dict(
            mode="direct_tgkill",
            oracle=AcceptanceOracle(101, "direct_tgkill", 12, 0x1234),
            observed_tid=12,
            observed_pc=0x1234,
            chunks_by_tid={12: 4},
            relevant_tids=frozenset({12}),
        )
        for changes, message in (
            ({"coverage_gaps": 1}, "coverage gap"),
            ({"decode_complete": False}, "incomplete"),
            ({"guest_visible_tracer_addresses": (0x70000100,)}, "tracer address"),
        ):
            with self.subTest(changes=changes), self.assertRaisesRegex(
                AcceptanceError, message
            ):
                validate_result(AcceptanceResult(**base, **changes))

    def test_validation_rejects_oracle_mismatch(self):
        result = AcceptanceResult(
            mode="sync_fault",
            oracle=AcceptanceOracle(303, "sync_fault", 51, 0x8080),
            observed_tid=52,
            observed_pc=0x8084,
            chunks_by_tid={51: 4},
            relevant_tids=frozenset({51}),
        )
        with self.assertRaisesRegex(AcceptanceError, "oracle"):
            validate_result(result)


if __name__ == "__main__":
    unittest.main()
