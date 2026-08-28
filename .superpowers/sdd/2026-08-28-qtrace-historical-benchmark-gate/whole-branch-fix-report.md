# Whole-branch fix report

Date: 2026-08-29

Fixed base: `048640a78243e4b88069cfb65a5e8f2133047974`

Scope source: `whole-branch-fix-brief.md`

## Result

Implemented F1–F6 without changing the deferred physical-gate command order,
the generic 512 MiB artifact/Flight defaults, or physical acceptance semantics.
The final host suites pass. Per the brief, no physical-device gate was run in
this fix wave.

Code location and call-path discovery began with the repository CodeGraph
index (`codegraph explore`) before direct source inspection.

## F1 — remote staging lifecycle

RED command:

```text
python3 -m unittest \
  scripts.tests.test_qtrace_build.DeployerTests.test_owned_staging_directory_is_removed_after_success \
  scripts.tests.test_qtrace_build.DeployerTests.test_owned_staging_directory_is_removed_after_mid_deploy_failure \
  scripts.tests.test_qtrace_build.DeployerTests.test_staging_cleanup_failure_preserves_primary_and_is_never_silent \
  scripts.tests.test_qtrace_build.DeployerTests.test_direct_push_route_never_removes_an_uncreated_staging_directory -v
```

RED result: two failures and one error exposed the missing exact `rm -rf`
cleanup and silent cleanup failure; the direct route already avoided removing
an uncreated staging directory.

GREEN: the same four-test command passed. `_attempt()` now removes only the
validated `/data/local/tmp/qtrace-staging/<UUIDv4>` owned by that attempt on
success and failure. Cleanup is bounded; a primary exception retains cleanup
failure notes, while cleanup failure after an otherwise successful deployment
is raised.

## F2 — true bounded artifact streaming

RED command:

```text
python3 -m unittest \
  scripts.tests.test_bounded_process.BoundedProcessTests.test_stream_bounded_writes_multiple_chunks_without_return_buffer \
  scripts.tests.test_bounded_process.BoundedProcessTests.test_stream_bounded_rejects_oversize_timeout_and_failed_partial_output \
  scripts.tests.test_qtrace_device.AdbDeviceTests.test_bound_target_stream_uses_one_direct_bounded_runner_contract \
  scripts.tests.test_qtrace_artifacts.ArtifactTests.test_bound_client_streams_chunks_and_removes_partial_on_transport_failure -v
```

RED result: two import errors, one missing device streaming method, and one
buffered `target_shell` failure proved that the only bound route materialized
the whole artifact.

GREEN: the four-test command passed. `stream_bounded()` reuses the existing
PID-namespace deadline/descendant teardown but writes each selector chunk
directly to a caller-owned regular-file FD. `BoundedRunner`, `AdbDevice`, and
`_BoundDeviceClient` preserve the already-bound target identity. The exact
512 MiB bound is unchanged. Oversize, timeout and subprocess errors retain
only bounded partial bytes, and `pull_named_artifacts()` removes its exclusive
temporary instead of publishing it.

Additional focused coverage:

```text
python3 -m unittest \
  scripts.tests.test_qtrace_artifacts.ArtifactTests.test_collector_rejects_a_short_stream_against_the_bounded_remote_size -v
```

Result: passed; the before/after remote-size oracle rejects a short stream and
the failed collection leaves no local session tree.

## F3 — one immutable host snapshot

RED command:

```text
python3 -m unittest \
  scripts.tests.test_qtrace_build.DeployerTests.test_deploys_and_hashes_one_validated_host_snapshot_when_source_is_replaced -v
```

RED result: replacement bytes were deployed because validate, push and hash
reopened the source pathname independently.

GREEN: the test passed. Both artifacts are copied from no-follow regular-file
FDs into a private `0700` root as `0400` snapshots, with the existing 512 MiB
limit. The snapshot bytes themselves receive the arm64 ELF validation and
SHA-256, held identities are checked around both pushes and integrity checks,
and both the private and fallback deployments use the same pair.

Self-review found that `/proc/self/fd/...` would resolve `self` as the spawned
`adb` process rather than the Python owner. An added assertion was RED and then
GREEN after changing the push path to `/proc/<python-pid>/fd/<root-fd>/...`.

Self-review also added two RED cleanup slices:

```text
python3 -m unittest \
  scripts.tests.test_qtrace_build.DeployerTests.test_snapshot_construction_cleanup_never_masks_primary_and_removes_private_root \
  scripts.tests.test_qtrace_build.DeployerTests.test_snapshot_root_setup_failure_removes_only_its_owned_empty_directory -v
```

RED exposed a close error masking the read failure plus leaked construction
roots. GREEN exhaustively transfers/closes descriptors, unlinks snapshot
members, identity-checks the root before `rmdir`, and annotates rather than
replaces the primary failure. Final `test_qtrace_build`: 24 tests, all passed.

## F4 — secondary Android user binding

Host RED command:

```text
python3 -m unittest \
  scripts.tests.test_qtrace_preflight.PreflightTests.test_binds_current_secondary_user_and_rejects_uid_user_mismatch \
  scripts.tests.test_qtrace_build.DeployerTests.test_private_deploy_uses_bound_secondary_user_data_directory \
  scripts.tests.test_qtrace_artifacts.ArtifactTests.test_manual_client_uses_bound_secondary_user_trace_root \
  scripts.tests.test_qtrace_session.SessionTests.test_session_status_and_snapshot_use_bound_secondary_user_trace_root -v
```

RED result: preflight did not bind the user/data directory, and deploy,
collection and session status remained on user-0/legacy paths.

Native RED command:

```text
./gradlew nativeHostTest --no-daemon
```

RED result: `session_status_test_default_output_directory` was undefined.

GREEN: the four host tests passed; the complete focused host group
(`preflight`, `device`, `build`, `artifacts`, `session`) passed 193 tests; and
native passed 45/45. Preflight queries bounded `cmd activity get-current-user`,
proves `package_uid / 100000 == user`, binds the exact
`/data/user/<user>/<package>` path, and rejects malformed or inconsistent
bindings. Nonzero-user `run-as` uses `--user`. Deploy, injection inputs,
session status/snapshot and manual collection consume that immutable binding.
Native derives the same user component from the target process UID. User 0
now canonically uses `/data/user/0/...` rather than the `/data/data` alias.

## F5 — bounded strict config input

RED command:

```text
python3 -m unittest \
  scripts.tests.test_qtrace_config.ConfigTests.test_accepts_exact_config_byte_limit_and_rejects_one_byte_over \
  scripts.tests.test_qtrace_config.ConfigTests.test_rejects_symlink_and_special_config_inputs_without_following_or_blocking \
  scripts.tests.test_qtrace_config.ConfigTests.test_normalizes_deep_json_and_invalid_utf8_to_config_error -v
```

RED result: the byte-limit API/behavior did not exist. The deep fixture was
corrected from 2,000 levels (which this Python build parses before rejecting
the non-object root) to 20,000 levels, which deterministically exercises
`RecursionError` while remaining below the byte bound.

GREEN: the three focused tests and all 31 config tests passed. The loader uses
`O_NOFOLLOW|O_NONBLOCK`, requires the pre-open pathname and opened FD to be the
same regular inode, enforces the documented exact 1 MiB size, reads at most
limit+1 in chunks, verifies stable identity/size/timestamps, decodes UTF-8
strictly, and normalizes I/O, malformed JSON, deep recursion, duplicate keys
and non-finite constants through `CONFIG_JSON_INVALID`. README documents the
limit and rejected input classes.

## F6 — evidence-based monitor classification

RED command:

```text
python3 -m unittest \
  scripts.tests.test_qtrace_session.SessionTests.test_monitor_partial_without_recovery_evidence_stays_process_exited \
  scripts.tests.test_qtrace_session.SessionTests.test_monitor_partial_is_crash_recovered_only_for_validated_recovery_records \
  scripts.tests.test_qtrace_artifacts.ArtifactTests.test_confirmed_process_exit_keeps_structurally_complete_flight_recovery_partial \
  scripts.tests.test_qtrace_artifacts.ArtifactTests.test_validated_crash_marker_classifies_only_its_validated_qtrb_root -v
```

RED result: an ordinary partial was published as `crash_recovered`; validated
Flight and QTRB roots lacked an explicit recovery classification. The QTRB
fixture import and its initial terminal assertion were corrected before GREEN:
partial crash recovery validly has no native footer termination, so the
validated crash marker—not an invented terminal—is the evidence.

GREEN: all four focused tests passed, followed by 143 session/artifact tests.
The collector emits `recovery_classification=crash_marker` only after a valid
marker and successful QTRB recovery, and `flight` only for a structurally
complete Flight summary observed after process exit. Session publication
requires the corresponding decoder/recovery fields; other exit-2 results keep
`process_exited`, their exit code and their outputs.

## Final verification

Final-code Python command:

```text
env PATH=/tmp/qbdi-flight-frida-17.17.0/bin:/tmp/qtrace-lz4-cli.GJt6c2/src/programs:/home/lyldalek/Android/sdk/platform-tools:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  ANDROID_NDK_HOME=/home/lyldalek/Android/sdk/ndk/26.1.10909125 \
  ANDROID_HOME=/home/lyldalek/Android/sdk \
  python3 -m unittest discover -s scripts/tests -p 'test_*.py'
```

Result after the stability fix described below: `Ran 790 tests in 76.344s` —
`OK (skipped=8)`.

Exact combined Gradle command:

```text
env PATH=/tmp/qbdi-flight-frida-17.17.0/bin:/tmp/qtrace-lz4-cli.GJt6c2/src/programs:/home/lyldalek/Android/sdk/platform-tools:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  ANDROID_NDK_HOME=/home/lyldalek/Android/sdk/ndk/26.1.10909125 \
  ANDROID_HOME=/home/lyldalek/Android/sdk \
  ./gradlew nativeHostTest :app:testDebugUnitTest :app:assembleDebug \
    :tracer:assembleDebug :tracer:copyTracerDebug --no-daemon
```

Result: native 45/45; `BUILD SUCCESSFUL in 44s` (74 tasks, 13 executed,
61 up-to-date).

Other final checks: Python compileall passed; `git diff --check` passed; the
fixed-base diff was inspected for F1–F6 scope and the Deferred Minor ordering
was not changed.

One F1–F6-external test-stability issue appeared during final repetition. The
first two 790-test full runs passed; a third run made the 64 MiB invalid
canonical-output fixture spend its unrelated one-second deadline while writing
and reading the fixture, so it reported the still-fail-closed deadline error
instead of the intended size error. Only that non-deadline test loop now uses a
five-second budget. Production deadlines and the independently mocked expired-
deadline test are unchanged. The focused case was repeated five times before
the final fresh full run.

## Concerns / handoff

- The brief explicitly deferred the physical gate. Secondary-user `run-as
  --user`, real ADB opening of `/proc/<host-pid>/fd`, and the complete strict
  device workflow therefore still require the controller's retained physical
  rerun.
- The physical gate's combined-Gradle-before-Python ordering remains untouched
  as the specified Deferred Minor.
- No generic default was reduced: artifact streaming and snapshot input remain
  bounded at 512 MiB, and the generic Flight capacity remains 512 MiB.

## Round 2 scoped rereview repairs

Round 2 started from review HEAD
`78c11300003bedb96e233b2d1345a48b1ecffe0f` and addressed only the three
remaining F3/F4 findings. F1, F2, F5, F6 and the Deferred Minor ordering were
not changed.

### F3 — snapshot FD crosses both containment exec boundaries

The controller's independent real-containment probe established the RED before
implementation: the held file was readable in the host process, while
`BoundedRunner` running `cat /proc/<host-python-pid>/fd/<fd>` failed with
`No such file or directory`. The namespace cannot name the host Python PID.

Behavioral RED commands included:

```text
python3 -m unittest \
  scripts.tests.test_qtrace_process.BoundedRunnerTests.test_real_fake_adb_reads_a_caller_owned_descriptor_in_the_target_namespace -v

python3 -m unittest \
  scripts.tests.test_bounded_process.BoundedProcessTests.test_pass_fds_reject_invalid_or_duplicate_inputs_before_target_spawn \
  scripts.tests.test_bounded_process.BoundedProcessTests.test_passed_file_identity_change_fails_before_target_spawn \
  scripts.tests.test_bounded_process.BoundedProcessTests.test_failed_target_does_not_take_ownership_of_passed_file_descriptor \
  scripts.tests.test_qtrace_device.AdbDeviceTests.test_push_open_file_uses_its_own_proc_fd_and_preserves_caller_ownership \
  scripts.tests.test_qtrace_build.DeployerTests.test_deployer_passes_each_held_snapshot_descriptor_without_a_path_fallback -v
```

The first test was RED because `BoundedRunner.capture()` had no `pass_fds`
contract. The device and deployer slices were RED because the device had no
descriptor push operation and deployment still passed a host-PID pathname.

GREEN passes each caller-owned snapshot descriptor through the controller's
`Popen` into the PID-namespace supervisor and through the supervisor's `Popen`
into the actual `adb` process. The command now opens only
`/proc/self/fd/<fd>`. Both boundaries use `close_fds=True` plus the exact
allowlist. Public input rejects non-integers, standard descriptors, duplicates,
closed descriptors, writable files, non-regular files, and more than 64
descriptors. Device/inode and read-only regular-file identity are checked before
the first spawn, after it, in the supervisor, and during cleanup. The caller
retains ownership on target success, target failure, and setup failure.

The real integration uses the production `BoundedRunner` and an executable
fake `adb`; it is not an in-process fake. It opens its own
`/proc/self/fd/<fd>`, reads the held bytes inside the namespace, and leaves the
caller's descriptor open. Host snapshot pathname checks and cleanup use the
already-held private-root descriptor plus `dir_fd`; no host PID pathname or
legacy path fallback remains.

### F4 — canonical secondary-user `run-as` argv

Behavioral RED command:

```text
python3 -m unittest \
  scripts.tests.test_qtrace_device.AdbDeviceTests.test_secondary_user_run_as_places_the_package_before_the_user_option \
  scripts.tests.test_qtrace_preflight.PreflightTests.test_binds_current_secondary_user_and_rejects_uid_user_mismatch -v
```

RED showed the production argv as `run-as --user 10 PACKAGE ...`, matching the
Pixel failure `unknown package: --user`. GREEN introduces one validated argv
builder used by preflight, bounded target shell, and target file streaming:
user 0 is `run-as PACKAGE ...`; a secondary user is
`run-as PACKAGE --user USER ...`. Tests assert the complete `adb shell` and
`adb exec-out` argument arrays, not string fragments, while the existing user-0
tests preserve its argv contract. Fakes use the same correct order.

### F4 — one UID-derived native trace directory

Native RED command:

```text
./gradlew nativeHostTest --no-daemon
```

RED failed to link the newly required normal-trace and Flight test path
builders. GREEN adds one internal header-only path helper that validates a safe
package path component, derives Android user as `uid / 100000`, and formats
`/data/user/<user>/<package>/files/qbdi-traces`. The status publisher, normal
binary writer and Flight coordinator all call that production helper. The
normal and Flight sources no longer contain `/data/data/`.

The production-backed native tests cover UID 10905 (user 0) and UID 1010905
(user 10) for normal traces and Flight paths; the existing status test covers
the same two users. A production-source contract also proves that all three
implementations call the shared helper, preventing a test-only helper from
masking divergent production paths. No public ABI or fixture protocol changed.

### Round 2 verification

Focused host command after the final self-review edit:

```text
python3 -m compileall -q qtrace scripts && \
python3 -m unittest \
  scripts.tests.test_bounded_process \
  scripts.tests.test_qtrace_process \
  scripts.tests.test_qtrace_device \
  scripts.tests.test_qtrace_build \
  scripts.tests.test_qtrace_preflight
```

Result: `Ran 97 tests in 13.045s` — `OK`; compileall exited 0.

Fresh full Python command:

```text
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
```

Result: `Ran 797 tests in 56.063s` — `OK (skipped=8)`.

Exact combined Gradle command:

```text
./gradlew nativeHostTest :app:testDebugUnitTest :app:assembleDebug \
  :tracer:assembleDebug :tracer:copyTracerDebug --no-daemon
```

Result: native 45/45; `BUILD SUCCESSFUL in 49s` (74 tasks: 13 executed,
61 up-to-date). `git diff --check` also exited 0.

### Round 2 design notes and concerns

- This round supersedes the earlier handoff note about opening
  `/proc/<host-pid>/fd` with real ADB: deployment now deliberately passes an
  allowlisted held FD and lets the actual `adb` process open
  `/proc/self/fd/<fd>` inside containment.
- The descriptor transport intentionally depends on Linux `/proc` and the
  existing Linux PID-namespace containment backend; unsupported platforms
  already fail that backend closed.
- The brief explicitly deferred the physical gate until scoped rereview. No
  Pixel/device claim is made from this round; the controller must decide when
  to rerun the retained physical workflow.
- The previously deferred combined-Gradle-before-Python physical-gate ordering
  remains unchanged.
