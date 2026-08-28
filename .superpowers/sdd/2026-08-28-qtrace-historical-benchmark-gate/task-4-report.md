# Task 4 Report: Strict Historical Pixel Release Gate

## Outcome

Task 4 is complete. The final physical Pixel 6 gate exited 0 on implementation
HEAD `489b38f0be479ecd054975236ddbb115a787285a`, without weakening the historical,
identity, artifact-completeness, package-access, selector, process-identity, or
crash-recovery contracts.

The successful evidence is retained at:

```text
/home/lyldalek/workspace/qbdi-android/.worktrees/qtrace-infrastructure/qtrace-acceptance-evidence/074b2c83-06f3-4960-a708-6ef808d24d90
```

The gate ran on `192.168.50.149:5555`, a rooted arm64 Pixel 6, through the
isolated ADB server on port 5039 with matching Frida host/server 17.17.0, NDK
26.1.10909125, build-tools 35.0.0, and host `lz4`.

## Documentation Contract

`README.md` now distinguishes:

- historical commit `2d6b1022a14ae554804a57e267544c12dea29353`;
- immutable raw audit SHA
  `5f1a970825ae8bacb17d8dd656e01bd1fe7172638ba3ddcacd82ffaaad6e62c0`;
- canonical admission SHA
  `0d8e856c819fb3cd7ae5917053172b4b75a7924784c43e09cb2855a298647169`;
- pinned NDK command `llvm-objcopy --strip-debug
  --remove-section=.note.gnu.build-id`;
- historical/current APK phase order and held tracer-pair reuse;
- fail-closed historical behavior with no semantic-only fallback;
- manual-only CI status and the explicitly required `--device` selector;
- recoverable demo trace quarantine and retained success/failure evidence.

The final device order is historical compare, current timed offset, current
timed symbol, four manual pulls over the sealed timed artifact, monitor-exit,
then flight-crash. Pulls intentionally precede exit/crash because those modes
retain truthful non-sealed native status and would make `--latest` fail strict
artifact validation.

## Final Physical Evidence

The exact bounded invocation was:

```bash
PATH=/tmp/qbdi-flight-frida-17.17.0/bin:/tmp/qtrace-lz4-cli.GJt6c2/src/programs:/home/lyldalek/Android/sdk/platform-tools:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
ANDROID_NDK_HOME=/home/lyldalek/Android/sdk/ndk/26.1.10909125 \
ANDROID_HOME=/home/lyldalek/Android/sdk \
ANDROID_ADB_SERVER_PORT=5039 \
GRADLE_OPTS=-Dorg.gradle.daemon.idletimeout=1000 \
timeout --signal=TERM --kill-after=15s 1800s \
  python3 scripts/qtrace_device_acceptance.py \
  --device 192.168.50.149:5555
```

Result: exit 0. Start was `2026-08-28T17:59:25.254Z`; completion was
`2026-08-28T18:06:39.590Z`.

The mode-0600, 1,517-byte success manifest is
`historical-benchmark-gate.success.json` beneath the retained mode-0700
directory. Its important bindings are:

| Field | Value |
| --- | --- |
| HEAD | `489b38f0be479ecd054975236ddbb115a787285a` |
| Device | `192.168.50.149:5555` |
| Historical APK SHA | `cd01fcf05427af326cbc61b4e9d42905733b1abb315f79298694b45ffc160dba` |
| Observed rebuilt raw target SHA | `c36de745e78d156544378357eae896572c06a63d46155f803dfb6ade5c06f47d` |
| Canonical target SHA | `0d8e856c819fb3cd7ae5917053172b4b75a7924784c43e09cb2855a298647169` |
| Current APK SHA | `f85be5636b54084c6ae97e2f27e2958e915054c9dadfd8481cbd59d2d04df114` |
| Tracer SHA | `76b04b96ecb7d575ae26720d38bc5824cbe63c0877cc6c2581eea9a4b6d6bd99` |
| Companion SHA | `4fe29375379c3c6bd7dae1f8af60f9b89a670149f3152ab0cedf8efa890fe2dd` |
| Trace backup | `files/qbdi-traces.pre-acceptance-70fae213e79a48eb91f70408b51b39bb` |
| Manifest status | `passed`, exit code 0 |

The difference between the immutable raw audit SHA and the rebuilt raw target
SHA is expected evidence, not an identity fallback: admission used the pinned
canonical SHA and the manifest records the actual installed bytes.

All eight bound report paths exist beneath the retained root. The two timed
reports are `sealed`/`completed`; monitor-exit is
`process_exited`/`completed`; flight-crash is
`crash_recovered`/`completed`; all have null errors. The four pull reports were
also parsed and validated by the same gate. Local HEAD and current APK/tracer/
companion hashes were independently recomputed and matched the manifest. The
recoverable device backup was independently `stat`-verified as a directory.

## Host Verification

Fresh final verification produced:

```text
python3 -m py_compile scripts/bounded_process.py \
  scripts/qtrace_historical_benchmark.py scripts/benchmark_trace.py \
  scripts/qtrace_device_acceptance.py
exit 0
```

```text
python3 -m unittest scripts.tests.test_bounded_process \
  scripts.tests.test_qtrace_historical_benchmark \
  scripts.tests.test_benchmark_trace -v
Ran 129 tests; OK
```

```text
python3 -m unittest \
  scripts.tests.test_qtrace_contracts.AcceptanceHarnessTests -v
Ran 88 tests; OK
```

```text
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
Ran 769 tests; OK (skipped=8)
```

```text
./gradlew nativeHostTest :app:testDebugUnitTest :app:assembleDebug \
  :tracer:assembleDebug :tracer:copyTracerDebug --no-daemon
native host tests: 45/45; BUILD SUCCESSFUL
```

The acceptance entrypoint itself runs that exact combined Gradle command and
the full Python command under bounded containment, so the final exit-0 physical
run also re-executed the complete host gate on `489b38f`.

Both help forms exited 0, required `--device`, and made no ADB call:

```text
env -u PYTHONPATH python3 scripts/qtrace_device_acceptance.py --help
env -u PYTHONPATH python3 -m scripts.qtrace_device_acceptance --help
```

`.github/workflows/ci.yml` contains no acceptance invocation. `git diff
--check` was empty. The fixed package remains confined to the demo adapter and
acceptance fixture; generic CLI/session paths remain package-parameterized.
There is no Task 7 adapter branch. Generic SessionOrchestrator/CLI flight
capacity remains 512 MiB; only the fixed demo flight-crash adapter explicitly
injects 64 MiB, while keeping 16 workers, at least five rotations, complete
record rendering/validation, and the crash-recovery oracle.

## Physical Failure to Test to Fix Ledger

Every retained physical/full-entrypoint failure remained fail-closed. None was
reclassified as a pass, and the retained directories below were not deleted.

| Retained evidence | Observed strict failure | RED / regression seam | Minimal fix |
| --- | --- | --- | --- |
| `3d529f0199b2495ca30f5a017b912326` | Historical compare lacked the Frida Java bridge. | Real dependency probe plus historical compare gate. | Install/use matching Frida 17.17.0 host tools; no source fallback. |
| `aa98e07e41704a96a46b6eac01794f9c` | ShadowHook companion configuration used an APK-native path that could not satisfy the staged pair contract. | `test_benchmark_agent_uses_staged_pair_and_rejects_malformed_responses_before_execution`; companion contract tests. | Configure the held app-private companion beside the tracer and never preload it. |
| `7d17af53b5fc4f3ebaaffdeafdc4041d` | Full Python gate caught a stale test requiring `applicationInfo.nativeLibraryDir`. | `test_application_injectors_configure_but_never_preload_companion`. | Align the contract test with same-root staged companion semantics; retain no-preload assertions. |
| `bf3248a758524b8ab52d49974694e542` | Historical benchmark produced no complete trace/metrics pair after aliased app-private paths reached native ShadowHook. | `test_agent_canonicalizes_staged_pair_together_and_never_preloads_companion` plus real GumJS probe. | Canonicalize the staged root inside the target process, use the same real root for tracer/helper, and never preload the helper. |
| `bf28e96db5e44e7b8c4795121c04965e` | Timed fixture Gradle exceeded its 90-second bounded deadline. | ArtifactBuilder/demo build environment merge tests, including `test_demo_build_bounds_gradle_daemon_lifetime_inside_bounded_runner`. | Preserve caller `GRADLE_OPTS`, append a bounded daemon idle timeout, and share the bounded artifact builder without reducing build memory. |
| `563928b3cc6146418f83e55bc72d06de` | Frida 17 handshake attempted a missing Python-device `version` attribute. | `test_frida_17_runtime_reads_server_version_from_a_clean_system_probe`, clean-parent and blocked-probe tests. | Query server version in a bounded clean subprocess; kill/reap on deadline and do not initialize Frida in the parent. |
| `caedf213142345568410b75ed74f13bb` | Monitor collection found native status still non-terminal after process death. | Native status backup-copy/fault-injection tests, sidecar scanner tests, and confirmed-process-exit artifact tests. | Durably retain prior status, find only strict backup names after death, publish cache metrics before seal, and keep footer/sidecar values equal; host process-exit context never fabricates native terminal state. |
| `ec902f738379470f9f677b33c12676a4` | A transient `pidof` absence was interpreted as PID replacement. | `/proc/<pid>/stat` parser and `test_monitor_verifies_owned_process_identity_after_pidof_false_negative`. | Hold `(pid,starttime)` and probe owned identity: live same identity continues; Z/X/ENOENT exits; mismatch is replacement; malformed/permission errors fail closed. |
| `435084b8a2454c27a4954a55cdb178e2` | Flight crash helper made `pidof` return multiple numeric PIDs, rejected as malformed. | `test_monitor_keeps_owned_pid_when_pidof_also_reports_crash_helper`, list/rejection parser tests. | Parse a strict numeric PID set, retain the owned PID when present, and still reject foreign-only or malformed sets. |
| `5e4d85df652d426cb0dfe4160640e7ac` | Retained flight output was rejected outside the trusted report directory. | Session-root binding tests for complete/partial retained evidence. | Bind validation to the report's own trusted session root; no pathname fallback outside it. |
| `cf1bfda3be544b9e8ae2847b9ee52df9` | A stale timed fixture PID was already gone when the harness issued its liveness command. | AcceptanceHarness ordering/liveness tests. | Keep the timed liveness oracle adjacent to the timed report that owns the PID and never reuse it after later fixture transitions. |
| `53d02ebcc5324ac99b6b01274882f8aa` | The old timed PID had been reused by a different process and `kill -0` returned access denied. | `test_monitor_rejects_reused_owned_pid_after_pidof_absence` and `test_monitor_rejects_same_numeric_pid_reused_by_package`. | Validate the held starttime on every poll, including same numeric `pidof`; treat reuse as `pid_replaced`, not liveness. |
| `9ebb02271f2a40858408f4104bc80d90` | Manual `pull --latest` constructed an unbound target-shell client. | `test_pull_binding_failure_publishes_nothing_and_never_constructs_processor`, `test_manual_client_reuses_the_same_bound_target_shell_device`, and binder tests. | Run the generic package-access binder before collection, reuse the identical bound target-shell client, publish zero output on binding failure, and provide no legacy fallback. |
| `5edab6918304495d98a49a2027ca32ad` | Timed process exited before seal because the quarantined trace root had not been freshly established for native status publication. | Demo isolation absence/rename/repeat/symlink/collision/rename/mkdir/inode/order tests. | Force-stop the fixed demo, strictly verify and atomically rename the old trace directory, create and identity-check a fresh root, and retain the backup without deletion. |
| `68213cdd40014f5db85e1b03e66931fc` | `pull --latest` correctly rejected a partial artifact selected from stale fixture data. | Explicit-name/latest selector relevance tests plus all-selector strictness and quarantine tests. | NAME/LATEST ignore only unrelated session temporaries; ALL remains globally strict. Isolate old demo data and order four pulls immediately after the sealed timed symbol report. |
| `8b160358-7a82-4f75-879c-a67c5b950393` | One bounded ADB receipt read raised raw `subprocess.TimeoutExpired`, bypassing the existing five-second evidence poll. | `test_timed_entry_evidence_retries_one_bounded_adb_timeout`. | Normalize the one-second subprocess timeout into the existing pollable not-ready result; keep both original deadlines unchanged. Commit `ee096c1`. |
| `a5ddb12e-9f0e-4b2a-8a38-33fa5d74048b` | Normal native return raced app exit between status temp write and rename, leaving active status plus a same-session temp; strict collection returned raw 2. | Kotlin `exit_readiness_waits_for_committed_inactive_scene_status` and standalone Pixel monitor replay. | Demo-only adapter waits at most one second for committed same-session running status with no active scene and a declared artifact before task/process exit. Commit `489b38f`. |
| `qtrace-acceptance-evidence/074b2c83-06f3-4960-a708-6ef808d24d90` | Final gate. | All preceding regressions plus success publish collision/rename/fsync/manifest/ordering tests. | Exit 0; atomically retained bounded success evidence after all validation and cleanup. |

This table covers every failure directory that contains a published gate JSON.
Five empty UUID directories and one empty hidden scratch directory from
interrupted pre-publication diagnostics also remain on disk. They contain no
report and were not treated as acceptance evidence; they were intentionally not
deleted.

Additional standalone real-device diagnostics drove the flight fixture changes:
the generic 512 MiB artifact made the 16-worker crash fixture exceed the
physical deadline, so a demo-only 64 MiB capacity was added under an explicit
test that generic defaults remain 512 MiB. Complete and deliberately truncated
QTRB/flight fixtures proved the recovery oracle still rejects incomplete
records. No rendering or record-validation oracle was skipped.

## Success Evidence RED/GREEN

The success-retention implementation was test-driven through these explicit
contracts:

- successful atomic publication and absolute path output;
- destination collision with neither directory replaced;
- rename failure preserving scratch;
- scratch identity swap rejection;
- parent-directory fsync failure exposing the retained destination;
- manifest failure converting the run into a retained gate failure;
- publication only after gate cleanup returns;
- post-rename failure reporting the actual retained path.

The manifest is strict schema 1, finite JSON, at most 64 KiB, created through
exclusive/no-follow files and an atomic no-replace directory rename. File and
parent directories are fsynced. Any publication error prevents success and
routes through failure preservation. Both evidence roots are gitignored; their
on-disk content remains intact.

## Approved Task 4 Scope Deviation

The physical gate proved that Task 4 could not complete with README-only
changes. Under the approved waiver, prerequisite repairs touched seven generic
qtrace files (`agent.js`, `artifacts.py`, `build.py`, `cli.py`, `demo.py`,
`preflight.py`, `session.py`), native tracer lifecycle/status code, and the
fixed demo app adapter. Each repair above arose from a real strict-gate failure
and has a regression seam.

The deviation does not add a demo branch to generic external-package paths,
does not change the generic 512 MiB default, and does not weaken strict
validation. Fixed-package behavior is confined to the acceptance/demo adapter.

## Review Findings and Remaining Concerns

- Same-numeric PID reuse was fixed by validating held starttime on every poll.
- The entrypoint's Gradle command is the exact required combined host gate.
- The review suggestion that `::close(source_fd) != 0 && success` might skip
  close was rejected: C++ `&&` evaluates the left operand first, so
  `::close(source_fd)` always executes; no code change was required.
- Injection canonicalization is target-side and follows the package's real
  app-private root, so it is compatible with secondary users. Manual pull's
  existing package-access binder still has a `/data/user/0` mapping limitation;
  the final user-0 Pixel gate validates that supported case, while secondary
  Android users remain an explicit follow-up risk rather than a silent
  hard-coded claim.
- Acceptance backups and success/failure evidence are intentionally retained.
  Operators must manage their disk usage manually; the gate never deletes them.

## Commits

The four plan-task implementation tips are:

- Task 1: `615e365`;
- Task 2: `59679eb`;
- Task 3: `1fee49f`;
- Task 4 implementation: `489b38f0be479ecd054975236ddbb115a787285a`.

Task 4 implementation commits are:

- `1206614bf3469c50a2a12c917fd7c209c71d0839` — strict physical-gate prerequisite repairs, tests, README, and waiver;
- `ee096c1fa56a4e855750fb51d636cacfbae2395f` — bounded ADB timeout normalization;
- `489b38f0be479ecd054975236ddbb115a787285a` — committed quiescent exit status wait.

The handoff separately reports the later documentation/report commit, which
cannot self-record its own hash. The success manifest intentionally binds the
final implementation HEAD `489b38f`, not that report-only commit.
