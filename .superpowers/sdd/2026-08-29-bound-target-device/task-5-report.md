# Task 5 Report: Bound artifact device interface

## Summary

- Migrated artifact collection's default device client and public processor annotations to `BoundTargetDevice`.
- The default client now checks only the bound package, takes its trace directory directly from `trace_directory`, and streams through the bound transport without optional-property fallbacks.
- Artifact metadata now reads non-optional bound identity fields. Existing status-host-context merging is unchanged.
- Added a complete `FakeBoundDevice` adapter and migrated artifact and contract callers from string sentinels.

## Files changed

- `qtrace/artifacts.py`
- `scripts/tests/test_qtrace_artifacts.py`
- `scripts/tests/test_qtrace_contracts.py`
- `.superpowers/sdd/2026-08-29-bound-target-device/task-5-report.md`

## RED

Command:

```bash
python3 -m unittest scripts.tests.test_qtrace_artifacts.ArtifactTests.test_manual_client_reuses_the_same_bound_target_shell_device
```

Output:

```text
ERROR: test_manual_client_reuses_the_same_bound_target_shell_device
qtrace.errors.QtraceError: qtrace: stage=artifacts code=artifact.binding_invalid detail=bound device package data directory is missing or inconsistent
Ran 1 test in 0.001s
FAILED (errors=1)
```

This was expected: the updated fake intentionally exposes `trace_directory`, not `package_data_dir`; the pre-change default client still performed package-data-directory validation.

## GREEN and focused regressions

Commands:

```bash
python3 -m unittest scripts.tests.test_qtrace_artifacts.ArtifactTests.test_manual_client_reuses_the_same_bound_target_shell_device
python3 -m unittest scripts.tests.test_qtrace_artifacts
python3 -m unittest scripts.tests.test_qtrace_contracts.AcceptanceHarnessTests.test_pull_validator_accepts_reports_written_by_every_production_pull_mode scripts.tests.test_qtrace_contracts.AcceptanceHarnessTests.test_pull_validator_accepts_real_complete_flight_union_record
python3 -m unittest scripts.tests.test_qtrace_artifacts scripts.tests.test_qtrace_session scripts.tests.test_qtrace_cli scripts.tests.test_qtrace_preflight scripts.tests.test_qtrace_device scripts.tests.test_qtrace_build scripts.tests.test_qtrace_injector
```

Output:

```text
Ran 1 test in 0.000s
OK

Ran 81 tests in 2.353s
OK

Ran 2 tests in 1.239s
OK

Ran 251 tests in 4.178s
OK
```

## Full regression gate

Commands:

```bash
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
python3 -m compileall -q qtrace
git diff --check
```

Output:

```text
Ran 800 tests in 58.926s
OK (skipped=8)

# compileall: no output, exit 0
# git diff --check: no output, exit 0
```

The discovery run contains expected child-process usage/error text and deprecation warnings from acceptance harness coverage; its unittest result is `OK (skipped=8)`.

## Bound-state scan

Command:

```bash
rg -n 'bind_package|_package: str \| None|_access_mode: str \| None|valid_binding|getattr\(device, "(package|access_mode|root_strategy|package_uid|target_strategy|android_user|package_data_dir|target_shell)"' qtrace
rg -n 'def bind_package\(' qtrace
```

Output:

```text
qtrace/preflight.py:275:def bind_package_access(
qtrace/cli.py:23:from qtrace.preflight import bind_package_access
qtrace/cli.py:368:    device = bind_package_access(device, arguments.package, timeout=arguments.adb_timeout)
# def bind_package(: no output
```

`bind_package_access` is the permitted replacement API; no deleted mutable binding method or optional downstream identity access matched.

## Self-review

- Default artifact streaming remains bounded at `_MAX_ARTIFACT_BYTES` and calls `BoundTargetDevice.stream_target_file()` directly.
- The existing target-shell calls for listing, size, and bounded status reads are unchanged; therefore command shape and path validation remain in the bound-device interface.
- Output publication, directory identity checks, and report-host-context precedence were left intact.
- Package mismatch retains `artifact.binding_invalid`; no CLI output or external command shape changed.
- Contract coverage now supplies the full bound identity shape where a custom artifact client bypasses the production adapter.

## Concerns

One initial full-suite run hit the unrelated timing-sensitive `test_runtime_byte_mutation_changes_canonical_hash` deadline. Its focused rerun passed in 0.197s, and the fresh required full discovery gate passed. No production change was made for that unrelated test.

## Commit

`fbac540eb50c99854dd24c44cc2b57588bd7b965` — `refactor(qtrace): use bound device for artifacts`

## Fix round 1

### Findings addressed

- Removed the default `artifact_client` and duck-typed artifact-client fallbacks from `_client_for()`. The explicit, validated `client_factory` remains the only internal seam; every default path now constructs `_BoundDeviceClient`, which enforces bound-package identity and uses `trace_directory`.
- Added a regression test covering both removed bypass shapes (`artifact_client` and duck-typed `list_names`/`read_file`/`stream_file`) with a mismatched bound package. Both now return `artifact.binding_invalid` before either legacy capability can run.
- Expanded the device-report metadata test to assert serial, package, access mode, root strategy, target strategy, and package UID.

### RED

Command:

```bash
python3 -m unittest scripts.tests.test_qtrace_artifacts.ArtifactTests.test_default_client_rejects_package_mismatch_despite_legacy_client_capabilities scripts.tests.test_qtrace_artifacts.ArtifactTests.test_artifact_report_uses_actual_device_metadata
```

Output:

```text
FAIL: test_default_client_rejects_package_mismatch_despite_legacy_client_capabilities (device='ArtifactClientDevice')
AssertionError: legacy artifact client must not be selected

FAIL: test_default_client_rejects_package_mismatch_despite_legacy_client_capabilities (device='DuckClientDevice')
AssertionError: QtraceError not raised

Ran 2 tests in 0.033s
FAILED (failures=2)
```

The failure is expected: the old default branches selected `artifact_client` and the duck-typed device before `_BoundDeviceClient` could enforce the package mismatch.

### GREEN and focused regressions

Commands:

```bash
python3 -m unittest scripts.tests.test_qtrace_artifacts.ArtifactTests.test_default_client_rejects_package_mismatch_despite_legacy_client_capabilities scripts.tests.test_qtrace_artifacts.ArtifactTests.test_artifact_report_uses_actual_device_metadata
python3 -m unittest scripts.tests.test_qtrace_artifacts
python3 -m unittest scripts.tests.test_qtrace_contracts
python3 -m unittest scripts.tests.test_qtrace_artifacts scripts.tests.test_qtrace_session scripts.tests.test_qtrace_cli scripts.tests.test_qtrace_preflight scripts.tests.test_qtrace_device scripts.tests.test_qtrace_build scripts.tests.test_qtrace_injector
```

Output:

```text
Ran 2 tests in 0.039s
OK

Ran 82 tests in 2.379s
OK

Ran 98 tests in 8.356s
OK

Ran 252 tests in 4.193s
OK
```

### Full gate

Commands:

```bash
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
python3 -m compileall -q qtrace
git diff --check
```

Output:

```text
Ran 801 tests in 52.207s
OK (skipped=8)

# compileall: no output, exit 0
# git diff --check: no output, exit 0
```

The full suite again emitted its expected child-process usage text and deprecation warnings. The prior historical-benchmark deadline flake did not recur in this run.

### Commit

`759236de154e4c596c289fee2382e720e9a441d1` — `refactor(qtrace): require bound artifact clients`
