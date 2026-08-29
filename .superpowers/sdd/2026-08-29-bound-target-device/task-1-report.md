# Task 1 report: immutable bound-device module

## Implementation

- Added frozen `TargetBinding` with package, access, root/target strategy, UID, Android user, and data-directory validation.
- Replaced mutable `AdbDevice.bind_package()` state with non-mutating `AdbDevice.bind_target()` returning a new `BoundTargetDevice`.
- Moved identity properties, root/target shell routing, bounded target streaming, and `trace_directory` to `BoundTargetDevice`.
- Updated device tests to use the new transition and added immutability/identity validation interface tests.

## Files changed

- `qtrace/device.py`
- `scripts/tests/test_qtrace_device.py`

## Tests and results

### RED (expected)

Command:

```text
python3 -m unittest scripts.tests.test_qtrace_device.AdbDeviceTests.test_bind_target_returns_a_new_bound_device_without_mutating_selected_device scripts.tests.test_qtrace_device.AdbDeviceTests.test_target_binding_rejects_inconsistent_identity_fields_with_stable_codes
```

Result (exact output):

```text
EE
======================================================================
ERROR: test_qtrace_device (unittest.loader._FailedTest.test_qtrace_device)
----------------------------------------------------------------------
ImportError: Failed to import test module: test_qtrace_device
Traceback (most recent call last):
  File "/usr/lib/python3.12/unittest/loader.py", line 137, in loadTestsFromName
    module = __import__(module_name)
  File "/home/lyldalek/workspace/qbdi-android/.worktrees/bound-target-device/scripts/tests/test_qtrace_device.py", line 11, in <module>
    from qtrace.device import AdbDevice, BoundTargetDevice, DeviceSelector, TargetBinding
ImportError: cannot import name 'BoundTargetDevice' from 'qtrace.device' (/home/lyldalek/workspace/qbdi-android/.worktrees/bound-target-device/qtrace/device.py)

----------------------------------------------------------------------
Ran 2 tests in 0.000s

FAILED (errors=2)
```

Both tests failed during import because `BoundTargetDevice` was not yet available from `qtrace.device`; this was the expected pre-implementation failure.

### GREEN

Command:

```text
python3 -m unittest scripts.tests.test_qtrace_device
```

Result:

```text
Ran 20 tests in 0.027s

OK
```

Also ran `git diff --check` successfully.

## Self-review

Reviewed the diff for the requested API boundary, immutable binding, validation error codes, unchanged bounded command tuples, and removal of mutable identity state from `AdbDevice`. No unrelated files were changed.

## Concerns

Existing callers outside this task still reference the removed mutable `bind_package()` API; those consumers are expected to migrate in subsequent tasks.
