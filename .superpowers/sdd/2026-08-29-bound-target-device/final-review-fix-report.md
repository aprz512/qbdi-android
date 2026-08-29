# BoundTargetDevice final-review fix wave

## Scope

- Corrected the preflight comment to describe late binding and the immutable identity of the returned wrapper. It no longer claims that binding prevents independent wrappers for the same selected device.
- Added focused command-route characterization tests for direct-root `root_shell()` and su-UID `stream_target_file()`.
- Did not change production routing, public behavior, or the existing non-blocking run-as `root_shell` design/plan prose tension.

## Characterized command tuples

- Direct root: `("adb", "-s", "SERIAL", "shell", "mkdir", "-p", "/data/local/tmp/qtrace")`, captured with `maximum_bytes=512` and `timeout=1.5`.
- su-UID stream: `("adb", "-s", "SERIAL", "exec-out", "su", "10905", "-c", "'cat /data/user/0/com.example.app/files/qbdi-traces/run.trace.bin'")`, streamed with `maximum_bytes=512` and `timeout=1.5`.

Both tests passed immediately on the existing production implementation, as expected for characterization coverage rather than a production defect fix:

```text
$ python3 -m unittest scripts.tests.test_qtrace_device.AdbDeviceTests.test_direct_root_shell_uses_the_direct_bounded_command_tuple scripts.tests.test_qtrace_device.AdbDeviceTests.test_su_uid_target_stream_uses_the_bounded_command_tuple
..
----------------------------------------------------------------------
Ran 2 tests in 0.000s

OK
```

## Verification

```text
$ python3 -m unittest scripts.tests.test_qtrace_device scripts.tests.test_qtrace_preflight
...................................
----------------------------------------------------------------------
Ran 35 tests in 0.014s

OK
```

```text
$ python3 -m unittest discover -s scripts/tests -p 'test_*.py'
Ran 803 tests in 60.512s

OK (skipped=8)
```

The discovery output also contains expected subprocess argument-validation/failure-path text and existing `multiprocessing` fork deprecation warnings; its exit status was 0.

```text
$ python3 -m compileall -q qtrace
# exit 0; no output

$ git diff --check
# exit 0; no output
```

## Self-review

Reviewed the final diff. The only source change is the corrected comment; the two tests assert literal ADB argv, returned/streamed data, and exact finite bound/timeout calls. No production defect was exposed.

## Files changed

- `qtrace/preflight.py`
- `scripts/tests/test_qtrace_device.py`
- `.superpowers/sdd/2026-08-29-bound-target-device/final-review-fix-report.md`

## Concerns

None. Code/test commit SHA: `7cfb6e28d8ea4ddf2fb3a77877d3f9c17d881f33`.
