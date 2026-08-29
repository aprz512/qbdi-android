# Task 3 Report: Trust the bound interface in deploy and inject

## Implementation summary

- Changed `Deployer` deploy helpers and `deploy()` to consume `BoundTargetDevice`.
- Removed duplicate deploy binding validation and direct reads now use the bound device's non-optional identity properties.
- Changed injector request validation, validated-request storage, and `FridaInjector` to consume `BoundTargetDevice` while retaining the provider's `AdbDevice` interface.
- Replaced the obsolete unbound deploy test with a regression proving deploy does not inspect `android_user`; added package-mismatch injection coverage.

## Files changed

- `qtrace/build.py`
- `qtrace/injector.py`
- `scripts/tests/test_qtrace_build.py`
- `scripts/tests/test_qtrace_injector.py`
- `.superpowers/sdd/2026-08-29-bound-target-device/task-3-report.md`

## TDD evidence

RED command:

```text
python3 -m unittest scripts.tests.test_qtrace_build.DeployerTests.test_deployer_does_not_revalidate_identity_owned_by_bound_device
```

Output: `FAILED (errors=1)`, with `qtrace: stage=deploy code=device.unbound ...` from the old duplicate validation block. This was expected because the structural fake intentionally omitted `android_user`.

GREEN focused command:

```text
python3 -m unittest scripts.tests.test_qtrace_build scripts.tests.test_qtrace_injector
```

Output: `Ran 54 tests ... OK`.

Additional focused command:

```text
python3 -m unittest scripts.tests.test_qtrace_cli scripts.tests.test_qtrace_preflight scripts.tests.test_qtrace_device scripts.tests.test_qtrace_session
```

Output: `Ran 115 tests ... OK`.

`git diff --check`: clean (exit 0).

## Self-review

- Session-ID validation remains before any device operation.
- Deployment routes, remote paths, command tuples, cleanup, and error behavior remain unchanged.
- Injector package mismatch fails before side effects with `inject.request_invalid`.
- `FridaProvider.get_device()` remains typed as `AdbDevice` as required.
- No session/artifact implementation work was included.

## Concerns

Existing test doubles are structural and are not runtime-checked with `isinstance`; this preserves current test seams while narrowing production annotations.

## Commit SHA

Implementation commit: `c82f3b6`.
