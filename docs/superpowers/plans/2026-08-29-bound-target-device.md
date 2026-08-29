# BoundTargetDevice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace mutable package binding on `AdbDevice` with a validated `TargetBinding` and a concrete `BoundTargetDevice` returned by preflight.

**Architecture:** `AdbDevice` remains the selected-device Module and retains generic, validated ADB operations. `AdbDevice.bind_target(TargetBinding)` returns a new `BoundTargetDevice`; downstream callers receive that type and use non-optional identity properties without repeating binding validation. The existing `CommandRunner` Seam remains the command test surface, with the bounded production runner and test fakes as its Adapters.

**Tech Stack:** Python 3 standard library, frozen dataclasses, `unittest`, existing qtrace `QtraceError` model.

## Global Constraints

- Preserve all qtrace CLI arguments, success output, failure exit codes, report shapes, and generated ADB commands.
- Do not retain compatibility for external Python callers of `AdbDevice.bind_package()`.
- Do not change ADB stderr/cause classification, `ArtifactResult`, publication claims, Native tracer code, or CI gates in this plan.
- Add no third-party dependency and no new binding Seam or Adapter.
- Keep `TargetBinding` identity fields non-optional and immutable through its public Interface.
- Use red-green-refactor: observe each new behavioral test fail for the intended reason before changing production code.
- Replace obsolete mutable-binding tests; do not layer them beneath the new Interface tests.
- In this indexed repository, use CodeGraph before grep or file reads when locating code during execution.

---

## File Map

- `qtrace/device.py`: owns `TargetBinding`, `AdbDevice`, and `BoundTargetDevice`; all binding invariants stay local here.
- `qtrace/preflight.py`: discovers a `TargetBinding` and returns a `BoundTargetDevice` only after every prerequisite passes.
- `qtrace/cli.py`: uses the bound object returned by manual pull preflight.
- `qtrace/build.py`: deploys through the bound Interface and removes duplicate identity validation.
- `qtrace/injector.py`: requires the bound Interface and compares the request package directly with it.
- `qtrace/session.py`: uses `trace_directory`, `target_shell`, and identity metadata directly from the bound Interface.
- `qtrace/artifacts.py`: builds its default client and report metadata from the bound Interface.
- `scripts/tests/test_qtrace_device.py`: primary Interface tests for binding and command routing.
- `scripts/tests/test_qtrace_preflight.py`: preflight return-value and identity-flow tests.
- `scripts/tests/test_qtrace_cli.py`: manual pull return-value flow test.
- `scripts/tests/test_qtrace_build.py`: deploy test Adapter and duplicate-validation deletion test.
- `scripts/tests/test_qtrace_injector.py`: bound-package validation regression tests.
- `scripts/tests/test_qtrace_session.py`: bound trace-directory and identity-flow tests.
- `scripts/tests/test_qtrace_artifacts.py`: bound artifact client and metadata tests.

---

### Task 1: Introduce the immutable bound-device Module

**Files:**
- Modify: `qtrace/device.py:200-477,623`
- Test: `scripts/tests/test_qtrace_device.py:11,117-180,349-420`

**Interfaces:**
- Consumes: existing `CommandRunner`, `_validate_package()`, `_validate_package_uid()`, `_validate_android_user()`, `_is_valid_remote_path()`, and bounded ADB helpers.
- Produces: `TargetBinding(package: str, access_mode: str, root_strategy: str, package_uid: int, target_strategy: str, android_user: int, package_data_dir: str)`, `AdbDevice.bind_target(binding: TargetBinding) -> BoundTargetDevice`, and `BoundTargetDevice.trace_directory: str` plus non-optional identity properties.

- [ ] **Step 1: Add the new Interface tests and replace the mutable-binding assertion**

Update the imports and add a helper at the top of `test_qtrace_device.py`:

```python
from dataclasses import FrozenInstanceError

from qtrace.device import AdbDevice, BoundTargetDevice, DeviceSelector, TargetBinding


def target_binding(**changes):
    values = {
        "package": "com.example.one",
        "access_mode": "root",
        "root_strategy": "su",
        "package_uid": 10905,
        "target_strategy": "run-as",
        "android_user": 0,
        "package_data_dir": "/data/user/0/com.example.one",
    }
    values.update(changes)
    return TargetBinding(**values)
```

Replace `test_validated_package_binding_is_idempotent_but_cannot_be_retargeted` with tests that describe the new Interface:

```python
def test_bind_target_returns_a_new_bound_device_without_mutating_selected_device(self):
    selected = AdbDevice("SERIAL", FakeRunner())

    bound = selected.bind_target(target_binding())

    self.assertIsInstance(bound, BoundTargetDevice)
    self.assertIsNot(selected, bound)
    self.assertIs(selected.runner, bound.runner)
    self.assertFalse(hasattr(selected, "package"))
    self.assertFalse(hasattr(selected, "target_shell"))
    self.assertEqual("com.example.one", bound.package)
    self.assertEqual("root", bound.access_mode)
    self.assertEqual("su", bound.root_strategy)
    self.assertEqual(10905, bound.package_uid)
    self.assertEqual("run-as", bound.target_strategy)
    self.assertEqual(0, bound.android_user)
    self.assertEqual("/data/user/0/com.example.one", bound.package_data_dir)
    self.assertEqual(
        "/data/user/0/com.example.one/files/qbdi-traces",
        bound.trace_directory,
    )
    with self.assertRaises(FrozenInstanceError):
        bound.binding.package = "com.example.other"


def test_target_binding_rejects_inconsistent_identity_fields_with_stable_codes(self):
    cases = (
        ({"access_mode": "invalid"}, "device.access_mode_invalid"),
        ({"root_strategy": "invalid"}, "device.root_strategy_invalid"),
        ({"target_strategy": "invalid"}, "device.target_strategy_invalid"),
        ({"access_mode": "run-as"}, "device.binding_invalid"),
        ({"root_strategy": "none"}, "device.binding_invalid"),
        ({"target_strategy": "su-uid", "access_mode": "run-as", "root_strategy": "none"},
         "device.binding_invalid"),
        ({"android_user": 1}, "device.data_dir_invalid"),
        ({"package_uid": 10000, "android_user": 1,
          "package_data_dir": "/data/user/1/com.example.one"},
         "device.uid_user_mismatch"),
    )
    for changes, code in cases:
        with self.subTest(changes=changes), self.assertRaises(QtraceError) as caught:
            target_binding(**changes)
        self.assertEqual(code, caught.exception.code)
```

- [ ] **Step 2: Run the new tests and verify RED**

Run:

```bash
python3 -m unittest \
  scripts.tests.test_qtrace_device.AdbDeviceTests.test_bind_target_returns_a_new_bound_device_without_mutating_selected_device \
  scripts.tests.test_qtrace_device.AdbDeviceTests.test_target_binding_rejects_inconsistent_identity_fields_with_stable_codes
```

Expected: FAIL because `BoundTargetDevice` and `TargetBinding` cannot yet be imported.

- [ ] **Step 3: Add `TargetBinding` and the non-mutating transition**

In `qtrace/device.py`, add this frozen value after the validation helpers and remove `_package`, `_access_mode`, `_root_strategy`, `_package_uid`, `_target_strategy`, `_android_user`, and `_package_data_dir` from `AdbDevice.__init__`:

```python
@dataclass(frozen=True)
class TargetBinding:
    package: str
    access_mode: str
    root_strategy: str
    package_uid: int
    target_strategy: str
    android_user: int
    package_data_dir: str

    def __post_init__(self) -> None:
        package = _validate_package(self.package)
        if self.access_mode not in {"root", "run-as"}:
            _fail("device.access_mode_invalid", "device.bind", "access mode is invalid")
        uid = _validate_package_uid(self.package_uid)
        user = _validate_android_user(self.android_user)
        expected_data_dir = f"/data/user/{user}/{package}"
        if self.package_data_dir != expected_data_dir or not _is_valid_remote_path(
            self.package_data_dir
        ):
            _fail(
                "device.data_dir_invalid",
                "device.bind",
                "package data directory does not match the bound Android user",
            )
        if uid // 100_000 != user:
            _fail(
                "device.uid_user_mismatch",
                "device.bind",
                "package UID does not belong to the bound Android user",
            )
        if self.root_strategy not in {"direct", "su", "none"}:
            _fail("device.root_strategy_invalid", "device.bind", "root strategy is invalid")
        if self.target_strategy not in {"run-as", "su-uid"}:
            _fail("device.target_strategy_invalid", "device.bind", "target strategy is invalid")
        if self.access_mode == "run-as" and (
            self.root_strategy != "none" or self.target_strategy != "run-as"
        ):
            _fail(
                "device.binding_invalid",
                "device.bind",
                "run-as access cannot carry a root or su-uid strategy",
            )
        if self.access_mode == "root" and self.root_strategy == "none":
            _fail("device.binding_invalid", "device.bind", "root access requires a root strategy")
        if self.target_strategy == "su-uid" and self.access_mode != "root":
            _fail("device.binding_invalid", "device.bind", "su-uid requires root access")
        object.__setattr__(self, "package", package)
        object.__setattr__(self, "package_uid", uid)
        object.__setattr__(self, "android_user", user)
        object.__setattr__(self, "package_data_dir", expected_data_dir)
```

Replace `AdbDevice.bind_package()` and its optional properties with this transition:

```python
def bind_target(self, binding: TargetBinding) -> "BoundTargetDevice":
    if not isinstance(binding, TargetBinding):
        _fail("device.binding_invalid", "device.bind", "target binding is invalid")
    return BoundTargetDevice(self.serial, self.runner, binding)
```

- [ ] **Step 4: Move identity-dependent behavior to `BoundTargetDevice`**

Remove `root_shell()`, `target_shell()`, and `stream_target_file()` from `AdbDevice`. Add `BoundTargetDevice` immediately before `DeviceSelector`:

```python
class BoundTargetDevice(AdbDevice):
    def __init__(
        self, serial: str, runner: CommandRunner, binding: TargetBinding
    ) -> None:
        super().__init__(serial, runner)
        if not isinstance(binding, TargetBinding):
            _fail("device.binding_invalid", "device.bind", "target binding is invalid")
        self._binding = binding

    @property
    def binding(self) -> TargetBinding:
        return self._binding

    @property
    def package(self) -> str:
        return self._binding.package

    @property
    def access_mode(self) -> str:
        return self._binding.access_mode

    @property
    def root_strategy(self) -> str:
        return self._binding.root_strategy

    @property
    def package_uid(self) -> int:
        return self._binding.package_uid

    @property
    def target_strategy(self) -> str:
        return self._binding.target_strategy

    @property
    def android_user(self) -> int:
        return self._binding.android_user

    @property
    def package_data_dir(self) -> str:
        return self._binding.package_data_dir

    @property
    def trace_directory(self) -> str:
        return f"{self.package_data_dir}/files/qbdi-traces"

    def root_shell(
        self,
        *args: str,
        timeout: float = 30.0,
        maximum_bytes: int = 1_048_576,
    ) -> bytes:
        if self.root_strategy == "direct":
            return self.shell(*args, timeout=timeout, maximum_bytes=maximum_bytes)
        if self.root_strategy == "su":
            return self.su_shell(*args, timeout=timeout, maximum_bytes=maximum_bytes)
        _fail("device.unbound", "device.root_shell", "root identity is not bound")

    def target_shell(
        self,
        *args: str,
        timeout: float = 30.0,
        maximum_bytes: int = 1_048_576,
    ) -> bytes:
        if self.target_strategy == "run-as":
            return self.shell(
                *_run_as_argv(self.package, self.android_user, *args),
                timeout=timeout,
                maximum_bytes=maximum_bytes,
            )
        return self.su_uid_shell(
            self.package_uid,
            *args,
            timeout=timeout,
            maximum_bytes=maximum_bytes,
        )

    def stream_target_file(
        self,
        path: str,
        output: object,
        *,
        maximum_bytes: int,
        timeout: float,
    ) -> None:
        path = _validate_remote_path(path)
        maximum_bytes, timeout = _validate_limits(
            maximum_bytes, timeout, stage="device.target_stream"
        )
        if self.target_strategy == "run-as":
            arguments = (
                "exec-out",
                *_run_as_argv(self.package, self.android_user, "cat", path),
            )
        else:
            command = _compose_su_command(("cat", path))
            arguments = ("exec-out", "su", str(self.package_uid), "-c", command)
        stream = getattr(self.runner, "stream", None)
        if not callable(stream):
            _fail(
                "device.streaming_unavailable",
                "device.target_stream",
                "bounded streaming transport is unavailable",
            )
        try:
            stream(
                self._host_command(*arguments),
                output,
                maximum_bytes=maximum_bytes,
                timeout=timeout,
            )
        except QtraceError:
            raise
        except (OSError, RuntimeError, TimeoutError, TypeError, ValueError) as error:
            wrapped = QtraceError(
                "device.command_failed",
                "device.target_stream",
                f"ADB stream failed: {error}",
            )
            raise wrapped from error
```

- [ ] **Step 5: Migrate the existing command-routing tests to the new transition**

Replace every `device.bind_package(...)` in `test_qtrace_device.py` with construction of the same `TargetBinding` followed by assignment of the returned device. For example:

```python
selected = AdbDevice("SERIAL", runner)
device = selected.bind_target(TargetBinding(
    package="com.example.app",
    access_mode="run-as",
    root_strategy="none",
    package_uid=1_010_905,
    target_strategy="run-as",
    android_user=10,
    package_data_dir="/data/user/10/com.example.app",
))
```

Use `target_binding(target_strategy="su-uid")` for the existing su-uid route test. Delete all assertions about idempotent rebinding and conflicting retargeting because those states no longer exist.

- [ ] **Step 6: Run the device tests and verify GREEN**

Run:

```bash
python3 -m unittest scripts.tests.test_qtrace_device
```

Expected: all device tests PASS, with the existing run-as, secondary-user, root, su-uid, and bounded streaming command tuples unchanged.

- [ ] **Step 7: Commit Task 1**

```bash
git add qtrace/device.py scripts/tests/test_qtrace_device.py
git commit -m "refactor(qtrace): introduce bound target device"
```

---

### Task 2: Make preflight and manual pull return the bound object

**Files:**
- Modify: `qtrace/preflight.py:13-14,138-307,315-451`
- Modify: `qtrace/cli.py:364-370`
- Test: `scripts/tests/test_qtrace_preflight.py:8-10,40-157,181-288`
- Test: `scripts/tests/test_qtrace_cli.py:215-276`

**Interfaces:**
- Consumes: `TargetBinding` and `AdbDevice.bind_target()` from Task 1.
- Produces: `_discover_package_access(...) -> TargetBinding`, `bind_package_access(...) -> BoundTargetDevice`, and `Preflight.run(...) -> tuple[BoundTargetDevice, DeviceIdentity]`.

- [ ] **Step 1: Change the preflight fake and expectations to return a distinct bound value**

Import `TargetBinding` in `test_qtrace_preflight.py` and add this fake next to `FakeDevice`:

```python
class FakeBoundDevice:
    def __init__(self, selected, binding):
        self.selected = selected
        self.binding = binding
        self.serial = selected.serial

    @property
    def package(self):
        return self.binding.package

    @property
    def access_mode(self):
        return self.binding.access_mode

    @property
    def android_user(self):
        return self.binding.android_user

    @property
    def package_data_dir(self):
        return self.binding.package_data_dir
```

Replace `FakeDevice.bind_package()` with:

```python
def bind_target(self, binding):
    self.events.append(("bind", binding))
    return FakeBoundDevice(self, binding)
```

Change the manual binder test to capture and inspect its return value:

```python
bound = bind_package_access(device, "com.example.external", timeout=2.0)

self.assertIsInstance(bound, FakeBoundDevice)
self.assertIs(device, bound.selected)
self.assertEqual("root", bound.binding.access_mode)
self.assertEqual("direct", bound.binding.root_strategy)
self.assertEqual(20000, bound.binding.package_uid)
self.assertEqual("run-as", bound.binding.target_strategy)
self.assertEqual(0, bound.binding.android_user)
self.assertEqual("/data/user/0/com.example.external", bound.binding.package_data_dir)
```

Update preflight success assertions from `self.assertIs(device, selected)` to:

```python
self.assertIsInstance(selected, FakeBoundDevice)
self.assertIs(device, selected.selected)
self.assertEqual(identity.access_mode, selected.binding.access_mode)
self.assertEqual(identity.android_user, selected.binding.android_user)
self.assertEqual(identity.package_data_dir, selected.binding.package_data_dir)
```

For existing bind event assertions, compare `event[1]` with the exact `TargetBinding` instead of the old flattened tuple.

- [ ] **Step 2: Verify the preflight tests are RED**

Run:

```bash
python3 -m unittest \
  scripts.tests.test_qtrace_preflight.PreflightTests.test_manual_package_binder_reuses_bound_target_identity_without_session_prerequisites \
  scripts.tests.test_qtrace_preflight.PreflightTests.test_installs_existing_apk_before_package_checks_and_records_identity
```

Expected: FAIL because `_discover_package_access()` still returns a tuple and preflight still calls `bind_package()`.

- [ ] **Step 3: Return `TargetBinding` from discovery and delete the mutation helper**

Update imports and the discovery return:

```python
from qtrace.device import (
    AdbDevice,
    BoundTargetDevice,
    DeviceIdentity,
    DeviceSelector,
    TargetBinding,
    _run_as_argv,
    _validate_package,
)


def _discover_package_access(
    device: AdbDevice,
    package: str,
    budget: Callable[[], float],
) -> TargetBinding:
```

Leave the discovery commands and their existing error handling unchanged. Replace the final tuple return, immediately after the existing UID/user consistency check, with:

```python
    return TargetBinding(
        package=package,
        access_mode=access_mode,
        root_strategy=root_strategy,
        package_uid=package_uid,
        target_strategy=target_strategy,
        android_user=android_user,
        package_data_dir=package_data_dir,
    )
```

Delete `_bind_discovered_package_access()`. Change the manual entry point to:

```python
def bind_package_access(
    device: AdbDevice, package: str, *, timeout: float
) -> BoundTargetDevice:
    """Return one package-bound device without config, build, Frida, or app launch work."""
    timeout = _positive_finite(timeout, "timeout")
    deadline = time.monotonic() + timeout

    def budget() -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _fail("preflight.timeout", "preflight", "package access time budget was exhausted")
        return remaining

    package = _validate_package(package)
    _external(
        "preflight.package",
        lambda: device.package_apk_paths(package, timeout=budget()),
    )
    binding = _discover_package_access(device, package, budget)
    return _external("preflight.bind", lambda: device.bind_target(binding))
```

- [ ] **Step 4: Return the bound value from full preflight**

Change the return annotation and final section of `Preflight.run()`:

```python
) -> tuple[BoundTargetDevice, DeviceIdentity]:
```

Use properties rather than tuple indexes after discovery:

```python
access_binding = _discover_package_access(device, package, budget)
access_mode = access_binding.access_mode
```

After every host, space, lz4, and Frida prerequisite succeeds:

```python
bound_device = _external(
    "preflight.bind", lambda: device.bind_target(access_binding)
)
return bound_device, DeviceIdentity(
    serial=bound_device.serial,
    abi=abi,
    api_level=api_level,
    access_mode=access_binding.access_mode,
    frida_host_version=host_version,
    frida_server_version=server_version,
    free_bytes=free_bytes,
    android_user=access_binding.android_user,
    package_data_dir=access_binding.package_data_dir,
)
```

- [ ] **Step 5: Make manual pull consume the binder return value**

Change `qtrace/cli.py`:

```python
selected = _select_device(arguments.device, runner, arguments.adb_timeout)
device = bind_package_access(
    selected, arguments.package, timeout=arguments.adb_timeout
)
result = ArtifactProcessor().pull_manual(
    device,
    arguments.package,
    _selection(arguments),
    arguments.output,
    arguments.pull_timeout,
)
```

In `test_qtrace_cli.py`, make the binder return a distinct object and assert that the collector receives it:

```python
bound = SimpleNamespace(serial="serial", package="com.example.app")
binder.return_value = bound

def pull_manual(device, *_args, **_kwargs):
    self.assertIs(bound, device)
    return result
```

Remove the `selected.bound` mutation and its assertion. Keep all assertions proving pull does not load config, build, inspect, launch, or import Frida.

- [ ] **Step 6: Run preflight and CLI tests and verify GREEN**

Run:

```bash
python3 -m unittest scripts.tests.test_qtrace_preflight scripts.tests.test_qtrace_cli
```

Expected: all tests PASS; binding remains the last preflight state transition and manual pull passes the returned object to `ArtifactProcessor`.

- [ ] **Step 7: Commit Task 2**

```bash
git add qtrace/preflight.py qtrace/cli.py \
  scripts/tests/test_qtrace_preflight.py scripts/tests/test_qtrace_cli.py
git commit -m "refactor(qtrace): return bound device from preflight"
```

---

### Task 3: Trust the bound Interface in deploy and inject

**Files:**
- Modify: `qtrace/build.py:19,522-528,599-610,754-820`
- Modify: `qtrace/injector.py:18,227-242,810-812`
- Test: `scripts/tests/test_qtrace_build.py:142-185,653-667`
- Test: `scripts/tests/test_qtrace_injector.py:331-357,446-483`

**Interfaces:**
- Consumes: non-optional identity properties from `BoundTargetDevice`.
- Produces: `Deployer.deploy(device: BoundTargetDevice, ...)` and `FridaInjector(device: BoundTargetDevice, ...)`; neither accepts an unbound production device.

- [ ] **Step 1: Add a failing deploy test that forbids duplicate identity validation**

Replace the obsolete unbound-device test with:

```python
def test_deployer_does_not_revalidate_identity_owned_by_bound_device(self):
    session_id = "123e4567-e89b-42d3-a456-426614174000"
    with tempfile.TemporaryDirectory() as directory:
        device = FakeDeployDevice()
        del device.android_user

        deployment = Deployer().deploy(
            device, session_id, self.make_artifacts(Path(directory))
        )

    self.assertEqual("app-private", deployment.route)
    self.assertTrue(deployment.remote_dir.startswith(device.package_data_dir))
```

This structural fake still supplies every property deployment needs (`package`, `access_mode`, `root_strategy`, `target_strategy`, `package_uid`, and `package_data_dir`) but deliberately omits `android_user`, which deployment must not inspect after preflight has produced a bound device.

- [ ] **Step 2: Run the deploy test and verify RED**

Run:

```bash
python3 -m unittest \
  scripts.tests.test_qtrace_build.DeployerTests.test_deployer_does_not_revalidate_identity_owned_by_bound_device
```

Expected: FAIL with `device.unbound` because the current `valid_binding` block revalidates `android_user`.

- [ ] **Step 3: Remove duplicate deploy validation and narrow annotations**

Import `BoundTargetDevice` in `qtrace/build.py`. Change `_control_shell()`, `_attempt()`, and `deploy()` device annotations from `AdbDevice` to `BoundTargetDevice`.

Replace the identity-validation block at the start of `deploy()` with direct reads:

```python
package = device.package
access_mode = device.access_mode
package_data_dir = device.package_data_dir
```

Delete the local `root_strategy`, `package_uid`, `target_strategy`, `android_user`, `valid_binding`, and `device.unbound` branch. Keep session-ID validation before any device operation. Keep `_attempt()` behavior and generated remote paths unchanged.

- [ ] **Step 4: Narrow the injector Interface and remove the optional package fallback**

In `qtrace/injector.py`, import `BoundTargetDevice`; keep `FridaProvider.get_device()` accepting `AdbDevice` because a bound device is an `AdbDevice` and the provider only needs `serial`.

Change these definitions:

```python
@dataclass(frozen=True)
class _ValidatedRequest:
    request: InjectionRequest
    native_request: dict[str, object]
    expected_scenes: tuple[ResolvedScene, ...]
    request_device: BoundTargetDevice


def _validate_request(
    request: InjectionRequest, device: BoundTargetDevice
) -> _ValidatedRequest:
    if not isinstance(request, InjectionRequest):
        _fail("inject.request_invalid", "inject.validate", "request must be an InjectionRequest")
    if not isinstance(request.package, str) or _PACKAGE.fullmatch(request.package) is None:
        _fail("inject.request_invalid", "inject.validate", "package name is invalid")
    if device.package != request.package:
        _fail(
            "inject.request_invalid",
            "inject.validate",
            "package does not match the selected device binding",
        )
```

Retain the rest of `_validate_request()` unchanged and update:

```python
class FridaInjector:
    def __init__(self, device: BoundTargetDevice, frida_provider: FridaProvider):
        self._device = device
        self._frida_provider: FridaProvider | None = frida_provider
```

The existing `FakeAdbDevice.package = PACKAGE` satisfies the real caller Interface. Add this regression test after the invalid-request table test:

```python
def test_rejects_request_package_that_differs_from_bound_device(self):
    harness = InjectorHarness()
    harness.adb.package = "com.example.other"

    with self.assertRaises(QtraceError) as caught:
        harness.install()

    self.assertEqual("inject.request_invalid", caught.exception.code)
    self.assertEqual([], harness.events.snapshot())
```

- [ ] **Step 5: Run deploy and injector tests and verify GREEN**

Run:

```bash
python3 -m unittest scripts.tests.test_qtrace_build scripts.tests.test_qtrace_injector
```

Expected: all tests PASS; deployment no longer revalidates binding fields, and injection still rejects a request whose package differs from the bound package before side effects.

- [ ] **Step 6: Commit Task 3**

```bash
git add qtrace/build.py qtrace/injector.py \
  scripts/tests/test_qtrace_build.py scripts/tests/test_qtrace_injector.py
git commit -m "refactor(qtrace): trust bound device in deploy and inject"
```

---

### Task 4: Use the bound Interface throughout session orchestration

**Files:**
- Modify: `qtrace/session.py:15-25,533-625,743-769`
- Test: `scripts/tests/test_qtrace_session.py:85-125,387-398`

**Interfaces:**
- Consumes: `BoundTargetDevice.trace_directory`, `target_shell()`, `serial`, `access_mode`, `target_strategy`, and `package_uid`.
- Produces: session helper methods whose device parameter is `BoundTargetDevice` and which have no fallback path for unbound devices.

- [ ] **Step 1: Make the session fake expose the bound trace-directory Interface**

Change `FakeDevice.__init__()` in `test_qtrace_session.py` to accept an Android user and provide all identity metadata used by session reports:

```python
def __init__(
    self,
    statuses: list[object],
    pids: list[int | None],
    starttimes: list[int | None] | None = None,
    *,
    android_user: int = 0,
) -> None:
    self.statuses, self.pids = list(statuses), list(pids)
    self.starttimes = list(starttimes) if starttimes is not None else [99, None]
    self.read_paths: list[str] = []
    self.shell_timeouts: list[tuple[str, float]] = []
    self.killed: list[int] = []
    self.package = PACKAGE
    self.access_mode = "root"
    self.root_strategy = "direct"
    self.target_strategy = "run-as"
    self.package_uid = android_user * 100_000 + 20_000
    self.trace_directory = f"/data/user/{android_user}/{PACKAGE}/files/qbdi-traces"
```

Remove `package_data_dir` from the fake. Update the secondary-user test to construct `FakeDevice(..., android_user=10)` and retain its assertion on `/data/user/10/...` paths.

- [ ] **Step 2: Run the secondary-user session test and verify RED**

Run:

```bash
python3 -m unittest \
  scripts.tests.test_qtrace_session.SessionTests.test_session_status_and_snapshot_use_bound_secondary_user_trace_root
```

Expected: FAIL with `session.binding_invalid` because `_trace_directory()` still reconstructs and validates `package_data_dir` instead of using `trace_directory`.

- [ ] **Step 3: Remove unbound fallbacks from session helpers**

Import `BoundTargetDevice` and change the device annotation on `_trace_directory()`, `_status_path()`, `_snapshot_artifacts()`, `_current_pid()`, `_read_process_identity()`, `_read_status()`, `_read_final_status()`, wait helpers, and `_collect()` where they operate after preflight.

Replace the trace-directory helpers with:

```python
def _trace_directory(self, device: BoundTargetDevice) -> str:
    return device.trace_directory


def _status_path(
    self, device: BoundTargetDevice, session_id: str
) -> str:
    return f"{device.trace_directory}/session-{session_id}.status.json"
```

Update their call sites to remove the redundant package argument. In snapshot, PID, process-identity, and status reads, call `device.target_shell(...)` directly. Delete all `getattr(device, "target_shell", None)`, `device.pid(package)` fallback, and `device.read_file(...)` fallback branches.

Keep `_missing_remote()` and `_transient_adb()` unchanged; typed ADB outcomes are outside this plan.

- [ ] **Step 4: Read report metadata directly from the bound Interface**

Replace the session collector metadata with:

```python
"device": {
    "serial": device.serial,
    "access_mode": device.access_mode,
    "target_strategy": device.target_strategy,
    "package_uid": device.package_uid,
},
```

Do not change the collector result compatibility logic in `_collect()`; typed `ArtifactResult` is a separate plan.

- [ ] **Step 5: Run session tests and verify GREEN**

Run:

```bash
python3 -m unittest scripts.tests.test_qtrace_session
```

Expected: all session tests PASS, including timed, monitored, missing-status, transient-ADB, secondary-user, and report metadata cases.

- [ ] **Step 6: Commit Task 4**

```bash
git add qtrace/session.py scripts/tests/test_qtrace_session.py
git commit -m "refactor(qtrace): use bound device in sessions"
```

---

### Task 5: Use the bound Interface for artifact clients and metadata

**Files:**
- Modify: `qtrace/artifacts.py:24-35,325-394,1033-1442,1506`
- Test: `scripts/tests/test_qtrace_artifacts.py:1-42,60-152,193-236,541-552`

**Interfaces:**
- Consumes: `BoundTargetDevice.package`, `trace_directory`, `target_shell()`, `stream_target_file()`, and non-optional report identity properties.
- Produces: default `_BoundDeviceClient` construction without package-directory revalidation and `ArtifactProcessor` methods annotated for `BoundTargetDevice`.

- [ ] **Step 1: Add a shared bound-device test Adapter**

At the top of `test_qtrace_artifacts.py`, add:

```python
@dataclass(frozen=True)
class FakeBoundDevice:
    serial: str = "SERIAL"
    package: str = "com.example.app"
    access_mode: str = "root"
    root_strategy: str = "direct"
    target_strategy: str = "run-as"
    package_uid: int = 20000
    trace_directory: str = "/data/user/0/com.example.app/files/qbdi-traces"


BOUND_DEVICE = FakeBoundDevice()
```

Import `dataclass` from `dataclasses`. Replace string device sentinels (`"d"` and `"SERIAL"`) in every `ArtifactProcessor.collect_session()` and `pull_manual()` call with `BOUND_DEVICE`. Keep the package argument unchanged because artifact status identity still validates it.

For `test_artifact_report_uses_actual_device_metadata`, use:

```python
device = FakeBoundDevice(
    root_strategy="su", target_strategy="su-uid", package_uid=10905
)
```

- [ ] **Step 2: Make the default client test require `trace_directory`**

Change the local fake in `test_manual_client_reuses_the_same_bound_target_shell_device` so it has no `package_data_dir`:

```python
class BoundDevice:
    package = "com.example.app"
    trace_directory = "/data/user/0/com.example.app/files/qbdi-traces"

    def __init__(self):
        self.calls = []

    def target_shell(self, *args, timeout, maximum_bytes):
        self.calls.append((args, timeout, maximum_bytes))
        return b""
```

Make the same `package_data_dir` to `trace_directory` replacement in the secondary-user and streaming local fakes.

- [ ] **Step 3: Run the default-client test and verify RED**

Run:

```bash
python3 -m unittest \
  scripts.tests.test_qtrace_artifacts.ArtifactTests.test_manual_client_reuses_the_same_bound_target_shell_device
```

Expected: FAIL with `artifact.binding_invalid` because `_BoundDeviceClient` still reads `package_data_dir`.

- [ ] **Step 4: Consume the bound artifact Interface directly**

Import `BoundTargetDevice` in `qtrace/artifacts.py`. Change `_client_for()`, `_BoundDeviceClient.__init__()`, `ArtifactProcessor._collect()`, `collect_session()`, and `pull_manual()` device annotations to `BoundTargetDevice`.

Replace `_BoundDeviceClient.__init__()` with:

```python
def __init__(self, device: BoundTargetDevice, package: str) -> None:
    self.device = device
    if device.package != package:
        raise _error(
            "artifact.binding_invalid",
            "bound device package does not match artifact package",
        )
    self.directory = device.trace_directory
```

Replace its streaming lookup with the direct call:

```python
self.device.stream_target_file(
    f"{self.directory}/{name}",
    output,
    timeout=timeout,
    maximum_bytes=_MAX_ARTIFACT_BYTES,
)
```

Keep the custom `client_factory` path: it is an internal Seam with real production/default and test Adapters, and it does not change the external bound-device Interface.

- [ ] **Step 5: Read artifact report metadata from non-optional properties**

Replace `device_metadata` in `_collect()` with:

```python
device_metadata = {
    "serial": device.serial,
    "package": package,
    "access_mode": device.access_mode,
    "root_strategy": device.root_strategy,
    "target_strategy": device.target_strategy,
    "package_uid": device.package_uid,
}
```

Keep the merge from status host context unchanged so existing report precedence remains stable.

- [ ] **Step 6: Run artifact tests and verify GREEN**

Run:

```bash
python3 -m unittest scripts.tests.test_qtrace_artifacts
```

Expected: all artifact tests PASS, including manual pull, session collection, secondary-user roots, streaming bounds, metadata, durable publication, and fault-injection cleanup.

- [ ] **Step 7: Run the complete Python regression gate**

Run:

```bash
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
python3 -m compileall -q qtrace
git diff --check
```

Expected: the full suite reports `OK` with only its existing documented skips; compileall emits no error; `git diff --check` emits no output.

Also verify the old mutable state and downstream optional identity reads are absent:

```bash
rg -n "bind_package|_package: str \| None|_access_mode: str \| None|valid_binding|getattr\(device, \"(package|access_mode|root_strategy|package_uid|target_strategy|android_user|package_data_dir|target_shell)\"" qtrace
```

Expected: no matches. `bind_package_access` remains valid and must not be mistaken for the deleted `bind_package()` method; if the broad expression reports it, rerun with `rg -n "def bind_package\(" qtrace` and expect no matches.

- [ ] **Step 8: Commit Task 5**

```bash
git add qtrace/artifacts.py scripts/tests/test_qtrace_artifacts.py
git commit -m "refactor(qtrace): use bound device for artifacts"
```

---

## Completion Evidence

Before claiming completion, record:

- the RED failure reason for the new test in each task;
- the targeted GREEN test result after each task;
- the final full-suite test count, skips, and elapsed time;
- `python3 -m compileall -q qtrace` success;
- empty `git diff --check` output;
- empty `git status --short` after the final commit.

Do not claim Native or device acceptance from this Python-only plan. Native source and Android device behavior are unchanged; the required evidence is the full host Python regression gate and unchanged command assertions.
