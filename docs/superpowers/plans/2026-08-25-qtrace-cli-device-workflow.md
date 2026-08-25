# QTrace CLI and Device Workflow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a repository-local, generic `python3 -m qtrace` workflow that can prepare an arbitrary debuggable/root-accessible Android app, inject the tracer once at startup, run timed or monitored capture sessions, and pull validated artifacts with stable reports and exit codes.

**Architecture:** A small standard-library Python package owns strict configuration, bounded subprocess/device access, ELF resolution, preflight/build/deploy, one-shot Frida startup, session orchestration, artifact collection, and CLI presentation. The native tracer remains autonomous after installation; the host polls process and status files through ADB and never keeps a Frida control channel alive. The `demo` command supplies only fixture defaults and delegates to the same generic orchestration path used by external applications.

**Tech Stack:** Python 3 standard library, `unittest`, ADB, Android NDK `llvm-readelf`/`llvm-nm`, Gradle/CMake, Frida Python bindings and JavaScript startup agent, existing `scripts.bounded_process` and `scripts.pull_trace` helpers.

## Global Constraints

- This plan depends on `2026-08-25-qtrace-stopped-trace-format.md` and `2026-08-25-qtrace-native-autonomous-stop.md`.
- The public entry point is repository-local `python3 -m qtrace`; no package installation is required.
- Android target scope is rooted `arm64-v8a`, API 24+, with one explicitly selected ADB device.
- Frida is startup-only: spawn, attach, load the tracer, call initialization once, resume, unload, and detach.
- Timed stop is native-owned; the host never sends a runtime stop request or kills the App after successful resume.
- Scene positions are module-relative half-open ranges `[startOffset,endOffset)` or uniquely resolved ELF symbols; base and absolute address inputs are forbidden.
- Generic external packages and the repository demo share the same orchestration path; only `qtrace.demo` knows fixture details.
- External APK construction is out of scope. Installation occurs only when explicitly requested with an existing APK.
- `pull` has no Frida, build, install, injection, or process-start dependency.
- Every command, read, wait, status publication, report publication, and artifact collection has a finite bound or atomic publication contract.
- Reports contain bounded diagnostics and explicitly selected device/tool facts only; they never dump environment variables, credentials, or unbounded logcat/tool output.
- Run, monitor, pull, interruption, and recovery never delete device trace/status evidence; cleanup is limited to host staging files, owned suspended PIDs, and deployment probe files.
- Stable exit codes are success `0`, error `1`, partial pull `2`, stop incomplete `3`, and interrupted `130`.

## File Structure

- `qtrace/config.py`, `models.py`, and `errors.py` own strict user input and stable public result/error types.
- `qtrace/process.py`, `device.py`, `preflight.py`, and `build.py` isolate all bounded host/ADB/build/deploy side effects.
- `qtrace/elf.py` alone resolves host/device ELF identities and converts symbols into module-relative ranges.
- `qtrace/agent.js` and `injector.py` own the fixed startup-only Frida protocol and immediate detach.
- `qtrace/session.py`, `lock.py`, and `report.py` own the generation state machine, serialization lock, deadlines, cleanup, and atomic session reports.
- `qtrace/artifacts.py` composes existing pull/decoder helpers into validated, atomic artifact sets.
- `qtrace/cli.py`, `__main__.py`, and `demo.py` expose commands; only `demo.py` knows repository fixture details.
- `scripts/tests/test_qtrace_*.py` are host unit/contract tests; `scripts/qtrace_device_acceptance.py` is the explicit one-device gate.

---

### Task 1: Create the package, strict configuration model, and stable errors

**Files:**
- Create: `qtrace/__init__.py`
- Create: `qtrace/__main__.py`
- Create: `qtrace/errors.py`
- Create: `qtrace/models.py`
- Create: `qtrace/config.py`
- Create: `scripts/tests/test_qtrace_config.py`
- Create: `scripts/tests/test_qtrace_errors.py`

**Interfaces:**
- Consumes: strict JSON/config and error requirements from the approved design specification.
- Produces: `QtraceError`, `ConfigError`, `AppConfig`, `TargetConfig`, `TracerConfig`, `UserConfig`, `OffsetScene`, `SymbolScene`, `parse_duration_ms(str) -> int`, and `load_config(Path) -> UserConfig`.

- [ ] **Step 1: Write failing duration and configuration tests**

Cover these exact cases in `scripts/tests/test_qtrace_config.py`:

```python
class DurationTests(unittest.TestCase):
    def test_accepts_ms_seconds_and_minutes(self):
        self.assertEqual(parse_duration_ms("30s"), 30_000)
        self.assertEqual(parse_duration_ms("250ms"), 250)
        self.assertEqual(parse_duration_ms("1.5m"), 90_000)

    def test_rejects_out_of_range_nonfinite_and_unknown_units(self):
        for value in ("30", "99ms", "-1s", "nan", "inf", "1441m", "2h", ""):
            with self.subTest(value=value), self.assertRaises(ConfigError):
                parse_duration_ms(value)

class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

    def write_json(self, name: str, payload: object) -> Path:
        path = Path(self.directory.name) / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_loads_offset_and_symbol_scenes(self):
        config = load_config(self.write_json("valid-qtrace.json", {
            "schemaVersion": 1,
            "app": {"package": "com.example.external"},
            "target": {"module": "libexternal.so"},
            "scenes": [
                {"name": "offset", "startOffset": "0x120", "endOffset": "0x180"},
                {"name": "symbol", "symbol": "do_work"},
            ],
        }))
        self.assertEqual(config.app.package, "com.example.external")
        self.assertEqual(config.scenes[0].start_offset, 0x120)
        self.assertEqual(config.scenes[1].symbol, "do_work")

    def test_rejects_unknown_keys_and_mixed_scene_forms(self):
        with self.assertRaisesRegex(ConfigError, "CONFIG_UNKNOWN_FIELD"):
            load_config(self.write_json("unknown-key.json", {
                "schemaVersion": 1,
                "app": {"package": "com.example.external"},
                "target": {"module": "libexternal.so"},
                "scenes": [{"name": "one", "symbol": "do_work"}],
                "unknown": True,
            }))
        with self.assertRaisesRegex(ConfigError, "SCENE_FORM_INVALID"):
            load_config(self.write_json("mixed-scene.json", {
                "schemaVersion": 1,
                "app": {"package": "com.example.external"},
                "target": {"module": "libexternal.so"},
                "scenes": [{
                    "name": "mixed", "symbol": "do_work",
                    "startOffset": "0x120", "endOffset": "0x180",
                }],
            }))
```

Also test schema version other than 1, duplicate scene names, more than 256 scenes, names longer than 128 UTF-8 bytes, an empty scene list, non-string package/module/binary values, integer rather than `0x...` string offsets, zero/unaligned offsets, `startOffset >= endOffset`, and a missing/unknown `flightEntryScene`.

- [ ] **Step 2: Run the tests and confirm the package is absent**

Run:

```bash
python3 -m unittest scripts.tests.test_qtrace_config scripts.tests.test_qtrace_errors -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'qtrace'`.

- [ ] **Step 3: Implement typed configuration and error contracts**

Add these public contracts:

```python
# qtrace/errors.py
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_PARTIAL = 2
EXIT_STOP_INCOMPLETE = 3
EXIT_INTERRUPTED = 130

class ErrorCode(str, Enum):
    DEVICE_NOT_FOUND = "DEVICE_NOT_FOUND"
    SESSION_BUSY = "SESSION_BUSY"
    FRIDA_VERSION_MISMATCH = "FRIDA_VERSION_MISMATCH"
    PACKAGE_NOT_INSTALLED = "PACKAGE_NOT_INSTALLED"
    UNSUPPORTED_ABI = "UNSUPPORTED_ABI"
    TARGET_MODULE_NOT_FOUND = "TARGET_MODULE_NOT_FOUND"
    SYMBOL_NOT_FOUND = "SYMBOL_NOT_FOUND"
    SYMBOL_SIZE_INVALID = "SYMBOL_SIZE_INVALID"
    TARGET_IDENTITY_MISMATCH = "TARGET_IDENTITY_MISMATCH"
    TRACER_LOAD_FAILED = "TRACER_LOAD_FAILED"
    HOOK_INSTALL_FAILED = "HOOK_INSTALL_FAILED"
    PROCESS_EXITED_DURING_SETUP = "PROCESS_EXITED_DURING_SETUP"
    STOP_NOT_ACKNOWLEDGED = "STOP_NOT_ACKNOWLEDGED"
    ARTIFACT_INCOMPLETE = "ARTIFACT_INCOMPLETE"
    ARTIFACT_INTEGRITY_FAILED = "ARTIFACT_INTEGRITY_FAILED"
    ADB_UNAVAILABLE = "ADB_UNAVAILABLE"
    ADB_PULL_FAILED = "ADB_PULL_FAILED"

class QtraceError(RuntimeError):
    def __init__(self, code: ErrorCode | str, stage: str, detail: str, *, exit_code: int = EXIT_ERROR): ...

class ConfigError(QtraceError): ...

# qtrace/models.py
@dataclass(frozen=True)
class OffsetScene:
    name: str
    start_offset: int
    end_offset: int

@dataclass(frozen=True)
class SymbolScene:
    name: str
    symbol: str

SceneSpec = OffsetScene | SymbolScene

@dataclass(frozen=True)
class AppConfig:
    package: str
    apk: Path | None

@dataclass(frozen=True)
class TargetConfig:
    module: str
    binary: Path | None

@dataclass(frozen=True)
class TracerConfig:
    profile: str
    compression: bool
    flight_enabled: bool
    flight_entry_scene: str | None
    library: Path | None
    companion: Path | None

@dataclass(frozen=True)
class UserConfig:
    schema_version: int
    app: AppConfig
    target: TargetConfig
    tracer: TracerConfig
    scenes: tuple[SceneSpec, ...]

# qtrace/config.py
def parse_duration_ms(text: str) -> int: ...
def load_config(path: Path) -> UserConfig: ...
```

The root JSON keys are exactly `schemaVersion`, `app`, `target`, optional `tracer`, and `scenes`. Require `schemaVersion=1`. App keys are exactly `package` and optional `apk`; target keys are exactly `module` and optional `binary`; tracer keys are exactly optional `profile`, `compression`, `flightEnabled`, `flightEntryScene`, `library`, and `companion`. Tracer defaults are `profile="fast"`, `compression=true`, and `flightEnabled=false`; profile is exactly `fast|balanced|full`. Require both prebuilt tracer paths together or neither. Require `flightEntryScene` when Flight is enabled and forbid it otherwise. A scene has exactly `name` plus either `startOffset`/`endOffset` or `symbol`. Accept explicit offsets only as strings matching `0x[0-9a-fA-F]+`, require nonzero four-byte-aligned start/end values and a strict half-open range. Resolve relative APK/ELF/tracer paths against the configuration file directory. Duration, device, and output directory never appear in the file; they are per-command CLI values.

`QtraceError.__str__` must emit one stable, script-readable line:

```text
qtrace: stage=<stage> code=<code> detail=<single-line detail>
```

Replace CR/LF in detail with spaces and truncate the UTF-8 diagnostic to 512 bytes without splitting a code point. `__main__.py` must only import and call `qtrace.cli.main`; create `qtrace/cli.py` with a temporary `main()` that returns `EXIT_ERROR` until Task 7 wires the commands.

- [ ] **Step 4: Run the focused tests**

Run:

```bash
python3 -m unittest scripts.tests.test_qtrace_config scripts.tests.test_qtrace_errors -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add qtrace scripts/tests/test_qtrace_config.py scripts/tests/test_qtrace_errors.py
git commit -m "feat: add qtrace configuration model"
```

### Task 2: Resolve and validate target ELF identities and scene ranges

**Files:**
- Create: `qtrace/elf.py`
- Create: `scripts/tests/test_qtrace_elf.py`
- Modify: `qtrace/models.py`

**Interfaces:**
- Consumes: `UserConfig`, `OffsetScene`, and `SymbolScene` from Task 1 plus bounded command and device-file protocols defined in this task.
- Produces: `ElfIdentity`, `ResolvedScene`, `ResolvedTarget`, `ElfInspector.inspect/symbol_range`, and `TargetResolver.resolve(UserConfig) -> ResolvedTarget` for native-request and demo-fixture construction.

- [ ] **Step 1: Write failing parser and resolver tests**

Use textual `llvm-readelf` and `llvm-nm` outputs stored as constants in the test. Cover:

- A unique `T` symbol becomes `[st_value, st_value + st_size)` relative to the module load bias.
- `t`, `W`, and `w` symbol types are accepted; undefined, data, zero-sized, duplicate, and non-four-byte-aligned functions are rejected.
- Every explicit or symbol-derived range must fit entirely inside an executable `PT_LOAD` range.
- All scenes resolve against the configured module; there is no image base or absolute-address input.
- Host and device ELF class, machine, and GNU build ID must match.
- Missing build IDs fail with `target.build_id_missing`; mismatches fail with `target.identity_mismatch`.
- Split APK candidates that contain more than one matching module fail with `target.module_ambiguous`.

The resolver test injects a fake command runner and a fake device file provider. It must not call real ADB or NDK tools.

Use this representative assertion to freeze offset semantics:

```python
def test_unique_text_symbol_resolves_to_half_open_module_offsets(self):
    runner = FakeRunner(readelf=ARM64_READELF, nm="do_work T 120 40\n")
    resolved = TargetResolver(ElfInspector(runner, Path("/ndk/bin")), FakeDevice()).resolve(
        config_with_scene(SymbolScene("work", "do_work"))
    )
    self.assertEqual((ResolvedScene("work", 0x120, 0x160),), resolved.scenes)
```

Define `FakeRunner`, `FakeDevice`, `config_with_scene`, `ARM64_READELF`, and their exact bounded-call assertions in the same test module; `FakeRunner` raises on every command not explicitly queued.

- [ ] **Step 2: Run the focused test and observe failure**

Run:

```bash
python3 -m unittest scripts.tests.test_qtrace_elf -v
```

Expected: FAIL because `qtrace.elf` does not exist.

- [ ] **Step 3: Implement ELF inspection and resolution**

Add these exact models and interfaces:

```python
@dataclass(frozen=True)
class ElfIdentity:
    elf_class: str
    machine: str
    build_id: str
    executable_ranges: tuple[tuple[int, int], ...]

@dataclass(frozen=True)
class ResolvedScene:
    name: str
    start_offset: int
    end_offset: int

@dataclass(frozen=True)
class ResolvedTarget:
    package: str
    module: str
    host_binary: Path
    device_binary: str
    identity: ElfIdentity
    scenes: tuple[ResolvedScene, ...]

class CommandRunner(Protocol):
    def capture(self, command: Sequence[str], *, maximum_bytes: int, timeout: float) -> bytes: ...

class DeviceFileProvider(Protocol):
    def package_apk_paths(self, package: str) -> tuple[str, ...]: ...
    def pull_member(self, apk_path: str, member: str, destination: Path) -> Path: ...

class ElfInspector:
    def __init__(self, runner: CommandRunner, ndk_bin: Path): ...
    def inspect(self, binary: Path) -> ElfIdentity: ...
    def symbol_range(self, binary: Path, symbol: str) -> tuple[int, int]: ...

class TargetResolver:
    def __init__(self, inspector: ElfInspector, device: DeviceFileProvider): ...
    def resolve(self, config: UserConfig) -> ResolvedTarget: ...
```

Invoke `llvm-readelf -h -n -lW` and `llvm-nm -S --defined-only --format=posix` through the bounded runner. If `target.binary` is absent, extract `lib/<abi>/<module>` from the configured APK or from the installed package's base/split APK set into a temporary directory. Keep the resolved device member/path distinct from the host temporary file.

For `llvm-nm` POSIX rows, parse `name type value size`; reject duplicate names before choosing a symbol. Preserve the configured scene order. Never add, subtract, or accept a runtime image base.

- [ ] **Step 4: Run the focused tests**

Run:

```bash
python3 -m unittest scripts.tests.test_qtrace_elf -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add qtrace/elf.py qtrace/models.py scripts/tests/test_qtrace_elf.py
git commit -m "feat: resolve qtrace target scenes"
```

### Task 3: Add bounded ADB access, preflight, build selection, and deploy

**Files:**
- Create: `qtrace/process.py`
- Create: `qtrace/device.py`
- Create: `qtrace/preflight.py`
- Create: `qtrace/build.py`
- Create: `scripts/tests/test_qtrace_process.py`
- Create: `scripts/tests/test_qtrace_device.py`
- Create: `scripts/tests/test_qtrace_preflight.py`
- Create: `scripts/tests/test_qtrace_build.py`

**Interfaces:**
- Consumes: `UserConfig` from Task 1 and `CommandRunner`/`DeviceFileProvider` behavior required by Task 2.
- Produces: `BoundedRunner`, `AdbDevice`, `DeviceIdentity`, `DeviceSelector`, `Preflight`, `TracerArtifacts`, `ArtifactBuilder`, `Deployment`, and `Deployer`.

- [ ] **Step 1: Write failing boundary tests**

Test without a physical device by injecting command results. Assert:

- Every subprocess has a finite timeout and bounded stdout/stderr.
- ADB commands are argument arrays, include `-s <serial>`, and never use `shell=True`.
- Missing or multiple devices fail unless `--device` selects one.
- Required properties are `ro.product.cpu.abi=arm64-v8a`, API level at least 24, a working root or `run-as` path, sufficient free space for two tracer artifact sets, and a host `lz4` executable when compression is enabled.
- Preflight performs a bounded Frida host/server version handshake; exact normalized semantic-version equality passes (`16.3.3 == 16.3.3`) and any major/minor/patch mismatch fails with `FRIDA_VERSION_MISMATCH` before spawn.
- Package absence is an error when `app.apk` is absent; when `app.apk` exists, `adb install -r` installs that prebuilt APK before package/build-ID verification. No external APK build command is issued.
- User-supplied `tracer.library` and `tracer.companion` are reused only when both are regular arm64 files; otherwise the repository Gradle native configuration/build tasks run with a bounded timeout.
- Deployment first probes a package-private directory for write, load, and later root/read access. It falls back to a validated tracer-owned `/data/local/tmp/qtrace/<session-id>/` directory only when the private route fails its explicit probe.
- Deploy pushes only tracer-owned files, applies mode `0755`, verifies device SHA-256, checks SELinux/linker-namespace loadability with the companion probe, and removes only its temporary probe file on failure.

Freeze command construction with assertions such as:

```python
device = DeviceSelector(FakeRunner(adb_devices=b"SERIAL\tdevice\n")).select("SERIAL")
self.assertEqual("SERIAL", device.serial)
self.assertEqual(["adb", "-s", "SERIAL", "shell", "id", "-u"],
                 device.command("shell", "id", "-u"))
self.assertTrue(all(call.timeout is not None and call.maximum_bytes is not None
                    for call in device.runner.calls))
```

The fake records argument arrays and fails the test if a caller supplies a string command, `shell=True`, a missing timeout, or a missing output bound.

- [ ] **Step 2: Run the focused tests and observe failure**

Run:

```bash
python3 -m unittest scripts.tests.test_qtrace_process scripts.tests.test_qtrace_device scripts.tests.test_qtrace_preflight scripts.tests.test_qtrace_build -v
```

Expected: FAIL because the modules do not exist.

- [ ] **Step 3: Implement bounded process and device contracts**

Reuse `scripts.bounded_process.capture_bounded` behind this adapter:

```python
class BoundedRunner:
    def capture(
        self,
        command: Sequence[str],
        *,
        maximum_bytes: int = 1_048_576,
        timeout: float = 30.0,
    ) -> bytes: ...

@dataclass(frozen=True)
class DeviceIdentity:
    serial: str
    abi: str
    api_level: int
    access_mode: str
    frida_host_version: str
    frida_server_version: str
    free_bytes: int

class AdbDevice:
    def __init__(self, serial: str, runner: BoundedRunner): ...
    def command(self, *args: str) -> list[str]: ...
    def shell(self, *args: str, timeout: float = 30.0, maximum_bytes: int = 1_048_576) -> bytes: ...
    def package_apk_paths(self, package: str) -> tuple[str, ...]: ...
    def pid(self, package: str) -> int | None: ...
    def install(self, apk: Path) -> None: ...
    def push(self, source: Path, destination: str) -> None: ...
    def read_file(self, path: str, maximum_bytes: int = 1_048_576) -> bytes: ...

class DeviceSelector:
    def select(self, requested_device: str | None) -> AdbDevice: ...

class FridaProbe(Protocol):
    def versions(self, device: AdbDevice, timeout: float) -> tuple[str, str]: ...
```

Validate all package names, session IDs, and remote path components before composing ADB arguments. Do not invoke a shell string on the host. Device-side shell fragments are permitted only in one reviewed helper that rejects characters outside `[A-Za-z0-9._/@:+,=-]` for every interpolated token.

- [ ] **Step 4: Implement preflight, build, and deploy**

```python
@dataclass(frozen=True)
class TracerArtifacts:
    tracer_so: Path
    companion: Path

@dataclass(frozen=True)
class Deployment:
    route: str
    remote_dir: str
    tracer_so: str
    companion: str
    sha256: Mapping[str, str]
    load_probe: Mapping[str, str]

class Preflight:
    def __init__(self, selector: DeviceSelector, frida_probe: FridaProbe): ...
    def run(
        self,
        config: UserConfig,
        requested_device: str | None,
        *,
        setup_timeout: float,
        adb_timeout: float,
    ) -> tuple[AdbDevice, DeviceIdentity]: ...

class ArtifactBuilder:
    def select_or_build(self, tracer: TracerConfig, *, timeout: float) -> TracerArtifacts: ...

class Deployer:
    def deploy(self, device: AdbDevice, session_id: str, artifacts: TracerArtifacts) -> Deployment: ...
```

Use the existing Gradle native configure/build task names discovered in `build.gradle`; do not invent an APK build requirement for external targets. If `app.apk` is configured, install that existing external APK as a separate preflight step; never build it. Record ABI/API, root/run-as mode, Frida versions, free-space result, chosen deployment route, tracer hashes, and probe diagnostics in `DeviceIdentity`/`Deployment` for the final report.

- [ ] **Step 5: Run the focused tests**

Run:

```bash
python3 -m unittest scripts.tests.test_qtrace_process scripts.tests.test_qtrace_device scripts.tests.test_qtrace_preflight scripts.tests.test_qtrace_build -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add qtrace/process.py qtrace/device.py qtrace/preflight.py qtrace/build.py scripts/tests/test_qtrace_process.py scripts/tests/test_qtrace_device.py scripts/tests/test_qtrace_preflight.py scripts/tests/test_qtrace_build.py
git commit -m "feat: add qtrace device preparation"
```

### Task 4: Implement one-shot startup injection and detach

**Files:**
- Create: `qtrace/agent.js`
- Create: `qtrace/injector.py`
- Create: `scripts/tests/test_qtrace_injector.py`

**Interfaces:**
- Consumes: `AdbDevice` and `Deployment` from Task 3 plus `ResolvedScene` from Task 2.
- Produces: `InjectionRequest`, `InjectionResult`, and `FridaInjector.install(InjectionRequest) -> InjectionResult` with no retained Frida connection.

- [ ] **Step 1: Write failing injection-order tests**

Build fake Frida device/session/script objects and assert this exact order:

```text
force-stop -> spawn -> attach -> create/load agent -> set companion path -> qbdi_tracer_configure_json(request) -> initialized message -> resume -> installed message -> unload agent -> detach session
```

Also cover:

- `qbdi_tracer_configure_json` returns a nonzero transport code or an `ok=false` response.
- The agent reports malformed JSON or an initialization/final generation/session-ID mismatch.
- Initialization is accepted but the setup deadline expires before final `installed` after resume.
- The spawned app exits during setup.
- Cleanup after failure kills only the PID spawned by this session.
- Success leaves the target app running and does not retain a Frida session, script, RPC export, or stop command.

- [ ] **Step 2: Run the focused test and observe failure**

Run:

```bash
python3 -m unittest scripts.tests.test_qtrace_injector -v
```

Expected: FAIL because `qtrace.injector` does not exist.

- [ ] **Step 3: Implement a fixed startup agent**

`qtrace/agent.js` must contain no user-generated JavaScript. It receives one JSON request from Python, loads the deployed tracer `.so`, calls `qbdi_tracer_set_shadowhook_helper_path(const char *)` with the deployed companion before configuration, resolves the existing `qbdi_tracer_configure_json(const char *, uint64_t, char *, uint64_t, uint64_t *)` ABI, passes the exact UTF-8 byte length, validates the transport code and bounded 64 KiB JSON response, and emits an accepted initialization result. After Python resumes the process, the same fixed agent polls `qbdi_tracer_get_status_json(uint64_t, char *, uint64_t, uint64_t *)` until the generation reaches `installed` or a setup terminal. Messages are limited to:

```javascript
send({type: "initialized", sessionId, generation, status});
send({type: "installed", sessionId, generation, status});
send({type: "error", stage, code, detail});
```

The agent must not export runtime RPC methods or accept a stop message. Once the post-resume installed status is validated, Python unloads the script and detaches the Frida session.

- [ ] **Step 4: Implement injection orchestration**

```python
@dataclass(frozen=True)
class InjectionRequest:
    package: str
    session_id: str
    tracer_so: str
    companion: str
    native_request: Mapping[str, object]
    setup_timeout: float

@dataclass(frozen=True)
class InjectionResult:
    pid: int
    session_id: str
    generation: int
    normalized_scenes: tuple[ResolvedScene, ...]

class FridaInjector:
    def __init__(self, device: AdbDevice, frida_provider: FridaProvider): ...
    def install(self, request: InjectionRequest) -> InjectionResult: ...
```

Keep importing Frida lazy so `python3 -m qtrace pull` works on hosts without the Frida Python package. Use the startup approach already proven in `scripts/benchmark_trace.py`: force-stop the package, spawn it suspended, attach, load, initialize, resume, then wait for the native generation to become installed. Validate both the initialization response and final hook status before success and detach immediately afterward.

- [ ] **Step 5: Run the focused test**

Run:

```bash
python3 -m unittest scripts.tests.test_qtrace_injector -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add qtrace/agent.js qtrace/injector.py scripts/tests/test_qtrace_injector.py
git commit -m "feat: add one-shot qtrace injection"
```

### Task 5: Orchestrate timed and monitored sessions with immediate cooperative stop

**Files:**
- Create: `qtrace/session.py`
- Create: `qtrace/lock.py`
- Create: `qtrace/report.py`
- Create: `scripts/tests/test_qtrace_session.py`
- Create: `scripts/tests/test_qtrace_report.py`

**Interfaces:**
- Consumes: preflight, resolver, builder, deployer, and injector outputs from Tasks 2 through 4 plus the native session-status schema.
- Produces: `SessionStage`, `SessionReport`, `ReportWriter`, `TargetLock`, `RunRequest`, `MonitorRequest`, `SessionResult`, and `SessionOrchestrator.run/monitor`.

- [ ] **Step 1: Write failing session-state tests**

Drive the orchestrator using fakes and a manual clock. Assert these state sequences:

```text
run:     preflight -> resolving_target -> building_tracer -> deploying -> injecting -> installing_hooks -> running -> stopping -> sealed -> pulling -> completed
monitor: preflight -> resolving_target -> building_tracer -> deploying -> injecting -> installing_hooks -> monitoring -> pulling -> completed
```

Cover these outcomes:

- `run --duration 250ms` sends normalized `durationMs=250` once; native starts its monotonic deadline only after all scene hooks reach Installed, while the host polls until every declared writer is sealed.
- Timed capture completes while the app remains running; the host never asks Frida to stop it.
- `monitor` waits until ADB reports the injected PID exited, then collects artifacts.
- `monitor` reports a normal completed artifact as `process_exited`, and valid crash-marker/Flight recovery as `crash_recovered` with exit code 2; it never fabricates a native terminal for either case.
- `monitor` detects package PID replacement and fails with `session.pid_replaced` instead of attaching to the new process.
- Ctrl-C after resume writes an `interrupted` report, releases the lock, leaves the app and device evidence untouched, prints the later `qtrace pull` command, and returns `130`.
- A stopped-but-unsealed status reaches `stopTimeout`, writes a partial report, and returns `EXIT_STOP_INCOMPLETE`.
- A transient ADB disconnect during running/monitoring is retried within the phase deadline; exhaustion writes `ADB_UNAVAILABLE`, preserves device evidence, and never reinjects or kills the resumed app.
- Failure after spawn kills only the owned suspended PID; failure after successful resume never force-stops the app.
- A nonblocking `fcntl.flock` keyed by device serial plus package prevents concurrent sessions for the same target but permits different targets.
- Every wait has a finite setup, run, stop, or pull deadline; poll intervals use the injected clock.

- [ ] **Step 2: Run focused tests and observe failure**

Run:

```bash
python3 -m unittest scripts.tests.test_qtrace_session scripts.tests.test_qtrace_report -v
```

Expected: FAIL because the session modules do not exist.

- [ ] **Step 3: Implement report and lock primitives**

```python
class SessionStage(str, Enum):
    PREFLIGHT = "preflight"
    RESOLVING_TARGET = "resolving_target"
    BUILDING_TRACER = "building_tracer"
    DEPLOYING = "deploying"
    INJECTING = "injecting"
    INSTALLING_HOOKS = "installing_hooks"
    RUNNING = "running"
    STOPPING = "stopping"
    SEALED = "sealed"
    MONITORING = "monitoring"
    PULLING = "pulling"
    COMPLETED = "completed"

@dataclass(frozen=True)
class SessionReport:
    schema: int
    session_id: str
    mode: str
    status: str
    stage: str
    package: str
    serial: str
    pid: int | None
    started_at: str
    finished_at: str
    timeline: tuple[Mapping[str, object], ...]
    device: Mapping[str, object]
    tracer: Mapping[str, object]
    target: Mapping[str, object]
    effective_config: Mapping[str, object]
    native: Mapping[str, object]
    artifacts: tuple[Mapping[str, object], ...]
    warnings: tuple[Mapping[str, object], ...]
    error: Mapping[str, object] | None
    outputs: tuple[str, ...]

class ReportWriter:
    def write_atomic(self, output: Path, report: SessionReport) -> None: ...

class TargetLock:
    def acquire(self, serial: str, package: str) -> ContextManager[None]: ...
```

Write JSON using a temporary sibling file, `flush`, `fsync`, and `os.replace`. Use UUIDv4 session IDs. Hash `serial + NUL + package` for the lock filename under `${XDG_RUNTIME_DIR:-/tmp}/qtrace-<uid>/`; create the directory mode `0700`.

- [ ] **Step 4: Implement session orchestration**

```python
class InstalledAction(Protocol):
    def __call__(self, device: AdbDevice, pid: int) -> None: ...

@dataclass(frozen=True)
class RunRequest:
    config: UserConfig
    device: str | None
    output: Path
    duration_ms: int
    setup_timeout: float
    stop_timeout: float
    adb_timeout: float
    pull_timeout: float
    installed_action: InstalledAction | None = None

@dataclass(frozen=True)
class MonitorRequest:
    config: UserConfig
    device: str | None
    output: Path
    setup_timeout: float
    adb_timeout: float
    pull_timeout: float
    installed_action: InstalledAction | None = None

@dataclass(frozen=True)
class SessionResult:
    session_id: str
    exit_code: int
    report: Path
    outputs: tuple[Path, ...]

class SessionOrchestrator:
    def run(self, request: RunRequest) -> SessionResult: ...
    def monitor(self, request: MonitorRequest) -> SessionResult: ...

def build_native_request(
    config: UserConfig,
    resolved: ResolvedTarget,
    session_id: str,
    duration_ms: int | None,
) -> dict[str, object]: ...
```

`build_native_request` copies the normalized profile/compression/flight settings and resolved offset scenes, adds the UUID session ID, and includes `durationMs` only for timed mode. It never sends an image base, absolute address, output path, or host deadline. The optional `InstalledAction` is a generic post-install test/automation seam invoked once after Frida detaches; production external-App requests leave it `None`, and the orchestrator contains no package-specific logic. The status polling contract is the native plan's `session-<UUID>.status.json`: accept only schema version 1, the expected package/session/generation/PID, monotonic transition timestamps and state progression, matching normalized scenes, and tracer-owned artifact names. Do not trust status paths supplied by the target app.

For timed mode, terminal success requires `state=sealed`, `reason=duration_elapsed`, and `stopAcknowledged=true`. For monitored mode, omit `durationMs`; process exit is the collection trigger and a final native status may be absent if the OS killed the process, so report `process_exited` separately from native stop completeness. Snapshot tracer-owned artifact names immediately before spawn; collection intersects the final native declarations with files added after that snapshot. After successful resume, a caught `KeyboardInterrupt` writes/fsyncs the interrupted report, releases the lock, and re-raises so `qtrace.cli.main` alone maps it to 130. In both modes, leave target process lifecycle under the app/user after successful resume.

- [ ] **Step 5: Run focused tests**

Run:

```bash
python3 -m unittest scripts.tests.test_qtrace_session scripts.tests.test_qtrace_report -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add qtrace/session.py qtrace/lock.py qtrace/report.py scripts/tests/test_qtrace_session.py scripts/tests/test_qtrace_report.py
git commit -m "feat: orchestrate qtrace sessions"
```

### Task 6: Pull, validate, decode, and report artifact sets

**Files:**
- Create: `qtrace/artifacts.py`
- Create: `scripts/tests/test_qtrace_artifacts.py`
- Modify: `qtrace/session.py`
- Modify: `qtrace/report.py`
- Modify: `scripts/pull_trace.py`
- Modify: `scripts/tests/test_pull_trace.py`

**Interfaces:**
- Consumes: `AdbDevice`, native status documents, `SessionResult`, and the stopped-trace decoder/metrics contracts from the prerequisite format plan.
- Produces: `PulledArtifact`, `pull_named_artifacts`, `ArtifactResult`, and `ArtifactProcessor.collect_session/pull_manual`.

- [ ] **Step 1: Write failing artifact tests**

Cover:

- Session collection only accepts files declared by the matching native status document and created for the current session.
- Concurrent manual pull publishes only normal artifacts declared sealed or Flight chunks proven committed/recoverable; it skips active temporary/current-writer files and records them as incomplete instead of relabeling them complete.
- Manual pull supports default/explicit `latest`, exact `name`, `all`, and `compressed-only` selection without needing a live session.
- `latest` chooses the newest valid native session status and only its declared artifacts; `name` pulls one validated exact artifact basename; `all` snapshots every non-temporary tracer-owned artifact; `compressed-only` filters any selected mode to compressed artifacts.
- `name + compressed-only` rejects an uncompressed suffix instead of silently returning an empty success.
- Names with traversal, control characters, unexpected extensions, or another session UUID are rejected.
- Existing final directories, symlinked destination components, and duplicate remote names are rejected; default collection never overwrites a prior local artifact or report.
- Each artifact is first copied into a temporary session directory, checksummed, decoded/validated, and atomically renamed to `<output>/<session-id>/`.
- A valid stopped trace requires exactly one terminal stop record and metrics-v3 termination fields matching it.
- A legacy completed trace remains pullable and decodable.
- One corrupt artifact produces `EXIT_PARTIAL`, preserves valid siblings, and records a per-file error in `report.json`.
- Pull timeout or ADB truncation never publishes a half-copied final file.

Include a stopped-session happy path that proves identity and atomic layout together:

```python
result = processor.collect_session(
    device, "com.example.external", SESSION_ID, SEALED_STATUS, output, 30.0
)
self.assertEqual(EXIT_OK, result.exit_code)
self.assertTrue((result.output_dir / "report.json").is_file())
self.assertTrue((result.output_dir / "artifacts" / "run.trace.txt").is_file())
self.assertFalse(any(output.glob(".qtrace-stage-*")))
```

- [ ] **Step 2: Run focused tests and observe failure**

Run:

```bash
python3 -m unittest scripts.tests.test_qtrace_artifacts scripts.tests.test_pull_trace -v
```

Expected: FAIL because `qtrace.artifacts` does not exist.

- [ ] **Step 3: Generalize the existing pull helper without breaking its CLI**

Keep `scripts/pull_trace.py` backward compatible. Expose its already-tested primitives through:

```python
@dataclass(frozen=True)
class PulledArtifact:
    remote_name: str
    local_path: Path
    sha256: str
    size: int

def pull_named_artifacts(
    client: AdbArtifactClient,
    package: str,
    names: Sequence[str],
    destination: Path,
    *,
    timeout: float,
) -> tuple[PulledArtifact, ...]: ...
```

Preserve the original `pull_artifact_set` behavior by implementing it on top of the new named primitive. Continue using bounded ADB reads and the existing safe package/artifact-name checks.

- [ ] **Step 4: Implement qtrace artifact processing**

```python
@dataclass(frozen=True)
class ArtifactResult:
    output_dir: Path
    files: tuple[Path, ...]
    errors: tuple[Mapping[str, str], ...]
    exit_code: int

class PullMode(str, Enum):
    LATEST = "latest"
    NAME = "name"
    ALL = "all"

@dataclass(frozen=True)
class PullSelection:
    mode: PullMode = PullMode.LATEST
    name: str | None = None
    compressed_only: bool = False

class ArtifactProcessor:
    def collect_session(
        self,
        device: AdbDevice,
        package: str,
        session_id: str,
        status: Mapping[str, object],
        output: Path,
        timeout: float,
    ) -> ArtifactResult: ...

    def pull_manual(
        self,
        device: AdbDevice,
        package: str,
        selection: PullSelection,
        output: Path,
        timeout: float,
    ) -> ArtifactResult: ...
```

Use the decoders finalized by the stopped-trace-format plan. Generate adjacent `.txt` output for each binary trace and include source/destination sizes, SHA-256, decoder status, stop reason, metrics schema, `producer_waits`, `producer_wait_ns`, conversion milliseconds, and host-observed stop-acknowledgement milliseconds in `report.json`. A session-owned collection publishes this exact tree atomically:

```text
<output>/<session-id>/
|-- session.json
|-- effective-config.json
|-- device.json
|-- artifacts/
|   |-- *.trace.bin.lz4
|   |-- *.metrics
|   `-- *.trace.txt
`-- report.json
```

Manual pull uses the same `<output>/<session-id>/artifacts` layout when a valid session status supplies an ID and a generated pull UUID otherwise. Publish the directory only after validation; when partial, publish valid files plus the report and exclude corrupt temporary files. Use `O_EXCL`/no-overwrite semantics for an existing final session directory.

- [ ] **Step 5: Run focused tests**

Run:

```bash
python3 -m unittest scripts.tests.test_qtrace_artifacts scripts.tests.test_pull_trace -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add qtrace/artifacts.py qtrace/session.py qtrace/report.py scripts/pull_trace.py scripts/tests/test_qtrace_artifacts.py scripts/tests/test_pull_trace.py
git commit -m "feat: collect qtrace artifacts"
```

### Task 7: Wire `run`, `monitor`, `pull`, and `demo` commands

**Files:**
- Modify: `qtrace/cli.py`
- Modify: `qtrace/__main__.py`
- Create: `qtrace/demo.py`
- Create: `scripts/tests/test_qtrace_cli.py`
- Modify: `README.md`

**Interfaces:**
- Consumes: every public type constructed in Tasks 1 through 6.
- Produces: `build_parser() -> argparse.ArgumentParser`, `main(Sequence[str] | None) -> int`, `DemoFixture`, `build_demo_fixture(Path, BoundedRunner, float) -> DemoFixture`, `make_demo_config(DemoFixture, ElfInspector, str, str) -> UserConfig`, `make_demo_action(str, int, int, int) -> InstalledAction`, and the four documented commands.

- [ ] **Step 1: Write failing command-contract tests**

Patch `SessionOrchestrator` and `ArtifactProcessor`; invoke `main(argv)` directly. Cover these exact forms:

```text
python3 -m qtrace run --config target.json --duration 30s [--device SERIAL] [--output DIR] [--json]
python3 -m qtrace monitor --config target.json [--device SERIAL] [--output DIR] [--json]
python3 -m qtrace pull --package com.example.app [--latest | --name ARTIFACT | --all] [--compressed-only] [--device SERIAL] [--output DIR] [--json]
python3 -m qtrace demo [--scenario timed|monitor-exit|flight-crash] [--duration 10s] [--scene-form offset|symbol] [--device SERIAL] [--output DIR] [--json]
```

Assert:

- `run` requires a positive duration; `monitor` rejects `--duration`.
- `pull` does not load a target config, import Frida, build, install, inject, or start an app.
- `pull` defaults to `--latest`; `--latest`, `--name`, and `--all` are mutually exclusive, while `--compressed-only` is an orthogonal filter.
- `run`/`monitor` incrementally build repository tracer artifacts unless config supplies both prebuilt tracer paths. If `app.apk` is present they install that existing APK but never build it.
- `demo` builds and installs the repository fixture APK plus tracer artifacts. Its default `timed` scenario uses the real run path; acceptance-only `monitor-exit` and `flight-crash` scenarios use the real monitor path and reject `--duration`.
- `demo` constructs a normal `UserConfig` and calls the same `SessionOrchestrator.run`; core modules never compare against the demo package name.
- Stable `QtraceError` values reach stderr as one line and map to the declared exit code.
- Success prints the report path and artifact paths to stdout; `--json` prints exactly one bounded machine result object and sends progress to stderr.
- `KeyboardInterrupt` maps to exit 130 after the orchestrator writes its interrupted report.

- [ ] **Step 2: Run focused tests and observe failure**

Run:

```bash
python3 -m unittest scripts.tests.test_qtrace_cli -v
```

Expected: FAIL because the CLI is not wired.

- [ ] **Step 3: Implement command parsing and dependency construction**

```python
def build_parser() -> argparse.ArgumentParser: ...
def main(argv: Sequence[str] | None = None) -> int: ...
```

Keep all defaults explicit:

- setup timeout: 90 seconds
- stop timeout: 10 seconds
- individual ADB timeout: 30 seconds
- pull timeout: 60 seconds
- output for every command: `qtrace-output` unless `--output` overrides it
- demo scenario: `timed`; its duration defaults to `10s` only after parsing, while monitor scenarios keep duration absent

Expose `--setup-timeout`, `--stop-timeout`, `--adb-timeout`, and `--pull-timeout` only where the matching phase exists; each must be finite and positive. `run --duration` additionally enforces the 100 ms through 24 h range from Task 1.

`main` catches only `QtraceError` and `KeyboardInterrupt`; unexpected exceptions retain a traceback for developer visibility. Construct Frida dependencies lazily inside `run`/`monitor`, not in the parser or `pull` branch.

- [ ] **Step 4: Implement demo as a thin fixture adapter**

```python
@dataclass(frozen=True)
class DemoFixture:
    apk: Path
    target_binary: Path

def build_demo_fixture(repo_root: Path, runner: BoundedRunner, timeout: float) -> DemoFixture: ...
def make_demo_config(
    fixture: DemoFixture,
    inspector: ElfInspector,
    scene_form: str,
    scenario: str,
) -> UserConfig: ...
def make_demo_action(
    mode: str,
    seed: int,
    iterations: int = 30,
    worker: int = 0,
) -> InstalledAction: ...
```

Obtain the fixture package/module/APK values from the existing demo build outputs. `build_demo_fixture` extracts exactly `lib/arm64-v8a/libdemo_target.so` from the built APK into `build/qtrace-demo/arm64-v8a/libdemo_target.so` using a temporary sibling plus atomic replace, so it does not depend on unstable CMake intermediate paths. `scene_form=offset` calls `ElfInspector.symbol_range` on that ELF and creates the equivalent `OffsetScene`; `scene_form=symbol` creates `SymbolScene` for the same exported function, so device acceptance can compare normalization. The config's `app.apk` points at the built APK so the ordinary preflight installs it. `scenario=flight-crash` enables Flight and names its entry scene; the other scenarios leave Flight disabled. `make_demo_action` maps `timed`, `monitor-exit`, and `flight-crash` to the fixture's documented acceptance intent through the generic `InstalledAction` seam after detach. Return the config/action to the ordinary run or monitor command; do not add demo cases to `device.py`, `injector.py`, `session.py`, or `artifacts.py`.

- [ ] **Step 5: Document the four commands and scene rules**

Add a concise README section with:

- One timed example and one monitor example for an arbitrary external package.
- Manual pull example.
- Demo example clearly labeled as a test fixture.
- Strict JSON example using offsets and a second example using a symbol.
- Statement that offsets are module-relative half-open ranges `[startOffset,endOffset)` and no base address is accepted.
- `latest`, `name`, `all`, and `compressed-only` pull examples.
- Root/arm64/API 24+/ADB/Frida/NDK/lz4 prerequisites and timeout/exit-code table.
- Clarification that external APK builds are out of scope; optional explicit install only.

- [ ] **Step 6: Run focused tests and command help**

Run:

```bash
python3 -m unittest scripts.tests.test_qtrace_cli -v
python3 -m qtrace --help
python3 -m qtrace run --help
python3 -m qtrace monitor --help
python3 -m qtrace pull --help
python3 -m qtrace demo --help
```

Expected: tests PASS and all help commands exit 0.

- [ ] **Step 7: Commit**

```bash
git add qtrace/cli.py qtrace/__main__.py qtrace/demo.py scripts/tests/test_qtrace_cli.py README.md
git commit -m "feat: expose qtrace command workflow"
```

### Task 8: Add contracts, host CI coverage, and one-device acceptance

**Files:**
- Create: `docs/qtrace-config.schema.json`
- Create: `docs/qtrace-session-status.schema.json`
- Create: `scripts/qtrace_device_acceptance.py`
- Create: `scripts/tests/test_qtrace_contracts.py`
- Create: `.github/workflows/ci.yml`
- Create: `app/src/main/kotlin/com/aprz/qbdiandroid/QtraceAcceptance.kt`
- Create: `app/src/test/kotlin/com/aprz/qbdiandroid/QtraceAcceptanceTest.kt`
- Modify: `app/src/main/kotlin/com/aprz/qbdiandroid/MainActivity.kt`
- Modify: `app/src/main/kotlin/com/aprz/qbdiandroid/NativeDemo.kt`
- Modify: `app/src/main/cpp/demo_target/demo_scenes.h`
- Modify: `app/src/main/cpp/demo_target/demo_scenes.cpp`
- Modify: `app/src/main/cpp/demo_target/demo_target.cpp`
- Modify: `app/build.gradle`
- Modify: `README.md`

**Interfaces:**
- Consumes: strict configuration/status field sets and public CLI contracts from Tasks 1 through 7.
- Produces: two versioned JSON Schema documents, `QtraceAcceptanceRequest`, `QtraceAcceptance.parse/start`, `NativeDemo.runTimedAcceptance`, exported `demo_timed_acceptance_case`, `scripts.qtrace_device_acceptance.main`, host-CI execution, and a manual rooted-device acceptance gate.

- [ ] **Step 1: Write failing contract tests**

Without adding a JSON Schema dependency, load both schema documents and assert their required keys, `additionalProperties: false` rules, enums, versions, and integer bounds match `qtrace.config` and the native session-status parser. Add a golden status document for each state: `installed`, `running`, `stop_requested`, `stopping`, `sealed`, and `stop_incomplete`.

Test the acceptance script's command construction with a fake runner. It must execute, in order:

```text
./gradlew nativeHostTest --no-daemon
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
./gradlew :app:assembleDebug --no-daemon
adb -s SERIAL install -r app/build/outputs/apk/debug/app-debug.apk
adb -s SERIAL shell am force-stop com.aprz.qbdiandroid
adb -s SERIAL shell am start -n com.aprz.qbdiandroid/.MainActivity --ez qtrace_acceptance true --es qtrace_acceptance_mode timed --el qtrace_acceptance_seed 5855319310239641971 --el qtrace_acceptance_iterations 30
python3 scripts/benchmark_trace.py --device SERIAL --profile fast --runs 5 --candidate-tracer out/arm64-v8a/libqbdi_tracer.so --compare docs/benchmarks/binary-trace-baseline.md
python3 -m qtrace demo --scenario timed --duration 2s --scene-form offset --device SERIAL --output TMP/offset
python3 -m qtrace demo --scenario timed --duration 2s --scene-form symbol --device SERIAL --output TMP/symbol
python3 -m qtrace demo --scenario monitor-exit --scene-form offset --device SERIAL --output TMP/exit
python3 -m qtrace demo --scenario flight-crash --scene-form offset --device SERIAL --output TMP/crash
python3 -m qtrace pull --package com.aprz.qbdiandroid --latest --device SERIAL --output TMP/latest
python3 -m qtrace pull --package com.aprz.qbdiandroid --name DISCOVERED_ARTIFACT --device SERIAL --output TMP/name
python3 -m qtrace pull --package com.aprz.qbdiandroid --all --device SERIAL --output TMP/all
python3 -m qtrace pull --package com.aprz.qbdiandroid --all --compressed-only --device SERIAL --output TMP/compressed
```

The script waits with a 15-second bound for the baseline result in the fixture files directory before starting qtrace. It obtains `DISCOVERED_ARTIFACT` from the validated timed `report.json`; it never interpolates an untrusted directory listing. It must then verify that Frida detached before the native deadline, the timed report is complete, the app PID still exists after timed collection, the long target eventually returns the same oracle value as the baseline, the binary contains one `TRACE_STOP(duration_elapsed)`, metrics v3 has `return_valid=false`, the text output is format 4, offset/symbol scenes normalize identically, monitored exit is classified separately from crash recovery, every manual pull mode succeeds, and a one-shot injected ADB read failure leaves device evidence available for the retry.

- [ ] **Step 2: Run focused tests and observe failure**

Run:

```bash
python3 -m unittest scripts.tests.test_qtrace_contracts -v
```

Expected: FAIL because the schemas and acceptance script do not exist.

- [ ] **Step 3: Add executable contracts and acceptance harness**

The configuration schema must encode the exact root/app/target/tracer/scene keys from Task 1. The status schema must encode schema version 1, UUIDv4 session ID, generation, package, PID, monotonic transition timestamp, state, normalized scenes, active scene/TID pairs, tracer-owned artifact names, warnings/errors, reason, and stop acknowledgement. Keep the schemas aligned with the strict runtime parsers; tests compare field sets directly.

Add a fixture-only intent protocol in `QtraceAcceptance.kt` with exact modes `timed`, `exit`, and `flight-crash`. `MainActivity.onCreate` and `onNewIntent` delegate matching intents to it. `timed` calls a new deterministic `NativeDemo.runTimedAcceptance(iterations, seed)`, atomically writes its return value to the app files directory, and leaves the process alive; `exit` writes success then exits the fixture process with code zero; `flight-crash` calls the existing Flight acceptance crash path. The helper rejects unknown modes and never runs without the explicit `qtrace_acceptance=true` extra. Unit-test intent parsing and result JSON without starting Android UI.

Implement the C++ oracle as a `noinline` exported function that performs one deterministic mixing block and one 100 ms `usleep` per requested iteration. Acceptance uses 30 iterations so the target remains active across the two-second deadline while the return value depends only on iteration count and seed. Run the same function once without tracing to create the baseline, then through `make_demo_action` during timed tracing. Do not put fixture symbols or intent extras in generic qtrace modules.

Use these fixture contracts:

```kotlin
data class QtraceAcceptanceRequest(val mode: String, val seed: Long, val iterations: Long)

object QtraceAcceptance {
    fun parse(extras: Map<String, Any?>): QtraceAcceptanceRequest?
    fun start(activity: MainActivity, request: QtraceAcceptanceRequest)
}

object NativeDemo {
    external fun runTimedAcceptance(iterations: Long, seed: Long): Long
}
```

```cpp
extern "C" __attribute__((noinline, visibility("default")))
uint64_t demo_timed_acceptance_case(uint64_t iterations, uint64_t seed) noexcept;
```

Implement:

```python
def main(argv: Sequence[str] | None = None) -> int: ...
```

in `scripts/qtrace_device_acceptance.py`. Require `--device`; refuse to select a default device in acceptance runs. Use `tempfile.TemporaryDirectory`, preserve the generated qtrace report paths on failure by printing them, and never run on ordinary host CI automatically. Implement the disconnect case with an acceptance-only `AdbDevice` wrapper that raises one `ConnectionError` on the first artifact read and delegates all later reads to the real device; this exercises host disconnect handling without restarting adbd or disrupting unrelated devices.

- [ ] **Step 4: Add host CI coverage**

Create one host workflow with these bounded commands:

```yaml
name: host-ci
on: [push, pull_request]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 45
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: '17'
      - uses: android-actions/setup-android@v3
      - name: Install pinned Android tools
        run: sdkmanager 'platforms;android-35' 'build-tools;35.0.0' 'cmake;3.22.1' 'ndk;26.1.10909125'
      - name: Python tests
        run: python3 -m unittest discover -s scripts/tests -p 'test_*.py'
      - name: Native, fixture, and tracer tests/builds
        run: ./gradlew nativeHostTest :app:testDebugUnitTest :app:assembleDebug :tracer:assembleDebug :tracer:copyTracerDebug --no-daemon
```

Add `testImplementation "junit:junit:4.13.2"` to `app/build.gradle`; keep the fixture parser test pure Kotlin so it does not need an emulator or Robolectric.

Keep device acceptance documented as a manual pre-release gate:

```bash
python3 scripts/qtrace_device_acceptance.py --device SERIAL
```

- [ ] **Step 5: Run the full host verification**

Run:

```bash
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
./gradlew nativeHostTest :app:testDebugUnitTest :app:assembleDebug :tracer:assembleDebug :tracer:copyTracerDebug --no-daemon
```

Expected: all Python and native host tests PASS.

If a rooted arm64 device is connected, additionally run:

```bash
python3 scripts/qtrace_device_acceptance.py --device SERIAL
```

Expected: exit 0 and a complete timed-session report. If no device is connected, record the acceptance command as pending in the handoff; do not claim device acceptance passed.

- [ ] **Step 6: Commit**

```bash
git add docs/qtrace-config.schema.json docs/qtrace-session-status.schema.json \
  scripts/qtrace_device_acceptance.py scripts/tests/test_qtrace_contracts.py \
  .github/workflows/ci.yml app/src/main/kotlin/com/aprz/qbdiandroid/QtraceAcceptance.kt \
  app/src/test/kotlin/com/aprz/qbdiandroid/QtraceAcceptanceTest.kt \
  app/src/main/kotlin/com/aprz/qbdiandroid/MainActivity.kt \
  app/src/main/kotlin/com/aprz/qbdiandroid/NativeDemo.kt \
  app/src/main/cpp/demo_target/demo_scenes.h \
  app/src/main/cpp/demo_target/demo_scenes.cpp \
  app/src/main/cpp/demo_target/demo_target.cpp app/build.gradle README.md
git commit -m "test: cover qtrace workflow contracts"
```

## Final verification and handoff

Run the exact full suite one final time:

```bash
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
./gradlew nativeHostTest
git status --short
```

Expected: tests PASS. `git status --short` should show only intentionally uncommitted device-output files, if the acceptance test was run; move those outside the repository before integration.

Review the implementation against these non-negotiable invariants:

1. Timed stop is initiated and completed by native code; Frida is detached after startup.
2. New target calls bypass instrumentation after stop begins, while active callbacks return QBDI `STOP` and seal on their owning threads.
3. CLI config accepts only module-relative offsets or symbols, never a base or absolute address.
4. Generic external packages use the same path as the demo; only the demo adapter knows fixture details.
5. `pull` is independent of Frida, build, install, and process startup.
6. Every subprocess/read/wait is bounded, every published report/artifact set is atomic, and all failure paths emit stable stage/code details.
7. Old completed traces remain readable and new stopped traces have exactly one terminal record plus matching metrics-v3 termination fields.
