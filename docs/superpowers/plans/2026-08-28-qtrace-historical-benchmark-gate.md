# Qtrace Historical Benchmark Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Task 8 rooted-device gate compare the current tracer against the exact historical benchmark workload, then reinstall the current fixture APK and complete the existing timed, exit, crash, and pull acceptance matrix.

**Architecture:** Extend the benchmark admission path with a reproducible canonical target identity and whole-APK binding, and add an acceptance-only builder that extracts and builds commit `2d6b1022a14ae554804a57e267544c12dea29353` in a held private tree. The acceptance harness snapshots the current APK and one current tracer/companion pair once, runs the historical APK performance phase, recovers to the current APK, and then runs the unchanged Task 8 fixture phase. Generic `qtrace` package/session/artifact paths remain untouched.

**Tech Stack:** Python 3 standard library, `unittest`, rootless PID namespaces through `scripts.bounded_process`, Git archive/tar, Gradle, Android SDK build-tools 35.0.0, Android NDK 26.1.10909125 `llvm-objcopy`, ADB, Frida, rooted Pixel 6.

## Global Constraints

- Preserve every historical performance row and semantic oracle in `docs/benchmarks/binary-trace-baseline.md` unchanged.
- Preserve the original raw target SHA-256 `5f1a970825ae8bacb17d8dd656e01bd1fe7172638ba3ddcacd82ffaaad6e62c0` as audit evidence; it is not the cross-worktree admission oracle.
- The only historical source revision is commit `2d6b1022a14ae554804a57e267544c12dea29353`; do not fetch, accept a branch/tag, or fall back to another revision.
- Canonical identity uses NDK `26.1.10909125` at `$ANDROID_HOME/ndk/26.1.10909125/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-objcopy` with `--strip-debug --remove-section=.note.gnu.build-id` in that order.
- The only accepted canonical target SHA-256 is `0d8e856c819fb3cd7ae5917053172b4b75a7924784c43e09cb2855a298647169`.
- Historical package, ABI, target entry, and benchmark symbol are exactly `com.aprz.qbdiandroid`, `arm64-v8a`, `lib/arm64-v8a/libdemo_target.so`, and `demo_benchmark_case` at `0x6e828`.
- `git archive` output is at most 8 MiB. Record 1 must be the only global PAX `g` record, have valid PAX length framing, and decode byte-for-byte to `comment=2d6b1022a14ae554804a57e267544c12dea29353\n`; it counts toward the 256-member cap, appears in the manifest as `type=global_pax` with its raw payload size/SHA-256, and is never extracted or published.
- Reject a missing, repeated, reordered, malformed, or different-commit global PAX record and every other PAX/GNU metadata record. After the pinned envelope, accept only directories and regular files below `app/**`, `gradle/wrapper/**`, `build.gradle`, `settings.gradle`, `gradle.properties`, and `gradlew`; reject traversal, duplicate/colliding paths, links, devices, FIFOs, sparse members, and every other record type.
- The archive permits at most 256 total records including the global PAX envelope, 8 MiB total regular-file content, 2 MiB per regular file, 512 UTF-8 path bytes, and 32 path components.
- Extraction owns a held mode-0700 root dirfd, creates directories as 0700, regular files as 0600, and `gradlew` as 0700 using no-follow exclusive descriptor-relative operations.
- Historical Gradle runs exactly `./gradlew :app:assembleDebug --no-daemon --offline` in the private extracted root with a 900-second absolute bound and 4 MiB caps on stdout and stderr.
- A historical APK is a nonempty no-follow regular file no larger than 128 MiB; ZIP admission permits at most 4096 entries, 512 MiB total uncompressed bytes, and 128 MiB per entry.
- The APK contains exactly one `lib/arm64-v8a/libdemo_target.so`, no other ABI's `libdemo_target.so`, and a nonempty target no larger than 64 MiB whose CRC and size validate.
- `aapt2` is pinned to `$ANDROID_HOME/build-tools/35.0.0/aapt2`; a missing/unexecutable pinned tool, package mismatch, ABI mismatch, canonical mismatch, or APK binding mismatch fails before warmup.
- Host order is `nativeHostTest -> full Python tests -> build current APK/tracer/companion -> snapshot current APK and one current tracer/companion pair -> build/validate historical APK`.
- Device order is `install historical APK -> force-stop -> stage held current tracer/companion pair -> historical --compare -> install current APK -> force-stop -> restage the same pair -> start/wait timed baseline -> timed offset -> timed symbol -> monitor-exit -> flight-crash -> pull latest -> pull name -> pull all -> pull all --compressed-only`.
- The first and second tracer staging operations consume the same held descriptors, bytes, and SHA-256 values; neither rereads mutable Gradle output.
- Historical build, identity, install, or compare failure is fail-closed; never use semantic-only fallback, rewrite the immutable baseline, or substitute an app-private historical SO for the historical APK.
- After historical APK installation, every failure attempts bounded recovery by force-stopping, installing the held current APK, and force-stopping again; cleanup errors append without replacing the primary error.
- Every subprocess uses the PID-namespace containment backend and one absolute monotonic deadline; every archive/APK/ELF read is no-follow, byte-capped, deadline-bounded, and cleanup-bounded.
- Failure evidence is a bounded atomically published JSON document containing phase, historical commit, archive manifest/hash, command status/stderr, host/device APK SHA values, raw/canonical target SHA values, held tracer pair SHA values, and every cleanup error.
- Success exhaustively closes and unlinks private resources; failure retains the acceptance evidence directory and prints its exact path.
- Do not modify `qtrace` config, session orchestration, external APK installer, Task 7 adapter, or generic artifact paths; historical commit/package/fixture knowledge stays in `scripts/benchmark_trace.py`, `scripts/qtrace_historical_benchmark.py`, and `scripts/qtrace_device_acceptance.py`.
- The rooted-device gate remains explicit and manual; ordinary CI must not start it automatically.

## File Structure

- Create `scripts/qtrace_historical_benchmark.py` for pinned identity, bounded canonicalization, trusted extraction/build/APK validation/held lifetime; create `scripts/tests/test_qtrace_historical_benchmark.py` for observable canonical, malicious tar/ZIP, exact command, deadline, identity, and cleanup contracts.
- Modify `scripts/benchmark_trace.py` for strict baseline parsing, whole-APK/canonical pre-warmup admission, and fixed report keys; modify `scripts/tests/test_benchmark_trace.py` for baseline, binding, report, and CLI regressions.
- Modify `docs/benchmarks/binary-trace-baseline.md`: add the exact historical commit and canonical SHA rows without changing raw SHA, profile rows, or semantic oracles.
- Modify `scripts/bounded_process.py` with a backward-compatible `cwd` keyword; modify `scripts/tests/test_bounded_process.py` to prove cwd while preserving output/timeout/error behavior.
- Modify `scripts/qtrace_device_acceptance.py` for held inputs, two phases, recovery, and evidence; modify `scripts/tests/test_qtrace_contracts.py` for exact order, same-pair reuse, failure matrix, and cleanup contracts.
- Modify `README.md`: explain canonical identity, historical/current two-APK gate, pinned tools, fail-closed behavior, and manual-only invocation.

---

### Task 1: Add Canonical Benchmark Admission and Reporting

**Files:**
- Create: `scripts/qtrace_historical_benchmark.py`
- Create: `scripts/tests/test_qtrace_historical_benchmark.py`
- Modify: `scripts/benchmark_trace.py:335-367,749-792,1344-1458`
- Modify: `scripts/tests/test_benchmark_trace.py:419-650`
- Modify: `docs/benchmarks/binary-trace-baseline.md:1-31`

**Interfaces:**
- Consumes: `capture_bounded(command: Sequence[str], *, maximum_bytes: int, timeout: float) -> bytes`, `$ANDROID_HOME`, and target bytes already bounded to 64 MiB.
- Produces: `canonical_elf_sha256(elf: bytes, *, deadline: float, android_home: Path | None = None, capture: Callable = capture_bounded) -> str` in `scripts.qtrace_historical_benchmark`.
- Produces: `InstalledTargetIdentity(installed_apk_sha256: str, target_library_sha256: str, target_library_canonical_sha256: str)` and `verify_installed_target_library(args: argparse.Namespace, baseline: dict[str, str]) -> InstalledTargetIdentity` in `scripts.benchmark_trace`.
- Produces: CLI option `--expected-installed-apk-sha256` taking one lowercase 64-hex value, plus report keys `installed_apk_sha256`, `target_library_sha256`, `baseline_target_library_sha256`, `target_library_canonical_sha256`, and `baseline_target_library_canonical_sha256`.

- [ ] **Step 1: Write failing canonicalization tests**

Create `CanonicalIdentityTests` with these exact methods:

```python
class CanonicalIdentityTests(unittest.TestCase):
    def test_debug_and_build_id_changes_share_one_canonical_hash(self):
        a = b"\x7fELFRUNTIME|DBG|/private/build-one|BUILD-ID|1111"
        b = b"\x7fELFRUNTIME|DBG|/private/build-two|BUILD-ID|2222"
        self.assertNotEqual(hashlib.sha256(a).digest(), hashlib.sha256(b).digest())
        self.assertEqual(canonical(a), canonical(b))

    def test_runtime_byte_mutation_changes_canonical_hash(self):
        self.assertNotEqual(canonical(b"\x7fELFRUNTIME-A|DBG|x"),
                            canonical(b"\x7fELFRUNTIME-B|DBG|x"))
```

Define `canonical(value)` as `canonical_elf_sha256(value, deadline=time.monotonic() + 2, capture=fake_objcopy)`. The capture double copies only bytes before `|DBG|` to the last argv path, records argv, and asserts pinned `llvm-objcopy`, `--strip-debug`, `--remove-section=.note.gnu.build-id`, source, destination order. Add `test_canonicalizer_rejects_missing_tool_empty_non_elf_oversized_and_expired_output`; every case raises before a digest and leaves no canonical temporary file.

- [ ] **Step 2: Write failing baseline, APK-binding, and pre-warmup tests**

Add `HistoricalTargetIdentityTests` with literal expectations:

```python
RAW_SHA = "5f1a970825ae8bacb17d8dd656e01bd1fe7172638ba3ddcacd82ffaaad6e62c0"
CANONICAL_SHA = "0d8e856c819fb3cd7ae5917053172b4b75a7924784c43e09cb2855a298647169"
COMMIT = "2d6b1022a14ae554804a57e267544c12dea29353"
def test_baseline_preserves_raw_identity_and_requires_canonical_identity(self):
    text = Path("docs/benchmarks/binary-trace-baseline.md").read_text(encoding="utf-8")
    identity = benchmark_trace.parse_baseline_document(text)
    self.assertEqual((RAW_SHA, CANONICAL_SHA, COMMIT),
        (identity["target_library_sha256"], identity["target_library_canonical_sha256"],
         identity["historical_target_commit"]))
```

Add `test_compare_binds_whole_apk_and_reports_raw_and_canonical_identities`.
Patch `parse_args()` with a complete `argparse.Namespace`, patch
`live_device_identity()`, `verify_candidate_tracer()`,
`verify_installed_target_library()`, and six `run_once()` results, capture
stdout with `contextlib.redirect_stdout()`, and assert this literal projection
of the parsed JSON:

```python
self.assertEqual({
    "installed_apk_sha256": "1" * 64,
    "target_library_sha256": "2" * 64,
    "baseline_target_library_sha256": RAW_SHA,
    "target_library_canonical_sha256": CANONICAL_SHA,
    "baseline_target_library_canonical_sha256": CANONICAL_SHA,
}, {key: report[key] for key in (
    "installed_apk_sha256", "target_library_sha256",
    "baseline_target_library_sha256", "target_library_canonical_sha256",
    "baseline_target_library_canonical_sha256",
)})
```

Add `test_compare_rejects_expected_apk_or_canonical_mismatch_before_warmup`:
patch `run_once` with an assertion-raising fake, run `main()`, assert distinct
`installed base.apk SHA-256` or `canonical target SHA-256` errors, and assert
zero warmup calls. Add
`test_installed_apk_rejects_multiple_base_paths_duplicate_target_other_abi_bad_crc_and_every_zip_size_bound_before_warmup`,
with literal cases for two `pm path` base entries, two arm64 target entries,
an `armeabi-v7a` target, a corrupted target payload, 4097 entries, 512 MiB + 1
aggregate metadata, a 128 MiB + 1 entry, and a 64 MiB + 1 target. Add
`test_expected_installed_apk_sha_requires_lowercase_64_hex` and
`test_manual_non_compare_run_does_not_require_expected_apk_sha`.

- [ ] **Step 3: Run the focused tests and verify RED**

Run:

```bash
python3 -m unittest \
  scripts.tests.test_qtrace_historical_benchmark.CanonicalIdentityTests \
  scripts.tests.test_benchmark_trace.HistoricalTargetIdentityTests -v
```

Expected: ERROR importing `scripts.qtrace_historical_benchmark` and FAIL because the baseline/parser/report do not contain canonical or whole-APK identity fields. Record both failure classes before implementation.

- [ ] **Step 4: Implement the bounded canonical identity helper**

Create these exact constants and entry point:

```python
HISTORICAL_COMMIT = "2d6b1022a14ae554804a57e267544c12dea29353"
HISTORICAL_RAW_TARGET_SHA256 = "5f1a970825ae8bacb17d8dd656e01bd1fe7172638ba3ddcacd82ffaaad6e62c0"
HISTORICAL_CANONICAL_TARGET_SHA256, NDK_VERSION = "0d8e856c819fb3cd7ae5917053172b4b75a7924784c43e09cb2855a298647169", "26.1.10909125"
MAX_TARGET_BYTES = 64 * 1024 * 1024
def canonical_elf_sha256(elf: bytes, *, deadline: float,
                         android_home: Path | None = None,
                         capture: Callable = capture_bounded) -> str:
    """Canonicalize one bounded ELF with the pinned NDK tool and hash its output."""
```

Require `0 < len(elf) <= 64 * 1024 * 1024`, `elf.startswith(b"\x7fELF")`, a positive remaining deadline, and an executable regular pinned tool. Use a mode-0700 `TemporaryDirectory`, create input/output as no-follow exclusive regular files, invoke exactly `[objcopy, "--strip-debug", "--remove-section=.note.gnu.build-id", input, output]`, cap subprocess output at 1 MiB, and read a nonempty no-follow regular ELF output no larger than 64 MiB before the same absolute deadline. Close/unlink every descriptor/path and append cleanup diagnostics to a primary error.

- [ ] **Step 5: Implement strict baseline and installed target admission**

Add:

```python
@dataclass(frozen=True)
class InstalledTargetIdentity:
    installed_apk_sha256: str
    target_library_sha256: str
    target_library_canonical_sha256: str
```

Extend `parse_baseline_document()` with `Target library canonical SHA-256 -> target_library_canonical_sha256` and `Historical target commit -> historical_target_commit`; require lowercase 64-hex SHA values and require the commit value to equal `HISTORICAL_COMMIT`, not merely match a 40-hex pattern. In `verify_installed_target_library()`, keep the 512 MiB bounded device read, compute whole-APK SHA first, validate an optional `args.expected_installed_apk_sha256`, require exactly one safe `pm path` base APK, at most 4096 unique ZIP entries, at most 512 MiB declared aggregate uncompressed bytes, at most 128 MiB per entry, one nonempty arm64 target no larger than 64 MiB, no target under another ABI, and matching target CRC/size. Compute raw and canonical target SHA values, require the canonical value to match the baseline, and return `InstalledTargetIdentity`. Raw mismatch no longer rejects; raw baseline identity remains report evidence.

Parse `--expected-installed-apk-sha256` without a default transformation. In compare mode validate it before any ADB call when supplied. In `main()`, perform device identity, tracer identity, whole-APK binding, and canonical target checks before the first `run_once()`, then render all five fixed identity keys. Keep `require_profile_warmup_oracle()` immediately after the one warmup and before the five measured runs.

- [ ] **Step 6: Add the immutable canonical baseline rows**

Under `## Device and build identity`, leave `Target library SHA-256` and every performance table byte-for-byte unchanged, and add `| Target library canonical SHA-256 | 0d8e856c819fb3cd7ae5917053172b4b75a7924784c43e09cb2855a298647169 |` and `| Historical target commit | 2d6b1022a14ae554804a57e267544c12dea29353 |`.

Replace the paragraph that calls the raw SHA reproducible with an explanation that raw SHA is audit evidence and the canonical SHA is the cross-worktree admission identity produced by pinned NDK 26.1.10909125 after stripping debug information and `.note.gnu.build-id`.

- [ ] **Step 7: Run focused and regression tests GREEN**

Run:

```bash
python3 -m unittest scripts.tests.test_qtrace_historical_benchmark.CanonicalIdentityTests \
  scripts.tests.test_benchmark_trace.HistoricalTargetIdentityTests \
  scripts.tests.test_benchmark_trace.OptimizedMetricsParserTests -v
python3 -m py_compile scripts/qtrace_historical_benchmark.py scripts/benchmark_trace.py
```

Expected: all selected tests PASS; malformed canonical rows, APK binding mismatches, and canonical mismatches fail before warmup; raw historical SHA, historical profile rows, and semantic oracle values remain unchanged.

- [ ] **Step 8: Commit canonical admission**

```bash
git add scripts/qtrace_historical_benchmark.py \
  scripts/tests/test_qtrace_historical_benchmark.py \
  scripts/benchmark_trace.py scripts/tests/test_benchmark_trace.py \
  docs/benchmarks/binary-trace-baseline.md
git commit -m "feat: bind benchmark to canonical target"
```

### Task 2: Build and Hold the Exact Historical APK

**Files:**
- Modify: `scripts/qtrace_historical_benchmark.py`
- Modify: `scripts/tests/test_qtrace_historical_benchmark.py`
- Modify: `scripts/bounded_process.py:751-1048`
- Modify: `scripts/tests/test_bounded_process.py`

**Interfaces:**
- Consumes: Task 1 constants and `canonical_elf_sha256()`, plus the existing PID-namespace containment semantics.
- Produces: `capture_bounded(command: Sequence[str], *, maximum_bytes: int, timeout: float, cwd: Path | None = None) -> bytes`; callers omitting `cwd` retain identical behavior.
- Produces: `HistoricalBenchmarkApk(path: Path, apk_sha256: str, target_raw_sha256: str, target_canonical_sha256: str)` with private non-init `_descriptor`, `_snapshot_root`, and `_closed` ownership fields, `verify_path() -> None`, and idempotent `close() -> None`.
- Produces: `build_historical_benchmark_apk(repository: Path, *, deadline: float) -> HistoricalBenchmarkApk` and `HistoricalBenchmarkError.report: dict[str, object]`.

- [ ] **Step 1: Write a failing contained-cwd test**

Add this behavior test without inspecting source text:

```python
def test_capture_bounded_runs_target_in_requested_directory(self):
    with tempfile.TemporaryDirectory() as directory:
        output = capture_bounded([sys.executable, "-c", "import os; print(os.getcwd())"],
                                 maximum_bytes=4096, timeout=3.0, cwd=Path(directory))
        self.assertEqual(str(Path(directory).resolve()), output.decode().strip())
```

Retain the existing timeout, nonzero exit, descendant containment, and maximum-byte tests to prove the new keyword does not weaken process semantics.

Add
`test_capture_bounded_rejects_missing_file_and_symlink_cwd_before_target_spawn`.
For each invalid cwd, pass a command that would create a marker; assert a
cwd-specific `BoundedProcessError`, no marker, and the pre-opened directory FD
count returns to its initial value. Add
`test_capture_bounded_holds_cwd_across_path_rebinding_and_aggregates_close_failure`:
rebind the original directory after its FD is opened, assert the target prints
the held directory rather than the replacement, inject one cwd-FD close
failure, and assert the primary plus cleanup diagnostic while every other FD
and namespace child is closed/reaped.

- [ ] **Step 2: Write malicious archive and exact-command RED tests**

Create `HistoricalArchiveTests` with
`test_archive_requires_one_first_pinned_global_pax_envelope`. Build a valid
POSIX length-framed global PAX `g` record whose decoded bytes are exactly:

```python
PINNED_PAX_VALUE = (
    b"comment=2d6b1022a14ae554804a57e267544c12dea29353\n"
)
```

Assert the valid envelope is record 1 and contributes this first manifest
projection, where `raw_pax_body` includes its POSIX decimal length prefix:

```python
self.assertEqual({
    "type": "global_pax",
    "size": len(raw_pax_body),
    "sha256": hashlib.sha256(raw_pax_body).hexdigest(),
}, {key: manifest[0][key] for key in ("type", "size", "sha256")})
```

Assert no file or directory is created for the PAX header name. Table-drive
missing envelope, two envelopes, a directory before the envelope, invalid
length framing, truncated payload, an extra decoded key/line, and commit
`0` * 40; each raises before extraction. After one valid envelope, reject
local PAX `x`, another global PAX `g`, GNU longname `L`, GNU longlink `K`, GNU
sparse `S`, and every type other than directory (`5`) or regular (`0`/NUL).

Add
`test_archive_rejects_every_path_type_duplicate_and_collision_boundary`.
Cover literal members `../escape`, `/absolute`, `app//empty`, `app/./dot`,
`app\\backslash`, an invalid UTF-8 raw name, an embedded-NUL raw header,
`outside.txt`, and `gradle/not-wrapper.txt`; construct the invalid UTF-8 and
NUL cases as raw 512-byte tar headers so `tarfile` cannot normalize the bytes
before validation. Cover `app/link` as symlink and hardlink, `app/device` as a
character device, `app/pipe` as a FIFO, a GNU sparse header, duplicate
`app/build.gradle`, both file-then-child and child-then-file collision orders,
and every post-envelope member type other than directory or regular file. Add
`test_archive_counts_pax_in_256_member_limit_and_rejects_every_size_boundary`:
accept the envelope plus 255 allowlisted directories, reject the envelope plus
256 directories, and reject 2 MiB + 1 single-file, 8 MiB + 1 regular aggregate,
513 UTF-8 path bytes, and 33 components.
In each subcase assert extraction raises, no path appears outside the held
root, and the held root contains no partially published regular file. Add
`test_archive_extracts_only_the_allowlist_with_canonical_modes`: assert held
root/directories are 0700, `gradlew` is 0700, every other regular file is
0600, the PAX header name has no extracted path, and the manifest records the
global PAX envelope plus each extracted path, type, size, and SHA exactly once.

Add `test_builder_uses_exact_commit_allowlist_private_cwd_and_offline_gradle`. The recording capture double must observe these argv sequences:

```python
[
    ["git", "-C", str(repository), "cat-file", "-e", "2d6b1022a14ae554804a57e267544c12dea29353^{commit}"],
    ["git", "-C", str(repository), "archive", "--format=tar", "2d6b1022a14ae554804a57e267544c12dea29353", "--", "app", "build.gradle", "settings.gradle", "gradle.properties", "gradlew", "gradle/wrapper"],
    ["./gradlew", ":app:assembleDebug", "--no-daemon", "--offline"],
]
```

The fake `git archive` response starts with the valid pinned global PAX record
above. Assert the Gradle call's `cwd` is the extracted private root rather than
the shared checkout, `timeout <= deadline - time.monotonic()`, and no `fetch`,
shell string, branch, or tag is accepted.

- [ ] **Step 3: Write historical APK validation and held-lifetime RED tests**

Create `HistoricalApkTests` methods
`test_validator_accepts_exact_pinned_aapt2_package_arm64_entry_and_canonical_identity`,
`test_validator_rejects_wrong_package_missing_or_extra_abi_duplicate_target_bad_crc_and_runtime_mutation`,
`test_validator_rejects_4097_entries_512_mib_plus_one_entry_128_mib_plus_one_and_target_64_mib_plus_one`,
`test_held_apk_rejects_path_rebind_growth_symlink_empty_and_nonregular_files`,
`test_held_apk_blocking_open_and_read_hit_deadline_and_reap_workers`,
`test_builder_preserves_primary_and_all_descriptor_tree_and_command_cleanup_failures`,
and `test_missing_commit_pinned_tools_or_offline_dependency_fails_without_installable_result`.
The accepted case records exact argv
`[str(aapt2), "dump", "badging", str(apk_path)]`; wrong build-tools or NDK
version paths are rejected rather than searched on `PATH`.

The accepted fixture must return `HistoricalBenchmarkApk.apk_sha256 == hashlib.sha256(apk_bytes).hexdigest()`, `target_raw_sha256 == hashlib.sha256(raw_target).hexdigest()`, and `target_canonical_sha256 == "0d8e856c819fb3cd7ae5917053172b4b75a7924784c43e09cb2855a298647169"`. Rebinding `result.path` while its descriptor is held must make `verify_path()` fail. The first `close()` removes the private snapshot tree; the second returns without error and the tree remains absent.

- [ ] **Step 4: Run Task 2 tests and verify RED**

Run:

```bash
python3 -m unittest \
  scripts.tests.test_bounded_process.BoundedProcessTests.test_capture_bounded_runs_target_in_requested_directory \
  scripts.tests.test_qtrace_historical_benchmark.HistoricalArchiveTests \
  scripts.tests.test_qtrace_historical_benchmark.HistoricalApkTests -v
```

Expected: FAIL with unexpected `cwd` for `capture_bounded`, and FAIL/ERROR because archive extraction, `HistoricalBenchmarkApk`, and `build_historical_benchmark_apk` do not exist.

- [ ] **Step 5: Add cwd to the containment boundary**

Extend only the public signature and outer wrapper spawn:

```python
def capture_bounded(command: Sequence[str], *, maximum_bytes: int,
                    timeout: float, cwd: Path | None = None) -> bytes:
```

Import `Path`; resolve/open cwd as a no-follow directory before target authorization, verify its held identity, and start outer `unshare` with `cwd=f"/proc/self/fd/{descriptor}"`. Keep that FD open through `Popen` cwd resolution, then close it independently with the other owned descriptors. Reject missing, symlink, and non-directory cwd before authorizing the target. Preserve the primary exception and append cwd close/rebind diagnostics without skipping selector, stream, pidfd, control, or status cleanup. Existing deadlines, PID namespace, wrapper pidfd identity, output caps, return mapping, and emergency kill/reap remain unchanged.

- [ ] **Step 6: Implement safe archive extraction and the isolated build**

Add these exact limits and public shape:

```python
MAX_ARCHIVE_BYTES, MAX_ARCHIVE_MEMBERS = 8 * 1024 * 1024, 256
MAX_ARCHIVE_FILE_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_PATH_BYTES, MAX_ARCHIVE_COMPONENTS = 512, 32
MAX_APK_BYTES = 128 * 1024 * 1024
MAX_ZIP_ENTRIES = 4096
MAX_ZIP_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
@dataclass
class HistoricalBenchmarkApk:
    path: Path
    apk_sha256: str
    target_raw_sha256: str
    target_canonical_sha256: str
    _descriptor: int = field(init=False, repr=False, compare=False)
    _snapshot_root: Path = field(init=False, repr=False, compare=False)
    _closed: bool = field(default=False, init=False, repr=False, compare=False)
    def verify_path(self) -> None:
        """Require the held fd and pathname to retain type, identity, size, and SHA."""
    def close(self) -> None:
        """Close the held descriptor and remove the private source/snapshot tree once."""
def build_historical_benchmark_apk(repository: Path, *, deadline: float) -> HistoricalBenchmarkApk:
    """Build, validate, snapshot, and hold the fixed historical benchmark APK."""
```

Validate `repository` as a held no-follow directory; run the exact `cat-file`
and archive argv from Step 2 with remaining time from the shared deadline and
an 8 MiB stdout cap. Raw-parse record 1 before ordinary path validation:
require typeflag `g`, valid POSIX PAX length framing, exactly one decoded line,
and decoded bytes exactly
`comment=2d6b1022a14ae554804a57e267544c12dea29353\n`. Count it as member 1;
append manifest type `global_pax`, tar-declared raw payload size, and SHA-256 of
the raw length-framed payload; skip all directory/file creation for it.

Raw-scan every later header and reject `g`, local PAX `x`, GNU longname `L`,
GNU longlink `K`, GNU sparse `S`, or any typeflag except directory `5` and
regular `0`/NUL. Before creating an ordinary member, validate raw tar header
name bytes as UTF-8 and reject NUL aliases,
absolute/empty/dot/dot-dot/backslash components, paths over 512 UTF-8 bytes or
32 components, paths outside the four root files plus
`app/**`/`gradle/wrapper/**` allowlist, more than 256 total records including
the envelope, individual regular files over 2 MiB, aggregate regular bytes
over 8 MiB, duplicates, both collision orders, links, devices, FIFOs, sparse
members, and every other record type. A missing, repeated, reordered,
malformed, or different-commit envelope fails before extraction. Parse without
`extractall()` and extract only ordinary members through held dirfds with
`O_NOFOLLOW|O_EXCL`, 0700 directories, 0600 files, and only `gradlew` at 0700.
Run exact offline Gradle in the private root through `cwd`, with a 900-second
maximum clipped to the absolute deadline, a 4 MiB stdout cap, and the existing
stricter 64 KiB stderr cap (both satisfy the 4 MiB upper bound).

- [ ] **Step 7: Validate and hold the historical APK**

Require pinned build-tools `35.0.0/aapt2`, run `[str(aapt2), "dump", "badging", str(apk.path)]` with bounded output, and require package `com.aprz.qbdiandroid`. Inspect ZIP metadata before payloads, reject unsafe/duplicate/link entries and every bound, stream the arm64 target through CRC/size checks, reject another ABI's target, and require Task 1's full canonical value.

Copy the APK once into a separate mode-0700 held snapshot root using a bounded worker, retain an open descriptor, record descriptor identity/size/SHA, and remove the extracted build tree before returning. `verify_path()` must recheck fd/path identity, type, size, and SHA in a killable worker with its own fixed 30-second deadline before and after each pathname consumer. Blocking open/read, growth, rebind, and timeout must kill/reap the worker. On failure, raise `HistoricalBenchmarkError` whose bounded `report` preserves phase, commit, manifest/hash, command argv/return/stderr, all computed identities, and all cleanup failures.

- [ ] **Step 8: Run Task 2 focused and full containment tests GREEN**

Run:

```bash
python3 -m unittest scripts.tests.test_qtrace_historical_benchmark -v
python3 -m unittest scripts.tests.test_bounded_process -v
python3 -m py_compile scripts/qtrace_historical_benchmark.py scripts/bounded_process.py
```

Expected: all archive/APK corpus cases fail before publication, the valid fake build returns one held verified APK, cwd is observable inside the contained target, and every existing setsid/double-fork/timeout containment test remains PASS.

- [ ] **Step 9: Commit the historical builder**

```bash
git add scripts/qtrace_historical_benchmark.py \
  scripts/tests/test_qtrace_historical_benchmark.py \
  scripts/bounded_process.py scripts/tests/test_bounded_process.py
git commit -m "feat: build held historical benchmark APK"
```

### Task 3: Run the Historical and Current APK Phases Safely

**Files:**
- Modify: `scripts/qtrace_device_acceptance.py:39-58,78-397,405-594,1296-1410`
- Modify: `scripts/tests/test_qtrace_contracts.py:1136-1423,2268-3050`

**Interfaces:**
- Consumes: `HistoricalBenchmarkApk`, `build_historical_benchmark_apk()`, the Task 1 benchmark CLI contract, `HostBinarySnapshot`, `Runner`, and existing fixture/report validators.
- Produces: `HeldTracerPair(tracer: HostBinarySnapshot, companion: HostBinarySnapshot)` with idempotent `close() -> None` and `verify_paths() -> None`.
- Produces: `_snapshot_current_inputs(*, deadline: float) -> tuple[HostBinarySnapshot, HeldTracerPair]`, `_install_held_apk(device: str, runner: Runner, apk: HostBinarySnapshot | HistoricalBenchmarkApk) -> None`, and `_stage_app_private_binaries(device: str, runner: Runner, *, token: str, pair: HeldTracerPair, package: str = PACKAGE) -> None`.
- Produces: `run_acceptance(device: str, directory: Path, *, runner: Runner, converter=None, artifact_client_factory=AdbArtifactClient, historical_builder=build_historical_benchmark_apk) -> int`.

- [ ] **Step 1: Write the exact two-phase order RED test**

Add `test_acceptance_installs_historical_then_current_and_reuses_one_held_pair`. Use a recording `historical_builder`, recording held APK installers, and the existing behavior fake for the fixture/report/pull phase. Assert the semantic event list is exactly:

```python
[
    "nativeHostTest", "full-python", "build-current", "snapshot-current-apk-and-pair",
    "build-historical-2d6b1022a14ae554804a57e267544c12dea29353",
    "install-historical", "force-stop-historical", "stage-historical-held-pair",
    "compare-historical", "install-current", "force-stop-current",
    "restage-current-same-held-pair", "start-timed-baseline", "wait-timed-baseline",
    "timed-offset", "timed-symbol", "monitor-exit", "flight-crash",
    "pull-latest", "pull-name", "pull-all", "pull-all-compressed-only",
]
```

Assert the two stage calls receive the same `HeldTracerPair` object and unchanged SHA values. Assert the compare command is exactly:

```python
("python3", "scripts/benchmark_trace.py", "--device", "SERIAL", "--profile", "fast",
 "--runs", "5", "--candidate-tracer", str(pair.tracer.path),
 "--expected-installed-apk-sha256", historical.apk_sha256,
 "--compare", "docs/benchmarks/binary-trace-baseline.md")
```

- [ ] **Step 2: Write held-input, install binding, and no-reread RED tests**

Add exact tests `test_current_apk_and_tracer_pair_are_snapshotted_before_historical_build`, `test_each_adb_install_revalidates_the_same_held_apk_before_and_after_path_use`, `test_second_stage_uses_held_pair_after_mutable_build_outputs_are_rebound`, `test_historical_compare_failure_never_starts_current_fixture_or_semantic_fallback`, and `test_current_qtrace_start_and_pull_commands_receive_no_historical_arguments`.

The path-rebind test must overwrite the original current APK, tracer, and companion after snapshots are created; fake ADB must receive only private held paths and bytes. The install test must mutate a pathname during fake `adb install`; `_install_held_apk()` must fail its post-install identity check and must not report the APK installed. The generic-path test asserts behavior through injected fakes and call records, not source text.

- [ ] **Step 3: Write recovery and exhaustive cleanup RED tests**

Add `test_every_post_historical_install_failure_recovers_current_apk_and_force_stops`. Iterate these literal primary boundaries:

```python
("force-stop-historical", "stage-historical", "compare-historical", "install-current",
 "force-stop-current", "restage-current", "start-timed-baseline")
```

For each boundary assert recovery attempts `force-stop -> install held current APK -> force-stop`, no later fixture/pull event runs after the primary, and the primary label remains the raised cause. Add `test_primary_and_every_recovery_snapshot_descriptor_tree_and_report_failure_are_visible`; inject one compare failure plus failures for all three recovery operations, both pair closes, current APK close, historical APK close, and evidence publication. Assert every unique label occurs once in deterministic diagnostic order and no close action is skipped.

Add `test_failure_report_is_bounded_atomic_and_retained_with_exact_phase_and_hashes`. Parse the retained JSON and assert keys and literal values for commit `2d6b1022a14ae554804a57e267544c12dea29353`, historical/current APK SHA values, raw/canonical target SHA values, both tracer pair SHA values, phase `compare-historical`, and the complete cleanup error array. Assert the archive manifest's first entry projects to `{"type": "global_pax", "size": len(raw_pax_body), "sha256": hashlib.sha256(raw_pax_body).hexdigest()}`, the PAX header name is absent from every extracted/published path, and no partial report name remains.

- [ ] **Step 4: Run Task 3 tests and verify RED**

Run:

```bash
python3 -m unittest \
  scripts.tests.test_qtrace_contracts.AcceptanceHarnessTests.test_acceptance_installs_historical_then_current_and_reuses_one_held_pair \
  scripts.tests.test_qtrace_contracts.AcceptanceHarnessTests.test_every_post_historical_install_failure_recovers_current_apk_and_force_stops \
  scripts.tests.test_qtrace_contracts.AcceptanceHarnessTests.test_failure_report_is_bounded_atomic_and_retained_with_exact_phase_and_hashes -v
```

Expected: FAIL because current production installs only the current APK, starts the timed baseline before compare, snapshots the pair inside each staging call, and has no historical recovery/evidence contract.

- [ ] **Step 5: Lift current snapshots over both phases**

Add:

```python
@dataclass
class HeldTracerPair:
    tracer: HostBinarySnapshot
    companion: HostBinarySnapshot
    def verify_paths(self) -> None:
        self.tracer.verify_path(); self.companion.verify_path()
    def close(self) -> None:
        """Attempt both closes and raise one ordered aggregate if either fails."""
```

Refactor `_stage_app_private_binaries()` to consume `pair` and never reopen `TRACER_PATH` or `COMPANION_PATH`. Preserve companion-first/tracer-last activation, final regular-file/mode/SHA validation, symlink refusal, private UUID scratch paths, and exhaustive cleanup. `_snapshot_current_inputs()` snapshots `app/build/outputs/apk/debug/app-debug.apk` with a 128 MiB cap and the pair with 64 MiB caps, all before calling `historical_builder`.

- [ ] **Step 6: Implement held APK installation and the strict phase order**

Implement `_install_held_apk()` as:

```python
def _install_held_apk(device: str, runner: Runner,
                      apk: HostBinarySnapshot | HistoricalBenchmarkApk) -> None:
    apk.verify_path()
    runner.run(("adb", "-s", device, "install", "-r", str(apk.path)), timeout=120.0)
    apk.verify_path()
```

In `run_acceptance()`, keep the first three host commands exact, snapshot current inputs, build/validate historical, then execute the complete Device order from Global Constraints. Pass the held tracer path and historical held APK SHA to the exact compare command from Step 1. Install current APK and successfully restage the same pair before starting the timed baseline. Leave every timed/monitor/crash/report/pull validator intact after that point.

- [ ] **Step 7: Add current-APK recovery and bounded evidence**

Mark recovery active only after historical install and post-path verification succeed, and keep it active until `run_acceptance()` succeeds. Any later primary failure triggers bounded `force-stop -> _install_held_apk(current) -> force-stop`, including failures after current staging.

Track phase and identities in one state object. Atomically publish at most 1 MiB to `historical-benchmark-gate.json` under the acceptance output root using a no-follow exclusive temporary; sort keys and reject non-finite JSON. Preserve the primary exception and append every recovery, evidence, descriptor, historical object, current snapshot, pair, and temporary-tree cleanup error in deterministic order. Let `main()` retain and print the existing `qtrace-acceptance-failures/` directory's UUIDv4 leaf on failure.

- [ ] **Step 8: Run Task 3 focused and existing acceptance tests GREEN**

Run:

```bash
python3 -m unittest scripts.tests.test_qtrace_contracts.AcceptanceHarnessTests -v
python3 -m py_compile scripts/qtrace_device_acceptance.py
```

Expected: exact two-phase order PASS; all recovery/fault boundaries retain their primary and every cleanup diagnostic; original report, timed proof, stopped-QTRB, exit/crash distinction, pull-union, one-read retry, held-root, and direct-entry tests remain PASS.

- [ ] **Step 9: Commit the dual-phase acceptance workflow**

```bash
git add scripts/qtrace_device_acceptance.py scripts/tests/test_qtrace_contracts.py
git commit -m "feat: run historical benchmark device phase"
```

### Task 4: Document and Execute the Complete Release Gate

**Files:**
- Modify: `README.md:155-170,464-496`
- Verify only: `.github/workflows/ci.yml`
- Verify only: `qtrace/**`, `scripts/qtrace.py`, and Task 7 adapter files shown by `git diff --name-only HEAD~3`

**Interfaces:**
- Consumes: all Task 1–3 CLI and lifecycle contracts.
- Produces: user-facing rooted-gate instructions that distinguish raw audit SHA, canonical admission SHA, exact historical commit, and the historical/current APK phases.
- Produces: host-suite and real Pixel 6 acceptance evidence; the implementation is not complete without a successful physical-device run.

- [ ] **Step 1: Update README behavior and operator expectations**

Document exact commit `2d6b1022a14ae554804a57e267544c12dea29353`, raw audit SHA `5f1a970825ae8bacb17d8dd656e01bd1fe7172638ba3ddcacd82ffaaad6e62c0`, canonical SHA `0d8e856c819fb3cd7ae5917053172b4b75a7924784c43e09cb2855a298647169`, and Android NDK 26.1.10909125 command `llvm-objcopy --strip-debug --remove-section=.note.gnu.build-id`.

Explain that `python3 scripts/qtrace_device_acceptance.py --device SERIAL` builds current outputs first, privately archives/builds the exact historical APK offline, installs historical APK for `--compare`, then installs current APK and completes timed/exit/crash/four-pull fixture acceptance with the same held tracer pair. State that any historical failure is a release-gate failure, never a semantic-only fallback; direct manual benchmark runs may omit `--expected-installed-apk-sha256`, while Task 8 always supplies it. Keep the manual-only CI warning prominent.

- [ ] **Step 2: Run syntax and focused suites**

Run:

```bash
python3 -m py_compile scripts/bounded_process.py scripts/qtrace_historical_benchmark.py scripts/benchmark_trace.py scripts/qtrace_device_acceptance.py
python3 -m unittest scripts.tests.test_bounded_process \
  scripts.tests.test_qtrace_historical_benchmark scripts.tests.test_benchmark_trace -v
python3 -m unittest scripts.tests.test_qtrace_contracts.AcceptanceHarnessTests -v
```

Expected: syntax checks exit 0 and every focused suite ends with `OK`; no timeout leaves a live namespace member or held descriptor.

- [ ] **Step 3: Run the complete host gates**

Run:

```bash
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
./gradlew nativeHostTest :app:testDebugUnitTest :app:assembleDebug :tracer:assembleDebug :tracer:copyTracerDebug --no-daemon
git diff --check
```

Expected: the Python suite ends with `OK`; Gradle ends with `BUILD SUCCESSFUL` and native host tests report 45/45; `git diff --check` prints nothing.

- [ ] **Step 4: Verify manual-only CI and generic-scope isolation**

Run:

```bash
git diff --name-only HEAD~3
env -u PYTHONPATH python3 scripts/qtrace_device_acceptance.py --help
env -u PYTHONPATH python3 -m scripts.qtrace_device_acceptance --help
```

Expected: the changed implementation paths are exactly the files listed in this plan; neither command starts ADB and both help outputs require `--device`. Inspect `.github/workflows/ci.yml` and confirm it contains no invocation of `qtrace_device_acceptance.py`. Confirm the diff has no changes beneath `qtrace/`, no Task 7 adapter change, and no fixture branch in a generic external-package path.

- [ ] **Step 5: Run the physical Pixel 6 gate**

With Pixel 6 `192.168.50.149:5555` online, rooted, arm64-v8a, paired with matching Frida host/server, NDK 26.1.10909125, build-tools 35.0.0, and host `lz4`, run:

```bash
python3 scripts/qtrace_device_acceptance.py --device 192.168.50.149:5555
```

Expected: exit 0. The historical phase reports the installed whole-APK SHA, raw target SHA, canonical target SHA `0d8e856c819fb3cd7ae5917053172b4b75a7924784c43e09cb2855a298647169`, passes the existing warmup oracle and exactly five fast measured runs, then the current phase passes timed offset/symbol normalization, distinct exit/crash classification, and all four pull modes. If the device or a pinned dependency is unavailable, report this step as `pending`; do not reinterpret it as a pass or weaken the gate.

- [ ] **Step 6: Commit documentation after the complete gate**

```bash
git add README.md
git commit -m "docs: explain historical benchmark gate"
```

Before handoff, run `git status --short`; expected output is empty. Report all four commit hashes and the retained evidence path from the successful Pixel run.
