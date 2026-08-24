# ShadowHook Pre-Constructor Offset Hook Simplification Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Install configured offset hooks synchronously from ShadowHook's loader callback before target constructors, without retaining or reopening the target module.

**Architecture:** ShadowHook's dl-init pre callback is the sole constructor-time adapter. It derives the exact module span from the callback's `dlpi_addr` and `PT_LOAD` headers, installs every configured `base + offset` gateway before returning, and relies on the loader's existing ownership of the mapping. A dl-fini post callback retires the matching generation and marks an active flight artifact incomplete before the mapping disappears; there is no retention worker, lease state machine, `RTLD_NOLOAD`, symbol probe, or transient retention flag.

**Tech Stack:** C++20, Android NDK `dl_phdr_info`, bundled ShadowHook, CMake/CTest, Python contract tests, Gradle Android builds, Pixel 6 device acceptance.

## Global Constraints

- Keep the external `target_so` plus scene `offset`/`end_offset` configuration interface unchanged; do not add a symbol-name configuration path.
- Constructor-time hook installation must finish synchronously inside the ShadowHook dl-init pre callback, before the real `soinfo::call_constructors` runs.
- Compute module bounds and executable ranges from the callback's `PT_LOAD` headers; do not use `/proc/self/maps` to normalize this loading generation.
- A constructor-time process termination is complete: there is no pending-retention incomplete reason.
- A matching dl-fini event must retire that exact base/path generation and fail closed with `CoverageGapReason::ModuleGeneration` if its flight artifact is still active.
- Delete `ModuleGenerationRetainer`, leases, worker/retry logic, target `dlopen`/`RTLD_NOLOAD`, handle-binding probes, and `RetentionPending` state/flags/tests.
- Preserve the ShadowHook calibration companion behavior from commit `9dcbae1984aff3ec92f3edcde498c18d3868ceb6`; the helper remains available-but-unloaded and is configured before tracer configuration.
- Preserve the existing offset proxy, thread-create gateway, signal broker, fork lifecycle, and retained-original behavior that is independent of module retention.
- Preserve all uncommitted Task 11 fixture, runner, and artifact files; do not stage or rewrite them.

---

### Task 1: Replace module retention with the pre-constructor adapter

**Files:**
- Modify: `tracer/src/main/cpp/core/module_maps.h`
- Modify: `tracer/src/main/cpp/core/module_maps.cpp`
- Modify: `tracer/src/main/cpp/hooks/inline_hook_adapter.h`
- Modify: `tracer/src/main/cpp/hooks/inline_hook_adapter.cpp`
- Modify: `tracer/src/main/cpp/tracer_entry.cpp`
- Modify: `tracer/src/main/cpp/core/capture_coordinator.h`
- Modify: `tracer/src/main/cpp/core/capture_coordinator.cpp`
- Modify: `tracer/src/main/cpp/flight/flight_artifact.h`
- Modify: `tracer/src/main/cpp/flight/flight_artifact.cpp`
- Modify: `tracer/src/main/cpp/flight/flight_atomic_u32.h`
- Modify: `tracer/src/main/cpp/CMakeLists.txt`
- Modify: `tracer/src/test/cpp/CMakeLists.txt`
- Modify: `tracer/src/test/cpp/tracer_entry_proxy_test.cpp`
- Modify: `tracer/src/test/cpp/shadowhook_retention_contract_test.cpp`
- Modify: `tracer/src/test/cpp/flight_artifact_test.cpp`
- Modify: `scripts/tests/test_shadowhook_companion.py`
- Test: `scripts/tests/test_flight_acceptance.py`
- Delete: `tracer/src/main/cpp/core/module_generation_retainer.h`
- Delete: `tracer/src/main/cpp/core/module_generation_retainer.cpp`
- Delete: `tracer/src/test/cpp/module_generation_retainer_test.cpp`

**Interfaces:**
- Consumes: ShadowHook `shadowhook_register_dl_init_callback(pre, nullptr, opaque)` and `shadowhook_register_dl_fini_callback(nullptr, post, opaque)`; existing `TraceConfig` scene offsets and `install_hooks_for_module` behavior.
- Produces: `bool module_range_from_phdr(const dl_phdr_info &info, ModuleRange *out) noexcept`; `bool register_inline_hook_dl_fini_callback(InlineHookDlInitCallback pre, InlineHookDlInitCallback post, void *opaque)`; a pre callback that installs the callback generation synchronously; a fini callback that retires the exact generation and records a module-generation gap.

- [ ] **Step 1: Write the failing range and lifecycle tests**

  Add host tests using a fake `dl_phdr_info` whose later `PT_LOAD` segments have non-zero `p_vaddr - p_offset`. Assert `module_range_from_phdr()` returns `start == dlpi_addr`, `end == dlpi_addr + page_aligned(max(p_vaddr + p_memsz))`, preserves the full path, and records executable ranges from `PF_X` loads. Add overflow, missing-load, and executable-range-capacity rejection cases. Add a proxy lifecycle test that installs a loading generation, invokes the production fini test seam with the same base/path, and asserts the generation is retired plus the active coordinator receives `CoverageGapReason::ModuleGeneration`; a different base/path must not retire it.

- [ ] **Step 2: Write the failing source and artifact contract tests**

  Change `shadowhook_retention_contract_test.cpp` to assert that the production pre callback derives the range from `dl_phdr_info` and synchronously reaches hook installation, that dl-init registration has no post callback, and that a dl-fini post callback is registered. Assert the production source and build contain none of `ModuleGenerationRetainer`, `ModuleRetentionLease`, `RTLD_NOLOAD`, `select_module_handle_probe`, `RetentionPending`, `begin_loading`, or `retain_postloaded`. Replace the artifact test that sets/clears `RetentionPending` with an assertion that constructor-time loading has no transient incomplete state. Extend the companion contract to reject target/helper preloading and to require tracer load, helper-path setter, then configure order while permitting the native pre adapter. Assert no production or test source references `retention_flags_address` or `flight_atomic_fetch_and_u32`.

- [ ] **Step 3: Run RED**

  Run:

  ```bash
  python3 -m unittest scripts.tests.test_shadowhook_companion scripts.tests.test_flight_acceptance -v
  /home/lyldalek/Android/sdk/cmake/3.22.1/bin/cmake --build build/flight-recorder-host-make -j2
  /home/lyldalek/Android/sdk/cmake/3.22.1/bin/ctest --test-dir build/flight-recorder-host-make --output-on-failure -R 'flight_artifact|tracer_entry_proxy|module_maps|shadowhook_retention_contract'
  ```

  Expected: compilation or assertions fail because `module_range_from_phdr`, fini registration/retirement, and the simplified source/artifact contracts do not exist while retention symbols and transient state still exist.

- [ ] **Step 4: Implement the minimum GREEN path**

  Implement `module_range_from_phdr()` with checked arithmetic and page alignment. Replace the retention callback setup with one dl-init pre callback and one dl-fini post callback. The pre callback path-matches the configured target, derives the callback generation from phdrs, and calls `install_hooks_for_module(module, current_generation, true)` before returning. The fini callback matches exact base/path, retires matching installed scene generations under the existing lock order, and marks `CoverageGapReason::ModuleGeneration` on their active coordinator. Remove all retainer types, target reopen/probe code, worker/fork detach paths, lease parameters/state checks, and their CMake entries. Remove `FlightIncompleteReason::RetentionPending`, `FlightArtifact::clear_incomplete`, `CaptureCoordinator::retention_flags_address`, the unused atomic fetch-and helper, and their tests. Keep permanent gap semantics and the companion setter/init sequence unchanged.

- [ ] **Step 5: Run focused and full GREEN**

  Rebuild and run the same focused Python/CTest commands, then the full host CTest suite, full Python unittest discovery, and:

  ```bash
  ./gradlew :app:assembleDebug :app:assembleRelease :tracer:assembleDebug :tracer:assembleRelease
  ```

  Verify APK/AAR/staged companion presence, tracer has no companion `DT_NEEDED`, and no removed retention symbol appears in the tracer dynamic or static symbol tables.

- [ ] **Step 6: Run bounded Pixel direct acceptance**

  On `192.168.50.149:5555`, use fresh APK/tracer/companion hashes and only seed `101` / `direct_tgkill` with `--artifact-mb 512`. Require ShadowHook init success, pre callback before constructor, 16 workers, at least five rotations, exact target TID/original PC, complete decode, zero gaps/loss/damage, and no guest-visible tracer address. Stop on the first real core RED.

- [ ] **Step 7: Review and commit separately**

  Request an independent read-only review of the simplification. Fix every Critical/Important finding, audit `git diff --check` and staged paths, then commit only the plan plus prerequisite core/test/tooling files as `fix(trace): simplify pre-constructor hooks`. Keep Task 11 fixture, acceptance runner, benchmark report, artifacts, and ignored SDD ledger unstaged.
