# Tracer collector and Flight capacity evidence — 2026-10-19

CORE-01 now avoids rebuilding an immutable fallback instruction on every Full
callback. CORE-02 checks available storage before sizing or mapping a Flight
artifact. The 512 MiB default, fixed ring, memory reads, compression settings,
wire formats, and historical reference files retain their existing semantics.

Machine-readable results and source/evidence hashes are in
[the report](qtrace-native-optimization-2026-10-19.json). Raw files below live in
[`artifacts/complete-optimization-2026-10-19/native/`](../../artifacts/complete-optimization-2026-10-19/native/).

## Fixed identities and admission

The device is Pixel 6 `1C111FDF600G6S`, build
`google/oriole/oriole:16/CP1A.260405.005/15001963:user/release-keys`.
The initially installed demo package was absent. Before editing native code,
the current stripped/unstripped tracer, companion, and local APK were copied to
`before-*` files; `initial-identities.json` records their hashes.

The existing `historical_benchmark` builder rebuilt the fixed demo APK using NDK
26.1.10909125. Its archive manifest and build output are retained. Both measured
batches use the exact installed APK
`13366b591c368f2c328bde5dac7447df36c7688c4e59286605afc1666947594e`, raw target
`b4dcaa6a9d317d84f30765dcb7bd3cce28f92ee4eea888c2f5afbc126af67c85`, and
canonical target
`0d8e856c819fb3cd7ae5917053172b4b75a7924784c43e09cb2855a298647169`.
The canonical identity matches the immutable historical reference. No tracked
historical benchmark was rewritten.

The before tracer SHA-256 is
`7101529d8940daa2f614b27c705ef79929d537cdcbc2593eeb201970c691bd86`.
The final tracer is
`b06bd71aa8d60906b0f3a618328cd6f2b38b6d71f81d2d7411aff1a83cf9a358`;
`after-identities.json` also records its unstripped ELF and sources. The final
binary includes the separately verified JSON endpoint extraction. Consequently,
the elapsed-time batch difference is not an isolated measurement of the one-line
collector change.

## Sampling and the selected change

The device's `/system/bin/simpleperf` reports version `1.build15001963`.
Sampling uses CPU cycles in userspace, 4 kHz and DWARF call graphs:

```sh
adb -s 1C111FDF600G6S shell su -c '/system/bin/simpleperf record -a --exclude-perf -e cpu-cycles:u -f 4000 --call-graph dwarf,8192 --duration 20 -o /data/local/tmp/qtrace-core-repeated.data'
```

The first Full five-round benchmark was profiled for 30 seconds: 101,139 samples,
zero lost. To obtain more samples of the short native trace, a diagnostic agent
then made 50 identical calls per profile; every call checked the deterministic
return value. Each 20-second recording lost zero samples: Fast 30,901, Balanced
31,588, Full 40,499. Profiling runs are separate from timing admission.

`simpleperf_report_lib` resolves the exact before ELF Build ID through
`before-symfs`. `summarize_profile.py` assigns each sampled period once to its
nearest recognized frame in the fixed tracer DSO. The denominator comprises only
recognized collector, encoder, output and compression frames; it is not all
process CPU or wall time. Raw `.data`, inclusive reports and unwind warnings are
retained. Inclusive tool percentages are not used as mutually exclusive totals.

| Profile | Collector | Encoder | Output | Compression |
| --- | ---: | ---: | ---: | ---: |
| Fast | 27.58% | 19.84% | 7.64% | 44.94% |
| Balanced | 34.73% | 14.98% | 7.14% | 43.14% |
| Full | 58.33% | 7.16% | 3.44% | 31.07% |

Full's collector has the largest classified share. Its top leaf is
`process_vm_readv`; those required memory reads are preserved. Within that same
collector path, disassembly showed that the fallback `CachedInstruction empty{}`
was constructed even when the cache supplied a decoded instruction. Changing it
to `static constexpr` preserves every default field and makes the same immutable
fallback available without repeated construction.

`collector-assembly-proof.json` and the before/after `on_pre` assembly show that
the stack temporary area decreases from `0x780` to `0x1d0` bytes and the Full
callback's `memset(..., 0x524)` disappears. Pending instruction ordering, rule
actions, register snapshots, safe memory reads and compression are unchanged.
This is a bounded mechanism improvement; the sample does not suggest that this
small initialization was the whole collector cost.

## Five-round result and fact preservation

Each profile has one warmup and five unprofiled measured runs. Both batches use
the existing benchmark's identity admission, decoder, footer/sidecar checks,
instruction/return oracle and historical compressed-size/rate gates. Commands
are recorded in `before-batch-commands.json` and `after-batch-commands.json`.

| Profile | Before ms | After ms | Median before → after | Maximum compressed bytes before → after | Historical size ceiling |
| --- | --- | --- | ---: | ---: | ---: |
| Fast | 13, 13, 13, 18, 13 | 20, 12, 12, 13, 13 | 13 → 13 | 267,182 → 267,171 | 307,925 |
| Balanced | 15, 22, 18, 16, 17 | 16, 16, 15, 16, 16 | 17 → 16 | 360,680 → 362,198 | 365,877 |
| Full | 26, 31, 28, 32, 33 | 26, 26, 25, 25, 26 | 31 → 26 | 378,790 → 379,717 | 429,199 |

All thirty measured traces contain 21,718 instructions and return
`0x5745c858653f5a7f`. Each profile's median meets its historical rate target
(1,000,000 / 800,000 / 500,000 instructions per second); each individual artifact
passes its compressed-size ceiling. A single five-round batch and integer-ms
timing do not establish a stable percentage gain.

`benchmark-facts.json` additionally compares the complete per-profile instruction
sequence, opcode, assembly with in-module addresses rebased, register names and
widths, memory operand metadata, memory event order, kind, flags, sizes and byte
capture lengths. All ten before/after measured traces per profile have the same
structural hash. Every run retains 25,960 register-read and 15,689 register-write
facts. Balanced and Full retain 5,910 memory reads and 3,857 writes. Full retains
75,320 before bytes and 30,856 after bytes; all 9,767 complete memory values agree
with their captured read-before/write-after bytes. Balanced keeps its existing
`<not-captured>` byte policy.

Absolute register, heap and stack values vary between processes and are not
equated across runs. Exact value behavior is also checked by the existing native
collector, decoder and memory-profile tests in the complete native suite.

## Actual Flight capacity and retained windows

The inventory reads thirteen existing real artifacts without writing or deleting
them: both successful acceptance runs, six retained failed acceptance runs, the
current Xiaomi capture, and five earlier 512 MiB acceptance artifacts. The raw
superblock/chunk header inventory is `flight-capacity-inventory.json`;
`flight_capacity_windows.py` and `flight-capacity-window-summary.json` add
allocated bytes and per-thread retained endpoints.

| Observed capacity | Sessions | Allocated bytes | Sealed committed content / capacity | Sealed physical records | Largest chunk generation |
| --- | ---: | ---: | ---: | ---: | ---: |
| 64 MiB | 8 | 67,108,864–67,112,960 | 81.04–86.63% | 824,299–886,049 | 40–49 |
| 512 MiB | 5 | 536,875,008 | 97.97–98.13% | 7,798,375–7,851,901 | 5 |

These are lower bounds from sealed chunk headers: active chunks can contain
additional committed records. They are physical wire records, not UI event
counts. The rings have already wrapped. Per-thread first/last sequence endpoints
can span overwritten gaps; they do not describe a continuous history interval.
Reading headers is an occupancy survey, not a replacement for payload integrity
recovery. Existing failed evidence remains failed evidence.

Flight has no per-event monotonic timestamp, so a retained duration in seconds
cannot be reconstructed honestly. The Xiaomi report's monitoring-to-pull
envelope is 12.303376 seconds; polling and scheduling are included, and this is
not a retained-history duration. The inventory records this limitation explicitly.

The sessions show substantial retained content and repeated overwrites at both
capacities. Different devices and workloads do not establish a controlled
64-versus-512 MiB experiment, but they provide no basis for reducing the default.
The existing JSON `capacityMb` range, 64–2048, already supports deliberate
workload-specific choices. Keep 512 MiB and fixed-ring behavior; no named preset
is added without a caller's minimum history-window requirement and a measured
workload rate. The default remains 256 KiB chunks, 256 thread slots and four
protected chunks.

## Startup space check and recovery proof

After exclusive creation, `FlightArtifact::create` now calls `fstatvfs` on that
same descriptor before `fchmod`, `ftruncate` or shared mapping. It compares
`ceil(capacity_bytes / fragment_bytes)` against `f_bavail`, using `f_bsize` if
`f_frsize` is zero. Comparing block counts avoids overflowing a filesystem byte
counter. A failed check or insufficient space preserves the error, closes the
descriptor and unlinks the new zero-length file before publishing any superblock.

The syscall wrapper tests use temporary directories and inject one block short,
`EIO`, non-aligned sizes, exact sufficient capacity, huge counters and invalid
fragment sizes. They assert no sizing/mapping, an actually closed descriptor,
invalid recorder state and no file on failure. The new test against the previous
production implementation fails at `!created` (exit 134, `host-space-red.log`);
the implementation passes the same target and the complete suite. No real
device was filled to provoke low storage.

`flight_lifecycle_probe.cpp` compiles the current production artifact, writer and
encoder. Both outputs use default 512 MiB capacity. One child calls `_exit`
after committing its events, without sealing, detaching, closing or running
destructors; the normal writer seals and closes. The unchanged Python decoder
recovers all eighteen wire records/eight logical events and the same final
registers from both. The unsealed artifact has an active chunk and truthful
unknown termination attribution. `flight-lifecycle-recovery.json` preserves the
full results. This proves host lifecycle recovery, not Android crash timing or
power-loss durability.

The space check is an availability preflight. It cannot reserve space against
later writers or quota changes, so existing runtime failure handling remains
necessary.

## Environment and final verification

The existing Xiaomi venv provides Frida 17.24.2. Compatible frida-tools 14.11.0
was added with Frida pinned. A task-owned 17.24.2 server runs on Pixel port 27043.
The raw sequential transport probe accepts scripts through 65,536 bytes and
disconnects at 131,072/262,144 bytes; the Java bridge plus benchmark agent exceeds
that limit. Failed probes and preflight attempts are retained.

For this device diagnosis, `benchmark_chunked.py` loads the identical full source
into one small bootstrap script through bounded 4,096-character posts. It keeps
the existing benchmark worker ownership, deadlines, native timing, admission and
artifact validation. Source loading precedes native measurement. This adapter
is retained as evidence; production CLI and benchmark interfaces are unchanged.

The final CI command passed:

```sh
ANDROID_HOME=/home/lyldalek/Android/sdk \
ANDROID_NDK_HOME=/home/lyldalek/Android/sdk/ndk/26.1.10909125 \
./gradlew nativeHostTest :app:testDebugUnitTest :app:assembleDebug \
  :tracer:assembleDebug :tracer:copyTracerDebug --no-daemon
```

`gradle-final-integration-retry.log` records all 45 native tests and successful
app/tracer tasks, exit 0, 27 seconds. The initial integration failure is preserved:
the endpoint extraction moved a source-contract boundary; its owner updated the
marker and retained lifecycle-order assertions before this successful retry.
The native candidate hash is unchanged by the retry. `git diff --check` passes
for these changes. Complete Python discovery is recorded by the coordinating
agent separately.

The installed fixed benchmark APK, staged final tracer, task-owned Frida service
and port forward remain available for inspection. Existing evidence was not
deleted; initial and final identities are recorded in the JSON report.
