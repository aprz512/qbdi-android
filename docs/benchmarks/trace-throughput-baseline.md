# Trace Throughput Baseline and Acceptance

Task 9 uses two deliberately different comparisons. The acceptance comparison measures the
actual shipped Debug-policy upgrade. A compiler-normalized legacy build is only a diagnostic and
does not replace that acceptance result.

## A. End-to-end acceptance comparison

Both sides used the same Pixel 6 (`oriole`), Android 16, `arm64-v8a`, Debug app, benchmark
workload (256 iterations), app-private application-namespace loader, and one unreported warmup
followed by five fresh-process measured runs. Every accepted call returned
`0x5745c858653f5a7f`.

| Field | Value |
| --- | --- |
| Device model | Pixel 6 (`oriole`) |
| Android version | 16 |
| ABI | `arm64-v8a` |
| Build type | Debug |
| Benchmark iteration count | 256 |

The legacy side was `f0a30197a13a7824b851e6b89a87b8cecfde7786` with its historical default
Debug compile policy (no optimization flag, effectively O0). This is the relevant baseline
because making the injected Debug tracer use `-O2 -g` is itself part of the Task 9 production
optimization.

| Legacy run | Elapsed ms | Instructions | Raw bytes | Instructions/s | Raw MiB/s |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 252 | 21718 | 2513209 | 86182.54 | 9.51104 |
| 2 | 226 | 21718 | 2513209 | 96097.35 | 10.60523 |
| 3 | 182 | 21718 | 2513209 | 119329.67 | 13.16914 |
| 4 | 201 | 21718 | 2513209 | 108049.75 | 11.92429 |
| 5 | 261 | 21718 | 2513209 | 83210.73 | 9.18308 |
| Median | 226 | 21718 | 2513209 | 96097.35 | 10.60523 |

The current source was based on `2ae81d7` plus the uncommitted Task 9 production changes. Its
actual Debug tracer ended with `-O2 -g` and did not define `NDEBUG`. The unstripped linked Debug
ELF retained `.debug_info`, `.debug_line`, and `.debug_str`; Android's copy task intentionally
stripped those sections from the smaller deployed app-private artifact. The measured deployed
artifact had SHA-256 `6e55e4410bcd49249908dc6c4f00cad60b07300eaabec827b2110d0cce33bb5a`;
the unstripped linked ELF had SHA-256
`db6e63e73b29809688991509652a84f25b465985d65c6fb8a255c9d768d5249a`. The deployed copy
ran under SELinux Enforcing.

| Current measured run | Fast elapsed ms | Balanced elapsed ms |
| --- | ---: | ---: |
| 1 | 27 | 33 |
| 2 | 25 | 30 |
| 3 | 26 | 30 |
| 4 | 25 | 46 |
| 5 | 32 | 39 |

| Current median field | Fast | Balanced |
| --- | ---: | ---: |
| profile | fast | balanced |
| instructions | 21718 | 21718 |
| elapsed_ms | 26 | 33 |
| instructions_per_second | 835307.692307 | 658121.212121 |
| raw_bytes | 2079102 | 2739513 |
| compressed_bytes | 306624 | 365104 |
| raw_bytes_per_second | 79965461.538461 | 83015545.454545 |
| disk_bytes_per_second | 11797192.307692 | 11063757.575757 |
| compression_ratio | 0.147479 | 0.133273 |
| cache_hits | 21558 | 21558 |
| cache_misses | 160 | 160 |
| cache_collisions | 0 | 0 |
| cache_hit_rate | 0.992632 | 0.992632 |
| buffer_swaps | 1 | 1 |
| producer_waits | 0 | 0 |
| producer_wait_ns | 0 | 0 |
| effective_buffer_bytes | 67108864 | 67108864 |

Balanced speedup is `226 / 33 = 6.848485x`, which exceeds the required 5x. Fast reaches
835,307.692307 instructions/s, below the aspirational 1,000,000 instructions/s target. O2
single-variable probes localized the remaining time to collector plus formatter/output work:
resolver/cache-only was 14 ms, collector counters-only was 24 ms, format-only was 27 ms, a fixed
writer was 20 ms, and normal fast was 33 ms in that diagnostic series. Producer waits were zero.
Because an experimental single-pass encoder had no reproducible device benefit, it was removed;
the result does not justify a higher-risk format rewrite in Task 9.

The exact balanced artifact
`1787203900199_32254_32267_benchmark_0x6e828_0.trace.txt.lz4` was pulled with its adjacent
sidecar and classified `complete`. An in-memory LZ4-frame decode produced 2,739,513 bytes,
started with `TRACE_BEGIN format=2`, and contained the continuous instruction sequence 1 through
21,718 before ending with:

```text
TRACE_END status=ok ret=0x5745c858653f5a7f elapsed_ms=33 instructions=21718 raw_bytes=2739513 cache_hit_rate=0.992632 buffer_swaps=1 producer_waits=0 producer_wait_ns=0
```

## B. Compiler-normalized legacy diagnostic

A separate `f0a3019` Debug tracer was built with final `-O2 -g`, no `NDEBUG`, and ELF debug
sections. Its local and deployed SHA-256 was
`38e479599ea0c92ad73e5ec35b07ba7f95fff94274caca622f5283cb85655e41`.

It could not produce a valid warmup, so no normalized throughput number is reported. The trace
file remained zero bytes. Logs showed the old `qbdi_tracer_configure()` detached installer and
the benchmark's explicit install hook the same address twice within 8 ms, changing the original
trampoline from `...1000` to `...1040`; Android then aborted the process after a main-thread
suspend timeout. This reproduces the old generation-lifecycle race fixed by the current
idempotent same-generation install policy. The failed diagnostic is not substituted into the
acceptance comparison.

## Runtime and commands

Final runs used the app-private `files/libqbdi_tracer.so`, loaded through
`Runtime.load0(application.getClass(), path)`, so the tracer shares the application's native
loader namespace and retains the target module. SELinux remained Enforcing throughout the final
measurement, legacy-O2 diagnostic, and restoration checks. An earlier loader-discovery session
temporarily used Permissive to prove that an external `shell_data_file` was the problem; it was
restored before these final runs.

```text
adb push out/arm64-v8a/libqbdi_tracer.so /data/local/tmp/qbdi-tracer-stage.so
adb shell run-as com.aprz.qbdiandroid cp /data/local/tmp/qbdi-tracer-stage.so files/libqbdi_tracer.so
adb shell run-as com.aprz.qbdiandroid chmod 700 files/libqbdi_tracer.so
python3 scripts/benchmark_trace.py --package com.aprz.qbdiandroid --device 192.168.51.42:5555 --profile fast --runs 5
python3 scripts/benchmark_trace.py --package com.aprz.qbdiandroid --device 192.168.51.42:5555 --profile balanced --runs 5 --compare docs/benchmarks/trace-throughput-baseline.md
```

## Historical sailfish baseline (context only)

The 2026-08-19 Pixel (`sailfish`), Android 10, Debug result is retained for context only and is
not used for Task 9's same-device acceptance calculation.

| Run | Elapsed ms | Instructions | Raw bytes | Instructions/s | Raw MiB/s |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 1937 | 21718 | 2358988 | 11212.18 | 1.16144 |
| 2 | 1886 | 21718 | 2358988 | 11515.38 | 1.19285 |
| 3 | 1978 | 21718 | 2358988 | 10979.78 | 1.13736 |
| 4 | 2226 | 21718 | 2358988 | 9756.51 | 1.01065 |
| 5 | 1931 | 21718 | 2358988 | 11247.02 | 1.16505 |
| Median | 1937 | 21718 | 2358988 | 11212.18 | 1.16144 |
