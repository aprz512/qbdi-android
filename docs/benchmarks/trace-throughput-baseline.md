# Legacy Trace Throughput Baseline

This baseline is captured with `python3 scripts/benchmark_trace.py --package com.aprz.qbdiandroid --runs 5 --legacy`.

## Capture status

Captured successfully on 2026-08-19 with one warmup followed by five fresh-process measured
runs. All six calls returned the stable value `0x5745c858653f5a7f`.

## Intended capture configuration

| Field | Value |
| --- | --- |
| Device model | Pixel (`sailfish`) |
| Android version | 10 |
| ABI | `arm64-v8a` |
| Build type | Debug |
| Benchmark iteration count | 256 |
| Command | `python3 scripts/benchmark_trace.py --package com.aprz.qbdiandroid --runs 5 --legacy` |

## Results

| Run | Elapsed ms | Instructions | Raw bytes | Instructions/s | Raw MiB/s |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 1937 | 21718 | 2358988 | 11212.18 | 1.16144 |
| 2 | 1886 | 21718 | 2358988 | 11515.38 | 1.19285 |
| 3 | 1978 | 21718 | 2358988 | 10979.78 | 1.13736 |
| 4 | 2226 | 21718 | 2358988 | 9756.51 | 1.01065 |
| 5 | 1931 | 21718 | 2358988 | 11247.02 | 1.16505 |
| Median | 1937 | 21718 | 2358988 | 11212.18 | 1.16144 |

## Optimized comparison status

The host-side final benchmark runner and metrics sidecar are ready for the required optimized
comparison. On 2026-08-20, the reference endpoint was retried with
`adb connect 192.168.50.53:5555`; it returned `Connection refused`, and `adb devices -l` listed no
devices. No optimized runtime measurements or speedup claim have therefore been recorded.

When the same Pixel is reachable, the pending capture commands are:

```text
python3 scripts/benchmark_trace.py --package com.aprz.qbdiandroid --profile fast --runs 5
python3 scripts/benchmark_trace.py --package com.aprz.qbdiandroid --profile balanced --runs 5 --compare docs/benchmarks/trace-throughput-baseline.md
```

Each command performs one unreported warmup followed by five fresh-process measured runs. The
runner accepts only newly created, paired `.trace.txt.lz4` and `.metrics` artifacts and rejects
profile or target-return mismatches.
