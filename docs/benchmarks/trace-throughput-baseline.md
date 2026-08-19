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
| 2 | 1886 | 21718 | 2358988 | 11515.38 | 1.19286 |
| 3 | 1978 | 21718 | 2358988 | 10979.78 | 1.13740 |
| 4 | 2226 | 21718 | 2358988 | 9756.51 | 1.01104 |
| 5 | 1931 | 21718 | 2358988 | 11246.50 | 1.16500 |
| Median | 1937 | 21718 | 2358988 | 11212.18 | 1.16144 |
