# Legacy Trace Throughput Baseline

This baseline is captured with `python3 scripts/benchmark_trace.py --package com.aprz.qbdiandroid --runs 5 --legacy`.

## Capture status

Blocked before capture. The reference device is reachable, but this checkout contains a Git LFS
pointer instead of `libQBDI.a` and the host has neither Git LFS nor the Python `frida` bindings.
Consequently, `:tracer:assembleDebug` cannot link and the benchmark cannot inject the tracer.

## Intended capture configuration

| Field | Value |
| --- | --- |
| Device model | Pixel (`sailfish`) |
| Android version | 10 |
| ABI | `arm64-v8a` |
| Build type | Debug |
| Benchmark iteration count | 8192 |
| Command | `python3 scripts/benchmark_trace.py --package com.aprz.qbdiandroid --runs 5 --legacy` |

## Results

| Run | Elapsed ms | Instructions/s | Raw MiB/s |
| --- | ---: | ---: | ---: |
| 1 | Not captured | Not captured | Not captured |
| 2 | Not captured | Not captured | Not captured |
| 3 | Not captured | Not captured | Not captured |
| 4 | Not captured | Not captured | Not captured |
| 5 | Not captured | Not captured | Not captured |
| Median | Not captured | Not captured | Not captured |
