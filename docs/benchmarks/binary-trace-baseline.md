# Binary trace baseline

This is the immutable device baseline for the format-2 binary trace writer before
the binary-format migration. Each profile uses one warmup followed by five fresh
processes; the artifact named in the table is the run at the median elapsed time.

## Device and build identity

| Field | Value |
| --- | --- |
| Device model | Pixel 6 |
| Device product | oriole |
| Android version | 16 |
| ABI | arm64-v8a |
| Android build type | user |
| App build type | Debug |
| Build fingerprint | google/oriole/oriole:16/CP1A.260405.005/15001963:user/release-keys |
| SELinux | Enforcing |
| Package | com.aprz.qbdiandroid |
| Tracer library SHA-256 | cc8c3509f81647e3d6bced804fcfc58dd983c32a2d577ce03f004ad5d14dece1 |

## Current format-2 artifact baselines

| Profile | Measured elapsed values (ms) | Median elapsed ms | Artifact | Compressed bytes | Decoded bytes | Instructions | Return | Decoded event count | First sequence | Last sequence | Footer | Artifact SHA-256 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| fast | 32, 25, 25, 27, 30 | 27 | 1787226448472_19456_19490_benchmark_0x6e828_0.trace.txt.lz4 | 307925 | 2091528 | 21718 | 0x5745c858653f5a7f | 21718 | 1 libdemo_target.so+0x6e828 STPXpre | 21718 libdemo_target.so+0x6ea28 RET | TRACE_END status=ok ret=0x5745c858653f5a7f elapsed_ms=27 instructions=21718 raw_bytes=2091528 cache_hit_rate=0.994935 buffer_swaps=1 producer_waits=0 producer_wait_ns=0 | a5d810cc779247a635fca7527583e4f245c3b6b69a5b65bdc5efb75a33280cc4 |
| balanced | 30, 35, 33, 36, 39 | 35 | 1787226459870_19752_19765_benchmark_0x6e828_0.trace.txt.lz4 | 365877 | 2751945 | 21718 | 0x5745c858653f5a7f | 21718 | 1 libdemo_target.so+0x6e828 STPXpre | 21718 libdemo_target.so+0x6ea28 RET | TRACE_END status=ok ret=0x5745c858653f5a7f elapsed_ms=35 instructions=21718 raw_bytes=2751945 cache_hit_rate=0.994935 buffer_swaps=1 producer_waits=0 producer_wait_ns=0 | 4c42382457952c2325a9b9a53f7af00e1bc72c1ef83638f548b1e984231feb87 |
| full | 53, 47, 43, 62, 68 | 53 | 1787226480609_20092_20105_benchmark_0x6e828_0.trace.txt.lz4 | 429199 | 3036250 | 21718 | 0x5745c858653f5a7f | 21718 | 1 libdemo_target.so+0x6e828 STPXpre | 21718 libdemo_target.so+0x6ea28 RET | TRACE_END status=ok ret=0x5745c858653f5a7f elapsed_ms=53 instructions=21718 raw_bytes=3036250 cache_hit_rate=0.994935 buffer_swaps=1 producer_waits=0 producer_wait_ns=0 | 712c910f4fab7109873718ddc14c298e7b14533de9778553bad2c2f0aa1dbe20 |

The decoded event count and the first and last sequence entries are the semantic
oracle. The footer is retained verbatim from the decoded median artifact.
