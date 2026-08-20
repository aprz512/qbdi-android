# Binary trace baseline

This is the immutable device baseline for the format-2 text trace writer before
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

## Accepted QTRB v1 results

The post-migration candidate used the same device, Android build, Debug app, benchmark scene,
256-iteration workload, one unreported warmup, and five fresh measured processes per profile. The
exact staged tracer was an ELF64 AArch64 shared object with SHA-256
`413eb36c87b9ea1212403b1e8139cd8335898f8407feb7f006c48e46d6437b7f`; the app-private copy had
mode `0700`, SELinux label `u:object_r:app_data_file:s0:c137,c259,c512,c768`, and the device stayed
Enforcing. Host conversion used LZ4 1.10.0. Default device compression was `lz4_level=2`.

| Profile | Elapsed ms (five measured) | Median elapsed ms | Median instructions/s | Encoded bytes | Median compressed bytes | Maximum compressed bytes | Format-2 limit | Median ratio | Cache hits/misses/collisions | Swaps | Producer waits | Median wait ns | Converted text bytes | Rate gate | Every-size gate |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | --- | --- |
| fast | 16, 16, 27, 24, 16 | 16 | 1357375.000000 | 1096964 | 267939 | 267950 | 307925 | 0.244255 | 21608/110/0 | 2 | 1 | 16681031 | 6299339 | PASS (>=1000000) | PASS |
| balanced | 28, 22, 25, 20, 24 | 24 | 904916.666666 | 1566635 | 362559 | 362743 | 365877 | 0.231425 | 21608/110/0 | 2 | 1 | 25361979 | 9415990 | PASS (>=800000) | PASS |
| full | 36, 34, 36, 33, 38 | 36 | 603277.777777 | 1672811 | 379982 | 380039 | 429199 | 0.227151 | 21608/110/0 | 2 | 1 | 24835897 | 9437602 | PASS (>=500000) | PASS |

Every measured artifact had `metrics_version=2`, 21,718 instructions, return
`0x5745c858653f5a7f`, no crash marker, a continuous format-3 `INST seq=1..21718`, and exact
TRACE_END/artifact/sidecar agreement. Each converted successfully. Representative median-elapsed
artifacts were:

| Profile | Artifact | Elapsed ms | Compressed bytes | Converted bytes | SHA-256 |
| --- | --- | ---: | ---: | ---: | --- |
| fast | `1787240911587_31370_31385_benchmark_0x6e828_0.trace.bin.lz4` | 16 | 267939 | 6299333 | `d2ad17becb1005185ee74d34422861c279865769d79393ab8e883e5fea8f2efb` |
| balanced | `1787240898809_31240_31253_benchmark_0x6e828_0.trace.bin.lz4` | 24 | 362559 | 9415990 | `b4f3f1c364231bec6814fccb00c6e6d1e4aee116d94d4ca027aa24fbb938565c` |
| full | `1787240933975_31824_31841_benchmark_0x6e828_0.trace.bin.lz4` | 36 | 379822 | 9437592 | `5cd887c3ab31353e1da5c8a4947b2db349dc3063b57d922a1e043c177917504a` |

### Compression-level diagnosis

The first QTRB candidate at LZ4 level 0 passed all three rate gates and the fast/full size gates,
but balanced measured 376636–377939 bytes against the 365877-byte limit. Recompressing the same
1,566,635-byte decoded balanced stream isolated compression level as the variable: level 1 was
376277 bytes, level 2 was 362107 bytes, and level 3 was 239929 bytes. Level 2 is the smallest fast
compressor setting that cleared the gate; the device A/B above confirmed all five balanced
artifacts at 362469–362743 bytes while retaining a 904916.666666 instructions/s median.

### Large-workload and failure evidence

The historical large workload of 8,192 iterations completed with 692,922 ordered instructions,
stable return `0x8f62a472c26c47a9`, 49,587,347 encoded bytes, 11,720,892 compressed bytes, and a complete
302,351,832-byte conversion. Repeating it with the Debug-only 4096-byte buffer forced 13,937
buffer swaps; one observed artifact grew during execution through 13,538,896, 15,838,526,
17,871,773, 19,855,711, and 19,945,382 bytes. The measured run completed and converted all 692,922
instructions with 49,587,347 encoded bytes and 19,946,321 compressed bytes.

The controlled setup-failure smoke published no trace artifacts and returned the independently
calculated native 256-iteration result `0x20a128f3d199a008`. This differs from the stable historical
QBDI-path oracle above; the migration preserved the existing QBDI result and did not introduce that
pre-existing execution-semantic difference. Crash-partial, corrupt-frame rejection, 4 KiB record
ordering, and atomic publication are covered by the final native/Python matrices.
