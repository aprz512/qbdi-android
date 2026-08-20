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
| Candidate tracer SHA-256 | 33083c68ea20082ea91fede32d5302d3677a0abaaa0e4e769a66d7563d50f53d |

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
TRACE_END/artifact/sidecar agreement. Each converted successfully.

### Per-run measured evidence

Run numbers are chronological after excluding the first artifact in each profile as the warmup.
`Conversion=PASS` means the retained artifact converted without error; `Sequence` and
`Footer/sidecar` record the converter's semantic and completion checks. SHA-256 covers the
`.trace.bin.lz4` artifact itself.

| Profile | Run | Artifact | SHA-256 | Elapsed ms | Instructions | Return | Instructions/s | Encoded bytes | Compressed bytes | Ratio | Cache hits | Cache misses | Cache collisions | Buffer swaps | Producer waits | Producer wait ns | Effective buffer bytes | Conversion | Converted bytes | Sequence | Footer/sidecar | Size limit | Size gate |
| --- | ---: | --- | --- | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | --- | --- | ---: | --- |
| fast | 1 | `1787240911587_31370_31385_benchmark_0x6e828_0.trace.bin.lz4` | `d2ad17becb1005185ee74d34422861c279865769d79393ab8e883e5fea8f2efb` | 16 | 21718 | `0x5745c858653f5a7f` | 1357375.000000 | 1096964 | 267939 | 0.244255 | 21608 | 110 | 0 | 2 | 1 | 16681031 | 67108864 | PASS | 6299333 | `1..21718` | PASS | 307925 | PASS |
| fast | 2 | `1787240913061_31433_31446_benchmark_0x6e828_0.trace.bin.lz4` | `adcd80f45c8f4dac7db68ccde66b46f2fafe13a1c8b222856507627b6e7322a6` | 16 | 21718 | `0x5745c858653f5a7f` | 1357375.000000 | 1096964 | 267950 | 0.244265 | 21608 | 110 | 0 | 2 | 1 | 16476807 | 67108864 | PASS | 6299339 | `1..21718` | PASS | 307925 | PASS |
| fast | 3 | `1787240916788_31528_31555_benchmark_0x6e828_0.trace.bin.lz4` | `9a5fa37309eda0b1b5c5d2dfa1884b5464cef33b13d60408fcae1116ac9edabc` | 27 | 21718 | `0x5745c858653f5a7f` | 804370.370370 | 1096964 | 267869 | 0.244191 | 21608 | 110 | 0 | 2 | 1 | 16530111 | 67108864 | PASS | 6299339 | `1..21718` | PASS | 307925 | PASS |
| fast | 4 | `1787240918983_31602_31615_benchmark_0x6e828_0.trace.bin.lz4` | `d943f363bbf93e5c6ca1b57089707a7244545b5246d4677b12da861980daebc5` | 24 | 21718 | `0x5745c858653f5a7f` | 904916.666666 | 1096964 | 267931 | 0.244247 | 21608 | 110 | 0 | 2 | 1 | 22871013 | 67108864 | PASS | 6299339 | `1..21718` | PASS | 307925 | PASS |
| fast | 5 | `1787240920335_31662_31682_benchmark_0x6e828_0.trace.bin.lz4` | `3d4687981491bc67e58e3a61ec43817f75d10a9390bc71eda31580013f40b3e2` | 16 | 21718 | `0x5745c858653f5a7f` | 1357375.000000 | 1096964 | 267943 | 0.244258 | 21608 | 110 | 0 | 2 | 1 | 16991008 | 67108864 | PASS | 6299339 | `1..21718` | PASS | 307925 | PASS |
| balanced | 1 | `1787240887800_31000_31013_benchmark_0x6e828_0.trace.bin.lz4` | `833a16c0bbc5d604e4a69a8d2874a045317174f35a8a99c4c800b6e8b3d37568` | 28 | 21718 | `0x5745c858653f5a7f` | 775642.857142 | 1566635 | 362517 | 0.231398 | 21608 | 110 | 0 | 2 | 1 | 31400716 | 67108864 | PASS | 9415990 | `1..21718` | PASS | 365877 | PASS |
| balanced | 2 | `1787240890209_31060_31073_benchmark_0x6e828_0.trace.bin.lz4` | `7cbdac5dac01d46f526cc03d4445a6ac55194d7bad6ec055126476e0a4fa1086` | 22 | 21718 | `0x5745c858653f5a7f` | 987181.818181 | 1566635 | 362679 | 0.231501 | 21608 | 110 | 0 | 2 | 1 | 22785279 | 67108864 | PASS | 9415990 | `1..21718` | PASS | 365877 | PASS |
| balanced | 3 | `1787240893844_31118_31132_benchmark_0x6e828_0.trace.bin.lz4` | `d3f2c0198187b7c7d2fb0f3420042e0b3729526adafe00668775068923e1e0d5` | 25 | 21718 | `0x5745c858653f5a7f` | 868720.000000 | 1566635 | 362743 | 0.231542 | 21608 | 110 | 0 | 2 | 1 | 31288737 | 67108864 | PASS | 9415980 | `1..21718` | PASS | 365877 | PASS |
| balanced | 4 | `1787240896306_31182_31195_benchmark_0x6e828_0.trace.bin.lz4` | `02b956e3936d46282bf8b12ce8031a74a161f194ae9b1cccaaec96021746bc78` | 20 | 21718 | `0x5745c858653f5a7f` | 1085900.000000 | 1566635 | 362469 | 0.231367 | 21608 | 110 | 0 | 2 | 1 | 22940674 | 67108864 | PASS | 9415990 | `1..21718` | PASS | 365877 | PASS |
| balanced | 5 | `1787240898809_31240_31253_benchmark_0x6e828_0.trace.bin.lz4` | `b4f3f1c364231bec6814fccb00c6e6d1e4aee116d94d4ca027aa24fbb938565c` | 24 | 21718 | `0x5745c858653f5a7f` | 904916.666666 | 1566635 | 362559 | 0.231425 | 21608 | 110 | 0 | 2 | 1 | 25361979 | 67108864 | PASS | 9415990 | `1..21718` | PASS | 365877 | PASS |
| full | 1 | `1787240933975_31824_31841_benchmark_0x6e828_0.trace.bin.lz4` | `5cd887c3ab31353e1da5c8a4947b2db349dc3063b57d922a1e043c177917504a` | 36 | 21718 | `0x5745c858653f5a7f` | 603277.777777 | 1672811 | 379822 | 0.227056 | 21608 | 110 | 0 | 2 | 1 | 24182251 | 67108864 | PASS | 9437592 | `1..21718` | PASS | 429199 | PASS |
| full | 2 | `1787240938142_31887_31905_benchmark_0x6e828_0.trace.bin.lz4` | `03feac8f1e05da4f3f009df9c7827e13f051b50ac27212bb95173cebf20646f0` | 34 | 21718 | `0x5745c858653f5a7f` | 638764.705882 | 1672811 | 380009 | 0.227167 | 21608 | 110 | 0 | 2 | 1 | 24835897 | 67108864 | PASS | 9437602 | `1..21718` | PASS | 429199 | PASS |
| full | 3 | `1787240941018_31951_31964_benchmark_0x6e828_0.trace.bin.lz4` | `6add8ce56cab6a18bec8d02f02762a11e188fc021f6c9e5fbd8cf4a8afde6755` | 36 | 21718 | `0x5745c858653f5a7f` | 603277.777777 | 1672811 | 379847 | 0.227071 | 21608 | 110 | 0 | 2 | 1 | 24475952 | 67108864 | PASS | 9437602 | `1..21718` | PASS | 429199 | PASS |
| full | 4 | `1787240946286_32026_32089_benchmark_0x6e828_0.trace.bin.lz4` | `06f3f198c760ebcdb6218f848b035b03305a20fea69c6cc3fc4d7623c3911fac` | 33 | 21718 | `0x5745c858653f5a7f` | 658121.212121 | 1672811 | 379982 | 0.227151 | 21608 | 110 | 0 | 2 | 1 | 32406616 | 67108864 | PASS | 9437602 | `1..21718` | PASS | 429199 | PASS |
| full | 5 | `1787240950285_32143_32156_benchmark_0x6e828_0.trace.bin.lz4` | `c4f18f95ae26e3e7716b84b138e0c6c2132a4a828cc295c2d1138262bdef10a9` | 38 | 21718 | `0x5745c858653f5a7f` | 571526.315789 | 1672811 | 380039 | 0.227185 | 21608 | 110 | 0 | 2 | 1 | 27008708 | 67108864 | PASS | 9437602 | `1..21718` | PASS | 429199 | PASS |

The aggregate medians above are recomputed from these fifteen rows; per-run rate and ratio are the
fixed-six sidecar values derived from `instructions * 1000 / elapsed_ms` and
`compressed_bytes / encoded_bytes`.

### Representative median-elapsed artifacts

| Profile | Artifact | Elapsed ms | Compressed bytes | Converted bytes | SHA-256 |
| --- | --- | ---: | ---: | ---: | --- |
| fast | `1787240911587_31370_31385_benchmark_0x6e828_0.trace.bin.lz4` | 16 | 267939 | 6299333 | `d2ad17becb1005185ee74d34422861c279865769d79393ab8e883e5fea8f2efb` |
| balanced | `1787240898809_31240_31253_benchmark_0x6e828_0.trace.bin.lz4` | 24 | 362559 | 9415990 | `b4f3f1c364231bec6814fccb00c6e6d1e4aee116d94d4ca027aa24fbb938565c` |
| full | `1787240933975_31824_31841_benchmark_0x6e828_0.trace.bin.lz4` | 36 | 379822 | 9437592 | `5cd887c3ab31353e1da5c8a4947b2db349dc3063b57d922a1e043c177917504a` |

### Final repair acceptance (2026-08-21)

The final repair candidate was the stripped Debug tracer with SHA-256
`33083c68ea20082ea91fede32d5302d3677a0abaaa0e4e769a66d7563d50f53d`. Its staged and app-private
hashes matched. Pixel 6 (`oriole`), Android 16 build fingerprint
`google/oriole/oriole:16/CP1A.260405.005/15001963:user/release-keys`, package
`com.aprz.qbdiandroid`, Debug app, and SELinux `Enforcing` matched the acceptance identity.
Each profile used one unreported warmup and exactly five fresh measured processes.

| Profile | Measured elapsed ms | Median instructions/s | Compressed bytes (five) | Maximum | Format-2 limit | Semantic oracle | Verdict |
| --- | --- | ---: | --- | ---: | ---: | --- | --- |
| fast | 18, 17, 23, 25, 21 | 1034190.476190 | 267194, 267166, 267157, 267089, 267189 | 267194 | 307925 | 21718 events; `1 libdemo_target.so+0x6e828 STPXpre`; `21718 libdemo_target.so+0x6ea28 RET` | PASS |
| balanced | 23, 19, 24, 22, 27 | 944260.869565 | 360277, 360344, 360324, 360354, 360628 | 360628 | 365877 | same exact count/first/last | PASS |
| full | 34, 38, 31, 41, 38 | 571526.315789 | 378225, 378147, 378005, 378282, 378145 | 378282 | 429199 | same exact count/first/last | PASS |

All 15 artifacts had stable return `0x5745c858653f5a7f`, strict v2 sidecars, complete QTRB/LZ4
framing, exact footer/sidecar counters, and successful bounded streaming conversion. The retained
evidence is under `/tmp/qbdi-binary-final2-{fast-rerun,balanced,full}`; the failed first fast batch
is retained under `/tmp/qbdi-binary-final2-fast`.
The final binary's first fast batch (`26, 16, 16, 22, 22` ms) measured a 22 ms median and missed
the 1M gate at 987181.818181 instructions/s; the complete rerun shown above passed at 21 ms. This
1 ms boundary jitter is retained as a performance-stability concern rather than discarded.

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
