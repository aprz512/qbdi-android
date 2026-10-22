# Binary trace baseline v2

2026-10-22. This version corrects the execution oracle while retaining the immutable
[format-2 baseline](binary-trace-baseline.md) and every original performance limit.
The old document records QBDI return `0x5745c858653f5a7f` and separately acknowledges
native return `0x20a128f3d199a008`. The saved pre-change tracer and the current
candidate both produce the latter return, 21,714 instructions, and the same
first/last sequence on the same historical target. This calibration does not
identify the historical QBDI defect that caused the older difference.

## Device, build and calibration identity


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
| Candidate tracer SHA-256 | 288b34e69557011ed0160b845cfa1538019691368af61a853e7d57a34c475ace |
| Target library SHA-256 | 5f1a970825ae8bacb17d8dd656e01bd1fe7172638ba3ddcacd82ffaaad6e62c0 |
| Target library canonical SHA-256 | 0d8e856c819fb3cd7ae5917053172b4b75a7924784c43e09cb2855a298647169 |
| Historical target commit | 2d6b1022a14ae554804a57e267544c12dea29353 |
| Baseline schema | 2 |
| Reference source HEAD | eb79bcb2c37acb27affda4983ecb099e3ac5c497 |
| Reference evidence SHA-256 | 863971c694b31d9c8dab9dbd00c0e93df2d444afb075f82d24d48a51670dc99a |
| Historical size budget source SHA-256 | 91dc77002b802b6c2dd1d3c1229292b4bf9a455e3c4acb52438c6a6a0a51d1ed |
| Native return | 0x20a128f3d199a008 |
| Warmups per profile | 1 |
| Measured runs per profile | 5 |

The candidate SHA in this identity table identifies the saved **reference** tracer,
not an admission requirement for a newly built candidate. Its associated checkout
HEAD and pre-existing diff hash are retained in the [reference evidence](evidence/binary-trace-baseline-v2.json);
this is binary provenance, not a claim that the reference came from a pristine checkout.
The historical raw target SHA remains the original audit identity. The rebuilt
reference APK's actual raw target SHA is `6629d11aa68bafbcdf96353930271fd1d77fdd62dcb539123e134581d17a311b`;
its canonical ELF SHA matches the unchanged historical admission identity.
The exact installed APK, staged tracer/companion, device identity, native agent,
all 18 artifacts, sidecars, decoded files, and cleanup have retained hashes.

## Version-2 correctness and performance gates

| Profile | Instructions | Return | Decoded event count | First sequence | Last sequence | Maximum compressed bytes | Minimum instructions/s |
| --- | --- | --- | --- | --- | --- | --- | --- |
| fast | 21714 | 0x20a128f3d199a008 | 21714 | 1 libdemo_target.so+0x6e82c STRXui | 21714 libdemo_target.so+0x6ea28 RET | 307925 | 1000000 |
| balanced | 21714 | 0x20a128f3d199a008 | 21714 | 1 libdemo_target.so+0x6e82c STRXui | 21714 libdemo_target.so+0x6ea28 RET | 365877 | 800000 |
| full | 21714 | 0x20a128f3d199a008 | 21714 | 1 libdemo_target.so+0x6e82c STRXui | 21714 libdemo_target.so+0x6ea28 RET | 429199 | 500000 |

Correctness must match for the warmup and every measured artifact. Every measured
artifact must have a completed, valid-return v3 footer, pass bounded strict
conversion, and meet its size limit. Rate uses the median of exactly five fresh
processes. The numbers above are inherited limits, not new reference measurements.
Device, APK, canonical ELF, staged bytes, framing, footer, and sidecar admission
checks remain mandatory. Unknown baseline versions fail without legacy fallback.

## Reference measurements

Each profile used one warmup followed by five fresh processes with the saved
reference tracer, Frida host/server 17.17.0, the same 256 iterations and seed
`0x514244492d626173`. The direct native agent asserts that no tracer is loaded
before and after calling `demo_benchmark_case`; its result is separately retained.

| Profile | Five measured elapsed values (ms) | Median ms | Median instructions/s | Maximum measured compressed bytes |
| --- | --- | --- | --- | --- |
| fast | 21, 21, 17, 20, 17 | 20 | 1085700.000000 | 265881 |
| balanced | 23, 27, 27, 28, 29 | 27 | 804222.222222 | 362328 |
| full | 42, 42, 45, 44, 41 | 42 | 517000.000000 | 378432 |

The reference collection calibrates correctness; it is not the candidate's release
gate. Retained artifacts live under `out/ux-remaining-20261022/reference-baseline-v2/`.
The checked-in evidence records hashes and measurements; local ignored artifacts
are required for a full replay audit. No old baseline or failed gate was rewritten.

## Compatibility and rollback

`benchmark_trace.py --compare` accepts this explicit schema 2 document and the
original format-2 document. The device release gate selects this version. To audit
the historical oracle, pass the old document explicitly; current native-correct
execution is expected to fail that old semantic oracle. Switching back does not
remove the new evidence or alter the old file.
