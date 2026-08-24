# Flight recorder device acceptance

This report records the final five-mode Pixel 6 acceptance run for the multithread crash flight
recorder. The retained machine-readable report is
`artifacts/flight-acceptance-final-v2/acceptance.json`; the five exact 512 MiB artifacts named below
are retained beside it.

## Device and candidate identity

| Field | Value |
| --- | --- |
| Acceptance date | 2026-08-24 |
| Device model | Pixel 6 |
| Device product | oriole |
| Android version / API | 16 / 36 |
| ABI | arm64-v8a |
| Build fingerprint | google/oriole/oriole:16/CP1A.260405.005/15001963:user/release-keys |
| SELinux | Enforcing |
| Package | com.aprz.qbdiandroid |
| App build type | Debug |
| QBDI | 0.12.1 AARCH64 Android |
| Flight artifact format | v2 |
| Frida host/server | 17.17.0 |
| Git branch | feat/flight-recorder |
| Candidate source commit | c870544073cecc02e32d5cfe4d67908627973f22 |
| Candidate state | Committed source; exact device binaries are identified by hashes below |
| APK SHA-256 | d5fc786766013f9e1b2986efa10db48ee6d37f51852aa429e0dcc13f8b0dd0fe |
| Tracer SHA-256 | e2bde1a884a7f23af032eb84be3d874b8e5eb4af487e9d96214ed56b96ea0c62 |
| ShadowHook companion SHA-256 | 4fe29375379c3c6bd7dae1f8af60f9b89a670149f3152ab0cedf8efa890fe2dd |

The runner used full-profile capture, a 512 MiB fixed artifact, 16 target workers, five measured
fixture rotations, a minimum four-retained-chunk gate for every worker, and the default 180-second
oracle timeout. The calibrated fixture used 2,048 mutation iterations per rotation. The measured
worker windows below show that this remained far above the four-chunk gate.

## Results

| Mode | Seed | PID | Workers | Rotations | Worker chunks min..max | Expected TID / PC | Observed TID / PC | Decode | Gaps | Verdict |
| --- | ---: | ---: | ---: | ---: | ---: | --- | --- | --- | ---: | --- |
| direct_tgkill | 101 | 29933 | 16 | 5 | 101..142 | 29953 / 0x6f098 | 29953 / 0x6f098 | complete | 0 | PASS |
| exit_group | 202 | 30171 | 16 | 5 | 117..137 | 30224 / 0x6f0ac | 30224 / 0x6f0ac | complete | 0 | PASS |
| sync_fault | 303 | 30402 | 16 | 5 | 117..136 | 30463 / 0x6f0b8 | 30463 / 0x6f0b8 | complete | 0 | PASS |
| target_sigkill | 404 | 30703 | 16 | 5 | 119..134 | 30728 / 0x6f0c8 | 30728 / 0x6f0c8 | complete | 0 | PASS |
| external_sigkill | 505 | 30891 | 16 | 5 | 123..134 | none / none | none / none | complete | 0 | PASS |

Every run also reported no guest-visible tracer address. The four target-originated termination
cases matched the independently published TID and original target-relative PC exactly. The host
originated SIGKILL recovered committed windows without inventing an initiator.

## Retained artifacts

| Mode | Artifact | SHA-256 |
| --- | --- | --- |
| direct_tgkill | `936548157380132_29933_libdemo_target.so.flight.bin` | `f47f09ce1b990371a229e0a3528e2a4d1fcb82ea9c860b8c90ea95d072f7ad2d` |
| exit_group | `935336294852634_30171_libdemo_target.so.flight.bin` | `4266507636c1baed7bcd3642794f9671325e9ee5fa5a2dc74ece34044220c162` |
| sync_fault | `933517157610003_30402_libdemo_target.so.flight.bin` | `97df5195e9ead41f592ca9d2f983031d3659dfe56a32d117a209b33a9b02dd0b` |
| target_sigkill | `949976516186706_30703_libdemo_target.so.flight.bin` | `5e2ab2a1e5ca85651c2a1ba1a87703b4b6e42614ebe2872940935228e4f4c9af` |
| external_sigkill | `933245496389269_30891_libdemo_target.so.flight.bin` | `884b3e5f4695590fcd16273adf963092daf145b119052efe1400950b75dd30d5` |

## Reproduction

```bash
/tmp/qbdi-flight-frida-17.17.0/bin/python scripts/flight_acceptance.py \
  --package com.aprz.qbdiandroid \
  --device 192.168.50.149:5555 \
  --seeds 101,202,303,404,505 \
  --artifact-mb 512 \
  --output-dir artifacts/flight-acceptance-final-v2
```

The external SIGKILL is issued as the debuggable app UID with
`adb shell run-as com.aprz.qbdiandroid kill -9 <pid>`. This is host-initiated termination; using
the adb shell UID directly is rejected by Android's process UID isolation.
