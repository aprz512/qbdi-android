# QTrace UI index memory: PERF-02

## Change

The 10M-event cold index previously held the encoded event metadata (240 MB) in memory while encoding the other sections. Cache reopening then held that encoded section and its decoded event columns at the same time. Large event metadata sections are now encoded into an automatically removed temporary file and copied into the atomic cache publication in bounded chunks. Cache reopening decodes the section in 4,096-row chunks before loading the other sections. The cache format, full-section checksum verification, validation, cancellation checks, and publication boundary remain unchanged.

## Reproduction and result

Run `qtrace-ui/tools/generate_performance_fixtures.py` to create the fixed 10M-event corpus, then run `qtrace-ui/tools/performance_gate.py --diagnostic` before and after the change on the same host. The after run used `--diagnostic-baseline` with the before JSON. Both runs used five cold indexes and five warm opens. The baseline analyzer was commit `0ca97c2` with binary SHA-256 `f7f54e20003a59822a366167bb59b7d9c05fb1d376199aa27d3427cfd27d228f`; the changed analyzer binary SHA-256 was `11ea9d835849ded0510c7cf09344c9e2b8c6100264f9c2d1d277f60701f5e9da`. These are local diagnostic results; the fixed reference host was not available.

| Metric | Before, five runs | After, five runs | Median change |
| --- | --- | --- | ---: |
| Cold index, seconds | 8.264, 8.442, 8.318, 8.308, 8.261 | 7.933, 8.126, 8.494, 8.965, 8.337 | +0.34% |
| Cold index peak RSS, MiB | 1693.1, 1693.1, 1693.0, 1692.8, 1693.0 | 1464.2, 1464.2, 1464.1, 1464.1, 1464.2 | **−13.52%** |
| Warm open, seconds | 1.318, 1.251, 1.305, 1.218, 1.310 | 1.325, 1.256, 1.400, 1.401, 1.257 | +1.57% |
| Warm open peak RSS, MiB | 1616.2, 1616.3, 1616.4, 1616.2, 1616.4 | 1463.8, 1463.8, 1463.8, 1463.8, 1463.8 | −9.43% |

Every run produced the same 730,331,981-byte cache and correctness digest `780f3fd8132848ee2afadeb4595d1601ed6286595dc038afbb0b44ce3ffb8c69`. The diagnostic reference thresholds passed. The observed cold index memory reduction exceeds the PERF-02 10% target; the 0.34% median time increase is below its 10% limit. Full Rust workspace tests, Clippy with warnings denied, and formatting checks passed. A targeted failure test also verifies that a truncated temporary section leaves no published or staging cache file.

Linux stage probes can be enabled with `QTRACE_UI_INDEX_PROBE=1` for further attribution. Before the change, memory grew from about 1.28 GiB after the source scan to about 1.58 GiB after event encoding and 1.65 GiB after all sections; the cache reopen also reached about 1.58 GiB after event decode. The bounded spool and streaming decode remove both large encoded copies from those phases.
