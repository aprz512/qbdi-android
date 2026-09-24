# qtrace-ui 富事件性能语料（PERF-01）

日期：2026-09-24。本页是开发机诊断，不替代固定参考主机的 10M QTRB / 512 MiB Flight 门禁。

## 语料和真值

`generate_performance_fixtures.py` 的原有语料与 manifest 格式保持不变。新增 `generate_rich_performance_fixture.py` 生成独立的 100,006 条记录 QTRB 1.2 语料，同时发布原始文件和真实 LZ4 frame 压缩文件。两种文件都由 Rust provider/store 打开，并逐行核对事件类型。

| 类型 | 数量 |
| --- | ---: |
| 指令，含读写寄存器值 | 60,000 |
| 内存读写 | 20,000 |
| 语义调用 | 20,000 |
| 元数据/结束记录 | 6 |
| 嵌套调用帧 | 5,000 |

原始 QTRB 的固定 SHA-256 是 `f00f7a25b0cc773903d42235bfbf629c2bea883fa88cfefd3d37ab72e8eadd7e`。生成器在发布前检查这一语义指纹；测试逐条核对 record 数量与类型。线程生命周期、覆盖 gap 和不连续证据仍由原有 `flight-512m.flight.bin` 提供：该语料含四线程、overwritten 和 coverage_gap 真值。富事件语料没有 optional 空记录，原 10M 语料继续用于大规模协议/索引门禁。

60:20:20 是固定的高负载组合，用来稳定触发三类查询路径。仓库内两份成功设备验收压缩轨迹（SHA-256 前缀 `87db7fa4`、`9d6cf360`，分别 15,608、24,527 字节）经 Python 逐帧 LZ4 解码后，分别有 717/275 和 1,199/462 条指令/内存，比例约 2.6:1；本语料的指令/内存比例为 3:1。两份小轨迹均无语义调用，所以额外的 20,000 条语义事件是压力场景，不能称作设备实测比例。Rust provider 当前对原始验收压缩文件报 `source.qtrb.compression`，因此这些文件不进入门禁语料。后续获得更长的采集后应增补按实测比例生成的场景，并保留本压力场景作回归对照。

生成和诊断：

```sh
python3 qtrace-ui/tools/generate_rich_performance_fixture.py --output /tmp/qtrace-rich-corpus
cd qtrace-ui
cargo build --release -p qtrace-service --example perf_driver
target/release/examples/perf_driver rich --input /tmp/qtrace-rich-corpus/rich-manifest.json --cache /tmp/qtrace-rich-new-cache
```

每轮必须传入新的空 cache 目录，才能把 `raw_cold_seconds` 与 `compressed_cold_seconds` 解释为冷索引。驱动还在同轮测原始文件 warm open、200 次 2,000 行查询、50 次寄存器回放、完整调用树，以及 service 的 2,000 行 JSON 页与调用树根页。输出 JSON 保留每次查询/回放采样，便于同机前后比较；不写官方基线。

## 本机五轮结果

机器：Intel Core Ultra 7 356H，16 逻辑 CPU，Linux 6.18.33.2 WSL2。代码基于 `94714a0`，含本项尚未合入的基准代码。每轮新建 cache；下表为五轮中位数，p95 汇总全部采样。

| 指标 | 结果 |
| --- | ---: |
| 原始 QTRB 冷索引 | 433.7 ms |
| 原始 QTRB warm open | 188.7 ms |
| LZ4 QTRB 冷索引 | 417.9 ms |
| 2,000 行查询 p95，1,000 次 | 0.022 ms |
| 寄存器 replay 构建 | 110.9 ms |
| 寄存器状态查询 p95，250 次 | 2.13 ms |
| 构建 5,000 帧调用树 | 1,763.3 ms |
| service 2,000 行查询 | 41.9 ms |
| service 页 JSON | 700,729 B |
| service 调用树首次根页 | 1,757.0 ms |
| service 调用树根页 JSON | 354 B |

浏览器诊断 `performance.spec.ts` 用同样的 2,000 行比例、摘要字段和分页上限，经 mock IPC 测从点击 Apply filters 到首行可见。五轮为 494.4、547.3、535.7、541.3、575.1 ms；中位数 541.3 ms，DOM 行数始终为 25。该数字包含 Playwright 点击及 mock 请求调度，不能单独解释为 React 绘制耗时；它不含真实本机索引和 Tauri IPC。

这组数据揭示两个后续观察点：首次调用树构建约 1.76 秒；2,000 行 service DTO 约 701 KiB。优化它们须另做同机前后对比。所有值均为本机诊断，不设跨设备性能结论。
