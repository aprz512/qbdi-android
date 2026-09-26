# qtrace-ui 两项性能优化与本机验收

日期：2026-09-26。对应 PERF-01、PERF-02；基点 `5dbff3a`，候选为当前未提交工作区。
完整样本、主机/语料/二进制身份和测试源码哈希见 [JSON 证据](qtrace-ui-optimization-2026-09-26.json)。

## 验收范围

两项已在用户指定的当前环境验收通过。当前环境登记为 `qtrace-ui-reference-v2`，新增
[当前环境基线](qtrace-ui-performance-current.md) 与 [五轮规模门禁原始证据](qtrace-ui-performance-current.json)。
历史 `qtrace-ui-performance.md` 保留；原 v1 的身份不匹配属于此前诊断记录。

本次规模门禁实际重新运行：五轮冷索引中位数 8.308 s、五轮缓存重开中位数 1.130 s、
冷索引峰值 RSS 中位数 1158.95 MiB；200 次 viewport 查询 p95 0.0372 ms，200 次结构化查询 p95 0.0126 ms。
所有原阈值与正确性检查通过，没有放宽阈值或禁用身份校验。

富事件五轮、真实 UI 和测试套件复用此前有效证据：逐项核对源码、analyzer 二进制、语料哈希、
主机硬件/系统字段，以及 rich oracle 与样本数量，均未变化。原报告保留 diagnostic 模式，
本次接受当前环境的记录另存于 JSON 的 `current_environment_acceptance`，没有伪造重新运行记录。
CI 已切换到当前环境基线；本轮没有触发远端 CI 或设备验收。

## PERF-02：冷索引内存

normalized EventColumn 不再重复 EventKey 的 timeline、tid、sequence，行结构从 56 B 降为 24 B。
posting partition 直接生成 delta runs，避免额外保存全量行号；事件表编码完成后提前释放源表。
保留原有二分查找改动并通过 owned/mapped 与 naive 查询等价测试。
持久缓存布局不变：坐标原本只编码在 event_keys section；旧缓存用新版本成功重开，摘要一致。
预算、取消、缓存校验、失败清理和原子发布沿用现有边界。

使用同一台主机、相同 10M QTRB/512 MiB Flight 语料，前后各五个独立进程及独立空缓存。
基线来自隔离的 `git archive 5dbff3a qtrace-ui scripts` 构建；候选没有修改基线源码。
计时包含 driver 进程启动、索引、发布与验证重开；内存取 Linux `wait4().ru_maxrss`。

| 指标 | 基线中位数 | 候选中位数 | 变化 | 判定 |
| --- | ---: | ---: | ---: | --- |
| 冷索引耗时 | 10.304 s | 9.508 s | -7.73% | 未回退超过 10% |
| 进程峰值 RSS | 1464.30 MiB | 1158.96 MiB | -20.85% | 下降至少 10% |
| 正确性摘要 | `780f3fd8…` | `780f3fd8…` | 一致 | 通过 |

候选分阶段日志也保存在 JSON。后续修改仅涉及 rich driver 和测试/文档，测量时的 store 代码与最终 store 代码相同。
前后对比仍是同机诊断；当前环境的独立规模门禁已通过，历史固定主机结果不用于跨环境速度比较。

## PERF-01：富事件与交互证据

生成器支持 100k、1M、10M 富事件加六条元数据/终端记录；保留旧 10M optional 基线。
本轮执行 1,000,006 条 QTRB：600,000 instruction、200,000 memory、200,000 semantic，含 5,000 call frames。
原始和多帧 LZ4 输入均读取；100k 与 1M 有固定语义哈希。流式生成和按 4 MiB 分帧压缩限制生成器内存。
Flight companion 含四线程、checkpoint/delta、overwritten 和 coverage gap；验证完整性 oracle 和线程列表。

`rich_performance_gate.py` 每轮使用新进程与空缓存。五轮均验证事件数、调用树、50 个原始/缓存/压缩回放状态等价、
200 次时间线分页与 200 次 memory 查询、IPC 上限、缓存大小和 RSS。任何真值不一致都失败。
此工具目前记录 rich 延迟，不设置未经测量支持的新延迟门槛；旧规模门禁保留原阈值。

| 指标 | 本机五轮结果 |
| --- | ---: |
| 原始冷索引中位数 | 5.866 s |
| 原始缓存重开中位数 | 2.194 s |
| 压缩冷索引中位数 | 5.085 s |
| 时间线查询 p95 | 0.0213 ms |
| memory 查询 p95 | 0.0492 ms |
| 寄存器状态查询 p95 | 2.354 ms |
| 单进程整体峰值 RSS 中位数 | 1732.32 MiB |
| IPC 时间线页字节数中位数 | 700729 B |
| IPC 调用树首分页字节数中位数 | 354 B |

**预算边界：** 1M 富事件在 service 冷开和缓存重开均触发累计 2 GiB allocation budget。
没有扩大或绕过生产 service 的预算。大语料用于直接 store/analysis；IPC 和真实 UI 使用 manifest 中独立标识的 100,006 条语料。
直接分析 driver 使用 AllowAll，因此其结果不是“生产 service 能打开 1M”的证据。
该限制是本次测量发现的规模边界，需要后续单独分析预算与分阶段资源所有权；不应据此放宽预算。

浏览器测试真实请求 Rust service，没有 mock 时间线。Debug Rust + Vite E2E 环境：
首次打开并显示约 11.105 s；50 次筛选 p95 1197.1 ms；DOM 保持 25 行。
延迟包含服务端、job polling 和浏览器等待；该值不代表打包后的 Tauri 延迟。部分测量期间有 host 验证任务，不作跨机器速度承诺。

## 复现与验证

```bash
python3 qtrace-ui/tools/generate_rich_performance_fixture.py --output /tmp/qtrace-rich
python3 qtrace-ui/tools/rich_performance_gate.py \
  --manifest /tmp/qtrace-rich/rich-manifest.json \
  --evidence /tmp/qtrace-rich/run.json --diagnostic
mkdir -p /tmp/qtrace-rich-ui/sessions/valid-mixed/artifacts
cp /tmp/qtrace-rich/qtrb-rich-100000.trace.bin /tmp/qtrace-rich-ui/sessions/valid-mixed/artifacts/main.trace.bin
cd qtrace-ui/src-web
PLAYWRIGHT_JSON_OUTPUT_NAME=/tmp/qtrace-rich/ui-run.json \
QTRACE_E2E_FIXTURE_ROOT=/tmp/qtrace-rich-ui \
  npx playwright test tests/e2e/performance.spec.ts -g 'real rich' --reporter=list,json
```

当前参考环境使用 `--reference-summary docs/benchmarks/qtrace-ui-performance-current.md`，不加 `--diagnostic`，
且按既有工作流设置`QTRACE_UI_REFERENCE_HOST=qtrace-ui-reference-v2`。

| 检查命令 | 结果 |
| --- | --- |
| `cargo test --workspace` | 全工作区通过，含 owned/mapped、篡改、取消、预算与发布测试 |
| `cargo clippy --workspace --all-targets -- -D warnings` | 通过 |
| `cargo fmt --all --check` | 通过 |
| `python3 -m unittest discover -s scripts/tests -p 'test_*.py'` | 最终 842 项，跳过 8 项，通过 |
| `python3 -m unittest scripts.tests.test_qtrace_ui_rich_fixture scripts.tests.test_qtrace_ui_performance -v` | 21 项通过 |
| `npm run lint`、`npm test` | 通过；42 项前端单测 |
| 真实 rich Playwright | 通过；50 次筛选，附件已收录 JSON 证据 |
| 当前环境规模门禁 | 原阈值下五轮冷/热、200 次查询均通过；rich/UI 证据经等价核对复用 |

首次 Python 全套运行有一项既有 `test_timeout_reaps_setsid_descendant_that_inherits_capture_pipes` emergency teardown 错误；
单项复跑通过，随后完整套件 842 项通过。未修改 bounded_process 代码。
