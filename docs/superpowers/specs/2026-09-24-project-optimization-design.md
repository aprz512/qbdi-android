# 项目整体优化机会清单

**首次整理：** 2026-09-24

**状态更新：** 2026-10-19（基于 HEAD `f4cf92b` 的工作区；新增 PERF-03、UI-07 与 UI-09 本机验收，保留此前小米采集验收）

**性质：** 持续维护的优化清单；实施与验收状态以各条目及对应证据为准

**范围：** Android 演示应用、native tracer、Python `qtrace` CLI/脚本、QTRB/Flight 协议、`qtrace-ui` Rust/React/Tauri、测试与发布流程。

## 1. 审查结论

仓库的主链路是 `app` 演示目标、`tracer` 设备端采集、`qtrace` 主机编排与产物发布，以及 `qtrace-ui` 离线分析。`qtrace-ui` 已采用 provider → store → analysis → service → Tauri/React 的分层；host CI、定期 fuzz、固定主机性能门禁和手动设备门禁都已存在。优化应先解决已经能从代码或现有证据确认的高成本路径，再处理结构复杂度；不要为了减小代码量削弱身份校验、预算、取消、完整性或原子发布。

PERF-01/PERF-02 已在用户指定的当前环境验收通过，真实小米采集到浏览器的功能链路也已打通。PERF-03 的缓存阶段测量与有界并行、UI-07 的加载进度、UI-09 的首次分析取消已完成本机验收。后续优先推进 **UI-10 累计页面内存测量、UI-06 请求所有权、UI-08 布局与规模边界复验**。 寄存器复用、调用树分页、时间线摘要、session 上下文、结果分页和开发机诊断模式已有实现，后续重点是针对各条目的剩余条件复验。历史大规模性能门禁不能替代当前版本的交互和真实事件负载验证。

### 证据边界

- 2026-10-19 后续长任务优化：相同 10M QTRB / 512 MiB Flight 语料交错各五轮，warm open 中位数 1.167 降至 0.808 秒（-30.75%），冷索引 8.077 降至 7.554 秒（-6.48%），峰值 RSS 基本不变，缓存大小与正确性摘要一致。阶段数据将成本定位到事件键读取/解码；改为事件键与元数据两路解码，再复用第二个 worker 做 checksum，保留全部身份、内容和篡改校验、原累计预算及 schema 2 / layout 3。服务缓存验证采用相同的最多两 worker 边界。打开任务新增七个阶段和字节/事件/行工作量，计数包含重复处理，不推算百分比或剩余时间。真实 1,185,909 事件 Flight 在 Chromium 中验证进度更新、建索引取消不发布工作区或缓存、重试与缓存重开；四份小米产物再次通过离线逐事件、分页与分析核对。工作区关闭绑定寄存器/调用树首次构建的取消令牌，release 单次取消后分别约 9.2 / 16.9 毫秒退出，缓存保持空且 store 引用释放；这不是取消延迟门禁。Rust 全工作区、最终 service 套件、clippy/fmt、生成物、前端 45 项测试、15 项 E2E 与生产桥接隔离通过。原始样本、源码/二进制身份、回归及截图见 [长任务优化与验收](../../benchmarks/qtrace-long-operations-2026-10-19.json)。这是本机对比与保留产物功能验收，未覆盖新的设备性能、rich 性能门禁或高缩放布局；固定参考报告保持不变。
- 2026-10-19 小米新采集验收：用户允许 Shell root 后，在 `M2011K2C`（`2d32ed71`、Android 16、Frida host/server 17.24.2）完成四份新 session。offset/symbol timed 各 987 个事件，均按原生 2 秒期限停止，应用仍存活，计算结果与本轮无追踪基线一致；monitor-exit 为 1,714 个事件；64 MiB Flight 恢复为 1,185,909 个事件，保留崩溃后的完整性缺口及未知终止原因。四份产物均通过逐事件离线核对、完整分页、分析抽样和缓存重开；随后通过 Chromium 与真实 Rust 服务完成上下文、筛选、寄存器、调用树、内存及历史、标注、高亮与服务重启恢复，Flight 另覆盖跨页与末页定位，均无接口或页面错误。新 Flight 暴露的有序内存候选重复排序已修复，原 100,000 Nodes 与 2,000 返回行限制保留。Rust 全工作区测试、clippy、fmt 均通过。首次目录缺失的失败证据和旧目录备份均保留；成功重试沿用现有设备门禁的目录准备流程。身份、命令、回归测试、截图及 trace 哈希见 [小米新采集与浏览器验收](../../benchmarks/qtrace-xiaomi-capture-2026-10-19.json)。本轮为功能验收，未重跑完整历史五轮设备性能门禁。
- 2026-10-19 较早的浏览器验收：前端 14 项工作区/持久化 E2E 与 1 项生产构建桥接隔离测试通过。另用 Chromium 153.0.8010.12，通过现有认证 loopback adapter 连接实际 Rust 服务，对历史 Flight 与 monitor-exit 报告完成真实界面操作，无响应 mock：核对上下文、事件总数与筛选，Flight 跨结果页并跳到末页，查询寄存器、调用树、内存及历史，保存标注和高亮，重启服务后验证缓存与持久化数据。两份真实产物均无接口或页面错误。该次小米预检的 `run-as` 可用，但 Magisk 仍拒绝 Shell root，因此只验证历史产物；后续新采集见上一条。原记录保留当时的设备状态和产物身份，见 [浏览器与小米预检记录](../../benchmarks/qtrace-browser-acceptance-2026-10-19.json)。
- 2026-10-19 后续修复：历史 Flight 与 monitor-exit 真实 session 均通过 `verify_capture` 的冷开、provider/store 逐事件核对、完整分页、筛选、寄存器/调用树/内存抽样，以及进程重启后的缓存重开核对。Flight 为 64 MiB、1,133,180 个事件；monitor-exit 为 1,714 个事件。输入额度按实际读取次数推导；保留索引/缓存 2 GiB、寄存器回放 512 MiB、交互 100,000 Nodes 与 2,000 返回行限制。修复范围、源码身份和验收摘要见 [离线链路预算验收](../../benchmarks/qtrace-capture-budget-2026-10-19.json)。这证明历史产物的离线服务链路可用，尚不能替代新的设备采集和浏览器验收。
- 2026-10-19 第一阶段：针对历史 Flight 的 discovery 累计分配超限，改用行号基数排序和原地置换，跨 chunk 复用事务扫描缓冲，无序号冲突时直接保留原事件表。同一 64 MiB、1,133,180 个输出事件的真实产物，前后各五轮：provider 恢复耗时中位数 3.059 降至 1.642 秒（-46.3%），整个诊断进程峰值 RSS 中位数 857.87 降至 643.29 MiB（-25.0%），累计 resident 授权量 5.588 降至 1.881 GiB（-66.3%）；事件与 summary 的联合哈希全部一致。原 2 GiB provider 预算由失败转为通过，32 MiB 小语料回归、稳定排序属性测试、取消/释放、分配授权及 Rust 全工作区检查通过。该阶段仍卡在建索引输入预算，后续修复见上一条。原始样本、命令和被测源码身份见 [第一阶段 Flight 证据](../../benchmarks/qtrace-flight-recovery-2026-10-19.json)。这些五轮性能数字属于第一阶段源码，不能视为后续修复版本的重新测量；未测量 tracer 吞吐。
- 2026-10-18：新增真实 session 的 provider/store/service 离线验证工具，修复 native LZ4 skippable 填充帧拒读、选择 `report.json` 时误用报告大小限制整个会话，以及压缩输入未计入解码后 QTRB 读取量三个问题。历史设备门禁的 offset/symbol 产物通过逐事件、分页、分析抽样与缓存重开核对；monitor-exit 内存查询和 Flight discovery 仍分别触及现有行数、累计内存预算，因此 QA-01 仅标为部分完成。小米 `M2011K2C` 的五个无追踪界面场景与 timed oracle 通过；`su` 被 Magisk 拒绝，未完成该设备的 Frida 采集。命令、身份、哈希及边界见 [本轮验证记录](../../benchmarks/qtrace-device-validation-2026-10-18.json)。本轮没有测量 tracer 吞吐收益。
- 初始审查以 `bdc266a` 为基点；本次更新核对 HEAD `5dbff3a`、关键实现和提交记录。初始核对时工作区有三个未提交文件：`qtrace-store/src/index/mod.rs`、`index/wire.rs`、`tests/index_equivalence.rs`。已提交 `ffda405` 包含大事件表的有界编码；当前 `wire.rs` 又提前释放编码后的源事件表。这些改动现已整合并通过本机测试与性能对比；仍未提交。随后按用户指示采用当前环境，规模门禁通过；历史基线保留，新增当前环境基线。
- 已有固定主机基线：1000 万 QTRB 事件、512 MiB Flight，冷索引中位数约 8.35 秒、warm open 约 1.29 秒、冷索引峰值约 1.77 GB，门禁为 30 秒、2 秒、2 GiB；见 `docs/benchmarks/qtrace-ui-performance.md`。这份结果对应旧提交和旧主机身份，不等于当前工作区的回归结果。
- 初始文档记录的上一轮本机诊断（本轮未复现）：生成相同规格语料后，单次冷索引峰值从 1,733,264 KiB 降至 1,654,848 KiB；改动后五次约 1,616 MiB 且摘要一致。固定参考主机身份校验在当前机器失败，因此这些数字只用于发现方向，不能替代固定主机验收。
- 初次更新只做静态核对；随后按用户要求完成 PERF-01/PERF-02 实现与本机验收，运行 Rust/Python/前端套件、五轮内存对比、五轮 rich workload 及真实 UI 测量。详细命令与原始证据见 [本机验收报告](../../benchmarks/qtrace-ui-optimization-2026-09-26.md)。未执行设备 benchmark 或 CPU flamegraph。旧条目的行号属于初始审查定位；已变更路径优先以当前符号和文件为准。标记为“待测”的收益不能当作已证明收益。

### 本轮离线链路修复

| 原因 | 已实现的处理 | 保留的边界 |
| --- | --- | --- |
| Flight checksum 与 record recovery 重读被误计为一次物理读取 | 单文件 discovery 按一次哈希加两次 provider 读取推导上界；索引源按两次读取推导 | checked 累加、取消、真实字节计量仍有效 |
| 大事件表、payload 序列化和寄存器快照反复分配 | 紧凑物理记录、已知事件数预留、复用序列化缓冲和快照存储 | 索引与缓存累计 resident 授权上限仍为 2 GiB |
| Flight 缺口事件与完整性摘要采用不同的合并粒度 | 缓存校验先按相同 domain、cause、provenance 合并证据，再核对完整的区间并集 | 原始逐条缺口事件不变；身份与篡改校验保留 |
| 大量合法缺口超过固定 16 MiB 上下文额度 | 总载荷上界取 16 MiB 与每行 256 B 推导值的较大者，复用有序缺口索引 | 单载荷仍限 1 MiB；填充放大、输入、分配与取消检查保留 |
| 全局缺口向每个线程复制回放事件与完整快照 | 全局失效索引共享，线程状态延迟应用最近缺口；用周期快照和最近失效点定位查询 | 43 个实际线程仍独立回放；缺口 evidence key 与后续采集恢复语义保留；构建仍限 512 MiB |
| 内存 posting 扫描消耗返回行数额度，未来缺口也占历史限额 | 内部扫描与排序计入 Nodes；返回地址行/历史证据计入 Rows；复用上下文，只取目标之前的缺口 | 交互仍限 100,000 Nodes、2,000 返回行；历史候选仍限 10,000 条；无全局顺序时的未来跨线程写冲突检查保留 |
| 新小米 Flight 的 7,858 条有序内存候选仍执行八轮排序 | 收集时检查源行号严格递增；成立则直接使用结果，否则保留原 radix 排序与去重 | 实际扫描、取消、分配及原候选/工作/返回行额度继续执行；状态与历史查询分别降至 47,523/47,387 Nodes |

两份真实产物均在全新缓存目录运行，冷开与重启后重开结果等价。Flight 冷开/重开分别为 8.230/4.659 秒，monitor-exit 为 0.015/0.005 秒；这是单次诊断，包含完整校验的服务打开，不是固定主机性能门禁。Rust 全工作区测试、clippy、fmt 和差异空白检查均通过。验收工具及可复现命令见 [`qtrace-ui/README.md`](../../../qtrace-ui/README.md#captured-session-verification)，事件计数、摘要、命令和检查结果见 [预算验收记录](../../benchmarks/qtrace-capture-budget-2026-10-19.json)。

## 2. 架构与责任边界

```text
Android app fixture
      │ 目标场景
      ▼
Frida / ShadowHook → native tracer → QTRB / Flight
                                      │
                                      ▼
Python qtrace CLI → 校验、拉取、报告、发布
                                      │
                                      ▼
qtrace-ui provider → store/cache → analysis → service → Tauri → React
```

| 子系统 | 当前主要职责 | 本次重点 |
| --- | --- | --- |
| `app` | Android 演示场景、JNI 与 native fixture | 保持确定性目标与设备验收；没有证据支持单独优化演示计算逻辑 |
| `tracer` | 注入入口、hook、QBDI 回调、QTRB/Flight 写入 | 热路径测量、默认 Flight 容量与协议契约 |
| `qtrace`、`scripts` | 配置、构建、注入、拉取、校验、报告、设备门禁 | 事务边界、故障矩阵与真实采集到 UI 的验收 |
| `qtrace-ui` provider/store | 严格解码、身份验证、持久索引与缓存 | 索引内存、缓存打开、富事件语料 |
| `qtrace-ui` analysis/service | 查询、回放、调用树、预算与 DTO | 重用分析结果、限制大结果、补齐上下文 |
| Tauri/React | 命令适配、时间线与分析面板 | 有界分页、信息密度、取消和布局 |

跨层优化必须保持以下约束：原始产物只读；QTRB 1.0–1.2 与 Flight v2 可读；普通 QTRB 的不同 artifact 不被虚构成全局顺序；Flight 的线程/全局顺序和缺口如实保留；`captured`、`derived`、`unknown`、`damaged` 不混淆；长任务有取消、资源预算和失败后不发布的保证。已有设计见 `docs/superpowers/specs/2026-08-30-qtrace-ui-design.md`。

## 3. 优化机会总表

### 状态标记与维护规则

- `[待实施]`：当前仍存在优化机会；尚未确认实现。证据栏为“待测”的项目应先测量，再决定是否实施。
- `[部分完成]`：已实现部分目标，仍有明确缺口或未提交改动。
- `[已实现·待复验]`：当前源码和提交记录确认实现；本轮没有重新运行验收。
- `[已验收]`：仅在对应验收条件满足、记录命令及证据路径后使用。
- `[已验收·本机]`：本机对比或保留产物的服务/浏览器功能验收通过；具体测量范围见条目，不替代固定主机或 Android 设备性能门禁。
- `[已验收·当前环境]`：实现、当前环境规模门禁及 rich/UI 证据核对均通过；不代表 Android 设备发布门禁通过。
- `[暂缓]`：需记录暂缓原因与重新评估条件；不因缺少设备自动标为暂缓。

本次共 28 项：6 项 `[已实现·待复验]`、2 项 `[已验收·当前环境]`、1 项 `[已验收·小米当前环境]`、3 项 `[已验收·本机]`、1 项 `[部分完成]`、15 项 `[待实施]`。

状态与证据强度独立。更新时保留 ID，记录日期、提交或报告路径；不得以提交存在代替性能收益证明。

优先级：P0 是当前功能成本或体验的明显瓶颈；P1 需要测量或局部设计；P2 是规模扩展和维护性工作。证据强度：“确认”表示代码直接显示行为；“待测”表示值得验证的假设。每项的验收条件是后续实施的停止标准，不要求本轮全部执行。

| ID | 优先级 | 状态 | 方向 | 现状与代码依据 | 下一步及验收条件 | 证据 |
| --- | --- | --- | --- | --- | --- | --- |
| UI-01 | P0 | [已实现·待复验] | 寄存器交互 | `service.rs::get_register_state` 按 artifact 懒建并共享 `Arc<RegisterReplay>`；`workspace.rs::ArtifactWorkspace` 持有 replay。提交 `0715262`。 | 保留缓存；复验同轨迹连续点击 50 次 p95、结果等价及关闭释放。已有 `register_replay_is_shared_by_queries_and_released_with_workspace` 覆盖共享、并发查询和释放。 | 确认实现；性能待复验 |
| UI-02 | P0 | [已实现·待复验] | 调用树规模 | `service.rs::get_call_tree` 缓存树并按父节点每页返回至多 100 个节点；`CallTreePane.tsx` 分页展开、虚拟渲染。提交 `0134db7`。 | 复验深树/宽树 IPC、DOM 上限与 stale identity。剩余前端累计页面内存见 UI-10；后端仍全量建树，需测首次构建成本。 | 确认实现；规模待复验 |
| UI-03 | P0 | [已实现·待复验] | 时间线可读性 | `EventRowDto` 已含 location、symbol、summary；`timeline/VirtualTimeline.tsx` 映射到位置、符号与指令列。提交 `8ba7929`。 | 复验指令/内存/语义摘要、附加 ELF 后符号更新及损坏数据。`service_contract.rs` 已有摘要与 160 字节上限断言。 | 确认实现；交互待复验 |
| UI-04 | P0 | [已实现·待复验] | Session 上下文 | `OpenWorkspaceDto` 已含 context 与 missing_capabilities；`publish_session` 从 session 传递字段，`SessionOverview.tsx` 展示上下文与降级。提交 `ff351a7`。 | 复验 report 与单文件打开；缺失字段继续显示 unavailable，配置不得伪造为 captured。已有 `SessionOverview.test.tsx`。 | 确认实现；流程待复验 |
| PERF-01 | P0 | [已验收·当前环境] | 性能语料 | 流式生成 100k/1M/10M 富事件；100k、1M 固定语义哈希；独立 Flight 四线程与缺口 oracle。rich gate 五轮测 store/analysis、回放等价和 IPC；真实 service 到 UI 测 50 次筛选。CI 已接入正式参考主机运行和证据上传。 | 本机五轮和 UI 已通过，详见 [报告](../../benchmarks/qtrace-ui-optimization-2026-09-26.md)。当前环境规模门禁通过，原阈值保持不变；历史基线保留。1M store/analysis 与 100k IPC/UI 分开计量；1M service 累计 2 GiB budget 拒绝，未放宽预算。 | 实现与当前环境验收通过 |
| PERF-02 | P0 | [已验收·当前环境] | 冷索引内存 | EventColumn 复用 EventKey 坐标，56 B 降为 24 B；posting 直接编码 runs；编码后释放事件表。保留原二分查找，并通过等价、取消、预算、篡改和原子发布测试；缓存布局未变，旧缓存重开通过。 | 相同 10M/512 MiB 语料前后各五轮：RSS 中位数 1464.30 降至 1158.96 MiB（-20.85%），耗时 10.304 降至 9.508 s（-7.73%），摘要一致。达到本机下降 ≥10%、耗时回退 ≤10% 条件；当前环境规模门禁另行通过（冷 8.308 s、热 1.130 s、RSS 1158.95 MiB）。见 [报告](../../benchmarks/qtrace-ui-optimization-2026-09-26.md)。 | 本机收益与当前环境门禁通过 |
| PERF-03 | P1 | [已验收·本机] | warm open | 新增 `QTRACE_UI_OPEN_PROFILE` 的哈希、身份、事件行、section checksum 与 catalog 阶段测量；事件键和元数据独立解码，再以第二个 worker 校验 checksum。源与缓存校验保留，服务每 artifact 最多两个 worker。 | 相同 10M/512 MiB 语料各五轮：热开 1.167 降至 0.808 秒（-30.75%），冷索引 8.077 降至 7.554 秒（-6.48%）；RSS 基本不变，缓存大小和摘要一致。已有缓存及顺序/并行篡改、预算、取消与原子发布测试通过。参考报告未替换；不将这些数字当作完整服务或 UI 延迟。 | [长任务优化与验收](../../benchmarks/qtrace-long-operations-2026-10-19.json) |
| UI-05 | P1 | [已实现·待复验] | 查询结果分页 | `ResultsPane.tsx` 独立保存页面、游标和 hit，通过 queryTimeline/locateTimelineOffset 跨页导航并展示 exact/indexing 总数。提交 `5dbff3a`。 | 复验超过 2,000 命中的 Previous/Next、跨页 hit、空结果及切换 workspace 竞态。已有 `ResultsPane.test.tsx`。 | 确认实现；流程待复验 |
| UI-06 | P1 | [待实施] | 数据请求所有权 | `App.tsx:94-335` 多处重复 cache key、`queryTimeline`、generation/abort 检查与 cursor 记录；`SegmentCache.ts:42-44` 每次写入通过 JSON 序列化估重。 | 提取一个页面仓库管理 identity、游标、请求合并和缓存权重；避免在主线程为每页重复序列化。保留已有取消/切换竞态测试，并测滚动帧时间。 | 确认重复，收益待测 |
| UI-07 | P1 | [已验收·本机] | 加载反馈 | 打开任务报告源验证、缓存验证、建索引、缓存发布、缓存重开、分析准备与工作区发布；artifact 总数独立保留。阶段工作量按块合并，分析准备也报告行工作量；分配授权区间内仅记录计数，延迟通知分配。界面显示 `Cancelling…`，提交失败可重试。 | 真实 1,185,909 事件 Flight 的 Rust/Chromium 链路覆盖七阶段、单文件索引中的变化、取消后无工作区/缓存、重新打开和缓存重开。单文件取消保持 `job.cancelled`；字节/事件/行数包含重复处理，不表示唯一覆盖率或 ETA。 | [长任务优化与验收](../../benchmarks/qtrace-long-operations-2026-10-19.json) |
| UI-08 | P1 | [待实施] | 布局与可访问性 | `global.css:7-15` 固定三列和 800×600 最小宽高；时间线已有 ARIA grid，但多个侧栏直接铺开长列表。 | 先做 800–1366 px 与高缩放下的面板可达性、键盘焦点和长文本截断检查，再调整布局；不引入设计规格排除的拖拽 dock。 | 待测 |
| STORE-01 | P1 | [待实施] | 源键索引 | `builder.rs:1103-1129` 为每个事件另建 `SourceKeyRow { row }` 并在必要时排序；1000 万事件约有额外 80 MB 原始行索引。 | 评估单调键的隐式顺序表示或压缩排列，并保留非单调 Flight 的明确索引。需要缓存 schema 兼容/重建策略、重复键检测与 owned/mapped 等价测试。 | 确认成本，收益待测 |
| STORE-02 | P1 | [待实施] | 多 artifact 打开 | `service.rs:162-192` 逐 artifact 构建/打开，最后才发布 workspace。 | 先测多 artifact session 的等待时间和峰值；若并发有收益，使用受控并行数及统一内存预算，保持单 artifact 失败隔离和结果顺序。 | 确认顺序，收益待测 |
| CORE-01 | P1 | [待实施] | tracer 热路径 | `instruction_collector.cpp:68-135` 每条指令协调 pending、signal/syscall、rule、寄存器和内存路径；历史吞吐报告把剩余开销定位到 collector 与 formatter/output。 | 在同一设备/二进制身份下用 simpleperf 和现有五轮 benchmark 分 profile 采样，再针对占比最高分支优化。必须保留指令数、寄存器/内存事实、返回值、压缩大小门禁。 | 已有历史诊断，当前待测 |
| CORE-02 | P1 | [待实施] | Flight 默认容量 | `trace_config.h:30-37` 默认预分配 512 MiB；README 已要求检查设备存储。 | 收集实际 session 的占用和保留窗口需求，评估可配置预设与启动前空间预检；不改变 Flight 的固定容量环形语义。验收覆盖低存储、崩溃恢复和正常关闭。 | 确认默认值，收益待测 |
| CLI-01 | P1 | [待实施] | 产物发布复杂度 | `qtrace/artifacts.py` 同时负责拉取、校验、事务发布、报告刷新和失败回收（约 1,630 行）；`qtrace/session.py` 又编排生命周期与发布。 | 先画清状态/所有权图，再按“远端读取、校验、原子发布、报告刷新”拆内部模块，不改变公开 CLI 或恢复语义；用现有故障注入测试证明每个可见状态。 | 确认职责集中 |
| CLI-02 | P1 | [待实施] | 子进程边界 | `scripts/bounded_process.py` 有 supervisor、PID 身份、取消、子进程回收和流式输出，`qtrace/injector.py`、device/acceptance 都依赖它。 | 增加跨入口的统一故障矩阵：超时、取消、ADB 断连、PID 复用、输出上限、孤儿进程；仅在矩阵证明安全后抽象共用接口。 | 确认复杂路径，风险待测 |
| PROTO-01 | P1 | [待实施] | 多语言协议同步 | `binary_trace_format.h` 定义设备端 QTRB；`scripts/trace_binary.py`、`scripts/flight_trace.py` 和 Rust `qtrace-provider` 分别解析同一格式。现有差分 fixture 已覆盖不少情况。 | 给每次协议变更加入跨语言兼容矩阵：C++ encoder 产物由 Python/Rust 读取，旧版本及 malformed fixture 保持固定；优先生成常量/规范，不生成相互依赖的解析器。 | 确认多实现 |
| QA-01 | P1 | [已验收·小米当前环境] | 真实采集到 UI | 新 offset/symbol、monitor-exit 与 Flight 四份 session 均通过真实设备采集、离线逐事件核对、完整分页、分析抽样及缓存重开；在 Chromium 与真实 Rust 服务中完成分页、筛选、寄存器/调用树/内存、标注及服务重启恢复。新 Flight 为 1,185,909 个事件，已修复有序内存候选重复排序；历史 Flight 与 monitor-exit 也复验通过。 | 当前环境功能链路已验收。完整历史设备性能门禁、原生文件对话框及高缩放/键盘布局检查不属于本次证明；保留产物的真实完整性状态。 | [小米新采集及浏览器验收](../../benchmarks/qtrace-xiaomi-capture-2026-10-19.json)；此前 [预算验收](../../benchmarks/qtrace-capture-budget-2026-10-19.json) 与 [历史产物浏览器记录](../../benchmarks/qtrace-browser-acceptance-2026-10-19.json) 保留 |
| QA-02 | P1 | [已实现·待复验] | 性能门禁漂移 | `performance_gate.py` 已有 --diagnostic 与 --diagnostic-baseline，同机/同语料比较、五轮校验，并拒绝覆盖 tracked reference 文件。提交 `2a6004c`。 | 复验同机前后比较与 host/corpus mismatch 拒绝路径。README 已写本机流程；官方验收继续使用固定主机，不将诊断结果升级为门禁通过。 | 确认实现；工具待复验 |
| SCALE-01 | P2 | [待实施] | 行数上限 | `dto.rs:186,220,231,237` 与 `service.rs:221,386,395-438` 将事件数、source row、total/start 限为 `u32`；部分摘要溢出时饱和为 `u32::MAX`。 | 明确支持上限并在打开前报结构化错误，或整体迁到字符串化 `u64` DTO；不能只放宽一个字段。以超过 2³² 行的模拟 view 测协议，不必生成巨型文件。 | 确认 |
| SCALE-02 | P2 | [部分完成] | 大型分析结果 | 调用树已按 100 个节点分页并校验分页 identity；`list_symbols` 等数组输入及 IPC 输出体积仍需统一核对。 | 复验跨页导航，并对其余 IPC 命令统一审计输入数组、输出字节、节点数与超时预算。大结果优先分页或流式 job；恶意参数不能造成无界单次 DTO。 | 调用树分页已实现；其余边界待审计 |
| MAINT-01 | P2 | [待实施] | 大模块边界 | `timeline.rs` 约 5,457 行（后段含单元测试），`index/mod.rs` 约 2,798 行，`tracer_entry.cpp` 约 2,157 行，`flight/recovery.rs` 约 2,182 行。 | 按状态/不变量和依赖方向抽出内部模块；先固定行为测试，再分批移动代码。验收看接口清晰和调用路径，而非行数下降。 | 确认规模，设计待定 |
| MAINT-02 | P2 | [待实施] | 前端状态所有权 | `App.tsx` 同时管 workspace、projection、分页、缓存、历史、详情和标注；已有 generation 竞态测试较多。 | 将分页导航、详情加载和持久编辑拆为独立 hooks/控制器，统一 stale-response 规则；每次重构保留 e2e/workspace 竞态用例。 | 确认职责集中 |
| QA-03 | P2 | [待实施] | fuzz 覆盖 | 定期 fuzz 工作流只跑 QTRB、Flight 两个目标（`.github/workflows/qtrace-ui-fuzz.yml`）；cache manifest、session report、annotation 数据库也是不可信输入。 | 根据事故/攻击面为这些边界增加结构化 corpus 和 bounded fuzz/property tests；在 CI 时间预算内先做离线短跑。 | 确认覆盖范围 |
| OPS-01 | P2 | [待实施] | 验收证据容量 | `qtrace-acceptance-evidence/` 和 `qtrace-acceptance-failures/` 留有多个本地目录；README 明确脚本不会自动删除。 | 提供只读目录清单与人工保留策略，再加显式 opt-in 清理命令；默认绝不删除失败证据。 | 确认现状 |
| UI-09 | P1 | [已验收·本机] | 首次分析取消 | `Workspace` 持有独立生命周期取消令牌；寄存器回放与调用树首次构建、状态查询绑定同一令牌，关闭与服务取消可中止持有 Arc 的构建。保留共享 slot 的单次构建与完整结果复用。 | 等待 slot 的两个回归用例修复前在关闭后仍返回成功，修复后返回 `job.cancelled`。真实 Flight 的两个构建运行 20 ms 后关闭，release 单次分别在 9.2 / 16.9 ms 内退出，slot 保持空且 Weak store 引用释放。原 512 MiB 构建预算及共享/并发/释放回归保留；非延迟门禁。 | [长任务优化与验收](../../benchmarks/qtrace-long-operations-2026-10-19.json) |
| UI-10 | P1 | [待实施] | 调用树页面内存 | `CallTreePane.tsx` 将加载页面 concat 到 Map，折叠仅移除 expanded；虚拟渲染限制 DOM，但已加载节点及每次 useMemo 的遍历仍随累计展开增长。 | 测持续展开/折叠的 heap 和帧时间；若达到预算，增加节点/字节上限与可重取的页面淘汰策略。保留 identity 校验、父子导航和滚动定位，不把 DOM 有界当成内存有界。 | 确认累积；收益待测 |

## 4. 推荐实施顺序

1. **后续交互复验。** PERF-01/PERF-02 当前环境验收已完成，见 [当前基线](../../benchmarks/qtrace-ui-performance-current.md)。UI-01–05 按表复验，不重新实现。
2. **后续索引测量。** PERF-02 与 PERF-03 本机五轮对比已完成；以保存的事件键、section 与 catalog 阶段数据评估 STORE-01，另行分析 rich service 的累计预算边界。
3. **继续交互边界。** UI-07 的加载进度与 UI-09 的关闭取消已验收；下一步先测 UI-10 累计页面内存，再处理 UI-06 请求所有权和 UI-08 可访问性。
4. **设备与跨层验证。** QA-01 已有小米新采集到浏览器的功能证据，后续改动沿用同样方法回归；CORE-01 先设备采样；CLI-01/02 和 PROTO-01 用故障矩阵及跨语言 fixture 约束改动。
5. **长期规模与维护。** 最后处理行数上限、巨型模块、额外 fuzz、证据保留及 STORE-02 并行打开；每项先证明成本，再设计边界。

## 5. 统一验收规则

- 性能改动使用相同 corpus、同一机器、至少五轮原始样本和中位数；固定主机报告继续要求身份一致。记录峰值 RSS、冷/热打开、查询 p95、缓存大小及正确性摘要。
- tracer 改动使用同一设备、同一目标构建和现有 historical benchmark；指令数、返回值、QTRB/Flight 完整性、sidecar 与压缩产物必须一致。
- UI 改动检查单文件降级、session 上下文、未知/损坏证据、取消/切换竞态、键盘可达性和高缩放；页面与 DOM 不随总 trace 行数增长。
- store/CLI 改动沿用资源预算、路径与身份校验、原子发布及故障注入。任何取消或失败都不能留下“看似成功”的缓存或报告。
- 文档中的“确认”只证明存在可优化路径；性能和体验收益必须由对应门禁验证。没有测量收益的候选项不应被描述为回归或缺陷。
