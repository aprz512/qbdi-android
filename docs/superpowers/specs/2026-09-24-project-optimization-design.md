# 项目整体优化机会清单

**首次整理：** 2026-09-24

**状态更新：** 2026-10-19（基于 HEAD `72548df` 的 `perf/complete-optimization-2026-10-19` 工作区；28 项均完成其记录范围内的实施或复验）

**性质：** 持续维护的优化清单；实施与验收状态以各条目及对应证据为准

**范围：** Android 演示应用、native tracer、Python `qtrace` CLI/脚本、QTRB/Flight 协议、`qtrace-ui` Rust/React/Tauri、测试与发布流程。

## 1. 审查结论

仓库的主链路是 `app` 演示目标、`tracer` 设备端采集、`qtrace` 主机编排与产物发布，以及 `qtrace-ui` 离线分析。`qtrace-ui` 已采用 provider → store → analysis → service → Tauri/React 的分层；host CI、定期 fuzz、固定主机性能门禁和手动设备门禁都已存在。优化应先解决已经能从代码或现有证据确认的高成本路径，再处理结构复杂度；不要为了减小代码量削弱身份校验、预算、取消、完整性或原子发布。

本轮已完成清单全部待实施、部分完成和待复验条件。新增源键隐式索引、共享预算的双 artifact 打开、完整 IPC 边界、Full collector 常量 fallback、Flight 空间预检、产物事务模块化、进程故障矩阵、跨语言 encoder 契约、存储 fuzz、布局与前端请求所有权。寄存器、调用树、摘要、ELF 更新、session 降级、跨页命中、关闭和持久化均已复验。

验收范围按证据区分：本机 Chromium/Rust、Pixel 6 五轮 benchmark，以及保留小米产物的 provider/service/浏览器回归。历史参考门槛与原始证据保留；诊断结果没有升级为固定主机门禁，也没有声称已测 WebKit、原生系统缩放、设备掉电持久性或远程 CI。完整命令、状态和报告映射见 [本轮总验收](../../benchmarks/qtrace-project-optimization-2026-10-19.md)。

### 证据边界

- 本轮完成：Rust 全量 520 通过、2 个环境依赖测试保持 ignored；Python 全量 858 项检查通过、8 skipped；前端 76 单测、14 E2E、1 production、build/lint 通过；native 45/45 和 Android app/tracer 构建通过。真实 C++/Python/Rust 矩阵、五个 ASan target、存储 property 及结构后 Flight ASan 均通过。源码身份、测量校正和范围限制见 [总验收](../../benchmarks/qtrace-project-optimization-2026-10-19.md)。
- STORE-01/02：10M/512 MiB 同机五轮，源键优化 RSS 中位数 -6.58%、冷开 -2.79%；2/4 artifact 冷开约 -40%、热开约 -46%，峰值 RSS 小幅增加，原累计预算不变。新旧缓存字节相同并互读，无重建。见 [store 与边界报告](../../benchmarks/qtrace-store-boundaries-2026-10-19.md)。
- CORE-01/02：Pixel 6 同 APK/target 前后各三档五轮全部通过；Full 每条回调的 0x524-byte 清零消除。保留默认 512 MiB，13 份真实 Flight 容量/每线程窗口调查、启动低存储注入和正常/未 seal 退出恢复均有证据。31→26 ms 是本批 Full 中位数观测，不声称稳定百分比收益。见 [native 报告](../../benchmarks/qtrace-native-optimization-2026-10-19.md)。
- UI-01–05/UI-08/MAINT-02：最终 50 次真实点击的稳定键和 34+34 寄存器等价；实际组件深宽树 DOM 有界，真实 Rust 5000 层/10000 根树完整分页，六布局场景与键盘焦点通过。摘要、ELF 同 projection 自动刷新、context 降级、真实跨页命中与 workspace 竞态均通过。见 [交互报告](../../benchmarks/qtrace-ui-layout-state-2026-10-19.md)。
- 2026-10-19 UI-06：`TimelinePages` 统一时间线滚动、翻页、跳转和历史恢复的 identity、共享请求与缓存；游标位置随页面淘汰，不再扩展稀疏数组。保留每页 2,000 行、128 页与 32 MiB 计量上限，改用字段长度与对象预留空间计量，取消和新导航不能提交旧响应或旧错误。相同 100k 合成滚动负载前后各五轮，25 个唯一页面的查询从每轮 72 降至 25 次，整页序列化从 53 降至 0 次；视口加载 p95 中位数从 185.5 降至 124.1 ms（-33.10%），GC 后页面 heap 增量从 19,448,228 降至 14,162,728 B（-27.18%），帧时间基本不变，时间线 DOM 最大均为 22 行。固定 60 ms 响应延迟用于制造重叠请求，数字不代表 Rust 或设备速度；heap 变化也受更保守的缓存计量影响。新增 13 项测试、最终 69 项前端测试、15 项 E2E、生产桥接隔离、构建和 ESLint 通过；实际 App 的共享查询回归在原实现上失败。四份小米保留产物通过最终版本与真实 Rust 服务的浏览器复验，包括 1,185,909 事件 Flight 的末页、结果翻页、分析与持久化。没有重新采集，未测 Tauri WebKit 或高缩放布局。见 [方法与范围](../../benchmarks/qtrace-ui-timeline-pages.md) 和 [原始样本及身份](../../benchmarks/qtrace-timeline-pages-2026-10-19.json)。
- 2026-10-19 UI-10：调用树改为每个父节点保留一个至多 100 节点的兄弟窗口，缓存同时限制 8,192 节点与 4 MiB 计量权重；LRU 淘汰可重取分支，清理不可达后代并保护请求的祖先路径。相同合成浏览负载前后各五轮，强制 GC 后的页面 heap 增量中位数从 4,272,520 降至 3,407,176 B（-20.25%），DOM 最大均为 18 个调用节点，帧时间基本不变。计量权重不等于浏览器 heap 限额；祖先路径单独超限时保留当前视图并提示限制，已有 5,000 层路径可保留。双向翻页、滚动、淘汰重取及迟到响应均有回归；原组件的两个交互回归均失败。四份小米保留产物通过真实服务到 Chromium 的调用树展开、折叠、重开及子节点跳转，其他分析与持久化流程也通过。未重新采集、未测 Tauri WebKit 或高缩放布局。方法见 [调用树分页与页面缓存诊断](../../benchmarks/qtrace-ui-call-tree-pages.md)，原始样本与身份见 [UI-10 证据](../../benchmarks/qtrace-call-tree-memory-2026-10-19.json)。
- 2026-10-19 后续长任务优化：相同 10M QTRB / 512 MiB Flight 语料交错各五轮，warm open 中位数 1.167 降至 0.808 秒（-30.75%），冷索引 8.077 降至 7.554 秒（-6.48%），峰值 RSS 基本不变，缓存大小与正确性摘要一致。阶段数据将成本定位到事件键读取/解码；改为事件键与元数据两路解码，再复用第二个 worker 做 checksum，保留全部身份、内容和篡改校验、原累计预算及 schema 2 / layout 3。服务缓存验证采用相同的最多两 worker 边界。打开任务新增七个阶段和字节/事件/行工作量，计数包含重复处理，不推算百分比或剩余时间。真实 1,185,909 事件 Flight 在 Chromium 中验证进度更新、建索引取消不发布工作区或缓存、重试与缓存重开；四份小米产物再次通过离线逐事件、分页与分析核对。工作区关闭绑定寄存器/调用树首次构建的取消令牌，release 单次取消后分别约 9.2 / 16.9 毫秒退出，缓存保持空且 store 引用释放；这不是取消延迟门禁。Rust 全工作区、最终 service 套件、clippy/fmt、生成物、前端 45 项测试、15 项 E2E 与生产桥接隔离通过。原始样本、源码/二进制身份、回归及截图见 [长任务优化与验收](../../benchmarks/qtrace-long-operations-2026-10-19.json)。这是本机对比与保留产物功能验收，未覆盖新的设备性能、rich 性能门禁或高缩放布局；固定参考报告保持不变。
- 2026-10-19 小米新采集验收：用户允许 Shell root 后，在 `M2011K2C`（`2d32ed71`、Android 16、Frida host/server 17.24.2）完成四份新 session。offset/symbol timed 各 987 个事件，均按原生 2 秒期限停止，应用仍存活，计算结果与本轮无追踪基线一致；monitor-exit 为 1,714 个事件；64 MiB Flight 恢复为 1,185,909 个事件，保留崩溃后的完整性缺口及未知终止原因。四份产物均通过逐事件离线核对、完整分页、分析抽样和缓存重开；随后通过 Chromium 与真实 Rust 服务完成上下文、筛选、寄存器、调用树、内存及历史、标注、高亮与服务重启恢复，Flight 另覆盖跨页与末页定位，均无接口或页面错误。新 Flight 暴露的有序内存候选重复排序已修复，原 100,000 Nodes 与 2,000 返回行限制保留。Rust 全工作区测试、clippy、fmt 均通过。首次目录缺失的失败证据和旧目录备份均保留；成功重试沿用现有设备门禁的目录准备流程。身份、命令、回归测试、截图及 trace 哈希见 [小米新采集与浏览器验收](../../benchmarks/qtrace-xiaomi-capture-2026-10-19.json)。本轮为功能验收，未重跑完整历史五轮设备性能门禁。
- 2026-10-19 较早的浏览器验收：前端 14 项工作区/持久化 E2E 与 1 项生产构建桥接隔离测试通过。另用 Chromium 153.0.8010.12，通过现有认证 loopback adapter 连接实际 Rust 服务，对历史 Flight 与 monitor-exit 报告完成真实界面操作，无响应 mock：核对上下文、事件总数与筛选，Flight 跨结果页并跳到末页，查询寄存器、调用树、内存及历史，保存标注和高亮，重启服务后验证缓存与持久化数据。两份真实产物均无接口或页面错误。该次小米预检的 `run-as` 可用，但 Magisk 仍拒绝 Shell root，因此只验证历史产物；后续新采集见上一条。原记录保留当时的设备状态和产物身份，见 [浏览器与小米预检记录](../../benchmarks/qtrace-browser-acceptance-2026-10-19.json)。
- 2026-10-19 后续修复：历史 Flight 与 monitor-exit 真实 session 均通过 `verify_capture` 的冷开、provider/store 逐事件核对、完整分页、筛选、寄存器/调用树/内存抽样，以及进程重启后的缓存重开核对。Flight 为 64 MiB、1,133,180 个事件；monitor-exit 为 1,714 个事件。输入额度按实际读取次数推导；保留索引/缓存 2 GiB、寄存器回放 512 MiB、交互 100,000 Nodes 与 2,000 返回行限制。修复范围、源码身份和验收摘要见 [离线链路预算验收](../../benchmarks/qtrace-capture-budget-2026-10-19.json)。这证明历史产物的离线服务链路可用，尚不能替代新的设备采集和浏览器验收。
- 2026-10-19 第一阶段：针对历史 Flight 的 discovery 累计分配超限，改用行号基数排序和原地置换，跨 chunk 复用事务扫描缓冲，无序号冲突时直接保留原事件表。同一 64 MiB、1,133,180 个输出事件的真实产物，前后各五轮：provider 恢复耗时中位数 3.059 降至 1.642 秒（-46.3%），整个诊断进程峰值 RSS 中位数 857.87 降至 643.29 MiB（-25.0%），累计 resident 授权量 5.588 降至 1.881 GiB（-66.3%）；事件与 summary 的联合哈希全部一致。原 2 GiB provider 预算由失败转为通过，32 MiB 小语料回归、稳定排序属性测试、取消/释放、分配授权及 Rust 全工作区检查通过。该阶段仍卡在建索引输入预算，后续修复见上一条。原始样本、命令和被测源码身份见 [第一阶段 Flight 证据](../../benchmarks/qtrace-flight-recovery-2026-10-19.json)。这些五轮性能数字属于第一阶段源码，不能视为后续修复版本的重新测量；未测量 tracer 吞吐。
- 2026-10-18：新增真实 session 的 provider/store/service 离线验证工具，修复 native LZ4 skippable 填充帧拒读、选择 `report.json` 时误用报告大小限制整个会话，以及压缩输入未计入解码后 QTRB 读取量三个问题。历史设备门禁的 offset/symbol 产物通过逐事件、分页、分析抽样与缓存重开核对；monitor-exit 内存查询和 Flight discovery 仍分别触及现有行数、累计内存预算，因此 QA-01 仅标为部分完成。小米 `M2011K2C` 的五个无追踪界面场景与 timed oracle 通过；`su` 被 Magisk 拒绝，未完成该设备的 Frida 采集。命令、身份、哈希及边界见 [本轮验证记录](../../benchmarks/qtrace-device-validation-2026-10-18.json)。本轮没有测量 tracer 吞吐收益。
- 初始审查以 `bdc266a` 为基点，随后核对 `5dbff3a`、关键实现和提交记录。当时工作区有三个未提交文件：`qtrace-store/src/index/mod.rs`、`index/wire.rs`、`tests/index_equivalence.rs`。`ffda405` 的大事件表有界编码与后续提前释放源事件表等改动已整合进 `f4cf92b`，并通过本机测试与性能对比。随后按用户指示采用当前环境，规模门禁通过；历史基线保留，新增当前环境基线。
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

两份真实产物均在全新缓存目录运行，冷开与重启后重开结果等价。Flight 冷开/重开分别为 8.230/4.659 秒，monitor-exit 为 0.015/0.005 秒；这是单次诊断，包含完整校验的服务打开，不是固定主机性能门禁。Rust 全工作区测试、clippy、fmt 和差异空白检查均通过。验收工具及可复现命令见 [qtrace-ui 开发指南](../../../qtrace-ui/docs/development.md#captured-session-verification)，事件计数、摘要、命令和检查结果见 [预算验收记录](../../benchmarks/qtrace-capture-budget-2026-10-19.json)。

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
- `[已验收·Pixel 6 当前环境]`：同一 Pixel 6、固定 APK/target 的五轮 profile benchmark 及事实/压缩门禁通过；不推广为其他设备的稳定吞吐保证。
- `[暂缓]`：需记录暂缓原因与重新评估条件；不因缺少设备自动标为暂缓。

本次共 28 项：24 项 `[已验收·本机]`、2 项 `[已验收·当前环境]`、1 项 `[已验收·小米当前环境]`、1 项 `[已验收·Pixel 6 当前环境]`；没有待实施、部分完成或待复验条目。

状态与证据强度独立。更新时保留 ID，记录日期、提交或报告路径；不得以提交存在代替性能收益证明。

优先级：P0 是当前功能成本或体验的明显瓶颈；P1 需要测量或局部设计；P2 是规模扩展和维护性工作。证据强度：“确认”表示代码直接显示行为；“待测”表示值得验证的假设。每项的验收条件是本轮实施与复验的停止标准；本轮已逐项满足并记录证据。

| ID | 优先级 | 状态 | 方向 | 当前实现 | 实施与验收结果 | 证据 |
| --- | --- | --- | --- | --- | --- | --- |
| UI-01 | P0 | [已验收·本机] | 寄存器交互 | artifact 懒建并共享 Arc<RegisterReplay>，关闭取消并释放；详情请求由 useEventDetails 统一持有。 | 同一真实 1,185,909 事件 Flight 连续点击 50 次，稳定键、34 before + 34 after 与 DOM 68 格全部等价；最终寄存器 DOM p95 902.2 ms（含自动化，非纯 IPC 或收益比较）。Rust 证明共享、并发等价和 Arc 释放。 | [布局与交互复验](../../benchmarks/qtrace-ui-layout-state-2026-10-19.md)；[store 与资源边界](../../benchmarks/qtrace-store-boundaries-2026-10-19.md) |
| UI-02 | P0 | [已验收·本机] | 调用树规模 | 后端缓存整树、100 siblings 分页并校验 identity；前端有界缓存和虚拟渲染。 | 真实 Rust 5000 层/10000 根树各五轮完整遍历、来源跳转和 stale 拒绝；首次构建中位 13.114 / 35.781 ms，最大 IPC 367 / 19077 B。组件 512 层/10000 根场景 DOM 最多15/13行；缓存 Arc 复用与关闭释放通过。 | [布局与交互复验](../../benchmarks/qtrace-ui-layout-state-2026-10-19.md)；[store 与资源边界](../../benchmarks/qtrace-store-boundaries-2026-10-19.md) |
| UI-03 | P0 | [已验收·本机] | 时间线可读性 | location/symbol/summary 有界显示，typed detail 保持来源；ELF 附加后主动刷新当前 projection 页面。 | 真实 instruction/memory/semantic/discontinuity 摘要对齐，损坏与缺口明确；有效 AArch64 ELF 自动更新 native_work+0x5，键/位置/捕获摘要不变；错误 digest 和迟到 Attach 不污染当前页。 | [布局与交互复验](../../benchmarks/qtrace-ui-layout-state-2026-10-19.md) |
| UI-04 | P0 | [已验收·本机] | Session 上下文 | SessionOverview 展示真实 context 与 missing capabilities，不伪造缺失配置。 | 报告 context 与真实保留报告完全一致；同 SHA Flight 单文件打开 context=null，明确 unavailable 且仍可查询；损坏 artifact 隔离与健康时间线可用。 | [布局与交互复验](../../benchmarks/qtrace-ui-layout-state-2026-10-19.md) |
| PERF-01 | P0 | [已验收·当前环境] | 性能语料 | 流式生成 100k/1M/10M 富事件；100k、1M 固定语义哈希；独立 Flight 四线程与缺口 oracle。rich gate 五轮测 store/analysis、回放等价和 IPC；真实 service 到 UI 测 50 次筛选。CI 已接入正式参考主机运行和证据上传。 | 本机五轮和 UI 已通过，详见 [报告](../../benchmarks/qtrace-ui-optimization-2026-09-26.md)。当前环境规模门禁通过，原阈值保持不变；历史基线保留。1M store/analysis 与 100k IPC/UI 分开计量；1M service 累计 2 GiB budget 拒绝，未放宽预算。 | 实现与当前环境验收通过 |
| PERF-02 | P0 | [已验收·当前环境] | 冷索引内存 | EventColumn 复用 EventKey 坐标，56 B 降为 24 B；posting 直接编码 runs；编码后释放事件表。保留原二分查找，并通过等价、取消、预算、篡改和原子发布测试；缓存布局未变，旧缓存重开通过。 | 相同 10M/512 MiB 语料前后各五轮：RSS 中位数 1464.30 降至 1158.96 MiB（-20.85%），耗时 10.304 降至 9.508 s（-7.73%），摘要一致。达到本机下降 ≥10%、耗时回退 ≤10% 条件；当前环境规模门禁另行通过（冷 8.308 s、热 1.130 s、RSS 1158.95 MiB）。见 [报告](../../benchmarks/qtrace-ui-optimization-2026-09-26.md)。 | 本机收益与当前环境门禁通过 |
| PERF-03 | P1 | [已验收·本机] | warm open | 新增 `QTRACE_UI_OPEN_PROFILE` 的哈希、身份、事件行、section checksum 与 catalog 阶段测量；事件键和元数据独立解码，再以第二个 worker 校验 checksum。源与缓存校验保留，服务每 artifact 最多两个 worker。 | 相同 10M/512 MiB 语料各五轮：热开 1.167 降至 0.808 秒（-30.75%），冷索引 8.077 降至 7.554 秒（-6.48%）；RSS 基本不变，缓存大小和摘要一致。已有缓存及顺序/并行篡改、预算、取消与原子发布测试通过。参考报告未替换；不将这些数字当作完整服务或 UI 延迟。 | [长任务优化与验收](../../benchmarks/qtrace-long-operations-2026-10-19.json) |
| UI-05 | P1 | [已验收·本机] | 查询结果分页 | ResultsPane 独立保存页面、游标和 hit，使用 query/locate 跨页。 | 真实 Flight 超过357k instruction命中，双向页面及跨页 hit 稳定；空结果禁用导航；延迟真实旧页后关闭、重开，旧响应不改变新页/busy/error。 | [布局与交互复验](../../benchmarks/qtrace-ui-layout-state-2026-10-19.md) |
| UI-06 | P1 | [已验收·本机] | 数据请求所有权 | `TimelinePages.ts` 按 workspace/projection/generation 管理共享查询、定位、导航所有权和 LRU；游标位置随缓存淘汰。字段长度计量替代整页 JSON，保留每页 2,000 行、128 页和 32 MiB 上限；关闭与切换拒绝旧响应。 | 同一 100k 合成负载前后各五轮，页面查询每轮 72 降至 25，整页序列化 53 降至 0；视口加载 p95 中位数 -33.10%，heap 增量 -27.18%，frame p95 均为 16.8 ms，DOM 最大 22 行。13 项新增测试及四份小米保留产物最终浏览器回归通过。权重不等于 heap 限额；合成延迟不代表 Rust/设备性能，Tauri WebKit 和高缩放未测。 | [方法](../../benchmarks/qtrace-ui-timeline-pages.md)；[原始证据](../../benchmarks/qtrace-timeline-pages-2026-10-19.json) |
| UI-07 | P1 | [已验收·本机] | 加载反馈 | 打开任务报告源验证、缓存验证、建索引、缓存发布、缓存重开、分析准备与工作区发布；artifact 总数独立保留。阶段工作量按块合并，分析准备也报告行工作量；分配授权区间内仅记录计数，延迟通知分配。界面显示 `Cancelling…`，提交失败可重试。 | 真实 1,185,909 事件 Flight 的 Rust/Chromium 链路覆盖七阶段、单文件索引中的变化、取消后无工作区/缓存、重新打开和缓存重开。单文件取消保持 `job.cancelled`；字节/事件/行数包含重复处理，不表示唯一覆盖率或 ETA。 | [长任务优化与验收](../../benchmarks/qtrace-long-operations-2026-10-19.json) |
| UI-08 | P1 | [已验收·本机] | 布局与可访问性 | 宽屏三栏；1100px以下重排，700px以下单列；长文本换行、树缩进有界，增加面板键盘入口及焦点轮廓。 | 800/1024/1366px 与对应200%等效400/512/683 CSS px共六场景均无页面/详情横向溢出；四面板实际 Tab/Enter 可达，焦点可见。未声称原生浏览器缩放或WebKit实测。 | [布局与交互复验](../../benchmarks/qtrace-ui-layout-state-2026-10-19.md) |
| STORE-01 | P1 | [已验收·本机] | 源键索引 | SourceKeyIndex 拥有隐式有序映射与非单调显式排列；排序归属 index/sorting.rs。 | 10M/512MiB 五轮 RSS -6.58%、冷开 -2.79%；schema/wire bytes不变，新旧互读且不重建；重复键、owned/mapped、非单调Flight、预算和取消通过。 | [store 与资源边界](../../benchmarks/qtrace-store-boundaries-2026-10-19.md) |
| STORE-02 | P1 | [已验收·本机] | 多 artifact 打开 | opening.rs 每批最多两个 worker，共享原 source/cache 累计预算，按报告次序合并。 | 2/4个100k富artifact前后各五轮冷开约快40%、热开约快46%，RSS小幅增加；顺序/事实/失败隔离保持。panic及创建失败先join，控制错误不发布workspace。 | [store 与资源边界](../../benchmarks/qtrace-store-boundaries-2026-10-19.md) |
| CORE-01 | P1 | [已验收·Pixel 6 当前环境] | tracer 热路径 | 按simpleperf三档采样选择Full collector；静态只读fallback消除每次重复构造，不削减必要内存读取。 | Pixel6同APK/target前后各三档五轮全部通过；30份trace指令/寄存器/内存形状、return、footer/sidecar和压缩门禁一致。Full栈临时区0x780降至0x1d0，0x524清零消失；31到26ms仅本批中位观测。 | [native 报告](../../benchmarks/qtrace-native-optimization-2026-10-19.md) |
| CORE-02 | P1 | [已验收·本机] | Flight 默认容量 | 默认512MiB、固定环语义及已有64–2048MiB配置保留；同文件描述符上增加fstatvfs空间预检。 | 13份真实环占用与每线程序号窗口调查支持保留默认值；不能从无事件时钟的数据伪造秒级窗口。低空间/EIO注入零遗留，默认512MiB正常关闭和未seal退出的Python恢复通过，Android构建通过。 | [native 报告](../../benchmarks/qtrace-native-optimization-2026-10-19.md) |
| CLI-01 | P1 | [已验收·本机] | 产物发布复杂度 | artifacts facade保留编排，远端读取、验证、原子发布、报告刷新分别归属四个内部模块，descriptor/token转移有所有权图。 | 公开CLI、恢复和提交边界保持；原82项产物故障注入及369项相关Python通过，全量858项检查通过（8skip）。 | [CLI/OPS 报告](../../benchmarks/qtrace-cli-optimization-2026-10-19.md) |
| CLI-02 | P1 | [已验收·本机] | 子进程边界 | 沿用bounded_process；Frida失败清理绑定原session脚本RPC及process-terminated回执，无法确认时明确cleanup_incomplete。 | 六真实命令入口×超时/取消/ADB断连/PID复用/输出上限/孤儿共36格通过；不使用裸PID猜杀。原实现反证、实际本机及Pixel原session退出验证通过。 | [CLI/OPS 报告](../../benchmarks/qtrace-cli-optimization-2026-10-19.md) |
| PROTO-01 | P1 | [已验收·本机] | 多语言协议同步 | 真实C++ encoder四产物与常量/固定字节契约，由独立Python/Rust读取；CI接入兼容矩阵。 | 37个exporter fixture，Python16/Rust25矩阵通过；QTRB1.0–1.2、Flightv2及malformed固定证据保留，encoder重复生成逐字节一致。 | [协议/fuzz 报告](../../benchmarks/qtrace-protocol-fuzz-2026-10-19.md) |
| QA-01 | P1 | [已验收·小米当前环境] | 真实采集到 UI | 新 offset/symbol、monitor-exit 与 Flight 四份 session 均通过真实设备采集、离线逐事件核对、完整分页、分析抽样及缓存重开；在 Chromium 与真实 Rust 服务中完成分页、筛选、寄存器/调用树/内存、标注及服务重启恢复。新 Flight 为 1,185,909 个事件，已修复有序内存候选重复排序；历史 Flight 与 monitor-exit 也复验通过。 | 当前环境功能链路已验收。完整历史设备性能门禁、原生文件对话框及高缩放/键盘布局检查不属于本次证明；保留产物的真实完整性状态。 | [小米新采集及浏览器验收](../../benchmarks/qtrace-xiaomi-capture-2026-10-19.json)；此前 [预算验收](../../benchmarks/qtrace-capture-budget-2026-10-19.json) 与 [历史产物浏览器记录](../../benchmarks/qtrace-browser-acceptance-2026-10-19.json) 保留 |
| QA-02 | P1 | [已验收·本机] | 性能门禁漂移 | diagnostic按host/generator/corpus比较，不读写参考摘要或覆盖tracked reference。 | 当前10M五轮before/after经生产比较器通过；host/corpus/wrong oracle/reference mode与覆盖拒绝测试通过。原参考SHA与阈值不变，本机诊断不升级为固定主机通过。 | [store 与资源边界](../../benchmarks/qtrace-store-boundaries-2026-10-19.md) |
| SCALE-01 | P2 | [已验收·本机] | 行数上限 | metadata view在分析准备和workspace发布前检查单artifact的u32协议上限，摘要/位置一律checked转换。 | 4,294,967,295可表达；超过2³²行的模拟view仅读取计数即返回workspace.event_limit_exceeded，任何行访问均被测试禁止；不生成巨型文件、不饱和。既有资源预算仍更早约束实际规模。 | [store 与资源边界](../../benchmarks/qtrace-store-boundaries-2026-10-19.md) |
| SCALE-02 | P2 | [已验收·本机] | 大型分析结果 | 25个IPC命令统一审计，数组/文本visitors和service双层验证，JSON Write counter限16MiB；jobs最多8active/512retained。 | 保留timeline2000行、calltree100节点、symbols2000PC；SQLite绑定交互预算/VM轮询/workspace取消；过大输入不改变generation/jobs或访问文件，输出转义和恶意size hint回归通过。 | [store 与资源边界](../../benchmarks/qtrace-store-boundaries-2026-10-19.md) |
| MAINT-01 | P2 | [已验收·本机] | 大模块边界 | 提取timeline discontinuity与semantic executor、Flight emergency选择、index源键/排序和native JSON endpoint。 | 公开接口、配置mutex、activation顺序、信号和恢复规则保持；同一行为套件前后通过，逐函数规范化对比一致。Rust全量520、native45、Android全构建及结构后ASan/矩阵通过。 | [模块边界证明](../../benchmarks/qtrace-module-boundaries-2026-10-19.md)；[store 与资源边界](../../benchmarks/qtrace-store-boundaries-2026-10-19.md) |
| MAINT-02 | P2 | [已验收·本机] | 前端状态所有权 | App组合界面；导航、详情、持久编辑分属三个hooks，RequestScope统一成功/错误迟到规则。 | 原69单测与14E2E基线保留；新增标注竞态和ELF刷新回归具旧实现失败证明。最终76单测、14E2E、1production及四保留产物浏览器全部通过。 | [布局与交互复验](../../benchmarks/qtrace-ui-layout-state-2026-10-19.md) |
| QA-03 | P2 | [已验收·本机] | fuzz 覆盖 | 新增cache manifest/session report/annotations三个target、结构化corpus与有界property；PR/push短跑，定时/手动长跑。 | 三个存储target覆盖input/row/node/resident/cancel与SQLite VM/rollback；64case property通过。五target ASan925984输入、结构后Flight324353输入，零crash；CI已配置，未声称托管执行。 | [协议/fuzz 报告](../../benchmarks/qtrace-protocol-fuzz-2026-10-19.md) |
| OPS-01 | P2 | [已验收·本机] | 验收证据容量 | qtrace_evidence.py提供只读inventory、保留/保护策略与显式opt-in清理，默认保护失败证据。 | 真实目录只读统计；2份成功约1.46GB、24份失败约3.61GB。所有删除回归仅临时目录，实际旧成功/失败证据未删除。 | [CLI/OPS 报告](../../benchmarks/qtrace-cli-optimization-2026-10-19.md) |
| UI-09 | P1 | [已验收·本机] | 首次分析取消 | `Workspace` 持有独立生命周期取消令牌；寄存器回放与调用树首次构建、状态查询绑定同一令牌，关闭与服务取消可中止持有 Arc 的构建。保留共享 slot 的单次构建与完整结果复用。 | 等待 slot 的两个回归用例修复前在关闭后仍返回成功，修复后返回 `job.cancelled`。真实 Flight 的两个构建运行 20 ms 后关闭，release 单次分别在 9.2 / 16.9 ms 内退出，slot 保持空且 Weak store 引用释放。原 512 MiB 构建预算及共享/并发/释放回归保留；非延迟门禁。 | [长任务优化与验收](../../benchmarks/qtrace-long-operations-2026-10-19.json) |
| UI-10 | P1 | [已验收·本机] | 调用树页面内存 | `CallTreePages.ts` 限制 8,192 节点和 4 MiB 计量权重；每个父节点一个至多 100 节点的兄弟窗口，LRU 淘汰后可重取，回收不可达后代并保护祖先路径。`CallTreePane.tsx` 保留身份/上下文校验、请求合并、双向翻页、滚动锚点与事件跳转。 | 相同负载前后各五轮，页面 heap 增量中位数 4.07 降至 3.25 MiB（-20.25%），DOM 最大均为 18 节点，帧时间基本不变。11 项新增测试与四份小米保留产物浏览器回归通过，5,000 层路径可保留；单独超限的祖先路径拒绝新增页面。计量权重不等于实际 heap 上限；未测 Tauri WebKit 与高缩放布局。 | [方法](../../benchmarks/qtrace-ui-call-tree-pages.md)；[原始证据](../../benchmarks/qtrace-call-tree-memory-2026-10-19.json) |

## 4. 本轮完成与后续维护

本轮实施计划与验收均已完成，见 [实施计划](../plans/2026-10-19-complete-project-optimization.md) 和 [总验收报告](../../benchmarks/qtrace-project-optimization-2026-10-19.md)。所有原始产物、历史参考、失败证据和本次测量校正均保留；改动未自动提交或推送。

今后的新协议、新负载、其他设备、不同最小保留窗口或打包WebKit要求，继续沿用以下验收规则独立评估。本轮未覆盖的平台或耐久性不因此被描述为已通过。

## 5. 统一验收规则

- 性能改动使用相同 corpus、同一机器、至少五轮原始样本和中位数；固定主机报告继续要求身份一致。记录峰值 RSS、冷/热打开、查询 p95、缓存大小及正确性摘要。
- tracer 改动使用同一设备、同一目标构建和现有 historical benchmark；指令数、返回值、QTRB/Flight 完整性、sidecar 与压缩产物必须一致。
- UI 改动检查单文件降级、session 上下文、未知/损坏证据、取消/切换竞态、键盘可达性和高缩放；页面与 DOM 不随总 trace 行数增长。
- store/CLI 改动沿用资源预算、路径与身份校验、原子发布及故障注入。任何取消或失败都不能留下“看似成功”的缓存或报告。
- 文档中的“确认”只证明存在可优化路径；性能和体验收益必须由对应门禁验证。没有测量收益的候选项不应被描述为回归或缺陷。
