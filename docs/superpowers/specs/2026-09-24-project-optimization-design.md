# 项目整体优化机会清单

**日期：** 2026-09-24  
**性质：** 代码与结构审查；供后续逐项设计和实施，不代表这些改动已经完成  
**范围：** Android 演示应用、native tracer、Python `qtrace` CLI/脚本、QTRB/Flight 协议、`qtrace-ui` Rust/React/Tauri、测试与发布流程。

## 1. 审查结论

仓库的主链路是 `app` 演示目标、`tracer` 设备端采集、`qtrace` 主机编排与产物发布，以及 `qtrace-ui` 离线分析。`qtrace-ui` 已采用 provider → store → analysis → service → Tauri/React 的分层；host CI、定期 fuzz、固定主机性能门禁和手动设备门禁都已存在。优化应先解决已经能从代码或现有证据确认的高成本路径，再处理结构复杂度；不要为了减小代码量削弱身份校验、预算、取消、完整性或原子发布。

本轮最高优先级是：**复用寄存器回放索引、限制调用树传输与渲染、让时间线展示可分析的信息、补齐 session 上下文，以及建立有代表性的性能语料。** 当前大规模性能门禁虽通过，但它不能替代这些交互和真实事件负载的验证。

### 证据边界

- 本文以 `bdc266a` 为已提交基点；审查时工作区有三个未提交文件：`qtrace-store/src/index/mod.rs`、`index/wire.rs`、`tests/index_equivalence.rs`。其中 `wire.rs` 包含上一轮“事件分区编码后提前释放源表”的改动。本文将它视为正在验证的工作，不重复列为待实现功能。
- 已有固定主机基线：1000 万 QTRB 事件、512 MiB Flight，冷索引中位数约 8.35 秒、warm open 约 1.29 秒、冷索引峰值约 1.77 GB，门禁为 30 秒、2 秒、2 GiB；见 `docs/benchmarks/qtrace-ui-performance.md`。这份结果对应旧提交和旧主机身份，不等于当前工作区的回归结果。
- 上一轮在当前机器生成相同规格语料后，单次冷索引峰值从 1,733,264 KiB 降至 1,654,848 KiB；改动后五次约 1,616 MiB 且摘要一致。固定参考主机身份校验在当前机器失败，因此这些数字只用于发现方向，不能替代固定主机验收。
- 本轮以静态代码审查和已有测试/报告为主；没有设备采样、用户交互追踪或新的 CPU flamegraph。标记为“待测”的收益不能当作已证明收益。

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

优先级：P0 是当前功能成本或体验的明显瓶颈；P1 需要测量或局部设计；P2 是规模扩展和维护性工作。证据强度：“确认”表示代码直接显示行为；“待测”表示值得验证的假设。每项的验收条件是后续实施的停止标准，不要求本轮全部执行。

| ID | 优先级 | 方向 | 机会与代码依据 | 建议及验收条件 | 证据 |
| --- | --- | --- | --- | --- | --- |
| UI-01 | P0 | 寄存器交互 | `service.rs:478-490` 每次查询创建 `RegisterReplay`；`registers.rs:112-239` 创建时扫描 observation 和事件、建立 scope/checkpoint。连续点击会重复全量工作。 | 按 artifact identity 复用只读 replay；在关闭工作区时释放。测同一大轨迹连续点击 50 次的 p95、峰值内存和结果等价。 | 确认 |
| UI-02 | P0 | 调用树规模 | `call_tree.rs:23` 允许至多 200 万节点；`service.rs:541-590` 一次构建并返回整树；`CallTreePane.tsx:4-30` 递归创建全部展开节点。 | service 提供有上限的根/子节点分页或分段展开；前端只渲染可见节点。保留完整树身份、父子关系和不完整帧语义；用深树与宽树测 IPC 大小、响应时间、DOM 节点数。 | 确认 |
| UI-03 | P0 | 时间线可读性 | `EventRowDto` 只有 key、kind、provenance、discontinuity（`dto.rs:218-225`）；`VirtualTimeline.tsx` 把 `instruction` 填成 `row.kind`，`symbol` 留空。 | 给一页增加受限的指令摘要：模块+相对 PC、mnemonic/反汇编、内存方向/地址、语义摘要；符号只在 ELF 已附加时显示。维持单页 2,000 行和固定前端缓存上限。 | 确认 |
| UI-04 | P0 | Session 上下文 | `OpenWorkspaceDto` 只带 workspace、artifact、warning（`dto.rs:198-205`）；`SessionOverview.tsx` 仅显示内部 ID 和事件数。设计要求展示设备、目标、配置、artifact 状态。 | 从已校验的 session report 传递有界、只读的 package/device/target/profile/scene 信息；单文件打开继续显式显示缺失 capability。检查 report 与单文件两条流程。 | 确认 |
| PERF-01 | P0 | 性能语料 | `generate_performance_fixtures.py:135-169` 每 4096 条才放一条 instruction/memory/semantic，其余是空 optional record；现有基线有 9,997,554/10,000,000 条 opaque optional。 | 保留旧语料作协议/规模基线，新增富事件语料：真实比例的指令、寄存器、内存、线程、gap、压缩 QTRB 与大调用树。分别记录 cold/warm、查询、回放、调用树、IPC 和 UI 延迟；语义摘要必须固定。 | 确认 |
| PERF-02 | P0 | 冷索引内存 | `builder.rs:65-91,145-179,560-610` 同时保留 keys/kinds/events、typed rows 和多个索引；`wire.rs:150-320` 生成并持有 section；`cache/writer.rs:283-395` 随后再写。编码阶段仍可能叠加多份大数据。 | 分阶段记录 peak RSS/heap；优先释放已编码的 owned rows，再评估边编码边写临时缓存。任何流式发布改动必须保留校验、取消、原子提交和失败清理。固定语料 RSS 至少下降 10%，冷索引时间不回退超过 10%。 | 确认结构，收益待测 |
| PERF-03 | P1 | warm open | 当前基线 warm open 约 1.29 秒，离 2 秒目标有余量但不大。`TraceStore::open_or_build_with_guards` 在打开时验证缓存，不能跳过。 | 对身份校验、mmap、section 验证和 normalized catalog 构建分别计时；只优化占比最高阶段。错误缓存仍自动重建，所有现有篡改测试保持通过。 | 待测 |
| UI-05 | P1 | 查询结果分页 | `ResultsPane.tsx:4-18` 将传入页面展平后截到前 2,000 条，显示“results”但没有查询结果的独立翻页与总数导航。 | 让结果列表使用 service cursor 逐页取数，显示当前页和总数是否精确；跨页 Previous/Next 必须能到达全部命中。 | 确认 |
| UI-06 | P1 | 数据请求所有权 | `App.tsx:94-335` 多处重复 cache key、`queryTimeline`、generation/abort 检查与 cursor 记录；`SegmentCache.ts:42-44` 每次写入通过 JSON 序列化估重。 | 提取一个页面仓库管理 identity、游标、请求合并和缓存权重；避免在主线程为每页重复序列化。保留已有取消/切换竞态测试，并测滚动帧时间。 | 确认重复，收益待测 |
| UI-07 | P1 | 加载反馈 | `service.rs:158-190` 以 artifact 数更新 open job，单个巨大 artifact 建索引期间进度几乎不动。 | 增加可审计的阶段和已处理字节/事件进度，明确“验证、索引、发布、重开”；UI 不猜剩余时间。大文件任务能在每一阶段给出变化且取消可见。 | 确认 |
| UI-08 | P1 | 布局与可访问性 | `global.css:7-15` 固定三列和 800×600 最小宽高；时间线已有 ARIA grid，但多个侧栏直接铺开长列表。 | 先做 800–1366 px 与高缩放下的面板可达性、键盘焦点和长文本截断检查，再调整布局；不引入设计规格排除的拖拽 dock。 | 待测 |
| STORE-01 | P1 | 源键索引 | `builder.rs:1103-1129` 为每个事件另建 `SourceKeyRow { row }` 并在必要时排序；1000 万事件约有额外 80 MB 原始行索引。 | 评估单调键的隐式顺序表示或压缩排列，并保留非单调 Flight 的明确索引。需要缓存 schema 兼容/重建策略、重复键检测与 owned/mapped 等价测试。 | 确认成本，收益待测 |
| STORE-02 | P1 | 多 artifact 打开 | `service.rs:162-192` 逐 artifact 构建/打开，最后才发布 workspace。 | 先测多 artifact session 的等待时间和峰值；若并发有收益，使用受控并行数及统一内存预算，保持单 artifact 失败隔离和结果顺序。 | 确认顺序，收益待测 |
| CORE-01 | P1 | tracer 热路径 | `instruction_collector.cpp:68-135` 每条指令协调 pending、signal/syscall、rule、寄存器和内存路径；历史吞吐报告把剩余开销定位到 collector 与 formatter/output。 | 在同一设备/二进制身份下用 simpleperf 和现有五轮 benchmark 分 profile 采样，再针对占比最高分支优化。必须保留指令数、寄存器/内存事实、返回值、压缩大小门禁。 | 已有历史诊断，当前待测 |
| CORE-02 | P1 | Flight 默认容量 | `trace_config.h:30-37` 默认预分配 512 MiB；README 已要求检查设备存储。 | 收集实际 session 的占用和保留窗口需求，评估可配置预设与启动前空间预检；不改变 Flight 的固定容量环形语义。验收覆盖低存储、崩溃恢复和正常关闭。 | 确认默认值，收益待测 |
| CLI-01 | P1 | 产物发布复杂度 | `qtrace/artifacts.py` 同时负责拉取、校验、事务发布、报告刷新和失败回收（约 1,630 行）；`qtrace/session.py` 又编排生命周期与发布。 | 先画清状态/所有权图，再按“远端读取、校验、原子发布、报告刷新”拆内部模块，不改变公开 CLI 或恢复语义；用现有故障注入测试证明每个可见状态。 | 确认职责集中 |
| CLI-02 | P1 | 子进程边界 | `scripts/bounded_process.py` 有 supervisor、PID 身份、取消、子进程回收和流式输出，`qtrace/injector.py`、device/acceptance 都依赖它。 | 增加跨入口的统一故障矩阵：超时、取消、ADB 断连、PID 复用、输出上限、孤儿进程；仅在矩阵证明安全后抽象共用接口。 | 确认复杂路径，风险待测 |
| PROTO-01 | P1 | 多语言协议同步 | `binary_trace_format.h` 定义设备端 QTRB；`scripts/trace_binary.py`、`scripts/flight_trace.py` 和 Rust `qtrace-provider` 分别解析同一格式。现有差分 fixture 已覆盖不少情况。 | 给每次协议变更加入跨语言兼容矩阵：C++ encoder 产物由 Python/Rust 读取，旧版本及 malformed fixture 保持固定；优先生成常量/规范，不生成相互依赖的解析器。 | 确认多实现 |
| QA-01 | P1 | 真实采集到 UI | host CI 跑各层测试；设备验收是手动门禁，UI fixture 由 Python 测试 builder 生成。缺少固定的“真实设备捕获 → qtrace 发布 → UI 打开/查询”验收链。 | 在手动设备门禁成功产物上跑 Rust provider/store/service 离线检查，保存 artifact/report/hash 和真值结果；不把设备依赖加到普通 host CI。 | 确认流程缺口 |
| QA-02 | P1 | 性能门禁漂移 | `performance_gate.py` 要求固定主机身份；本次当前机器执行得到 `reference host identity drift`，因此本地无法与已提交基线直接比较。 | 保留严格参考主机门禁，另加清楚标注的“开发机诊断模式”输出同机前后对比，不写入官方基线。 | 确认 |
| SCALE-01 | P2 | 行数上限 | `dto.rs:186,220,231,237` 与 `service.rs:221,386,395-438` 将事件数、source row、total/start 限为 `u32`；部分摘要溢出时饱和为 `u32::MAX`。 | 明确支持上限并在打开前报结构化错误，或整体迁到字符串化 `u64` DTO；不能只放宽一个字段。以超过 2³² 行的模拟 view 测协议，不必生成巨型文件。 | 确认 |
| SCALE-02 | P2 | 大型分析结果 | `get_call_tree` 是最明显的全量返回；`list_symbols` 也接受调用方提供的地址数组。 | 对所有 IPC 命令统一审计输入数组、输出字节、节点数与超时预算。针对大结果优先分页或流式 job；恶意参数不能造成无界单次 DTO。 | 确认接口形态 |
| MAINT-01 | P2 | 大模块边界 | `timeline.rs` 约 5,457 行（后段含单元测试），`index/mod.rs` 约 2,798 行，`tracer_entry.cpp` 约 2,157 行，`flight/recovery.rs` 约 2,182 行。 | 按状态/不变量和依赖方向抽出内部模块；先固定行为测试，再分批移动代码。验收看接口清晰和调用路径，而非行数下降。 | 确认规模，设计待定 |
| MAINT-02 | P2 | 前端状态所有权 | `App.tsx` 同时管 workspace、projection、分页、缓存、历史、详情和标注；已有 generation 竞态测试较多。 | 将分页导航、详情加载和持久编辑拆为独立 hooks/控制器，统一 stale-response 规则；每次重构保留 e2e/workspace 竞态用例。 | 确认职责集中 |
| QA-03 | P2 | fuzz 覆盖 | 定期 fuzz 工作流只跑 QTRB、Flight 两个目标（`.github/workflows/qtrace-ui-fuzz.yml`）；cache manifest、session report、annotation 数据库也是不可信输入。 | 根据事故/攻击面为这些边界增加结构化 corpus 和 bounded fuzz/property tests；在 CI 时间预算内先做离线短跑。 | 确认覆盖范围 |
| OPS-01 | P2 | 验收证据容量 | `qtrace-acceptance-evidence/` 和 `qtrace-acceptance-failures/` 留有多个本地目录；README 明确脚本不会自动删除。 | 提供只读目录清单与人工保留策略，再加显式 opt-in 清理命令；默认绝不删除失败证据。 | 确认现状 |

## 4. 推荐实施顺序

1. **补测量和真值。** 先做 PERF-01、QA-02，并为 UI-01/UI-02 建连续点击、深树/宽树基线。现有 10M 门禁继续保留。
2. **修明显交互成本。** 实施 UI-01、UI-02，再做 UI-03、UI-04、UI-05。每项单独验证 DTO 兼容、真实事件与前端响应。
3. **压缩索引峰值。** 在 PERF-02 的分阶段数据下决定释放 owned rows、分区流式写入或 STORE-01；只选能在同机和参考主机重复证明收益的改法。
4. **设备端和 CLI。** CORE-01 需设备采样与历史 benchmark；CLI-01/02 用故障矩阵约束结构调整；QA-01 把成功采集和离线分析串起来。
5. **长期规模/维护。** 最后处理 `u32` DTO、跨语言协议规范、巨型模块拆分和额外 fuzz。它们涉及兼容迁移，不宜与性能补丁捆绑。

## 5. 统一验收规则

- 性能改动使用相同 corpus、同一机器、至少五轮原始样本和中位数；固定主机报告继续要求身份一致。记录峰值 RSS、冷/热打开、查询 p95、缓存大小及正确性摘要。
- tracer 改动使用同一设备、同一目标构建和现有 historical benchmark；指令数、返回值、QTRB/Flight 完整性、sidecar 与压缩产物必须一致。
- UI 改动检查单文件降级、session 上下文、未知/损坏证据、取消/切换竞态、键盘可达性和高缩放；页面与 DOM 不随总 trace 行数增长。
- store/CLI 改动沿用资源预算、路径与身份校验、原子发布及故障注入。任何取消或失败都不能留下“看似成功”的缓存或报告。
- 文档中的“确认”只证明存在可优化路径；性能和体验收益必须由对应门禁验证。没有测量收益的候选项不应被描述为回归或缺陷。
