# Store、服务边界与规模验收

本报告覆盖 STORE-01、STORE-02、SCALE-01、SCALE-02、MAINT-01 的 index 责任边界、QA-02，以及 UI-02 的真实 Rust 后端证明。起点为 `72548df`，所有改动位于 `perf/complete-optimization-2026-10-19` 工作区。完整五轮样本、二进制身份、语料身份与校正记录见 [机器可读证据](qtrace-store-boundaries-2026-10-19.json)。

## STORE-01：有序源键使用隐式行号

`index/source_keys.rs` 现在拥有源键顺序判定、重复检测、行映射解码和二分定位。严格递增键仅保存事件数；非单调键仍分配并排序明确的排列。相邻和非相邻重复都拒绝。解码旧排列遇到第一处偏离时，先授权完整分配，再填充前缀；所有线性路径保留分块取消检查。`index/sorting.rs` 统一原有可取消排序，builder、interval 与源键共用同一实现。

内存表示改变没有改变 cache schema 2、normalized layout 3 或 u64 行号 wire bytes。五组新旧缓存逐字节相同；新读旧、旧读新均成功，文件 SHA256 和 mtime 不变，证明没有靠重建掩盖兼容问题。全量 store 测试继续覆盖 owned/mapped 等价、非单调 Flight、重复键、篡改、分配授权、取消和原子发布。

同一主机的 10,000,000 事件 QTRB 与 512 MiB Flight，cache 冷开和热开均为五轮，顺序交替；冷表示索引缓存为空，不表示清空操作系统 page cache。冷开中位数从 7.864685 s 降至 7.645371 s（-2.79%），峰值 RSS 从 1159.23 MiB 降至 1082.93 MiB（-6.58%，约 80 MB）。热开从 0.847042 s 到 0.841690 s（-0.63%），不宣称显著热开收益。正确性摘要保持一致。

200 个视口和结构查询样本 p95 分别从 21.881 / 12.086 µs 变为 25.777 / 14.224 µs。保留这一相对上升，不把所有指标描述为改善；绝对耗时仍远低于原门槛。原参考报告及门槛未覆盖。

## STORE-02：两个 artifact 共享预算打开

`opening.rs` 独立拥有 artifact 准备。每批最多两个 worker，共用原有 source/cache 累计预算和取消令牌。结果按报告次序合并；格式错误仍只隔离所属 artifact，控制类错误中止整个打开。所有 worker，包括线程创建失败前已启动的 worker，都会在返回错误前 join。单 artifact 直接在调用线程处理。service 仅在完整准备和响应体积校验后原子发布 workspace。

输入为两组固定身份语料：2 或 4 个独立模块的 100,006 事件富 QTRB。前后各五轮、每轮新进程，冷开缓存为空，热开复用同一缓存；时间为 service 调用内耗时。

| 负载 | 顺序 | 并行 2 | 时间变化 | 峰值 RSS 顺序 / 并行 |
| --- | --- | --- | --- | --- |
| 2 个 artifact，冷开 | 1.222765 s | 0.737173 s | -39.71% | 154.15 / 159.51 MiB |
| 2 个 artifact，热开 | 0.635556 s | 0.343130 s | -46.01% | 151.05 / 143.15 MiB |
| 4 个 artifact，冷开 | 2.423347 s | 1.446632 s | -40.30% | 292.64 / 305.44 MiB |
| 4 个 artifact，热开 | 1.256552 s | 0.683399 s | -45.61% | 289.26 / 297.64 MiB |

并行冷开约快 40%，峰值 RSS 小幅增加；累计 2 GiB source 和 2 GiB cache 授权额度没有按 worker 放大。所有 artifact 的顺序、事件数、上下文、warning 和重开结果相同。1,000,006 事件的真实富负载 service 打开仍按既有累计内存预算拒绝：`control.budget_exceeded`，2147484497 > 2147483648 bytes；没有通过提高预算换取结果。

首次测量脚本整文件 SHA 曾抬高父进程历史 VmHWM，导致小负载的 wait4 RSS 继承 733004 KiB 下界。已保留原始记录并排除其 multi/warm 样本；最终小负载在新的低内存进程中重跑，全部使用流式 SHA。10M 冷开和 rich 1M 的实际峰值高于该下界，原样保留。证据明确记录两批测量，未混用失真的 RSS。

## SCALE-01 / SCALE-02：25 个 IPC 命令的边界

当前协议的单 artifact 事件数上限为 4,294,967,295；实际可打开容量还受原有 work/allocation 预算约束。`view_event_count` 在准备分析前检查 metadata-only view，超出时返回 `workspace.event_limit_exceeded`，不会饱和成最大值或发布工作区。模拟 view 的任何行访问都会 panic，测试证明超过 2³² 行的拒绝只需读取计数。DTO 的 total、start、source row、调用节点区间继续统一使用 checked u32 转换。

| 命令组（合计 25 个） | 输入与输出边界 | 工作、时间与生命周期 |
| --- | --- | --- |
| 两种打开 picker | 无任意路径参数；metadata 输出至多 16 MiB | 原 source/cache 累计预算各 2 GiB、30 分钟截止；worker 至多 2，失败不发布 workspace |
| close / summary | 256 B workspace ID；固定结构 | 关闭取消 projection 与首次分析，清除 workspace jobs |
| create projection | 全字段合计 256 terms，文本各 4 KiB、合计 64 KiB；memory 保留 read/write/readwrite/unknown 四种方向 | admission 在改变 generation 前；有界分析工作计划、固定 semantic 队列、可取消 job |
| query / locate / locate offset | 每页 1–2000 行；cursor 8 KiB；checked u32 | 保留 projection identity、工作计划与取消；结果 JSON 16 MiB |
| event detail | u32 artifact/row；输出 JSON 16 MiB | 原始源只读；单事件 payload 仍受解码与打开预算约束 |
| register state | 固定 34 before + 34 after | 首次回放 30 s / 512 MiB；交互 5 s / 256 MiB，绑定 workspace 取消 |
| memory state / history | checked u64 地址，原分析范围至多 1 MiB；返回工作最多 2000 rows；JSON 16 MiB | 交互 5 s / 100000 nodes / 256 MiB；内部 posting 扫描不冒充响应 rows |
| call tree | 每页 100 siblings，256 B identity，父节点与来源行受检 | 首次 30 s / 512 MiB / 2000000 nodes / 10000000 rows；跨页 identity，关闭取消与释放 |
| attach ELF / list symbols | 名称 4 KiB、digest 严格解析、build ID 4 KiB、最多 2000 PCs；JSON 16 MiB | 交互 5 s / 100000 nodes / 2000 rows / 256 MiB；ELF 路径仍来自 native picker |
| annotation / highlight 五命令 | comment 64 KiB，highlight 256 B；读结果 JSON 16 MiB | SQLite 每 1000 VM instructions 轮询；绑定交互预算和 workspace 取消，提交前再次检查 |
| local symbol 三命令 | digest 严格解析，name 4 KiB；读结果 JSON 16 MiB | 同一 SQLite guard、事务与取消规则 |
| list / cancel jobs | ID 256 B；最多 8 active、512 retained jobs，仅淘汰 terminal | 原错误 detail 512 B；保持所有 active 可见；线程创建失败返回结构化错误并完成 job 收尾 |

Serde visitors 拒绝过大 size hint、数组与字符串，service 再验证直接 Rust 调用。响应按包含 JSON escaping 的实际编码字节计数，使用 Write counter，不另造整份编码副本；打开 metadata 在写入 workspace 前检查。输出字节上限与累计分配预算作用不同，均不声称为实际堆上限。

新增回归覆盖超量输入不改变 generation/jobs、不访问文件；四种已有内存方向的合法组合仍可用；超大数组 hint 不读取首项；输出转义膨胀；active quota 的并发 admission；terminal 淘汰；worker panic 和创建失败先回收。附加有效 AArch64 ELF 后，同一个 projection 返回 `native_work+0x5`。

## UI-01 / UI-02：真实生命周期与树规模

寄存器共享、并发等价和关闭释放继续由 Rust `register_replay_is_shared_by_queries_and_released_with_workspace` 证明。调用树新增相同 Arc 复用及关闭释放证明；已有真实大 Flight 的首次构建取消测试保留。前端最终 50 次点击和深宽 DOM 证据见 [交互报告](qtrace-ui-layout-state-2026-10-19.md)。

真实 QTRB 分别产生 5,000 层链和 10,000 个根节点。各五轮 fresh process，遍历每个真实服务 page 和每个节点的来源跳转，检查无重复/遗漏、stale identity 拒绝及关闭失效；没有合成 IPC 响应。

| 树 | 节点 | 深度 | 首次构建中位数 | 缓存首页中位数 | 每页最大节点 | 最大 IPC JSON |
| --- | --- | --- | --- | --- | --- | --- |
| deep | 5,000 | 5,000 | 13.114 ms | 0.002 ms | 1 | 367 B |
| wide | 10,000 | 1 | 35.781 ms | 0.026 ms | 100 | 19,077 B |

首次成本仍是全量建树；这些数据支持当前明确上限，不声称建树已经变成按需算法。另五轮 rich 1M store/analysis 加 100k service IPC 全部满足既有事件、寄存器、压缩重放、5,000 frame、Flight 四线程与缺口 oracle。

## QA-02 与最终集成

以上 10M before/after 记录直接通过生产 `compare_diagnostics` 比较器，同机、同 generator、同 corpus；注入 host/corpus mismatch 时均被拒绝。全量 Python 同时覆盖 wrong workload oracle、reference 模式和 tracked reference 覆盖拒绝。所有本轮结果均为诊断，不提升为固定主机门禁；当前参考文件 SHA256 保持 `195a26bc81aa59b4fa664d7fcc16d927aba6a799d9b9ae70f140c94021a606a8`。

最终集成命令及退出状态收录于 [总验收报告](qtrace-project-optimization-2026-10-19.md)。四份保留小米报告均在最终 service 下通过逐事件 provider/store/完整分页/分析及缓存重开核对，原始 SHA、事件计数和 completeness 不变。浏览器另覆盖相同四份产物。
