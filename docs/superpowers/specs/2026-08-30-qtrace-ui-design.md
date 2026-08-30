# qtrace-ui 设计

**日期：** 2026-08-30
**状态：** 已批准
**范围：** Linux 离线桌面分析器；普通 QTRB 与 Flight Recorder 的统一浏览、搜索、调用树、寄存器、内存、完整性、ELF 符号与本地标注
**相关研究：** [trace-ui 源码研究](../../research/2026-08-30-trace-ui-analysis.md)

## 1. 决策摘要

在仓库内新增独立的 `qtrace-ui/` Rust workspace，使用 Rust、Tauri 和 React 构建 Linux 桌面应用。qtrace-ui 直接读取 qtrace session、QTRB 和 Flight 二进制产物，不以转换后的文本作为分析事实源。

首版同时支持：

- QTRB 1.0、1.1、1.2；
- Flight v2；
- 完整 qtrace session 目录；
- 单文件降级导入；
- 统一时间线、线程、搜索过滤、调用树、寄存器状态、内存状态、完整性显示；
- ELF `.dynsym`/`.symtab` 符号化；
- 本地重命名、注释和高亮。

首版仅分析已封存或可合法恢复的离线产物，不读取正在写入的 trace，不提供实时采集或流式分析。

qtrace-ui 可以推动采集协议演进，但新协议必须保持对现有 QTRB 1.0–1.2 和 Flight v2 的读取能力。新增 typed JNI 或显式事件关联时，优先使用向后兼容的 optional record 或 capability；只有无法兼容表达的变化才另立 major version。

## 2. 背景与研究结论

现有仓库已经解决采集侧的主要难题：严格 qtrace CLI、QTRB 二进制协议、异步压缩、Flight Recorder、多线程恢复、崩溃与 signal 语义、完整性报告和实体设备发布门禁。当前明显缺口位于采集之后：产物虽然可靠，但日常分析仍依赖长文本、手工搜索和分散的 JSON 报告。

trace-ui 证明了 mmap、稀疏定位、扁平索引、分块扫描、Canvas viewport 和 GUI/MCP 共享 core 适合大型 ARM64 trace。它也暴露了 qtrace-ui 必须避免的边界：text-first parser、单线程全局状态、启发式控制依赖、点击时重新线性扫描、脆弱 cache identity、单一可变分析结果和过度集中的前端主表。

trace-ui 当前 main 使用 Personal Use License，不能直接复制当前源码用于可分发的 qtrace-ui。实现必须基于本文、QTRB 需求和公开行为独立完成，不复制其源码、组件或资源。旧 tag 的许可证兼容性不在本项目首版范围内。

## 3. 目标与非目标

### 3.1 目标

1. 用户选择一个 qtrace session 后，可以在一个工作区内理解设备、目标、配置、artifact 和完整性，而不是手工打开多个文件。
2. 1000 万条普通事件或 512 MiB Flight 在固定 Linux reference host 上通过性能门禁。
3. 普通 QTRB 与 Flight 共享稳定的查询与 UI 模型，同时保留各自真实 capability。
4. 每项显示和分析都区分捕获事实、确定性派生、有限推断、未知与损坏。
5. 原始 session 和 artifact 始终只读；cache 与用户标注独立、可删除、可重建。
6. 同一 service contract 可以在后续供人用 CLI 与 MCP 使用，但首版只交付 Tauri 桌面客户端。

### 3.2 非目标

首版不包含：

- 实时采集、实时 tail 或边采集边分析；
- DEF/USE、反向 Slice、dependency DAG；
- 字符串提取和 Crypto 候选识别；
- MCP server 或面向人的分析 CLI；
- DWARF 源码行、反编译或符号服务器；
- IDA/Ghidra 数据库导入；
- macOS 或 Windows 打包；
- 浮动多窗口、Minimap、主题市场或可拖拽 dock 系统；
- 修改、修复或重新发布原始 trace。

这些能力只能建立在本设计的 provider、store、analysis 和 service 边界之上，不能绕过它们直接加入 React 或 Tauri adapter。

## 4. 总体架构

新增目录：

```text
qtrace-ui/
├── Cargo.toml
├── crates/
│   ├── qtrace-provider/
│   ├── qtrace-store/
│   ├── qtrace-analysis/
│   └── qtrace-service/
├── src-tauri/
└── src-web/
```

依赖方向固定为：

```text
qtrace-provider
      ↓
qtrace-store
      ↓
qtrace-analysis
      ↓
qtrace-service
      ↓
Tauri adapter ↔ React UI
```

上层不能被下层 import。React 不理解 QTRB record；Tauri 不实现分页、预算、状态重放或调用树；analysis 不读取任意文件路径；provider 不构建调用树或用户标注。

### 4.1 `qtrace-provider`

职责是严格解析源格式并回答“产物真实记录了什么”。它包含：

- QTRB 1.0–1.2 parser；
- Flight v2 parser/recovery；
- 统一的 typed event/cursor contract；
- source identity、capability 和 completeness；
- 协议上限、引用、顺序、终端和校验验证。

它不创建持久 cache，不解释 ELF，不建立调用树，也不把 unknown 补成零。

### 4.2 `qtrace-store`

职责是把输入变成只读工作区并管理派生索引：

- session manifest 加载与 containment 校验；
- artifact identity 与 SHA 校验；
- provider 选择；
- normalized event store；
- eager 基础索引；
- cache manifest、section、校验和与原子发布；
- ELF symbol index；
- annotation SQLite database。

### 4.3 `qtrace-analysis`

职责是纯分析与查询：

- timeline projection；
- 结构化搜索与过滤；
- per-thread call tree；
- register state；
- memory state/history；
- symbol resolution；
- completeness 和 provenance 传播。

分析输入是 provider/store view，输出是不可变结果或稳定查询 cursor。内部实现可以变化，但不能改变 service contract 的语义。

### 4.4 `qtrace-service`

职责是唯一应用 API：

- workspace/session 生命周期；
- query pagination；
- background job；
- deadline、budget 和 cancellation；
- immutable analysis artifact identity；
- stable DTO；
- structured error。

未来 CLI 与 MCP 必须调用这层，不得直接访问 store 或 analysis。

### 4.5 Tauri 与 React

Tauri command 是 service 的薄 adapter，负责参数反序列化、调用和 DTO 返回。React 只保存选中项、viewport、过滤器和 panel 状态；完整事件、索引和大结果集始终留在 Rust 侧。

## 5. 领域模型

```text
Workspace
  └── Session
       ├── Artifact
       ├── Timeline
       │    └── Thread
       │         └── Event
       ├── SymbolIndex
       └── AnalysisArtifact
```

### 5.1 Workspace 与 Session

`Workspace` 是用户打开的本地分析上下文。完整 qtrace session 提供 report、session metadata、effective config、device metadata 和 artifacts。单文件导入创建降级 session，并显式标记缺少 package、device、target identity 或配置字段。

### 5.2 Artifact 与 Timeline

`Artifact` 持有完整 source identity：规范化路径、文件身份、大小、完整 digest、格式版本、profile、producer metadata 和 completeness。

每个普通 QTRB artifact 形成独立 timeline。即使同一 session 有多个普通 trace，qtrace-ui 也不虚构跨文件全局顺序。Flight 使用自身 `global_seq` 形成一个多线程 merged timeline，并保留 per-thread projection。

### 5.3 Event identity

稳定事件坐标包含 artifact digest、timeline identity、source record ordinal 和 source byte offset；有 instruction sequence、Flight global sequence 或 TID 时再作为校验字段保存。QTRB semantic event 没有独立 sequence，因此不能要求每种事件都提供 sequence。内部 row number 或过滤后可见行号不是稳定 identity，不能用于注释、导航历史或外部 API。

事件分为：

- instruction；
- memory；
- semantic call/rule/error；
- thread/lifecycle；
- syscall/signal/signal-handler；
- termination；
- discontinuity/completeness；
- begin/terminal metadata。

### 5.4 Capability

provider 显式报告能力，例如：

- global ordering；
- per-thread ordering；
- full register checkpoint；
- register read/write observation；
- memory metadata；
- before/after bytes；
- lifecycle；
- signal/termination；
- loss/damage ranges。

UI 和 analysis 根据 capability 启用功能。缺少能力时返回 `unsupported` 或 `unknown`，不依赖可空字段猜测格式。

## 6. 导入与 cache 数据流

### 6.1 Session 导入

```text
选择 session/report.json
→ 校验 manifest schema 与路径 containment
→ 校验 artifact 类型、大小、身份与 SHA
→ 识别 provider/version
→ 严格解析与完整性验证
→ 流式构建临时基础索引
→ 校验所有 cache section
→ fsync file 和目录
→ 原子发布 cache
→ 打开只读 workspace
```

session 中一个 artifact 无效时只隔离该 artifact，其他已验证 timeline 可以使用；report 身份、路径 containment 或根 schema 无效时拒绝整个 session。

### 6.2 QTRB

未压缩 `.trace.bin` 可以 mmap，并以 record framing 建 source-offset index。`.trace.bin.lz4` 使用 Rust 内的 bounded streaming decoder，边解压边验证和建索引，不要求 host `lz4`，也不发布中间 `.trace.bin` 或文本。

QTRB optional record 按协议规则跳过或保留 opaque provenance；unknown required version、feature、record、flag、reference 或 lifecycle 必须失败关闭。合法 crash-partial 只接受协议已经允许的完整 frame/record，不制造 terminal。

### 6.3 Flight

Flight 原始文件 mmap。provider 按 chunk generation、commit prefix、checksum、directory identity、checkpoint/delta、fragment 和 global sequence 规则恢复。索引包含 active/sealed、lost、overwritten、coverage gap、damage、stale state 和 termination，而不是只保留恢复后的可见事件。

### 6.4 Normalized store

固定列与变长数据分离：

- event columns：timeline、TID、sequence、kind、source offset；
- instruction columns：module、relative PC、definition、opcode、flags、register spans；
- memory columns：owner event、address、size、direction、value、before/after spans；
- semantic columns：category/name 与 detail blob；
- completeness columns：range、cause、severity、recovery point；
- dictionaries：module、instruction definition、string/blob。

首轮 eager index 只包含首版功能所需内容：timeline/thread/sequence、kind、PC/module、instruction definition、register observations/checkpoints、memory range history、call flags 和 semantic category/name。后续规格若增加 string、Crypto 或 dependency index，必须把它们实现为 lazy analysis，不能阻塞首次打开。

### 6.5 Cache

cache 位于 XDG cache 目录，不写入 session。cache identity 包含：

- 完整 artifact digest；
- source format/version/features；
- cache schema；
- analyzer version；
- endian/layout；
- build options。

cache manifest 描述每个 section 的 offset、length、element layout 和 checksum。reader 在创建任何 typed view 前验证 bounds、alignment、element-size 整除与 checksum。损坏、不兼容或身份失配只能触发丢弃重建，不能 panic。

cache 使用唯一临时文件、完整写入、校验、`fsync` 和同目录原子 rename。取消或失败的 build 不发布 cache。

### 6.6 用户数据

注释、重命名、高亮和 UI workspace 设置存入 XDG data 下的 SQLite。数据库使用事务；记录键使用稳定事件坐标或 module identity + relative offset。annotation database 可以备份或删除，但不影响 source/cache 正确性。

## 7. 核心分析语义

### 7.1 Provenance

所有值、边界和分析结果使用以下状态之一：

| 状态 | 含义 |
|---|---|
| `captured` | 产物直接记录 |
| `derived` | 从完整、确定的事件序列计算 |
| `heuristic` | 使用有界推断，必须显示依据 |
| `unknown` | 当前 capability 或事件不足 |
| `damaged` | 结果跨越 gap、corruption、overwrite 或无可靠恢复点 |

`damaged` 不是 `unknown` 的别名：前者表示已知存在破坏，后者表示没有足够证据。UI 不得用普通数值或正常颜色隐藏二者。

### 7.2 时间线与过滤

首版过滤字段：

- TID 集合；
- event kind 集合；
- module；
- relative PC/PC range；
- sequence range；
- mnemonic exact/contains；
- register read/write；
- memory overlap range 和 direction；
- semantic category/name；
- semantic detail text。

不同字段之间使用 AND，同一字段的多个选项使用 OR。查询由 service 分页，返回稳定事件坐标、总数是否精确、下一页 cursor 和 completeness 摘要。UI 不 materialize 全部结果。

QTRB MEMORY/CALL/RULE/ERROR 根据生产者顺序、PC 和当前 instruction context 关联。只有确定关联时才作为 instruction child；无法确定时保持独立事件并标注 provenance。

### 7.3 调用树

调用树按 timeline 和 TID 独立构建：

1. call/return instruction flag 是主要证据；
2. immediate target、动态下一 PC、LR 和 captured register value 用于确定目标；
3. semantic JNI/libc/ART CALL 只用于 enrich 节点，不代替 instruction control flow；
4. ELF symbol 和本地命名只影响显示，不改变地址或树结构；
5. 不匹配 RET、trace begin/end 中途 frame、signal/unwind 和 discontinuity 产生显式 `IncompleteFrame`；
6. signal handler 作为特殊 execution interval 显示，不作为普通函数 frame；
7. 分析不跨越 lost/damaged boundary 伪造 parent/return。

尾调用、异常展开或外部 runtime 行为缺少确定证据时标为 heuristic 或 incomplete。首版不声称恢复完整静态调用图。

### 7.4 寄存器状态

Flight 优先使用原生 34 GPR checkpoint/delta，并按线程维护 validity。

普通 QTRB 从 instruction register observations 恢复：read value 表示执行前证据，write value 表示执行后证据。派生 checkpoint 保存 value 和 validity bitset，只用于缩短重放；它不把从未观察的寄存器变为已知。

discontinuity 使受影响线程的派生状态失效。之后只有新的 captured observation 或可靠原生 checkpoint 能恢复对应寄存器。真实 `0xffffffffffffffff` 必须与 unknown 分开表达，不能使用哨兵值复用。

### 7.5 内存状态

内存 API 分开返回：

- `observed` access value；
- full profile 的 `before`；
- full profile 的 `after`；
- 由先前 write 确定的 `last_written`；
- byte validity/completeness。

history 和 xref 按范围 overlap 查询，不只按 access start address。READ 可以提供观察证据，但不能被误记为程序写入。gap、unknown capture 或范围只部分覆盖时，结果按 byte 表达 validity；未采集 bytes 不补零。

### 7.6 符号化

符号主键是 module identity + relative PC，避免 ASLR 影响。首版读取 ELF `.dynsym` 和 `.symtab`，展示最近包含符号或最近前序符号加偏移。

候选 ELF 位于 session 外时不自动读取；UI 要求用户确认，并验证 ELF64/AArch64、build-id 和已有 target identity。用户本地重命名优先于 ELF 名称。首版不读取 DWARF source line，也不导入 IDA/Ghidra 数据库。

## 8. 桌面工作台

采用固定停靠布局：

```text
┌ Session / Timeline / Search / Filters / Index progress ┐
├──────────────┬────────────────────────┬────────────────┤
│ Threads      │                        │ Registers      │
│ Call Tree    │   Virtual Timeline     │ Memory         │
│ Symbols      │                        │ Event Detail   │
│              │                        │ Completeness   │
├──────────────┴────────────────────────┴────────────────┤
│ Search results / warnings / background jobs           │
└────────────────────────────────────────────────────────┘
```

### 8.1 打开与概览

打开 session 后先显示 session/device/target/config identity、artifact 列表、每个 timeline 的状态、警告和 index progress。用户选择 timeline/thread 后进入时间线。单文件降级模式始终显示缺失的 session capability。

### 8.2 时间线

默认行：

```text
seq | tid | module+offset | symbol | mnemonic operands | R/W/M/C badges
```

展开行显示 register reads/writes、memory before/after、semantic detail 和 provenance。gap、lost、damaged、signal handler、thread lifecycle 和 termination 是不可隐藏为普通空白的特殊行。

点击 instruction 时：

- call tree 定位当前 frame；
- register panel 显示 before/after 与 validity；
- memory panel定位相关 range/history；
- event detail 显示 raw typed fields、source identity 和 provenance。

点击 call-tree 节点跳到入口。折叠 frame 只改变 `TimelineProjection`，不修改真实事件 identity。搜索结果支持前后跳转和导航历史。

### 8.3 前端模块

- `TimelineProjection`：真实事件与过滤/折叠后 visible row 的双向映射；
- `ViewportController`：scroll、overscan、request coalescing、cancellation、generation；
- `SegmentCache`：按 session/artifact/projection key 的 weighted LRU；
- `TraceCanvasRenderer`：纯绘制，不调用 IPC、不保存业务状态；
- `InteractionLayer`：键盘、选择、复制、tooltip、注释和无障碍文本层；
- 独立 panes：threads/call tree、registers、memory、event/completeness、results/jobs。

所有 viewport 请求携带 generation。切换 session、timeline、filter 或 projection 后，旧响应不能合并进新视图。前端 cache 有固定 weight 上限，不随源事件总数增长。

### 8.4 首版 UX 限制

首版仅提供固定 panel、系统深浅主题和基础快捷键。不实现浮动窗口、任意 dock、Minimap、主题市场、MCP 状态、实时采集或高级分析 panel。

## 9. 错误、安全、取消与预算

统一错误结构：

```text
code + stage + source + retryable + detail
```

示例错误码：

- `session.manifest_invalid`；
- `session.path_escape`；
- `source.qtrb.truncated`；
- `source.flight.checksum`；
- `source.version_unsupported`；
- `cache.identity_mismatch`；
- `cache.section_checksum`；
- `analysis.capability_unsupported`；
- `analysis.budget_exceeded`；
- `job.cancelled`。

Rust 外部输入路径不得 panic。Tauri/React 只交换结构化错误；panic、poison 或任意 debug string 不成为应用 contract。

### 9.1 路径边界

- session artifact 路径必须相对、规范化且 contained in 选定 session root；
- symlink、special file、目录替换和读取期间 identity 改变均失败关闭；
- session 外 ELF 只显示候选，用户确认和 identity 验证后加载；
- service 不提供无约束“打开任意路径”API；
- 首版没有 MCP 文件读取入口。

### 9.2 失败隔离

- root manifest/identity/path 失败：拒绝 session；
- 单 artifact 无效：隔离该 artifact，保留其他 timeline；
- 合法 partial/gap/overwrite：作为 completeness 数据打开；
- cache 无效：删除并重建；
- analysis 失败：只丢弃本次临时 artifact；
- annotation 失败：回滚 SQLite transaction。

### 9.3 长任务

所有 index/query/analysis job 接受：

- cancellation token；
- wall-clock deadline；
- input/decompressed byte budget；
- event/node/result-row budget；
- memory budget。

实现按 bounded interval cooperative check。取消后的临时结果不发布。关闭 workspace 会取消未完成 job；已完成但 generation 过期的结果可以进入 content-addressed cache，但不能改变当前 UI 或 annotation 状态。

## 10. 测试设计

### 10.1 Provider

- QTRB 1.0/1.1/1.2 golden fixtures；
- Flight v2 golden fixtures；
- 与现有 Python QTRB converter/Flight recovery 的差分 oracle；
- crash-partial、stopped、lost、overwritten、coverage gap 和 damage；
- malformed/truncated/reference/order/feature/flag 上限；
- property tests 和 fuzz，要求任意输入只返回合法结果或 typed error。

### 10.2 Store/cache

- source/cache identity 与 version 失配；
- section bounds、alignment、length、checksum corruption；
- atomic publish、cancel、process interruption、concurrent open；
- owned build view 与 mmap reload view 的查询等价；
- cache corruption 只能触发 rebuild，不能 panic。

### 10.3 Analysis

- 多线程交错 call/return 不混栈；
- unmatched RET、signal、gap、overwrite 与 incomplete frame；
- QTRB register validity 和 Flight checkpoint/delta；
- discontinuity 后 unknown/damaged 传播与重新捕获；
- overlapping memory history、before/after、last-written；
- symbol/manual-name precedence；
- 过滤字段 AND、同字段多值 OR、pagination cursor 稳定性。

### 10.4 Service/Tauri/frontend

- service DTO/error/pagination/cancellation contract；
- Tauri adapter contract tests；
- `TimelineProjection`、`ViewportController`、weighted LRU 和 stale generation；
- React component tests：filter、jump、fold、selection sync、job/error state；
- Playwright：打开真实小 session、滚动、搜索、thread switch、annotation restart recovery；
- UI 请求乱序和取消后不显示旧结果。

### 10.5 CI

普通 host CI 运行 Rust format/lint/test、frontend lint/type/test、Tauri contract 和缩小 fixture。Linux package workflow 必须在打包前运行上述 gate，不得只有 release build。

大型 benchmark 使用独立定时或手动门禁，不拖慢普通提交反馈。门禁记录 source generator/version、analyzer commit、reference host、每轮原始数据、median、peak RSS 和 cache size。

## 11. 性能目标

固定验收规模：

- 1000 万条普通 QTRB 事件；
- 512 MiB Flight artifact，其中 committed event 集覆盖多线程、checkpoint/delta、memory 和 discontinuity；
- Linux reference host 身份记录在 benchmark 证据中。

首版目标：

| 指标 | 目标 |
|---|---:|
| cold index | ≤ 30 s |
| warm open | ≤ 2 s |
| viewport query p95 | ≤ 50 ms |
| indexed structured search p95 | ≤ 200 ms |
| indexing peak RSS | ≤ 2 GiB |
| frontend resident row cache | 固定 weight 上限，与总事件数无关 |

性能结论使用多轮 median，不用单次最快值。正确性失败、完整性丢失、cache validation 关闭或 fixture identity 漂移时，性能门禁直接失败，不能用更快但不等价的路径通过。

## 12. 验收标准

1. Linux 桌面应用可以打开完整 qtrace session 和单文件降级输入。
2. QTRB 1.0–1.2 与 Flight v2 通过 strict provider 和现有 Python oracle 差分测试。
3. 原始 session/artifact 不被修改；cache 和 annotation 位于 XDG 目录。
4. 普通 QTRB timeline 不被错误全局合并；Flight global/per-thread timeline 保留原始顺序和完整性边界。
5. 用户可以按已定义字段搜索、过滤、分页和跳转。
6. per-thread 调用树不会跨线程混栈，gap/RET/signal 异常产生可见 incomplete/discontinuity。
7. register 和 memory panel 区分 captured、derived、heuristic、unknown、damaged，不补零或隐瞒 gap。
8. ELF `.dynsym/.symtab` 和本地重命名按规定优先级显示，module-relative identity 不受 ASLR 影响。
9. Canvas viewport、projection、generation 和 weighted cache 在快速滚动/切换下不合并旧结果。
10. malformed source/cache 不导致 panic；失败隔离、取消和原子 publication 测试通过。
11. Rust、Tauri、React、Playwright 和缩小 fixture CI gate 通过。
12. 1000 万事件/512 MiB Flight 性能门禁达到第 11 节目标。

## 13. 后续演进边界

首版完成后，后续规格可以分别设计：

1. DEF/USE 与 immutable backward-slice artifact；
2. 字符串候选与生命周期/xref；
3. Crypto evidence scoring；
4. typed JNI/QTRB optional records；
5. 人用 CLI 与 MCP；
6. IDA/Ghidra import；
7. macOS/Windows 分析端。

每项都必须复用 provider/store/analysis/service，不得把格式解析或全量扫描重新放入 adapter/UI。
