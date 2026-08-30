# trace-ui 源码研究：如何做一个更好的 qtrace-ui

> 研究日期：2026-08-30
> 检视对象：`imj01y/trace-ui` 的 `main`，固定到 commit [`fee4276280ffe3e3dc532f16758756de1e4fb1bd`](https://github.com/imj01y/trace-ui/tree/fee4276280ffe3e3dc532f16758756de1e4fb1bd)（tag `v0.5.8`）
> 来源边界：只使用该 revision 的 README、许可证、源码和构建配置；旧许可证只核对仓库内 `v0.5.3` tag。本文是源码设计研究，不是法律意见。
> 验证限制：研究环境没有 `cargo`，因此无法实际执行测试；测试数字是静态统计的测试属性数量，性能结论来自实现复杂度与仓库自己的注释，而不是本机 benchmark。

## 结论先行

trace-ui 最值得学习的不是某一个面板，而是它围绕“超大纯文本 trace”建立的一条完整路径：源文件 mmap、256 行采样定位、可 mmap 的扁平索引、可见窗口按需解析、Canvas 绘制、同一 `TraceEngine` 服务 GUI 与 MCP。ARM64 DEF/USE 分类、成对/128-bit 指令精度、并行扫描后的跨块修补，以及 MCP 的响应上限也都很扎实。

但 qtrace-ui 不应以 trace-ui 为代码底座：

1. 当前许可证不允许分发或发布修改版，也把组织/商业使用排除在 Personal Use 之外；只适合研究设计，不能直接复制当前源码。
2. trace-ui 的 core 从文本行和两种 parser 出发，没有 `TraceProvider` 抽象；格式分支渗入 scan/query/slice。qtrace-ui 应以 QTRB 的 typed record、profile、完整性和线程语义为事实源，不应先降级成文本再重新猜测。
3. trace-ui 的索引虽快，但并非“常量内存”：依赖边、逐地址内存历史、检查点、字符串快照都随 trace 增长；缓存只校验文件大小和前 1 MiB，section 读取也不够防御性。
4. 调用树、控制依赖、寄存器状态是单一全局时间线启发式；这对普通单 TID trace 尚可，对带 TID、gap、signal、syscall、checkpoint/delta 的 Flight 数据不成立。
5. UI 的 Canvas 路线值得保留，但 3000 多行的 `TraceTable.tsx` 把虚拟坐标、IPC、折叠、污点、选择、箭头、动画和绘制揉在一起，不是可持续的模块边界。

因此，建议把 qtrace-ui 定位为“QTRB 语义查询引擎 + 多视图客户端”，而不是“trace-ui 的 QTRB parser 版本”。

## 1. Workspace、模块边界与共享 core

workspace 明确分成五个 Rust member：`trace-parser`、`trace-core`、`trace-mcp`、`trace-cli`、`src-tauri`（[workspace 清单](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/Cargo.toml#L1-L3)）。职责基本如下：

| 模块 | 实际职责 | 评价 |
|---|---|---|
| `trace-parser` | Unidbg/GumTrace 文本解析、ARM64 指令分类、静态 DEF/USE | 算法内聚度较好，但格式能力与 ARM64 语义混在同一 crate |
| `trace-core` | session、mmap、扫描/索引/缓存、查询、调用树、污点、字符串与 crypto | 真正的共享核心；也承担了太多存储与分析策略 |
| `trace-mcp` | `Arc<TraceEngine>` 的工具适配、stdio/HTTP transport、响应裁剪 | 复用 core 是对的，部分业务分页/整形重复到了 adapter |
| `trace-cli` | 创建 engine 并启动 MCP stdio（[main](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-cli/src/main.rs#L1-L8)） | 名为 CLI，实质是 headless MCP server，不是面向人的分析 CLI |
| `src-tauri` + `src-web` | Tauri command adapter、内嵌 HTTP MCP、React/Canvas UI | GUI 与 MCP 共享 session；前端主表过度集中 |

Tauri 启动时只创建一个 `Arc<TraceEngine>` 并放入 managed state，随后从该 state clone 给 MCP controller（[Tauri main](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/src-tauri/src/main.rs#L20-L39)）；`TraceToolHandler` 也只保存一个 `Arc<TraceEngine>`（[MCP handler](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-mcp/src/tools.rs#L137-L154)）。这使桌面 GUI、内嵌 HTTP MCP 和 stdio MCP 使用同一 core API，而不是各自重新实现索引。

问题是“共享 core”尚未等于“共享 query service”：Tauri command 和 MCP tool 都会自行校验、取全量结果、再做 DTO/分页。例如 MCP `taint_analysis` 先取全部污点 seq 和全部对应行，最后才裁剪返回（[实现](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-mcp/src/tools.rs#L579-L663)）。这会让 adapter 的性能与语义漂移。

### 对 qtrace-ui 的边界建议

建议拆成四层，而不是按 UI 功能堆进一个 core：

```text
qtrace-format / qtrace-provider
        │ typed record + completeness + source identity
        ▼
qtrace-store
        │ mmap/stream、segment、cache、基础 indexes
        ▼
qtrace-analysis
        │ call/state/DEF-USE/taint/string/crypto，产出 immutable artifact
        ▼
qtrace-service
        ├── Tauri adapter
        ├── human CLI
        └── MCP adapter
```

GUI、CLI、MCP 只做 transport 和展示，分页、上限、取消、错误码与分析 artifact 生命周期都由 service 层统一。

## 2. Parser 与缺失的 `TraceProvider`

### 2.1 trace-ui 当前模型

源码里没有 `TraceProvider` trait，也没有等价的存储/事件 provider seam。只有 `TraceFormat::{Unidbg, Gumtrace}`（[类型定义](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-parser/src/types.rs#L1-L15)），格式检测读取开头约 20 行并在不能识别时默认 Unidbg（[检测逻辑](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-parser/src/gumtrace.rs#L110-L137)）。scan、browse、query、dependency tree 多处直接 `match TraceFormat`，例如统一扫描（[scan dispatch](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/scan_unified.rs#L300-L370)）和查询重放（[query dispatch](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/engine/query.rs#L110-L114)）。加第三种格式会触及整个 core。

解析结果 `ParsedLine` 是面向“单条汇编文本”的临时结构，包含 mnemonic、small-vector operands、内存绝对地址/值、箭头位置、writeback、lane/pair 等信息（[结构](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-parser/src/types.rs#L240-L363)）。`RegId` 用 `u8` 压缩 98 个逻辑寄存器槽，包括 SIMD low/high（[编码](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-parser/src/types.rs#L18-L127)）。解析使用 `memchr`、手写十六进制和少量受前提约束的 unsafe UTF-8 快路，适合重复扫描文本。

ARM64 指令被归成约 42 类，再由较完整的规则生成 DEF/USE；对 SIMD full-width、lane、read-modify-write 和 pair 拆分做了特别处理（[DEF/USE 主逻辑](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-parser/src/def_use.rs#L1-L180)）。这是值得迁移的“语义规则测试集”思路，但不应复制受限许可证代码。

标准 Unidbg 输出不是可靠输入。README 明确要求修改 Unidbg 以输出 `mem[READ/WRITE] abs=`（[格式要求](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/README.md#L320-L348)），构建阶段若检测不到内存注解会返回 parse error（[检查](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/engine/build.rs#L183-L202)）。这说明它依赖的是一个非标准文本协议，格式探测也不足以成为扩展边界。

### 2.2 qtrace-ui 应定义的 provider contract

QTRB 已经是 typed binary protocol。普通 trace 有 type 1–10（begin/module/instruction definition/instruction/memory/call/rule/error/end/stop）；instruction 自带 branch、PC-relative、call、return flags 和读写寄存器值，balanced/full memory 还可给出 before/after。Flight 另有 `global_seq`/TID、34 GPR checkpoint+delta、thread/syscall/signal/termination/coverage-gap，并显式报告 lost/overwritten/damage。qtrace-output 又是包含 report/config/device/artifacts 的 session 目录，不只是一个 trace 文件。

因此 provider 不应返回“文本行”，而应至少暴露：

- `TraceSourceIdentity`：session/artifact、schema/profile、source size/hash、producer build、设备/进程元数据；
- `TraceCompleteness`：completed/stopped/damaged、lost/overwritten ranges、coverage gaps；
- `EventCursor`：按 `(timeline, thread, seq/global_seq)` 迭代 typed record；
- `InstructionView`：definition 引用、PC/module、flags、register reads/writes；
- `MemoryView`：访问种类、地址/宽度、before/after 与“未采集/未知”的区别；
- random access 与批量 column access，而不是强迫每个分析器反复 materialize 大对象。

`QtrbProvider`、`FlightProvider`、未来的 text-import provider 可以实现该 contract；分析器依赖 provider capability，而不是枚举格式。CALL/RULE/ERROR 的 detail 仍是字符串，应被保留为带 provenance 的半结构化事件，不能假装它们已经类型安全。

## 3. mmap、索引与缓存格式

### 3.1 源文件和行索引

`create_session` 把整个文本文件 mmap 到 `Arc<Mmap>`，Unix 上给 `WillNeed`，并用 `file_size / 110` 估计行数（[session 创建](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/engine/mod.rs#L28-L76)）。mmap 避免复制整文件，但 `WillNeed` 对非常大文件可能形成激进预读；它也不等于常量 resident memory。

`LineIndex` 每 256 行只记录一个 byte offset，随机取行时从最近采样点最多扫描 255 个换行符（[实现](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/line_index.rs#L1-L22)，[定位](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/line_index.rs#L93-L113)）。这是非常适合文本 fallback 的小而深设计；QTRB 则应优先利用 record framing/segment offset，不必模拟文本行。

统一扫描在一次遍历中生成 dependency、call tree、memory access、register checkpoint、line index 和 strings（[build 接线](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/engine/build.rs#L150-L236)）。10 MiB 以下走单线程；以上按 CPU 数切到换行边界，用 Rayon 做独立 chunk scan，再顺序修补跨块寄存器/内存/control/call 状态（[并行入口](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/parallel.rs#L1-L48)，[merge](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/merge.rs#L1-L40)）。这个“两阶段局部摘要 + 边界重放”模式值得迁移到 QTRB segment。

### 3.2 内存索引和依赖索引

依赖边采用 CSR 风格的 `CompactDeps`，并行结果用分块 offsets/data 加 sorted patches；边的高 3 bit 编码 half2/shared/control，剩下 29 bit 是 line number（[`LINE_MASK`](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/scanner.rs#L88-L94)）。因此硬上限约为 536,870,911 行，parallel 入口会显式检查（[检查](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/parallel.rs#L31-L42)）。标记塞进 ID 虽紧凑，却限制规模和可扩展 edge kinds；qtrace-ui 应使用显式 edge type/column，或至少 64-bit packed schema 带版本。

内存访问先按地址聚合，落盘后是 sorted unique addresses + CSR offsets + fixed records（[flat archive sections](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/flat/archives.rs#L24-L47)）。这个布局使 exact-address query 可二分且适合 mmap，是可迁移设计。可是 byte-granularity last-def 与逐访问记录仍为 O(memory events)；源码甚至说明 200M+ HashMap 条目可占 10–16 GiB（[merge 注释](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/merge.rs#L628-L642)）。README 所谓大文件“常量内存”至多成立于前端窗口，不成立于整套索引。

### 3.3 cache 的亮点与失效漏洞

cache 文件名是 source path 的 SHA-256；有效性只比较 source size 与前 1 MiB 的 SHA-256，magic 为 `TCACHE03/04`（[cache key/header](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/cache.rs#L1-L66)）。文件在首 1 MiB 之后发生等长修改时会误命中旧 cache，这是实质性正确性漏洞。

phase2、scan、line-index 使用 64-byte header + section table + aligned raw arrays，并在加载时 mmap；string、crypto、Gum extra 等仍走 bincode。`SectionWriter::write_slice<T>` 直接复制 native struct bytes，`SectionReader::slice<T>` 再 unsafe reinterpret（[格式实现](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/flat/cache_format.rs#L1-L36)，[reader](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/flat/cache_format.rs#L76-L129)）。优点是零拷贝；缺点是：

- 不自描述，缺少 schema/build/architecture/endian/record-layout manifest；
- reader 只检查 section table 存在，未逐项验证 offset+length、alignment、element-size 整除，损坏文件可能越界 panic 或形成未对齐 typed slice；
- 保存直接 `File::create` 目标文件，写错通常静默返回，不用 temp + fsync + atomic rename（[save path](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/cache.rs#L77-L104)，[section save](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/cache.rs#L123-L151)）；
- 刚扫描完成的 session 继续持有 owned indexes；只有重开时才享受 cache mmap，峰值/常驻内存仍高。

`Owned`/`Mapped` 共用只读 view 的 `CachedStore` 思想则很好：新建索引和 mmap 重载后的查询代码无需分叉。qtrace-ui 应保留这个抽象，但 cache 必须使用完整内容身份（或可信 artifact digest）、versioned manifest、每 section bounds/checksum、portable layout 与原子提交；corrupt cache 只能降级重建，不能 panic。

## 4. 核心分析的数据结构、算法与边界

### 4.1 调用树

`CallTreeNode` 保存 id、目标地址/名字、entry/exit seq、parent 与 child IDs；builder 维护一个 stack，call push、ret pop，trace 末尾关闭未结束节点（[结构与 builder](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/query/call_tree.rs#L1-L101)）。BL immediate 和 BLR runtime target 驱动建树；Unidbg 的 intercepted BLR 通过“下一条 PC == BLR PC + 4”判断无函数体（[single scan](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/scan_unified.rs#L104-L126)，[处理](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/scan_unified.rs#L210-L239)）。

优点是 O(n)、结构紧凑。限制是只有一个全局 stack，没有 thread key，也不表达 exception/signal/unwind/tail-call/gap；额外 RET 被忽略，entry seq 是 call 指令而非 callee 首指令。qtrace-ui 应按 TID 建 stack，优先使用 QTRB call/return flags 和 Flight thread/signal/termination 事件；遇到 coverage gap/lost/overwritten 时插入 `IncompleteFrame/Discontinuity`，不要伪造完整树。

另有一个大小相关的不一致：小文件单线程路径会把 GumTrace 的 `call func:` annotation 写回节点名；大文件并行路径虽定义了 `SetFuncName` event，却没有在 chunk scan 端生产它，merge 后的 call-tree 名称可能为空（[event enum](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/parallel_types.rs#L65-L76)，[chunk special-line handling](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/chunk_scan.rs#L164-L216)）。这说明 parallel-vs-single 测试不能只比节点数，应比较完整字段。

### 4.2 寄存器与内存状态

寄存器每 1000 行保存 98 个 `u64` checkpoint，未知值用 `u64::MAX`；查询从最近 checkpoint 向前重放至目标行（[checkpoint interval](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/chunk_scan.rs#L29-L79)，[query replay](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/engine/query.rs#L401-L490)）。这把随机查询限制在约 1000 条解析，但存在三类语义风险：global state 不分 TID；`u64::MAX` 不能与真实全 1 值区分；未知/未采集/被 gap 破坏没有 provenance。QTRB Flight 已有 34 GPR checkpoint+delta，qtrace-ui 应原生读取并维护 per-thread validity bitset，而不是另造固定 98-slot 快照。

并行 checkpoint 还有可疑的状态传播缺陷：每个 chunk 从全 unknown 开始，merge 会用前一 chunk 的 final values 填当前 checkpoint 的 unknown，但随后保存的仍是当前 chunk 未累积的原始 final values；一个寄存器若在 chunk N-2 写入、N-1 未写，可能在 N 的继承状态中重新变 unknown（[chunk initialization](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/chunk_scan.rs#L59-L80)，[checkpoint merge](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/merge.rs#L394-L407)）。现有 parallel equivalence tests 没比较 checkpoint/query 结果。

内存历史按 exact address 二分，状态查询对每个 byte 检查 `byte_addr-7..byte_addr` 的候选访问，选目标 seq 前最新覆盖记录，以兼容最多 8-byte 访问；128-bit 会拆成两条 8-byte 记录（[query](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/engine/query.rs#L286-L399)，[128-bit 拆分](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/chunk_scan.rs#L670-L707)）。它重建的是“trace 中观察到的 bytes”，不是进程真实完整内存；复杂度约为 `8 × requested bytes × history lookup`。Tauri 的 memory query 未像 MCP 一样统一限制长度，服务层应施加 page/range 上限和流式结果。

QTRB balanced/full 的 before/after 必须保留方向：read value、write-before、write-after 是不同证据。无 before/after 的 profile 不能被补成零；gap 后状态要传播 unknown/damaged。

### 4.3 DEF/USE、依赖图与反向污点

扫描器把 parser 的 register defs/uses 与 byte-level `MemLastDef` 串成每条指令的 backward edges；load 从覆盖 bytes 引入 store dependencies，pair/128-bit 用 half1/half2/shared 标签维持精度。若 load 的每个 byte 都来自同一 store 且值相等，会剪掉 address-register pass-through edges（[扫描依赖逻辑](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/chunk_scan.rs#L340-L535)）。这比简单“上一条同名寄存器”准确，是 trace-ui 最强的一块。

但未知 mnemonic 会落为零 DEF/USE 的 `Nop`，最终 unknown-class 统计又没有成为用户可见的“不完整分析”信号（[classifier fallback](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-parser/src/insn_class.rs#L470-L480)）。`MemOp` 只有 read/write 二选一，无法正确表达 atomic RMW 同时读写内存；被拦截/外部调用也未建模 ABI 参数、返回值和 memory effects。pass-through 剪枝适合追“值来源”，却有意丢掉 address provenance。qtrace-ui 应让 unsupported/unknown、value dependency 与 address dependency 都成为显式结果维度。

所谓 control dependency 只是把“最近一条条件分支”附到后续指令，直到下一条件分支（[edge 写入](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/chunk_scan.rs#L374-L393)；并行 merge 也做同类 patch）。它不是基于动态 CFG/post-dominator 的控制依赖，在调用、线程切换和异常边界上会产生噪声。UI/API 应标成 heuristic control context，或在 qtrace-ui 中基于动态 basic-block region 明确定义算法。

反向污点使用 `BitVec` visited/result + `VecDeque` BFS 遍历 dependency CSR，`data_only` 会跳过 control tag（[slice BFS](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/query/slice.rs#L1-L99)）。复杂度是 reachable nodes+edges，结果 bitset 是 O(total instructions)。两个容易误解的边界：

- `reg:X@line` / `mem:A@line` 为寻找起点最多只反扫 50,000 行；更远的真实定义会被漏掉（[source resolution](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/engine/slice.rs#L1-L160)）。
- `mem:ADDR:SIZE` 的 size 会在解析时被剥掉而未参与 seed 扩展，实际只从一个地址起步；range/multi-byte source 语义不完整（[memory source resolution](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/engine/slice.rs#L16-L142)）。
- range 是 BFS 完成后的结果过滤，不是 traversal boundary；限制输出区间不会限制分析成本。

session 只保存一个 `slice_result`/`slice_origin`（[session state 初始化](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/engine/mod.rs#L48-L67)），GUI 与 MCP 共享 engine 时可互相覆盖。qtrace-ui 应让每次分析返回 immutable `AnalysisId`，保存 source revision、options、completeness、result index，并允许多个并发 artifact。

Dependency tree 的 node 上限默认 10,000，但实现达到上限后仍继续遍历以计算 total，因此不能限制最坏运行时间（[BFS 与 cap](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/query/dep_tree.rs#L45-L120)）。由 mnemonic 生成的 C-like expression 只是展示启发式，不是 symbolic execution（[formatter](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/query/dep_tree.rs#L300-L380)）；产品文案必须区分“解释性伪代码”和“等价语义”。

`get_def_use_chain` 另行从点击点向前/向后最多扫 50,000 行并反复 parse，只追同一寄存器、遇到重定义停止（[实现](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/engine/query.rs#L864-L954)）。它没有复用预建 dependency graph，既可能漏远端链，也会让交互成本变成 O(50k × line lookup/parser)。qtrace-ui 应让“DEF/USE chain”成为统一 dependency index 的轻量 projection。

### 4.4 字符串

字符串扫描器用 sparse paged memory：每页 4096-byte data、512-byte validity bitset、4096 个 owner `u32`（[PagedMemory](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/query/strings.rs#L78-L151)），每个 touched page 约 20.5 KiB，元数据约是内容页的 5 倍。每次 observed READ/WRITE 更新 little-endian bytes；变化会结束旧 active string，并在附近至多 1024 bytes 内重新扫描 printable ASCII/UTF-8，最后按 seq 排序（[builder](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/query/strings.rs#L153-L370)）。

好处是能发现运行时逐字节拼接，且记录地址、seq、读写 provenance。局限包括：读值也会创造“内存字符串”；不支持 UTF-16/UTF-32/长度字段/terminator 语义；相同内容和旧快照可能很多；xref 先按地址数 read，再按字符串每 byte 累加，单次多字节 read 可能被重复计数。搜索还会为所有 content 分配 lowercase 并全量过滤后再分页（[query](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/engine/query.rs#L566-L612)）。

qtrace-ui 应把 string 作为可增量、可取消的二级 analysis：按 encoding detector 插件输出 candidate，携带 byte validity、first/last observation、read/write evidence、thread、gap contamination 和 confidence；分页在 index 上执行，不 materialize 全结果。

### 4.5 crypto

README 称 28 种魔数，但源码常量表实际有 27 个 label。实现把每个 `u32` 格式化为小写 hex，然后对原始文本行做不带 token boundary 的 ASCII case-insensitive substring 搜索，每个 pattern 每行只报一次；超过 10,000 行会并行分块（[pattern table 与 matcher](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/engine/query.rs#L119-L160)，[scan](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/engine/query.rs#L956-L1055)）。

这只能叫“magic constant candidates”，不能叫算法识别：会受 endian、立即数拆分、表加载方式、常量合成、文本格式和 substring 假阳性影响。qtrace-ui 应用结构化 instruction immediate/memory values 建 inverted index，再把多常量共现、时间/调用邻域、循环/rotate/xor/add 特征组合成 evidence score；UI 展示“命中证据与置信度”，不要只显示 `algorithms_found`。

## 5. 大文件前端虚拟化

当前 main 的主 trace 表不是简单使用 `@tanstack/react-virtual`。README 仍这样描述（[README](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/README.md#L298-L305)），依赖也还存在，但 `TraceTable` 实际是固定 22 px 行高的自定义 Canvas renderer（[常量](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/src-web/src/components/TraceTable.tsx#L20-L52)）。它只绘制可见窗口，HiDPI 缩放，dirty 才在 rAF loop 重绘，并用透明 DOM 文本层支持选择（[Canvas loop](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/src-web/src/components/TraceTable.tsx#L2583-L2669)）。滚轮实时更新 float ref，React row 更新节流 60 ms、数据加载再 debounce 80 ms；滚动期间独立预取，cache 超过 5000 留最后 3000（[滚动/预取](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/src-web/src/components/TraceTable.tsx#L947-L1024)）。共享 line cache 每 session 最多 5000、最多 10 sessions（[hook](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/src-web/src/hooks/useLineCache.ts#L1-L39)）。

这是很好的大文件 UX 策略：可见窗口批取、滚动占位、bounded cache、ref 驱动即时 Canvas 和延迟 React 状态。应保留“viewport query + Canvas”原则。

不应复制其组件组织。`TraceTable.tsx` 超过 3000 行，混合 virtual coordinate、fold/taint projection、IPC prefetch、session cache、selection、hover、tooltip、arrow routing、animation 与 draw calls。cache 是 insertion-order/FIFO 而非真正 LRU；并发请求没有明确的取消、合并或 generation 检查，快速滚动/切 session 时存在过期响应 merge 风险。

qtrace-ui 建议拆为：

- `TimelineProjection`：真实 event index ↔ 可见 row（fold/filter/gap/taint view）；
- `ViewportController`：滚动、overscan、request generation、取消与 coalescing；
- `SegmentCache`：按 session+artifact+projection key 的 weighted LRU；
- `TraceCanvasRenderer`：纯输入绘制，不发 IPC、不持有业务状态；
- `InteractionLayer`：选择、无障碍文本、tooltip、keyboard；
- 独立 panes：call tree、register/memory state、dependency graph，不向 table 塞更多状态。

## 6. 错误、并发、取消与安全边界

core 内部有 typed `TraceError`（[定义](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/error.rs#L1-L34)），但 Tauri commands 大多 `map_err(|e| e.to_string())`，MCP 也返回字符串，错误码、可重试性和细节在边界丢失。qtrace service 应稳定输出 `{code, message, details, retryable, source}`。

并发策略总体合理：engine 的 sessions 是 `RwLock<HashMap<...>>`，session state 是 `RwLock`；长任务通过 Tauri `spawn_blocking`（[commands](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/src-tauri/src/commands/mod.rs#L18-L92)）或 Tokio blocking wrapper 离开 async executor；扫描/搜索/crypto 用 Rayon。MCP 各工具也设有 response cap，例如 lines、memory、search、tree depth/nodes（[limits](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-mcp/src/tools.rs#L236-L301)，[tree](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-mcp/src/tools.rs#L524-L556)），这是 agent-facing API 应保留的习惯。

主要问题：

- `build_cancel` 会 reset/set，但实际 build/merge 没有贯穿检查 cancellation token；关闭 session 只从 map 移除，已有 `Arc` 的 scan 仍继续并可能写回（[build flags](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/engine/build.rs#L35-L48)，[close](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/engine/mod.rs#L91-L103)）。字符串扫描反而会每 10,000 次检查 token（[实现](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/engine/query.rs#L676-L728)）。
- close 为 drop handle 单独 spawn 一个 OS thread；连续关闭可产生无界线程。
- cache override、MCP controller 等有 poison lock `unwrap`，损坏 cache reader 也可能 panic；外部输入应全程 fallible。
- HTTP MCP 绑定 loopback 并尝试端口，降低网络暴露，但 `open_trace(file_path)` 允许本地 client 指定可读路径（[tool](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-mcp/src/tools.rs#L177-L231)）。qtrace-output 应采用显式 workspace/session 授权，避免通用任意路径打开。

qtrace-ui 的所有长查询都应接收 deadline/cancellation、定期 cooperative check，并对 CPU、bytes、nodes、returned rows 分别设 budget；取消后不能 publish partial artifact，除非明确标为 partial。

## 7. 测试、CI 与性能边界

静态统计该 revision 的 Rust 测试属性：`trace-parser` 221、`trace-core` 175、`trace-mcp` 40，共 436。覆盖亮点包括 parser/ARM64 分类与 DEF/USE、flat cache round-trip、slice/string/call-tree，以及 parallel-vs-single 的跨块寄存器/内存/control/call 等价性（[parallel tests](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-core/src/parallel.rs#L390-L780)）；MCP 还有直接实例化 handler/core 的 integration test（[integration test](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/crates/trace-mcp/tests/integration_test.rs#L1-L28)）。这部分工程纪律明显强于常见 UI 工具。

缺口同样明确：

- `src-tauri` 没有测试属性；前端没有 `*.test.*`/`*.spec.*` 文件，`package.json` 只有 dev/build/preview，没有 test script（[package scripts](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/src-web/package.json#L1-L13)）。
- release workflow 只安装依赖并构建 Tauri，没有 `cargo test` 或前端测试 gate（[workflow](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/.github/workflows/release.yml#L43-L65)）。
- 没有 benchmark harness/回归阈值；README 的大文件速度只能作为 anecdotal claim，无法防止退化。
- `.gitignore` 忽略 `Cargo.lock`，对桌面应用造成不可复现依赖解析风险（[ignore](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/.gitignore)）。
- parallel equivalence tests 主要覆盖依赖、pair/init bits 与 call-tree 节点数量，没有比较 register checkpoint query、完整 call node 字段、字符串内容或完整 memory history；上述大小相关差异因此可能漏过。
- 本研究环境无 `cargo`，未执行上述 436 个测试；不能声称当前 commit tests passing。

qtrace-ui 的最低 gate 应包括：provider malformed/truncated/fuzz；普通 QTRB 与 Flight golden files；gap/lost/overwritten 状态传播；per-thread call/state；cache corruption/跨版本；analysis cancellation；GUI viewport 请求乱序；MCP/Tauri/CLI contract parity；再加固定 1M/10M/100M event 数据集的 wall time、peak RSS、cache size、cold/warm query p95 budgets。

## 8. 许可证约束

当前 `main` 的 `trace-ui Personal Use License` 只允许个人学习、研究、下载运行与私人修改；禁止组织/商业使用、分发、发布修改版、托管为产品，以及删除 notice（[许可证定义与 grant](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/LICENSE#L1-L44)，[限制](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/LICENSE#L45-L73)）。README 说明从 v0.5.4 起由 GPL-3.0 改为 Personal Use，之前版本仍按 GPL-3.0（[说明](https://github.com/imj01y/trace-ui/blob/fee4276280ffe3e3dc532f16758756de1e4fb1bd/README.md#L444-L448)）；仓库 `v0.5.3` 的 LICENSE 确为 GPLv3（[旧 tag](https://github.com/imj01y/trace-ui/blob/407d4c0bffec7e1a116f752bf920290e0263d8a6/LICENSE)）。

实际工程决策应是：

- 不复制当前 main 的源码、组件、资源或衍生改写到要分发的 qtrace-ui，除非取得作者书面授权；
- 可以研究公开行为、数据结构取舍和性能策略，再基于 QTRB 需求独立设计与实现；保留设计记录和原创实现证据；
- 若考虑复用 v0.5.3 或更早代码，必须单独做 GPL 兼容性与发布义务评估，不能把“旧版本是 GPL”理解成当前代码可自由拿取；
- 最终由项目维护者/法务确认，本文不替代法律意见。

## 9. 迁移决策表

| trace-ui 设计 | qtrace-ui 决策 | 原因/改进 |
|---|---|---|
| source mmap + sampled random access | 保留理念 | QTRB 用 record/segment offsets；按 profile 调整 madvise，不默认全文件 `WillNeed` |
| 一次 scan 同时建多个索引 | 部分保留 | 基础索引一次建；string/crypto/dep 等重索引 lazy、可取消、可按 segment 增量 |
| parallel chunk + sequential boundary repair | 保留 | 直接对 QTRB segment/Flight checkpoint 做 summary merge，并以 TID 隔离状态 |
| CSR dependency/memory histories | 保留 | 64-bit IDs、显式 edge kinds、thread/timeline key、versioned portable columns |
| register checkpoint + bounded replay | 保留 | 优先 Flight 原生 checkpoint+delta；普通 QTRB 按 thread/capability 建 validity-aware checkpoint |
| single mutable slice result | 拒绝 | immutable `AnalysisId`，可并存、可分页、带 source revision/options/completeness |
| last conditional branch = control dep | 拒绝或明确降级 | 实现动态 CFG region；启发式必须标 confidence/provenance |
| 50k 反扫 DEF/USE | 拒绝 | 统一 dependency index，query 不因 UI 点击重新线性 parse |
| magic substring = crypto detection | 拒绝 | typed value index + 多证据评分，名称为 candidate 而非 recognized algorithm |
| sparse paged string reconstruction | 改造后保留 | 支持 UTF-16/terminator/validity/gap/provenance，压缩 owner metadata，index-first pagination |
| Canvas visible-window render | 保留 | renderer 与 viewport/service 分层；请求带 generation/cancel/coalescing |
| GUI/MCP 共用 `Arc<TraceEngine>` | 保留并深化 | GUI/CLI/MCP 共用同一 typed service/DTO/error/budget，不在 adapters 批量取全量 |
| path+size+first-1MiB cache validity | 拒绝 | artifact digest/full identity + manifest + per-section checksum + atomic commit |
| native-memory section bytes + unsafe cast | 拒绝 | 明确 endian/layout、checked offsets/alignment，corruption 自动丢弃重建 |

## 10. 推荐的 qtrace-ui 首批路线

按价值与风险排序：

1. **先定 provider/service contract**：普通 QTRB、Flight、qtrace-output session 都映射到 typed cursor、completeness、per-thread timeline；定义 structured errors、pagination 与 cancellation。
2. **做基础 store/index**：artifact identity、segment mmap、event offset、thread/global-seq、PC/module、instruction definition、memory address history；cache 必须原子且可验证。
3. **先交付大文件时间线**：Canvas viewport、批量 column query、generation-aware cache、gap/lost/damage 可视化。这一阶段就建立 cold/warm p95 与 RSS benchmark。
4. **状态与调用树**：利用 QTRB flags/values 与 Flight checkpoint/delta，所有结果 per-thread、validity-aware；gap 后展示未知和恢复点。
5. **统一 DEF/USE 与 backward slice**：ARM64 规则独立实现并用 golden corpus 驱动；依赖 edge 带 evidence kind，analysis 返回 immutable artifact。
6. **字符串与 crypto candidates**：作为 lazy analysis 插件，不阻塞首次打开；结果带 provenance/confidence，并能被 slice/call/state 面板交叉导航。
7. **最后接 MCP 和人用 CLI**：直接复用 service 的游标、预算、分页、错误与 analysis IDs；MCP response 限额继续沿用 trace-ui 的好经验。

一句话总结：学习 trace-ui 的“大文件访问路径、扁平索引、ARM64 语义测试和 core 复用”，但让 qtrace-ui 的领域核心从 QTRB typed events、线程与完整性出发，并把 cache、analysis artifact、取消和 UI renderer 做成真正可演进的边界。
