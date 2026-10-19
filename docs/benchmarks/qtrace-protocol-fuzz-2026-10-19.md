# 协议兼容矩阵与存储 fuzz 验证

本记录对应优化清单中的 PROTO-01 与 QA-03。起点为 `72548df9c099f3e7813016eba5bd46da34099760`，验证对象是 `perf/complete-optimization-2026-10-19` 分支的工作区改动。本次不提交或推送；测试使用临时产物，不打开用户的 trace、cache 或 annotation 原件。最终命令和结果记录在同名 JSON 文件中。

## 协议兼容矩阵

新增 `tracer/src/test/cpp/protocol_fixture_emitter.cpp`，直接调用生产 `BinaryTraceEncoder`、`FlightEncoder`、`FlightArtifact` 和 `FlightChunkWriter`，输出 QTRB completed/stopped 与 Flight active/sealed 四个产物。产物包含指令定义、不同宽度的寄存器、内存状态、UTF-8、引号换行和拆分 UTF-8 字符的事件分片。host CMake 注册独立的 `protocol_fixture_emitter` target。

`python3 qtrace-ui/tools/check_protocol_matrix.py --check` 编译当前 C++ encoder，连续生成两次并比较完整字节，再与 `qtrace-ui/fixtures-native` 中经过审核的固定产物、长度及 SHA-256 比较。C++ 同时导出版本、feature 和布局常量，Python 使用自身的结构尺寸与常量进行比较。该工具还验证当前 37 个 fixture 的再现性和 Python 读取契约，运行 Rust QTRB/Flight 差分和 framing 测试。

Rust 的精确差分测试同时读取当前 C++ 新产物和固定旧语料：QTRB 1.0、1.1、1.2，Flight v2，以及错误 header、feature、长度、序列、引用和 terminal 等 malformed 语料。Flight 比较事件键、物理来源坐标、顺序、寄存器、投影及完整性原因；QTRB 比较规范化文本和统计。解析器保持独立，不从其他语言解析器生成代码。`--write` 是显式更新固定 native fixture 的维护命令。

## 存储 fuzz 与预算

新增 `cache_manifest`、`session_report`、`annotations` 三个 libFuzzer target。原有 `qtrb` 和 `flight` target 保留。可读 corpus selector 展开后，可使用三字节 XOR 后缀修改有限偏移；未经 selector 包装的任意输入也直接进入对应生产入口。

cache 语料由生产 `CacheWriter` 创建，覆盖正确 manifest、区段重叠、长度溢出、身份冲突、区段数量、未知字段和截断。payload 变异后更新有效 envelope 的 checksum，使随机变异能够进入 JSON 和区段语义验证。读取后验证 cache 字节未变。

session 语料覆盖真实三 artifact session、路径越界、NUL、尺寸溢出、集合超限、未知字段及合法 report 外层内的深层 JSON。尺寸错误保持 artifact 级隔离；非法根 report 必须拒绝。每次都验证 report 和 artifact 原始字节未变。

annotation 语料从生产创建并 checkpoint 的 SQLite 数据库生成，覆盖 schema 1/2/3、超长文本、错误 SQLite storage class、损坏文件头，以及递归百万行的恶意 view。SQLite 仅打开临时副本。新增 `AnnotationStore::open_guarded`；兼容的 `open` 入口继续存在。guard 覆盖数据库和 sidecar 输入、连接工作区、SQLite 每 1,000 VM 步的节点/取消检查、输出文本分配和事务提交前的取消。首次 abort 保持有效，迁移中断不能成为成功发布。SQLite 文本长度、page cache、page count 和查询长度限制继续生效。

| 边界 | 限制 |
| --- | --- |
| QTRB / Flight 输入 | 16 MiB |
| cache / session 输入 | 1 MiB |
| annotation 数据库输入 | 256 KiB |
| 每次 guard 输入 / 解压字节 | 各 16 MiB |
| event / node / row | 各 100,000 |
| 累计 resident 授权 | 32 MiB |
| guard 取消 deadline | 1 秒 |
| report JSON 分配预留 | 编码长度的 64 倍 |
| CI 单输入超时 / RSS / 单次 malloc | 3 秒 / 512 MiB / 128 MiB |

固定 corpus 测试证明有效语料实际进入生产读取路径，损坏语料按契约拒绝。另有 64 次固定随机种子的 property 检查，混合任意字节和结构化 seed 变异，并验证全部工作预算维度与输入上限。annotation 的独立回归证明打开前取消不创建目录、输出读取计费、取消提交回滚，以及 VM 预算中断保留旧 schema。

## CI 与验证范围

`.github/workflows/qtrace-ui-fuzz.yml` 对 `qtrace-ui/**`、`qtrace/report.py`、`scripts/**`、`tracer/src/**` 和自身配置的 push/PR 运行协议矩阵、storage corpus/property、annotation guard 回归，以及五个 target 各 60 秒的 ASan fuzz。手动与每周运行保留每个 target 1,800 秒。独立 fuzz workspace 的 `Cargo.lock` 纳入跟踪，CI 使用固定依赖；失败时上传 crash 输入。

本地验证不等同于已执行托管 CI。远程工作流会在用户后续推送后运行；本次按授权保持未提交、未推送。长时间 fuzz 并非无缺陷证明；当前完成条件是固定兼容矩阵、有效/恶意存储 corpus、可执行预算和 CI 短跑连接。

本机协议矩阵通过 16 个 Python 和 25 个 Rust 测试。storage fuzz 的 6 个测试（含 64 次固定随机种子的 property）、15 个 annotation 新旧测试，以及对应的 clippy 均通过。CMake 的独立 emitter target 构建通过。五个 ASan target 各请求运行 10 秒，共执行 925,984 次输入，无 crash；各 target 的输入次数、实际耗时和日志路径见 JSON。libFuzzer 使用临时 corpus 副本，未向仓库 corpus 写入新变异。

另在独立临时 workspace 中仅移除 SQLite progress hook，VM 预算回归按预期失败：实际返回 `annotation.sqlite`，不再是所要求的 `control.budget_exceeded`。恢复到当前工作区实现后，同一回归通过。该反证没有修改共享工作区源码或用户数据库。

模块职责提取后再次运行完整矩阵（37 个 exporter fixture、16 个 Python 与 25 个 Rust 测试）和 6 个 storage corpus/property 测试，均通过；另运行 Flight ASan 10 秒，执行 324,353 次输入、零 crash。结构后日志及源码身份记录位于 `artifacts/complete-optimization-2026-10-19/protocol-maint/verification.json`。新增 ELF 首次触发预期类清单遗漏，现已补充可执行 PT_LOAD、trace PC、`native_work+0x5` 和 build-id 的布局断言，完整重跑通过；原有 section-only ELF 保持原字节。
