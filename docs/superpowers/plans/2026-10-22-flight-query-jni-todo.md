# Flight 大产物查询与 JNI 验收 TODO

日期：2026-10-22。本文跟踪已由源码或夹具确认的问题。F01–F05 的实现位于 `feat/flight-query-bounded`；已补充 Pixel 6/API36 的候选准入、独立部署及真机 Flight 验证，未合入或推送。

需求来源为 2026-10-22 桌面 Flight 体验记录。其中的 2 GiB 产物、耗时、RSS 和目标调用链尚未取得对应原始文件与日志，不能当作本轮独立复验结果。

核对基线：当前工作树 `eb79bcb2c37acb27affda4983ecb099e3ac5c497`，main 为 `ee4a3b7dfb21a4f2cc2daeaec00c013a2304f111`。原有查询/转换文件在体验记录引用的 `059cff0`、当前工作树与该 main 中一致；JNI 解码及 call handler 在这三个版本中也一致。实施时核对上述 main，复用当前隔离 worktree，保留原有未提交材料。

## 优化前确认的缺口

| 编号 | 优先级 | 当前行为与证据 | 完成条件 |
| --- | --- | --- | --- |
| F01 | P0 | [`events-flight`](../../../qtrace/flight_scene_events.py) 先全范围扫描、配对场景，再筛选事件；两遍共享 512 MiB payload 上限，游标不让第一遍跳过旧 payload。未闭合场景只有计数，没有场景内事件。 | 提供不依赖场景闭合的有界 sequence/尾部查询；大文件尾部查询不再先解码全部旧 payload。 |
| F02 | P0 | [`scenes-flight`](../../../qtrace/flight_inspection.py) 限制累计扫描 64 MiB，sealed chunk 可按游标跳过，但没有场景边界索引，也不回答“该 sequence 属于哪个场景”。 | 大文件支持可复用的边界查找和包含关系查询，资源上限、取消与验证范围保持明确。 |
| F03 | P1 | [`publish_flight_outputs`](../../../scripts/flight_convert.py) 完整调用 `recover_flight`，保留所有事件，再同时生成 merged 和各 TID 的文本字符串。 | 恢复、筛选、排序和写出均不依赖全量事件或全量文本常驻内存；支持明确标记范围的局部输出。 |
| F04 | P1 | `inspect-flight` 只读取元数据，返回 `payload_verification: not_performed` 和 `target_returned: null`；边界查询的空行不能说明场景从未命中。 | 保留快速预览，另提供按需的场景证据摘要；无法确认的安装、命中和返回状态明确为未知。 |
| F05 | P2 | 现有 [`Deployer`](../../../qtrace/build.py) 已有 app-private 部署和主机/设备 SHA-256 比对，但公开 CLI 没有面向通用手动加载的独立 payload/config 部署入口。构建版本也缺少可直接回显的源码修订与本地改动身份。 | 复用已有部署能力，形成可核对的构建、部署及加载身份链；手动加载工作流可单独使用。 |

这些是特定工作流的能力缺口；64/512 MiB 限制本身是现有接口的资源合同，不能简单删除上限来宣告修复。

## 实施清单与验收

### F01：先让崩溃尾部可查

- [x] 复用现有 chunk 读取与解码器，提供 sequence 范围或尾部事件查询。sealed chunk 使用已验证的范围定位；active chunk 不把未发布的头部范围当事实。
- [x] 原始事件查询允许场景尚未返回。返回场景归属时给出证据来源；入口被覆盖、缺口穿过场景或缺少配对时保留未知，不推造 return、结束时间或完整调用。
- [x] 保留 `events-flight` 已有“完整配对场景按时间重叠选择”的语义。是否新增 `tail-flight` 命令由最小公开接口决定，不同时增加多套等价命令。
- [x] 验收覆盖跨 chunk、环形槽位顺序、多线程交错、嵌套场景、未闭合场景、入口已覆盖、active 前缀、损坏、取消与文件变化。结果与小文件的完整恢复逐事件对照。
- [x] 使用密集大产物测量查询尾部 30 行的耗时、峰值 RSS、读取 payload 字节数与解码 chunk 数；证明旧 payload 被跳过。原体验文件可取得后再复验其具体超时，不把合成夹具当作该真机问题已复验。

### F02：场景索引与游标解释

- [x] 从实际 `qtrace.scene` 边界构建可复用索引；chunk 的 `first/last` 只定位候选范围，不能直接推出 scene 内容或包含关系。
- [x] 索引绑定输入身份和索引版本；首次构建采用流式、有预算、可取消的扫描，文件变化或索引失配时明确拒绝复用。
- [x] 在 F01 基础上提供“包含 sequence 的场景”查询，允许入口位于游标之前；缺少可信入口或有歧义时明确说明未知。
- [x] 保持 `scenes-flight --after-sequence` 为边界事件的排他游标，说明 `rows: []` 仅表示筛选后没有边界，不能解释为没有活动场景。
- [x] 验收首次索引与复用分别记录成本；覆盖游标恰在边界、跨游标长场景、多线程嵌套、被覆盖入口与旧文件兼容。默认查询预算不得被静默放宽。

### F03：转换器有界恢复与写盘

- [x] 从恢复层消除全量事件驻留，再处理文本流式写出；仅把 `_render` 改成逐行输出不足以完成此项。
- [x] 复用 chunk 解码，按需要采用有界归并或临时文件处理线程交错、环形顺序及跨 chunk 语义碎片。保留顺序、缺口和损坏检查。
- [x] 提供 sequence 范围及最大事件数等最小筛选接口；局部输出标注请求范围、实际保留范围和截断原因，不冒充全产物 complete。
- [x] 保留 merged、各 TID 与 summary 的现有命名、拒绝覆盖和整组原子发布/回滚语义。磁盘不足、取消或源文件变化时不发布貌似完成的结果。
- [x] 验收小文件输出等价、大文件内存随工作窗口而非总事件数增长，并记录耗时、峰值 RSS、临时磁盘和最终输出大小。

### F04：按需摘要与可信状态

- [x] 默认 `inspect-flight` 保持不读 payload；深度统计使用显式选项或独立查询，说明扫描范围、预算和是否来自已验证索引。
- [x] 摘要分开呈现场景进入、显式返回、停止采集、未闭合、损坏及覆盖缺口；按需显示有证据的首末 sequence 与指令数，不将头部声明计数当作解码统计。
- [x] 如需入口寄存器查询，核对 scene 入口与 checkpoint 的实际位置关系。普通 chunk checkpoint 不自动等于 scene 入口；缺失快照时明确不可用。
- [x] 离线摘要将安装状态保持未知；后续安装判断须结合 native status、配置及实际 payload 身份，不能只凭有效 Flight 文件区分未安装、未命中和命中后未返回。
- [x] 线程覆盖区分“记录到的 TID”“已跟踪线程”与“未知的未跟踪线程”。没有全进程观测依据时，不输出看似完整的 `unfollowed` 总数；裸 clone 不经过 pthread gateway 自动接管，也不能据此断言永远无法命中显式 scene。
- [x] 验收空场景、只有 thread 生命周期、无返回、缺口及预算拒绝；同步 CLI、严格 schema、旧数据兼容与实际 stdout/stderr/JSON 测试。

### F05：构建身份与通用手动部署

- [x] 构建身份至少关联 Git revision、本地差异身份、构建参数与实际 SO SHA-256；仅短 commit 加时间戳不能区分同 HEAD 的不同本地改动。
- [x] 部署复用 `Deployer` 的文件身份快照、app-private 路由、哈希比对与 staging 收尾。独立入口接收手动配置，不启动 Frida 或目标业务，也不另造一份配置 schema。
- [x] 区分主机选择的文件、设备部署的文件和进程实际加载的文件。无法证明运行中加载身份时明确说明，不用 `BUILD SUCCESSFUL` 或目标路径代替。
- [x] 真机验证发现并修复 session 预留/失败清理使用错误身份，以及配置传输使用读写 FD 的问题；复用既有控制身份和只读传输合同，保留原目录内容与权限。
- [x] 主机回归覆盖 checkout/本地差异、错误/旧 payload、私有路由不可用、部署哈希不符和失败收尾；保留原有 session 部署行为。实际 Android 构建与侧车字节核对通过，设备部署验收已绑定当前候选及其 JNI/arm64 报告。

## JNI 可变参数：历史修复与当前候选准入

- [x] 确认历史 bug 位于本项目 JNI 观测解码层。旧 formatter 把普通/V/A 都按连续 GPR 展开，V 的 `va_list*`、A 的 `jvalue*` 被误显示为 Java 参数，另有符号、浮点和栈参数问题；不是已证明的上游 QBDI 执行引擎缺陷。
- [x] 当前 [`jni_argument_decoder.cpp`](../../../tracer/src/main/cpp/jni/jni_argument_decoder.cpp) 区分普通/V/A，使用独立 GP/FP 游标及栈区，复制而不消耗 `va_list`，区分 variadic float 提升和 A 数组的直接 float32。修复已包含在 `1b48e10`，体验记录的 `059cff0` 也已包含。
- [x] 当前 [`call_handlers.cpp`](../../../tracer/src/main/cpp/handlers/call_handlers.cpp) 传入 GPR、FP 和 SP，并让每个 pending transfer 持有自己的 JNI 快照。固定 float/double 参数和嵌套 enter/leave 的修复沿用现有实现，不重复列为待修 bug。
- [x] 核对历史原始 RED/GREEN 报告：旧版本 Java 实收值及返回正确、参数文本错误；最终 GREEN 在 Pixel 6 `1C111FDF600G6S`、API36/arm64 上 14 项检查全部通过。验收 tracer SHA-256 为 `8a66b7b3e6f8a8e0740f75ef4090570a2dc85a8a5c13b5396bdcf1665473da9f`，不是任意新构建的准入证明。
- [ ] 核对体验记录中实际加载的 payload SHA、源码差异和 companion 身份；当前只给出的 `57e4c61c…` 不足以判断是否仍有该 bug。与历史 GREEN 哈希不同也不自动意味着有 bug。
- [x] 当前候选 tracer SHA-256 `366113d821b8d2e2ba586d1050c8d055f8fab9b5d3356d6119fba6ca290fddb8` 在 Pixel 6/API36 上完成 [JNI/arm64 准入](../../jni-abi-acceptance.md)，14/14 通过、30 份轨迹具有有效真实返回；普通/V/A、GP/FP/栈参数、浮点、异常及分派均有原生与 Java 对照。独立 deploy 已用 `--abi-report` 绑定同一报告。
- [x] 当前候选在上述矩阵中未复现参数文本错误或真实调用结果变化，未重写 JNI 解码器。以后出现新复现时再保留输入与字节身份定位；签名缺失、A 形式和缺少 FP 上下文仍分别处理。

JNI 历史证据见 [RED/GREEN 验收](../../benchmarks/jni-abi-2026-10-21.md) 和 [机器摘要](../../benchmarks/jni-abi-2026-10-21.json)。本轮另直接核对主工作区的 `artifacts/qbdi-p0-2026-10-21/device-red-2/report.json`、`artifacts/qbdi-jni-fixed-2026-10-21/device-{red,green}-reset/report.json`；这些原始证据属于历史运行。本轮新设备证据见[设备补验](../../benchmarks/flight-device-2026-10-22.md)。

## 实现入口

- [main 合入验证](../../benchmarks/flight-main-integration-2026-10-22.md)：合并后的兼容修复、全量回归及新候选 JNI/arm64 准入；下列历史测量保留原始身份。
- [离线查询与转换](../../flight-offline.md)：`tail-flight`、`index-flight`、`scene-at-flight`、`scenes-flight --index`、`inspect-flight --index` 和 `convert-flight`。
- [通用手动加载与部署](../../manual-tracing.md#通用手动加载与部署)：`inspect-payload`、`deploy` 与 `build-identity.json`。复用 native JSON 和已有 `Deployer`。
- [性能与验证记录](../../benchmarks/flight-offline-2026-10-22.md)：生产编码器密集夹具、首次扫描与复用、内存和临时磁盘成本。
- [设备补验](../../benchmarks/flight-device-2026-10-22.md)：JNI 14/14、部署 8 项、两份真实 Flight 的查询/转换对照及 Python 全量 961 项（9 跳过）。

勾选项表示主机实现及已注明的设备范围。当前候选准入已完成，原体验产物及其实际 payload 身份仍待取得；独立部署回执不证明之后的业务进程加载身份。场景索引遇到分片 scene 边界会明确拒绝；完整语义碎片恢复由转换器承担。入口寄存器快照、安装状态和未跟踪线程总数没有观测依据时保持未知。

## 验证与停止条件

实施顺序为 F01、F02、F03，随后处理 F04/F05。JNI 作为已有修复的防回归与候选准入，不在没有新复现时重写解码器。每项分别记录源码身份、命令、结果、资源占用和未覆盖条件。

相关现有测试入口：

- Flight：`scripts/tests/test_flight_inspection.py`、`test_flight_scene_events.py`、`test_flight_trace.py`、`test_flight_convert.py`。
- CLI/状态：`scripts/tests/test_qtrace_cli.py`、`test_qtrace_summary.py`、`test_qtrace_build.py`、`test_qtrace_abi.py`。
- JNI：`tracer/src/test/cpp/jni_argument_decoder_test.cpp`、`jni_formatter_test.cpp`、`jni_call_handlers_test.cpp`，以及 `scripts/tests/test_jni_abi_acceptance.py`。

本轮验证和资源测量见[验收记录](../../benchmarks/flight-offline-2026-10-22.md)。主机回归覆盖原有恢复合同、完整小文件输出等价、尾部分页、嵌套与跨游标场景、源变化、预算拒绝、发布回滚、构建差异身份及部署失败收尾。native 全套通过，包含现有 JNI 解码回归。

更换候选 SO、companion 或设备系统后须重新执行 ABI 准入；当前通过结论只覆盖本轮绑定的字节与设备。完成单项验收即停止扩展该项；不顺带修改目标业务、线程 hook 或其他项目。
