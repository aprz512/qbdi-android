# qbdi-android 优化交接

## 通用阶段执行记录（2026-10-21）

P1 生命周期、有界 Flight 查询及 P2 调用摘要、进程控制边界已完成实现与独立设备对照，见
[通用优化验收](../../benchmarks/qbdi-generic-2026-10-21.md)及[执行清单](2026-10-21-qbdi-generic-completion.md)。
当前 tracer SHA 为 `f0ad3048b2d2d0ae4cea91182cf8c3de67e493a1a9b0fbf8bc864dcced1494d5`；
20 组通用 native 配置与当前产物的 14 项 JNI 准入通过，设备均已清理。
下文各轮产物 SHA、测量和未知状态继续按历史范围保留，不作为当前产物的验证身份。
执行范围遵循用户后续限定，仅包含通用工具能力。

## 首批执行记录（2026-10-21）

两个 P0 已完成通用工具闭环，详见[JNI/arm64 验收](../../benchmarks/jni-abi-2026-10-21.md)与[复现说明](../../jni-abi-acceptance.md)。
保留交接时 20 个文件的未提交基线及哈希快照，新增普通/V/A 解码、显式未解码原因、嵌套 JNI 快照、独立 ART 设备夹具和 CLI `--abi-report` 准入。
Pixel 6/API36 的 15 组调用与 18 份轨迹完成 RED/GREEN，12 项准入通过；14 个相关 native Host 目标通过，Python 全量 886 项检查完成、9 项跳过。
构建身份、设备收尾和原始证据位置见验收记录；本轮结果不替代后续 P1/P2 的测量和验收。

后续补充修复了固定 JNI float/double 参数的寄存器来源，并扩展构造器、实例及 nonvirtual 的普通/V/A 真机对照。
当前矩阵为 27 组场景、30 份轨迹和 14 项准入，Pixel 6 全部通过；14 个相关 native Host 目标与 Python 889 项检查完成，9 项跳过。
当前 tracer SHA 为 `8a66b7b3e6f8a8e0740f75ef4090570a2dc85a8a5c13b5396bdcf1665473da9f`，原始证据见 `artifacts/qbdi-jni-fixed-2026-10-21/`。

通用 P1 初查：native status 已提供 `deadlineMonotonicNs` 和 `activeScenes`；flight 摘要已分别记录完整性、termination 与未结束线程。
公开分析器已有工作预算、取消与分页，见[现有边界及历史测量](../../benchmarks/qtrace-store-boundaries-2026-10-19.md)。
后续应先测量具体入口和负载，区分离线 Python 转换与公开分析器，不能沿用私有脚本的历史耗时作为公共入口缺陷。
本轮未执行 256 MiB 查询测量，也未完成 P1/P2 验收。

## 原始交接

交接日期：2026-10-21。目标是在 DIGIMON UP / AppGuard 防护库分析经验基础上优化 qbdi-android 的正确性、稳定性和使用体验。本文件只交接后续工具工作，不表示下列优化已经实施。

## 新会话先读

1. [实战体验与优化建议](../../research/2026-10-21-qbdi-dgup-tool-experience.md)：优化优先级、已确认问题、验收建议及证据限制。
2. [环境检测研究](../../research/2026-10-20-appguard-dgup-environment.md)：防护库检测项、上报链与证据限制。
3. [手动追踪说明](../../manual-tracing.md)：当前配置、部署和采集入口。
4. [跟踪可靠性验收](../../benchmarks/qtrace-tracing-reliability-2026-10-19.md)：已有可靠性能力与验证边界。

先盘点现有入口和测试，再选择最小改动。体验报告主要评价 native configure/status API、logical region、flight 和 JNI 观测，没有完整评测公开 qtrace CLI/UI。不要据实验脚本的故障直接宣布公共入口有缺陷，也不要重新实现已经存在的能力。

## 工作区与协作边界

- 仓库：`/home/lyldalek/workspace/qbdi-android`。
- 本次只读核对时，分支为 `main`，HEAD 为 `0660cc21d48bd05e490d35fc9e9850d31156dc88`。开始实现前重新查询实际状态。
- **关键修复仍在工作区，尚未提交。** 不能把 HEAD 当作当前有效源码，也不能直接重置、清理或以干净 main 替换工作区。
- 已有改动涉及 `qbdi_thread_session.*`、`tracer_entry.cpp`、`tracer_configuration.cpp`、`trace_config.h`、`capture_coordinator.h`、`thread_create_gateway.cpp`、CMake、ShadowHook 的 `sh_island.c`、相关主机测试及文档。先核对 diff，保存既有实现与证据，再开展优化。
- 仓库有 `.codegraph/`；定位陌生代码先用 `codegraph explore`。索引不准确或结果无用时，再用 `rg` 和定点读取；不要因交接自行重建索引。
- 本交接没有授权 merge、push、删除分支或清理其他会话的 worktree。

## 必须保留的有效基线

| 已实现能力 | 约束与已有证据 |
| --- | --- |
| 真实 pthread 目标栈 | traced 目标留在真实线程栈，QBDI engine 使用调用者拥有的 16 MiB 栈。原虚拟目标栈会使 ART 的线程栈检查 abort；已有主机回归和真实设备 JNI 验证。 |
| Android arm64 x18 | 初始化 traced 状态时复制同一 pthread 的平台 x18。已有 RED/GREEN；基线和 traced Java 回调均返回 42，pendingException 为 0。 |
| 线程跟踪选择 | `flight.followThreads` 默认保持开启；聚焦时可设为 false，避免无关线程占满 scene 槽。已有单槽及四个无关真实线程的回归。 |
| hook 岛兼容 | 实测调试构建避免复用已被另一套 hook 使用的 ELF gap，使用私有匿名岛或已有长跳转能力。不要回退已验证的跳板兼容处理。 |
| 匿名代码定位 | logical region 与显式 scene 已能定位解密后匿名 engine，不依赖 maps 中完整 SO 名称。 |

已验证 tracer 的 SHA-256 为 `67f3aed005ba3c487df413265304190f20188e8a0b521c5e91bf6556e3e3b262`。它是历史有效产物身份，新构建须记录自己的 SHA，不能沿用该哈希声明新产物已通过。

可复用设备夹具及同输入基线见 [JNI/arm64 准入说明](../../jni-abi-acceptance.md)，源码为 [jni_abi_probe.cpp](../../../tracer/src/test/device/jni_abi_probe.cpp) 和 [JniAbiProbe.java](../../../tracer/src/test/device/JniAbiProbe.java)。该独立夹具覆盖同线程 x18、真实栈、attach/callback、返回值与异常状态；使用前核对实际文件、产物哈希和准入报告。

## 第一阶段：两个 P0

### 1. 修复 JNI 参数解码正确性

已观察到 `conditionCallback(II[B)V` 的首个 variadic jint 文本显示成类似栈指针的超 32 位值。问题在采集、`va_list` 解码还是格式化尚未确定；先通过最小夹具定位，不直接用截断或强制转换掩盖异常。

代码起点：

- `tracer/src/main/cpp/handlers/call_handlers.cpp`：JNI enter/leave 与调用转移处理。
- `tracer/src/main/cpp/jni/jni_formatter.*`：参数与返回值展示。
- `tracer/src/main/cpp/jni/jni_call_resolver.*`、`jni_function_registry.*`、`jni_function_table.h`：调用识别及函数元数据。
- `tracer/src/main/cpp/jni/jni_state.*`、`jni_state_updater.*`：方法签名与状态传播。
- `tracer/src/test/cpp/jni_*_test.cpp` 和对应 `CMakeLists.txt`：已有 Host 验证入口。

实现与验收顺序：

1. 构造真实 Android arm64 JNI 普通调用、V 调用和 A 调用的同输入基线，复现文本与实参不一致。
2. 覆盖两个 int、正负值、byte[]、long/double 混合参数，以及参数跨寄存器和栈的边界；以 Java 实际收到的值和 native 调用者实参作独立对照。
3. 定位并在负责的解码层修复。签名或 ABI 不可确定时，明确输出未解码及原因，不能显示貌似可信的数值。
4. 验证输出值、顺序、符号、类型和 enter/leave 配对。确保观察不改变目标返回值、异常状态或调用语义。
5. 运行受影响的现有 Host 测试和真实 arm64 夹具；保存 RED/GREEN、源码与产物身份。Host 测试不能替代设备 ABI 证明。

### 2. 将 ABI 夹具做成设备准入

复用已有真实栈和 x18 夹具，组合 native 基线与 traced 的成对结果，覆盖 JNI attach/callback、异常状态和返回值。报告设备、ABI、tracer SHA、通过/失败/不可用及具体原因。

准入失败时，阻止后续复杂目标采集，并提供可定位的诊断。保持现有可用入口与配置兼容；先核对已有准入能力，再决定新增接口的位置。普通 JNI、V/A 调用与平台寄存器夹具可共用输入和身份记录，避免重复部署脚本。

这两个 P0 是首个实现闭环：最小复现、负责层修复、设备正向对照、诊断及文档同步。不要同时重写注入、flight 格式、CLI 和 UI。

## 后续阶段：完成 P0 后逐项推进

| 优先级 | 工作项 | 验收重点 |
| --- | --- | --- |
| P1 | scene 与生命周期状态 | 区分 scene 已进入、已返回、仍开放、目标退出及生命周期截止时间；不能把 flight 文件 complete 等同于目标函数返回。长 JNI/Binder 等待的诊断先核对已有能力，再增加有界、可选的 Java 栈或等待链信息。 |
| P1 | 大 flight 有界查询 | 先核查公共查询入口。对 256 MiB 输入测量首个摘要耗时、峰值 RSS、取消效果，以及按类型/时间/地址区间的流式读取。私有摘要脚本曾超过 45 秒、约 4 GiB RSS，这不是已确认的公共 CLI/UI 性能结论。 |
| P2 | 低开销定位方式 | 验证现有 fast/balanced/full 的实际采集内容，再评估调用/系统调用摘要、模块聚焦和按需升级详细采集；当前 fast 仍记录指令，不能称为已验证的独立 call-only 模式。 |
| P2 | 间接转移与进程控制边界 | 用当前 ABI 和构建做最小夹具，记录返回、未覆盖边界及原因；先证实问题，再提出修复。 |

每项先复现或测量，再实现最小闭环；完成适用验证后更新体验报告。未证明的问题保持候选状态，不把报告中的所有建议一次性实现成庞大框架。

## 证据与设备约束

- 目标设备候选是 Pixel 6 `1C111FDF600G6S`，Android16/API36、arm64。它可能被原会话或其他会话使用；先核对现有 adb server、serial、用户和 canonical guard，不重启 server、不抢锁、不终止其他会话的进程。
- Android SDK adb 的已有路径为 `/home/lyldalek/Android/sdk/platform-tools/adb`。使用前核实当前环境，不将历史设备在线状态视为当前事实。
- 保留设备原有 Root、USB/ADB、应用、账号和存档，不通过改变物理环境制造工具通过。
- 先用独立夹具验证工具。需要真实游戏复验时记录同输入无注入基线，使用空 CodeRules；不要使用 `scripts/appguard_dgup/rules.cpp` 或跳过游戏检测来证明工具正确。
- 记录 APK/目标库/tracer SHA、配置、注入入口、引擎、PID/epoch、scene、返回点、丢失区间和清理终态。16 个丢失 sequence 的 Settings/report 会话只能证明局部行为，不能宣称完整检测覆盖。
- Root 精确缓存写入来源主要由外部硬件观察定位，不能写成 QBDI 已完整跟踪。运行环境故障与工具缺陷须分别复现，不能仅凭目标退出归因。
- 历史 vfork 异常使用 x18 修复前的 `bd973672…` tracer；**当前剩余 vfork 缺陷尚未证实**。必须用当前产物最小复验。

## 每个优化闭环的交付

提交可审查的源码与适用回归；说明问题如何复现、修在何层、验证了哪些设备与输入、哪些仍未验证。同步使用说明和体验报告，保留原始证据及构建身份。确认自有临时库、采集线程和设备占用收尾；未知责任如实记录，不以超时当作取消或成功。

## 可直接粘贴给新会话

```text
请在 /home/lyldalek/workspace/qbdi-android 工作，先阅读
docs/superpowers/plans/2026-10-21-qbdi-optimization-handoff.md
及其中链接的工具体验报告，按照优先级优化 qbdi-android。

先核对并保留工作区尚未提交的真实栈、x18、followThreads 和 hook 岛兼容修复。
从 P0 JNI 普通/V/A 参数解码正确性及真实 arm64 ABI 准入开始：先做最小 RED/GREEN，
再在负责层修复并完成设备对照、诊断和文档。P0 闭环后继续按文档推进 P1/P2，
先检查已有能力，避免重复实现。不要抢占设备、关闭 USB、
改变物理运行环境或使用检测跳过规则来证明工具正确。
```
