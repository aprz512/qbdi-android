# qbdi-android 实战体验：AppGuard 防护库分析

后续离线优化已使原256 MiB密集语料在原2 GiB预算内完成索引，并新增按真实场景时间返回场景内事件的查询，
见[Flight 查询优化](../benchmarks/flight-query-2026-10-21.md)。场景范围与逐事件时间仍明确区分，以下历史测量及证据范围保持原样。

两个 P0 已完成独立工具验证，见[JNI/arm64 验收](../benchmarks/jni-abi-2026-10-21.md)。
普通/V/A 解码、带符号数值和浮点返回文本已通过同输入 Java/native 正向对照；同线程 x18、真实栈及 attach/callback 纳入设备准入。
CLI 可通过 `--abi-report` 在注入前绑定设备与产物 SHA。固定 float/double 参数、构造器、实例及 nonvirtual 调用已纳入同一通用夹具，当前为30份轨迹、14项设备准入。

后续 P1/P2 已完成独立最小夹具验证，见[通用优化验收](../benchmarks/qbdi-generic-2026-10-21.md)。
场景状态分开描述采集封口与真实返回；新增有界元数据预览、实际场景时间查询和可选 calls 事件选择。
vfork、exec、进程退出与 pthread_exit 的封口已有设备正向对照。
无逐指令时间戳、原生子分支覆盖边界和未证明 CPU 加速等限制仍保留。
这些通用结果不替代下文防护库场景的实测，也不扩展其历史结论。

本文分析 DIGIMON UP `com.bandainamcoent.dgup_ww` 1.5.0(55) 中的 AppGuard 防护库，
重点为 native configure/status API、logical region、Flight 回收和 JNI 观测。
本轮没有完整评测公开 qtrace CLI 或 qtrace-ui，不能把实验脚本的问题直接当作这些入口的缺陷。
检测函数、地址与证据等级见[检测研究](2026-10-20-appguard-dgup-environment.md)。

## QBDI 实际帮助解决的问题

| 观察目标 | 取得的证据 | 能作出的结论 |
| --- | --- | --- |
| USB/无线 ADB | 空 CodeRules 会话 `2e87c49c-e361-487a-bc6b-d386d0b23c3e` 中的 `NewStringUTF`、`Settings$Global.getInt` 和 helper 返回寄存器 | SDK 先读 `adb_enabled`，首读为0后继续读 `adb_wifi_enabled`；只分析第一个键会漏掉后续分支。 |
| JNI 上报与工具 ABI | 五次 `conditionCallback(II[B)V` 均有对应 leave；原始寄存器与外部观察核对 SDK 类型 | 可以确认这些调用实际返回；历史参数文本仍需核对，不能只相信格式化结果。 |
| 匿名解密代码 | 按映射头及指令签名确认代码后，注册 logical region 并设置 scene | 不必先还原整个保护库，也不依赖 maps 中存在完整 SO 名称，可聚焦匿名 engine 的 Settings/report 入口。 |
| 早期构造阶段 | pre-constructor 会话 `f720cd78-67c4-43e6-aad1-e1f11737ff3c` 保留1,671,415条指令和412条 call | 构造前入口取得实际记录；未确认完整返回，不能把文件有效当作调用完成。 |

Settings/report 会话保留214,062条指令、1,224条 call、54,439条 memory，
存在3个缺失区间、共16个 sequence。它是有效的局部证据，不是全部检测覆盖证明。
该轮 tracer SHA-256 为 `67f3aed005ba3c487df413265304190f20188e8a0b521c5e91bf6556e3e3b262`，
不能用这个历史哈希声明其他构建已经通过。

Root 判定采用 QBDI、外部硬件执行/写入观察和静态解密的交叉证据。
包枚举命中 `com.topjohnwu.magisk` 对应34/301；挂载表 `strstr(magisk)` 与 PATH
`%s/su`/`access(F_OK)` 写入0x10和0x800，最终载荷为34/`MAGISK_TY:2:7`。
精确缓存写入来源主要由硬件观察定位，不能冒充 QBDI 已完整跟踪这些分支。

## 有效的工具能力

- **指令、寄存器和 JNI 元数据互证。** 可确认读取了哪个键，以及寄存器在当前指令执行前还是执行后有效；方法名和签名帮助连接 native 与 framework 调用。
- **logical region 与显式 scene 适合解密保护库。** 可从上报、Settings 或缓存消费者逐步缩小目标，避免把所有解包指令都纳入同一分析。
- **Flight 保存局部现场。** 退出后仍能回收片段；完整性、缺失区间和哈希可用于限定结论，文件结构 complete 不等于目标调用返回。
- **schema、状态和构建身份便于复核。** UUID、容量和未知字段会明确拒绝；核对 tracer SHA 避免把旧版本失败归因于当前源码。

## 分析中暴露的工具问题

| 问题 | 复现与影响 | 修复与证据 |
| --- | --- | --- |
| 目标使用虚拟栈 | traced native 调用进入 ART `AttachCurrentThread` 后，ART 发现 SP 不在真实 pthread 栈范围并 abort | 目标保留真实线程栈，QBDI engine 使用独立栈；后续独立 JNI/arm64 夹具覆盖真实栈与 attach/callback。 |
| Android arm64 x18 未初始化 | 历史 traced x18 为0，真实 JNI 随后 SIGSEGV | 初始化时复制同一 pthread 的平台 x18；独立设备准入检查基线与 traced 值，并验证 Java 回调和异常状态。 |
| 自动线程跟踪消耗 scene 槽 | 无关 pthread 占满有限槽位，显式目标无法进入 | 增加默认开启的 `flight.followThreads`；聚焦时可设 false，已有单槽及无关线程回归。 |
| 多套 inline hook 复用 ELF gap | 已使用的 libc 跳板被另一套 ShadowHook 当作空闲岛，发生 ABI 冲突 | 调试构建避免复用 ELF gap，使用独占匿名岛或已有长跳转能力；不把跳板冲突解释为防护库检测。 |

独立设备夹具为 [jni_abi_probe.cpp](../../tracer/src/test/device/jni_abi_probe.cpp) 与
[JniAbiProbe.java](../../tracer/src/test/device/JniAbiProbe.java)，运行方式见[JNI/arm64 准入](../jni-abi-acceptance.md)。
它们验证工具 ABI，不需要执行或修改游戏检测函数。

## 历史痛点与优化验收

下表记录当时的观察和建议；已完成的通用工作见本文开头链接，不据此补写未执行的防护库复验。

| 优先级 | 本轮痛点 | 建议与验收 |
| --- | --- | --- |
| P0 | `conditionCallback(II[B)V` 的首个 variadic jint 文本显示成栈指针 | 定位采集、va_list 解码和格式化链；以真实 arm64 普通/V/A 夹具覆盖整数、byte[]、long/double 和寄存器/栈边界，文本与 Java 实收值互证。 |
| P0 | 工具 ABI 故障表现为目标自身 ART 崩溃 | 将真实栈、x18、attach/callback、异常和返回值纳入设备准入，以基线、traced 结果和构建 SHA 绑定后续采集。 |
| P1 | trace 文件有效与场景正常返回容易混淆 | 分开显示进入、返回、仍开放、目标退出和截止时间；长 JNI/Binder 等待不能仅凭没有新指令判为新反调试检测。 |
| P1 | 大 Flight 的人工恢复脚本曾超过45秒、RSS约4 GiB | 为256 MiB输入测量摘要耗时、RSS与取消；优先有界预览和按需查询，该观察不是公开 CLI/UI 已确认的性能缺陷。 |
| P2 | 全指令跟踪对寻找少量环境探测点成本较高 | 明确 fast/balanced/full 的实际内容，评估可选调用摘要、模块聚焦与后续详细采集。 |
| P2 | 间接转移后是否返回或继续覆盖需要人工判断 | 用当前 ABI 做最小间接分支和进程控制夹具，报告未覆盖边界，不从旧产物推断当前缺陷。 |

历史会话 `c13e8a4d-a4f7-40b7-9e85-ea2cde06a968` 的 vfork/_exit/stack protector 异常使用修复 x18 前的
`bd973672…` tracer，不能作为当前版本缺陷的证据。后续通用 vfork 修复有独立夹具，
见[进程边界验收](../benchmarks/qbdi-generic-2026-10-21.md#间接转移与进程边界)，两组证据分别保留。

## 后续分析方法与边界

先建立同输入的无注入基线，再从少量明确入口采集。记录 APK、库和 tracer SHA、
注入方式、PID/epoch、scene、返回点、缺失区间及失败清理结果。
关闭无关线程跟踪是聚焦配置，不能据此声称全进程覆盖。

“检测了什么”优先由真实读取、判定寄存器、缓存写入和上报链证明，静态字符串只作为候选。
USB 证据限定于实际读取的两个 Settings 键，不能外推全部 USBManager、broadcast、sysfs 或硬件证明检查。
Root 缓存写入、JNI 表检查和普通上报路径也应分别定位，不能用一个安全码替代全部因果链。

类查找异常、工具栈错误、UUID/容量配置拒绝、禁用 linker init、误读缺失区间等，
均须先复现并核对输入。不能把任意进程退出都归因于防护库命中新检测。
本文结果只限指定防护库、采集入口和观测窗口，不代表所有检测均已覆盖，也不证明插桩无法被识别。
