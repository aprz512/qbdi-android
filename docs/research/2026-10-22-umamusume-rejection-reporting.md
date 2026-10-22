# 赛马娘独立调查：本地拒绝根因与远端上报边界

日期：2026-10-22。本报告记录 Java Root 条件、运行时方法定位、原生拒绝分支及候选内存队列的分析过程。结论分别绑定样本 SHA 和具体采集，不将不同轮次拼接成连续执行。

**已确认本次物理设备拒绝的本地原因：Cygames 的 `CheckApp.isRootUser()` 创建 `su` 进程成功，返回 true；游戏初始化随后显示 `Error0032` 无按钮对话框并停止推进。远端上报仍未证实。** 这条 Root 检查属于 Cygames Java / Cute.Core 调用链，不能直接归为 CrackProof 的检测项。

[机器证据](evidence/2026-10-22-umamusume-rejection-reporting.json)保存完整样本 SHA、四轮设备观察、原始资料清单及 81 个分析输入文件的 SHA。原始二进制、日志和快照保留在本机工作树；本报告只摘录相关检查日志，不导出其他注册令牌或无关日志内容。

## 样本与设备身份

| 输入 | 身份 |
| --- | --- |
| 游戏 | `com.cygames.umamusume`，英文版 `1.35.2`，versionCode `153` |
| 设备 | Pixel 6，serial `1C111FDF600G6S`，Android 16；物理安装 user `0`、UID `10172` |
| 系统 | `google/oriole/oriole:16/CP1A.260405.005/15001963:user/release-keys` |
| `classes5.dex` SHA-256 | `f29cb6dc7496c214335480e7421e95fc353e53092ce8ff23f7bcc1209ddbfb02` |
| `global-metadata.dat` SHA-256 | `75ed0dc144073cd925de615401ffa5c8b2877493ed24b62d8ddb9afeed167706` |
| `libil2cpp.so` SHA-256 | `144c6b1ca7d88d5a1455bf1b91b2c00137bd9475e3b89a6ddd50aebc066bee8b` |
| `lib__4e06__.so` SHA-256 | `160483775aae439b392ff12f0879925b3064cc0b7aff36fa0782efec1d7b59ee` |

每轮新启动均核对已安装 base/split 身份。以下地址仅适用于这些输入。`libil2cpp.so` 的地址为解包后运行时 RVA；不能将其直接当作原始磁盘文件中的明文代码偏移。

## Java 检查的实际条件

`classes5.dex` 中 `jp.co.cygames.androidroot.CheckApp.isRootUser():boolean` 为 `public static`，code item 位于 `0x2d8648`，首条指令位于 `0x2d8658`。字节码逻辑如下：

1. `UnityPlayer.currentActivity` 或其 `PackageManager` 为空时返回 false。
2. 调用 `Runtime.getRuntime().exec("su")`，随后调用返回进程的 `destroy()`。
3. 打印 `DEBUG===CheckApp: rootUser`，返回 true。
4. 捕获 `IOException` 时打印 `NameNotFoundException`，返回 false。该日志文字与实际捕获的异常类型不一致。

函数没有 `waitFor()`、退出码、UID 或提权结果检查。它把创建 `su` 进程且未抛出 `IOException` 当作 Root 命中；这不证明游戏获得了 root 权限。即使后续 root 授权被拒绝，也不能据此推断该布尔值为 false。

历史启动 `12018/3545067` 在 07:10:06.128 打印 `rootUser`，对应原拒绝界面。后续新启动分别核对日志、进程身份及 UI，不用跨进程观察补造连续调用链。

原始字节码摘录见[CheckApp 反汇编](/home/lyldalek/.codex/worktrees/cd7b/qbdi-android/out/umamusume-independent-20261022/checkapp-java-disassembly.txt)。

## 从检查结果到拒绝对话框

在新物理进程 `28811/7825056` 中，使用 `process_vm_readv` 保存五段已映射 IL2CPP 区域，共 `135,086,080` 字节；读取前后核对 PID/starttime。它是多次只读采样，不是原子快照，也不是磁盘 ELF 的复制品。

metadata version `31` 中，`Cute.Core.Device.IsIllegalUser` 是无参数静态布尔方法。结合 metadata、运行时方法表、原生签名及调用者，确认以下位置：

| 方法或分支 | 运行时 RVA | 作用 |
| --- | --- | --- |
| `Cute.Core.Device.IsIllegalUser` | `0x3412ad4` | 通过 JNI 调用 Java Root 检查 |
| `Gallop.GameSystem.<InitializeGame>d__33.MoveNext` | `0x6307760` | 游戏初始化协程 |
| Root 调用及布尔分支 | `0x630816c`、`0x6308170` | 调用后执行 `tbz w0,#0` |
| false 分支 | `0x63082a4` | 向父对象 `+0x30` 写入数值 `2`，结束本次协程 |
| `Gallop.LocalizeExtention.Text` | `0x6427fc0` | 解析标题与正文 TextId |
| `Gallop.DialogCommon.Data.SetSimpleNoButtonMessage` | `0x68a76c8` | 构造无按钮消息 |
| `Gallop.DialogManager.PushDialog` | `0x62dca58` | 展示对话框 |

Root 为 true 时，代码创建 `DialogCommon.Data`，依次解析 `0x3d6` 和 `0x4ca`，调用 `SetSimpleNoButtonMessage` 及 `PushDialog`，然后 `MoveNext` 返回 false。该路径没有执行 false 分支的 `+0x30 = 2` 写入。这里仅描述字段写入值，不为尚未验证的字段赋予业务名称。

metadata 默认值将 `Gallop.TextId.Common0071 = 982 / 0x3d6` 对应到 `Error`，将 `Gallop.TextId.Error0032 = 1226 / 0x4ca` 对应到 `You are not permitted to play on this device.`，与设备拒绝界面一致。压缩默认值分别为 `87ac` 和 `8994`；正文字符串长度为 `45`。

第二个新进程 `31698/7912331` 使用更小的读取窗口复核 JNI 参数：类名为 `jp.co.cygames.androidroot.CheckApp`，方法名为 `isRootUser`。引用前后稳定；原生包装函数 `0x244` 字节与前一进程完全一致，SHA-256 为 `a67852c72bc080529c483a24236d5ff56e40c2846119f3b990b78b35bce24f04`。该轮同时保留 `rootUser` 日志和[读取后的拒绝界面](/home/lyldalek/.codex/worktrees/cd7b/qbdi-android/out/umamusume-independent-20261022/physical-root-chain-control/screen-after-memory.png)。

这组证据将 Java true 分支、JNI 参数、原生拒绝分支、TextId 和实际界面对应起来；没有声称取得完整逐指令执行轨迹。结论限定为本版本、本设备上的这条拒绝路径，不排除其他启动阶段还有不同检查。

### 方法映射中被否定的假设

普通 token RID 索引最初得到 `0x341c55c`，但该函数写入实例字段，属于构造器形态，与无参数静态布尔方法 ABI 不符，因此已否定。失败结果仍保留在原始资料中，不能引用为 Root 函数定位成功。

本样本使用 image 内 metadata 方法顺序得到候选，再用静态签名、直接调用者、五个已验证方法、TextId 及第二进程中的 JNI 参数交叉确认。这里不推断通用混淆算法，也不将差异归为 Il2CppDumper 缺陷。

metadata 布局及压缩默认值解析参考固定上游提交 `f21d300861e6fc72b2c6a1a49bb49242169e0a11` 的 [MetadataClass.cs](https://github.com/Perfare/Il2CppDumper/blob/f21d300861e6fc72b2c6a1a49bb49242169e0a11/Il2CppDumper/Il2Cpp/MetadataClass.cs)、[Il2CppExecutor.cs](https://github.com/Perfare/Il2CppDumper/blob/f21d300861e6fc72b2c6a1a49bb49242169e0a11/Il2CppDumper/Utils/Il2CppExecutor.cs) 和 [BinaryReaderExtensions.cs](https://github.com/Perfare/Il2CppDumper/blob/f21d300861e6fc72b2c6a1a49bb49242169e0a11/Il2CppDumper/Extensions/BinaryReaderExtensions.cs)。只复用解析格式进行本地分析，没有运行 Il2CppDumper CLI，也没有将其加入产品依赖。

## 新启动对照与观察干扰

| 本轮目录 | PID/starttime | 结果与边界 |
| --- | --- | --- |
| `physical-root-control` | `25804/7783454` | 已保留 `rootUser` 和拒绝界面；`/proc/PID/mem` pread 得到 0 字节，进程随后自行退出。内存采集记为 unavailable，仅前缀有效。 |
| `physical-ui-only-control` | `27437/7811004` | 不部署读取器、不读目标内存；再次出现 Root 日志及拒绝界面。24 次身份采样覆盖 Root 日志后约 14 秒，进程持续存活。 |
| `physical-vmread-control` | `28811/7825056` | 仅用 `process_vm_readv` 读取完整的已映射 IL2CPP 区域；采集后主进程及 child `28905` 均存活。 |
| `physical-root-chain-control` | `31698/7912331` | 最小读取原生包装函数及两个 JNI 参数字符串；引用稳定，拒绝界面保持，主进程及 child `31799` 均存活。 |

第一轮系统 exit-info 为 `EXIT_SELF`、status `0`，不能称为原生崩溃，也不能将其直接解释为最初拒绝的后果。无内存读取对照保持存活，后续 vmread 两轮也完成；目前只确认 pread 尝试与退出在同一观察窗口发生，尚未证明观察干扰的具体原因。

读取器为独立静态 ARM64 程序，校验 PID/starttime，设备自测通过；SHA-256 为 `31dd36a16bc9943a31f76b379d51f6bc1c73ba63617c51f1b521055b7d468767`。vmread 模式不打开目标 `/proc/PID/mem`。本轮没有 Frida/QBDI 注入、ptrace 附加、目标代码或返回值改写。

设备操作均持 serial 专用锁。每轮开始时物理游戏为 `stopped=true`，结束后停止本轮创建的物理启动、删除临时读取器并恢复原前台；四轮 cleanup 均无错误。没有替换 APK、卸载、修改 root 策略或网络配置。正常启动可能更新游戏自身缓存，本报告不声称应用数据逐字节未变化。

## 远端上报：已推进到候选内存队列

历史进程 `26145/3911236` 的定点快照还保存了多个代码及数据区域。核心消费者通过描述符 `(143, 0x15a4)` 解析回调。另一段已保存的代码中，ID getter 返回 `143`，且模块 `+0x15a4` 与描述符匹配：

| 位置 | 已确认逻辑 |
| --- | --- |
| 候选模块基址 `0x723aaf4000` | 历史快照中的代码区域 |
| ID getter `0x723aaf559c` | 返回 `143` |
| 候选回调 `0x723aaf55a4` | 向内存队列追加一个 `80` 字节记录，返回 `1` |
| count `0x723ab13430`、队列 `0x723ab13438` | 对有效非负 count，`0..15` 追加并递增；`>=16` 不追加 |

主机 Unicorn `2.1.4` 执行原 ARM64 指令，通过 count `0`、`15`、`16` 和连续 `17` 次调用共四组检查；队列容量和边界哨兵符合上述逻辑。另有 36 个字符串解码结果与原生解码函数交叉一致。这些是原代码的主机验证，使用合成内存，不是目标 Android 上的执行证明。

**候选函数本身是内存队列追加器。** 运行时解析表位于未采集的 heap，缓存槽当时为零，因此仍未确认历史运行中最终绑定或调用了该候选函数。队列后续读取者及传输函数尚未闭合，不能将“记录错误上下文”直接写成“发送到远端”。已恢复的路径、环境和 proc 字符串也不能用来排除上传行为。

既有网络观察有以下缺口：

- 两轮 strace 的 `connect` 均为 `AF_UNIX`，但过滤器未采集 `write/writev/pwrite64/sendto/sendmsg/sendmmsg/socket`。继承连接、已有 FD 和其他 UID 代发均不在排除范围内。
- 原内核探针只覆盖 `__sys_connect`、`__sys_sendto`、`__sys_recvfrom`，发送采样上限 `384` 字节；没有覆盖全部写出路径或跨 UID 委托。
- `api.games.umamusume.com` 的 TLS SNI 和加密请求只能证明与该端点通信；不能仅凭域名将内容归为普通业务，也不能归为保护库上报。
- `app_4e06` 下既有 21 字节文件的 stat 和 `O_RDWR|O_CREAT` 打开，不足以证明该轮真实写入。`PlayIntegrity` 方法及模拟器检测桥的存在，同样不证明它们在拒绝时执行或上传。

远端上报仍缺两项关键证据：同一进程 epoch 内队列读取者与发送路径的实际关联，以及能识别语义并归属到责任模块的出站内容。本地 Root 拒绝已定位，不会自动补齐这些传输证据。

## 与旧 QBDI 证据的关系

旧构造器 Flight 只有有效执行前缀，没有显式构造器返回。窄 syscall 包装函数的 88 个 scene return 只证明该包装函数的局部返回。本调查没有补造旧采集的返回事件，也没有以新 Java/IL2CPP 结论替代当时缺失的 syscall、信号或父构造器证据。

原 CrackProof 指纹、五种路径函数的主机验证继续见[保护库补证](2026-10-22-umamusume-verification.md)；工具优化与验收继续见[handoff](../superpowers/plans/2026-10-22-qbdi-ux-handoff.md)。
