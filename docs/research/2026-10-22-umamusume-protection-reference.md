# 赛马娘防护库：观察手段、检测线索与分析过程

本参考整理 2026-10-22 的样本分析，只保留防护库与 qbdi-android 工具使用相关内容。它供后续体验优化和分析方法复用，不提供完整检测清单，也不宣称已经定位游戏拒绝的唯一条件。

筛选后的计数、指令字、字符串及原始资料 SHA 见[证据摘要](evidence/2026-10-22-umamusume-protection.json)。不同采集分别保留，不能拼接成同一次连续执行。摘要只导出限定事实，不要求阅读其他调查材料。

后续[补证报告](2026-10-22-umamusume-verification.md)与[新机器摘要](evidence/2026-10-22-umamusume-verification.json)确认了 CrackProof 指纹命中、五种路径子串函数的离线正/负对照，同时修正了本地文件写入证据的强度。旧 QBDI 采集的返回边界保持不变。

在 handoff 本地合入 main 后，另行完成[拒绝根因与远端上报调查](2026-10-22-umamusume-rejection-reporting.md)：本版本物理设备拒绝已定位到 Cygames `CheckApp.isRootUser` 的 `su` 进程创建检查及 IL2CPP `Error0032` 对话框分支。候选保护库回调已恢复为 16 槽内存队列追加器；实际绑定、后续传输及远端上报仍未证实。该调查独立于工具功能验收。

## 样本身份与加载入口

| 项目 | 本轮输入 |
| --- | --- |
| 游戏 | `com.cygames.umamusume`，英文版 `1.35.2`，versionCode `153` |
| 目标库 | arm64 split 内的 `lib__4e06__.so`，`EM_AARCH64` |
| SHA-256 | `160483775aae439b392ff12f0879925b3064cc0b7aff36fa0782efec1d7b59ee` |
| SONAME | `lib__XXXX__.so` |
| ELF 入口与首个非零构造器 | 模块相对 `+0x1d54` |
| Java 加载入口 | `com.cygames.umamusume.EntryApplication.attachBaseContext` 经 `util001.framework.load` 加载 |
| 直接 syscall 包装函数 | 模块相对半开区间 `[0x5e08, 0x5e3c)` |

导出名称与多数可读字符串经过处理，文件含异常大的尾部 section；结合 Java 加载位置和构造器，可将其作为受保护启动加载器分析。后续以原始 YARA 引擎复核 APKiD 的 `crackproof_a`，构造器、SVC 包装及额外代码片段均匹配，并通过三个字节扰动负对照，已有 CrackProof 强指纹归类证据；具体厂商样本认证、版本及完整检测配置仍未知，见[厂商核查](2026-10-22-umamusume-vendor-attribution.md)。

## 已观察行为与检测线索

| 线索 | 已有证据 | 可以说明什么；尚不能说明什么 |
| --- | --- | --- |
| 绕过 libc 的直接 SVC | `+0x5e1c` 为 `mov x8,x7`，`+0x5e20` 为 `svc #0`；原始指令字分别为 `e80307aa`、`010000d4`。动态采集有 syscall-enter。 | 仅 hook libc 会漏观察路径；直接 syscall 也可服务加载/解包，不单独证明反调试。 |
| 进程映射和自身库路径观察 | 只读诊断记录过读取 `/proc/self/maps`、按映射中的路径重新打开自身库。 | 存在映射/路径观察；不能仅凭访问 maps 判定具体检测目标或拒绝条件。 |
| 加载路径与目录 metadata | 定点运行时快照与反汇编关联到路径查询，镜像中出现 `bool checkLoadPath_extractNativeLibs_true(const char*)`；后续恢复五种路径子串匹配及输出码，并在主机执行原 ARM64 函数通过 11 个对照。 | 已确认这一局部函数的输入/输出逻辑；实际 Android 分支命中、完整通过条件及拒绝根因仍未知。主机合成结果不能当作设备执行证据。 |
| 系统库相关检查 | 同一镜像有 `jni/checkSystemLib.cpp` 标记。 | 是进一步定位的线索；字符串不能代替已执行调用链、校验算法或失败判定。 |
| 本地文件访问及主动终止 | 诊断窗口确认 `app_4e06` 下既有文件的 stat、`O_RDWR|O_CREAT` 打开，随后 SIGABRT。原 strace 未采集 `write/send*`。 | 证明文件访问与终止；不能直接证明该轮写入、记录内容或远端上报，也未隔离导致终止的具体条件。 |
| 子进程与信号观察 | 不同诊断轮次观察过父子进程、ptrace 和信号交互。 | 需结合实际 syscall 返回、signal 交付与 handler 返回分析，不能把子进程存在、SIGSEGV 或末端 SIGKILL 直接称为防护检测命中。 |
| Cygames Java Root 拒绝 | 后续字节码、运行时 JNI 类名/方法名、IL2CPP 分支及新启动 UI 对应到 `CheckApp.isRootUser` 和 `Error0032`。 | 已确认本设备、本版本的这条本地拒绝路径；条件是创建 `su` 未抛 IOException，不证明获得 root 权限，也不归因于 CrackProof。 |

原始采集没有完成针对 Root、Frida、Xposed/LSPosed、Magisk 或模拟器的逐项受控 A/B。单独的 `You are not permitted to play on this device.` 截图只能证明界面拒绝；后续独立调查通过字节码、运行时代码与参数、无内存读取对照补齐了上述 Root 分支证据，但仍未完成全部检测项的逐项 A/B。

## 分析过程与有效观察边界

### 1. 先固定输入与对照

保存原始 APK/split、目标 ELF SHA、实际进程身份和启动日志，先观察无注入行为。随后每轮记录 tracer/companion SHA、Frida host/server 版本、scene、配置、PID/starttime 和观察时段。

本轮工具源码基线为 `eb79bcb2c37acb27affda4983ecb099e3ac5c497`。实际复用且核过 SHA 的 tracer 为 `f0ad3048b2d2d0ae4cea91182cf8c3de67e493a1a9b0fbf8bc864dcced1494d5`，companion 为 `636fbfb054ef93d1ce7009654b2fe6489463bde5b2369503e519e8d4eda293fa`。这些是历史产物身份，新构建须重新绑定源码与设备证据。

### 2. 用静态入口定位最小动态窗口

检查 ELF header、program headers、动态表和构造器，不假设 ELF 虚拟地址等于文件偏移。`+0x1d54` 保存寄存器、调用内部实现后恢复并返回。直接 syscall 包装函数另保存寄存器、设置 x8、执行 SVC 后返回，适合作为比整个构造器更窄的采集点。

这些偏移仅对应上述 ELF SHA。场景地址使用模块相对偏移，不复用某次 ASLR 基址；定位方法见[偏移说明](../ida-offsets.md)。

### 3. 用 Flight 保留早期退出前缀

手工 native 配置曾因缺少必填字段返回 `NATIVE_CONFIG_REJECTED`，该轮没有有效指令证据。修正配置后，普通异步轨迹在早期退出窗口仍可能只有 crash marker 或缺少可恢复正文；不能把文件存在算作成功采集。

构造器的一次独立应用采集使用 64 MiB Flight、`events: calls`、native `followThreads: false` 和 5 秒 deadline，恢复出 70 个事件，其中 66 个 syscall 入口：

| syscall | 入口数 |
| --- | ---: |
| openat | 1 |
| mmap | 1 |
| lseek | 1 |
| read | 62 |
| close | 1 |

场景记录为 `enter` 后 `capture_stopped`，没有构造器返回事件。其结论是保留了一个有效前缀，构造器返回未知；后续 SIGABRT 也不能补成返回证据。

### 4. 缩到 syscall 包装函数，逐次核对局部返回

另一轮只采 `[0x5e08, 0x5e3c)`，恢复 353 个事件、88 个 syscall 入口及 88 个 scene return：

| syscall | 入口数 |
| --- | ---: |
| openat | 3 |
| mmap | 4 |
| lseek | 5 |
| read | 68 |
| close | 3 |
| munmap | 2 |
| mprotect | 3 |

本片段没有 signal 事件，最后一个 mprotect 对应包装函数返回 x0 为 0。它证明这段包装函数的局部调用有返回证据，不证明父构造器、后续解包代码或完整防护流程完成。两张表来自不同采集，不能比较成同一进程的连续阶段。

上述历史 `calls` 采集的 syscall-enter 提供号、PC 和六个入口参数，路径只保留指针；scene return 是显式函数返回，不能升级为所有 syscall 的返回与 errno。当前工具另有默认关闭的[syscallDetails](../syscall-details.md)，提供有界路径及严格配对的返回；新能力不补写这些旧采集缺失的数据。相关状态语义见[使用指南](../usage.md#场景状态与有界离线查询)。

### 5. 在实际执行时取得解包镜像

较晚读取的匿名可执行映射曾已经清零。快照全零不能说明此前没有代码，也无法恢复当时分支。

更有效的做法是在目标路径查询仍执行时短暂停住实际线程，保存寄存器、maps、栈及对应可执行区域，然后立即解除观察。该定点镜像保留了加载路径检查标记和可反汇编代码。动态字符串只作为定位入口，仍需用实际调用和独立对照证实条件。

二进制导出按 maps 的精确区间截取，先确认原始工具是否混入尾部统计文本；带文本尾巴的文件不能整体当作机器码。跨轮比较核对 PID/starttime 和镜像身份，不使用已退出或复用 PID 的后读结果解释早期现场。

### 6. 区分真实行为与观测干扰

- 全局 Frida `Process.setExceptionHandler` 曾截获大量 ART 正常隐式异常并引发 suspend timeout；这轮不能用于认定原始故障原因。
- Flight signal 的 PC 可能是 QBDI 逻辑 PC；它不一定是原生内核现场的故障指令。
- ptrace 截获、信号实际交付、handler 消费/返回与进程终止是不同事件，最终 SIGKILL 不能单独解释最初原因。
- 一轮附加观察改变了终态时，保留无注入对照并缩小观察范围；不能把不同终态拼成同一因果链。

## 对工具体验优化的输入

1. 复用配置构造器，明确 CLI/native schema，尽早定位缺字段与环境问题。
2. 给出从无注入基线、Flight/calls 到窄包装函数的可复现示例；默认展示采集状态与返回证据的区别。
3. 评估可选的有界只读路径快照及明确配对的 syscall 返回；截断、坏指针、缺失证据不能显示成可信值。
4. 改进进程身份、信号来源及未知收尾的说明；Java/JIT 快照作为需独立验证的可选能力。

优化顺序、现有能力和验收要求见[体验优化交接](../superpowers/plans/2026-10-22-qbdi-ux-handoff.md)。本参考不要求重做完整样本分析，也不包含目标返回值修改或检测绕过规则。
