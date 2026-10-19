# 数码宝贝 UP：AppGuard 校验、退出链与 QBDI 兼容性

> 后续改进已落地：当前 `engine` 默认由持久 QBDI hook 同时处理上报桥和退出线程；默认通用 CodeRules 为空。启动复用正式 `FridaInjector`，验收联合检查 PID、启动时间、标题标志与持续时长。当前结果及限制见 [可靠性改进验收](../benchmarks/qtrace-tracing-reliability-2026-10-19.md)。下文保留此前组合方案的分析过程；其中“默认”“最终”指此前实验，旧临时卸钩失败记录不代表当前实现。


本记录针对手机上实际安装的「数码宝贝 UP / DIGIMON UP」，不是宝可梦游戏。目标包名为 `com.bandainamcoent.dgup_ww`，版本为 `1.5.0`，versionCode 为 `55`。验收要求是进入标题或登录界面，并在同一个进程内连续运行至少 120 秒。

已通过该验收。QBDI 能跟踪 AppGuard 的实际上报桥，并用 CodeRules 阻断本机命中的 Root、USB 调试事件；独立的原生延迟退出线程由固定版本的原生跳板处理。最终复测 PID `32099` 存活 180 秒，标题界面两次截图间隔 162.14 秒；13 份轨迹严格解码通过，记录 7 次 Root、3 次 USB 上报阻断和 12 次原生退出线程阻断。普通 QBDI 跟踪存在临时卸钩窗口，纯 QBDI 拦截并发退出线程的实验未通过，不能把组合方案描述成所有阻断均由 QBDI 完成。

可复现工具位于 [`scripts/appguard_dgup/`](../../scripts/appguard_dgup/)，默认使用已验证的组合方案。没有替换 APK、关闭全局 USB 调试或移除设备的 Root。

## 样本与偏移的适用范围

测试设备是小米 11，Android 16 / API 36，arm64，LineageOS 23.2。系统存在 Magisk，USB 调试开启。文中的地址偏移只适用于以下样本；运行时地址需要加上当次映射基址。

| 文件 | 字节数 | SHA-256 |
| --- | ---: | --- |
| `libcompatible.so` | 1728552 | `e5e27eb73dd1d8a78da9ec7e2d09231bc93de045e98e1a9370f0b4f29eb84f86` |
| `libengine.so` | 1543880 | `4aeafdbe1ea691c8c6f7ea675cb817688a1f4875a258b97e1f342aaebd9094d0` |
| `libmain.so` | 6696 | `1aa3ef824c78cc5ba84f27ac38313790f33ab40125673174a6eff438558a5a89` |

磁盘上的 `libengine.so` 是 AppGuard 自定义容器，文件头为 `03 25 64`，不是 ELF。其运行时解包结果位于大小为 `0x184000` 的匿名 RWX 映射。下文的引擎偏移相对于这块映射，不是磁盘文件的直接补丁位置。

证据保存在本机的三个目录：

- `artifacts/appguard-dgup-2026-10-19/`：原始 APK、DEX、JNI 映射、ptrace 关系和早期 Flight 记录。
- `artifacts/appguard-stability-2026-10-19/`：无注入对照、Frida 生命周期和 QBDI 初始化跟踪。
- `artifacts/appguard-resolution-2026-10-19/`：运行时 DEX、检测事件载荷、阻断实验和验收记录。

这些目录受 Git 忽略规则管理。不要把报告中的相对路径理解为仓库已提交的原始样本。

## 启动与检测入口

Manifest 的 Application 为 `com.inca.security.Proxy.AppGuardFrontApplication`。类初始化加载 `libcompatible.so`，`attachBaseContext` 进入受保护的原生代理。运行时还存在 `com.inca.security.Core.AppGuardEngine` 等类，它们没有完整出现在原始五个 DEX 中。

另外有独立的隔离服务 `AppGuardService`。其 `SERVICE_ROOTING_MAGISK = 1`；Messenger 收到 `what=1` 时调用 `AppGuardPreAssistantNative.IiiiIIiIIi(1)`，把原生结果放入回复的 `arg1`。此服务的返回值含义未完整还原，不能把任意非零值直接写成「检测到 Root」。

主进程及两层子进程形成 ptrace 环：主进程跟踪子进程，子进程跟踪孙进程，孙进程跟踪主进程。这与 Android 的隔离服务是两套机制。已有跟踪者会阻碍后续 attach 和系统 crash_dump。

## 从运行时恢复校验逻辑

在进程内存中找到一个包含 183 个 `com.inca.security` 类的 DEX。其 `file_size`、`data_size`、`data_off` 被改为 `0x01010101`，直接交给解析器会报校验错误。

该样本的 `map_off = 0x4843c`，map_list 有 17 项，末尾为 `0x4850c`；string_data 起点为 `0xf6c0`。仅在主机副本中修复尺寸、数据区偏移、SHA-1 和 Adler-32 后，可以还原类和方法。没有把修复后的 DEX 写回游戏。

关键证据：

- `diagnostic-keepalive/appguard-runtime.repaired.dex`
- `diagnostic-keepalive/dex-reconstruction.json`
- `diagnostic-keepalive/appguard-runtime.disasm.txt`
- `diagnostic-keepalive/AppGuardEngine.java`
- `diagnostic-keepalive/AppGuardMessage.java`

反编译 Java 在控制流合并处有失真。分支、参数和偏移以 DEX 指令及运行时观测交叉确认。

## 已确认的检测项

错误框使用 `String.format("[Code:%08d]", code)`，因此数字是十进制。

| 事件 | 对应常量 | 本机证据 | 阻断位置 |
| --- | --- | --- | --- |
| `type=2, code=34` | `DETECT_ROOTING_ENVIRONMENT` | 原生载荷为 `199:/product/bin/su`；该路径是指向 `./magisk` 的符号链接 | 原生上报桥进入 Java 之前 |
| `type=2, code=38` | `DETECT_USBDEBUGGING_FLAG` | 设备 `adb_enabled=1`；只处理 34 后，实际弹出 `00000038` | 同一上报桥，独立判断 38 |
| `type=2, code=8` | `DETECT_INVALID_LIBRUNTIME_SO` | 对 `libart.so` 的 JNI 函数做 inline hook 后，上报 `libart.so{hash:...}` | 改用引擎自己的上报桥，避免修改 ART 函数正文 |
| `type=2, code=50` | `DETECT_HIDDEN` | 载荷前四字节为 `22 00 00 00`，随后包含 `BootloaderLocked : 0` | 当前保留原始处理；其 Java 解析器明确设置为不终止、不通知回调 |

34 的载荷证明此次命中与 `/product/bin/su` 有关，但尚未完整反汇编其文件探测函数。`199` 是原始载荷中的标记，不能据此编造厂商规则编号含义。38 的常量、设备状态和弹窗已确认；其具体读取哪个属性或系统 API，尚未独立还原。

## Java 策略与退出链

原生引擎调用：

```java
AppGuardEngine.conditionCallback(int type, int code, byte[] data)
```

`type=0` 是普通事件，`type=1` 是错误，`type=2` 是检测事件。对于检测事件，Java 侧选择解析器，应用策略，取得带符号的结果码，再决定是否启动退出线程。

`DetectionDataParser.applySecurityPolicy` 先根据 `code-1` 对应的位查询禁用和仅上报选项。允许终止时，`getMsgCodeWithStatus()` 返回正数；只上报时返回负数。隐藏事件的解析器返回 0。对 34 和 38，本次运行实际进入了终止分支。

`AppGuardEngine.conditionCallback` 的 DEX code_item 位于 `0x326f8`。其关键指令相对于该方法指令区：

| 指令偏移 | 行为 |
| --- | --- |
| `+0x00ae` | `sendHackLog()` |
| `+0x00b4` | `getMsgCodeWithStatus()` |
| `+0x00f8` | 调用监听器 `onDetected(...)` |
| `+0x011e` | 非正结果码直接离开终止路径 |
| `+0x0146` | 向 `AppGuardMessage` 发送策略违规消息 |
| `+0x014c` | 创建 `AppGuardEngine$4` |
| `+0x0156` | 启动退出线程 |

`AppGuardMessage` 显示不可取消的安全提示。`Globals.TerminateTimeout = 30`；`AppGuardEngine$4.run` 等待 30 秒，然后依次尝试：

1. 打开 HOME Activity。
2. 反射调用 `Process.killProcess(Process.myPid())`。
3. 反射调用 `System.exit(0)`。
4. 调用 `AppGuardAssistantNative.IllIIIlIII()`。

`AppGuardMessage` 自身也会启动退出线程。只隐藏弹窗或拦一次 SIGKILL，都不足以解除策略退出。实测拦截 SIGKILL 后，紧接着出现 `System.exit called, status: 0`，进程仍然结束。

## 对应的原生阻断逻辑

运行时解包引擎的 `+0x146c88` 是事件上报桥。根据参数寄存器、JNI 调用及正常返回路径，其接口为：

```cpp
int report(JNIEnv *env, jobject engine, int type, int code,
           const void *data, size_t length);
```

其中 `x2/w2` 是类型，`x3/w3` 是检测码，`x4` 是原始数据，`x5` 是长度。桥函数取得 `conditionCallback(II[B)V`，构造 Java byte[]，并在 `+0x146db8` 等位置调用本地 JNI 包装函数 `+0xa93e0`。包装函数在 `+0xa9454` 调用 `JNIEnv->CallVoidMethodV`。正常找到 Java 方法的返回路径在 `+0x146f30` 检查方法 ID，返回 1。

本轮采用的最小策略拦截：

```cpp
if (type == 2 && (code == 34 || code == 38)) {
    log_original_event(type, code, data, length);
    return 1;
}
return original_report(env, engine, type, code, data, length);
```

这是在本地阻断特定环境检测的上报及其 Java 终止分支，没有把设备修改为非 Root，也没有证明服务端会接受此环境。普通事件、初始化完成事件、隐藏事件及其他检测码仍走原函数。

安装前必须同时验证容器头、匿名映射尺寸、函数偏移和完整 16 字节入口签名。当前入口前四条指令都是基于 SP 的寄存器保存，适合本样本的固定跳板；不能把这种复制方式用于含 PC 相对指令的任意函数。

ShadowHook 在这个匿名映射上曾返回错误 40（分支岛分配失败），并且在 QBDI 同时安装时复现。实验改用经过入口签名验证的 ARM64 绝对跳转跳板。当前处理仅限启动前注入：先发布配置，恢复应用前卸载 Frida 会话，随后由原生线程等待引擎解包。不能把这一实现直接当成运行中任意时刻的安全热补丁。

## 第三条退出链：原生延迟终止线程

仅过滤 34、38 后，Java 弹窗和 30 秒退出线程不再出现，但仍会在约 85–95 秒退出。没有执行 QBDI 的对照也出现同类崩溃。

在晚期 SIGSEGV 观测中取得原生帧链，找到解包引擎 `+0xc6114` 的独立 `pthread` 入口。该函数等待约 `50 + rand()%10` 秒，然后调用其他终止任务、尝试发送信号，最后走 `exit(1)`。`+0xc61bc` 的退出调用，其返回地址是 `+0xc61c0`。

退出路径进入 AppGuard 的匿名 libc 副本。副本 `+0x1af24` 对应系统 libc 的 `__cxa_finalize+0xbc`；清理析构函数表时访问不可读页面，最终表现为 SIGSEGV。它是终止路径的下游表现，不能据此认定 QBDI 的正常执行损坏了析构表。

默认组合方案将 `+0xc6114` 接到一个立即 `return nullptr` 的线程入口。它不再等待或执行退出逻辑。它只修改这个已确认的引擎入口，不全局修改 `kill`、`exit`、ART 或 Java 的线程创建逻辑。上游完整的任务调度条件尚未还原，不能把每次创建该线程都归因于某个尚未定位的具体文件校验函数。

安装必须等待两个入口都完成解密。只看到 `0x184000` 映射或上报桥可读还不够：实测退出入口会晚约 10 毫秒才变为正常指令。

| 入口 | 必须匹配的前 16 字节 |
| --- | --- |
| 上报桥 `+0x146c88` | `fd7bbaa9fc6f01a9fa6702a9f85f03a9` |
| 退出线程 `+0xc6114` | `ff0303d1fd7b0aa9f44f0ba9fd830291` |

证据位于 `native-crash-caller/`、`qbdi-native-worker-ready/`、`final-qbdi/`。默认等待上限约 10 秒；版本、映射、签名不匹配时不写入目标入口，并在日志中报失败。

## 用 qbdi-android 分析上报桥

默认 `--mode engine` 使用逻辑模块名 `appguard-runtime.so`，基址指向经过签名验证的匿名解包映射。新增原生接口：

```cpp
int qbdi_tracer_install_region(const char *logical_module,
                              uintptr_t base, uintptr_t size);
```

此接口要求整个范围位于同一块可读、可执行映射，检查空范围、溢出和目标名。返回 0 只表示发起安装；安装是否成功仍以原生状态凭据为准。它不把匿名区伪装成 ELF，也不提供磁盘样本身份校验；本例由运行脚本的三个 SHA-256 和原生入口签名共同限定样本。

QBDI 跟踪区间为 `[0x146c88, 0x146f80)`。`rules.cpp` 在入口读取 `x2`、`x3`、`x4`、`x5`，记录原始事件。只有 `type=2 && (code=34 || code=38)` 执行：

```cpp
context.set_return_value(1);
context.set_pc(context.lr());
return QBDI::BREAK_TO_VM;
```

此时第一条指令尚未执行，栈未建立，立即返回的记录应当是 **0 条目标指令**，同时存在 `appguard-report`、`appguard-policy` 两条 RULE 和有效返回值 1。不能把这些记录当成已经执行了完整检测算法。

其他事件执行原函数。实测普通事件和隐藏事件分别产生 100 或 113 条目标指令，返回 1；它们的完整 QTRB、metrics、文本经过严格转换检查。窄范围没有把所有 JNI 包装函数、Java 逻辑和文件探测实现一并纳入指令跟踪。

## 工具实际暴露的问题及改善

使用评价：适合已知 native 入口的窄范围追踪，参数、规则事件、指令和返回值能形成可校验的证据。面对真实加固游戏，目前仍需要解包识别、目标专用规则和启动时机处理，尚未达到只填写包名即可稳定分析的程度。默认示例 CodeRules 含固定偏移修改；本例显式指定独立规则源，避免把通用构建中的示例规则带入目标分析。

| 问题 | 影响 | 本次处理 |
| --- | --- | --- |
| native 从 RX 映射计算 `start-file_offset` | `libmain.so` 基址多 `0x4000`，重复安装失败 | 优先采用 linker 的 `dlpi_addr` 和 PT_LOAD，与构造回调保持一致；保留非 linker 映射的原有回退 |
| CLI 仅从可执行 PT_LOAD 推导 ELF 原点 | 把正确的 `0x4a80` 拒绝为不可执行地址 | 改用全部 PT_LOAD 的最小 `vaddr-offset`，保留现有非零原点处理；加入真实 16 KB 布局回归用例 |
| 等安装完成才脱离 Frida | 空脚本驻留在启动期也曾引发 `sigaction` 崩溃 | 新增正式 `run/monitor --detach-before-resume`；先配置、卸载脚本、detach，再 resume，通过 ADB 严格校验原生安装凭据 |
| `wc -c` 回显完整长路径，但输出上限仅 128 字节 | 正常跟踪文件无法拉取 | 上限改为有界 8192 字节，覆盖路径及计数 |
| `adb exec-out su -c` 沿用 `adb shell` 的外层引号 | 拉到的是 shell 错误文本，随后报文件大小变化 | exec-out 按直接 argv 语义传递经校验的命令，去掉多余引号；实机 `qtrace pull` 完整成功 |
| 解包代码不在 ELF/linker 列表中 | 现有安装接口不能定位匿名引擎 | 增加显式区域安装接口，拒绝越界、不可读或不可执行区域 |
| 匿名区附近无法分配分支岛，ShadowHook 错误 40 | QBDI hook 无法安装 | 增加默认关闭的 `QTRACE_SHADOWHOOK_LONG_JUMP_FALLBACK`；本实验构建启用原库已有的长跳转回退 |
| 每次自定义 CodeRules 都要改默认源文件 | 目标专用规则容易污染通用 tracer | 增加 `QTRACE_USER_RULES_SOURCE` CMake 参数，本例独立编译规则 |

`--detach-before-resume` 不是把“配置收到”当作“hook 成功”。它核对状态 schema、session UUID、包名、PID、generation、全部场景偏移和错误字段；缺少凭据会超时，身份不匹配或有原生错误会失败。原有注入方式保持默认。若 detach 后 resume 失败，无法再通过已卸载的原进程 RPC 确认清理，会返回不完整清理证据，不报告成功。

长跳转回退只用于这个受控启动实验。它会覆盖多条入口指令；上游默认关闭该策略。本次保持通用构建默认关闭，也没有把版本限定的固定跳板改成通用 ARM64 重定位器。

注入库和 companion 都要先 `realpath`。该设备实际映射使用 `/data/data/...`。这一处理已存在于正式 agent，实验脚本也保持一致。

### 仍存在的并发覆盖问题

普通非 Flight 跟踪在 `trace_proxy_dispatch` 中临时 `unhook_function`，调用 QBDI 后重新挂钩。这个时间窗口内，其他线程可能直接进入原函数。

`qbdi-all-policy/` 实验用 QBDI 同时处理上报桥和退出入口：PID `30705` 的两条退出线程并发启动，只有一条留下 QBDI 阻断记录；另一条线程随后在约 80 秒出现同类原生终止路径 SIGSEGV。该现象与源码中的临时卸钩窗口吻合，第二线程的完整入口执行序列没有单独捕获。失败受线程时序影响。代码规则的单元测试通过，并不能证明运行时没有漏掉并发入口。

因此默认 `engine` 模式只用 QBDI 处理上报桥，退出入口保留原生拦截。`engine-qbdi-workers` / guard 模式 15 仅用于重现这一失败，**不是通过验收的运行方式**。修复普通跟踪的完整并发覆盖需要调整入口接管与 trampoline 执行方式；本次没有把未经验证的生命周期改造放入通用路径。

### 其他边界

- `libcompatible.so` 没有 GNU build ID，严格 ELF CLI 仍会拒绝它。`libengine.so` 是自定义容器；不能伪造 build ID 或把容器偏移当 ELF 偏移。匿名引擎分析目前需要上述专用启动脚本，尚非通用 CLI 的自动解包流程。
- 首次 constructor 的 Flight 曾保留约 48 万条指令，但大量为扁平化分派。窄范围跟踪实际策略桥，更容易确认参数、分支和返回值；没有宣称完整还原 AppGuard 的所有校验。
- 本机命中的是环境检测。游戏登录、战斗、支付、服务端校验和其他机型未纳入两分钟标题验收。
- Root、USB 检测会重复上报，不能只过滤第一次。默认 engine 使用无时长的原生 session，持续保留策略规则，直到进程退出。

## 实测验收与复现

| 用例 | 结果 |
| --- | --- |
| 无注入 | Root `00000034`，约 32 秒 SIGKILL；35 秒采样见原 PID 消失 |
| 只处理 Root | 暴露 USB `00000038`，仍按 Java 策略终止 |
| 处理 Root、USB，不处理原生线程 | 进入资源下载，约 85–95 秒走原生终止路径 |
| guard 13 ＋ QBDI 跟踪 Unity 初始化 | PID `21205` 连续存活 180 秒；标题截图间隔 235.64 秒；26 条初始化指令、返回 `0x10006` |
| guard 14 ＋ QBDI 上报桥规则 | PID `28496` 连续存活 180 秒；标题截图间隔 218.04 秒；普通事件执行 100/113 条指令，34/38 被规则返回 1 |
| 退出入口也完全交给普通 QBDI | PID `30705` 约 80 秒失败，确认并发入口漏拦 |
| 最终默认脚本，含状态校验和自动收集 | PID `32099` 存活 180 秒；标题间隔 162.14 秒；13 份 QTRB 和 13 份 metrics 拉取、大小检查及严格转换通过；原生状态无错误 |

标题验收的关键文件：`final-qbdi/title-{start,end}.{json,png}`、`qbdi-engine-long-jump/title-{start,end}.{json,png}`。这些文件与各自 `report.json`、maps、logcat、trace summary 一起使用，不能用重新拉起后的不同 PID 代替连续存活证据。

最终源码对应的凭据在 `final-engine/`：`report.json`、`startup.json`、`title-{start,end}.{json,png}`、`trace-summary.json`、`traces/`。共执行 326 条未被入口规则跳过的目标指令。恢复游戏前已脱离 Frida，两次 maps 采样均没有发现 `frida-agent` 或 `frida-gadget` 映射。此结果不等于证明任何检测器都无法识别插桩。

构建和执行默认方案（Linux 主机，NDK 26.1 已实测）：

```bash
python3 scripts/appguard_dgup/build.py --ndk /path/to/android-ndk
python3 scripts/appguard_dgup/run.py \
  --serial 2d32ed71 \
  --mode engine --seconds 180 --handle-startup-prompts \
  --output artifacts/appguard-$(date +%s)
```

需要主机的 `frida`、`Pillow` Python 包及版本匹配的设备端 server。`build.py` 自动寻找主机或 SDK 内的 CMake；也可传 `--cmake`。编译产物单独放在 `out/appguard-dgup/`，不覆盖通用 CodeRules。

`run.py` 在停止游戏前校验已安装的三个 native 样本哈希，使用 qtrace 的设备绑定和部署逻辑。启动后在同一原始 PID 上按 5 秒间隔采样；退出码为 0 还要求原生状态有效、无错误、轨迹和 sidecar 完整拉取、严格转换成功。它输出 `report.json`、`startup.json`、截图、maps、logcat、`traces/` 和 `trace-summary.json`。当前脚本还会匹配版本限定的标题标志，核对 `/proc/PID/stat` 启动时间，并要求连续标题时长至少 120 秒；生成 `acceptance-summary.json`。旧版验收曾依赖人工观察截图。

`--handle-startup-prompts` 仅处理通知权限拒绝和 Google Play Games 的取消按钮，不创建玩家资料或登录账号。游戏资源已经在本机完成下载；另一设备首次运行可能需更长时间。

若仅验证通用 CLI 的初始化跟踪，可在目标配置中选择 `libmain.so` 和 `[0x4a80,0x4b0c)`，使用：

```bash
python3 -m qtrace run --config target.json --duration 5s \
  --device 2d32ed71 --detach-before-resume --output results
```

这条 CLI 命令只验证初始化跟踪，不自动加载游戏专用策略 helper。正式 `qtrace pull` 已在本机验证可拉取、校验和转换原始 QTRB 及 metrics，相关报告位于 `official-cli-pull-stream-fixed/`。

本轮相关 Python 回归覆盖 injector、CLI、session、ELF、device、artifact，另检查 ShadowHook companion 和构建选择；native 检查 `module_maps_test`、`appguard_rules_test`、`tracer_entry_proxy_test`。16 KB ELF 的 CLI 用例和模块定位用例在修复前失败，修复后通过；传输另有使用实际 shell 的二进制保真回归。测试命令、文件摘要和实机结果汇总保存在本机证据目录的 `verification.json`。

所有运行时补丁在进程结束后消失。回退时强制停止目标包，移除本轮注入的缓存库和跟踪文件，再正常启动；不要替换原 APK 或清除用户游戏数据。
