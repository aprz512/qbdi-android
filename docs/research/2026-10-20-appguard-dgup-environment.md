# DIGIMON UP / AppGuard：环境检测清单

目标为「数码宝贝 UP / DIGIMON UP」，包名 `com.bandainamcoent.dgup_ww`，
样本版本 `1.5.0 (55)`。本文只记录 AppGuard 防护库的检测项、调用关系和观测证据。
检测常量存在、运行时命中、策略允许终止是三个不同事实。

已确认的环境检测包括 Root、USB 调试和运行库完整性。Root 载荷既出现过
`199:/product/bin/su`、`301`，也出现过 `MAGISK_TY:2:7`，不能把它们解释为同一个探测点。
应用虚拟化事件 `41` 目前只有静态定义，具体 native 判断函数尚未还原。
工具使用反馈见[防护库分析体验](2026-10-21-qbdi-dgup-tool-experience.md)。

## 证据范围

原始证据位于本机忽略目录 `artifacts/appguard-resolution-2026-10-19/`、
`artifacts/appguard-environment-pixel6-2026-10-20/` 和
`artifacts/appguard-environment-pixel6-2026-10-21/`。
APK、设备日志、运行时 DEX 和内存副本不随本文提交。

| 来源 | 取得或复核的证据 | 能证明的范围 |
| --- | --- | --- |
| 小米 11，2026-10-19 | 13 份 QBDI QTRB、metrics、上报参数 | 同一 APK 的已命中事件及实际执行片段 |
| Pixel 6，2026-10-20 至 21 | 局部 QBDI 轨迹、外部硬件执行和写入观察 | 指定检查函数的参数、缓存写入与上报关系，不能代表完整检测覆盖 |
| 恢复的 AppGuard DEX | 183 个类、45 个检测常量、检测线程与策略的 DEX 指令 | Java 实现及检测码定义；常量存在不代表本机命中 |
| 解包 native 内存副本 | `libcompatible.so` 初始化函数及 JNI 包装函数反汇编 | 局部调用关系，不代表完整还原 native 检测算法 |

此前上报桥实验启用了特定规则，下面单独说明其覆盖范围。
硬件观察与 QBDI 采集属于不同证据来源，不能相互冒充。

## 已确认的检测项及手段

| 检测项 | 事件码 | 实现或实际载荷 | 证据与限制 |
| --- | --- | --- | --- |
| Root 环境 | 34 | native 载荷 `199:/product/bin/su`；此前设备该文件指向 Magisk | 小米实际命中。尚未定位该轮具体使用 `access`、`stat`、`openat` 中哪一个；`199` 的含义未确定 |
| 已安装包检查 | 34，载荷 `301` | 遍历包名列表，实际命中 `com.topjohnwu.magisk` | owner、索引和字符串与同轮入队、上报事件互证，不能泛化为全部包检测规则 |
| 挂载表与 su 路径 | 34，载荷 `MAGISK_TY:2:7` | `strstr(magisk)` 与 PATH 中 `%s/su` 的 `access(F_OK)` 检查 | 硬件写入观察定位了缓存位来源；尚未用 QBDI 完整跟踪所有相关分支 |
| Magisk 专用辅助检查 | 服务命令 1 | `SERVICE_ROOTING_MAGISK=1`；Messenger 转入 `AppGuardPreAssistantNative.IiiiIIiIIi(1)`，通过 `arg1` 回复 | 服务入口已确认，返回值语义未完整恢复，不能把任意非零值写成检测成功 |
| USB 调试 | 38 | `Settings.Global.getInt` 读取 `adb_enabled`；首读为0后继续读取 `adb_wifi_enabled` | 原始上报、实际键名与返回寄存器互证，不能外推全部 USB 状态检查 |
| ART 运行库被修改 | 8 | 修改 ART 的 JNI 函数后上报 `/apex/com.android.art/lib64/libart.so{hash:ba1990da:480c910e}` | 支持运行库完整性检查；哈希算法与校验范围未确定，不能认定检测到了 Frida 名称 |
| Bootloader／硬件证明信息 | 50，隐藏事件 | 载荷包含 `Cert Count : 4 Verified 1 SecurityLevel : 1 BootloaderLocked : 0 (0)` | Java 使用 AndroidKeyStore 生成 EC 密钥并读取证明证书链；隐藏解析器不终止、不通知回调，不能把解锁信息等同于退出原因 |
| Java 调试器 | 11 | `AntiDebugThread.run()` 每6000 ms调用 `Debug.isDebuggerConnected()`，为真时上报 `(2, 11, "DDMS".getBytes())` | Java 与 DEX 实现一致；未通过 JDWP 制造阳性结果，线程启动受禁用选项控制 |
| native 反调试／防附加 | 相关常量22 | 主进程、子进程、孙进程构成 ptrace 环，三者依次跟踪下一个进程 | 结构会影响 attach 和 crash_dump；不能把 ptrace 环本身解释为已上报22 |
| Java HTTP 代理 | 42 | `AppGuardEngine.setReserved1()` 的特定分支读取 `System.getProperty("http.proxyHost")`，非 null 时上报 `(2, 42, host.getBytes())` | 已确认代码路径；未设置代理触发，不代表覆盖全部 VPN 或代理检测 |
| 受保护对象完整性 | 12 | `SecureDataIntegrityThread` 每6000 ms调用 `ObjectIntegrityManager.checkIntegrity()`，失败上报 `(2, 12, null)` | Java 调度和失败分支已确认，底层对象校验算法未完整还原 |

硬件证明代码位于 `DeviceEnvironment.getAttestationCerts()`，使用 AndroidKeyStore、
EC `secp256r1`、SHA-256 和 attestation challenge，读取证书链后删除临时别名 `appguard_key`。
调用关系从 `AppGuardClientImpl.appendAttestationCerts()` 可见；证书解析和服务端接受条件未完整还原。

## 静态检测常量与未确认项

以下映射直接来自恢复 DEX 的字段初值，不是根据通用检测清单猜测。

| 检测码 | 常量 | 可确认的含义 |
| --- | --- | --- |
| 32 | `DETECT_EMULATOR` | 模拟器检测事件 |
| 33 | `DETECT_INSTALLED_BAD_APPLICATION` | 可疑已安装应用；字符串表对应 `DETECT_BAD_APPLICATION` |
| 37 | `DETECT_CUSTOMROM` | 自定义 ROM 检测事件 |
| 40 | `DETECT_INSTALLABLE_NON_MARKET_APPS` | 非市场来源安装相关事件 |
| 41 | `DETECT_APP_VIRTUALIZATION` | 应用虚拟化检测事件 |
| 43 | `DETECT_CLOUD_EMULATOR` | 云模拟器检测事件 |
| 24 | `DETECT_SO_LIBRARY_INJECTION` | SO 注入检测事件 |
| 29 | `DETECT_API_HOOKING` | API hook 检测事件 |

另有 APK／签名、ODEX、libc／ART、framework、Unity assembly、内存扫描、
内存转储、可疑进程和内核模块等常量。完整字段和值见 `detection-constants-from-dex.json`，
客户端字符串表见 `detection-code-map.json`。

目前没有事件41的实际命中证据，也没有还原其 native 判断函数。
不能据此认定它使用 UID、PMS、ClassLoader、框架类名、CPU 属性或 `/dev/qemu_pipe` 检查。
`/proc/self/maps` 等字符串存在于 native 内存，不能单凭字符串归到某一检测码。

## Root 检查的具体调用关系

上报桥为匿名 engine `+0x146c88`，入队点为 `+0xc5f34`。
包枚举检查的调用方为 `+0x15e610`，上游 `+0x15cab4` 遍历26个包名。
`+0x15e528` 命中索引1，owner 表项为 `com.topjohnwu.magisk`；
owner、数组和字符串指针读取均成功，随后同轮取得入队与上报事件，三条事件、丢失为零。
此前未去除 owner 指针 TBI tag 的空字符串读取无效，不能据其推断检测目标。

另一条 Root 路径的原生工厂位于 `libcompatible.so+0x115c20`，参数3返回 `+0x14a104`。
该函数消费缓存的 `TY:2:7`，由外层补上前缀。载荷与旧包枚举的 `301` 不同。

硬件 WRITE watch 记录了 `+0x10274c` 的 `0 -> 0x10` 和
`+0x102778` 的 `0x10 -> 0x810`，两处调用者为 `+0x1026fc`。
上游 `+0x102a44` 扫描 `/proc/self/mounts` 中的 `magisk` 字串，
`+0x148e74` 拆分 PATH 并检查 `%s/su`。该轮两条事件、丢失为零，14个观察 FD 已关闭。
具体命中的挂载行和 su 路径仍待补全，不能把所有静态候选都列为动态命中。

按 carrier 字符串构造器和 AES-CFB128 解出的 app_process 映射、内存标记、
native bridge、environ/exe 和 mounts 等内容仍只作为候选，除非有单独的运行时正向证据。

## USB 检查与 JNI 表完整性

USB 硬件采样在匿名 engine `+0xedf88` 记录 `adb_enabled`，
在 `+0xedfdc` 记录 `android/provider/Settings$Global`，调用为
`getInt(ContentResolver,String,int)`，默认值零。
`+0xee094` 样本的结果寄存器为 `w21=1`，该地址的指令随后才复制至 `w0`；
因此旧 `w0=0` 不能作为返回值。随后 `+0x15bc78` 实际以 `type=2, code=38` 入队。
该轮四条事件、丢失为零。后续局部 QBDI 会话确认首读为0后还会读取 `adb_wifi_enabled`。

JNI 表检查函数为 `+0x154f7c`。它逐项检查 `GetEnv/AttachCurrentThread`
返回的 JNI 表前 `0x748` 字节：非空函数地址应处于真实 `libart.so`，另有 `libhoudini.so` 特例。
三个子检查在 `+0x15145c / +0x151464 / +0x15146c` 的返回值曾为 `0 / 1 / 0`。

失败路径的 `+0x151414` 写出4100字节帧，前四字节为 little-endian `9005`、正文全零；
接收端 `+0x14ca44` 进入 `+0x152a18`，映射为检测参数23。
相邻的 `mov w0, #13` 不在该路径上，分支直接跳到 `+0x1535c4`，不能把13写成本轮退出实参。
这些检查说明了函数地址完整性约束，不能仅据失败结果认定检测到了某个工具名称。

## QBDI 证据如何使用

上报桥参数接口为：

```cpp
report(JNIEnv *env, jobject engine, int type, int code,
       const void *data, size_t length);
```

`x2` 为类型，`x3` 为检测码，`x4/x5` 为载荷和长度。
原始13份 QTRB 的 SHA-256、文件大小、严格转换与 metrics 均已复核，
合计326条实际记录指令。详情见 `prior-trace-verification.json` 和 `prior-qbdi-events.json`。

其中34、38在此前实验中被入口规则立即返回，因此对应轨迹是
**0条目标指令加原始参数事件**。它们证明上报参数，不能证明逐指令还原了文件探测或 USB 读取算法。
隐藏事件与普通事件保留了实际执行指令；规则及退出链见[此前研究](2026-10-19-appguard-dgup.md)。

后续空 CodeRules 会话 `2e87c49c-e361-487a-bc6b-d386d0b23c3e` 保留214,062条指令、
1,224条 call、54,439条 memory；存在3个缺失区间、共16个 sequence。
它确认了 Settings 读取和五组正常返回的 `conditionCallback(II[B)V`，不能宣称完整检测覆盖。
历史 variadic jint 文本曾误把栈指针当参数，检测类型须与原始寄存器互证；
后续通用修复与独立对照见[JNI/arm64 验收](../benchmarks/jni-abi-2026-10-21.md)。

早期构造阶段会话 `f720cd78-67c4-43e6-aad1-e1f11737ff3c` 保留1,671,415条指令和412条 call，
证明 pre-constructor 入口取得了实际记录，但未确认目标完整返回。
Flight 的 `complete` 只表示文件结构有效，不等于目标调用已经返回。

## 安全事件与退出的关系

native 上报后，Java 进入 `AppGuardEngine.conditionCallback(type, code, data)`。
只有 `type=2` 是检测事件；同样的数字在其他 type 下含义不同。
`DetectionDataParser` 依据禁用和仅上报位决定是否终止。

此前34、38进入过安全提示及约30秒退出分支，依次尝试 HOME、
`Process.killProcess`、`System.exit(0)` 和 native 终止接口；另有独立原生延迟终止线程。
详见[退出链研究](2026-10-19-appguard-dgup.md)。
不能把类查找异常、ART abort 或插桩 ABI 故障直接解释为安全策略退出。

## 样本身份与复核入口

| 文件 | SHA-256 |
| --- | --- |
| base.apk | `afa07ad0c62b1dc14be1d6d6f76846621abdc86b16952e7645152242f3f4d56c` |
| arm64 split | `3bf06b2fcd80a5fe61287e3793d2d6613cb5b467d559de33ffaf0e4412256ee9` |
| libcompatible.so | `e5e27eb73dd1d8a78da9ec7e2d09231bc93de045e98e1a9370f0b4f29eb84f86` |
| libengine.so 封装文件 | `4aeafdbe1ea691c8c6f7ea675cb817688a1f4875a258b97e1f342aaebd9094d0` |

原始 DEX、Java 反编译与 DEX 指令位于
`artifacts/appguard-resolution-2026-10-19/diagnostic-keepalive/`。
`detection-constants-from-dex.json`、`detection-code-map.json` 和原始上报记录需一起使用。
所有偏移、签名和载荷均限定于本样本；版本变化后须重新校验，不能直接套用。
