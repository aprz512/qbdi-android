# 赛马娘保护库补证：指纹、路径函数与观察边界

日期：2026-10-22。**原始 Android 库通过 CrackProof 公开 YARA 指纹复核；五种路径子串逻辑通过主机 ARM64 正/负对照。** 本报告只保留样本、分析方法和观察边界。

后续[独立调查](2026-10-22-umamusume-rejection-reporting.md)已确认本版本物理设备的 Cygames Java Root 检查及 `Error0032` 拒绝路径。候选上下文回调已恢复为 16 槽内存队列追加器，实际绑定、后续传输和远端上报仍未证实。本页继续保留原补证方法和计数，不将后续观察改写为本轮采集。

本轮只读复查原始资料和既有进程，另在主机仿真保存的原生指令。没有重新启动、附加、停止游戏，没有修改目标代码、返回值、配置或目标内存。既有 UX 功能和发布门禁结果见[交接](../superpowers/plans/2026-10-22-qbdi-ux-handoff.md)，不以这次样本调查重新认定工具正确性。

机器摘要见 [verification.json](evidence/2026-10-22-umamusume-verification.json)：含 31 项分析输入的 SHA-256、采集覆盖、函数输入/输出及对应进程身份。原始资料在 `6580` 工作树，本轮输出在 `cd7b/out/protection-verification-20261022/`；旧资料及旧 QBDI 采集保持原样。

## 样本归类：已有强指纹证据

对象仍为英文版 `com.cygames.umamusume` 1.35.2 / versionCode 153，arm64 `lib__4e06__.so`，SHA-256：

```text
160483775aae439b392ff12f0879925b3064cc0b7aff36fa0782efec1d7b59ee
```

固定 [APKiD 上游 commit 的规则](https://github.com/rednaga/APKiD/blob/deb0b623f2a1b9f64f23a72e2c125b63123c60f3/apkid/rules/elf/packers.yara)，在 `yara-python 4.5.4` 中编译原始 `crackproof_a` 及其 `is_elf` 依赖，对原库运行匹配；另用独立字节/通配匹配核对位置：

| 必要匹配 | 文件偏移 / ELF 虚拟地址 |
| --- | --- |
| `$init_proc` | `0x1d54` |
| `$do_asm_syscall` | `0x5e08` |
| `$func1`，满足至少一个 `$func*` | `0x1ae4` |

三个主机缓冲区负对照分别改变上述位置的一个固定字节，每次均使 `crackproof_a` 不再匹配。原样本文件及设备未改变。本轮实际运行的是 YARA 引擎中的上游规则，没有运行 APKiD CLI。

这足以将该样本归为 **CrackProof 公开分类器命中**。[DNP 官方资料](https://www.dnp.co.jp/news/detail/1187680_1587.html)确认 CrackProof 开发者为 DNP HyperTech；[官方 Android SO 产品页](https://www.hypertech.co.jp/products/android-so/)确认该平台产品存在。仍没有厂商或 Cygames 对此 SHA-256 的认证，也未确定保护版本及启用的完整检测项。[厂商来源核查](2026-10-22-umamusume-vendor-attribution.md)保留 Steam/Windows 与 Android 的范围区别。

## 路径匹配：五组函数行为已离线验证

分析输入是历史 PID `26145` / starttime `3911236` 的匿名可执行快照，映射 `[0x723801e000, 0x7238035000)`。以下绝对地址只适用于该快照，不能当作原始 ELF 偏移使用。

恢复到 `0x723802ef98` 的短字符串解码函数：逐字节计算 `(~rol8(cipher[i], 5) - (i & 3)) & 255`，遇输入零字节或长度上限停止。定位到 55 个直接调用点；保守解释同一基本块内的立即数初始化，完整恢复 46 处输入。全部 46 处均用 Unicorn 2.1.4 执行保存的原始 ARM64 解码指令交叉核对通过。未能完整恢复的输入保持未知，不补零猜测。

已恢复内容包括 `%s/lib`、`/mnt/asec/%s-%d/lib`、`/proc/self/maps`、`/proc/self/environ`、线程名/进程名路径、`LD_LIBRARY_PATH` 及 `/system/lib/libhoudini.so`。这些是代码中的观察能力，不能据字符串存在认定相应分支已经执行。

进一步从 `0x72380213dc` 执行完整路径匹配函数。主机仿真使用保存的原生代码和合成路径、栈、输出缓冲及 stack guard 数据；原生指令未改，未访问 Android 目标进程：

| 输入路径含有的子串 | 返回 x0 | 输出码 |
| --- | ---: | --- |
| `/com.cyjh.mobileanjian` | 1 | `0x26` |
| `/com.dualapp.multispace` | 1 | `0x34` |
| `/com.kcm.cloneapp` | 1 | `0x42` |
| `/io.va.exposed` | 1 | `0x50` |
| `/com.rinzz.wdf` | 1 | `0x5e` |

五组正例均通过；分别破坏子串起始 `/` 的五组负例，以及中性赛马娘路径，均返回 0、输出码 0，共 11 个完整函数对照。完整执行还恢复了上述五个字符串，其中三处输入此前无法仅在单一基本块内恢复。

**已证实的是路径参数的子串匹配及返回码，未证实“枚举已安装应用”，也未证实这些路径曾出现在设备实际输入里。** 调用者在 `0x7238020ba8` 调用该函数，命中后分支进入 `0x7238020f30`，再经 `0x723802fc64` 到 `0x723802f910` 构造、保存 80 字节内存上下文。后续独立调查进一步验证了候选队列追加器，但未确认实际绑定或发送链；保存上下文不能称为远端上报，也不能与已定位的 Cygames Root 拒绝直接等同。

## 路径查询：入口、返回与终止保持分轮

PID 26145 的停点为 `PC=0x7238030134`、`x8=79`。保存的栈在 `x1=0x7febd33de8` 处确实包含：

```text
/data/user/0/com.cygames.umamusume/lib/lib__4e06__.so
```

这是 `newfstatat` 的入口观察：`x0=0xffffffffffffff9c` 为输入 `AT_FDCWD=-100`，不是 syscall 返回或 errno。当前快照不能给出这一调用的返回。栈地址扫描的候选返回地址也不能称为完成展开的调用栈。

该镜像的 metadata 辅助函数 `0x723802afb4` 对调用成功返回真；失败时，非 EACCES 的 errno 路径返回假，EACCES 有单独的父目录权限回退。上层还有多套路径回退，因此一次路径失败不能直接升级为唯一终止条件。

另一轮 PID 20658 的 strace 记录了 legacy 路径 `ENOENT`、原生库备选路径 `EINVAL`，随后还有其他路径尝试及 SIGABRT。这与 PID 26145 的入口、主机合成函数结果分别保留；相同数值地址不构成跨进程连续执行证据。

## 本地记录和上报：修正旧结论的强度

原始 `native_wait.py` 的 strace 过滤器含 `connect`，但不含 `write/writev/pwrite64/sendto/sendmsg/sendmmsg/socket`，`read` 仅输出原始指针。重新审计两份原始轨迹：

| PID | 行数 | connect 入口 | 地址族 |
| --- | ---: | ---: | --- |
| 19897 | 68,420 | 9 | 均为 AF_UNIX |
| 20658 | 15,388 | 6 | 均为 AF_UNIX |

两份有界轨迹没有 AF_INET/AF_INET6 connect 入口。但已有连接、委托的其他进程，以及未采集的发送/写入路径均未排除，不能由此断言没有上传。

PID 20658 末段可确认 `app_4e06/ueD1IdeQ-BaGB0.txt` 已存在、大小为 21 字节，随后以 `O_RDWR|O_CREAT` 打开，再发生本 PID 发出的 SIGABRT。**这份轨迹不能直接证明该轮写入了什么**，旧参考中的“写入本地记录”据此收窄为“访问既有本地记录文件”。

## Java 加载入口

另用 Android SDK 35.0.0 `dexdump` 复核原 APK 的 `classes6.dex`：`EntryApplication.attachBaseContext` 调用 `load.entry()`，触发 `load.<clinit>` 的 `System.loadLibrary("__4e06__")`；这两个入口均没有 catch。该 DEX 为 2,992 字节，SHA-256 `a338f6c97a56069f1093d7bf6793dcead2b7408309bf96601c60b51179de6455`。

该 DEX 入口只说明库加载关系，不能代替构造器的动态返回证据，也不证明全部保护检查或完整游戏流程完成。

## 剩余缺口与可继续的证据

- 厂商对该 Android SHA 的认证与保护版本：公开分类器不能提供官方样本认证。
- 拒绝路径范围：后续已确认 Cygames `CheckApp.isRootUser` 创建 `su` 未抛 `IOException` 后返回 true，触发 `Error0032`；不证明获得 root 权限，也不排除其他拒绝路径。逐项环境 A/B 及五种路径检查的设备实际命中仍未完成。
- 远端上报：候选队列逻辑虽已离线验证，仍需确认实际绑定、队列读取者与写出路径，覆盖继承连接及相关进程，并把调用与具体模块、实际负载对应。游戏 API 的 TLS 流量不能单独证明或排除防护上报。
- 完整流程：旧构造器仍只有进入与停止证据，另一轮 88 次窄包装函数返回也只证明局部调用。

复核入口为 `out/protection-verification-20261022/{verify-yara.py,decode-snapshot-strings.py,emulate-path-helper.py}`。YARA 与 Unicorn 位于该目录的隔离分析环境，未增加项目运行依赖。本轮验证为 3 个 YARA 负对照、46 个原生解码交叉核对、11 个完整路径函数对照；未重跑没有改动的 UX 产品测试。
