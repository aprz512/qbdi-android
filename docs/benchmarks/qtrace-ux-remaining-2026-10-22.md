# 使用体验剩余实现与验收：2026-10-22

[handoff](../superpowers/plans/2026-10-22-qbdi-ux-handoff.md) · [实施计划](../superpowers/plans/2026-10-22-qbdi-ux-remaining.md) · [机器证据](evidence/qtrace-ux-remaining-2026-10-22.json)

本轮完成更多路径 syscall、普通 QTRB、嵌套信号/SA_RESTART、PC 来源及可选运行时/Java 快照。独立功能验收、新版发布基线校准、完整设备发布门禁及恢复均通过，当前状态为 **PASS**。实现保留在 `cd7b` / `feat/qtrace-ux-handoff`，基线 `eb79bcb2c37acb27affda4983ecb099e3ac5c497`，尚未提交、合入或推送。

## 实现

`syscallDetails` 默认关闭，要求 calls、CodeRules 关闭，现支持 Flight 和普通 QTRB。arm64 选择表支持最多两个路径，每个 128 字节，覆盖 access/readlink/stat、链接与重命名等直接 pathname 参数。schema 2 使用 `paths`，保留旧 schema 1 和旧入口 detail 读取。严格配对核对 artifact/TID/id、schema、号码、PC 及顺序；QTRB 使用物理 record ordinal，Flight 使用全局 sequence，不跨文件补配。[使用说明](../syscall-details.md)列出选择表和可执行解码示例。

普通 QTRB 在显式开启详情时注册 broker 观察上下文，信号 epoch 改变后返回保持未知。嵌套交付及 SA_RESTART 仍不推算内核执行次数。新 producer 以 `qtrace.signal_pc` policy 说明逻辑 PC、嵌套 kernel ucontext 和 handler 返回上下文；缺失、较晚、不同线程或不支持的 policy 保持 unknown。C++ 紧急记录布局与旧 flag 位保持原样，Python/Rust 字段和差分语料同步。

`qtrace snapshot` 通过既有 tracer export，在普通诊断线程保存运行时/JIT 映射、native 线程及可用 Java 栈。输出上限 64 KiB、最多 32 线程/32 帧，绑定 PID/starttime，分别表达禁用、不可用及截断。JNI 查询保留原 exception/errno/attachment；文件、目录和 JNI local frame 按作用域收尾。主机 worker 超时不证明目标 JNI 调用已结束，不重试或杀目标。[命令、ABI 与资源边界](../runtime-snapshot.md)有完整说明。

Java 首轮实测发现 linker namespace 隐藏 VM 符号，以及 boot image 先占满映射行预算。修复复用现有 loaded-ELF 查询，并优先保留运行时/JIT；不强制加载 VM、不初始化新 hook 或安装全局异常处理器。原失败 `jni-art` 报告保留，修复后 Debug/Release 独立重做。

## 源码、构建与产物

QBDI 固定 `09b2efb66d242b3616a4723e4b487f623b0e93d7`，NDK `26.1.10909125`。本轮使用实现工作树自己的正常 Gradle 源码构建 Debug/Release，不复用前轮私有重链接 tracer。

```bash
./gradlew :app:assembleDebug :app:assembleRelease \
  :tracer:assembleDebug :tracer:assembleRelease :tracer:copyTracerDebug \
  nativeHostTest --no-daemon
```

仓库没有 `copyTracerRelease` task；最初错误调用的日志保留，更正为 `assembleRelease` 后通过。Release 从实际 stripped 输出单独保存。最终资源收尾修正后重新构建，并重跑对应设备矩阵。

| 最终产物 | SHA-256 |
| --- | --- |
| Debug tracer | `06671f4ef34680578924cd960dbf31749be53149325fec4523218d6a590044ec` |
| Debug companion | `4fe29375379c3c6bd7dae1f8af60f9b89a670149f3152ab0cedf8efa890fe2dd` |
| Release tracer | `d3a7831596b542dcdc4ef3f8b1db8aab77d54399b2138373b73c6b962a3ad69a` |
| Release companion | `9cd6c92b3113d508613aa6e2e07d3419c43cfd0475b3877b982d969713b31069` |

`out/ux-remaining-20261022/final-source-identity.json` 保存源码 SHA，机器证据绑定其路径与 SHA。候选保存在 `candidate-final/{debug,release}/`，原始报告保存在各 `final-*` 目录，构建及测试日志复制到 `verification-logs/`。这些本机原始目录被 Git 忽略；筛选清单随文档保存，不能在原始文件已丢失后仅凭路径宣称重新验证。

## 独立设备功能检查

功能设备为 Mi 11 `2d32ed71`，arm64、物理用户 0、root，SDK 属性报告 36，fingerprint 为 `Xiaomi/venus_global/venus:14/UKQ1.240624.001/OS2.0.3.0.UKBMIXM:user/release-keys`。SDK 属性与 fingerprint 的 Android 版本表示不同，本报告保留两者，不据属性推断完整 Android 16 兼容性。

所有操作使用现有 `tcp:localhost:5037` 和 canonical serial guard。runtime/JNI/snapshot 夹具只创建自有进程与目录，不安装 APK；每份报告保存原 PID/starttime、实际请求、tracer/companion/独立目标 SHA 和 cleanup receipt。最终候选的下列 17 份功能报告均通过并完成收尾：

| 最终轮次 | 结果 |
| --- | --- |
| `final-qtrb-pointers` | 6 个入口/返回；有效、ENOENT、EFAULT、部分可读、截断，与独立 SVC oracle 一致。 |
| `final-qtrb-concurrent` | 两个实际 TID、两个 artifact、12 次调用，没有跨线程或跨文件配对。 |
| `final-qtrb-paths`、`final-flight-paths` | 7 次 access/readlink/stat/statx/rename/link/symlink，路径参数及双路径原始字节匹配。 |
| `final-qtrb-nested`、`final-flight-nested` | SA_NODEFER 两次 handler、顺序 1234、原生/traced EINTR 一致，返回证据仍为 signal_intervened。 |
| `final-qtrb-restart`、`final-flight-restart` | SA_RESTART 的 read 最终读到一字节、handler 一次，仍不把重启后的 x0 当作唯一内核返回。 |
| `final-qtrb-stopped` | nanosleep 跨越 100 ms 停止请求，POST 保存真实 0，随后采集停止；scene 返回保持未知。 |
| `final-flight-missing` | 自有进程收到 SIGKILL，保留 nanosleep 入口，缺失返回不补配。 |
| `final-jni-debug`、`final-jni-release` | 普通/V/A、整数/浮点、字段、异常、线程 attachment、x18 和真实栈均通过；snapshot 返回真实 Java main 栈、ART/JIT 映射，并保留原 exception/errno/attachment。 |
| `final-release-15/16/17` | Release 分别验证 Flight 多路径、QTRB 嵌套及 Flight 重启。 |
| `final-snapshot-native` | 无 VM 时为结构化 unavailable；保留 errno 及 SIGSEGV/SIGBUS/SIGABRT/SIGUSR1 disposition。 |
| `final-snapshot-cli` | 公开 CLI 实测 Java 栈、显式禁用、错误 starttime 拒绝；stdout JSON 契约和单次目标运行通过。 |

最初 `qtrb-stopped` 将“已过名义截止”误当成“采集已停止”，因此要求 syscall 返回未知而失败。实测 POST 先于协作式停止，返回 0 有直接证据；已修正夹具要求，保留原失败，重做最终轮次。没有为了通过检查丢弃已观察到的返回。普通异步 QTRB 不承诺 SIGKILL 前的缓冲已提交，缺失返回的设备检查仍用 Flight；QTRB 合法前缀及缺失返回另由严格 decoder 和生产 encoder fixture 核对。

## 同条件增量测量

同一 Mi 11、最终 Debug tracer/companion、目标及 scenario 15，calls + Flight，每组 3 次关闭/开启交错执行，均核对原生返回、配置和收尾。计时包含首次 QBDI JIT、libc、7 次 SVC 和 producer 回调，不是稳定状态的 syscall 微基准。

| 模式 | 三次 traced 耗时（ms） | 中位数（ms） |
| --- | --- | --- |
| 默认关闭 | 22.732969 / 22.750052 / 14.849792 | 22.732969 |
| 显式开启 | 22.322656 / 16.064010 / 22.880989 | 22.322656 |

原始值在 `final-measure-*` 报告中。短函数波动使差值不能解释为提速、零开销或每次路径读取成本；此前资源收尾修正前的测量另行保留，不拼接为同一候选。

## 主机与协议检查

- Python 全量 963 项，9 项跳过，无失败；新增测试覆盖真正 CLI 通道、严格 snapshot 身份/预算、主机 worker 超时回收、错误和收尾并存、schema 2/QTRB 与 PC policy 的线程及顺序边界。
- Native Host CTest 50 项全部通过；正常 Debug/Release APK、tracer 与 companion 构建通过。
- Rust workspace 524 passed、2 ignored，无失败；覆盖受影响 provider/model/store/analysis。
- C++ 生产 encoder、Python/Rust 差分矩阵 `--write` 与独立 `--check` 均通过，保留原 fixture 字节，增加 schema 2 的 QTRB/Flight 与 signal PC policy fixture。没有修改 wire version。

## 发布门禁与保留边界

完整门禁要求与已保存性能基线同一 Pixel 6 `1C111FDF600G6S`。Mi 11 身份检查被正确拒绝。改用 Pixel 6 后先遇到缺少 frida-tools Java bridge，隔离环境补齐后仍在 benchmark 阶段报连接关闭。后来确认该设备没有运行中的 Frida server；独立临时路径启动匹配的 17.24.2 并确认版本就绪后，门禁仍在 `compare-historical` 报 `the connection is closed`。上述失败的 cleanup 均已确认，未改写为成功。

最小对照不加载 tracer，只 spawn/attach、加载发送状态的普通脚本并 resume。17.24.2 在 resume 后的下一次脚本创建报 TransportError，已经收到的 plain-ready 表明当时 tracer 未加载。另一个匹配的 17.17.0 对照可加载 Java bridge，但等待 Java.perform 回调超时；该进程 logcat 显示普通应用界面已启动，无 QBDI tracer 加载。两者分别记录，尚不能据此确定 Frida/ART 的具体根因，或归因于本轮 tracer 改动。

17.17.0 的实际 benchmark 使用 Java.performNow，可以完成采集；最小 Java.perform 超时没有被当作该路径不可用的证据。历史 gate 随后严格拒绝旧 oracle：当前候选与保存的改动前 tracer 均为 21714 条指令、返回 `0x20a128f3d199a008`，旧不可变表为 21718 与 `0x5745c858653f5a7f`。旧文档已经记录 QBDI 与原生值不同。

用户已批准建立[新版基线](binary-trace-baseline-v2.md)。同机参考 tracer 的 fast/balanced/full 各一次预热与五次独立测量共 18 个 artifact，加独立不加载 tracer 的直接原生调用，确认新版语义。原设备/APK/canonical ELF/终态检查保留，三档速率及每次大小限制不变；旧表保留，未知版本拒绝。[基线证据](evidence/binary-trace-baseline-v2.json)记录原始文件与 SHA。该参考采集不等于候选发布门禁，控制采集最初的报告写入失败也未改写为成功。

首次通过新版历史 benchmark 后，完整门禁在 timed-offset 发现空 `.crash` 占位文件于列出后被 native 正常收尾删除的竞争。collector 现在仅跳过空占位或该绑定路径的精确 ENOENT；权限、异路径和非空 marker 消失仍为失败。原设备失败与红/绿回归保留，全量 963 项 Python（9 跳过）通过；修复后的最终完整门禁通过。

固定 demo 包每轮门禁前保存原 APK 和用户 0 数据 tar，核对设备/本地 SHA 并完整读取 tar。原始备份在 `release-gate/` 与 `release-gate-pixel6/`。进入当前场景前原子改名旧 traces；历史阶段失败与首次 timed-offset 失败分开保留。自有 Frida server 按 PID/starttime 收尾，不停止其他 server，不重启 ADB。原 APK、私有二进制恢复与收尾报告均通过。

### 最终完整门禁

Pixel 6 `1C111FDF600G6S`、Frida host/server 17.17.0，执行同一 `run_acceptance`、全部构建/主机检查与原有八场景准入。临时 runner 只逐条保存 stdout/命令结果，没有跳过或替换门禁步骤。Debug tracer 为上表 `06671f4e…`，companion SHA 相同；历史目标 canonical SHA 仍为 `0d8e856c819fb3cd7ae5917053172b4b75a7924784c43e09cb2855a298647169`。

成功 manifest：`qtrace-acceptance-evidence/b8e25dc5-5e33-48cf-b6e8-a71d13581fd9/historical-benchmark-gate.success.json`，起止时间为 `2026-10-22T09:41:02.339Z` 至 `09:45:39.597Z`。它绑定 HEAD、安装 APK、实际 tracer/companion、旧 traces 备份路径和八个 report：

| 场景 | 终态 |
| --- | --- |
| timed-offset、timed-symbol | 两种入口形式均通过；协作式停止和返回未知语义正确。 |
| pull-latest、pull-name、pull-all、pull-compressed | 四种读取及输出校验通过。 |
| monitor-exit | 原进程退出与有界收尾通过。 |
| flight-crash | 预期返回 2，恢复部分采集并通过严格崩溃证据检查。 |

fast 使用一次预热与五次新进程，测量为 `17, 24, 21, 15, 21` ms，中位 `1034000.000000` instructions/s，21,714 条指令及原生返回一致。五次压缩大小为 `265876, 265880, 265875, 265887, 265877` 字节，全部低于旧限制 `307925`，速率通过原 `1000000` 门槛。短工作负载接近速率边界，单轮通过不证明持续性能余量。

benchmark JSON 记录实际读取的基线 SHA。随后仅删除身份表与 provenance 行间的一个空行以修正 Markdown 显示；读取时的精确副本保存在 `gate-baseline-v2.md`，与交付版三档语义、预算及身份的解析等价核对保存在 `baseline-format-equivalence.json`。没有重写原 JSON 或将两份字节当成同一 SHA。六个原始 gate benchmark artifact、sidecar 与完整转换再次核对后，保存在 `restore-pixel6/gate-benchmark/`；这是对原 gate 的离线审计，不是新 gate。

### 恢复与保留

`restore-pixel6/report.json` 与 `restore-mi11/report.json` 均为 pass、cleanup=true。Pixel 6 原 APK SHA 为 `13366b591c368f2c328bde5dac7447df36c7688c4e59286605afc1666947594e`，原私有 tracer SHA 为 `b06bd71aa8d60906b0f3a618328cd6f2b38b6d71f81d2d7411aff1a83cf9a358`；tracer 原位恢复保留 SELinux label，设置原 mode/mtime，并核对 SHA。Mi 11 原 APK SHA 为 `c1c01cd0f10ccb443d37a2c312a638b2a3a04439d2c4214d6181bf0d7700212b`；原先不存在的两个私有库仅在确认属于本轮部署后移除。两机 demo 均停止，没有卸载应用或覆盖整个 userdata，Pixel 6 用户 11 数据未写入。原始备份与历史 traces 继续保留。

自有 Frida server 的 PID/starttime、退出与目录移除已确认；Mi 11 借用的现有 server 未停止。设备 guard 正常释放，ADB server 沿用原实例。

本轮没有新的完整游戏、防护检测因果、厂商、上报或完整构造器结果；[样本参考](../research/2026-10-22-umamusume-protection-reference.md)中的未证实结论保持原样。通用工具的功能、构建与发布门禁通过不构成这些样本结论的证明。
