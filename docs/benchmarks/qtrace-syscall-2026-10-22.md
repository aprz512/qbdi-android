# 可选 syscall 证据验收：2026-10-22

[配置与配对示例](../syscall-details.md) · [handoff](../superpowers/plans/2026-10-22-qbdi-ux-handoff.md) · [源码与设备证据 JSON](evidence/qtrace-syscall-2026-10-22.json)

本轮完成 handoff 第 3 项的 calls + Flight 首版，并复核第 4 项公开入口的责任边界。实现位于 `/home/lyldalek/.codex/worktrees/cd7b/qbdi-android`、`feat/qtrace-ux-handoff`，基线为 `eb79bcb2c37acb27affda4983ecb099e3ac5c497`。改动尚未提交、合入或推送。第 1、2 项的历史结果保留在[原验收记录](qtrace-ux-2026-10-22.md)。

## 实现与边界

CLI `tracer.syscallDetails` 和 native `trace.syscallDetails` 默认关闭，严格要求 calls、Flight 开启、CodeRules 关闭。开启后只注册 SVC 的 POSTINST 回调；关闭时保留原入口 detail，不读取路径，也不增加此回调。没有零开销或性能改善结论。

arm64 openat 的参数 1 最多快照 128 字节，分别表达 complete、unreadable、partial、truncated，并保留原始 bytesHex。读取与写事件期间恢复 libc errno。返回保存对应 SVC POST 的原始 x0，另解释 Linux 错误区间；它不读取或推断目标 errno。

配对绑定 artifact、实际 TID 和调用 id，核对入口 PC、syscall 号和 sequence。broker 信号 epoch 改变、POST PC 不符、缺少 POST、采集结束时保持未知。信号 handler 中的原生执行不混入目标 syscall 返回；缺失或环形覆盖也不通过 scene return 补配。

复用语义 CALL，detail schema 为 1，Flight/QTRB wire layout 未变。通用解码器保留原字符串；新增 Python 解释入口严格校验字段与配对。生产 C++ encoder 的新增 Flight fixture 经 Python/Rust 差分矩阵检查。该 fixture 与 Flight 专用 Syscall record 分开，不将通用字符串传输能力解释为普通 QTRB 已可开启此选项。

未覆盖其他 pathname syscall、普通 QTRB 开启选项、嵌套信号或自动重启的完整设备矩阵。broker epoch 仅代表实际观察到的信号；POST x0 不证明唯一内核因果。路径快照也不能排除其他线程在内核读取前修改字符串。

## 设备与产物

设备为 Pixel 6 `1C111FDF600G6S`，API36、arm64、物理用户 0，fingerprint 为 `google/oriole/oriole:16/CP1A.260405.005/15001963:user/release-keys`。使用既有 `tcp:localhost:5037`，未重启 ADB server。所有运行持有 本机约定的共用设备锁目录 中的 serial guard，只创建、清理自身进程与目录，没有安装 APK。

| 产物 | SHA-256 |
| --- | --- |
| 当前 tracer | `948464a87cad418d12643a1acf7e296b30c0a67c5053406a67c32148bde43660` |
| 旧 tracer 对照 | `288b34e69557011ed0160b845cfa1538019691368af61a853e7d57a34c475ace` |
| companion | `4fe29375379c3c6bd7dae1f8af60f9b89a670149f3152ab0cedf8efa890fe2dd` |
| 独立目标库 | `dd4ff2c211da95b9270046fdf2d1ffd6c2cf717b13800f5de01a00bc501f6eaf` |
| 最终 launcher | `24fa9a9507788804917c4c362269992917fce05b2da3cf754734251d5030f982` |

tracer 使用 NDK `26.1.10909125`，从实现工作树重编全部 50 个 tracer 自有 translation unit，再链接此前从固定 QBDI 源码构建的第三方 archive；不是复用旧 tracer。QBDI 固定 `09b2efb66d242b3616a4723e4b487f623b0e93d7`。完整命令、源码与 archive SHA 位于 `out/ux-syscall-20261022/candidate/build-identity.json`，筛选 JSON 保存其路径与 SHA，并补充当前头文件身份。

这次复用主工作区生成的 archive 和 QBDI 配置头。主工作区 tracked 源码与已链接库保持原样；link 命令曾在其 `.cxx` 缓存中写入生成的 `link.d`，现已用原基线输入重新生成并恢复。私有目录中的基线重链接与主工作区未剥离库 SHA 完全一致；恢复凭据保留，后续私有构建将依赖文件写入自己的目录。该构建不替代干净 Gradle 打包、release gate 或完整 JNI 矩阵。

fixture 目标从实现工作树独立构建。最终 launcher 在 configure 前保存实际请求，驱动在清理前读取并核对 session/package，SIGKILL 用例因此仍有直接配置证据。旧性能轮次的 launcher 为 `93103354851288c0bb2f62b4189fd5bb490a766d4d9914b8f9e74b3488cc0489`；它与最终版仅相差保存请求的操作，目标库完全相同。两组报告各自保存实际 launcher/源文件 SHA，不混写产物身份。

## 独立功能对照

每轮由 supervisor 先运行原生子进程，再在同输入下运行 traced 子进程。fixture 在实际 SVC 前记录六个参数，直接保存返回和 errno；分析器再逐一核对，未用 tracer 自身输出作为返回 oracle。

| 最终轮次 | 独立检查与采集结果 |
| --- | --- |
| `verified-paths`，scenario 11 | 6 个入口及返回精确配对。openat 成功、close 成功、ENOENT、坏指针 EFAULT、跨不可读边界 EFAULT、长路径 ENAMETOOLONG；路径状态及字节全部匹配。 |
| `verified-concurrent`，scenario 12 | 两个实际 worker TID，各 6 次调用，共 12 个配对，无串配。 |
| `verified-interruption`，scenario 13 | 原生/traced oracle 均返回 `-EINTR`；存在 handler 返回记录，syscall 返回显式为 `signal_intervened`、原始值和错误解释均为 null。 |
| `verified-missing-return-recheck`，scenario 14 | 夹具辅助线程向自己的 phase 进程发送 SIGKILL；原生/traced 均未返回、信号 9、receipt 为 K。采集保留 nanosleep 入口，返回缺失，严格配对结果保持 null。 |
| `verified-default-all`，scenario 0 | 关闭新选项，保留 all 模式。5 次原生/traced 计算结果一致、返回 42，Flight 记录指令和内存，5 个 scene 显式返回。 |

scenario 11/12 的所有直接 SVC 观察均保持 errno 123；scenario 13 也保持该值。collector 主机测试另核对入口处理前后的 GPR 不变。
所有最终轮次退出与收尾检查通过，原 PID/starttime、native 请求、UTC、scene 时间、trace/report SHA、严格 syscall 结果及 cleanup receipt 见 JSON 和 `out/ux-syscall-20261022/verified-*/`。完整恢复没有 coverage gap 或 recovery damage，旧入口/孤立返回计数为零。

SIGKILL 产物的已提交数据可完整恢复，仍不能证明缺失的 syscall 或 scene 返回；这也验证了文件完整性与目标返回分别判断。使用说明中的完整恢复和严格配对代码已直接读取实际采集文件。

## 同条件开销测量

同设备、目标库、companion、scenario 11、calls + Flight，每组 3 次，按旧 tracer、候选关闭、候选开启交错执行。计时包住单次目标函数，包含首次 QBDI JIT、mmap/libc 和六次 SVC，不是稳定状态的 syscall 微基准。

| 模式 | 三次 traced 函数耗时（ms） | 中位数（ms） |
| --- | --- | --- |
| 旧 tracer | 4.933431 / 5.830118 / 5.618042 | 5.618042 |
| 候选，关闭 | 11.173909 / 4.673421 / 4.128947 | 4.673421 |
| 候选，开启 | 15.940593 / 5.929972 / 9.374797 | 9.374797 |

开启与关闭的中位数相差约 4.701 ms。短函数和调度波动显著，无法据此分离每次 syscall 的增量成本、证明默认无回归或宣称回调优化收益。每轮 baseline、原始纳秒值、配置、进程身份、源码与产物身份均保留。默认关闭没有新增路径读取或 SVC POST 注册，这是源码检查结论。

较早全指令 POST 候选及计时另存于 `candidate-v1-all-post/` 和 `measure-*`，不与最终候选拼接，也不据两份小样本宣称加速。

## 第 4 项复核

公开 `_run_injection_worker` 只有一次 spawn。既有测试覆盖 setup 超时、session 断开、attach 失败、原 session 收尾及父进程取消；补强三个既有测试，明确超时/断开/attach 失败仍只 spawn 一次。42 项 injector 回归通过。它们使用 Fake Frida 和真实隔离 worker，未对外部 daemon 自动启动作设备验收。

现有工具保留 `inject.cleanup_incomplete` 和原 PID，不凭裸 PID 杀可能重用的进程。没有复现需要自动重放外部 daemon 启动的公开 CLI 缺陷。手动说明继续要求分别判断观察、交付、handler 返回、终止和 PC 来源；未增加全局异常处理器、PC 来源字段或 Java/JIT 快照。

早期 `final-interruption` 的功能检查全部通过，但清理读取身份失败，原报告保持 `unavailable`。随后在同一 guard 下读取原始凭据，证明 supervisor、baseline、traced 的原 PID 均已退出，完成目录清理并解除本轮责任标记；后续证据另存 `cleanup-followup.json`。身份读取失败原因仍未确定，不把补充清理改写为原轮通过。

`verified-missing-return` 另留下 31,613,440 字节的截断 tar，独立重读报 `ReadError: unexpected end of data`，随后的身份清理失败又遮盖了原始异常。已在驱动真实 `main` 入口复现“部署错误 + 收尾错误”被遮盖，修复后 `error` 保留原始错误，另存 `cleanup_error`，责任标记继续保留。原轮没有改为通过；同 guard 下完成 PID/epoch 清理后，以新目录重做独立夹具。传输截断和身份读取失败的具体原因仍未知。

开销轮次 `measure-final-2-off` 在 push fixture 时超过 30 秒，目标尚未启动，目录已确认清理；该轮排除，使用新目录补齐关闭测量。两份失败报告及 SHA 保留在 JSON，未重启 ADB、自动重放可能已完成的目标或删除他人责任标记。

## 检查结果

- Python 全量：共 944 项，9 项跳过，无失败；保留 stdout/stderr 日志及 SHA。
- native：`./gradlew nativeHostTest --no-daemon`，50 项全部通过。
- 协议矩阵：生产 C++ encoder、Python/Rust reader、QTRB 1.0–1.2、Flight v2、malformed corpus 通过；旧 fixture 字节保留，增加一份 syscall detail fixture。
- 最终请求留存与错误诊断补充后，runtime/syscall 的 14 项集中检查及新设备轮次通过。
- 文档配置和离线代码、JSON、链接及 diff 单独核对。

这些结果只证明上述工具和独立夹具。没有新的应用注入、完整游戏、防护检测因果、远端上报或完整 JNI 验收；[样本参考](../research/2026-10-22-umamusume-protection-reference.md)的未证实结论保持原样。
