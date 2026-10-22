# qbdi-android 使用体验优化交接

更新：2026-10-22。目标是减少配置、采集和结果判断的操作成本，保留严格校验、默认只读、进程身份及资源收尾语义。

## 当前状态

用户授权的剩余功能、Java/JIT 快照、新版发布基线、完整设备门禁及设备恢复均已完成。Java 范围为“运行时/JIT 映射、线程信息及可用的 Java 线程栈”。本轮状态为 **PASS**；[验收报告](../../benchmarks/qtrace-ux-remaining-2026-10-22.md)区分功能、基线校准与完整门禁，保留原失败和未覆盖边界。

实现已提交为 `2bd271f1f360dc69e337ba8b3a57470f321b511c`，本地快进合入 main。合入后 963 项 Python（9 跳过）及 C++/Python 协议检查通过，见[合入复核](../../benchmarks/qtrace-ux-main-integration-2026-10-22.md)。另行完成的[赛马娘独立调查](../../research/2026-10-22-umamusume-rejection-reporting.md)已确认本版本物理设备的本地 Root 拒绝路径；远端上报仍未证实。研究文档随本次更新合入本地 main，不作为 handoff 的剩余功能。

| 顺序 | 状态与入口 |
| --- | --- |
| 1. 配置与前置诊断 | 完成。严格 CLI/native 接口、字段修正提示、bindings/版本诊断；[使用说明](../../usage.md#配置接口与前置诊断)。 |
| 2. 窄场景与返回判断 | 完成。stderr 摘要、stdout/JSON 契约、独立 baseline 与停止后未知状态；[可执行示例](../../narrow-capture.md)。 |
| 3. syscall 路径与返回 | 完成扩展。calls 的 Flight/QTRB、最多两个各 128 字节的路径、schema 2 与旧数据读取、严格配对；[使用及配对](../../syscall-details.md)。 |
| 4. 信号与未知终态 | 完成。QTRB/Flight 嵌套信号与 SA_RESTART 对照、单次 spawn、保守返回、显式 PC 来源；[格式契约](../../trace-format.md#scene-and-signal-evidence)。 |
| 5. 可选运行时快照 | 完成。PID/starttime 绑定的映射、线程与可用 Java 栈；[snapshot 命令与 ABI](../../runtime-snapshot.md)。 |
| 6. 最终检查与交付 | 完成。Debug/Release、50 项 native、963 项 Python（9 跳过）、524 项 Rust（2 ignored）、协议矩阵及 Pixel 6 八场景门禁通过；两台设备恢复与自有 server 收尾通过。 |

## 工作区与证据

- 主交付工作区：`/home/lyldalek/workspace/qbdi-android`，本地 main 已包含实现提交 `2bd271f1f360dc69e337ba8b3a57470f321b511c`；功能已完成，不重复实现。
- 原实现工作树：`/home/lyldalek/.codex/worktrees/cd7b/qbdi-android`。原功能分支 `feat/qtrace-ux-handoff` 和原始证据保留；独立调查分支为 `research/umamusume-rejection-reporting`，研究提交 `a84eced` 及本次文档同步一并合入本地 main。实际设备验收基线仍为 `eb79bcb2c37acb27affda4983ecb099e3ac5c497`，按源码 SHA 绑定，不回写成新采集。
- 原资料工作树：`/home/lyldalek/.codex/worktrees/6580/qbdi-android`。其中原始交接、样本参考及其他调查材料保留原样。
- 用户已授权 qbdi-android 实现与研究文档的本地合入；未推送，也未删除分支、工作树或其他会话文件。
- `.codegraph/` 存在但无可用索引。按规则先尝试查询，失败后用 `rg` 和定点读取，不自行重建索引。

进入后先核对 main、工作树和状态；目录失效时先用 `git worktree list --porcelain` 定位既有交付：

```bash
cd /home/lyldalek/workspace/qbdi-android
git branch --show-current
git status --short
git rev-parse HEAD
```

历史记录分别保留，不回写成新候选的验收：

- [配置与窄场景首轮](../../benchmarks/qtrace-ux-2026-10-22.md)：931 项 Python、三轮 Pixel 6 fixture，属于当时源码和产物。
- [syscall 首版](../../benchmarks/qtrace-syscall-2026-10-22.md)：944 项 Python、50 项 native、calls + Flight/openat 的设备证据，以及失败轮次和收尾补证。
- [剩余扩展验收](../../benchmarks/qtrace-ux-remaining-2026-10-22.md)与[新版发布基线](../../benchmarks/binary-trace-baseline-v2.md)分开记录本轮功能、基线校准与发布结果。
- 本轮原始报告、构建日志、候选 Debug/Release、JNI 与快照证明位于 `out/ux-remaining-20261022/`。新清单须绑定实际源码、产物 SHA、配置、PID/starttime 及 cleanup，不能沿用历史候选的 SHA。

## 已确认与未证实的分析结论

先读[赛马娘防护库参考](../../research/2026-10-22-umamusume-protection-reference.md)。该材料只说明工具需求，不以游戏启动判断工具正确性。

已有证据包括本地检测线索、拒绝界面、诊断文件访问、终止行为及有限 QBDI 前缀。[补证](../../research/2026-10-22-umamusume-verification.md)以原始 YARA 引擎确认 CrackProof 公开指纹及三个负对照，并在主机执行原 ARM64 指令验证五种路径子串的返回逻辑。

[独立拒绝调查](../../research/2026-10-22-umamusume-rejection-reporting.md)将 Java 字节码、运行时 JNI 参数、IL2CPP 分支、TextId 和新启动 UI 对应起来：Cygames `CheckApp.isRootUser` 创建 `su` 未抛 `IOException` 后返回 true，游戏显示 `Error0032` 并停止推进。这不证明取得 root 权限，不归为 CrackProof 的 Root 检测，也不排除其他拒绝路径。候选保护库回调的 16 槽内存队列逻辑已通过主机原指令验证，实际绑定和后续发送仍缺证据。

厂商对具体 SHA 的认证、五种路径检查在设备上的实际命中、远端上报及完整解包/防护流程仍未证实。原 strace 未覆盖写入/发送，旧“写入本地记录”应收窄为既有文件访问。构造器记录仍为进入后停止、返回未知；另一轮 88 次包装函数返回仅证明局部调用，不与其他轮次拼接。新增通用工具通过独立 fixture 验证，样本补证不承担工具验收。

## 继续维护时保留的契约

1. CLI `--config` 与手动 native JSON 是两个接口；复用 `load_config/build_native_request`，不接受字段互换。已有前置诊断、摘要、生命周期和 Flight 查询不要重复实现。
2. `syscallDetails` 默认关闭，要求 calls、CodeRules 关闭。新 schema 2 使用 `paths`；旧 schema 1 与旧入口仍可读。关闭时不读路径，也不注册新增 SVC POST 回调。
3. 配对绑定 artifact、TID、id、schema、号码、PC 及顺序。QTRB 使用本文件 record ordinal，Flight 使用全局 sequence；不跨 artifact 补配。信号介入、缺少 POST、覆盖或断片保持未知。
4. 停止为协作式。阻塞 SVC 可在名义截止后先记录有效 POST，下个 PRE 才停止采集；已知 syscall 返回与未知 scene 返回可以同时成立。普通异步 QTRB 不承诺突然终止前的缓冲已落盘。
5. PC 来源只在保留了同线程、先前的受支持 producer policy 时解释。`qbdi_logical/kernel_ucontext/guest_handler_context` 表示值的来源，不证明信号根因；旧数据、缺失 policy 保持 unknown。
6. 快照属于独立主动操作，不在 signal handler 内进入 JNI，不全局安装 `Process.setExceptionHandler`。Java 不可用、禁用和截断分别表达；Java id 不当作 native TID。主机超时不证明目标侧已结束，不自动重试或杀目标。
7. CLI 普通 stdout 保留路径，`--json` 保留机器对象，人读信息写 stderr。配置/schema 改动同时覆盖 producer、严格 validator、旧/不可用分支、类型和实际输出通道。

## 验收与后续维护

功能扩展见[实施计划](2026-10-22-qbdi-ux-remaining.md)。主机检查按[开发指南](../../development.md)执行；JNI 按[独立准入说明](../../jni-abi-acceptance.md)，PC/语义记录按[协议矩阵](../../../qtrace-ui/docs/development.md#native-protocol-fixtures)验证。

设备继续使用既有 `tcp:localhost:5037` 和 本机约定的共用设备锁目录 的 serial guard。Mi 11 `2d32ed71` 已用于独立功能对照；现有性能基线绑定 Pixel 6 `1C111FDF600G6S`，不能用 Mi 11 的结果通过同机比较。每次重新核对身份与占用，不抢设备或重启 ADB server。

发布门禁需要匹配的 Frida bindings/server、frida-tools Java bridge、host lz4、固定 NDK/build-tools 和离线历史构建依赖。本机可用隔离环境为 `out/ux-remaining-20261022/frida-17.17/` 与 `host-tools/`。17.24.2 的连接关闭，以及 17.17.0 最小 Java.perform 回调超时均保留为有限对照，不能据此归因于 tracer。实际 benchmark 使用 Java.performNow，在匹配的 17.17.0 下通过。

旧 oracle 为 21718 条指令与 `0x5745c858653f5a7f`；旧文档已说明原生返回不同。新版同机参考的 18 个预热/测量 artifact，以及独立、不加载 tracer 的原生调用确认 21714 条指令与 `0x20a128f3d199a008`，当前候选一致。新版速率与单次大小门槛不变，旧格式仍可读，未知版本拒绝。原始采集在 `reference-baseline-v2/`，严格摘要随基线保存。

首次通过历史比较后，timed-offset 暴露空 `.crash` 占位文件在列出后被 native 收尾删除的竞争条件。collector 现在仅跳过空占位与该绑定路径的精确 ENOENT；权限、异路径及已观察为非空的 marker 消失继续保留失败。红/绿回归与原失败报告均保留。修复后的完整门禁已通过：`b8e25dc5-5e33-48cf-b6e8-a71d13581fd9`，八个场景报告齐全，原 HEAD 与最终 Debug tracer SHA 绑定。门禁逐条执行记录在 `release-transcript-v2-fixed/`。
固定 demo 包的原 APK 与用户 0 数据保留在 `release-gate/`、`release-gate-pixel6/`；旧 traces 原子备份路径保存在成功 manifest。Pixel 6 原 APK、原私有 tracer/companion 已核对恢复；Mi 11 原 APK 已恢复，并移除本轮新增且原先不存在的两个私有文件。两机 demo 均停止，`restore-{pixel6,mi11}/report.json` 与自有 server cleanup 均通过。未覆盖整个 userdata，历史 traces/证据继续保留；未卸载应用，也未触碰用户 11 数据。实现已提交并本地合入 main，尚未推送；本次合入没有重跑设备操作。

## 可复制的新会话提示词

```text
请先读取：
/home/lyldalek/workspace/qbdi-android/docs/superpowers/plans/2026-10-22-qbdi-ux-handoff.md

handoff 已以 2bd271f1f360dc69e337ba8b3a57470f321b511c 本地合入 main；保留 cd7b 原始产物、6580 原资料及历史证据。
剩余功能和可用 Java 栈快照已完成；新版发布基线保留原性能门槛，完整门禁已通过。
成功 manifest：qtrace-acceptance-evidence/b8e25dc5-5e33-48cf-b6e8-a71d13581fd9/historical-benchmark-gate.success.json。
先核对实施计划、最终 diff、机器证据及 restore-{pixel6,mi11}/report.json；不要重复实现已完成能力。
后续有实际改动时重跑适用检查；设备操作仍使用既有 ADB server 和 canonical serial guard。
保留 stdout/JSON、未知返回、只读与 cleanup 契约；不自动重放可能完成的启动。
样本补证见 docs/research/2026-10-22-umamusume-verification.md：CrackProof 公开指纹已复核，五种路径子串函数已离线验证，保留局部返回与完整流程之间的证据边界。
独立调查见 docs/research/2026-10-22-umamusume-rejection-reporting.md 及同名 evidence JSON；研究提交 a84eced 及文档同步已本地合入 main。
本版本物理拒绝已定位到 Cygames CheckApp.isRootUser 的 su 进程创建检查和 Error0032 分支；不证明取得 root 权限，也不归因于 CrackProof。
候选回调为 16 槽内存队列追加器；实际绑定、后续发送和远端上报仍未证实。厂商官方样本认证、五种路径分支实际命中、完整流程及旧 QBDI 差异原因也仍未知。
后续上报调查保持独立，按需从当前 main 隔离；不要复用旧 PID 或重复实现已完成的 handoff。
尚未推送；其他项目改动、推送及清理需另有明确请求。
```
