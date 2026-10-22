# 使用体验优化：剩余实现与验收

2026-10-22。承接[handoff](2026-10-22-qbdi-ux-handoff.md)。用户已要求继续实现剩余项，沿用 `cd7b` / `feat/qtrace-ux-handoff`，保留此前未提交代码和历史证据。范围包括功能、文档、正常 Gradle 构建与适用发布门禁；提交、合入及推送仍不自动执行。

## 实施顺序

- [x] **更多路径参数与普通 QTRB**：arm64 pathname 参数选择表，最多两个路径、每个 128 字节；支持 rename/link 等双路径。新 detail schema 2 使用 `paths`，保留 schema 1 读取。默认关闭、calls、禁止 CodeRules 的限制保留，解除仅 Flight 限制。QTRB 与 Flight 使用同一严格配对入口，分别记录覆盖/缺失证据。
- [x] **嵌套信号与重启**：独立 fixture 覆盖嵌套交付、SA_RESTART 与真实阻塞 syscall。baseline/traced 的返回、errno、handler 次数及顺序核对；只要观察到信号介入就保持返回未知，不根据重启后成功推算内核返回次数。
- [x] **PC 来源**：保留现有紧急记录布局与深度计数。以显式 producer policy 说明 PC 表示，Python/Rust 输出来源字段；旧数据或 policy 缺失保持 unknown。同步 UI/service 严格字段与差分语料，不将逻辑 PC 当成内核故障现场。
- [x] **可选 Java/JIT 快照**：独立、有界、绑定 PID/starttime 的诊断入口，记录运行时/JIT 映射、线程信息及可用的 Java 线程栈。默认不采集，不安装全局异常处理器，不在 signal handler 内进入 ART/JNI；不具备 VM/权限时给出结构化不可用原因。用户已确认包含可用 Java 栈的范围。
- [x] **完整验收**：主机与协议矩阵、Debug/Release Gradle 构建、独立设备对照、JNI/ART 与手动发布门禁。重新绑定候选及 fixture SHA、原 PID/starttime、配置和收尾结果，失败与环境缺口不标成完成。
- [x] **文档与证据交付**：更新指南和 handoff；新证据单独保存，不回写此前成功报告。对实际完成范围和未覆盖条件作最终核对。

## 约束与验证

多路径 detail 总量有固定上限。参数快照不得改变业务寄存器、内存或 libc errno；路径内容只证明用户态读取，不证明并发条件下内核看到相同字节。
配对身份继续绑定 artifact、TID 和调用 id；版本、号码、PC 或 sequence 矛盾必须拒绝。缺少返回、断片和覆盖保持 unknown，不用最近入口或 scene return 补配。
诊断快照属于主动请求的普通线程操作，不修改异常处理或重放目标启动。Java/JIT 映射与 Java 栈各自表达可用性和截断，不作故障根因判断。
设备继续使用 canonical guard 和唯一自有目录。发布门禁可能涉及 demo 包，先核对现状、备份和恢复约束，保留其他应用与数据。

## 工作记录

- 开始状态：前两项和 syscall 首版已通过；CodeGraph 当前无可用索引，按规则回退定点读取。
- 已启动当前工作树的正常 Debug Gradle 链，先准备耗时的固定 QBDI/LLVM 源码依赖。功能修改后再次构建，最终证据仅引用最终产物。

- 实现完成：syscall detail schema 2、最多双路径、普通 QTRB 严格配对、观察上下文与 PC producer policy 已接通；原有 CALL wire layout 保留。
- 独立设备扩展矩阵已通过。停止用例的最初假设经实测纠正：阻塞 SVC 的 POST 可以先于停止观察，返回已知与 scene 返回未知可同时成立。原失败报告保留。
- 新增 `qtrace snapshot` 与独立 native ABI；输出 64 KiB、最多 32 线程/32 帧。JNI 入口、异常/errno/attachment、无 VM、信号 disposition 与公开 CLI 输出通道完成独立设备检查。最终资源收尾审查补充 proc 文件/目录的 RAII，候选已重建，最终 17 份功能与 6 份测量报告均通过，cleanup 已确认。
- Debug/Release 正常 Gradle 链、50 项 native、963 项 Python（9 跳过）、524 项 Rust（2 ignored）及 C++/Python/Rust 协议矩阵通过。原有 runtime fixture 两个产物字节保持不变，新增无 VM snapshot fixture。
- 发布门禁保留三次失败：Mi 11 与 Pixel 6 基线身份不匹配；Pixel 6 缺少 frida-tools Java bridge；补齐后 connection closed。三轮 cleanup 已确认。Pixel 6 随后空闲时确认无运行中的 Frida server，现用独立临时路径启动匹配版本，验证就绪后重跑门禁；结束将按原 PID/starttime 回收。

- 用户已批准扩展范围：保留不可变旧基线，建立版本化新基线并完成发布门禁。改动前保存的 tracer 与当前候选均得到 21714 条指令和原生返回 `0x20a128f3d199a008`；旧表记录 21718 与不同 QBDI 返回。新基线先采集独立原生调用和参考 tracer 的三 profile、各一次预热加五次测量，原速率与每次压缩大小门槛不变。

- 新版基线已建立：同一 Pixel 6、匹配 Frida 17.17.0，参考 tracer 的三档各一次预热加五次测量，共 18 个 artifact；直接原生调用确认相同返回。旧基线和所有原性能门槛保持不变。首次新版完整门禁通过历史比较后，在 timed-offset 发现空 crash 占位收尾竞争；已保留失败，修复 collector 并通过红/绿回归及全量 963 项 Python。最终完整门禁通过，成功 manifest 为 `b8e25dc5-5e33-48cf-b6e8-a71d13581fd9`，八场景报告与原候选身份齐全。

- 最终恢复与交付完成：Pixel 6、Mi 11 的原 APK 均恢复并核对 SHA，Pixel 6 原私有库原位恢复，Mi 11 原先不存在的自有部署库移除；demo 停止，自有 server/临时恢复目录收尾通过。原数据 tar、trace 备份和历史失败保留。源码清单、基线证据、完整门禁与恢复报告分别绑定 SHA，指南和 handoff 已同步；提交、合入及推送未执行。
