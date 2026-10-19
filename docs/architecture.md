# 架构与设计

[项目首页](../README.md) · [文档目录](README.md)

本文描述当前模块职责、追踪边界和配置协议。操作步骤见[使用指南](usage.md)，二进制字段见[格式规范](trace-format.md)。

## 数据流与模块职责

```text
qtrace CLI / Frida 脚本
  -> 加载 tracer、发布配置、恢复应用
  -> ShadowHook 安装入口 hook
  -> QBDI 执行目标与采集事件
  -> QTRB/LZ4 或持久 Flight Recorder
  -> 主机拉取、校验与转换
  -> qtrace-ui 离线索引与分析
```

| 模块 | 职责 |
| --- | --- |
| [`app/`](../app/) | Kotlin 演示 APK、native 场景和确定性验收 fixture |
| [`qtrace/`](../qtrace/) | 配置校验、设备绑定、目标身份解析、构建部署、session 编排、产物与报告发布 |
| [`tracer/`](../tracer/) | ShadowHook 入口接管、QBDI 执行、CodeRules、事件编码、持久写入与原生停止 |
| [`scripts/`](../scripts/) | 手动注入、格式转换、Flight 恢复、benchmark 和设备验收工具 |
| [`qtrace-ui/`](../qtrace-ui/) | 独立离线桌面分析器；provider、store、analysis、service 与 Tauri/React 展示层 |

Frida 负责启动期加载与配置。采集时限和停止由目标进程内的 native runtime 管理。
`qtrace demo` 只负责本仓库 fixture，外部应用的 APK 构建由使用方完成。

## 会话与停止

带 `session.durationMs` 的 generation 使用原生 deadline；只有 `session.id` 时使用 monitor。
strict schema 不接受 `mode`。默认链路在安装确认后 detach；CLI 的 `--detach-before-resume`
可提前 detach，并通过 ADB 校验绑定的原生安装凭据。

deadline worker 只发布停止请求。目标线程在 QBDI 边界各自封存产物，然后停止采集，以 control-only
方式执行到真实目标返回。阻塞线程可能延迟 acknowledgement，配置时长不保证强制返回，qtrace 不为满足时长 kill App。
精确控制顺序、线程 admission 和 terminal 语义见[会话生命周期](trace-format.md#autonomous-session-lifecycle)。

## 跟踪可靠性与样本身份

缺少 GNU build ID 的 ELF 可通过 `target.sha256` 显式验证；本地与设备副本都必须匹配。

普通模式保持入口 hook，QBDI 执行保留的原始指令跳板。跳板重定位的入口指令不计入目标指令轨迹，轨迹通过 `hook-gateway` 事件声明此边界。入口规则在跳板执行前按逻辑偏移评估，此入口通知没有解码指令信息。

[可靠性改进验收](benchmarks/qtrace-tracing-reliability-2026-10-19.md) 包含并发回归、模块偏移定义、自动标题验收、短函数缓冲测量与复现命令。

## 写入与恢复

普通 trace 在设备端编码为 QTRB，使用异步双缓冲和 LZ4 分帧写入。缓冲同时繁忙时生产者等待，
metrics 保留 backpressure；各 profile 不主动采样、丢弃或重排事件。文本格式 4 在主机端生成。

Flight Recorder 使用固定容量的多线程持久环形文件，始终按 full 语义记录目标模块内的指令、内存和 GPR。
恢复只使用已提交记录；覆盖范围、coverage gaps、损坏和未知终止原因必须保留。
`SIGKILL` 无法捕获，外部 `SIGKILL` 不会产生虚构的发起者。

产物完整性以 terminal、sidecar 和 Flight 恢复报告为依据。字段、容量计算、兼容与恢复规则统一见[格式规范](trace-format.md)。

## 配置与安装状态

CLI JSON 与 native JSON 分别见[使用指南](usage.md#qtrace-命令行)和[手动追踪](manual-tracing.md#配置-tracer)。
以下状态协议属于 native configure/status ABI：

configure 成功后，Frida console 会先打印 generation 和归一化 offset，再轮询同一
generation 的 status。状态依次可能是 `waiting_for_module`、`installing`，以及终态
`installed`、`hook_failed`、`rollback_failed` 或 `superseded`；场景状态还包括
`pending`、`rolled_back`。相同 status 不会重复打印，warning 用 `[!]` 输出且不等于失败。

JSON schema 是严格的：malformed JSON、unknown/missing/wrong-type 字段、JSON number 地址、
冲突 locator、`address - imageBase` 减法下溢、解析出的地址超出 `uintptr_t`、非法范围或无效
`flight.entryScene` 都会在发布前拒绝候选，且不会替换当前 generation。常见稳定错误码包括
`MALFORMED_JSON`、`UNKNOWN_FIELD`、
`TYPE_MISMATCH`、`INVALID_HEX_ADDRESS`、`CONFLICTING_LOCATION`、
`ADDRESS_BELOW_IMAGE_BASE`、`ADDRESS_OVERFLOW`、`INVALID_RANGE` 和
`INVALID_FLIGHT_ENTRY_SCENE`。

另一个 `ADDRESS_OVERFLOW` 发生在模块加载后计算
`runtimeAddress = moduleBase + normalizedOffset` 时。此时配置已经被接受并获得 generation；
它不是 configure rejection，而会令对应场景以
`error: {code: "ADDRESS_OVERFLOW", hookError: 0}` 进入 `hook_failed`，generation 最终为
`hook_failed`（或在回滚不能完成时为 `rollback_failed`）。

与此不同，packed library 的实际映射可能偏离静态 ELF。`ADDRESS_OUTSIDE_TARGET_MODULE`、
`ADDRESS_NOT_EXECUTABLE` 和 `ADDRESS_IN_RUNTIME_MAPPING` 只产生 warning，tracer 仍会尝试
安装 hook。真正的安装/回滚失败使用 `HOOK_INSTALL_FAILED`、`HOOK_INSTALL_RESIDUAL` 或
`HOOK_ROLLBACK_FAILED` 等稳定码，并保留 ShadowHook integer error。status 查询未知或已淘汰
generation 时返回 `GENERATION_NOT_FOUND`。

ABI transport code 只描述 JSON 是否完整传输：`0` 为 `QTRACE_JSON_OK`，`1` 为
`QTRACE_JSON_RESPONSE_TOO_SMALL`（可按返回的含 NUL size 安全重试，首次尝试不发布配置），
`2` 为 `QTRACE_JSON_INVALID_ARGUMENT`。schema/config/hook 结果都在 transport code 0 的 JSON
response 中。Configure rejection 或 status lookup rejection 使用
`error: {code, path, message}`；accepted generation 的 per-scene hook/runtime failure 使用
`error: {code, hookError}`，没有 `path` 或 `message`。

## 完整性扩展

默认 CodeRules 为空。启用样本规则须同时满足构建时样本绑定和运行时显式配置，
规则按模块偏移匹配，可修改寄存器、参数、返回值、PC、标志位或内存。
操作入口见[CodeRules](usage.md#完整性检查与-coderules)，机制见[完整性说明](integrity-bypass.md)。

## 离线分析与历史设计

分析器的证据分级、缓存、分页和资源边界见[qtrace-ui 设计](../qtrace-ui/docs/design.md)。
[文档目录](README.md#设计与历史记录)保留按主题组织的历史方案与实施计划；
历史方案用于理解决策，当前操作以使用指南和开发指南为入口。
