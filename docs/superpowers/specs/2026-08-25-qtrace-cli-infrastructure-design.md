# qtrace 通用工作流与稳定性基础设施设计

**日期：** 2026-08-25

**状态：** 已完成设计讨论，等待书面规格复核

**范围：** 仓库内 `qtrace` CLI、通用 App 接入、native 自治停止、产物管理与验证基础设施

## 1. 背景

当前项目已经具备较完整的 Android arm64 QBDI tracing 能力：结构化 tracer 配置、ShadowHook
入口接管、普通 QTRB/LZ4 trace、持久 Flight Recorder、崩溃恢复、主机转换工具以及性能基线。
当前基线包含 259 个 Python 测试和 43 个 native host 测试，均已通过。

现阶段的主要矛盾不再是缺少底层采集字段，而是完整工作流仍分散在 JavaScript、Python、
Gradle、adb 和外部工具之间。普通使用者需要手动编辑 `spawn_trace.js`、部署多个动态库、
管理 Frida 会话、识别产物并分别调用拉取和转换脚本。设备端已有较强的故障语义，但主机端
缺少统一会话、稳定错误码和可供 CI 使用的报告。

本设计将这些能力收敛为仓库内的通用 `qtrace` 工作流。仓库自带 demo 只作为 fixture 和
真实设备验收对象；通用路径不得依赖 demo 的 package、模块或场景。

## 2. 目标

首个阶段实现以下目标：

1. 使用 `python3 -m qtrace` 统一构建 tracer、部署、注入、采集、拉取、转换和报告。
2. 支持任意已安装或由用户提供 APK 的 Android arm64 App，而不是只支持 demo。
3. 提供定时采集、持续监控和独立手动拉取三种工作流。
4. Frida 仅参与 spawn 注入和一次性初始化；成功安装 hook 后，native tracer 独立运行。
5. 定时到期后尽快停止记录并封口产物，但不结束 App，也不伪造目标函数返回。
6. 使用稳定状态机、错误码、原子产物发布和 session 报告改善故障诊断。
7. Host CI 覆盖主机和 native 逻辑；单台 USB/root arm64 设备提供一键端到端验收。
8. 为未来 resolver、injector、transport、processor 和 reporter 后端保留清晰接口。

## 3. 非目标

首个阶段不包含：

- 多设备并发或多个活跃采集会话。
- 常驻 daemon、远程任务服务或 Web UI。
- 字节特征码扫描、DWARF 高级查询或 IDA image-base 地址转换。
- 单会话多目标模块、非主进程自动发现或多 ABI 支持。
- 动态加载第三方 Python/native 插件。
- 自动修改、签名或重打包目标 APK。
- 自动停止或强杀目标 App。
- 对生产环境作稳定性承诺。

## 4. 总体架构

新增仓库内 Python package `qtrace/`。CLI 只依赖模块接口，不直接拼接不受约束的 adb shell
命令，也不解析 QTRB 内部细节。

```text
python3 -m qtrace
        |
        v
SessionOrchestrator
        |
        +-- ConfigLoader
        +-- Preflight
        +-- TracerBuilder
        +-- AppInstaller
        +-- TargetResolver
        +-- DeviceTransport
        +-- FridaInjector
        +-- SessionObserver
        +-- ArtifactProcessor
        `-- Reporter
```

各模块边界如下：

- `ConfigLoader`：加载用户 JSON、拒绝未知字段、归一化路径，并生成 native tracer JSON。
- `Preflight`：检查 adb、设备、ABI、package、Frida、NDK LLVM、lz4、存储和部署权限。
- `TracerBuilder`：构建本仓库 tracer/companion，或验证用户指定的预构建产物。
- `AppInstaller`：只安装用户明确提供的现成 APK；不构建外部 App。
- `TargetResolver`：把 ELF symbol 或显式模块相对范围解析为 native offset/endOffset。
- `DeviceTransport`：封装有 timeout、输出上限和参数校验的 adb 操作。
- `FridaInjector`：spawn App、加载 tracer、调用一次初始化、等待 hook 安装，再分离。
- `SessionObserver`：通过 adb 观察 PID 和 native session 状态文件，不依赖持续 Frida RPC。
- `ArtifactProcessor`：发现、流式拉取、校验、恢复和转换普通/flight 产物。
- `Reporter`：输出控制台进度、机器 JSON 和完整 session 报告。

现有 `pull_trace.py`、`trace_convert.py`、`flight_convert.py`、`lz4_frames.py` 和相关解析器中的
可靠实现应下沉为可复用函数。旧 CLI 在迁移期间保留兼容入口。`benchmark_trace.py` 继续作为
性能验收工具，不再承担通用工作流职责。

orchestrator 按 `device serial + package` 获取主机锁。同一目标已有 `run` 或 `monitor` 时，第二个
写会话以 `SESSION_BUSY` 失败。`pull` 可以并行读取，但只发布 native 已声明 sealed 的普通产物
或 Flight Recorder 已提交的可恢复 chunks，不把正在写入的文件当作完整结果。

## 5. 命令模型

### 5.1 定时采集

```bash
python3 -m qtrace run --config target.json --duration 60s
```

流程：

```text
preflight -> resolve -> build/select tracer -> optional APK install
-> deploy -> Frida spawn/init/resume -> wait for installed -> Frida detach
-> native timed capture -> native stop/seal -> pull -> validate -> convert -> report
```

`--duration` 是必填的正时长。计时从 generation 的全部 scene hook 成功安装并进入
`installed` 后开始，不包含等待模块加载和 hook 安装的时间。到期后只停止 tracer generation，
App 保持运行。

时长接受 `ms`、`s`、`m` 后缀并在主机端归一化；最小 100 ms，最大 24 h。默认 setup timeout
为 90 s、stop acknowledgement timeout 为 10 s、单次 adb timeout 为 30 s，均可通过独立 CLI
参数覆盖。省略 `--device` 时必须恰好连接一台 adb 设备，否则在 preflight 阶段拒绝选择。

### 5.2 持续监控

```bash
python3 -m qtrace monitor --config target.json
```

初始化过程与 `run` 相同，但不设置 native deadline。Frida 分离后，主机通过 adb 监控目标
PID。App 正常退出或崩溃后，工具自动拉取、恢复、转换并报告。

用户按 Ctrl-C 只终止主机监控，不向 App 或 tracer 发送停止请求，也不删除设备产物。
命令输出明确提示稍后可使用 `qtrace pull`。本阶段不提供运行期 Frida 控制通道。

### 5.3 手动拉取

```bash
python3 -m qtrace pull --package com.example.app --latest
python3 -m qtrace pull --package com.example.app --name <artifact>
python3 -m qtrace pull --package com.example.app --all
python3 -m qtrace pull --package com.example.app --compressed-only
```

`pull` 不启动 Frida、不启动或停止 App，也不要求采集会话仍然存在。默认行为等同于
`--latest`。所有目标文件先写入唯一临时文件，校验成功后原子发布；默认不覆盖既有本地文件。

### 5.4 Demo 验收

```bash
python3 -m qtrace demo
```

`demo` 是项目自检入口：构建并安装仓库自带 fixture，使用与外部 App 完全相同的配置、
orchestrator 和产物路径运行真实设备验收。通用模块内不得出现 demo package、模块名或 scene
特判。

## 6. 用户配置

首版采用严格 JSON，避免新增 YAML/TOML 依赖，并与已有 native JSON schema 保持一致的验证
风格。示例：

```json
{
  "schemaVersion": 1,
  "app": {
    "package": "com.example.app",
    "apk": "artifacts/example.apk"
  },
  "target": {
    "module": "libtarget.so",
    "binary": "symbols/arm64-v8a/libtarget.so"
  },
  "tracer": {
    "profile": "balanced",
    "compression": true,
    "flightEnabled": true,
    "flightEntryScene": "verify"
  },
  "scenes": [
    {
      "name": "decrypt",
      "startOffset": "0x18a40",
      "endOffset": "0x18b20"
    },
    {
      "name": "verify",
      "symbol": "Java_com_example_Native_verify"
    }
  ]
}
```

规则：

- `schemaVersion`、`app.package`、`target.module` 和非空 `scenes` 必填。
- `app.apk` 可选。存在时表示使用该现成 APK 进行安装和目标 ELF 提取；工具不构建它。
- `target.binary` 可选，优先用于 symbol 解析。它可以是与安装产物 build ID 匹配的未剥离 ELF。
- 用户配置不包含设备序列号、duration 和输出目录；这些是单次 CLI 参数。
- 用户不编辑 `spawn_trace.js`。主机生成 native JSON 并注入固定的通用 Frida loader。
- 未知字段、类型错误、非法范围和路径歧义在 spawn 前失败。

### 6.1 Scene 规则

一个 scene 表示目标模块中的一个 hook 入口和明确的 instrumentation 半开区间。最多允许 256
个 scene。

- `name` 必填、非空、最长 128 字节，并在配置内唯一。
- 每个 scene 必须且只能使用一种形式：
  - `startOffset + endOffset`；或
  - `symbol`。
- 不接受绝对运行时地址，不接受 `imageBase + address`。
- 显式偏移必须是 `0x...` 字符串，不能使用 JSON number。
- `startOffset` 非零，`endOffset` 为 exclusive end，且必须严格大于 start。
- arm64 起止偏移必须满足指令对齐，并位于目标 ELF 的可执行映射内。
- symbol 必须唯一解析为 AArch64 函数符号，且 symbol size 大于零。
- symbol 的 value 和 size 被归一化为 `[startOffset, endOffset)`；size 为零时要求改用显式偏移。
- 如果提供未剥离 `target.binary`，其 build ID 必须与 APK/已安装目标模块匹配；不匹配时拒绝
  启动，而不是只给 warning。
- 所有 scene 属于全局 `target.module`。数组顺序只用于稳定展示和 native scene index，不表达
  优先级。
- Flight Recorder 启用时，`flightEntryScene` 必须精确引用一个 scene name。

scene 的 end 只限定被记录的指令范围，不负责强行结束目标函数。QBDI 仍执行真实目标函数，
直到函数返回、线程退出或发生已定义的终止事件。

### 6.2 目标 ELF 来源

解析 symbol 时按以下顺序寻找 ELF：

1. `target.binary`。
2. `app.apk` 中与设备 ABI 对应的 `lib/<abi>/<target.module>`。
3. 通过 `pm path` 获取已安装 base/split APK，再提取唯一匹配模块。

找不到模块、出现多个无法消歧的候选、ABI 不符、build ID 不匹配或符号范围不可执行时，
在注入前失败。首版使用 Android NDK LLVM 工具解析 ELF，不自行实现完整 ELF parser。

## 7. Frida 启动职责

Frida 只存在于启动阶段：

```text
spawn suspended process
-> load tracer/companion
-> call qtrace_init(config) once
-> resume process
-> wait until native generation is installed or setup timeout
-> detach Frida
```

模块通常在 App resume 后才加载，因此 injector 可以在启动阶段短暂查询安装结果；一旦 generation
进入终态，采集、deadline、停止和封口均不再依赖 Frida。运行期状态通过 app-private session
文件提供给 adb observer。

初始化拒绝沿用现有 generation 保留语义：无效配置不能替换最后一个有效 generation。CLI
必须验证一次性初始化响应和最终 hook 状态，不能仅以 transport code 判断成功。

## 8. Native 自治停止

### 8.1 状态

每个 generation 拥有不可复用的 stop 状态：

```text
running -> stop_requested -> stopping -> sealed
                            `-> stop_incomplete
```

generation 安装成功后启动 native deadline timer。timer 不接触 writer，只原子发布
`stop_requested`。旧 generation 的 timer 不得影响新 generation。

### 8.2 新调用

proxy 在进入 QBDI 前检查 generation stop 状态。deadline 后到达的新 scene 调用不再创建 trace，
而是通过 retained-original 安全透传。hook 可以安全卸载时允许卸载；卸载失败时保持 dormant
proxy 透传，并在 session report 中保留稳定错误码。

### 8.3 活跃调用

活跃目标线程在下一次 QBDI PRE callback 观察 `stop_requested`：

1. callback 在执行新的采集操作前返回 `QBDI::STOP`。
2. `vm.run()` 提前返回，并保留当前 GPR/PC 状态。
3. writer 在所属目标线程停止接受事件、flush、写 terminal record 并封口。
4. native 发布该调用已 sealed。
5. 现有 `QbdiThreadSession` 使用 `control_only` 从当前状态继续执行到真实函数返回。
6. `control_only` 不运行 `InstructionCollector`，但保留 QBDI 所需控制范围和真实 ABI/返回值。

“立即停止”定义为下一次可执行的 QBDI callback，而不是硬实时中断。线程阻塞在 syscall、模块外
代码或不可调度状态时，必须等控制权重新进入 QBDI。主机在 `--stop-timeout` 到期后将 session
标记为 `stop_incomplete`，拉取其他已封口产物并返回退出码 3；不得强杀 App 或伪造 footer。

多个活跃 scene 各自在所属线程完成封口。generation 只有在所有已登记 writer 均 sealed，或被
明确判定无法及时确认后，才能进入 session 终态。stop 和 seal 操作必须幂等。

Flight Recorder 使用相同 generation stop flag。deadline 后不再登记新线程；已登记线程在下次
callback 停止发布事件并由所属线程 seal 当前 chunk。`CaptureCoordinator` 只有在全部登记线程
确认后才发布 stopped 终态。未在 timeout 内确认时保留已经提交、可恢复的 chunks，将 session
标为 `stop_incomplete`，不得跨线程强制 seal 另一个线程正在写入的 chunk。

## 9. Trace 终止格式

主动定时停止发生在目标函数返回之前，现有 QTRB v1.1 `TRACE_END` 的 success/return-value
语义无法准确表达该状态。因此定义 QTRB v1.2：

- `StreamHeader.minor = 2`。
- `required_features` bit `0x00000001` 表示 reader 必须理解 stopped terminal。
- 正常函数返回继续使用 record type 9 `TRACE_END` 的既有布局。
- 新增 record type 10 `TRACE_STOP`，flags 必须为零，reason `1` 表示 `duration_elapsed`；reason
  `0` 非法，`2..255` 保留。
- `TRACE_STOP` payload 是 96 字节，按 little-endian 顺序为：

```text
reason u8
reserved u8[7] = 0
elapsed_ms u64
instructions u64
encoded_bytes u64
compressed_bytes u64
cache_hits u64
cache_misses u64
cache_collisions u64
buffer_swaps u64
producer_waits u64
producer_wait_ns u64
effective_buffer_bytes u64
```

`encoded_bytes` 包含 `TRACE_STOP` 自身的 104 个 record bytes；`compressed_bytes` 使用与既有
`TRACE_END` 相同的最终 artifact 口径。stopped terminal 不包含目标返回值。

metrics v3 保留 v2 writer 字段，并新增：

```text
termination=completed|stopped
return_valid=0|1
```

为保持 sidecar 键集合稳定，v3 始终保留 `return`：completed 设置真实十六进制值和
`return_valid=1`；stopped 设置规范值 `0x0` 和 `return_valid=0`。消费者在
`return_valid=0` 时不得使用 `return`。

文本格式升级为 format 4。completed terminal 输出 `status=completed return_valid=1
return=0x...`；stopped terminal 输出 `status=stopped reason=duration_elapsed return_valid=0`，
并输出共同 metrics。failed/crashed 不由 converter 合成虚假 terminal；它们仍由 writer failure、
有效 crash marker 和 recovery report 表达。

新 converter 必须继续读取 QTRB v1.0/v1.1、metrics v1/v2 和既有文本产物。旧 reader 可以
拒绝带 required feature bit 的 v1.2，而不得静默误读。stopped 产物属于完整、预期终止的采集
窗口，`qtrace run` 为其返回退出码 0。上述 wire 值由 golden codec tests 固定，并同步写入
`docs/trace-format.md`。

## 10. Session 状态与产物归属

主机为每次 `run`/`monitor` 生成不可预测且唯一的 session ID，并随初始化配置传给 native。
native 只在状态转换时原子更新 app-private session 文件；指令热路径不得写该文件。

示例：

```json
{
  "schemaVersion": 1,
  "sessionId": "7d5807cf-cf09-4f21-92de-1ad92802610a",
  "generation": 3,
  "state": "sealed",
  "reason": "duration_elapsed",
  "activeScenes": [],
  "artifacts": ["...trace.bin.lz4"],
  "errors": []
}
```

session ID 使用小写 UUIDv4；展示时间只属于 report，不参与 identity。状态文件必须包含 schema
version、generation、单调阶段时间、归一化 scene、活跃 TID、产物名、
warning/error code 和停止确认。设备端文件名包含 session ID，且 package/name 在主机和 native
两侧都经过安全字符验证。

orchestrator 在启动前仍记录设备产物清单，并将“session 文件声明的产物”与“本次新增产物”
交叉验证。两者不一致时拒绝把不明产物归入当前 session。`pull --latest` 依据有效 session 文件
选择；`--name` 保留现有精确产物选择能力。

## 11. 部署和预检

通用 App 路径不构建目标 APK：

- 没有 `app.apk`：验证 package 已安装。
- 提供 `app.apk`：安装该现成 APK，并使用其 ELF 做解析/identity 检查。
- tracer 默认由当前仓库构建；用户可显式指定预构建 tracer/companion。

部署策略为 `auto`：优先选择已验证可由目标进程加载且可由主机拉取的 app-private 路径，失败
时再使用明确配置的远端目录。预检必须在 spawn 前验证实际映射权限、可用空间、ABI、Frida
握手、run-as/root 能力和 host lz4。不能把 SELinux/linker namespace 问题延迟成模糊的
`Module.load failed`。

所有外部进程通过现有 bounded-process 风格执行，具备独立 timeout、输出大小上限和参数数组，
不把 package、文件名或用户输入拼入 shell 程序文本。

## 12. 错误与清理

主机状态机为：

```text
preflight -> resolving_target -> deploying -> injecting -> installing_hooks
-> running -> stopping -> sealed -> pulling -> completed
```

错误至少包含稳定 code、阶段、用户说明和受限长度的底层诊断。首版稳定 code 包括：

- `DEVICE_NOT_FOUND`
- `SESSION_BUSY`
- `FRIDA_VERSION_MISMATCH`
- `PACKAGE_NOT_INSTALLED`
- `UNSUPPORTED_ABI`
- `TARGET_MODULE_NOT_FOUND`
- `SYMBOL_NOT_FOUND`
- `SYMBOL_SIZE_INVALID`
- `TARGET_IDENTITY_MISMATCH`
- `TRACER_LOAD_FAILED`
- `HOOK_INSTALL_FAILED`
- `PROCESS_EXITED_DURING_SETUP`
- `STOP_NOT_ACKNOWLEDGED`
- `ARTIFACT_INCOMPLETE`
- `ARTIFACT_INTEGRITY_FAILED`
- `ADB_PULL_FAILED`

清理原则：

- spawn 后、resume 前失败：释放 Frida 对象并结束被挂起的进程。
- resume 后失败：默认不停止 App；结束主机工作并保存诊断。
- 不删除设备端原始产物。
- 拉取使用临时文件、fsync 和原子发布，默认不覆盖。
- stopped 是定时模式的正常成功；crash recovered 与普通 completed 明确区分。

稳定退出码：

- `0`：按预期完成，包括定时 stopped。
- `1`：配置、环境、注入、hook 或运行失败。
- `2`：得到可用但不完整或崩溃恢复的产物。
- `3`：停止未在 timeout 内完全确认。
- `130`：用户中断主机命令。

## 13. 输出与报告

每次运行生成独立目录：

```text
qtrace-output/<session-id>/
|-- session.json
|-- effective-config.json
|-- device.json
|-- artifacts/
|   |-- *.trace.bin.lz4
|   |-- *.metrics
|   `-- *.trace.txt
`-- report.json
```

`report.json` 包含：

- session ID、命令模式、完整阶段时间线和退出分类。
- 设备、Android、ABI、Frida、tracer hash、目标 ELF hash/build ID。
- 原始配置来源与归一化 scene ranges。
- hook 状态、native generation、deadline 和停止原因。
- 活跃 scene/TID、stop acknowledgement、恢复范围和覆盖缺口。
- 每个产物的大小、hash、格式、完整性、转换输出和 warning/error。

控制台默认显示精简进度；`--json` 输出适合 CI 的机器结果。报告不得包含未显式允许的环境
变量、设备凭据或无限制 logcat/工具输出。

## 14. 验证策略

### 14.1 Host CI

每次提交运行：

- qtrace 配置、resolver、状态机、错误映射和 reporter 单元测试。
- fake adb/fake Frida adapter 的超时、断连、异常输出和清理测试。
- 现有全部 Python tests 和 native host tests。
- tracer 与 demo Debug 构建及既有构建契约测试。
- QTRB v1.2、metrics v3 golden codec tests 和旧格式兼容测试。
- 损坏、截断、重复文件、路径安全和原子发布测试。

### 14.2 Native 竞态

必须覆盖：

- deadline 与 scene 入口同时发生。
- 多线程执行同一/不同 scene。
- stop 位于 PRE/POST/memory callback 边界。
- stop 后新调用透传且不创建产物。
- writer 封口后拒绝任何写入。
- 重复 stop/seal 幂等。
- generation 切换时旧 timer 隔离。
- fork、线程退出、signal 与 stop 交叉。
- opt-in ThreadSanitizer 覆盖新增共享状态。

### 14.3 单设备验收

`python3 -m qtrace demo` 在一台 USB/root arm64 设备上验证：

1. 定时到期后停止记录，App 继续运行。
2. 长目标在 stop 后进入 control-only，最终返回值与未追踪执行一致。
3. monitor 等待正常退出并自动拉取。
4. 崩溃后恢复 Flight Recorder/partial trace。
5. Frida 初始化后分离，native 仍按 deadline 完成。
6. 手动 latest/name/all/compressed-only 拉取。
7. symbol 与等价显式范围得到相同归一化结果。
8. adb 暂时断开后，设备证据保留并可稍后拉取。

### 14.4 性能

- stop 检查不得在每条指令执行系统调用或更新 session 文件。
- 使用既有 benchmark 中位数和语义 oracle 评估 fast profile。
- 性能门使用预先记录的容差和多次运行，不以单次耗时判定。
- 报告 stop 检查、writer backpressure 和转换成本，便于定位退化来源。

## 15. 扩展接缝与演进顺序

首版使用内部稳定接口，不提供动态插件发现：

- `TargetResolver`：未来增加特征码、DWARF、IDA map。
- `Injector`：未来增加 Gadget 或其他注入后端。
- `DeviceTransport`：未来增加远程设备和设备农场。
- `ArtifactProcessor`：未来增加 SQLite、Perfetto、Chrome Trace。
- `Analyzer`：未来增加调用图、热点、内存访问和 trace diff。
- `Reporter`：未来增加 HTML 或 Web UI。

建议后续顺序：

1. 本设计的通用 CLI、native stop、session/report 和验证闭环。
2. `doctor`、`config init`、symbol 列表、历史 session 查询。
3. SQLite 索引、查询、diff 和热点分析。
4. 单会话多模块、更多 ABI、Gadget/non-root 工作流。
5. 设备矩阵、远程任务和团队产物归档。

## 16. 验收标准

本阶段完成时必须满足：

1. 外部 App 可以仅通过 JSON 配置和 `python3 -m qtrace` 接入，无需修改 JS/C++。
2. scene 只接受明确的相对范围或能解析出有效 size 的 symbol。
3. Frida 在启动安装完成后可分离，定时停止不依赖运行期 Frida 线程。
4. deadline 后新调用不再采集；活跃调用在下一 QBDI callback 停止记录并安全封口。
5. App 不被 qtrace 的正常 stop 流程结束，目标函数最终保持真实 ABI 和返回行为。
6. stopped trace 有独立、可校验的 terminal/metrics/text 语义。
7. run、monitor、pull 和 demo 均使用同一 orchestrator/processor 边界。
8. 每个成功发布的产物能对应唯一 session，并通过 container/footer/sidecar 校验。
9. host 失败不删除设备证据；stop timeout、crash 和 corruption 有不同结果。
10. 全部 host tests 通过，并产生至少一份真实设备验收报告。
