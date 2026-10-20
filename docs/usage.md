# 使用指南

[项目首页](../README.md) · [文档目录](README.md)

本文覆盖 qtrace CLI、采集档位、产物拉取和排障。所有命令从仓库根目录执行。
手动调整 Frida 脚本见[手动追踪](manual-tracing.md)；构建与测试见[开发指南](development.md)。

## 环境要求

- 仅构建 `arm64-v8a`，最低 Android API 24；示例当前使用 compile/target SDK 35。
- 主机需要 Python 3.11+、Android SDK、NDK、CMake 3.22.1 与 3.31.6、JDK 17、Git 和主机 C/C++ 编译器。
- tracer 使用 CMake 3.31.6 构建 QBDI 源码；fixture 和主机测试仍使用 CMake 3.22.1。首次 Android 构建需要联网下载 LLVM、spdlog，并为 LLVM 编译主机工具。
- 安装 Frida Python bindings 与 CLI，并保证 host/server 版本匹配。配置 `ANDROID_HOME`，以及 `ANDROID_NDK_HOME` 或 `ANDROID_NDK_ROOT`。
- 需要可执行 spawn 注入的 Frida 环境。root 设备通常使用与主机版本匹配的 `frida-server`；jailed/non-root 设备通常需要 Frida Gadget。
- APK 的 release 变体明确设置为 `debuggable false`；实验所需的注入流程使用 debug 变体。
- 场景以 `module_base + offset` 定位，偏移与具体构建产物绑定；重新编译目标库后应重新确认。
- 手动 Frida 脚本默认启用 Flight Recorder，预分配 512 MiB 文件；CLI 默认关闭 Flight。启用前确认设备存储空间。
- `SIGKILL` 无法捕获。tracer 只能解释目标线程在执行终止 syscall 前写下的意图，外部 `SIGKILL` 不会产生虚构的发起者。

确认以下命令可用：

```bash
adb version
frida --version
java -version
git --version
```

Frida 主机工具与设备端 server 应使用匹配版本。QTRB `.trace.bin.lz4` 始终需要主机 `lz4`，包括 `--compressed-only`。后者只抑制转换文本发布，仍会解压校验 QTRB 版本、terminal 和 sidecar。遗留 `.trace.txt.lz4` 与 Flight Recorder `.flight.bin` 使用 `--compressed-only` 可原样拉取，无需解压。

初始化 QBDI 源码 submodule（新克隆也可使用 `git clone --recurse-submodules`）：

```bash
git submodule update --init --recursive
```

之后每次拉取父仓库更新，都执行同一条命令同步固定的 QBDI commit。
依赖版本、构建缓存、升级与回退见[QBDI 源码依赖](development.md#qbdi-源码依赖)。

首次使用 CLI 前，先完成 APK 和 tracer 的源码构建，避免 LLVM 编译超过默认的 90 秒 setup/build 时限：

```bash
./gradlew :app:assembleDebug :tracer:copyTracerDebug --no-daemon
```

## qtrace 命令行

`python3 -m qtrace` 是一次性 app tracing 工作流。它需要 rooted（或对目标
app 可用 `run-as`）的 `arm64-v8a`、API 24+ 设备，ADB、匹配版本的 Frida
host/server、Android NDK（设置 `ANDROID_NDK_HOME` 或 `ANDROID_NDK_ROOT`）和
host `lz4`。外部应用的 APK 构建不在 qtrace 范围内；配置可选的 `app.apk`
只会安装那个已存在的 APK，绝不会构建它。

对任意外部包，先写严格 JSON 配置 `target.json`，再运行带时长的 session 或无限期 monitor。配置文件必须是
不超过 1 MiB 的 UTF-8 regular file；符号链接、special file、重复字段、非有限数字及过深 JSON
都会在任何设备操作前被拒绝：

```bash
python3 -m qtrace run --config target.json --duration 30s --device SERIAL --output results
python3 -m qtrace monitor --config target.json --device SERIAL --output results
```

如果目标在 Frida 驻留的启动阶段出现兼容性问题，可给 `run` 或 `monitor` 加
`--detach-before-resume`。该选项在发布原生配置后、恢复应用前卸载脚本并脱离会话，
随后通过 ADB 校验绑定 session、PID、generation 和场景的原生安装凭据；不会将配置回执当作安装成功。

配置中的 offset 是模块相对、半开区间 `[startOffset,endOffset)`；不接受 base
address。offset 与 symbol 两种严格形式如下（它们不能混用，也不能附加 `base`）：

```json
{
  "schemaVersion": 1,
  "app": { "package": "com.example.app" },
  "target": { "module": "libtarget.so" },
  "tracer": { "profile": "fast" },
  "scenes": [
    { "name": "target", "startOffset": "0x120", "endOffset": "0x180" }
  ]
}
```

```json
{
  "schemaVersion": 1,
  "app": { "package": "com.example.app" },
  "target": { "module": "libtarget.so" },
  "tracer": {},
  "scenes": [
    { "name": "target", "symbol": "target_function" }
  ]
}
```

将示例包名、模块名、偏移或符号替换为本次目标构建的实际值。CLI 的 offset 必须非零且按 4 字节对齐。
CLI 在主机解析 symbol，再把 offset 交给 native tracer；这与[手动 Frida 配置](manual-tracing.md#配置-tracer)的 locator 格式不同。

常用可选字段：

| 字段 | 用途 |
| --- | --- |
| `app.apk` | 安装已有 APK；不会构建外部应用 |
| `target.binary` | 指定本地目标 ELF；路径相对配置文件目录解析 |
| `target.sha256` | 以 64 个小写十六进制字符的 SHA-256 验证样本，本地与设备副本必须匹配；无 GNU build ID 时使用 |
| `tracer.profile` | `fast`、`balanced` 或 `full`，默认 `fast` |
| `tracer.compression` | 是否压缩，默认 `true` |
| `tracer.flightEnabled` / `tracer.flightEntryScene` | 开启 Flight 并明确指定已配置的入口场景；关闭时省略 `flightEntryScene` |
| `tracer.library` / `tracer.companion` | 同时指定预构建 tracer 与 ShadowHook companion；路径相对配置文件目录解析 |
| `tracer.codeRules` | 显式启用样本规则，要求同时提供 `target.sha256` |

### 拉取与 demo

手动拉取不读取目标配置、不构建 tracer，也不加载 Frida；选择器默认是
`latest`，`compressed-only` 是正交过滤器：

```bash
python3 -m qtrace pull --package com.example.app --latest --device SERIAL
python3 -m qtrace pull --package com.example.app --name run.trace.bin.lz4 --device SERIAL
python3 -m qtrace pull --package com.example.app --all --device SERIAL
python3 -m qtrace pull --package com.example.app --all --compressed-only --device SERIAL
```

`demo` 仅是本仓库的设备验收 fixture，不是外部应用的模板；它构建 fixture APK，
再走完全相同的 orchestrator：

```bash
python3 -m qtrace demo --scenario timed --duration 10s --scene-form offset --device SERIAL
```

### 输出、时限与退出码

所有命令默认将报告和产物写入 `qtrace-output`；`--json` 只在 stdout 输出一个
机器结果对象，进度写 stderr。默认 setup/stop/单个 ADB/pull timeout 分别为
90/10/30/60 秒；每个 timeout 必须为有限正数，`run --duration` 必须介于
100 ms 和 24 h，输入使用 `ms`、`s` 或 `m`，例如 `100ms`、`30s`、`1440m`。

| Exit code | Meaning |
| ---: | --- |
| 0 | 完整成功 |
| 1 | 配置、设备、注入或命令错误 |
| 2 | 已发布部分可恢复产物 |
| 3 | 原生 stop 未完整封存 |
| 130 | 用户中断；orchestrator 已写 interrupted report |

session report 保存包名、设备、目标和配置上下文。离线分析优先在 [qtrace-ui](../qtrace-ui/README.md) 中打开 report；
单个轨迹文件也可打开，但缺少这些上下文。成功、部分恢复和停止失败应结合退出码与报告判断。

## 采集配置

| Profile | 指令与寄存器 | 内存访问元数据 | 内存前后字节 | 适用场景 |
| --- | --- | --- | --- | --- |
| `fast` | 是 | 否 | 否 | 大范围指令流、优先吞吐 |
| `balanced` | 是 | 是 | 否 | 分析读写地址、大小和类型 |
| `full` | 是 | 是 | 是，单侧最多 64 B | 深入检查内存状态与崩溃上下文 |

三种配置都不会主动采样、丢弃或重排事件。两个异步缓冲区同时繁忙时，生产者会等待，并在 metrics 中记录 backpressure。

Flight Recorder 始终按 full 语义采集目标模块内的指令、内存和 GPR，不受普通 trace profile 影响。完整字段、容量计算和兼容规则见 [QTRB 与文本格式说明](trace-format.md)。

## Pull Traces

以下底层脚本适合手动 Frida 采集；CLI session 优先使用上面的 `python3 -m qtrace pull`。

普通轨迹和 Flight Recorder 产物都写入 debuggable 应用的 app-private 目录：

```text
/data/data/com.aprz.qbdiandroid/files/qbdi-traces/
```

使用 `adb exec-out run-as` 拉取最新产物。指定 `--device` 可选择设备：

```bash
python3 scripts/pull_trace.py --package com.aprz.qbdiandroid \
  --device 192.168.51.42:5555 --output pulled-traces
```

常用操作，将示例文件名替换为设备中的实际产物名：

```bash
# 指定设备列表中的某个产物。
python3 scripts/pull_trace.py --package com.aprz.qbdiandroid \
  --name run.flight.bin --output pulled-traces

# 遗留 `.trace.txt.lz4` 可不依赖主机 lz4 原样拉取；用 --name 避免自动选中 QTRB。
python3 scripts/pull_trace.py --package com.aprz.qbdiandroid \
  --name legacy.trace.txt.lz4 \
  --compressed-only --output pulled-traces

# `.flight.bin` 也可用 --compressed-only 原样拉取。QTRB `.trace.bin.lz4` 即使使用
# --compressed-only 仍需要 lz4，以在发布前校验版本、terminal 和 sidecar。

# 明确允许替换已有本地输出。
python3 scripts/pull_trace.py --package com.aprz.qbdiandroid \
  --force --output pulled-traces

# 手动把 QTRB/LZ4 转成文本格式 4。
python3 scripts/trace_convert.py input.trace.bin.lz4 --output output.trace.txt
```

完整的 QTRB 产物带有严格的 `metrics_version=3` sidecar。工具会校验容器、终端、指标和指令序列，再原子发布文本；默认拒绝覆盖已有文件。完成的 type 9 终端显示为 `status=completed`，有效 stopped type 10 终端显示为 `status=stopped`，两者均以 exit 0 返回；带有效 crash marker 的截断产物只恢复完整先前帧，仍以 exit 2/`crashed` 返回，且不会伪造 terminal。

兼容矩阵：

| 输入 | 含义 | 支持 |
| --- | --- | --- |
| QTRB 1.0/1.1 + metrics v2 | 旧 completed 输入 | 可读取 |
| QTRB 1.2 type 9 + metrics v3 | completed | 可读取，文本 format 4 |
| QTRB 1.2 type 10 + metrics v3 | stopped | 可读取，文本 format 4 |
| truncated + valid crash marker | recovered/partial | 只恢复完整先前帧，不伪造 terminal |

对于 `.flight.bin`，正常拉取会保留原文件，并生成：

- `<basename>.merged.trace.txt`：按进程全局序列合并；
- `<basename>.tid-<tid>.trace.txt`：每个被恢复线程一份；
- `<basename>.flight.json`：完整性、终止候选、信号、保留/覆盖范围、coverage gaps 和损坏摘要。

判断崩溃窗口是否完整时，以 `.flight.json` 为准。缺少 terminal marker 代表终止原因未知，不等同于损坏；coverage gap、torn/invalid chunk、仍活跃 chunk 或未闭合线程生命周期会使结果不完整。

## 完整性检查与 CodeRules

integrity 场景包含 `.text` hash 校验和 `/proc/self/maps` 检查。通用 CodeRules 默认为空。自定义策略须通过 `QTRACE_USER_RULES_SOURCE` 选择源文件、通过 `QTRACE_USER_RULES_SAMPLE_SHA256` 绑定样本，并显式设置 `tracer.codeRules: true` 和 `target.sha256`。CodeRules 按目标模块偏移匹配；JavaScript 配置负责场景位置。

具体机制见 [完整性检查与 CodeRules](integrity-bypass.md)。

真实应用的检测链、QBDI 跟踪结果、工具修复和并发覆盖限制，见
[数码宝贝 UP / AppGuard 实测](research/2026-10-19-appguard-dgup.md)。

## 常见问题

### 构建提示 `QBDI submodule is missing`

在仓库根目录运行 `git submodule update --init --recursive`，再重试构建。
父仓库的源码压缩包不包含 submodule 源码；请使用 Git 克隆并初始化依赖。

### tracer 构建提示 CMake 版本过低

安装 Android SDK 中的固定版本：`sdkmanager 'cmake;3.22.1' 'cmake;3.31.6'`。
Gradle 使用 3.31.6 构建 tracer；直接调用 CMake 构建 tracer 时也应选择该版本。
3.22.1 供 fixture 和主机测试使用。

### 首次 CLI 构建超时

CLI 默认的 setup/build 时限为 90 秒，首次下载和编译 LLVM 可能超过该时限。
先运行 `./gradlew :app:assembleDebug :tracer:copyTracerDebug --no-daemon`，完成后再运行 CLI。
后续构建使用已有缓存；也可通过 `--setup-timeout SECONDS` 显式调整 CLI 时限。

### Frida 提示 `need Gadget to attach on jailed Android`

当前流程依赖早期 spawn 注入。请改用 root 设备与匹配版本的 `frida-server`，或嵌入并配置 Frida Gadget；普通 attach 无法捕获 constructor 阶段。

### `Module.load()` 无法加载 tracer

检查 `scripts/spawn_trace.js` 的 `remoteDir` 是否与部署目录一致、两份 `.so` 是否存在，以及 SELinux/linker namespace 是否允许映射。受限设备可参考[性能与基线复现](benchmarking.md#复现-benchmark)的 app-private staging 与应用 class loader 方案。

### 找不到 host `lz4`

若选中 QTRB `.trace.bin.lz4`，安装 LZ4 CLI；`--compressed-only` 只不发布文本，不能绕过解压后的版本、terminal 和 sidecar 校验。遗留 `.trace.txt.lz4` 可使用带 `--name` 的 `pull_trace.py --compressed-only` 原样保存；Flight Recorder 的 `.flight.bin` 本身不需要 LZ4。

### constructor 没有轨迹

确认使用 `frida -f` spawn，而不是 attach 到已运行进程；同时重新核对 `init` 偏移。初始化完成后无法补采此前事件。

### `run-as` 被拒绝

确认安装的是本仓库 debuggable APK，包名为 `com.aprz.qbdiandroid`。不要用 adb shell UID 直接读取 app-private 目录。

### Flight Recorder 有输出但标记为 incomplete

查看 `.flight.json` 中的 coverage gaps、damage、active chunks、线程生命周期和 retained sequence ranges。恢复出文本只说明存在可用提交记录，不代表窗口完整。
