# qbdi-android

`qbdi-android` 是一个面向 Android `arm64-v8a` 的 QBDI 注入式追踪演示项目。它展示如何在应用启动阶段通过 Frida 注入独立 tracer，使用 ShadowHook 接管 native 场景入口，再由 QBDI 动态执行并采集指令、寄存器与内存事件。

本仓库用于逆向分析、安全研究和插桩实验，不是通用 Android SDK，也不建议将示例 APK 或 tracer 直接用于生产环境。

```text
Frida spawn 注入 → ShadowHook 接管场景入口 → QBDI 执行与采集 → QTRB/LZ4 落盘 → 主机拉取、校验与转换
```

## 主要特性

- **完整注入链路**：Frida spawn 注入 `libqbdi_tracer.so`，ShadowHook 在目标库初始化前安装入口 hook，QBDI 接管指定 native 场景。
- **多类演示场景**：覆盖 native constructor、JNI、libc、计算逻辑、完整性检查和确定性 benchmark。
- **三级采集配置**：`fast` 记录指令与寄存器，`balanced` 增加内存访问元数据，`full` 再增加受限长度的内存前后快照。
- **紧凑二进制轨迹**：设备端写入 QTRB v1 事件流，支持异步双缓冲和 LZ4 分帧压缩；主机可转换为文本格式 3。
- **持久 Flight Recorder**：使用固定容量的多线程环形文件保留崩溃前窗口，进程异常退出后仍可恢复已提交记录。
- **崩溃与信号语义**：支持 guest signal disposition 虚拟化、handler 区间记录及部分终止 syscall 解释；恢复报告会明确覆盖缺口和损坏范围。
- **完整性实验扩展**：通过原生 CodeRules 按模块偏移修改寄存器、参数、返回值、PC、标志位或内存。
- **可验证性能基线**：保留设备身份、产物哈希、每次运行数据和语义一致性检查，不以单次耗时作为结论。

## 适用范围与限制

- 仅构建 `arm64-v8a`，最低 Android API 24；示例当前使用 compile/target SDK 35。
- 需要 Android SDK、NDK、CMake 3.22.1、JDK 17 和 Git LFS。
- 需要可执行 spawn 注入的 Frida 环境。root 设备通常使用与主机版本匹配的 `frida-server`；jailed/non-root 设备通常需要 Frida Gadget。
- APK 的 release 变体明确设置为 `debuggable false`；实验所需的注入流程使用 debug 变体。
- 场景以 `module_base + offset` 定位，偏移与具体构建产物绑定；重新编译目标库后应重新确认。
- 默认 Flight Recorder 预分配 512 MiB 文件；开始实验前确认设备存储空间。
- `SIGKILL` 无法捕获。tracer 只能解释目标线程在执行终止 syscall 前写下的意图，外部 `SIGKILL` 不会产生虚构的发起者。

## 项目结构

```text
app/                         Kotlin 演示 APK 与 native 目标库
tracer/                      QBDI tracer、ShadowHook、QTRB 与 Flight Recorder
scripts/spawn_trace.js       可直接交给 Frida 的自包含注入脚本
scripts/trace_config.js      主机脚本共享配置
scripts/pull_trace.py        从 app-private 目录拉取、校验并转换轨迹
scripts/benchmark_trace.py   多进程 benchmark 与基线验收
docs/                        格式、偏移、完整性与性能证据
```

## 环境准备

确认以下命令可用：

```bash
adb version
frida --version
java -version
git lfs version
```

Frida 主机工具与设备端 server 应使用匹配版本。主机转换 `.trace.bin.lz4` 还需安装 `lz4`；没有该命令时可用 `--compressed-only` 只拉取原始产物。

拉取由 Git LFS 管理的 QBDI 静态库：

```bash
git lfs pull
```

当前依赖包括 QBDI 0.12.1 Android AARCH64、vendored ByteDance ShadowHook，以及 LZ4 1.10.0。

## 构建

构建演示 APK，并把 standalone tracer 与 ShadowHook companion 复制到 `out/arm64-v8a/`：

```bash
./gradlew :app:assembleDebug
./gradlew :tracer:assembleDebug :tracer:copyTracerDebug
```

主要产物：

```text
app/build/outputs/apk/debug/app-debug.apk
out/arm64-v8a/libqbdi_tracer.so
out/arm64-v8a/libshadowhook_nothing.so
```

## 主机端原生验证

在已设置 `ANDROID_HOME` 且 Android SDK 安装了 CMake 3.22.1 的主机上运行：

```bash
./gradlew nativeHostTest --no-daemon
```

该任务依次配置、构建并通过 CTest 运行 `tracer/src/test/cpp` 的原生测试；它不依赖 Android JVM 单元测试任务。

普通 Python 单元测试不启动 Gradle，也不要求完整 Android SDK：

```bash
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
```

构建契约属于显式集成套件。它会实际运行 Debug/Release manifest 合并、解析合并后的 manifest，并运行 Native Host Gradle/CTest 链；每次 Gradle 子进程有 300 秒 timeout：

```bash
ANDROID_HOME=/path/to/Android/sdk \
python3 -m unittest scripts.tests.build_contract_integration -v
```

## 安装与部署

安装 APK，并把 tracer 与 companion 放到 `spawn_trace.js` 默认读取的目录：

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell mkdir -p /data/local/tmp/qbdi-android
adb push out/arm64-v8a/libshadowhook_nothing.so /data/local/tmp/qbdi-android/
adb push out/arm64-v8a/libqbdi_tracer.so /data/local/tmp/qbdi-android/
```

`libshadowhook_nothing.so` 不由 Frida 主动加载；tracer 在 ShadowHook 初始化前只把它的绝对路径配置为 linker companion。两份文件必须同时部署。

若设备的 SELinux/linker namespace 不允许应用从 `/data/local/tmp` 映射 tracer，可参考下文 benchmark 流程，将 tracer 暂存到 debuggable 应用私有目录并通过应用 class loader 加载。

## 配置场景偏移

tracer 不依赖运行时符号名，而是使用目标模块相对偏移。打开本次构建生成的：

```text
app/build/intermediates/merged_native_libs/debug/mergeDebugNativeLibs/out/lib/arm64-v8a/libdemo_target.so
```

在 IDA、Ghidra 或 `llvm-objdump` 中定位：

- `demo_init_stage`
- `demo_jni_case`
- `demo_libc_case`
- `demo_algorithm_case`
- `demo_integrity_case`

将相对偏移同步写入 `scripts/trace_config.js` 和 `scripts/spawn_trace.js` 内嵌的 `config.scenes`。详细步骤见 [IDA/objdump 偏移指南](docs/ida-offsets.md)。目标库布局变化后必须重新核对，不能照搬其他 APK 的数值。

## 注入与采集

必须在目标库加载前执行 spawn 注入：

```bash
frida -U -f com.aprz.qbdiandroid -l scripts/spawn_trace.js
```

脚本完成配置后，恢复应用并在界面选择 JNI、libc、algorithm、integrity 或 benchmark 场景。constructor、持久 `pthread_create` gateway 和 signal gateway 都需要在目标初始化前安装；attach 到已运行进程无法补回遗漏的开头。

默认启用 Flight Recorder：

```javascript
flight: {
  enabled: true,
  capacityMb: 512,
  chunkKb: 256,
  maxThreads: 256,
  protectedChunks: 4
}
```

若只需要普通单场景轨迹，可在两份配置中关闭 `flight`。普通轨迹默认使用 `fast` profile 和 LZ4 压缩。

## 采集配置

| Profile | 指令与寄存器 | 内存访问元数据 | 内存前后字节 | 适用场景 |
| --- | --- | --- | --- | --- |
| `fast` | 是 | 否 | 否 | 大范围指令流、优先吞吐 |
| `balanced` | 是 | 是 | 否 | 分析读写地址、大小和类型 |
| `full` | 是 | 是 | 是，单侧最多 64 B | 深入检查内存状态与崩溃上下文 |

三种配置都不会主动采样、丢弃或重排事件。两个异步缓冲区同时繁忙时，生产者会等待，并在 metrics 中记录 backpressure。

Flight Recorder 始终按 full 语义采集目标模块内的指令、内存和 GPR，不受普通 trace profile 影响。完整字段、容量计算和兼容规则见 [QTRB 与文本格式说明](docs/trace-format.md)。

## Pull Traces

普通轨迹和 Flight Recorder 产物都写入 debuggable 应用的 app-private 目录：

```text
/data/data/com.aprz.qbdiandroid/files/qbdi-traces/
```

使用 `adb exec-out run-as` 拉取最新产物。指定 `--device` 可选择设备：

```bash
python3 scripts/pull_trace.py --package com.aprz.qbdiandroid \
  --device 192.168.51.42:5555 --output pulled-traces
```

常用操作：

```bash
# 指定设备列表中的某个产物。
python3 scripts/pull_trace.py --package com.aprz.qbdiandroid \
  --name <trace-file>.flight.bin --output pulled-traces

# 不依赖主机 lz4，只拉取压缩产物与 sidecar。
python3 scripts/pull_trace.py --package com.aprz.qbdiandroid \
  --compressed-only --output pulled-traces

# 明确允许替换已有本地输出。
python3 scripts/pull_trace.py --package com.aprz.qbdiandroid \
  --force --output pulled-traces

# 手动把 QTRB/LZ4 转成文本格式 3。
python3 scripts/trace_convert.py input.trace.bin.lz4 --output output.trace.txt
```

完整的 QTRB 产物带有 `metrics_version=2` sidecar。工具会校验容器、footer、指标和指令序列，再原子发布文本；默认拒绝覆盖已有文件。

对于 `.flight.bin`，正常拉取会保留原文件，并生成：

- `<basename>.merged.trace.txt`：按进程全局序列合并；
- `<basename>.tid-<tid>.trace.txt`：每个被恢复线程一份；
- `<basename>.flight.json`：完整性、终止候选、信号、保留/覆盖范围、coverage gaps 和损坏摘要。

判断崩溃窗口是否完整时，以 `.flight.json` 为准。缺少 terminal marker 代表终止原因未知，不等同于损坏；coverage gap、torn/invalid chunk、仍活跃 chunk 或未闭合线程生命周期会使结果不完整。

## 性能

以下数字来自已提交的 [QTRB v1 二进制格式验收基线](docs/benchmarks/binary-trace-baseline.md)：Pixel 6（oriole）、Android 16、`arm64-v8a`、Debug APK、SELinux Enforcing；固定 benchmark 执行 256 次迭代并产生 21,718 条指令。每种 profile 先预热一次，再启动五个独立新进程测量，下表取中位数。

| Profile | 中位耗时 | 指令吞吐 | 编码字节 | 压缩后大小 |
| --- | ---: | ---: | ---: | ---: |
| `fast` | 16 ms | 1,357,375 条/秒 | 1,096,964 B | 267,939 B |
| `balanced` | 24 ms | 904,916.67 条/秒 | 1,566,635 B | 362,559 B |
| `full` | 36 ms | 603,277.78 条/秒 | 1,672,811 B | 379,982 B |

这些数据是特定设备、构建和工作负载下的实测结果，不是所有设备的性能保证。`elapsed_ms` 在被追踪目标执行与生产者回调结束时停止计时，不包含写入器最终排空、footer/sidecar 发布、ADB 拉取和主机转换，因此表示追踪热路径吞吐，不是端到端完成时间。

### 复现 benchmark

benchmark agent 通过应用 class loader 加载 app-private tracer，使它共享应用 linker namespace，并可在 SELinux Enforcing 下执行。先部署本次候选产物：

```bash
adb push out/arm64-v8a/libqbdi_tracer.so /data/local/tmp/qbdi-tracer-stage.so
adb shell run-as com.aprz.qbdiandroid cp \
  /data/local/tmp/qbdi-tracer-stage.so files/libqbdi_tracer.so
adb shell run-as com.aprz.qbdiandroid chmod 700 files/libqbdi_tracer.so
```

运行五次独立进程并与已提交基线比较：

```bash
python3 scripts/benchmark_trace.py --package com.aprz.qbdiandroid \
  --device <adb-serial> --profile balanced --runs 5 \
  --candidate-tracer out/arm64-v8a/libqbdi_tracer.so \
  --compare docs/benchmarks/binary-trace-baseline.md
```

带 `--compare` 才是验收模式：工具会额外预热，并检查设备/系统身份、SELinux、候选与 app-private tracer 哈希、事件数、返回值及首尾指令。没有 `--compare` 的运行仅用于诊断。

Flight Recorder 的多线程崩溃压力结果见 [Flight Recorder 验收报告](docs/benchmarks/flight-recorder-acceptance.md)。

## 完整性检查与 CodeRules

integrity 场景包含 `.text` hash 校验和 `/proc/self/maps` 检查。运行时绕过逻辑应放在 `tracer/src/main/cpp/rules/user_code_rules.cpp`，由 CodeRules 按目标模块偏移匹配；JavaScript 配置只负责场景位置。

具体机制见 [完整性检查与 CodeRules](docs/integrity-bypass.md)。

## 常见问题

### Frida 提示 `need Gadget to attach on jailed Android`

当前流程依赖早期 spawn 注入。请改用 root 设备与匹配版本的 `frida-server`，或嵌入并配置 Frida Gadget；普通 attach 无法捕获 constructor 阶段。

### `Module.load()` 无法加载 tracer

检查 `scripts/spawn_trace.js` 的 `remoteDir` 是否与部署目录一致、两份 `.so` 是否存在，以及 SELinux/linker namespace 是否允许映射。受限设备可参考 benchmark 的 app-private staging 与应用 class loader 方案。

### 找不到 host `lz4`

安装 LZ4 CLI，或先使用 `pull_trace.py --compressed-only` 保存原始产物。Flight Recorder 的 `.flight.bin` 本身不需要 LZ4。

### constructor 没有轨迹

确认使用 `frida -f` spawn，而不是 attach 到已运行进程；同时重新核对 `init` 偏移。初始化完成后无法补采此前事件。

### `run-as` 被拒绝

确认安装的是本仓库 debuggable APK，包名为 `com.aprz.qbdiandroid`。不要用 adb shell UID 直接读取 app-private 目录。

### Flight Recorder 有输出但标记为 incomplete

查看 `.flight.json` 中的 coverage gaps、damage、active chunks、线程生命周期和 retained sequence ranges。恢复出文本只说明存在可用提交记录，不代表窗口完整。

## 深入文档

- [QTRB v1、文本格式 3、指标与崩溃恢复](docs/trace-format.md)
- [IDA/objdump 场景偏移定位](docs/ida-offsets.md)
- [完整性检查与 CodeRules](docs/integrity-bypass.md)
- [QTRB v1 性能与大小基线](docs/benchmarks/binary-trace-baseline.md)
- [追踪吞吐优化过程](docs/benchmarks/trace-throughput-baseline.md)
- [Flight Recorder 多线程崩溃验收](docs/benchmarks/flight-recorder-acceptance.md)

## License

见 [LICENSE](LICENSE)。第三方组件仍遵循各自许可证。
