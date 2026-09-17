# qbdi-android

`qbdi-android` 是一个面向 Android `arm64-v8a` 的 QBDI 注入式追踪演示项目。它展示如何在应用启动阶段通过 Frida 注入独立 tracer，使用 ShadowHook 接管 native 场景入口，再由 QBDI 动态执行并采集指令、寄存器与内存事件。

离线分析端见 [qtrace-ui](qtrace-ui/README.md)：它以 Tauri 桌面应用打开 QTRB/Flight 文件及 session report，并独立记录构建、测试、真值、缓存、打包和性能流程；下文采集 CLI 保持不变。

本仓库用于逆向分析、安全研究和插桩实验，不是通用 Android SDK，也不建议将示例 APK 或 tracer 直接用于生产环境。

```text
Frida spawn 注入 → ShadowHook 接管场景入口 → QBDI 执行与采集 → QTRB/LZ4 落盘 → 主机拉取、校验与转换
```

## 主要特性

- **完整注入链路**：Frida spawn 注入 `libqbdi_tracer.so`，ShadowHook 在目标库初始化前安装入口 hook，QBDI 接管指定 native 场景。
- **多类演示场景**：覆盖 native constructor、JNI、libc、计算逻辑、完整性检查和确定性 benchmark。
- **三级采集配置**：`fast` 记录指令与寄存器，`balanced` 增加内存访问元数据，`full` 再增加受限长度的内存前后快照。
- **紧凑二进制轨迹**：设备端写入 QTRB v1 事件流，支持异步双缓冲和 LZ4 分帧压缩；主机可转换为文本格式 4。
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

Frida 主机工具与设备端 server 应使用匹配版本。QTRB `.trace.bin.lz4` 始终需要主机 `lz4`，包括 `--compressed-only`。后者只抑制转换文本发布，仍会解压校验 QTRB 版本、terminal 和 sidecar。遗留 `.trace.txt.lz4` 与 Flight Recorder `.flight.bin` 使用 `--compressed-only` 可原样拉取，无需解压。

拉取由 Git LFS 管理的 QBDI 静态库：

```bash
git lfs pull
```

当前依赖包括 QBDI 0.12.1 Android AARCH64、vendored ByteDance ShadowHook、LZ4 1.10.0，
以及 vendored nlohmann/json 3.12.0。JSON 单头文件与许可证分别位于
`tracer/src/main/cpp/third_party/nlohmann/json.hpp` 和
`tracer/src/main/cpp/third_party/nlohmann/LICENSE.MIT`。

## qtrace 命令行

`python3 -m qtrace` 是一次性 app tracing 工作流。它需要 rooted（或对目标
app 可用 `run-as`）的 `arm64-v8a`、API 24+ 设备，ADB、匹配版本的 Frida
host/server、Android NDK（设置 `ANDROID_NDK_HOME` 或 `ANDROID_NDK_ROOT`）和
host `lz4`。外部应用的 APK 构建不在 qtrace 范围内；配置可选的 `app.apk`
只会安装那个已存在的 APK，绝不会构建它。

对任意外部包，先写严格 JSON 配置，再运行带时长的 session 或无限期 monitor。配置文件必须是
不超过 1 MiB 的 UTF-8 regular file；符号链接、special file、重复字段、非有限数字及过深 JSON
都会在任何设备操作前被拒绝：

```bash
python3 -m qtrace run --config target.json --duration 30s --device SERIAL --output results
python3 -m qtrace monitor --config target.json --device SERIAL --output results
```

配置中的 offset 是模块相对、半开区间 `[startOffset,endOffset)`；不接受 base
address。offset 与 symbol 两种严格形式如下（它们不能混用，也不能附加 `base`）：

```json
{"schemaVersion":1,"app":{"package":"com.example.app"},"target":{"module":"libtarget.so"},"tracer":{},"scenes":[{"name":"target","startOffset":"0x120","endOffset":"0x180"}]}
```

```json
{"schemaVersion":1,"app":{"package":"com.example.app"},"target":{"module":"libtarget.so"},"tracer":{},"scenes":[{"name":"target","symbol":"target_function"}]}
```

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

所有命令默认将报告和产物写入 `qtrace-output`；`--json` 只在 stdout 输出一个
机器结果对象，进度写 stderr。默认 setup/stop/单个 ADB/pull timeout 分别为
90/10/30/60 秒；每个 timeout 必须为有限正数，`run --duration` 必须介于
100 ms 和 24 h。

| Exit code | Meaning |
| ---: | --- |
| 0 | 完整成功 |
| 1 | 配置、设备、注入或命令错误 |
| 2 | 已发布部分可恢复产物 |
| 3 | 原生 stop 未完整封存 |
| 130 | 用户中断；orchestrator 已写 interrupted report |

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

## 手动设备发布门禁

下列验收是发布前的手动门禁，**不会**在普通 host CI 中自动运行。它需要明确
指定一台 rooted arm64 设备，以及可用的 ADB、匹配的 Frida host/server、NDK 和 host
`lz4`；脚本拒绝选择默认设备，并以有界的子进程和读操作执行。历史 benchmark 还固定
使用 Android NDK 26.1.10909125 和 build-tools 35.0.0；缺少固定版本工具、历史提交或离线
Gradle 依赖时会直接关闭门禁，不会退化成仅检查语义。

```bash
python3 scripts/qtrace_device_acceptance.py --device SERIAL
```

该门禁先构建并持有本次候选 APK、tracer 和 companion，再从提交
`2d6b1022a14ae554804a57e267544c12dea29353` 私有归档目标源码，以 `--offline` 在隔离目录
构建历史 APK。第一阶段安装历史 APK，并用同一份候选 tracer 执行 binary benchmark
`--compare`；第二阶段重新安装当前 APK、重新部署同一对 tracer/companion，等待最多 15 秒
的无追踪 timed oracle，再完成 timed offset/symbol 和四种手动 pull，最后验证 monitor-exit
与预期返回 2 的 flight-crash recovery。任一历史构建、身份或 benchmark 失败都属于发布门禁
失败，绝不会回退为仅检查语义。
全部验证和清理成功后，门禁才会将本轮目录原子发布到
`qtrace-acceptance-evidence/<uuid>`，写入一个不超过 64 KiB 的成功 manifest，并打印最终绝对
路径。manifest 绑定本次 HEAD、设备 serial、历史 commit/canonical SHA、当前 APK、tracer、
companion 哈希、八个场景 report、trace 备份路径和 gate 起止时间；任一 manifest、rename 或
目录 fsync 失败都会令门禁失败并保留等价诊断。失败证据保留在
`qtrace-acceptance-failures/<uuid>`。这两个目录均被 Git 忽略，脚本不会自动删除其中内容。

进入当前 fixture 场景前，门禁会先 force-stop 固定 demo 包，严格确认已有的
`files/qbdi-traces` 是真实目录而非 symlink，再将它原子重命名为同级且唯一的
`files/qbdi-traces.pre-acceptance-<uuid>`，随后创建并验证一个全新的 trace 目录，再部署和
运行本轮场景。这样 native status publisher 启动时已有可写根目录，四种 pull 也只验证本轮
fixture 数据；旧目录作为可恢复备份保留，成功或失败后都不会自动删除。该隔离只作用于固定
demo 包，不会访问用户指定的外部 package 路径。

Frida/GumJS adapter 的 host 测试是显式 opt-in；它要求可用的 Frida Python package 和
本机 attach 能力，不属于默认 Python 套件：

```bash
QTRACE_RUN_FRIDA_HOST_TESTS=1 \
  python3 -m unittest scripts.tests.test_spawn_trace_gumjs -v
```

构建契约属于显式集成套件。它会实际运行 Debug/Release manifest 合并、解析合并后的 manifest，并运行 Native Host Gradle/CTest 链；每次 Gradle 子进程有 300 秒 timeout：

```bash
ANDROID_HOME=/path/to/Android/sdk \
python3 -m unittest scripts.tests.build_contract_integration -v
```

JNI 状态的 ThreadSanitizer 回归是显式 opt-in，避免让环境敏感的 sanitizer 影响默认套件：

```bash
cmake -S tracer/src/test/cpp -B build/native-tests-tsan \
  -DQTRACE_ENABLE_TSAN=ON
cmake --build build/native-tests-tsan --target jni_state_tsan_test --parallel 2
ctest --test-dir build/native-tests-tsan -R jni_state_tsan_test --output-on-failure
```

该 opt-in 目标仅面向 Linux host，并通过 `setarch -R` 配合非 PIE 可执行文件固定 TSAN shadow-memory 布局。

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

## 配置 tracer

`scripts/spawn_trace.js` 顶部的 `config` 是普通交互追踪唯一需要人工维护的配置源。
`loader` 只供 Frida adapter 加载动态库；只有 `config.tracer` 会经
`JSON.stringify` 发送到 native tracer。完整形状如下：

```javascript
const config = {
  loader: {
    remoteDir: '/data/local/tmp/qbdi-android',
    tracer: 'libqbdi_tracer.so',
    shadowhookCompanion: 'libshadowhook_nothing.so'
  },

  tracer: {
    schemaVersion: 1,
    packageName: 'com.aprz.qbdiandroid',
    targetModule: 'libdemo_target.so',

    trace: {
      profile: 'fast',
      compression: true,
      lz4Level: 2,
      autoBuffer: true,
      bufferMb: 0,
      hexdumpLimit: 32
    },

    flight: {
      enabled: true,
      entryScene: 'init',
      capacityMb: 512,
      chunkKb: 256,
      maxThreads: 256,
      protectedChunks: 4
    },

    scenes: [
      {
        name: 'init',
        location: {
          offset: '0x6ac90',
          endOffset: '0x6ad00'
        }
      },
      {
        name: 'algorithm',
        location: {
          imageBase: '0x10000',
          address: '0x7db38',
          endAddress: '0x7dc00'
        }
      }
    ]
  }
};
```

场景位置只接受两种互斥形式：`offset`（可带 `endOffset`），或
`imageBase + address`（可带 `endAddress`）。所有地址必须是 `0x` 十六进制字符串，
不能写成 JSON number；native 会把后一种形式归一化为
`offset = address - imageBase`。所有 `endOffset`/`endAddress` 都是 exclusive end，
必须严格大于起始位置。没有范围时省略 end 字段。

Flight Recorder 启用时，`flight.entryScene` 必须精确命名 `scenes` 中的一项；数组顺序
不再隐含入口语义。若只需要普通单场景轨迹，在这个唯一配置中把 `flight.enabled`
设为 `false`。

tracer 不依赖运行时符号名。要确定本次构建的地址，打开：

```text
app/build/intermediates/merged_native_libs/debug/mergeDebugNativeLibs/out/lib/arm64-v8a/libdemo_target.so
```

在 IDA、Ghidra 或 `llvm-objdump` 中定位：

- `demo_init_stage`
- `demo_jni_case`
- `demo_libc_case`
- `demo_algorithm_case`
- `demo_integrity_case`

把相对偏移或 IDA/Ghidra image-base 地址写入 `scripts/spawn_trace.js` 的
`config.tracer.scenes`。详细步骤见 [IDA/objdump 偏移指南](docs/ida-offsets.md)。目标库布局
变化后必须重新核对，不能照搬其他 APK 的数值。

## 注入与采集

必须在目标库加载前执行 spawn 注入：

```bash
frida -U -f com.aprz.qbdiandroid -l scripts/spawn_trace.js
```

在 `session` 中提供 `durationMs` 即为 timed 采集，其控制链路的精确顺序是：

```text
Frida load/init -> resume -> Installed -> Frida detach
-> native deadline -> stop_requested -> per-thread seal
-> control-only real return
```

Frida 只负责启动期加载、配置和 hook 安装；`Installed` 发布后可以 detach，时限由目标进程内
每个 accepted generation 唯一的 native runtime 负责。deadline worker 只发布停止请求，不会
关闭 writer；已进入 QBDI 的目标线程会在观察到请求后各自 seal，再以 control-only 方式运行到
真实目标返回。阻塞在目标代码或系统调用中的线程可能延迟 acknowledgement，因此时长是停止请求
的 deadline，不是强制退出时刻。qtrace 不会为了满足时长而 kill App。

`session` 仅含 `id`、省略 `durationMs` 时即为 monitor 采集：它没有 native deadline，会持续
采集到 App 自行退出或用户结束 App；后续仍可用手动拉取命令读取 app-private 产物。strict
schema 不接受额外的 `mode` 字段。

脚本完成配置后，恢复应用并在界面选择 JNI、libc、algorithm、integrity 或 benchmark 场景。constructor、持久 `pthread_create` gateway 和 signal gateway 都需要在目标初始化前安装；attach 到已运行进程无法补回遗漏的开头。

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

### arm64 设备验收（opt-in）

部署上面的 Debug APK、tracer 和 companion 后，在一台 arm64 设备上执行四次 spawn：

1. 使用 `offset` locator。
2. 改成等价的 `imageBase + address` locator；确认 Frida status 中的 normalized offset 和
   runtime address 与第 1 次一致。
3. 使用可解释但映射可疑的地址；确认 warning 先出现，随后仍有真实 hook 结果。
4. 用下面的专用 harness 在同一进程依次提交 `config.tracer`、malformed JSON `{`，再查询
   第一次返回的 generation；确认输出包含相同 generation、
   `"rejectedCode": "MALFORMED_JSON"` 和 retained terminal/current state。

普通追踪以及第 1–3 项仍使用完全相同的注入命令：

```bash
frida -U -f com.aprz.qbdiandroid -l scripts/spawn_trace.js
```

第 4 项使用同一份 `spawn_trace.js` 配置的 opt-in Python/Frida harness，不复制 scene 配置：

```bash
python3 scripts/config_retention_acceptance.py \
  --package com.aprz.qbdiandroid
```

该 harness 需要 Frida Python package 和 USB device；它只用于验收，不是第二份普通配置源。
本仓库的当前 host 验证没有执行这条设备命令。

分别记录 Frida console 和 Logcat 中的 generation、warning/error code；两边应一致。完成运行后
拉取并验证产物：

```bash
python3 scripts/pull_trace.py --package com.aprz.qbdiandroid \
  --output pulled-traces
```

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

# 遗留 `.trace.txt.lz4` 可不依赖主机 lz4 原样拉取；用 --name 避免自动选中 QTRB。
python3 scripts/pull_trace.py --package com.aprz.qbdiandroid \
  --name <legacy-trace>.trace.txt.lz4 \
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

带 `--compare` 才是验收模式，而且必须安装由历史提交
`2d6b1022a14ae554804a57e267544c12dea29353` 构建的 APK。基线保留原始 target SHA-256
`5f1a970825ae8bacb17d8dd656e01bd1fe7172638ba3ddcacd82ffaaad6e62c0` 作为审计证据；跨工作树
准入使用 canonical SHA-256
`0d8e856c819fb3cd7ae5917053172b4b75a7924784c43e09cb2855a298647169`。canonical 内容由固定的
Android NDK 26.1.10909125 `llvm-objcopy --strip-debug --remove-section=.note.gnu.build-id`
去除调试信息与 build ID 后生成，运行时字节发生变化仍会导致拒绝。

工具会在预热前校验设备已安装的整个 `base.apk`、从中提取的唯一
`lib/arm64-v8a/libdemo_target.so`、canonical target 身份、本地候选与 app-private tracer
哈希，以及设备/系统身份和 SELinux。预热完成后立即核对 complete footer、事件数、返回值
及首尾指令，只有严格匹配才会进入恰好五次 measured runs。发布门禁始终传入
`--expected-installed-apk-sha256`，把已安装 APK 绑定到其持有的历史构建；直接手动运行
`benchmark_trace.py` 时可以省略该参数，便于诊断，但这不等同于发布验收。APK 重建可能
改变 scene offset、指令数或返回值，不能把这种漂移当作 tracer 性能变化，也不能据此改写
历史基线。没有 `--compare` 的运行仅用于诊断。

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

若选中 QTRB `.trace.bin.lz4`，安装 LZ4 CLI；`--compressed-only` 只不发布文本，不能绕过解压后的版本、terminal 和 sidecar 校验。遗留 `.trace.txt.lz4` 可使用带 `--name` 的 `pull_trace.py --compressed-only` 原样保存；Flight Recorder 的 `.flight.bin` 本身不需要 LZ4。

### constructor 没有轨迹

确认使用 `frida -f` spawn，而不是 attach 到已运行进程；同时重新核对 `init` 偏移。初始化完成后无法补采此前事件。

### `run-as` 被拒绝

确认安装的是本仓库 debuggable APK，包名为 `com.aprz.qbdiandroid`。不要用 adb shell UID 直接读取 app-private 目录。

### Flight Recorder 有输出但标记为 incomplete

查看 `.flight.json` 中的 coverage gaps、damage、active chunks、线程生命周期和 retained sequence ranges。恢复出文本只说明存在可用提交记录，不代表窗口完整。

## 深入文档

- [QTRB v1、文本格式 4、指标与崩溃恢复](docs/trace-format.md)
- [IDA/objdump 场景偏移定位](docs/ida-offsets.md)
- [完整性检查与 CodeRules](docs/integrity-bypass.md)
- [QTRB v1 性能与大小基线](docs/benchmarks/binary-trace-baseline.md)
- [追踪吞吐优化过程](docs/benchmarks/trace-throughput-baseline.md)
- [Flight Recorder 多线程崩溃验收](docs/benchmarks/flight-recorder-acceptance.md)

## License

见 [LICENSE](LICENSE)。第三方组件仍遵循各自许可证。
