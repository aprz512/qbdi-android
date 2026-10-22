# 手动 Frida 追踪

[项目首页](../README.md) · [文档目录](README.md)

本文面向直接编辑 `scripts/spawn_trace.js` 的调试流程。自动构建、部署、采集与拉取见[使用指南](usage.md)。
这两种入口使用不同配置格式；CLI `target.json` 由主机解析，本文的 `config.tracer` 直接发送给 native tracer。
所有命令从仓库根目录执行。

字段对照与同一 Python 环境的检查见[配置接口与前置诊断](usage.md#配置接口与前置诊断)。
`NATIVE_CONFIG_REJECTED` 或手动 `tracer config rejected` 时，先按响应的 `error.path` 修正下面的完整 native 配置；
不要用 CLI `target.json` 替换 `config.tracer`。独立的基线、calls + Flight 与窄场景返回示例见[逐步采集](narrow-capture.md)。

开始复杂目标采集前，先用[独立 JNI/arm64 夹具](jni-abi-acceptance.md)验收本次 tracer 字节。
手动入口由调用者在准入退出码为 0 后继续；CLI 可使用 `--abi-report` 在注入前强制核对。

## 构建

先完成[环境准备](usage.md#环境要求)，再构建 Debug APK、standalone tracer 和 companion：

```bash
git submodule update --init --recursive
./gradlew :app:assembleDebug
./gradlew :tracer:assembleDebug :tracer:copyTracerDebug
```

QBDI 由 submodule 源码构建；首次编译会下载并编译 LLVM 等依赖。tracer 使用 CMake
3.31.6，fixture 使用 3.22.1。版本同步与升级见[QBDI 源码依赖](development.md#qbdi-源码依赖)，
产物路径及主机验证见[开发指南](development.md)。

## 通用手动加载与部署

`copyTracerDebug` 同时生成 `out/arm64-v8a/build-identity.json`，关联源码 revision、本地差异、构建配置和两个 SO 的 SHA-256。可以先独立核验：

```bash
python3 -m qtrace inspect-payload \
  --library out/arm64-v8a/libqbdi_tracer.so \
  --companion out/arm64-v8a/libshadowhook_nothing.so --json
```

为已有 native 加载入口部署现成 payload 和 native JSON，可使用：

```bash
python3 -m qtrace deploy --device SERIAL --package com.example.app \
  --library out/arm64-v8a/libqbdi_tracer.so \
  --companion out/arm64-v8a/libshadowhook_nothing.so \
  --config native-config.json --abi-report abi-results/current/report.json \
  --output deploy-receipts/run-20261022.json
```

该命令复用 app-private 部署、哈希核对和 staging 收尾，不启动 Frida 或应用业务。`--config` 接收已有 native JSON，不接受 CLI 的 `target.json`。除为本次部署生成新的 `session.id` 外保留配置内容；配置省略 `session` 时自动补入该对象。原主机配置文件不变，回执同时记录源与部署配置 SHA。native 配置的最终合法性仍由 configure 接口确认。

回执和远端 session 目录默认拒绝覆盖。部署命令会核对实际设备上的 payload/config SHA；`--abi-report` 复用现有设备、系统和 SO 身份门禁。不传报告不表示已通过 ABI 准入。

`loaded_payload_status: "unknown"` 表示尚未证明目标进程实际加载这些字节。后续手动加载应使用回执中的路径，并另保留实际 PID/starttime 与加载身份；设备部署成功不能代替进程内证据。只有 SO 哈希与构建身份匹配时才回显记录的源码来源；旧 payload 没有侧车时来源保持未知。

当前候选的设备准入、独立部署与拒绝路径记录见[设备补验](benchmarks/flight-device-2026-10-22.md)。报告只适用于其中匹配的 SO、companion 和设备系统。

## 安装与部署

安装 APK，并把 tracer 与 companion 放到 `spawn_trace.js` 默认读取的目录：

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell mkdir -p /data/local/tmp/qbdi-android
adb push out/arm64-v8a/libshadowhook_nothing.so /data/local/tmp/qbdi-android/
adb push out/arm64-v8a/libqbdi_tracer.so /data/local/tmp/qbdi-android/
```

`libshadowhook_nothing.so` 不由 Frida 主动加载；tracer 在 ShadowHook 初始化前只把它的绝对路径配置为 linker companion。两份文件必须同时部署。

若设备的 SELinux/linker namespace 不允许应用从 `/data/local/tmp` 映射 tracer，可参考[性能与基线复现](benchmarking.md#复现-benchmark)，将 tracer 暂存到 debuggable 应用私有目录并通过应用 class loader 加载。

## 配置 tracer

`scripts/spawn_trace.js` 顶部的 `config` 是手动 Frida 追踪需要维护的配置源。
`loader` 只供 Frida adapter 加载动态库；只有 `config.tracer` 会经
`JSON.stringify` 发送到 native tracer。下面展示完整结构；场景地址仅为示例，必须按本次目标构建重新定位：

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

需要保留持久 flight、但只跟踪显式场景时，可设置 `flight.followThreads: false`。
此可选布尔值默认 `true`，保留自动 pthread 跟踪；`false` 时不为新线程自动记录生命周期或
分配 flight 线程槽，场景 Hook 仍正常进入采集。大量模块外线程会占用 `maxThreads` 时，
可用此选项为稍后命中的目标函数保留槽位；它不补录场景入口之前的线程活动。

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
`config.tracer.scenes`。详细步骤见 [IDA/objdump 偏移指南](ida-offsets.md)。目标库布局
变化后必须重新核对，不能照搬其他 APK 的数值。

采集档位见[使用指南](usage.md#采集配置)。配置状态、稳定错误码及 JSON ABI 见[架构与设计](architecture.md#配置与安装状态)。

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

场景和 pthread gateway 的目标调用使用当前 pthread 的真实栈，QBDI 引擎移到独立的 16 MiB 栈。
实现复用固定版本 QBDI 的 `switchStack`，与其[官方 stack-switch 调用语义](https://qbdi.readthedocs.io/en/stable/api_cpp.html)一致；目标调用、停止和 control-only continuation 全部在同一次栈切换内结束，之后才释放引擎栈。目标 SP 只在该调用寿命内有效，不能跨调用复用。原有 signal probe 的独立栈不因此改写。

小米 API36 的 JNI 对照先在堆目标栈上触发 `StackOverflowError`；真实栈实现后，
`ActivityManager$RunningServiceInfo` 与 `java/util/List` 查询成功，目标 SP 位于暂停时记录的主线程 stack mapping 内。
四组 runner/session/coordinator 生命周期回归通过。该结果验证了已附加主线程的 JNI 路径，未代替其它线程及完整应用业务验收。

Android arm64 的新 VM 还会从同一个 pthread 保留 `x18`，遵循 Android 的
[平台保留寄存器约定](https://developer.android.com/ndk/guides/abis#arm64-v8a)。
只初始化参数寄存器会让 VM 中的 `x18` 变为零，即使目标使用真实线程栈，JNI 回调仍可能失败。
Pixel 6 的独立夹具先复现原值非零、traced 值为零；修复后两个实际 Guest actor 的值一致，
`Integer.parseInt("42")` 的基线与 traced 回调均返回 42，且没有 pending exception。
这项结果不替代具体业务的 JNI 场景回归。当前通用进程边界夹具另行验证了合法 `vfork` 的父进程与原生子进程执行，见[通用优化验收](benchmarks/qbdi-generic-2026-10-21.md)。

native JSON 可在 `trace` 中增加 `events: "calls"`，用于保留调用与目标 `svc` 入口摘要，关闭指令和 memory 采集；默认仍为 `all`。
需要有界路径与返回证据时，另设 `trace.syscallDetails: true`；要求 calls、CodeRules 关闭，默认关闭，支持 Flight/QTRB。最多快照两个路径，返回缺失保持未知；完整含义和配对示例见[syscall 说明](syscall-details.md)。主动运行时/JIT 与 Java 线程栈诊断使用独立的 [snapshot 入口](runtime-snapshot.md)，不在信号回调中执行。
各 profile、场景返回状态和离线预算见[使用指南](usage.md#场景状态与有界离线查询)。
对 libc `exec*` 和 `exit/_Exit/_exit` 转移，采集先封口再执行原调用；exec 失败后的续跑不重新执行已经开始的目标。
合法 `vfork` 的子分支直接在原生调用点继续至 exec 或 `_exit`，不进入共享 QBDI 引擎；父分支继续采集。
子分支的指令不属于采集覆盖范围。原始 clone/vfork 系统调用、自定义 libc、未覆盖调用点和非法的子分支返回不能由这组结果外推。

`session` 仅含 `id`、省略 `durationMs` 时即为 monitor 采集：它没有 native deadline，会持续
采集到 App 自行退出或用户结束 App；后续仍可用手动拉取命令读取 app-private 产物。strict
schema 不接受额外的 `mode` 字段。

脚本完成配置后，恢复应用并在界面选择 JNI、libc、algorithm、integrity 或 benchmark 场景。constructor、持久 `pthread_create` gateway 和 signal gateway 都需要在目标初始化前安装；attach 到已运行进程无法补回遗漏的开头。

信号观察、信号实际交付、handler 返回与进程终止分别判断。新 Flight producer policy 允许恢复 `pc_source`：`qbdi_logical`、`kernel_ucontext`、`guest_handler_context`，缺失或不支持的 policy 为 `unknown`；[格式说明](trace-format.md#scene-and-signal-evidence)列出规则。PC 来源不证明故障根因。不要为了补充诊断而全局安装 `Process.setExceptionHandler`；它可能接管 ART 正常隐式异常。
外部手工 daemon 启动超时后，先核对原 PID/starttime 和端点；连接超时本身不能证明启动失败，也不应触发自动重放。

## 拉取与排障

```bash
python3 scripts/pull_trace.py --package com.aprz.qbdiandroid \
  --output pulled-traces
```

完整的拉取、转换、兼容矩阵与恢复语义见[使用指南](usage.md#pull-traces)。
常见加载、constructor、LZ4 和 `run-as` 问题见[排障](usage.md#常见问题)。
手动 locator 等价性与配置保留验收见[开发指南](development.md#配置与-hook-设备验收opt-in)。
