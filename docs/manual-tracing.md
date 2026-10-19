# 手动 Frida 追踪

[项目首页](../README.md) · [文档目录](README.md)

本文面向直接编辑 `scripts/spawn_trace.js` 的调试流程。自动构建、部署、采集与拉取见[使用指南](usage.md)。
这两种入口使用不同配置格式；CLI `target.json` 由主机解析，本文的 `config.tracer` 直接发送给 native tracer。
所有命令从仓库根目录执行。

## 构建

先完成[环境准备](usage.md#环境要求)，再构建 Debug APK、standalone tracer 和 companion：

```bash
./gradlew :app:assembleDebug
./gradlew :tracer:assembleDebug :tracer:copyTracerDebug
```

产物路径及主机验证见[开发指南](development.md)。

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

`session` 仅含 `id`、省略 `durationMs` 时即为 monitor 采集：它没有 native deadline，会持续
采集到 App 自行退出或用户结束 App；后续仍可用手动拉取命令读取 app-private 产物。strict
schema 不接受额外的 `mode` 字段。

脚本完成配置后，恢复应用并在界面选择 JNI、libc、algorithm、integrity 或 benchmark 场景。constructor、持久 `pthread_create` gateway 和 signal gateway 都需要在目标初始化前安装；attach 到已运行进程无法补回遗漏的开头。

## 拉取与排障

```bash
python3 scripts/pull_trace.py --package com.aprz.qbdiandroid \
  --output pulled-traces
```

完整的拉取、转换、兼容矩阵与恢复语义见[使用指南](usage.md#pull-traces)。
常见加载、constructor、LZ4 和 `run-as` 问题见[排障](usage.md#常见问题)。
手动 locator 等价性与配置保留验收见[开发指南](development.md#配置与-hook-设备验收opt-in)。
