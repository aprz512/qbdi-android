# 性能与基线复现

[项目首页](../README.md) · [文档目录](README.md)

本文保留历史性能摘要及复现条件。构建与完整设备发布门禁见[开发指南](development.md#手动设备发布门禁)。
分析器的主机性能流程见[qtrace-ui 开发指南](../qtrace-ui/docs/development.md#performance-reproduction)。

## 历史设备基线

以下数字来自已提交的 [QTRB v1 二进制格式验收基线](benchmarks/binary-trace-baseline.md)：Pixel 6（oriole）、Android 16、`arm64-v8a`、Debug APK、SELinux Enforcing；固定 benchmark 执行 256 次迭代并产生 21,718 条指令。每种 profile 先预热一次，再启动五个独立新进程测量，下表取中位数。

| Profile | 中位耗时 | 指令吞吐 | 编码字节 | 压缩后大小 |
| --- | ---: | ---: | ---: | ---: |
| `fast` | 16 ms | 1,357,375 条/秒 | 1,096,964 B | 267,939 B |
| `balanced` | 24 ms | 904,916.67 条/秒 | 1,566,635 B | 362,559 B |
| `full` | 36 ms | 603,277.78 条/秒 | 1,672,811 B | 379,982 B |

这些数据是特定设备、构建和工作负载下的实测结果，不是所有设备的性能保证。`elapsed_ms` 在被追踪目标执行与生产者回调结束时停止计时，不包含写入器最终排空、footer/sidecar 发布、ADB 拉取和主机转换，因此表示追踪热路径吞吐，不是端到端完成时间。

## 复现 benchmark

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
  --device SERIAL --profile balanced --runs 5 \
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

Flight Recorder 的多线程崩溃压力结果见 [Flight Recorder 验收报告](benchmarks/flight-recorder-acceptance.md)。
