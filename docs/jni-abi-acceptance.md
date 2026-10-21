# JNI 参数与 arm64 ABI 准入

[文档目录](README.md) · [开发与验证](development.md) · [设备验收记录](benchmarks/jni-abi-2026-10-21.md)

准入先在独立 ART 进程中比较同输入的原生基线和 traced 结果，再决定是否开始目标采集。
夹具通过 `app_process` 加载自己的 DEX 和 native 库，不需要安装 APK。
目前设备夹具要求 root、API28+、`arm64-v8a` 和物理 Android 用户 0。
其他环境返回 `unavailable`，不能把 Host 测试当作设备准入。

## 解码行为

JNI 普通调用按 AAPCS64 分别读取 `x0–x7`、`v0–v7` 和共享栈参数区；`x8` 不作为第九个参数。
V 调用读取调用时的 32 字节 `va_list` 副本，按 GP/FP 保存区和栈游标解码，不消耗目标的 `va_list`。
A 调用按 8 字节 `jvalue` 数组及方法签名解码。普通/V 调用处理 C 的默认参数提升，A 调用保留 `jfloat` 的直接表示。
实现依据 [AAPCS64](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst) 和
[JNI 方法调用合同](https://docs.oracle.com/en/java/javase/26/docs/specs/jni/functions.html)。

固定 JNI 参数也按独立的 GP/FP 游标读取；`SetFloatField` / `SetStaticFloatField` 的值是直接传入的 float32，
`SetDoubleField` / `SetStaticDoubleField` 的值是 double64，不适用可变参数的默认提升。
整数文本遵循 JNI 位宽与符号；固定及 Java 方法的浮点参数和 JNI 浮点返回值使用浮点寄存器的位表示。
数组以不透明引用地址显示；夹具另由 Java 核对 `byte[]` 内容，tracer 不为展示数组调用 JNI。
方法签名缺失、签名不合法、寄存器上下文缺失或参数存储不可读时，Java 参数展开输出 `<undecoded: 原因>`，不输出部分参数列表。
JNI enter 快照归各自的 pending transfer 所有，嵌套调用不会覆盖外层快照。

## 构建与运行

先按[开发指南](development.md#构建)构建待验收 tracer 与 companion，并保留其原始字节。
构建设备夹具：

```bash
python3 scripts/build_jni_abi_probe.py \
  --ndk "$ANDROID_NDK_HOME" --sdk "$ANDROID_HOME"
```

使用现有 adb server，并将 `QTRACE_DEVICE_GUARD_ROOT` 指向本机正在使用的 canonical guard 目录。
guard 必须与其他设备工具共用，不能为本轮另选目录绕过已有占用。
脚本按同一 server/serial 键获取非阻塞 guard，存在占用或未完成收尾的责任标记时拒绝执行。
它不启动、重启或切换 adb server。

```bash
python3 scripts/jni_abi_acceptance.py \
  --serial SERIAL \
  --adb "$ANDROID_HOME/platform-tools/adb" \
  --guard-root "$QTRACE_DEVICE_GUARD_ROOT" \
  --tracer out/arm64-v8a/libqbdi_tracer.so \
  --companion out/arm64-v8a/libshadowhook_nothing.so \
  --output abi-results/current
```

输出目录必须尚不存在。每轮使用唯一进程、部署目录和 trace 目录，校验部署文件 SHA-256。
完成后拉取原始 QTRB、metrics、状态和 Java 观测，再确认 PID/epoch 终态并删除本轮设备文件。
ADB 查询失败不视为进程消失；无法确认取消或清理时保留 canonical guard 的责任标记，报告 `unavailable`。
先按标记核实原进程和收尾责任，再安排后续设备操作。

## 验收范围与报告

`report.json` 的 `result` 为 `pass`、`fail` 或 `unavailable`，仅 `pass` 返回退出码 0。
报告包含设备 serial、ABI、SDK、系统 fingerprint、tracer/companion/夹具/DEX SHA、配置、PID/epoch 和收尾结果。
夹具构建还生成 `build-identity.json`，记录 Java/C++ 源码 SHA；驱动核对其产物哈希后将身份写入报告。
保留 `stdout.txt`、`stderr.txt`、`traces.tar` 及严格转换后的 trace，供独立复核。

同输入在普通/V/A 三种模式下各执行九种场景：两个正负 int 与 `byte[]`、int 极值、
long/double/float 与整数混合、窄整数与 char、预期 Java 异常、固定浮点字段、构造器、实例方法和 nonvirtual 方法。
字段场景在三种模式下重复执行四种固定 setter/getter，其余调用分别使用相应的普通/V/A 形式。
每次字段场景前在未采集的 Java 设置路径中清零全部字段，确保基线和 traced 的 setter 都必须重新写入目标值。
实例方法返回 43、nonvirtual 基类方法返回 42，独立核对分派行为。
混合用例同时耗尽 GP 和 FP 参数寄存器，并跨入栈参数区。
Java 实收值、native 返回值和异常状态分别核对，不能只比较两轮彼此相等。
另核对同 pthread 的 x18、真实线程栈边界、原生线程 attach/callback，以及 JNI enter/leave 和浮点返回文本。
全部 30 份轨迹须有有效的真实返回 terminal、匹配 metrics，且无活跃 scene 或原生错误。
14 项必要检查包含固定浮点参数与返回值文本；缺少这些检查的历史报告须重新验收。

该夹具验证独立 ART 进程的 ABI 与 JNI 观测行为。它不证明任意应用、其他设备、所有 JVM 回调或完整业务路径均通过。
嵌套快照与未知转移的配对另有 Host 回归；设备矩阵中的构造器、实例和 nonvirtual 用例均有真实 Java 对照。

## 采集前强制使用报告

为需要准入保护的 `run` 或 `monitor` 显式传入报告：

```bash
python3 -m qtrace run --config target.json --duration 30s \
  --device SERIAL --abi-report abi-results/current/report.json
```

在目标配置中显式选择已验收的 `tracer.library` 和 `tracer.companion`。
CLI 在部署前检查报告已通过、全部必要检查为真、收尾完成、设备身份未改变、两个库的 SHA 完全相同。
部署后再核对实际部署哈希，才允许注入。失败返回 `tracer.abi_rejected`，不会启动目标注入。
会话报告记录准入报告 SHA 和验收 session，便于回查。

旧命令和 native 配置保持兼容。未传 `--abi-report` 时不会自动执行夹具或推断准入成功。
手动及 native API 调用方应先检查准入脚本退出码，再执行采集；本次未增加 native 配置字段。
更换 tracer、companion、设备或系统构建后重新验收，不能把旧报告的 SHA 当作新产物的证据。
