# 可选运行时、JIT 与线程快照

[使用指南](usage.md) · [手动追踪](manual-tracing.md) · [syscall 证据](syscall-details.md)

`qtrace snapshot` 对已经加载当前 tracer 的存活进程执行一次主动诊断，保存运行时/JIT 映射、native 线程名称，以及可用的 Java 线程栈。它默认不随采集执行，也不在信号处理器中进入 ART/JNI。

## 公开入口

使用同一进程身份凭据中的 PID 和 starttime。starttime 是 `/proc/PID/stat` 第 22 字段的时钟 tick 字符串，解析时须先跳过带括号的 comm，不能直接按整行空格编号。

```bash
python3 -m qtrace snapshot --device SERIAL --pid PID --starttime STARTTIME \
  --output out/runtime-snapshot.json
```

输出必须是新文件，已有路径或 symlink 不会被替换。普通模式只向 stdout 打印文件路径，人读状态写 stderr。`--json` 的 stdout 是单个 `{snapshot,pid,starttime,exitCode}` 对象。`--no-java-stacks` 仅收集映射与 native 线程，Java 区段为 `disabled/not_requested`。

命令需要匹配的 Frida host/server 和目标访问权限。它只 attach 指定 PID、调用现有 `qbdi_tracer_snapshot_json` export，然后 unload/detach；不加载新 tracer、不配置场景、不 spawn 或重放目标。目标未加载 tracer、export 不存在、身份不符、采集或收尾失败时不发布成功文件。

`--timeout` 默认 10 秒，限制隔离的主机 worker。超时会回收该 worker；已经进入目标的 JNI 操作可能稍后完成，目标完成状态仍未确认。命令不重试，也不杀目标。一次请求期间的映射和线程可能变化，结果不是全进程原子暂停快照。

## 数据与固定上限

成功 JSON schema 1 绑定 `pid/starttime`，同时保存采集前后的 `startedMonotonicNs/finishedMonotonicNs`。每个区段都有 `status/reason/truncated/rows`，不可用不等于没有运行时或线程。

| 区段 | 内容与上限 |
| --- | --- |
| `mappings` | 最多 64 行、16 KiB 行 JSON 预算；每次扫描 maps 最多 1 MiB，共三次，依次优先保留 ART runtime、JIT、Java image。路径名匹配只产生 `*_name_match` 分类，不证明某段代码由哪个 Java 方法生成。 |
| `nativeThreads` | 最多 32 个实际 TID、comm 及读取状态；线程可能在读取时退出。没有原生 unwind 或寄存器转储。 |
| `java` | 有 VM 时枚举 ThreadGroup，最多 32 个 Java 线程，每线程最多 32 帧、24 KiB 区段预算；名称及帧文本最多 128 个 UTF-16 code unit，输出截断显式标记。Java id 与 native TID 分开，不推断对应关系。 |

`--max-threads`、`--max-frames` 可在 1..32 内减小上限。完整 native response 上限为 64 KiB，主机严格检查字段、身份、时间、状态及每层数量后才原子发布文件。Java API 在目标 VM 内的临时分配和运行耗时不由这些输出预算限制。

Java 操作只调用公共 Thread/ThreadGroup/StackTraceElement 方法；通过已有 VM 查询，必要时仅 attach 当前诊断线程，并只 detach 自己建立的 attachment。目标原有 pending exception 保留，此时 Java 区段为 `unavailable/preexisting_java_exception`；本次诊断产生的异常在返回前清理，libc errno 保留。没有 VM、JNI 访问失败、线程枚举失败等情况各自保留原因。

proc 名称中的无效 UTF-8 使用替换字符，Java 文本按 UTF-16 转换为 UTF-8。该文本策略不同于 syscall 的 `bytesHex` 原始字节保存；不要用快照展示文本验证文件名字节相等。

## 手动 native ABI

在普通线程调用以下 C ABI。不要在 signal handler 中调用，也不要按 buffer-too-small 自动重试诊断：

```cpp
int32_t qbdi_tracer_snapshot_json(const char *request, uint64_t request_size,
    char *response, uint64_t capacity, uint64_t *response_size) noexcept;
```

请求恰有六个字段，不接受未知字段或重复键：

```json
{"schema":1,"expectedPid":1234,"expectedStarttime":"123456","includeJava":true,"maxThreads":32,"maxFrames":32}
```

request 最多 1024 字节，response capacity 为 2..65536。返回码沿用 JSON ABI：0 成功、1 缓冲区不足、2 参数非法；`response_size` 在完成序列化后包含结尾 NUL。身份不符返回传输成功的 `{schema:1,ok:false,reason:"process_identity_mismatch"}`，不进行 Java/线程采集。公开 CLI 一次提供完整 buffer，不补发请求。

## 证据边界

独立 ART/JNI 夹具由 `scripts/build_jni_abi_probe.py` 构建，`scripts/jni_abi_acceptance.py` 核对真实 Java main 栈、运行时映射、原有 exception/errno/attachment、错误身份和传输预算。`scripts/build_runtime_probe.py` 另构建 `snapshot_native_probe`：将 tracer 和该可执行文件部署到自有临时目录，以 tracer 绝对路径作为唯一参数执行，可验证无 VM 时的结构化不可用、errno 和四种 signal disposition 保留。设备操作继续使用 canonical serial guard，并按 PID/starttime 清理自有进程。

快照辅助定位运行时与等待线程，不证明防护检测根因、故障指令、JIT 方法归属或远端上报。Java 栈可为空、截断或不可用；采到某个栈也不能据此判定该线程引发了先前信号。信号 PC 来源及 handler 返回应从各自的 Flight 记录判断。
