# 可选 syscall 路径与返回证据

[使用指南](usage.md) · [窄场景采集](narrow-capture.md) · [验收记录](benchmarks/qtrace-syscall-2026-10-22.md)

`syscallDetails` 为目标模块内实际采集到的 arm64 SVC 增加调用身份、有界路径快照和返回观察。默认关闭，支持 calls 的 Flight 与普通 QTRB；不修改目标寄存器、路径内存或 libc errno。它只覆盖 tracer 已进入的目标指令，不是整个进程的 syscall 审计。

## 配置

在已有的有效 CLI 配置中替换 `tracer` 部分；保留实际包名、模块和场景：

```json
{
  "events": "calls",
  "syscallDetails": true,
  "flightEnabled": true,
  "flightEntryScene": "entry"
}
```

`entry` 必须是已有场景的名称。使用[完整 CLI 配置](usage.md#qtrace-命令行)时，将此对象放到 `tracer` 字段，而不是作为完整配置文件。
要求 `tracer.events: "calls"`、CodeRules 关闭；不满足时在设备操作前拒绝。省略选项或设为 `false` 保留旧入口 detail。普通 QTRB 使用 `{"events":"calls","syscallDetails":true}`；省略两个 Flight 字段。

手动 native JSON 对应 `trace.syscallDetails: true`、`trace.events: "calls"`。使用 Flight 时仍需 `flight.enabled: true` 和有效的 `flight.entryScene`。完整结构见[手动追踪](manual-tracing.md#配置-tracer)。CLI 字段不能直接放入 native JSON。

当前 detail schema 2 使用 `paths` 数组，保留首版 schema 1 的读取。新 detail 使用既有语义 CALL 记录，未更改 Flight 或 QTRB 的 wire layout。通用解码器保留 detail；严格解释由 `scripts/syscall_evidence.py` 完成，字段见[格式说明](trace-format.md#optional-syscall-detail-evidence)。

## 路径与返回的含义

每次最多快照两个路径，每个最多 128 字节；遇到 NUL 停止，不将 NUL 放进结果。参数编号从 0 开始。schema 2 的 `paths: []` 表示该调用没有支持的路径选择项，不等于参数为空。

| arm64 syscall 号 | 路径参数编号 |
| --- | --- |
| 5、6、8、9、11、12、14、15、39、43、45、49、51、221、224、225 | 0 |
| 27、34、35、48、53、54、56、60、78、79、88、264、281、291、428、433、437、439、442、452 | 1 |
| 36（symlinkat） | 0、2 |
| 37（linkat）、38（renameat）、276（renameat2）、429（move_mount） | 1、3 |
| 40（mount）、41（pivot_root） | 0、1 |
| 263（fanotify_mark） | 4 |

选择表覆盖 xattr、open/access/stat/readlink、目录/权限、链接/重命名、mount、exec 等直接字符串参数。不会递归读取 `open_how`、argv、envp 或其他结构。支持快照一个号码不代表该设备内核实现了该 syscall。

| `paths[].status` | 含义 |
| --- | --- |
| `complete` | 预算内实际读到 NUL；空路径也可能完整 |
| `unreadable` | 未取得任何字节；不推断路径内容 |
| `partial` | 已读到前缀，后续读取失败；不能将前缀当成完整路径 |
| `truncated` | 读满 128 字节，仍未观察到 NUL |

`bytesHex` 是原始字节；`display` 将非 ASCII 和控制字节显示为 `\xNN`，不假设 UTF-8。路径是执行前的用户态快照，其他线程可能在内核读取前修改内存，因此不能证明内核实际使用了同一字符串。

`syscall-return.observed: true` 表示在对应 SVC 的 POSTINST 观察到 x0，逻辑 PC 为入口 PC + 4，且期间没有观察到 broker 信号 epoch 变化。`rawReturn` 保存完整 64 位十六进制值；仅在 Linux 错误区间 `-4095..-1` 时填写正数 `linuxErrorNumber`。例如 `0xfffffffffffffff2` 对应 14。这个解释值不是目标 libc errno；直接 SVC 不负责设置 libc errno。

信号介入、PC 不匹配或缺少 POST 时，返回值保持 `null`，原因分别是 `signal_intervened`、`unexpected_pc`、`post_not_observed` 或 `capture_ended`。采集封口、环形覆盖、进程终止也可能使返回事件完全缺失。缺失不是未返回，更不是成功或失败。

broker 的 epoch 只反映其实际观察到的信号。普通 QTRB 在显式开启详情时也注册观察上下文。嵌套信号及 SA_RESTART 的独立 fixture 会核对 handler 次数、顺序及原生返回；只要观察到信号介入，返回仍为未知，不推算内核重启次数。它不排除绕过 broker 的信号或其他未观测行为。`rt_sigaction` 虚拟化和终止边界可能先由既有机制处理，不能据 CALL 数量推算所有 SVC 数量。

停止是协作式的：阻塞 SVC 返回后，POST 可能先保存有效返回，下一个目标 PRE 才处理已请求的停止。名义截止时间不等于已停止采集；syscall 返回可已知，而 scene 的目标返回仍未知。普通 QTRB 使用异步缓冲，突然杀进程不保证入口或 footer 已提交；不能据未留下记录推断没执行。

## 离线配对

从仓库根目录运行，传入已拉取的原始 Flight 文件：

```bash
python3 - capture.flight.bin <<'PY'
import json
import sys
from scripts.flight_trace import recover_flight
from scripts.syscall_evidence import pair_syscall_events

with open(sys.argv[1], "rb") as source:
    recovery = recover_flight(source)
print(json.dumps({
    "complete": recovery.summary["complete"],
    "coverage_gaps": recovery.summary["coverage_gaps"],
    "recovery_damage": recovery.summary["recovery_damage"],
    **pair_syscall_events(recovery.merged),
}, ensure_ascii=False, indent=2))
PY
```

配对身份是这份 artifact 的 `(TID, id)`，同时核对入口 PC、syscall 号和 sequence 顺序。默认最多保留 4096 个入口，超限明确报错；重复身份、矛盾返回或错误 schema 也会拒绝，不猜配。

普通 QTRB 使用同一配对规则。直接传入解压后的原始 `.trace.bin`，严格转换验证结束后才返回证据：

```bash
python3 - capture.trace.bin <<'PY'
import json
import sys
from scripts.syscall_evidence import recover_qtrb_syscalls
with open(sys.argv[1], "rb") as source:
    evidence = recover_qtrb_syscalls(source)
print(json.dumps(evidence, ensure_ascii=False, indent=2))
PY
```

Flight 的顺序来自全局 sequence；QTRB 的 `source_order: "qtrb_record_ordinal"` 来自本文件物理 record 顺序，不能跨 artifact 比较或配对。默认拒绝没有合法 terminal 的 QTRB；显式 `allow_partial=True` 只处理合法保留前缀，不补造返回或 terminal。

- `calls[].return: null`：入口存在，缺少配对返回。
- `calls[].return.observed: false`：有显式未知返回记录，原始值仍为空。
- `orphaned_returns`：返回存在，入口未保留；不能借其他入口补配。
- `legacy_entries`：旧格式只有入口，不能生成新返回证据。

完整恢复会读取所有保留的已提交前缀。只查询已结束 scene 的视图可能遗漏早期退出片段；判断缺失返回时同时检查覆盖与恢复结果，不只看 `events-flight` 的某个页面。

## 独立设备复现

先按[开发指南](development.md)构建 tracer 和 companion，再构建 fixture。`QTRACE_GUARD_ROOT` 指向本机已约定的共用设备锁目录；所有使用同一设备的工具必须采用相同目录，不要通过换目录绕过占用：

```bash
python3 scripts/build_runtime_probe.py --ndk "$ANDROID_NDK_HOME" --output out/runtime-probe
python3 scripts/runtime_acceptance.py \
  --serial SERIAL --adb "$ANDROID_HOME/platform-tools/adb" \
  --guard-root "${QTRACE_GUARD_ROOT:?set shared device guard directory}" \
  --tracer PATH_TO_LIBQBDI_TRACER --companion PATH_TO_COMPANION \
  --probe-dir out/runtime-probe --scenario 11 --profile calls --flight \
  --syscall-details --output out/syscall-paths
```

`--output` 必须是新目录。需要兼容、空闲的 rooted arm64 设备和已运行的 ADB server；脚本持有 serial guard，按 PID/starttime 清理自己创建的进程与目录。它不安装 APK。
scenario 11 覆盖有效路径、失败 syscall、坏指针、部分可读和截断；12 覆盖双线程配对；13 覆盖 broker 信号中断和 EINTR；14 用 Flight 保留自身 SIGKILL 前的入口及缺失返回；15 覆盖 access/readlink/stat/statx 和双路径 rename/link/symlink；16 覆盖 SA_NODEFER 嵌套交付；17 覆盖阻塞 read 的 SA_RESTART；18 覆盖截止请求跨越阻塞 SVC、已知 syscall 返回和未知 scene 返回。去掉 `--flight` 可核对普通 QTRB。各轮实际设备身份、产物和未覆盖条件分别保留在验收记录中。
