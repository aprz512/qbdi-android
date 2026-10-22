# 从独立基线到窄场景采集

[使用指南](usage.md) · [手动追踪](manual-tracing.md) · [开发与验证](development.md)

先用独立输入确认工具行为，再替换为自己的目标。这里复用已有的 native runtime fixture，
不安装 APK，也不加载游戏或 Frida。它只记录一个 `runtime_probe_target` 场景；地址由本次 ELF 实际加载位置确定。
这条示例验证 native 采集和返回证据，CLI 的注入、应用启动和 Java 异常仍需各自验收。

## 1. 准备本次产物与设备

从仓库根目录执行，先按[开发指南](development.md#构建)完成环境及源码依赖准备：

```bash
git submodule update --init --recursive
./gradlew :tracer:copyTracerDebug --no-daemon
python3 scripts/build_runtime_probe.py --ndk "$ANDROID_NDK_HOME"
```

显式选择已核实空闲的 rooted arm64、物理用户 0 设备。将 `SERIAL` 换成实际 serial，
复用本机既有的 canonical guard 目录；不要另建目录绕过其他会话的占用。
以下输出目录必须尚不存在；重复实验时换一个目录，保留旧证据。

```bash
QTRACE_EXAMPLE_SERIAL=SERIAL
: "${ANDROID_HOME:?set Android SDK directory}"
: "${QTRACE_DEVICE_GUARD_ROOT:?set existing canonical device guard directory}"
```

驱动在 guard 内核对设备、为每轮创建唯一目录，部署后核对库 SHA，并绑定 PID/starttime。
报告保留两轮进程观测、配置、fixture 源码/产物 SHA、tracer/companion SHA 和 cleanup receipt。
任何检查失败都应先处理该轮报告；不能删除责任标记后直接重试。

## 2. 无注入基线与 calls + Flight

```bash
python3 scripts/runtime_acceptance.py \
  --serial "$QTRACE_EXAMPLE_SERIAL" --adb "$ANDROID_HOME/platform-tools/adb" \
  --guard-root "$QTRACE_DEVICE_GUARD_ROOT" \
  --tracer out/arm64-v8a/libqbdi_tracer.so \
  --companion out/arm64-v8a/libshadowhook_nothing.so \
  --scenario 0 --profile calls --flight --output out/narrow-example/calls-flight
```

每条 acceptance 命令先运行不加载 tracer 的 baseline 子进程，再以相同输入运行 traced 子进程。
场景 0 各调用五次，独立核对返回 42、计算后的数组、getpid 与各自进程 PID 一致、join 结果和正常退出。
不同进程的 PID 不必相等，不能直接把两轮 getpid 数值相等作为验收。

fixture 的 `--profile calls` 是现有适配器参数：它构造 native `trace.profile: "fast"` 与
`trace.events: "calls"`。CLI 配置中对应 `tracer.events: "calls"`，并不存在 `tracer.profile: "calls"`。
fixture 显式使用 native `flight.followThreads: false`、64 MiB Flight 和单一入口 `runtime`；
这些不是可以直接复制到 CLI `tracer` 下的字段。

## 3. 校验完整性、进入与显式返回

acceptance 退出码 0 后，进一步解码本轮小 fixture，检查每个已配对场景中的 SVC 入口：

```bash
python3 - <<'PY'
import json
from pathlib import Path
from scripts.flight_trace import recover_flight

root = Path("out/narrow-example/calls-flight")
report = json.loads((root / "report.json").read_text())
assert report["result"] == "pass" and report["cleanup"] is True
assert all(report["checks"].values())
paths = list((root / "traces").glob("*.flight.bin"))
assert len(paths) == 1
with paths[0].open("rb") as source:
    recovery = recover_flight(source)
summary = recovery.summary
assert summary["complete"] is True
assert summary["scene_lifecycle_omitted"] == summary["scene_lifecycle_invalid"] == 0
assert not summary["coverage_gaps"] and not summary["recovery_damage"]
scenes = summary["scene_lifecycle"]
assert len(scenes) == 5
entries = [event for event in recovery.merged
           if event.kind == "call" and event.data.get("category") == "syscall-enter"]
assert len(entries) == 5
for scene in scenes:
    assert scene["entry_sequence"] is not None
    assert scene["target_returned"] is True and scene["return_value"] == "0x2a"
    assert sum(event.tid == scene["tid"] and
               scene["entry_sequence"] <= event.global_seq <= scene["last_sequence"]
               for event in entries) == 1
assert not any(event.kind in {"instruction", "memory"} for event in recovery.merged)
print("5 paired scene returns = 42; 5 syscall entries; cleanup confirmed")
print(paths[0])
PY
```

这五次返回属于 `runtime_probe_target`，不能当作内层 getpid 的通用 syscall 返回事件。
当前 syscall-enter 只有号、PC 与六个原始入口参数；指针值不等于路径内容，入口不证明成功。

对上一步打印的 Flight 路径使用公开离线入口。以下命令中的路径由本轮目录取得，不复用其他采集：

```bash
QTRACE_EXAMPLE_FLIGHT=$(python3 -c 'from pathlib import Path; print(next(Path("out/narrow-example/calls-flight/traces").glob("*.flight.bin")))')
python3 -m qtrace inspect-flight "$QTRACE_EXAMPLE_FLIGHT" --json
python3 -m qtrace scenes-flight "$QTRACE_EXAMPLE_FLIGHT" --limit 2000
python3 -m qtrace events-flight "$QTRACE_EXAMPLE_FLIGHT" --limit 2000
```

`inspect-flight` 仅预览元数据。`scenes-flight` 列出进入/结束边界；`events-flight` 按配对场景查询事件。
检查 `has_more`，必要时带相同条件及返回的游标续页。这些有界查询不代替上面的完整恢复校验。

## 4. 停止采集后，目标返回仍可能未知

用同一命令参数，将 `--scenario 0` 改为 `--scenario 7`，输出目录改为
`out/narrow-example/stopped-flight`。该 fixture 在 100 ms 请求停止后继续运行到实际返回 42。
驱动检查 `sealed_target_still_visible`、`actual_return_clears_open_target` 和
`file_complete_is_not_target_return`。保存的 Flight 可结构完整，但 scene 为 `capture_stopped`、
`target_returned: null`；独立 supervisor 后续观察到 42，也不会补写成窗口内返回。

分别判断：进入事件证明进入；`capture_stopped` 证明采集停止；明确 `return` 才证明窗口内返回；
PID/starttime 终态证明原进程结束。`unknown` 不表示目标没有返回。

## 5. 再升级 all

保持场景、设备与输入，将第 2 步的 `--profile calls` 改为 `--profile full`，
输出目录改为 `out/narrow-example/all-flight`。该适配器省略 `trace.events`，保持默认 `all`。
仍须通过独立 baseline/traced 返回与退出检查，再检查 Flight 的真实返回和指令、memory 事件。
不要将第 3 步“没有 instruction/memory”的 calls 断言原样用于 all。
单次运行只能证明功能；性能收益需要同条件重复测量，不能从事件数量直接推断加速。

## 6. 应用采集的输出约定

换为已配置的 Android 应用时，复用[CLI 配置](usage.md#qtrace-命令行)，先选一个明确函数或包装函数。
CLI 示例保留 stdout 路径及 `--json` 机器接口：

```bash
python3 -m qtrace run --config target.json --device "$QTRACE_EXAMPLE_SERIAL" \
  --duration 5s --output out/app-narrow > paths.txt 2> progress.log
python3 -m qtrace run --config target.json --device "$QTRACE_EXAMPLE_SERIAL" \
  --duration 5s --output out/app-narrow-json --json > result.json 2> progress-json.log
```

这是两次独立采集。普通 stdout 只列报告及产物路径，人读采集/返回摘要写 stderr；
`--json` 的 stdout 是一个结果对象，不混入人读摘要，进度仍写 stderr。
配置和前置失败以非零退出码及 stderr 报错，不保证产生结果对象。退出码 0 也不自动证明目标返回。

本轮实测及未覆盖条件见[2026-10-22 验收记录](benchmarks/qtrace-ux-2026-10-22.md)。
