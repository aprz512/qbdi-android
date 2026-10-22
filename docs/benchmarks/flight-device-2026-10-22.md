# Flight 与 JNI/arm64 设备补验

日期：2026-10-22。分支 `feat/flight-query-bounded`，基线 `eb79bcb2c37acb27affda4983ecb099e3ac5c497`。本轮补充实际候选的设备准入、独立部署与真机 Flight 的离线处理；未合入或推送。原有 2 GiB 密集夹具测量见[离线验收](flight-offline-2026-10-22.md)。

## 设备与产物

使用 Pixel 6 `1C111FDF600G6S`，API36、`arm64-v8a`、物理用户 0，系统 fingerprint 为 `google/oriole/oriole:16/CP1A.260405.005/15001963:user/release-keys`。所有写入与执行均持有现有 adb server/serial 对应的共享 guard；未重启 adb server、安装或卸载 APK。

- tracer SHA-256：`366113d821b8d2e2ba586d1050c8d055f8fab9b5d3356d6119fba6ca290fddb8`。
- companion SHA-256：`4fe29375379c3c6bd7dae1f8af60f9b89a670149f3152ab0cedf8efa890fe2dd`。

两个 SO 与上轮实际 Android 构建、身份侧车及本轮设备部署字节一致。后续仅调整主机部署代码，native 输入和 SO 未变。

## JNI/arm64：14/14 通过

使用仓库现有 `build_jni_abi_probe.py` 和 `jni_abi_acceptance.py`，在独立 ART 进程执行同输入 baseline/traced 对照。54 条 Java 观测、普通/V/A 参数文本、符号与极值、GP/FP 耗尽及栈参数、固定浮点字段、构造器、实例/nonvirtual、异常、x18、线程栈和 attach callback 均通过。30 份轨迹都有匹配 metrics、指令和有效真实返回，native 状态无错误或活动场景。

脚本退出码为 0，14 个必要检查均为 true。另从原始 stdout、转换后的轨迹及 metrics 重新核对，确认 30 个有效返回 terminal。验收 session 为 `f8069b44-0664-484a-8d18-89f12e5bf232`。本候选在该矩阵中未复现 JNI 可变参数文本错误或真实调用结果变化；此结论不覆盖尚未取得的历史实际 payload。

独立 ART 进程已退出，本轮远端部署目录和合成数据目录均已清理。

## 独立部署及实际修复

在设备上已有且停止运行的测试应用 `com.aprz.qbdiandroid` 验证 `qtrace deploy --abi-report`，无需安装或启动应用。真机测试先发现两处缺陷，各保留失败证据并完成回归：

1. 已有 `cache/qtrace` 为 root 所有、应用只读。session 预留和失败清理使用了应用身份，导致 `Permission denied`。现改为复用 `Deployer` 的 app-private 控制身份，不修改已有父目录的属主或权限；仅处理本轮成功预留的 UUID 目录。
2. 配置暂存文件以读写方式打开，违反 `push_open_file` 只接受只读常规文件 FD 的合同。现写入私有临时目录后关闭 writer，再以只读方式持有 FD 传输，保留底层传输检查。

修复后完整 CLI 部署通过，8 项设备检查全部为 true：真实 SO/配置哈希匹配、ABI 报告身份匹配、缺省 session 自动补入且源配置不变、重复回执拒绝覆盖、错误 payload 哈希报告在部署前拒绝、应用保持停止，以及原有 session/staging 内容保持。app-private linker 探测通过。

回执继续保留 `loaded_payload_status: "unknown"`。linker 探测和设备文件哈希不能证明之后的业务进程加载了这些字节。本轮部署文件和 staging 已清理，原有目录及文件保留。

## 真机 Flight 与离线工具

使用现有独立 native runtime 夹具产生两份 64 MiB Flight，调用时传入同一已验收 SO；分别选择 scenario 1 和 scenario 7，`--profile full --flight`。两轮 baseline/traced 行为及收尾检查均通过。

| 情况 | 持久轨迹的场景状态 | 轨迹内目标返回证据 |
| --- | --- | --- |
| 正常返回 | `returned` | `true`，返回值 `0x2a` |
| 定时停止采集 | `capture_stopped` | `null` |

定时停止用例还确认：采集封口时目标仍在活动场景中，稍后实际返回才清除 native 活动状态；持久文件 `complete: true` 仍不能替代轨迹内返回证据。

对两份真实文件分别运行 `tail-flight`、`index-flight`、`scene-at-flight`、`scenes-flight --index`、`inspect-flight --index` 与 `convert-flight`。尾部 30 条事件的公开 JSON 与严格全恢复逐项一致，包含 sequence、TID、寄存器、内存及源偏移。索引复用不读 payload；范围转换明确标记自身不完整，保留正确场景状态。离线安装状态和未跟踪线程总数继续保持未知。

## 验证记录与边界

- 两项部署修复均先复现失败；目录身份覆盖成功和失败清理，配置传输回归复用真实只读 FD 校验。
- 部署、构建、ABI 与 CLI 重点回归：67 项通过。
- 最终 Python 全量：961 项，9 项跳过，其余通过。
- native 50/50 与 Android 构建沿用上轮证据；已重新核对 native 输入身份和 SO 字节未变。

命令、原始报告、源码及证据哈希见[机器摘要](flight-device-2026-10-22.json)。原始数据保存在本工作树 `out/flight-validation-20261022-6580/`，包含 JNI 轨迹、两份真机 Flight、失败现场、部署回执和最终回归日志。旧报告、重复回执等拒绝用例单独记录，不作为成功准入报告使用。

本轮没有复现原体验记录中的具体崩溃。原始大产物和当时实际加载 payload 的完整身份仍待取得；业务进程之后的手动加载也须另保留进程内证据。
