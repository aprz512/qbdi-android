# 通用优化验收：生命周期、查询与进程边界

日期：2026-10-21。工作区基于 `0660cc21d48bd05e490d35fc9e9850d31156dc88`，保留交接时未提交修复。
本轮为通用工具能力。原始报告、失败记录与产物位于 `artifacts/qbdi-generic-2026-10-21/`；
机器可读摘要见[同名 JSON](qbdi-generic-2026-10-21.json)，最终源码及二进制身份见该目录下 `final/manifest.json`。
历史 JNI 证据继续保留在[上一轮记录](jni-abi-2026-10-21.md)。

## 当前产物及验证范围

最终 tracer SHA-256：`f0ad3048b2d2d0ae4cea91182cf8c3de67e493a1a9b0fbf8bc864dcced1494d5`。
构建为 NDK `27.0.12077973`、arm64-v8a、android-28、CMake `RelWithDebInfo`。
设备为 Pixel 6 `1C111FDF600G6S`、Android 16/API36、物理用户 0。
20 组 native 配置分别执行独立 baseline 与 traced 子进程，覆盖四种事件配置、11 个目标场景、普通 QTRB 与 Flight。
每组均保存目标库与 tracer 哈希、配置、PID/epoch、返回或退出状态、严格解码结果与清理回执。

最终产物另完成 27 场景、30 份轨迹、14 项 JNI/ART 准入，报告为 `accepted-jni/report.json`，会话
`37f1f2ee-dd80-4c46-9874-728b6f4832ca`。Java 实收值、普通/V/A、固定 FP 参数、浮点返回、异常、attach/callback、真实栈与 x18 检查全过。
同一报告通过 CLI 的 ABI preflight，重新核对在线设备 fingerprint/ABI/SDK 与本地两份库的哈希；回执为 `accepted-abi-preflight.json`。

## 场景与生命周期

旧产物在采集封口时从 status 移除仍在执行的目标。`lifecycle-device-red/report.json` 保留旧行为，
新状态将 capture admission 与尚未结束的目标分开，使用同一固定容量限制，并拒绝仍开放 scene/TID 的重复 admission。
`activeScenes[].sealed: true` 明确表示“轨迹已封口、目标仍开放”，实际返回后才移除。
普通 writer 的停止终端现在立即写入并关闭，避免目标长期等待期间只有缓冲区中的 footer。
对应 RED/GREEN 包括 `normal-stop-red-tests.log`、`boundary-host-tests.log` 和 `open-duplicate-valid-red-tests.log`。

`accepted-runtime-7` 与 `accepted-flight-7` 均验证 100 ms 停止请求后，目标继续至真实返回 42；
采集封口期间目标仍可见，实际返回后 status 清除。Flight 文件结构 complete，但该次 scene 为 `capture_stopped`，返回值未知。
`accepted-flight-1` 则包含真实 `return`、返回值 `0x2a`，与 baseline 和调用者收到的值相符。
`qtrace.scene` 使用已有 RULE 记录，不改 Flight wire layout；摘要最多保留 256 个调用，并报告省略与无效元数据。

CLI 报告分开描述 capture、开放 scene、截止时间与已确认的原进程退出。
单独拉取 status 时，进程状态保持未知。现有 TID、截止时间与开放状态可作为等待定位入口；
本轮没有自动采集 Java 栈或 Binder 等待链，也不从“没有新指令”推断具体等待原因。
这避免为状态诊断额外引入信号、全线程暂停或目标运行行为变化。

## 256 MiB 输入的预算与查询

语料由生产 `FlightEncoder` 写入，完整容量均为 268,435,456 字节。必须区分占用量：

| 输入 | 已提交 payload | 组数 | 结果 |
| --- | ---: | ---: | --- |
| 密集输入 | 223,552,088 B | 60,000 | 索引触发现有累计分配预算并拒绝 |
| 较低占用输入 | 14,896,088 B | 4,000 | 索引及全部分页查询通过 |

每组包含一条指令、一条 memory、一条带约 3,000 B detail 的 call 和两条实际场景时间边界。
60,000 组语料有 585,002 个头部声明的物理记录。4,000 组语料解码为 39,002 个公开事件。

| 操作 | 单次观测耗时 | 峰值 RSS | 结论 |
| --- | ---: | ---: | --- |
| 密集输入元数据预览 | 0.10 s | 23,700 KiB | 请求 1,052,672 B 元数据；未读取或验证 payload |
| 密集输入索引 | 3.50 s | 938,876 KiB | `control.budget_exceeded`；累计分配 2,151,308,951 B，预算 2,147,483,648 B |
| 4,000 组首次索引 | 1.075 s | 162,332 KiB | 类型、地址及 sequence 查询全部通过 |
| 4,000 组复用缓存 | 0.642 s | 113,648 KiB | 查询通过；仅本机单次观测 |
| 场景时间查询 | 2.19 s | 24,188 KiB | 时间区间命中 6 条边界，首两页各 2 行，无无效边界 |

这些是本机单次观测，包含调度和并行回归负载，不作为跨设备的性能保证。
累计分配预算不是峰值 RSS。15,000 与 40,000 组中间语料触发独立的 16 MiB string arena 限制；失败记录保留。
没有放宽既有预算来让密集输入通过，也没有把较低占用的 256 MiB 文件当作密集输入成功分析。

公开服务的 instruction 和 call 各 4,000 行、两页；地址区间命中 2,000 行，sequence 100–1000 命中 901 行。
每页最多 2,000 行，最大页 JSON 为 860,624 B，所有查询完成后 workspace 已关闭。
生产服务的取消实测发现底层 `control.cancelled` 被登记为 Failed；统一映射到 `job.cancelled` 后，
任务为 Cancelled，工作线程被 join。source 校验阶段取消到 join 为 0.256 ms；另在实际索引已处理
56,131 个事件时取消，到 join 为 5.166 ms，两者均返回 `job.cancelled`，不发布 workspace。
这些是单次取消观测，不是最坏时限保证。

`inspect-flight` 默认 5 秒、8 MiB 元数据、1024 个线程目录预算，只提供标明未验证的头部预览。
`scenes-flight` 按实际场景单调时钟查询，默认 5 秒、64 MiB payload、1 MiB 单 chunk、2,000 行；
exclusive sequence cursor 用于下一页，每页重新扫描同一未改变的文件，在 chunk 边界检查取消与截止时间。
它校验所解码 chunk，不替代全文件恢复或配对。
指令事件没有逐条时钟字段；时间过滤仅适用于真实场景边界，不插值、不把 sequence 冒充时间。
用法见[使用指南](../usage.md#场景状态与有界离线查询)。

## 调用摘要与实际采集内容

`tracer.events: "calls"` / native `trace.events` 为可选配置，默认 `all` 不变。
复用原有 JNI、libc 与执行转移处理；目标中的 `svc` 仅记录入口号与六个参数。
已有模块与 scene 聚焦继续使用，详细采集按下一次会话需要升级，不增加另一套注入入口。

| 配置 | 指令 | memory | 有前后字节的 memory | CALL | 单次原始轨迹 |
| --- | ---: | ---: | ---: | ---: | ---: |
| fast/all | 2,849 | 0 | 0 | 3 | 153,361 B |
| balanced/all | 2,849 | 527 | 0 | 3 | 178,904 B |
| full/all | 2,849 | 527 | 527 | 3 | 185,224 B |
| fast/calls | 0 | 0 | 0 | 4，含 1 条 syscall-entry | 726 B |

每种配置执行五次，同输入独立 buffer oracle 与 PID 系统调用结果全部匹配。
Flight/calls 另执行五次：没有 instruction 或 memory 事件，保留五条 syscall-entry 和五个真实返回，
无 coverage gap 或恢复损坏；`accepted-flight-calls-contract.json` 保存事件计数和返回元数据。
排除首轮后的四次中位数为 fast 9.789 ms、balanced 13.663 ms、full 11.671 ms、calls 11.048 ms。
每次场景调用都创建自己的 VM，包含初始化、翻译、writer 和 hook 成本；未取得稳定的 CPU 加速结论。
可确认的是 calls 显著降低这组输入的输出量，而非取消 QBDI 执行成本。
Flight 的 calls 模式仍保留必要 checkpoint 和场景元数据，不宣称全进程或子进程调用树。

## 间接转移与进程边界

| 目标 | baseline 与 traced 结果 | 采集边界 |
| --- | --- | --- |
| BLR 与 BR 尾跳转 | 实际返回 42，轨迹包含两类分支 | 父目标完整返回 |
| fork / 子进程 `_exit(17)` | parent 返回 42，wait status 为 `17 << 8` | 子进程按已有 detach 规则原生执行 |
| vfork / 子进程 `_exit(17)` | parent 返回 42，wait status 正确 | 子进程在真实调用点原生执行 |
| vfork / 子进程 exec | exec `/system/bin/true`、退出 0，parent 返回 42 | 不进入共享引擎 |
| 两个 pthread 并发 vfork | 两个 parent 结果、子进程状态与两份完整轨迹均正确 | instrumented vfork 转移串行保护 |
| exec 成功 | receipt E、原进程退出 0，无目标返回 | `exec_boundary` 封口后执行原调用 |
| exec 失败 | 返回 42，前后副作用各一次 | 尝试之后停止采集，原调用继续，无目标重放 |
| `_exit(23)` | receipt X、退出 23，无目标返回 | `process_exit` 终端 |
| pthread_exit | receipt T、join 值 42，无目标返回 | `thread_exit` 终端 |

当前 ABI 的旧产物在 vfork 最小夹具中 SIGSEGV，见 `boundary-baseline-3/report.json`，不是沿用历史故障推论。
修复位于 native 执行转移边界：无栈帧 AArch64 桥保存 parent broker 返回点；合法 child 直接返回原调用点，
直至 exec 或 `_exit`，不会进入共享引擎或修改其 TLS/分配器。没有将 vfork 替换为 fork。
设计核对了 [AOSP arm64 vfork 实现](https://android.googlesource.com/platform/bionic/+/HEAD/libc/arch-arm64/bionic/vfork.S)。

原普通采集在 exec、`_exit` 和 pthread_exit 时存在未刷出轨迹；本轮使对应终端耐久写入。
早期在 exec transfer 返回 STOP 的实现会使续跑停滞：本地 QBDI `Engine::run` 拒绝从未插桩的 libc 入口启动。
最终在冷转移边界封口后由原 broker 执行一次，成功/失败两条 exec 路径均经真机对照。
这些开发期失败保留在 `exec-device-green` 和 `exit-final`，目录名不代表验收结果，按 report 的 result 判断。

覆盖限定为被选目标模块、当前 Bionic/ABI、夹具中的合法调用。原始 clone/vfork 系统调用、自定义 libc、
未覆盖调用点、子分支返回到调用者的非法用法和其它设备/ABI不在本轮证明范围内。
原生子进程区间是明确的覆盖边界，不能因 parent 成功返回而宣称 child 指令已被采集。

## 复现与收尾

`scripts/build_runtime_probe.py --ndk "$ANDROID_NDK"` 构建独立目标库和 supervisor。
`scripts/runtime_acceptance.py --help` 列出 serial、tracer、companion、既有 canonical guard 与输出参数；
scenario 为 0–10，profile 为 fast/balanced/full/calls，Flight 通过 `--flight` 选择。
脚本只在唯一的自有目录运行；部署后重验哈希，停止自有进程前检查 PID/epoch，保存父子进程清理回执。
所有最终设备报告 `cleanup: true`，自有临时目录删除，guard 已释放。

Host 全量 50 个目标通过；Rust provider/store/analysis/service 全量通过。
Python 全量完成 906 项，9 项跳过，最终复跑通过；该套件也完成其现有的前端构建检查。
`git diff --check` 与 Rust 格式检查通过。原始工作区的 20 个交接文件哈希全部保持不变。
命令、日志和复核结果见同名 JSON 与最终 manifest。
早期 contract/oracle 未同步导致的测试失败与一次既有时限测试失败均保留；未通过的记录不覆盖为成功。
验收时工作尚未提交；后续提交和合入状态以 Git 历史为准，既有证据保留。
