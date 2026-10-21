# Flight 密集索引与场景事件查询

本轮从 `18297336506bc909c5c220cce9b784aab4c0e271` 继续优化离线工具。
原始输入来自生产 `FlightEncoder` 的 256 MiB、60,000 组语料，已提交 payload 为 223,552,088 B，保留 585,002 个事件。
历史拒绝记录仍保留在[通用优化验收](qbdi-generic-2026-10-21.md)。本轮不修改 native 采集格式，也不将离线测试视作新设备验收。

## 索引机制

恢复阶段由输出的 `StringDefinition` 事件持有字节，字典只保存输出行号。
只有 fragment 用到的 2–3 个字符串引用才建立共享 Arc。完整性记录按实际新增事件数预留，避免因 retained 范围重分配整张事件表。

分析器缓存升级至 layout 4。有效 UTF-8 定义使用紧凑 JSON 文本，任意非 UTF-8 字节仍保留为数组。
原始字符串定义完整保留在事件 payload 中；名字索引只保存实际使用的规范化名字。
无转义语义 detail 直接引用当前事件的 payload 文本；需要反转义的内容继续使用 blob arena，返回的字节不变。
已驻留的 Flight 事件先为唯一 payload 估算容量，再执行一次受授权的 arena 分配。
哈希仅用于预留容量；实际 interning 仍比较完整字节，冲突时继续执行受预算控制的扩容。

缓存复核仅对字段、类型、UTF-8、边界和尾部全部符合闭合字面形状的 payload 使用精确解码授权。
转义、fragment、数组和异常形状继续使用原有保守授权。实际分配由 allocator oracle 检查，未跳过 checksum、源身份或内容重建核对。
索引与缓存的累计分配预算保持 2 GiB；payload/string/blob arena 上限分别保持 8 GiB、16 MiB、64 MiB。
旧缓存按新身份重建；公开 provider JSON 序列化及 QTRB/Flight wire 格式不变。

## 场景时间

新增 `events-flight`，按实际 enter 与 return/capture_stopped 时间选取重叠的完整场景，再分页返回场景内执行事件。
它不推算逐事件时钟；每行明确返回 `time_source: "scene_interval"` 与 `event_monotonic_ns: null`。
开放场景或缺少入口的场景不补造结束时间。fragment 单独呈现，不进行跨 chunk 拼装。
扫描、行数、场景状态、JSON 大小、截止时间和取消边界见[使用指南](../usage.md#场景状态与有界离线查询)。

## 验证记录

| 最终操作 | 进程总耗时 | 峰值 RSS | 结果 |
| --- | ---: | ---: | --- |
| 密集输入冷开及四类完整分页 | 10.58 s | 1,104,220 KiB | 索引 585,002 个事件；服务打开本身为 10.025 s |
| 同缓存重开及四类完整分页 | 5.06 s | 706,792 KiB | 服务打开本身为 4.628 s；分页结果一致 |
| 全链路逐事件及重启核对 | 38.33 s | 1,836,036 KiB | 冷开与重开各核对 585,002 个事件；分页、寄存器、调用树与内存抽样一致 |
| 密集输入场景事件查询 | 26.80 s | 29,780 KiB | 3 个场景、15 个事件；实际扫描 223,581,832 B payload |

四类分页分别返回 instruction 60,000 行、call 60,000 行、地址范围 30,000 行、sequence 范围 901 行。
页面最多 2,000 行，最大页 JSON 为 871,284 B，工作区均已关闭。
场景时间范围为 `[1100000000, 1102500000]` ns，命中场景 101–103：3 条指令、3 条 memory、3 条 call 与 6 条边界。
较低占用语料的前两页与密集语料的对应前缀一致；跨多个开放区间的 cursor、嵌套、线程隔离、旋转槽位和 active chunk 另有回归覆盖。

源校验取消至 join 单次为 0.179 ms；实际索引恢复处理 54,761 个事件时取消，至 join 为 11.354 ms。
两次任务均为 `job.cancelled`，未发布工作区。场景查询发送 Ctrl-C 后以 130 退出，单次约 15.5 ms。
这些观测不是取消延迟上限。累计分配授权与峰值 RSS 是不同指标，不根据 RSS 推断预算通过。

Rust provider/store/analysis/service 全量为 519 项通过、2 项忽略；Python 全量 917 项检查通过，其中 9 项跳过。
clippy、fmt、生成 fixture/TypeScript 绑定、前端构建与差异空白检查通过。独立审查发现的 fragment 全字典扫描已修正，无剩余确证问题。

命令、源码与二进制身份、原始测量和回归日志保存在 `artifacts/flight-query-2026-10-21/`。
本轮执行中的拒绝及环境依赖缺失记录与成功结果分别保留。
最终测量与检查摘要见[机器可读记录](flight-query-2026-10-21.json)。这些数字属于本机单次功能验收，不是跨主机性能门禁。

## Worktree 收尾

旧 `ca0a` worktree 与已合入分支 `fix/qbdi-generic-20261021` 已删除。
三组 JNI/通用验收原始产物先迁回主仓库的 `artifacts/qbdi-{generic,jni-fixed,p0}-2026-10-21/`，未删除验收证据。
验收时优化位于 `perf/flight-query-20261021` worktree，主仓库当时没有本轮源码改动。
后续合入与清理状态以 Git 历史及 `artifacts/flight-query-2026-10-21/integration.json` 为准。
