# Flight 大产物离线查询与转换

[使用指南](usage.md#场景状态与有界离线查询) · [开发与验证](development.md) · [优化 TODO](superpowers/plans/2026-10-22-flight-query-jni-todo.md)

## 先看元数据，再查尾部

以下命令只访问主机文件，不需要设备或 Frida：

```bash
python3 -m qtrace inspect-flight run.flight.bin --json
python3 -m qtrace tail-flight run.flight.bin --limit 30
python3 -m qtrace tail-flight run.flight.bin --after-sequence 27013000 --limit 30
```

`inspect-flight` 默认只检查头部元数据，保留 `payload_verification: "not_performed"` 和未知返回状态。

`tail-flight` 返回请求 sequence 范围内最后 N 条原始事件，按 sequence 升序排列，允许场景尚未返回。`--after-sequence` 为排他下界，`--until-sequence` 为包含的上界。需要更早一页时，把结果的 `next_until_sequence` 传给 `--until-sequence`，保留相同的下界及源文件。

查询根据 sealed chunk 声明的范围跳过旧 payload，校验实际读取的 chunk；active chunk 的未发布范围不用于跳过数据。结果列出 `payload_bytes_read`、`decoded_chunks` 与验证范围。它不验证被跳过的 payload，不证明全文件完整性，也不推断 scene 已返回。

跨 chunk 语义碎片以 `semantic_fragment` 原样返回，不冒充完整 call。需要完整逻辑事件或全局恢复结论时，使用严格转换入口。

默认每页 30 行、最多 2000 行，截止时间 30 秒，payload 扫描上限 64 MiB，元数据上限 8 MiB，单 chunk 上限 1 MiB，JSON 页上限 16 MiB。超限明确失败，不返回看似完整的截断页。

## 一次建立场景索引，后续复用

```bash
python3 -m qtrace index-flight run.flight.bin --index run.scenes.sqlite --timeout 900
python3 -m qtrace scenes-flight run.flight.bin --index run.scenes.sqlite \
  --after-sequence 27000000 --limit 100
python3 -m qtrace scene-at-flight run.flight.bin --index run.scenes.sqlite \
  --sequence 27013000 --tid 20848
python3 -m qtrace inspect-flight run.flight.bin --index run.scenes.sqlite --json
```

首次建索引扫描、校验实际 chunk 和应急槽，提取真正的 `qtrace.scene` 边界。chunk 头的范围只用于定位，不能代替 scene 内容。默认最多扫描 4 GiB payload、耗时 300 秒，索引文件最多 8 GiB；可显式调整 `--max-scan-bytes` 和 `--timeout`。Ctrl-C 会取消，失败不发布半成品。默认拒绝覆盖索引，`--force` 才允许原子替换。

索引绑定源文件设备号、inode、长度及纳秒 mtime/ctime；源文件变化或版本不符时拒绝复用。复制后的另一个文件需要重新建索引。复用查询不重新读取 payload，结果明确标出这一验证范围；索引不是全逻辑事件恢复报告。分片 scene 边界会明确拒绝建索引，须先用严格恢复检查；普通 call 碎片不参与场景配对。

`scenes-flight --after-sequence` 始终筛选游标之后的边界事件。`rows: []` 只表示没有匹配边界，不说明此前进入的场景已结束。未指定索引的旧命令继续保留原有 64 MiB 扫描预算。

`scene-at-flight` 可以找到入口位于游标之前的场景，按最新入口优先返回；不指定 `--tid` 时允许多个线程各自包含该全局 sequence。未闭合场景保留 `open_at_end`、未知返回和已观测的末尾范围。缺失 sequence、coverage gap 或缺少入口时，归属保持不确定，不能把候选场景当作已证明的完整调用。没有候选时 `membership_status: "unknown"`，不能由空列表推断从未命中。

显式索引摘要包含全局指令数、场景进入/返回/停止/未配对数量、缺口和记录到的 TID，以及最多 256 个入口地址的统计；被省略的条目另计数。场景指令数包含嵌套场景内的指令。安装状态和未跟踪线程总数保持未知，普通 checkpoint 不标为精确 scene 入口快照。

## 严格转换使用磁盘暂存

```bash
python3 -m qtrace convert-flight run.flight.bin --output converted
python3 -m qtrace convert-flight run.flight.bin --output selected \
  --after-sequence 27013000 --max-events 1000 --json
```

转换复用原有严格恢复算法，将事件、物理记录和归并状态放入临时 SQLite 存储，再逐行写出 merged、各 TID 文本和 JSON。默认输出命名、拒绝覆盖、整组原子发布和失败回滚保持不变；`--force` 显式允许覆盖。

`--after-sequence`、`--until-sequence`、`--max-events` 限制导出内容。局部结果标记 `complete: false`，`output_scope` 给出请求条件、实际首末 sequence、事件数及是否还有更多事件；`source_complete` 单独保留源恢复结论。局部结果不作为整产物验收凭据。

范围导出仍需严格恢复源文件，不是快速尾部查询。默认临时数据库预算为 16 GiB，可通过 `--max-spool-bytes` 调整；可用 `TMPDIR` 选择有足够空间的临时目录。内存工作窗口受单 chunk、单个逻辑事件和元数据约束，临时磁盘随输入增长。单 chunk 最多 1 MiB、元数据最多 8 MiB；预算不足、磁盘不足、取消或源文件变化会明确失败，不发布半套结果。

普通 `qtrace pull` 与底层拉取脚本也复用磁盘恢复，并直接取得紧凑摘要，不把完整 `.flight.json` 再读回内存。派生产物的 SHA-256 按块计算。

文件 complete、采集封口、目标显式返回与进程退出仍是不同证据。Flight 尾部、索引和转换都不能据文件存在推断目标成功执行。

本轮测量和回归范围见[离线优化验收](benchmarks/flight-offline-2026-10-22.md)；真实设备的返回/定时停止轨迹对照见[设备补验](benchmarks/flight-device-2026-10-22.md)。
