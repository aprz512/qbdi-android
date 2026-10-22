# Flight 大产物离线优化验收

日期：2026-10-22。工作分支 `feat/flight-query-bounded`，基线 `eb79bcb2c37acb27affda4983ecb099e3ac5c497`。本轮实现仅涉及离线查询、转换与通用手动部署工具；native 采集协议和 JNI 解码器未修改。工作位于隔离 worktree，未合入或推送。

## 实现范围

`tail-flight` 按 sealed chunk 范围跳过旧 payload，返回未闭合场景内的原始事件。`index-flight` 将实际边界及指令范围写入绑定源身份的 SQLite 索引；`scenes-flight --index`、`scene-at-flight` 和 `inspect-flight --index` 复用索引。缺失入口、覆盖或损坏不推造场景归属和目标返回。

`convert-flight` 与普通 pull 使用同一严格恢复算法的磁盘存储后端，逐行输出文本与 JSON。小文件完整输出与原内存恢复逐字节对照；范围导出保留源恢复结论，但标记自身 `complete: false`，请求范围和截断状态另列。默认数据库预算 16 GiB，临时磁盘随输入增长。

`copyTracerDebug` 生成关联源码、改动、构建配置与 SO SHA-256 的身份侧车。`inspect-payload` 核对字节，`deploy` 复用 app-private 部署与现有 ABI 报告门禁，写出 payload/config 回执。回执保持 `loaded_payload_status: "unknown"`，不代替进程内实际加载证明。

## 输入与方法

夹具使用本工作树的生产 `FlightEncoder` 写出格式 2，容量均为 2,147,483,648 B。每组包含一条指令和 32 条带 64 B before/after 数据的 memory 事件，仅首组写入 scene enter，没有 scene return。两份输入分别保留入口和覆盖入口；不用稀疏空洞代替密集 payload。

```bash
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/cmake --build build/native-tests --target flight_query_fixture -j 4
build/native-tests/flight_query_fixture out/flight-query-20261022-6580/dense-open.flight.bin 330000 2048 open
build/native-tests/flight_query_fixture out/flight-query-20261022-6580/dense.flight.bin 350000 2048 open
```

使用 `/usr/bin/time` 记录进程耗时与最大 RSS；临时文件按 0.5 秒采样，同时统计打开但已删除的 SQLite 临时文件。测量属于当前主机的单次功能验收。输入和文件缓存未隔离，扫描任务可能并行运行；这些数字不是跨主机性能门禁或严格速度比。

| 操作 | 进程耗时 | 峰值 RSS | 结果与读取成本 |
| --- | ---: | ---: | --- |
| 保留入口的密集输入，尾部 30 行 | 0.11 s | 27,604 KiB | 1 chunk，80,064 B payload |
| 覆盖入口的密集输入，尾部 30 行 | 0.13 s | 28,628 KiB | 1 chunk，180,024 B payload |
| 保留入口输入，首次场景索引 | 253.42 s | 43,040 KiB | 扫描 2,136,905,608 B，8,158 chunks |
| 覆盖入口输入，首次场景索引 | 259.86 s | 43,684 KiB | 扫描 2,145,650,256 B，8,191 chunks |
| 复用索引查询边界 / 包含场景 | 0.06–0.09 s | 25,336–25,448 KiB | 不重读 payload |
| 覆盖入口输入，严格恢复后导出尾部 30 条 | 821.02 s | 50,060 KiB | 临时磁盘峰值 14,932,125,055 B，输出合计 1,152,478 B |

表内耗时与 RSS 来自 GNU time 原始记录。转换监控器的 monotonic 总耗时为 800.96 s，索引监控器也存在数秒差异；两个计时源均保留，测量不用于计算精确加速比。临时磁盘数字包含已打开但已删除的 SQLite 临时文件，采样值不是严格瞬时上限。转换数据库未超过默认 16 GiB 配额，运行结束后暂存目录为空。

保留入口输入含 10,914,479 个物理记录和 330,000 条指令；已提交 payload 占文件容量约 99.5%。其场景入口为 sequence 6，末尾为 10,914,479；在 sequence 10,914,450 查询包含关系仍返回该入口，`open_at_end`、`target_returned: null`，指令数 330,000。此时 `scenes-flight --after-sequence` 的空列表仅表示没有更晚边界。

覆盖入口输入保留 10,959,140 个物理记录和 331,350 条指令，实际缺失一个 sequence 区间。它没有保留 scene 边界，因此包含关系返回 `membership_status: "unknown"`。尾部仍可读取。严格范围导出的 30 条 sequence 与 `tail-flight` 完全一致；导出保持 `complete: false`，源恢复结论另放在 `source_complete`。

同一覆盖入口输入上，原有 `scenes-flight` 在默认 5 s 截止时间失败；原有 `events-flight` 即使携带尾部游标，也在默认 30 s 截止时间失败。它们的既有时间、扫描预算与配对语义保持不变，新命令提供相应的有界入口。

688,128 B 小夹具使用基线源码和当前源码分别在独立 Python 进程转换。两个进程记录实际导入模块路径与源码 SHA-256；merged、TID 文本和 summary 的 SHA-256 完全一致。Python 峰值分配从 25,244,889 B 降至 2,331,944 B，进程 RSS 从 67,152 KiB 降至 32,552 KiB。该小夹具耗时从 1.93 s 增至 4.38 s；磁盘恢复用于控制大文件内存，快速定位使用 tail 和索引。

## 回归与边界

- Python 全量：`python3 -m unittest discover -s scripts/tests -p 'test_*.py'`，957 项，9 项跳过；最终部署配置兼容调整后，部署/构建/ABI 相关 43 项再通过。
- 恢复/转换/pull 重点回归：278 项通过，包含全套原有严格恢复向量、碎片损坏、原子发布回滚、范围输出、源变化及数据库预算拒绝。完整小文件输出与原实现逐字节一致。
- native：`./gradlew nativeHostTest --no-daemon`，50/50 通过。生产夹具另经重新构建，保留原默认场景行为。
- Ctrl-C：对大输入的索引和转换各发送 SIGINT，均以 130 退出，单次收尾约 15.5 ms；没有发布局部索引/输出，也没有残留本轮暂存文件。这不是取消延迟上限。
- 构建配置：Gradle help 与 `:tracer:copyTracerDebug --dry-run` 通过，实际源码身份采集通过。
- Android payload 构建身份：实际运行 `:tracer:copyTracerDebug`，6m 3s 成功；`inspect-payload --json` 核对两份真实 arm64 SO 与侧车哈希，`source_status: "recorded"`。tracer SHA-256 为 `366113d821b8d2e2ba586d1050c8d055f8fab9b5d3356d6119fba6ca290fddb8`。构建与身份检查未执行设备部署或 JNI/arm64 设备准入。

最终差异中的源文件别名保护和空碎片表索引不改变两份无语义碎片输入的解码、筛选与输出路径。最终碎片分组顺序及入口保护由上述重点回归覆盖。

原始命令、stdout/stderr、计时、输入、索引及输出保存在本工作树 `out/flight-query-20261022-6580/`；该目录不纳入版本控制。机器可读摘要见 [flight-offline-2026-10-22.json](flight-offline-2026-10-22.json)。生产夹具、核心实现和检查日志的哈希随摘要记录。

原体验记录的输入文件和实际运行 payload 尚未取得，前述离线验收没有复现其具体真机崩溃。现有 JNI 历史修复与设备证据仍见 [JNI/arm64 验收](jni-abi-2026-10-21.md)；不能用本轮主机通过状态替代候选 payload 的设备准入。

同日后续完成当前候选的 JNI/arm64 14/14、独立部署及两份真机 Flight 验证，并修复两项部署问题，见[设备补验](flight-device-2026-10-22.md)。前述资源数字及其原始源码快照保留。
