# Flight 优化本地 main 合入验证

日期：2026-10-22。本轮将 `feat/flight-query-bounded` 的 `a00c7db` 合入原 main `ee4a3b7`，包含有界离线查询、场景索引、磁盘恢复、构建身份及通用手动部署。仅本地合入，分支和工作树保留。

合并保留 main 的 `snapshot` 与新增 CLI 入口。磁盘恢复重放 main 的严格恢复测试时，复现 `pc_source` 注解未保存的问题；现将注解写回私有存储，保留原信号策略、线程和顺序语义。同一回归由失败转为通过。

合并结果验证：

- Python 全量 997 项，9 项跳过，其余通过；重点兼容回归 95 项通过。
- native 50/50；`:tracer:copyTracerDebug` 构建和产物身份核对通过。
- 协议矩阵通过：生产 C++ encoder、Python reader、fixture 字节及 16 项协议测试。本轮未重跑 Rust；合入增量未修改 Rust 或协议编码布局。
- 新候选在 Pixel 6 `1C111FDF600G6S`、API36、arm64、物理用户 0 上通过 JNI/arm64 21/21，包括 main 新增的 snapshot 检查。30 份轨迹均有有效真实返回，共 4,067 条指令；自有进程退出，远端目录及轨迹目录清理完成。

新候选 tracer SHA-256 为 `d1e9952f6c589735c44b78b1bbab098094b459acbba617ae9385a634f3bdbe6b`，companion 为 `4fe29375379c3c6bd7dae1f8af60f9b89a670149f3152ab0cedf8efa890fe2dd`。构建发生于合并提交前，身份记录绑定原 main revision、合并源码差异、输入树摘要与实际 SO；提交前再次核对相关输入未变。

[机器证据](evidence/flight-main-integration-2026-10-22.json)保存源码身份、命令、日志及原始报告 SHA。原始数据保存在 `out/flight-main-integration-20261022/`；不复制运行环境中的外部协调路径或无关应用信息。提交增量及本轮新增文件已检查相关项目名称和依赖，未发现匹配。原工作树的其他修改按 SHA 核对保留。

[离线测量](flight-offline-2026-10-22.md)与[前轮设备补验](flight-device-2026-10-22.md)继续绑定各自原始基线和候选；本轮没有重新执行 2 GiB 测量、独立部署或业务进程手动加载，不改写这些历史证据。原体验文件及当时实际 payload 的完整身份仍待取得。
