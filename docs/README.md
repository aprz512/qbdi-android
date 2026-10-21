# 文档目录

[项目首页](../README.md) · [离线分析器](../qtrace-ui/README.md)

首次使用从使用指南开始；需要修改实现时阅读架构与开发指南。
各指南中的命令默认从仓库根目录执行，另有说明时按文档切换目录。

## 使用与开发

| 文档 | 内容 |
| --- | --- |
| [使用指南](usage.md) | 环境要求、CLI 配置、采集档位、拉取转换、恢复判断与常见问题 |
| [手动 Frida 追踪](manual-tracing.md) | 脚本配置、APK 与 tracer 部署、spawn 注入、入口定位 |
| [架构与设计](architecture.md) | 模块职责、会话与停止、样本身份、写入恢复、配置状态与 JSON ABI |
| [开发与验证](development.md) | 构建产物、QBDI submodule 管理、主机测试、设备发布门禁与配置验收 |
| [性能与基线复现](benchmarking.md) | 历史设备性能、benchmark 复现、身份检查与计时边界 |
| [分析器使用](../qtrace-ui/docs/usage.md) | 打开轨迹、导航、证据分级、缓存与批注 |
| [分析器设计](../qtrace-ui/docs/design.md) | 分层、分页缓存、取消与服务资源边界 |
| [分析器开发](../qtrace-ui/docs/development.md) | Rust/前端测试、打包、实测轨迹验证、性能门禁 |

## 格式与专题

- [QBDI submodule 初始化、升级与回退](development.md#qbdi-源码依赖)
- [QTRB v1、文本格式 4、指标与崩溃恢复](trace-format.md)
- [IDA/objdump 场景偏移定位](ida-offsets.md)
- [完整性检查与 CodeRules](integrity-bypass.md)
- [数码宝贝 UP / AppGuard 实测](research/2026-10-19-appguard-dgup.md)
- [数码宝贝 UP / AppGuard 环境检测清单](research/2026-10-20-appguard-dgup-environment.md)
- [qbdi-android 实战体验与优化建议：AppGuard 防护库分析](research/2026-10-21-qbdi-dgup-tool-experience.md)
- [离线分析器前期调研](research/2026-08-30-trace-ui-analysis.md)

## 设计与历史记录

当前架构见[架构与设计](architecture.md)。以下文档保留当时的设计、实施步骤和验收条件；
历史方案可能包含已被后续实现替换的细节，当前操作以使用指南和开发指南为入口。

- [CLI 基础设施设计](superpowers/specs/2026-08-25-qtrace-cli-infrastructure-design.md)
- [结构化 tracer 配置设计](superpowers/specs/2026-08-25-structured-tracer-configuration-design.md)
- [QTRB 二进制格式设计](superpowers/specs/2026-08-20-binary-trace-format-design.md)
- [多线程 Flight Recorder 设计](superpowers/specs/2026-08-21-multithread-crash-flight-recorder-design.md)
- [离线分析器设计](superpowers/specs/2026-08-30-qtrace-ui-design.md)
- [项目优化清单与状态](superpowers/specs/2026-09-24-project-optimization-design.md)
- [全部设计记录](superpowers/specs/)与[实施计划](superpowers/plans/)

## 性能与验收证据

复现步骤见[性能指南](benchmarking.md)和[分析器开发指南](../qtrace-ui/docs/development.md)。
按日期保留的原始记录统一位于 [benchmarks/](benchmarks/)，常用入口：

- [QTRB 设备性能与大小基线](benchmarks/binary-trace-baseline.md)
- [追踪吞吐优化过程](benchmarks/trace-throughput-baseline.md)
- [Flight Recorder 多线程崩溃验收](benchmarks/flight-recorder-acceptance.md)
- [跟踪可靠性与样本身份验收](benchmarks/qtrace-tracing-reliability-2026-10-19.md)
- [分析器当前性能基线](benchmarks/qtrace-ui-performance-current.md)
- [分析器调用树分页验收](benchmarks/qtrace-ui-call-tree-pages.md)
- [分析器时间线请求验收](benchmarks/qtrace-ui-timeline-pages.md)
