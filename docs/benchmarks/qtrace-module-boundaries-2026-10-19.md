# MAINT-01：模块职责与行为保持证明

本记录覆盖 `timeline.rs`、Flight `recovery.rs` 和 `tracer_entry.cpp` 的责任提取。起点为 `72548df9c099f3e7813016eba5bd46da34099760`，执行于 `perf/complete-optimization-2026-10-19` 工作区；既有 UI、CLI、store 与其他优化改动保留。`index/**` 的模块化由主任务单独负责。本次不增加协议字段、配置开关、依赖或公开函数。

## 提取后的所有权

| 模块 | 调用者使用的接口 | 模块内部拥有的规则 |
| --- | --- | --- |
| `qtrace-analysis/src/timeline/discontinuity.rs` | 原有 crate 内 `decode_discontinuity_payload` 路径和返回类型 | 先检查事件 tag，再读取不分配堆内存的 canonical JSON；拒绝 escape、重复/未知字段、错误枚举、溢出数字、无效范围及尾随内容。 |
| `qtrace-analysis/src/timeline/semantic_executor.rs` | `SemanticJob::new`、`SemanticExecutor::global/submit` | 固定 worker 和队列上限、启动失败清理、任务 panic 隔离、拒绝通知，以及关闭和 join。父模块继续拥有 projection 状态、匹配器和预算。 |
| `qtrace-provider/src/flight/recovery/emergency.rs` | 原有 `scan_emergencies` 调用 | 两个 emergency cell 的 commit/version/checksum 验证、旧 checksum 兼容、stale 历史裁决、pinned termination/signal 配对和来源完整性记录。 |
| `tracer/src/main/cpp/core/tracer_json_endpoint.{h,cpp}` | `TracerJsonEndpoint::configure/status`；原有 C ABI 包装保留 | 指针/容量检查、transport 回复复制、异常隔离，以及先复制 accepted 回复再执行 activation 的顺序。 |

这些模块按不变量和资源所有权划分。私有解析 cursor、emergency candidate 和 worker 队列没有成为新的公开接口。worker 的三个既有测试随资源所有权移动到对应私有模块。discontinuity 的零分配证明继续检查同一个错误输入，并通过原有解码入口检查对外错误语义，不暴露内部 tag 错误枚举。

## 保持的约束

- timeline 的过滤顺序、候选预算、稳定排序、cursor 身份、分页结果、semantic terminal 状态和取消代码不变。
- Flight 的正常序列索引仍在读取 emergency 前创建；emergency 不能覆盖已提交的正常记录。所有 guard 检查、分配、物理来源坐标和合成事件 ordinal 的顺序保留。
- JSON endpoint 借用既有 `TracerConfiguration` 和配置调用 mutex，fork 和配置转换仍使用同一把 mutex。ready 与 activation 是无分配的函数指针；endpoint 本身使用 `constinit` 初始化。
- 两个导出的 C 函数保留名称、参数、返回类型、`noexcept`、默认可见性和实际返回内容。新增内部 C++ 类使用 hidden visibility；Android 与 host source 列表均注册新 `.cpp`，并在 Android 为该冷路径保留异常支持。
- hook 安装、signal 路径、runtime 销毁时机、instruction collector、Flight writer 和原始产物所有权没有迁入 JSON 模块。

## 前后验证

结构修改前完成以下基线：

| 命令 | 结果 |
| --- | --- |
| `cargo test --locked -j 2 -p qtrace-analysis` | 107 个测试通过。 |
| `cargo test --locked -j 2 -p qtrace-provider --test flight_recovery --test flight_events --test flight_differential` | 48 个测试通过。 |
| CMake 构建 `tracer_entry_proxy_test`、`production_trace_contract_test`，再用 CTest 执行这两个 test | 2/2 通过，包含 JSON ABI、故障注入、配置/模块/fork 生命周期及原有生产约束。 |

逐个模块移动后，timeline 的 19 个单元测试与 28 个分页测试通过；Flight 的同一组 48 个测试通过；新增 JSON endpoint 已随真实 `tracer_entry_proxy_test` target 成功编译。

额外的静态核对比较了移动前后的函数体。discontinuity 解码、semantic executor 和 emergency 选择只有文件位置、导入和可见性变化。JSON configure/status 和 transport 函数在依赖名称替换、等价 lifecycle callback 与单语句 brace 规范化后完全一致。原始快照位于本机 `/tmp/qtrace-module-baseline-20261019`；比较结果位于 `/tmp/qtrace-module-move-equivalence.json`。

结构后完整验证：

| 命令 / 证据 | 结果 |
| --- | --- |
| 主任务 `cargo test --workspace`，`artifacts/complete-optimization-2026-10-19/rust-final.log` | 520 通过、2 ignored；其中 analysis 107、provider 143、service 51、store 214、headless Tauri 5。 |
| 主任务 `cargo clippy --workspace --all-targets --features qtrace-service/e2e-fixture -- -D warnings`，`clippy-final.log` | exit 0。 |
| `tracer_entry_proxy_test`、`production_trace_contract_test` 重新构建后执行 | 2/2 通过。 |
| `python3 qtrace-ui/tools/check_protocol_matrix.py --check` | 当前生产 C++ 产物再现一致，37 个 exporter fixture、16 个 Python 与 25 个 Rust 测试通过。 |
| 独立 fuzz workspace `cargo test --locked -j 2 --tests` | 6 个测试通过，含 64 个固定 seed 的 property case。 |
| Flight ASan，`-max_total_time=10 -seed=20261019 -timeout=3 -rss_limit_mb=512 -malloc_limit_mb=128` | 324,353 次输入，0 crash；使用临时 corpus 副本。 |
| 主任务 `check_generated` 与全量 Python | generated exit 0；Python 858 tests、8 skipped，通过。 |

上述本次独立验证日志、命令和源码 SHA-256 归档于 `artifacts/complete-optimization-2026-10-19/protocol-maint/verification.json`；主任务全量 Python 修复后日志为 `artifacts/complete-optimization-2026-10-19/python-final-recheck.log`。静态移动等价性记录也已复制到该 evidence 目录。

全量 nativeHostTest 首次还揭示 source-contract 的旧函数结束标记依赖已迁移的 `write_json_result`。现将结束边界更新到原位的 readiness 函数，保留 hook 初始化、callback 注册、模块查找顺序的原断言；另检查 endpoint 绑定同一个配置对象/mutex/activation、先复制响应再 activation，以及 hook/module 生命周期操作仍在 tracer entry。修复后该契约定向 1/1 通过，完整 Gradle `nativeHostTest` 45/45 通过（15.21 秒）；同次 app/tracer `assembleDebug` 和 `copyTracerDebug` 成功，Gradle exit 0。最终日志为 `artifacts/complete-optimization-2026-10-19/native/gradle-final-integration-retry.log`，首次失败日志保留在同目录。

此前 [协议与 fuzz 验证](qtrace-protocol-fuzz-2026-10-19.md) 的五个 ASan target 共 925,984 次输入对应模块提取前工作区；结构后的 ASan 证据是本表独立记录的 Flight 324,353 次。

本项交付是模块职责和可验证的行为保持，不声称吞吐量或延迟改善，也不改变其他性能条目的完成条件。
