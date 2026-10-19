# 项目优化清单最终验收 — 2026-10-19

[原优化清单](../superpowers/specs/2026-09-24-project-optimization-design.md) 的 28 项已全部完成其记录范围内的实施或复验：24 项本机验收、2 项保留的当前环境验收、1 项小米当前环境验收、1 项 Pixel 6 当前环境验收。没有待实施、部分完成或待复验条目。[实施计划](../superpowers/plans/2026-10-19-complete-project-optimization.md) 已同步完成。

改动位于 `perf/complete-optimization-2026-10-19`，基于 `72548df` 的工作区。未自动提交、推送、替换性能参考或删除历史成功/失败证据。每项映射、命令、日志 SHA 和所有改动源码身份见 [机器可读索引](qtrace-project-optimization-2026-10-19.json)。

## 实际结果

- 单调源键使用隐式行号，保留非单调排列、重复检测和原 cache wire。10M/512MiB 同机五轮，冷开中位 7.864685→7.645371 s，峰值 RSS 1159.23→1082.93 MiB，分别下降 2.79% 和 6.58%。新旧缓存互读且无重建。
- 多 artifact 最多两个并发 worker，共享原累计预算。2/4 个100k富artifact前后各五轮，冷开约快40%、热开约快46%，RSS小幅增加；结果顺序、失败隔离和取消保持。线程创建失败和panic会完成join及job收尾。
- 25个IPC命令完成数组、文本、输出、工作与时间预算审计。输出至多16MiB JSON；恶意size hint、u32溢出、输入超限和job堆积提前拒绝。原有四种内存方向可同时使用；最终二进制实际RPC已验证合法组合与第五项拒绝，generation/jobs不变。
- Pixel 6 simpleperf 三档采样后，只消除Full collector的重复只读fallback构造；每回调0x524-byte清零消失，栈临时区0x780降为0x1d0。三档前后各五轮全部满足指令、return、寄存器/内存事实与历史压缩门禁。Full的31→26ms是本批中位数观测，包含其他已验证提取，不声明稳定百分比收益。
- Flight保留512MiB默认及已有64–2048MiB配置，增加启动空间预检。13份实际环占用和每线程窗口调查支持该决定；低空间/EIO注入零遗留，正常关闭/未seal退出可恢复。没有从缺少事件时钟的数据虚构秒级保留窗口。
- 前端拆出导航、详情、持久编辑所有者；修复迟到标注与ELF附加后旧页符号问题。六布局/键盘场景通过；真实Flight 50次点击键和值等价。真实后端5000层/10000根树均完整遍历，IPC每页至多100节点，组件DOM有界。
- CLI事务责任分开并保留公开接口、descriptor/token和原子发布规则；六入口×六故障矩阵通过。Frida清理绑定原session回执，未确认时明确报告cleanup_incomplete。证据工具提供只读inventory和显式opt-in清理，实际旧证据未删除。
- 协议矩阵使用真实C++ encoder与独立Python/Rust读取；增加三类存储fuzz和SQLite VM预算。timeline、index、Flight emergency、JSON endpoint按不变量提取；原行为与ABI保留。

## 验证结果

| 检查 | 最终结果 | 证据 |
| --- | --- | --- |
| Rust workspace | 520通过、2环境依赖ignored，exit0 | `artifacts/complete-optimization-2026-10-19/rust-final.log` |
| Rust Clippy / format / generated | 全部exit0 | 同目录 `clippy-final.log`、`format-final.log`、`generated-final.log` |
| Python全量 | 858项检查，OK，8 skipped，exit0 | 同目录 `python-final-recheck.log` |
| Native与Android | 45/45；app unit+assemble、tracer assemble+copy；BUILD SUCCESSFUL | 同目录 `native/gradle-final-integration-retry.log` |
| 前端 | 76 unit、14 E2E、1 production；build/lint通过 | [前端证据](qtrace-ui-layout-state-2026-10-19.json) |
| 协议矩阵 | 37 corpus成员；Python16、Rust25通过；encoder重复产物一致 | [协议证据](qtrace-protocol-fuzz-2026-10-19.json) |
| Fuzz/property | 五target ASan925984输入，结构后Flight324353输入；零crash；6 property测试含64case | 同上 |
| 实际保留产物 | 4/4完整provider/store/分页/分析/cache重开核对，4/4真实浏览器交互与restart，零API/page错误 | 同目录 `offline/summary.json`、`browser/browser-captures-result.json` |

四份保留产物为offset-v2 987、symbol 987、monitor-exit 1714及Flight crash 1,185,909事件。原始SHA、context、completeness与逐事件事实保持。寄存器共享、调用树共享及关闭后的Arc释放由Rust测试证明，浏览器关闭后旧workspace查询失效。

## 各项证据

| 范围 | 报告 |
| --- | --- |
| STORE-01/02、SCALE-01/02、QA-02、UI-01/02后端、index提取 | [Store与资源边界](qtrace-store-boundaries-2026-10-19.md) |
| UI-01–05、UI-08、MAINT-02 | [前端布局与交互](qtrace-ui-layout-state-2026-10-19.md) |
| CORE-01/02 | [Tracer与Flight](qtrace-native-optimization-2026-10-19.md) |
| CLI-01/02、OPS-01 | [CLI所有权、故障与保留](qtrace-cli-optimization-2026-10-19.md) |
| PROTO-01、QA-03 | [协议与fuzz](qtrace-protocol-fuzz-2026-10-19.md) |
| MAINT-01 | [模块边界与行为保持](qtrace-module-boundaries-2026-10-19.md) |
| 本轮已存在的PERF-01/02、QA-01、UI-06/07/09/10、PERF-03 | 原清单对应的历史报告继续保留，本轮集成不把历史数据伪装为新测量 |

本轮性能对比均为本机诊断，正式性能参考保持原SHA和门槛。小负载RSS测量曾受测量父进程历史HWM影响，已保存失败方法并在干净进程中重测，最终报告区分原始与校正样本。

范围为当前Linux/Chromium、固定Pixel 6目标与已保留的小米产物。200%等效布局不声称原生浏览器/操作系统缩放、WebKit或屏幕阅读器通过；host Flight恢复不声称设备掉电耐久性。托管CI已配置，未因完成本地任务而自动推送或声称远程执行。
