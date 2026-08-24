# 中文 README 与代码质量审查实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 面向 Android 逆向与安全工程师完成当前项目的代码质量审查，并交付基于仓库事实和实测基线的中文 README。

**Architecture:** README 按首次实验的任务流组织，复杂格式和验收细节链接到现有 `docs/`。代码审查只检查项目自有代码，通过 CodeGraph、定向源码检查和现有测试收集证据，最终按严重程度报告，不在本任务中修改功能实现。

**Tech Stack:** Android Gradle Plugin 8.5.2、Kotlin 1.9.24、C++20/NDK、QBDI 0.12.1、ShadowHook、Frida、Python 3、LZ4、Markdown

## Global Constraints

- README 使用中文，主要读者是希望直接复现实验的 Android 逆向与安全工程师。
- 支持范围按当前构建配置写为 Android `arm64-v8a`、API 24+。
- 性能引用 Pixel 6、Android 16、Debug、256 次迭代、21,718 条指令、一次预热后五个独立进程中位数。
- 明确 `elapsed_ms` 是追踪热路径指标，不是注入、发布、拉取和转换的端到端耗时。
- 排除 `tracer/src/main/cpp/third_party/` 下的 vendored 依赖质量审查。
- 本任务只修改 `README.md` 和设计/计划文档，不修复功能代码。

---

### Task 1: 建立代码质量审查证据

**Files:**
- Inspect: `app/src/main/`
- Inspect: `tracer/src/main/cpp/`（排除 `third_party/`）
- Inspect: `scripts/`
- Inspect: `tracer/src/test/cpp/`
- Inspect: `scripts/tests/`

**Interfaces:**
- Consumes: `.codegraph/` 索引、当前 `HEAD` 源码和仓库测试。
- Produces: 带严重程度、绝对文件路径、行号、风险和修复方向的审查发现；供最终交付使用。

- [ ] **Step 1: 用 CodeGraph 定位高风险调用链**

Run:

```bash
codegraph explore "审查 tracer 自有代码的配置、hook 安装、QBDI 会话、异步写入、flight recorder、信号处理和进程生命周期；定位资源管理、并发安全、错误传播、边界校验和测试覆盖风险，排除 third_party"
```

Expected: 返回关键符号、调用路径和带行号源码。

- [ ] **Step 2: 检查项目级质量信号**

Run:

```bash
git status --short
rg -n "TODO|FIXME|HACK|XXX|abort\(|std::terminate|detach\(|catch \(\.\.\.\)|except Exception|except:" app tracer/src/main/cpp scripts -g '!tracer/src/main/cpp/third_party/**'
find app tracer scripts -type f -not -path '*/third_party/*' -printf '%s %p\n' | sort -nr | head -30
```

Expected: 获得未完成标记、危险失败路径和超大文件候选；每个候选继续核对上下文，只有可证明的风险进入报告。

- [ ] **Step 3: 运行主机侧测试**

Run:

```bash
python3 -m unittest discover -s scripts/tests -p 'test_*.py' -v
./gradlew :tracer:testDebugUnitTest
```

Expected: 测试通过；环境或依赖导致的失败需记录原始命令和错误，不能声称通过。

- [ ] **Step 4: 整理审查发现**

对每项候选逐一验证：问题能否从当前源码触发、现有测试是否覆盖、影响是否属于项目自有代码。最终只保留包含 `严重程度 / 文件:行号 / 风险 / 修复建议` 四部分的发现；没有发现的维度明确报告为未发现高置信问题。

### Task 2: 重写中文 README

**Files:**
- Modify: `README.md`
- Reference: `docs/trace-format.md`
- Reference: `docs/integrity-bypass.md`
- Reference: `docs/ida-offsets.md`
- Reference: `docs/benchmarks/binary-trace-baseline.md`
- Reference: `docs/benchmarks/flight-recorder-acceptance.md`

**Interfaces:**
- Consumes: 当前 Gradle 任务、脚本 CLI、配置文件、格式文档和性能基线。
- Produces: 能独立指导首次构建、注入、采集、拉取和转换的中文 `README.md`。

- [ ] **Step 1: 写项目介绍、链路和特性**

README 开头写明项目是 Android arm64 QBDI 注入式追踪演示，不是通用 SDK。用一行链路表示：

```text
Frida spawn 注入 → ShadowHook 接管场景入口 → QBDI 执行与采集 → QTRB/LZ4 落盘 → 主机拉取、校验与转换
```

特性覆盖场景追踪、三级配置、异步二进制输出、Flight Recorder、崩溃恢复、信号虚拟化、CodeRules 和完整性实验。

- [ ] **Step 2: 写环境与完整使用流程**

按以下顺序提供可复制命令：

```bash
git lfs pull
./gradlew :app:assembleDebug
./gradlew :tracer:assembleDebug :tracer:copyTracerDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb push out/arm64-v8a/libshadowhook_nothing.so /data/local/tmp/qbdi-android/
adb push out/arm64-v8a/libqbdi_tracer.so /data/local/tmp/qbdi-android/
frida -U -f com.aprz.qbdiandroid -l scripts/spawn_trace.js
python3 scripts/pull_trace.py --package com.aprz.qbdiandroid --output pulled-traces
```

解释场景偏移需要同步更新 `scripts/trace_config.js` 与 `scripts/spawn_trace.js`，并说明构造函数、pthread 和信号网关要求 spawn 注入。

- [ ] **Step 3: 写性能与限制**

性能表使用以下已提交中位数：

| Profile | 中位耗时 | 指令吞吐 | 压缩后大小 |
| --- | ---: | ---: | ---: |
| fast | 16 ms | 1,357,375 条/秒 | 267,939 B |
| balanced | 24 ms | 904,916.67 条/秒 | 362,559 B |
| full | 36 ms | 603,277.78 条/秒 | 379,982 B |

紧邻表格写明设备与指标口径；限制包括 arm64-only、Debug/root 或 Gadget 条件、偏移版本相关、Flight Recorder 默认 512 MiB，以及 `SIGKILL` 只能记录目标发起前的终止意图。

- [ ] **Step 4: 写排障与深入文档入口**

覆盖 jailed Android/Gadget、缺少主机 `lz4`、构造阶段遗漏、私有目录访问和恢复结果完整性判断。链接使用相对路径，并将格式、IDA 偏移、完整性规则、性能基线和 Flight Recorder 验收分别指向现有文档。

### Task 3: 验证 README 与交付结果

**Files:**
- Verify: `README.md`
- Verify: `docs/superpowers/specs/2026-08-24-chinese-readme-and-code-quality-review-design.md`
- Verify: `docs/superpowers/plans/2026-08-24-chinese-readme-and-code-quality-review.md`

**Interfaces:**
- Consumes: Task 1 的测试结果和 Task 2 的 README。
- Produces: 无格式错误、事实可追溯的文档差异和最终审查报告。

- [ ] **Step 1: 校验命令入口**

Run:

```bash
./gradlew tasks --all | rg 'assembleDebug|copyTracerDebug|testDebugUnitTest'
python3 scripts/pull_trace.py --help
python3 scripts/benchmark_trace.py --help
```

Expected: README 与计划引用的任务及 CLI 参数存在。

- [ ] **Step 2: 校验文档事实和链接**

Run:

```bash
rg -n "1357375|904916|603277|Pixel 6|Android 16|21718" README.md docs/benchmarks/binary-trace-baseline.md
rg -o '\]\([^)]*\.md(?:#[^)]*)?\)' README.md
git diff --check
```

Expected: 性能数字可追溯到基线，相对 Markdown 链接对应现有文件，`git diff --check` 无输出。

- [ ] **Step 3: 检查最终差异**

Run:

```bash
git diff --stat HEAD~1
git diff -- README.md docs/superpowers/specs/2026-08-24-chinese-readme-and-code-quality-review-design.md docs/superpowers/plans/2026-08-24-chinese-readme-and-code-quality-review.md
git status --short
```

Expected: 功能源码无改动，README 覆盖介绍、特性、使用和性能，设计与计划文档完整。

- [ ] **Step 4: 提交 README 与计划**

Run:

```bash
git add README.md docs/superpowers/plans/2026-08-24-chinese-readme-and-code-quality-review.md
git commit -m "docs: rewrite README in Chinese"
```

Expected: 提交成功；最终回复列出测试结果、README 变更和按严重程度排序的代码质量发现。
