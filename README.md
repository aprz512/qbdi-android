# qbdi-android

面向 Android `arm64-v8a` 的 QBDI 注入式追踪项目。通过 Frida 在应用启动阶段加载 tracer，
由 ShadowHook 接管 native 入口，再用 QBDI 采集指令、寄存器与内存事件。
主机端提供 `qtrace` 命令行和 [qtrace-ui 离线分析器](qtrace-ui/README.md)。

```text
Frida spawn 注入 -> ShadowHook 入口 hook -> QBDI 采集
  -> QTRB/LZ4 或 Flight Recorder -> 主机校验与离线分析
```

## 能做什么

- 追踪 native constructor、JNI、libc、计算逻辑与完整性检查场景。
- 使用 `fast`、`balanced`、`full` 三种采集档位，按需记录内存访问与快照。
- 定时采集，或持续监控至应用退出；原生 runtime 负责停止与产物封存。
- 使用持久 Flight Recorder 保留多线程崩溃前窗口，并报告恢复范围与覆盖缺口。
- 通过样本绑定的 CodeRules 扩展实验，使用离线分析器查看轨迹与数据来源。

本仓库用于逆向分析、安全研究和插桩实验。仅支持 Android API 24+ 的 `arm64-v8a`；
示例 APK 与 tracer 面向实验，不作为生产 SDK。

## 快速开始

准备 Python 3.11+、ADB、匹配的 Frida 主机工具及设备端环境、JDK 17、Android SDK/NDK、
CMake 3.22.1 与 3.31.6、Git、主机 C/C++ 编译器和 `lz4`。配置 `ANDROID_HOME`，
以及 `ANDROID_NDK_HOME` 或 `ANDROID_NDK_ROOT`。设备须支持 spawn 注入，且允许 root
或对目标应用使用 `run-as`。
详细要求见[环境准备](docs/usage.md#环境要求)。

在仓库根目录运行设备验收 demo，将 `SERIAL` 替换为设备序列号：

```bash
git submodule update --init --recursive
./gradlew :app:assembleDebug :tracer:copyTracerDebug --no-daemon
adb devices -l
python3 -m qtrace demo --scenario timed --duration 10s --scene-form offset --device SERIAL
```

`demo` 会构建并安装本仓库 fixture，再走统一的采集流程；默认报告和产物写入 `qtrace-output/`。
QBDI 从固定版本的 submodule 源码编译；首次构建需要联网下载并编译 LLVM 等依赖，耗时明显长于增量构建。
先执行上面的 Gradle 构建，避免首次编译超过 CLI 默认的 90 秒 setup/build 时限。
依赖同步、版本升级与回退见[QBDI 源码依赖](docs/development.md#qbdi-源码依赖)。
查看结果时，优先在 [qtrace-ui](qtrace-ui/README.md) 中打开 session report。

追踪外部应用时，按[使用指南](docs/usage.md#qtrace-命令行)编写 `target.json`，再运行：

```bash
python3 -m qtrace run --config target.json --duration 30s --device SERIAL --output results
```

## 文档导航

| 需要做什么 | 文档 |
| --- | --- |
| 配置 CLI、采集、拉取、转换与排障 | [使用指南](docs/usage.md) |
| 调整 Frida 脚本、部署 tracer 与定位入口 | [手动追踪](docs/manual-tracing.md) |
| 理解模块职责、会话、配置协议与追踪边界 | [架构与设计](docs/architecture.md) |
| 构建、主机测试与设备发布验收 | [开发与验证](docs/development.md) |
| 查看历史性能摘要、复现 benchmark | [性能与基线](docs/benchmarking.md) |
| 使用或开发离线桌面分析器 | [qtrace-ui](qtrace-ui/README.md) |

格式规范、专题说明、历史设计与实测证据统一见[文档目录](docs/README.md)。

## 项目结构

```text
app/         Kotlin 演示 APK、native 目标库与验收 fixture
qtrace/      Python CLI、设备与 session 编排、产物发布
tracer/      QBDI tracer、ShadowHook、QTRB 与 Flight Recorder
scripts/     手动注入、拉取转换、benchmark 与验收工具
qtrace-ui/   Tauri 离线桌面分析器
docs/        使用、设计、开发、格式与历史证据
```

## License

见 [LICENSE](LICENSE)。第三方组件遵循各自许可证。
