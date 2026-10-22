# 开发与验证

[项目首页](../README.md) · [文档目录](README.md)

构建、主机测试、设备门禁和配置验收从仓库根目录执行。首次环境准备见[使用指南](usage.md#环境要求)。
分析器的 Rust、前端、打包与性能检查见[qtrace-ui 开发指南](../qtrace-ui/docs/development.md)。

JNI 解码或执行 ABI 变更还需运行[独立 arm64 设备准入](jni-abi-acceptance.md)，
保存同输入原生/traced 对照、调用文本、产物 SHA 和清理终态。Host 测试不替代真实设备证明。

## 构建

`:tracer:copyTracerDebug` 在构建前采集 native 输入身份，完成后比较源码是否改变，并为两个实际 SO 写出 `out/arm64-v8a/build-identity.json`。输入包含 tracked/untracked 的 native 文件、本地差异、QBDI submodule revision、相关构建参数及可用的 CMake cache。构建期间源码变化时拒绝发布身份；记录的是本轮构建与字节的关联，不代替设备 ABI 验收或进程实际加载证明。独立检查和手动部署见[手动追踪](manual-tracing.md#通用手动加载与部署)。

首次构建前初始化源码依赖，并安装两套固定版本的 CMake：

```bash
git submodule update --init --recursive
sdkmanager 'cmake;3.22.1' 'cmake;3.31.6'
```

两套 CMake 的用途如下；tracer 所依赖的 QBDI v0.12.1 最低要求 CMake 3.28。

| 构建范围 | 本仓库固定使用的 CMake |
| --- | --- |
| Android tracer 与 QBDI 引擎 | 3.31.6 |
| 演示 APK 的 native fixture、主机原生测试 | 3.22.1 |

构建演示 APK，并把 standalone tracer 与 ShadowHook companion 复制到 `out/arm64-v8a/`：

```bash
./gradlew :app:assembleDebug
./gradlew :tracer:assembleDebug :tracer:copyTracerDebug
```

主要产物：

```text
app/build/outputs/apk/debug/app-debug.apk
out/arm64-v8a/libqbdi_tracer.so
out/arm64-v8a/libshadowhook_nothing.so
```

当前依赖包括 QBDI 0.12.1 Android AARCH64、vendored ByteDance ShadowHook、LZ4 1.10.0，
以及 vendored nlohmann/json 3.12.0。JSON 单头文件与许可证分别位于
`tracer/src/main/cpp/third_party/nlohmann/json.hpp` 和
`tracer/src/main/cpp/third_party/nlohmann/LICENSE.MIT`。

## QBDI 源码依赖

QBDI 使用[官方仓库](https://github.com/QBDI/QBDI)的 Git submodule，位于
`tracer/src/main/cpp/third_party/qbdi`，固定在 `v0.12.1`
（`09b2efb66d242b3616a4723e4b487f623b0e93d7`）。tracer 通过 CMake 3.31.6
编译并静态链接 `QBDI::QBDI_static`，不再依赖 Git LFS 或提交预编译的 `.a`。
QBDI 引擎始终按 Release 配置构建，避免 Debug tracer 开启引擎逐指令调试日志。

### 初始化与同步

新克隆可使用 `git clone --recurse-submodules`。已克隆的工作副本运行
`git submodule update --init --recursive`，即可检出父仓库记录的 QBDI commit。
之后每次拉取父仓库更新，都同步 submodule：

```bash
git pull
git submodule update --init --recursive
git submodule status -- tracer/src/main/cpp/third_party/qbdi
```

构建版本由父仓库中的 submodule 指针决定；初始化与同步不会自动升级到上游最新版本。

### 构建与缓存

首次 Android 构建会下载上游固定版本并校验哈希的 LLVM 19.1.5、spdlog 1.15.0，
并用主机 C/C++ 编译器构建 LLVM TableGen；需要联网，耗时和磁盘占用较大。
下载与编译产物留在 tracer 的 `.cxx/` 构建目录，不修改 submodule。
后续构建使用增量缓存；删除对应的 `.cxx/` 目录后需要重新准备依赖并编译。
主机测试通过 `tracer/src/main/cpp/cmake/QBDIHeaders.cmake` 从同一个 submodule
生成 Android AARCH64 头文件，不下载或编译 LLVM，也不要求先完成 Android tracer 构建。
协议兼容矩阵使用相同的头文件生成入口，命令见[分析器开发指南](../qtrace-ui/docs/development.md#native-protocol-fixtures)。
首次使用 CLI 或运行设备验收前先完成上述 Gradle 构建，避免冷构建超过流程时限。

### 升级与回退

升级时将下面的 `QBDI_REV` 替换为目标 tag 或 commit，再构建和测试。
头文件与静态库都从所选源码生成，无需另外下载或替换 `.a`。

```bash
QBDI_REV=v0.12.1
git -C tracer/src/main/cpp/third_party/qbdi fetch --tags origin
git -C tracer/src/main/cpp/third_party/qbdi checkout --detach "$QBDI_REV"
./gradlew nativeHostTest :tracer:assembleDebug :tracer:copyTracerDebug --no-daemon
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
git add tracer/src/main/cpp/third_party/qbdi
git diff --cached --submodule=short -- tracer/src/main/cpp/third_party/qbdi
```

确认验证通过后，提交 submodule 指针及所需的兼容性改动。若目标 commit 尚未下载，先在
submodule 中执行 `git fetch origin COMMIT`，将 `COMMIT` 替换为目标提交。
其他工作副本在拉取父仓库更新后运行 `git submodule update --init --recursive`。
回退时将 `QBDI_REV` 设为先前验证过的 tag 或 commit，执行相同的 checkout、构建和测试，
再提交回退后的指针。设备发布前仍需运行下文的手动设备门禁；主机测试和构建成功不代表设备验收完成。

## 主机测试

在已设置 `ANDROID_HOME` 且 Android SDK 安装了 CMake 3.22.1 的主机上运行：

```bash
./gradlew nativeHostTest --no-daemon
```

该任务依次配置、构建并通过 CTest 运行 `tracer/src/test/cpp` 的原生测试；它不依赖 Android JVM 单元测试任务。

普通 Python 单元测试不启动 Gradle，也不要求完整 Android SDK：

```bash
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
```

## 可选主机集成测试

Frida/GumJS adapter 的 host 测试是显式 opt-in；它要求可用的 Frida Python package 和
本机 attach 能力，不属于默认 Python 套件：

```bash
QTRACE_RUN_FRIDA_HOST_TESTS=1 \
  python3 -m unittest scripts.tests.test_spawn_trace_gumjs -v
```

构建契约属于显式集成套件。它会实际运行 Debug/Release manifest 合并、解析合并后的 manifest，并运行 Native Host Gradle/CTest 链；每次 Gradle 子进程有 300 秒 timeout：

```bash
ANDROID_HOME=/path/to/Android/sdk \
python3 -m unittest scripts.tests.build_contract_integration -v
```

JNI 状态的 ThreadSanitizer 回归是显式 opt-in，避免让环境敏感的 sanitizer 影响默认套件：

```bash
cmake -S tracer/src/test/cpp -B build/native-tests-tsan \
  -DQTRACE_ENABLE_TSAN=ON
cmake --build build/native-tests-tsan --target jni_state_tsan_test --parallel 2
ctest --test-dir build/native-tests-tsan -R jni_state_tsan_test --output-on-failure
```

该 opt-in 目标仅面向 Linux host，并通过 `setarch -R` 配合非 PIE 可执行文件固定 TSAN shadow-memory 布局。

## 手动设备发布门禁

下列验收是发布前的手动门禁，**不会**在普通 host CI 中自动运行。它需要明确
指定一台 rooted arm64 设备，以及可用的 ADB、匹配的 Frida host/server、NDK 和 host
`lz4`；脚本拒绝选择默认设备，并以有界的子进程和读操作执行。历史 benchmark 还固定
使用 Android NDK 26.1.10909125 和 build-tools 35.0.0；缺少固定版本工具、历史提交或离线
Gradle 依赖时会直接关闭门禁，不会退化成仅检查语义。

```bash
python3 scripts/qtrace_device_acceptance.py --device SERIAL
```

该门禁先构建并持有本次候选 APK、tracer 和 companion，再从提交
`2d6b1022a14ae554804a57e267544c12dea29353` 私有归档目标源码，以 `--offline` 在隔离目录
构建历史 APK。第一阶段安装历史 APK，并用同一份候选 tracer 执行 binary benchmark
`--compare docs/benchmarks/binary-trace-baseline-v2.md`。新版基线通过同机原生调用与改动前
保存的 tracer 校准正确性，沿用旧版全部速率和每次压缩大小门槛；旧版文档保留不变，仍可
显式传给 benchmark 作历史核查，未知版本直接拒绝。第二阶段重新安装当前 APK、重新部署
同一对 tracer/companion，等待最多 15 秒
的无追踪 timed oracle，再完成 timed offset/symbol 和四种手动 pull，最后验证 monitor-exit
与预期返回 2 的 flight-crash recovery。任一历史构建、身份或 benchmark 失败都属于发布门禁
失败，绝不会回退为仅检查语义。
全部验证和清理成功后，门禁才会将本轮目录原子发布到
`qtrace-acceptance-evidence/<uuid>`，写入一个不超过 64 KiB 的成功 manifest，并打印最终绝对
路径。manifest 绑定本次 HEAD、设备 serial、历史 commit/canonical SHA、当前 APK、tracer、
companion 哈希、八个场景 report、trace 备份路径和 gate 起止时间；任一 manifest、rename 或
目录 fsync 失败都会令门禁失败并保留等价诊断。失败证据保留在
`qtrace-acceptance-failures/<uuid>`。这两个目录均被 Git 忽略，脚本不会自动删除其中内容。

进入当前 fixture 场景前，门禁会先 force-stop 固定 demo 包，严格确认已有的
`files/qbdi-traces` 是真实目录而非 symlink，再将它原子重命名为同级且唯一的
`files/qbdi-traces.pre-acceptance-<uuid>`，随后创建并验证一个全新的 trace 目录，再部署和
运行本轮场景。这样 native status publisher 启动时已有可写根目录，四种 pull 也只验证本轮
fixture 数据；旧目录作为可恢复备份保留，成功或失败后都不会自动删除。该隔离只作用于固定
demo 包，不会访问用户指定的外部 package 路径。

## 配置与 hook 设备验收（opt-in）

部署[手动追踪](manual-tracing.md)中的 Debug APK、tracer 和 companion 后，执行以下检查。
这组检查补充上面的发布门禁，不属于普通主机测试。

在同一台 arm64 设备上执行四次 spawn：

1. 使用 `offset` locator。
2. 改成等价的 `imageBase + address` locator；确认 Frida status 中的 normalized offset 和
   runtime address 与第 1 次一致。
3. 使用可解释但映射可疑的地址；确认 warning 先出现，随后仍有真实 hook 结果。
4. 用下面的专用 harness 在同一进程依次提交 `config.tracer`、malformed JSON `{`，再查询
   第一次返回的 generation；确认输出包含相同 generation、
   `"rejectedCode": "MALFORMED_JSON"` 和 retained terminal/current state。

普通追踪以及第 1–3 项仍使用完全相同的注入命令：

```bash
frida -U -f com.aprz.qbdiandroid -l scripts/spawn_trace.js
```

第 4 项使用同一份 `spawn_trace.js` 配置的 opt-in Python/Frida harness，不复制 scene 配置：

```bash
python3 scripts/config_retention_acceptance.py \
  --package com.aprz.qbdiandroid
```

该 harness 需要 Frida Python package 和 USB device；它只用于验收，不是第二份普通配置源。
主机测试通过不代表已完成这条设备命令。

分别记录 Frida console 和 Logcat 中的 generation、warning/error code；两边应一致。完成运行后
拉取并验证产物：

```bash
python3 scripts/pull_trace.py --package com.aprz.qbdiandroid \
  --output pulled-traces
```

## 性能与证据

独立 native 边界夹具通过 `python3 scripts/build_runtime_probe.py --ndk "$ANDROID_NDK"` 构建。
使用 `python3 scripts/runtime_acceptance.py --help` 选择设备、已构建库、场景 0–10 和既有 canonical guard；
它在唯一自有目录中成对执行 baseline/traced，部署后核对哈希，并以 PID/epoch 证明父子进程清理。
不需要安装或卸载应用。普通与 Flight 的完整性、目标返回和退出状态分别验收。
Flight 生产语料生成目标为 Host `flight_query_fixture`，调用方式为 `flight_query_fixture OUTPUT [GROUPS]`；
公开服务基准为 `cargo run --release -p qtrace-service --example flight_query_bench -- INPUT CACHE open`，
最后一个参数改为 `cancel` 可验证初始阶段取消，`cancel-index` 等待实际索引处理事件后取消，并验证 worker join。
命令在 `qtrace-ui` 目录运行。
容量、占用、资源拒绝和复现范围见[通用优化记录](benchmarks/qbdi-generic-2026-10-21.md)。

[性能与基线复现](benchmarking.md)单独说明设备身份、历史 APK、canonical SHA 和 benchmark 的计时边界。
发布门禁成功与性能诊断是不同结论；历史基线和原始证据保留在 `docs/benchmarks/`。
