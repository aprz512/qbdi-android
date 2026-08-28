# qtrace 历史 Benchmark Gate 修复设计

**日期：** 2026-08-28

**状态：** 方案 A 已批准，等待实现计划

**范围：** Task 8 rooted-device acceptance 的历史 benchmark 身份、隔离构建与双 APK 阶段；不改变通用 `qtrace` 外部应用工作流

## 1. 决策

历史性能行、语义 oracle 和原始 target SHA-256 保持不可变。验收从固定提交隔离构建历史
APK，用可复现的 canonical runtime identity 判断 target，再用当前 tracer 候选运行历史性能门。
完成后安装当前 APK，并以同一份 tracer/companion 快照运行 Task 8 fixture gate。

这份设计取代 Task 8 brief 中“安装当前 APK 后立即比较历史 baseline”的冲突顺序。README
关于 `--compare` 必须使用历史 workload、不得用 APK 漂移改写 baseline 的规则继续有效。

## 2. 背景与身份模型

历史 baseline 的原始 target SHA-256 是：

```text
5f1a970825ae8bacb17d8dd656e01bd1fe7172638ba3ddcacd82ffaaad6e62c0
```

它继续作为生成原始报告时的审计证据，不再作为跨 worktree admission oracle。Debug ELF
保留绝对构建路径，GNU build ID 也随路径改变；两个独立目录中的 `2d6b102` 构建分别产生
不同 raw SHA，但 benchmark offset 都是 `0x6e828`。

Canonical identity 只去除不参与 Android runtime 执行的 debug 信息和 build ID。使用 NDK
`26.1.10909125` 的 `llvm-objcopy`，命令和顺序固定为：

```text
llvm-objcopy --strip-debug --remove-section=.note.gnu.build-id INPUT OUTPUT
sha256(OUTPUT)
```

两个独立历史构建经过该过程后字节完全一致。唯一接受值是：

```text
0d8e856c819fb3cd7ae5917053172b4b75a7924784c43e09cb2855a298647169
```

工具必须来自：

```text
$ANDROID_HOME/ndk/26.1.10909125/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-objcopy
```

缺失、不可执行或版本路径不同均在 target spawn 前失败。Canonicalization 在私有临时文件上
运行，不改 APK 或其解出的原始 ELF。pre-Task8 与 Task 8 target 的 canonical identity 均已
确认不同于历史 workload identity。

## 3. Baseline 与报告契约

`docs/benchmarks/binary-trace-baseline.md` 保留所有历史性能行、offset、首尾指令、return 和
`Target library SHA-256`。新增：

```text
Target library canonical SHA-256 = 0d8e856c819fb3cd7ae5917053172b4b75a7924784c43e09cb2855a298647169
Historical target commit = 2d6b1022a14ae554804a57e267544c12dea29353
```

`benchmark_trace.py --compare` 在 warmup 前比较 canonical SHA。Raw SHA 只进入报告，不影响
判定。报告键固定为：

- `installed_apk_sha256`：设备 `base.apk` 的 raw SHA；
- `target_library_sha256`：设备 APK 内 target 的 raw SHA；
- `baseline_target_library_sha256`：第 2 节的历史 raw SHA；
- `target_library_canonical_sha256`：设备 target canonical SHA；
- `baseline_target_library_canonical_sha256`：canonical admission oracle。

新增 CLI 参数 `--expected-installed-apk-sha256 <64-lowercase-hex>`。Task 8 harness 在
`--compare` 时必须提供它；benchmark 读取设备上唯一 `base.apk` 后要求 raw APK SHA 与本地
held snapshot 一致。普通手工 benchmark 可以省略该参数，但 canonical target gate 不可省略。

Canonical gate 通过后仍执行现有 warmup oracle：complete footer、事件数、return、首尾指令
必须与历史 profile 完全一致，之后才开始五次 measured runs。

## 4. 历史源码快照与隔离构建

新增 acceptance-only 模块 `scripts/qtrace_historical_benchmark.py`。它只接受仓库根目录和固定
commit，不接受分支、tag 或用户拼接的 revision。先用 `git cat-file` 确认对象存在且类型为
commit，再以 argv、无 shell 方式运行：

```text
git archive --format=tar 2d6b1022a14ae554804a57e267544c12dea29353 --
  app build.gradle settings.gradle gradle.properties gradlew gradle/wrapper
```

不自动 fetch；shallow clone 缺少对象时 fail closed。Archive 最大 8 MiB。解析后的约束是：

- 最多 256 个成员、所有 regular-file 内容合计最多 8 MiB、单文件最多 2 MiB；
- UTF-8 路径最多 512 bytes、最多 32 个 component；
- 只允许上面列出的 root 文件、`app/**` 和 `gradle/wrapper/**`；
- 拒绝 absolute、空 component、`.`、`..`、反斜线、NUL、重复路径和 file/directory collision；
- 只允许 directory 与 regular file；拒绝 symlink、hardlink、device、FIFO 和 sparse member；
- extraction 通过 held 0700 root dirfd、`openat`、`O_NOFOLLOW|O_EXCL` 完成；目录归一为
  0700，普通文件 0600，只有 `gradlew` 为 0700。

历史构建在该私有 root 中运行：

```text
./gradlew :app:assembleDebug --no-daemon --offline
```

超时 900 秒，stdout/stderr 各最多 4 MiB。当前 APK/tracer build 先完成，因此需要的相同 Gradle
依赖已进入 cache；offline 缺依赖直接失败。构建不得修改 shared checkout。

输出 APK 必须是 nonempty、nofollow regular file，最大 128 MiB。把它复制到 held 0700
snapshot root，记录 fd identity、size 和 SHA，并在每次把 pathname 交给 adb 前后重新校验。

## 5. APK 与 target 验证

安装前必须验证 held historical APK：

- pinned build-tools `35.0.0/aapt2` 报告 package 恰为 `com.aprz.qbdiandroid`；
- ZIP 最多 4096 entries，累计 uncompressed size 最多 512 MiB，单 entry 最多 128 MiB；
- 恰有一个 `lib/arm64-v8a/libdemo_target.so`，没有其他 ABI 的同名 target；
- target nonempty 且不超过 64 MiB，ZIP CRC/size 必须匹配；
- raw target SHA 被记录，canonical SHA 必须等于第 2 节的完整 canonical acceptance value。

`adb install` 只接收 held APK pathname。安装前后验证同一 fd/path/size/SHA。benchmark 随后
读取设备上唯一 `base.apk`，要求 whole-APK SHA 等于 held APK SHA，再执行 raw/canonical target
报告与 canonical gate。任何 mismatch 都发生在 warmup 和 measured runs 之前。

## 6. 两阶段验收顺序

Host 阶段：

```text
nativeHostTest -> full Python tests -> build current APK/tracer/companion
-> snapshot current APK and one current tracer+companion pair
-> build/validate historical APK
```

Device 阶段严格为：

```text
install historical APK
-> force-stop
-> stage held current tracer+companion pair
-> historical benchmark --compare (5 fast runs)
-> install current APK
-> force-stop
-> restage the same held tracer+companion pair
-> start/wait timed baseline
-> timed offset
-> timed symbol
-> monitor-exit
-> flight-crash
-> pull latest
-> pull name
-> pull all
-> pull all --compressed-only
```

Tracer 与 companion 在第一次 device install 前各 snapshot 一次；两个阶段复用同一 held bytes
和 SHA，不从 mutable build output 重新读取。当前 APK 成功安装并 force-stop 后才允许开始
fixture。历史阶段任一失败都会终止 gate，不运行 semantic-only fallback。

历史 APK 一旦安装，就注册 bounded recovery：force-stop、安装已 held 的当前 APK、再次
force-stop。主失败仍是顶层 cause；recovery、staging、descriptor、temporary-tree cleanup 的
每个失败都追加到同一诊断。若恢复失败，报告明确设备可能仍安装历史 APK。

## 7. 模块与接口

**Create `scripts/qtrace_historical_benchmark.py`**

`HistoricalBenchmarkApk` 是 dataclass，字段为 `path: Path`、`apk_sha256: str`、
`target_raw_sha256: str` 和 `target_canonical_sha256: str`；它提供
`verify_path() -> None` 与 `close() -> None`。构建入口固定为
`build_historical_benchmark_apk(repository: Path, *, deadline: float) -> HistoricalBenchmarkApk`。

该模块拥有 archive validation、safe extraction、historical Gradle build、host APK validation
和 held snapshot。它不被 `qtrace/` import。

**Modify `scripts/benchmark_trace.py`**

新增 `InstalledTargetIdentity`，让 `verify_installed_target_library()` 返回 APK raw SHA、target
raw SHA 和 target canonical SHA。Baseline parser 要求 canonical row；rendered report 使用第
3 节固定键。Canonical mismatch 与 expected APK mismatch 是 distinct、稳定的 pre-warmup
错误。

**Modify `scripts/qtrace_device_acceptance.py`**

`run_acceptance()` 增加可注入的 `historical_builder`，生产默认使用上述 builder。把当前
APK 与 tracer pair snapshot 生命周期提升到两个 APK phase 外层，并执行第 6 节顺序和
recovery。

**Modify tests/docs**

- `scripts/tests/test_qtrace_historical_benchmark.py`：archive、path、type、count/size、APK、
  canonicalization 与 cleanup；
- `scripts/tests/test_benchmark_trace.py`：raw-vs-canonical、APK binding、pre-warmup gate 和报告；
- `scripts/tests/test_qtrace_contracts.py`：两阶段命令顺序、same-pair restage、故障矩阵；
- `docs/benchmarks/binary-trace-baseline.md`：新增 canonical identity，不改历史数据；
- `README.md`：记录 canonical 定义和两 APK rooted gate。

## 8. 有界执行、证据与失败语义

每个 git、Gradle、aapt2、llvm-objcopy、adb subprocess 使用现有 PID-namespace containment 和
绝对 deadline。每次 archive/APK/ELF read 都有 byte cap，并只从 held nofollow root 读取。
Canonical output 必须是 nonempty regular ELF 且不超过 64 MiB。

失败目录保留一个有界 JSON report：当前 phase、commit、archive manifest/hash、command
return/stderr、host/device APK SHA、raw/canonical target SHA、tracer pair SHA 和全部 cleanup
错误。证据写入临时文件后原子发布。成功路径 exhaustive close/unlink；失败路径保留报告并
打印准确目录。Cleanup 共享既定 deadline，不覆盖 primary failure。

## 9. 测试与验收

按 RED→GREEN 实现。测试必须证明：

- 只改 debug 路径/build ID 的两个 ELF raw SHA 不同、canonical SHA 相同；任一 runtime byte
  mutation 使 canonical gate 失败；
- malicious tar/ZIP corpus 的每个边界都在 extraction/install 前失败；
- canonical、package、ABI、APK binding 任一缺失或 mismatch 都不会调用 warmup；
- fake runner 只有第 6 节顺序能通过，并能识别 second-stage 漏装、漏 force-stop、重新读取
  mutable tracer 或 silent diagnostic fallback；
- 每个 build/install/stage/compare 边界的 primary 与全部 cleanup failures 同时可见；
- 完整 Python、native host、Kotlin/Gradle tests 通过。

最终必须在真实 Pixel 6 rooted gate 上确认：历史 canonical/whole-APK binding 通过、历史
warmup 与五次性能比较通过、当前 APK 随后完成 timed/exit/crash/pull 全矩阵。没有真实设备
成功证据时状态只能是 pending。

## 10. 明确拒绝的替代方案

- **改写 immutable baseline：** 会把历史性能行错误归属给新 target。新 workload 只能创建
  新版本 baseline，不能修改本文件的历史证据。
- **semantic-only benchmark：** README 已定义无 `--compare` 仅为诊断，不能替代性能 gate。
- **只供应 app-private historical SO：** admission 验证的是已安装 `base.apk`，且 Java/JNI、
  package 和 target 必须来自同一历史 workload；旁加载 SO 不能证明这些条件。

本修复不修改 `qtrace` config、session orchestration、外部 APK installer、Task 7 adapter 或
通用 artifact path；所有 historical commit、demo package 与 benchmark fixture 知识只存在于
acceptance/benchmark 专用模块。
