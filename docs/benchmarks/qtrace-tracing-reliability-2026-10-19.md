# 跟踪可靠性验收（2026-10-19）

本次按 P0、P1、P2 顺序执行。精简机器凭据保存在同目录的 `qtrace-tracing-reliability-2026-10-19.json`；原始日志、截图、QTRB、metrics 和失败实验保存在被 Git 忽略的 `artifacts/appguard-reliability-2026-10-19/`。

最终验收通过：小米 11，原始 PID `10482`、启动时间 `62751889` ticks 保持不变；观察 181.91 秒，连续标题标志 159.95 秒。12 条退出线程均有 QBDI 入口规则记录，原生退出 guard 命中 0 次；25 份 QTRB 与 metrics 严格校验通过，记录 323 条目标指令，原生状态无错误。

## 并发入口与默认规则

普通模式保持物理 hook，由每次调用持有的原始指令跳板进入 QBDI；调用期间不再卸钩、重装或消耗新代理代际。配置替换、退休、fork 和停止仍使用既有代际生命周期。退休时保留的跳板和调用快照允许已经进入的调用安全完成。

双线程主机回归先在旧实现上因 `still_installed` 失败。真机随后发现第二层问题：crash marker 的单会话限制使一个并发线程因 `EBUSY` 回退原生。现改为重叠会话共享信号处理代际，各线程持有独立 marker；首个会话结束不会撤销其他会话的处理器。新回归验证并发创建、按故障线程写入、两种完成顺序、旧处理器与 fork 的既有语义。另将原生轨迹列表从 16 项扩到状态协议已支持的 256 项，避免把新增并发轨迹遗漏在验收之外。

持久 hook 还需处理 VM 内部的入口回跳。ARM64 回归先捕获到目标轨迹混入 hook 分支，修复后内部回跳也进入保留的跳板。普通入口规则在原始指令执行前按逻辑地址评估。

**采集边界：跳板重定位的入口指令不计入目标指令轨迹。** `hook-gateway` 事件明确声明这个边界，入口规则通知没有解码指令、助记符或对应的 POSTINST。113 条原生指令的短函数在本探针上记录 112 条目标指令；少的一条由跳板执行，不能宣称已完整采集全部原生指令。

通用 `user_code_rules.cpp` 现在为空。自定义策略必须显式选择 `QTRACE_USER_RULES_SOURCE`、设置 64 个十六进制字符的 `QTRACE_USER_RULES_SAMPLE_SHA256`，并在原生请求中提供匹配的 `codeRules.enabled=true` 和 `sampleSha256`。正式 CLI 使用 `tracer.codeRules` 与 `target.sha256` 生成此请求。原生调用方负责提供已经验证的样本身份；AppGuard 适配器同时检查安装样本的三个文件哈希、容器头、映射尺寸和两个入口签名。绑定的哈希是磁盘容器身份，不是解包内存区的 SHA-256。

## 启动、身份与定位

游戏适配器复用正式 `FridaInjector`、静态 agent、脱离、安装状态校验及失败进程清理。新增的 `StartupAdapter` 只指定同一部署目录内的原生适配库、入口和模式，原生适配器负责解包识别及策略。旧专用 Frida agent 已删除；旧 `load` 实验入口移除，`engine-qbdi-workers` 保留为当前 `engine` 的别名。`engine-native-workers` 显式选择此前的原生退出线程对照。

无 GNU build ID 的 ELF 默认仍被拒绝；显式设置 `target.sha256` 后，本地与设备提取的 ELF 字节均须匹配。已有 build ID 时，显式哈希也必须匹配。实际安装的 `libcompatible.so` 已通过正式 `TargetResolver` 校验，build ID 为空，SHA-256 为 `e5e27eb73dd1d8a78da9ec7e2d09231bc93de045e98e1a9370f0b4f29eb84f86`。

偏移统一为半开范围 `[startOffset,endOffset)`，运行时地址为模块原点加偏移。ELF 原点来自 linker load bias 加 PT_LOAD 的最小 `p_vaddr-p_offset`；符号地址减同一个 ELF 原点。不同可执行段允许具有不同填充量，段间空洞不当作可执行范围。匿名区域原点由显式注册的 `base` 给出，范围必须处于可读、可执行映射内；容器文件偏移不会自动转换成解包区域偏移。测试覆盖多段、非零原点、重载以及 4 KB／16 KB ELF 布局；真机运行使用 4 KB 内核页，未声称在 16 KB 内核设备上运行过。

## 自动验收与缓冲测量

验收同时要求同一 PID、同一 `/proc/PID/stat` 启动时间、目标窗口焦点、版本限定的标题图像标志，以及连续至少 120 秒的标题采样。PID 复用、标题中断、采样间隔超过 15 秒、原生错误、轨迹或 metrics 不完整均不能通过。截图有 SHA-256 凭据；每份轨迹都严格解码并核对 metrics。标题模板只覆盖本次已验证的界面和宽高比，其他界面需新的已验证模板。

缓冲探针使用同一 113 条原生指令短函数，比较 8／16／64 MiB，每种配置三个独立进程，每进程十次调用。比较完整 hook 调用耗时，排除各进程首次调用；记录进程峰值 RSS、实际缓冲大小、指令数和 producer waits。具体数值见 JSON。小缓冲没有显示稳定的 RSS 或耗时收益，因此保留通用 64／128 MiB 自动默认值。双缓冲由 `mmap` 按需分配，容量不等于常驻内存；不能把 64 MiB 配置直接写成 64 MiB RSS。显式缓冲参数可用于后续长轨迹对比。

| 缓冲（MiB） | 首次 RSS 中位数（KiB） | 复测 RSS 中位数（KiB） | 首次调用中位数（µs） | 复测调用中位数（µs） |
| --- | ---: | ---: | ---: | ---: |
| 8 | 42892 | 43036 | 4042.813 | 3561.927 |
| 16 | 42960 | 43064 | 4249.531 | 4092.136 |
| 64 | 42620 | 43056 | 3632.396 | 4091.250 |

调用时间排序在两组间变化，结果不足以证明全局默认值应降低。

仍保留资源上限：每进程 crash marker 代际最多 1024 个，单会话状态最多 256 个轨迹名。达到上限或其他设置失败会使验收失败；本轮证据不证明无限期运行、所有设备或所有故障条件下都没有覆盖缺口。

## 复现

```bash
python3 scripts/appguard_dgup/build.py --ndk /path/to/android-ndk
uv run --with frida==17.24.2 --with pillow python scripts/appguard_dgup/run.py \
  --serial 2d32ed71 --mode engine --seconds 180 --handle-startup-prompts \
  --output artifacts/appguard-reliability-run
```

设备需有匹配的 Frida server。上述命令验证已安装的固定样本，会停止并重新启动目标游戏，不清除游戏数据。默认 `engine` 将两个入口均交给 QBDI；验收摘要还要求实际出现策略规则和退出线程规则。

```bash
NDK_CLANG=/path/to/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android28-clang++
"$NDK_CLANG" -O2 -g -fPIE -pie -nostdlib++ -Wl,-z,max-page-size=16384 \
  tracer/src/test/device/persistent_hook_probe.cpp -ldl -o out/appguard-dgup/persistent-hook-probe
python3 scripts/persistent_hook_acceptance.py --serial 2d32ed71 \
  --probe out/appguard-dgup/persistent-hook-probe \
  --tracer out/appguard-dgup/libqbdi_tracer.so \
  --companion out/appguard-dgup/libshadowhook_nothing.so \
  --calls 10 --repeats 3 --output artifacts/persistent-hook-probe
```

探针需要 Root 和已安装的演示包 `com.aprz.qbdiandroid`，只启动独立原生进程。自动检查两个不同 TID 的轨迹、VM 内入口回跳及缓冲配置，保留原始凭据，并清理本轮可执行文件及部署库。
