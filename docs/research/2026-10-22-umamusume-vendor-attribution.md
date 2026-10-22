# 赛马娘保护库厂商归属：公开一手资料核查

核查日期：2026-10-22。结论：**Android 样本 `lib__4e06__.so` 满足 APKiD 公开 `crackproof_a` 规则，已有归类为 CrackProof 的强指纹证据；尚无厂商或 Cygames 对该样本的官方认证。** 具体机器码匹配见[工具指纹归类](#工具指纹归类)。另已确认 CrackProof 的开发厂商为 DNP HyperTech，以及英文版 Steam 官方商店的 CrackProof 标示；Steam 声明仍只覆盖 Windows 产品。

## 核查对象

以下身份来自本轮输入和[本地样本参考](2026-10-22-umamusume-protection-reference.md)。工具指纹一节引用本轮保留的独立字节比对记录，本报告不重复执行设备实验：

| 项目 | 对象 |
| --- | --- |
| 包名与版本 | `com.cygames.umamusume`，英文版 `1.35.2`，versionCode `153` |
| 目标文件 | arm64 split 中的 `lib__4e06__.so` |
| SHA-256 | `160483775aae439b392ff12f0879925b3064cc0b7aff36fa0782efec1d7b59ee` |
| SONAME | `lib__XXXX__.so` |
| Java 入口 | `EntryApplication.attachBaseContext` 经 `util001.framework.load` 加载 |
| 动态镜像线索 | `bool checkLoadPath_extractNativeLibs_true(const char*)`、`jni/checkSystemLib.cpp` |
| 本地目录线索 | `app_4e06` |

## 已证实的公开映射

| 映射 | 一手证据及强度 | 适用边界 |
| --- | --- | --- |
| 英文版 Steam 产品存在 CrackProof 标示 | **直接、强。** [Steam 官方商店，app 3224770](https://store.steampowered.com/app/3224770/Umamusume_Pretty_Derby/)列出开发商和发行商 Cygames, Inc.，并显示 “Uses Kernel Level Anti-Cheat” 与 “CrackProof®”。 | 同页系统要求为 Windows 11；这是当前商店声明，不是 Android 版本、具体模块或实际内核行为的验证。 |
| CrackProof 由 DNP HyperTech 开发 | **直接、强。** [DNP 2017-01-16 官方新闻](https://www.dnp.co.jp/news/detail/1187680_1587.html)明确将 CrackProof 开发者写为株式会社 DNP ハイパーテック。 | 证实品牌开发者；没有提及本次样本。 |
| DNP HyperTech 开发、销售 Android 版 CrackProof | **直接、强。** [DNP 2015-10-16 官方新闻](https://www.dnp.co.jp/news/detail/1187535_1587.html)明确陈述 Android 产品的开发与销售主体，并注明 CrackProof 为该公司商标。 | 历史产品与商标关系；不能证明 Cygames 某个 Android 版本采用它。 |
| CrackProof 有 Android SO 与 DEX 产品 | **直接、强。** [Android SO 官方产品页](https://www.hypertech.co.jp/products/android-so/)说明对包含原生共享库的 AAB/APK 加固；[Android DEX 官方产品页](https://www.hypertech.co.jp/products/android-dex/)说明对包含 DEX 的 AAB/APK 加固。 | 证明产品具备相应平台和对象类型，不提供本次库的指纹映射。 |

这些官方资料确认品牌开发者和产品平台范围。Android 样本的归类依据来自下一节的机器码指纹匹配；不能仅把 Steam 标示移植到 Android。

## 工具指纹归类

[APKiD 上游规则源码](https://github.com/rednaga/APKiD/blob/deb0b623f2a1b9f64f23a72e2c125b63123c60f3/apkid/rules/elf/packers.yara)在固定 commit `deb0b623f2a1b9f64f23a72e2c125b63123c60f3` 定义 `crackproof_a`，描述为 `CrackProof`，并关联 HyperTech 网站。其条件是 `is_elf and $init_proc and $do_asm_syscall and 1 of ($func*)`。这是分类器作者的一手实现，产品归属命名仍来自第三方分类器。

对上述 SHA-256 的原始样本逐段比对六个十六进制模式，[本地机器证据](/home/lyldalek/.codex/worktrees/cd7b/qbdi-android/out/protection-verification-20261022/apkid-fingerprint.json)记录如下。位置均为文件偏移 / ELF 虚拟地址，不是 ASLR 后的进程绝对地址。

| 模式 | 长度 | 通配字节数 | 匹配位置 |
| --- | ---: | ---: | --- |
| `$init_proc` | 132 B | 3 | `0x1d54` / `0x1d54` |
| `$do_asm_syscall` | 52 B | 0 | `0x5e08` / `0x5e08` |
| `$func1` | 28 B | 3 | `0x1ae4` / `0x1ae4` |
| `$func2` | 36 B | 3 | 未命中 |
| `$func3` | 32 B | 3 | 未命中 |
| `$func4` | 32 B | 3 | 未命中 |

记录中的 `is_elf` 为真，两个必选模式和 `$func1` 均命中，因此满足规则条件；`$func2` 至 `$func4` 未命中不影响该条件。随后在 `yara-python 4.5.4` 中编译原始上游规则及 `is_elf` 依赖，对原始库实际运行，确认 `crackproof_a` 命中及上述三个偏移。三个主机缓冲区负对照分别翻转三个必要模式中的一个固定字节，每次均使该规则不再匹配；原文件和设备没有改变。本轮没有运行 APKiD CLI。

**归属判断已从产品候选提升为独立字节比对与原始 YARA 引擎共同复核的 CrackProof 强指纹证据。** 引擎版本、固定规则 SHA、匹配位置及负对照结果见[补证机器摘要](evidence/2026-10-22-umamusume-verification.json)和[原始引擎记录](/home/lyldalek/.codex/worktrees/cd7b/qbdi-android/out/protection-verification-20261022/yara-verification.json)。

该证据不等同于 DNP HyperTech 或 Cygames 的官方样本认证，不识别具体保护版本，也不证明某项检测已经启用或执行。Windows 商店声明不承担此处 Android 指纹匹配的证明作用。

## 样本线索与厂商之间的缺口

本轮对完整 SHA-256、`lib__4e06__.so`、`lib__XXXX__.so` / `lib__XXXX__`、`util001.framework` / `util001.framework.load`、`EntryApplication` 与 `util001` 的组合、`checkLoadPath_extractNativeLibs_true`、`checkLoadPath` 与 `extractNativeLibs` 的组合、`jni/checkSystemLib.cpp` / `checkSystemLib.cpp`、`app_4e06` 进行了公开搜索。没有找到将这些文本标识连接到厂商或产品的厂商/游戏方官方资料；机器码分类证据另见上一节。

另用 Cygames、赛马娘及 DNP HyperTech 官方域名限定检索产品名称、公司/游戏名称及部分样本标识。未找到 Cygames Android 版采用声明、厂商案例、官方源代码或官方模块指纹。搜索覆盖的是公开可检索页面；未命中不能证明资料不存在，也不能排除 CrackProof 或其他产品。

| 线索 | 本轮能够支持的结论 | 不能支持的结论 |
| --- | --- | --- |
| 文件名、SONAME、`util001.framework`、`app_4e06` | 可作为继续寻找官方标识的检索键。 | 没有一手命名规范或指纹对应，不能据此命名厂商。 |
| `checkLoadPath_extractNativeLibs_true` | 其中 `extractNativeLibs` 是 Android 官方定义的打包/加载属性：决定安装程序是否把原生库从 APK 提取到文件系统。[Android 官方文档](https://developer.android.com/guide/topics/manifest/application-element#extractNativeLibs) | 该词本身不能充当某厂商的专属指纹；官方属性语义也不能替代对该函数实际逻辑的分析。 |
| 路径检查、系统库检查、反调试或环境限制等行为 | 可与产品公开功能作进一步对照。CrackProof Android SO 页公开列出 SO 加密、签名检查、调试器阻止及 root/模拟器限制。[官方产品页](https://www.hypertech.co.jp/products/android-so/) | 功能名称相符不构成代码来源证明，也不证明本次样本启用了某项功能。 |

## 厂商官方样本认证的缺口

若要进一步取得官方来源的样本归属证明，还需要能连接本次 Android 样本的证据，例如：Cygames 或厂商明确覆盖该 Android 发行物的采用声明；官方 SDK/受保护示例中可验证的专属标识，并与本次库独立对应；或有来源和版本记录的官方产物，其内部产品标识、构建身份或代码指纹与样本一致。

目前已取得 **本样本满足 CrackProof 公开分类器规则的强指纹证据**，并已确认 **CrackProof 的开发厂商及其 Android 产品存在**。尚未取得该 SHA-256 的厂商官方认证；不能把分类器命中进一步扩展为具体版本、完整检测清单或其他厂商的排除结论。

本报告汇总公开资料、字节比对及 YARA 复核；未修改目标程序或执行检测绕过。设备现状与离线路径函数验证另见[补证报告](2026-10-22-umamusume-verification.md)。
