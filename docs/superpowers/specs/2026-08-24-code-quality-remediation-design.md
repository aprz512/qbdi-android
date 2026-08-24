# 代码质量问题修复设计

**日期：** 2026-08-24

**范围：** JNI 调用元数据、字符串与状态安全、Native 测试接入、场景配置一致性和 Release 构建安全性

## 目标

修复代码质量审查确认的七项问题，同时保留现有 JNI 追踪能力：

1. JNI 地址映射不得引用已销毁的函数表元素。
2. JNI 句柄和目标进程地址不得被不受保护地直接解引用。
3. JNI 状态查询结果在线程解锁后仍然有效。
4. JNI 地址映射初始化不存在数据竞争或不安全发布。
5. Native Host CTest 可通过明确的 Gradle 任务运行，并覆盖新增 JNI 单元测试。
6. `spawn_trace.js` 与 `trace_config.js` 的演示场景偏移保持一致。
7. Release APK 不再标记为 debuggable，Debug 构建继续支持注入和调试。

## 总体方案

采用小型模块化修复。把 JNI 函数元数据的拥有关系和地址索引从调用处理器中分离为可独立测试的注册表；状态查询返回值对象；格式化器只通过安全内存读取接口读取真正的 C 字符串，不尝试把 JNI 引用当作字符地址。

不重构无关的调用追踪、二进制格式、QBDI 执行或飞行记录器逻辑。

## JNI 函数注册表

新增 `JniFunctionRegistry`，由它拥有 `std::vector<JniFuncInfo>`，并维护地址到表元素的只读索引。注册表完成构建后不再改变底层容器，因此索引中的指针在注册表整个生命周期内稳定。

注册表提供两类窄接口：

- 构建阶段将函数名对应到解析出的地址；
- 运行阶段按调用目标地址查询 `const JniFuncInfo *`。

`call_handlers.cpp` 使用函数局部静态注册表和 `std::once_flag`。第一次 JNI 调用通过 `std::call_once` 完成 `dlsym`、JNIEnv vtable 和 JavaVM 后备解析；初始化成功发布后，调用热路径只进行只读查询。即使多个线程同时遇到首次 JNI 调用，也只有一个线程执行构建，其余线程在完成后观察到一致状态。

初始化不设置可竞争的普通布尔标志。注册表构建过程中产生的日志计数由构建结果直接提供。

## JNI 状态所有权与并发

`JniState` 的查询接口从 `const char *` 改为 `std::optional<std::string>`。每次查询在互斥锁保护下复制值，调用方持有自己的字符串对象，后续插入、擦除或哈希表扩容不会使其失效。

更新接口继续在内部加锁。格式化器和方法签名解析调用方适配值语义，不在锁外保存状态容器内部地址。

并发回归测试会让读写线程反复更新并查询同一标识，并验证返回副本在后续状态变化后保持原值。

## 安全字符串读取

原始地址读取统一建立在 `safe_read_memory` 上：按固定大小或单字节读取到本地缓冲区，遇到 NUL 终止，并限制最大长度。格式化代码只使用本地 `std::string`，不返回目标地址中的字符指针。

按 JNI 类型区分处理：

- `FindClass`、方法名、签名、`RegisterNatives` 字段等真正的 `char *` 使用安全 C 字符串读取。
- `GetStringUTFChars` 返回的 modified UTF-8 字节指针可使用安全 C 字符串读取。
- `jstring` 是不透明句柄，只从 `JniState` 查询已经捕获的内容，不直接读取句柄地址。
- `NewStringUTF` 从入口的 UTF-8 参数更新状态。
- `NewString` 和 `GetStringChars` 使用 UTF-16 数据；在没有可靠长度和转换路径时不把它们伪装成 UTF-8。`NewString` 状态更新先停止错误读取，后续若需要展示 UTF-16 内容应单独设计转换。

无法安全读取、没有 NUL 终止或包含不允许控制字符时，格式化器省略元数据，而不是崩溃或输出未经验证的数据。

## 测试与构建接入

Native Host CTest 增加以下测试：

- 注册表拥有函数信息且源临时表销毁后查询仍有效；
- 注册表重复地址和未知地址行为明确；
- `JniState` 查询返回独立副本，并覆盖并发读写；
- JNI 格式化器不会解引用未知 `jstring`，能格式化状态中已有字符串；
- 安全 C 字符串读取覆盖有效、不可读、未终止和控制字符输入。

测试按红—绿—重构执行，每项生产改动之前先加入会因现状失败的用例并确认失败原因。

在根 Gradle 构建中新增 `nativeHostTest` 任务：使用独立 Host CMake 构建目录配置、编译并执行 `ctest --output-on-failure`。它不会伪装成 Android JVM 单元测试，也不改变 `testDebugUnitTest` 的语义。README 的验证说明改为使用该任务，避免把 `NO-SOURCE` 当作 Native 测试成功。

## 配置和发布安全

`scripts/trace_config.js` 的 integrity 演示偏移同步为 `0x6E584`，与注入脚本当前的已解析偏移一致；benchmark 保持 `0x0`，表示仍需按构建解析。增加脚本契约测试，防止两份共享场景配置再次漂移。

`app/build.gradle` 明确设置 `release.debuggable false`。`debug` 继续保持 `debuggable true` 和 `jniDebuggable true`，作为设备注入、符号调试和演示构建。

## 警告清理

删除未使用的 `has_buffer_arg`，并在 `format_leave` 中显式处理未使用的 `tid` 参数，或在不破坏公共接口的前提下移除该参数。优先保持调用接口兼容，使用命名省略或显式 `(void)tid`。

## 验收标准

- 新增 JNI 测试在修复前按预期失败，修复后通过。
- 完整 Native Host CTest 通过，且无新增编译警告。
- 完整 Python unittest 通过。
- Gradle `nativeHostTest` 可从仓库根目录执行并真实运行 CTest。
- Tracer Debug Native 构建通过。
- 配置契约测试确认共享场景偏移一致。
- Gradle 配置确认 Release 不可调试，Debug 仍可调试。
- `git diff --check` 无错误。

完整 Android APK 构建若再次停滞于 Kotlin 编译，将如实记录为未确认，不用其他测试结果替代该结论。
