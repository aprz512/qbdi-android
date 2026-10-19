# Qtrace UI 布局、状态所有权与交互复验

2026-10-19，分支 `perf/complete-optimization-2026-10-19`，共享未提交工作区。本轮保留已有 UI-06 `TimelinePages`、`SegmentCache` 和 `timeline_pages.mjs` 的实现及负载。完整命令、文件 SHA256、原始布局数据、50 次点击样本、调用树和真实事件验证均保存在 [机器可读报告](qtrace-ui-layout-state-2026-10-19.json)。

UI-08、MAINT-02 及本轮分配的 UI-01–05 前端复验均已完成。最终实现通过 76 项单元测试、14 项工作区和重启 E2E、1 项生产桥接隔离测试、构建及 ESLint。六个布局场景、50 次真实事件点击、真实 Flight 交互和真实 ELF 附加均通过。最终重新编译的服务还通过四份保留产物的实际浏览器回归，全部没有 API 或页面错误。

## UI-08：先检查，再调整

基线使用实际 Chromium 与认证 Rust 服务，分别检查 800、1024、1366 px 视口，以及对应的 200% 等效布局。等效缩放使用 400、512、683 CSS px 和 DPR=2，不等同于实测浏览器原生缩放。基线三个放大场景的文档宽度都被固定在 800 px，详情栏 `scrollWidth` 为 1730 px，栏内宽度只有 279 px；原布局也缺少面板直接跳转入口。

现在宽屏保持三栏；1100 px 以下将时间线放在整行，导航与详情在后；700 px 以下顺排。过滤器、artifact 按钮、输入框和底部面板可换行。原始字段与长标注换行；调用树视觉缩进有上限，长名称截断但保留完整 `title` 和 ARIA 层级。时间线的固定列保留在内部横向滚动区域，各列单独裁剪，完整摘要继续由标题和可访问名称提供。`ResizeObserver` 更新视口与 canvas 尺寸，避免尺寸改变后继续按旧宽高绘制。没有加入拖拽 dock。

布局检查的六个场景均无页面横向溢出，详情栏也无横向溢出。四个键盘快捷入口均用 Tab、Enter 实际到达面板，且 `:focus-visible` 和实线轮廓可见。截图和基线位于 `artifacts/ui-layout-state-2026-10-19/{baseline,layout-integrated}`。

## MAINT-02：请求由明确的所有者管理

`App.tsx` 现在为 75 行，负责组合界面、工作区状态和 jobs。`useTimelineNavigation` 管 projection、分页、跳转和历史，继续复用 `TimelinePages` 的共享请求与有界缓存；`useEventDetails` 管详情、寄存器、内存和调用树读取；`usePersistentEdits` 管标注读取与按字段提交。

`RequestScope` 统一当前请求与已失效请求的判断。切换、关闭、后续选择、取消和卸载后，旧成功响应与旧失败均不能提交到当前界面。标注的 comment 与 highlight 各自保留提交所有权，迟到读取不会覆盖已经保存的字段。编辑器在选择改变时重建，并拒绝早先保存的迟到完成或错误。

原有 69 项前端测试在重构前通过。新增四项标注竞态测试均能发现原实现的问题。独立临时 fixture 中，原版编辑器的两项测试失败；原版 App 搭配同版 SegmentCache 的两项标注和一项 ELF 刷新测试也在对应行为断言处失败，没有替换正在工作的组件。较早一次 App 存档混用了旧 App 与新缓存 API，不能作为行为回归证据，已在机器报告中明确排除。重构后 76 项测试通过；最终 ELF 刷新加入后，14 项工作区和重启 E2E、1 项生产测试重新执行，全部通过。

ELF 附加暴露了另一处缓存问题：后端已有 projection 会返回新符号，但前端仍持有附加前的页面。新增 `refreshSymbols` 在原 workspace/projection/generation 仍匹配时清空该 projection 的页面缓存，并重查当前范围，保留过滤器、选择和历史。正向回归在修复前失败；另外两项回归证明迟到 Attach 不会清空替换后的工作区或 projection。

## UI-01–05：真实交互与规模边界

- UI-01：保留小米 Flight 包含 1,185,909 个事件。最终协调静默窗口连续 50 次点击覆盖 10 个事件，各重复 5 次；每次稳定键、34 个 before 和 34 个 after 寄存器、68 个 DOM 单元格均一致。寄存器 DOM 延迟 p95 为 902.2 ms，包含自动化、传输、并发详情请求和 DOM 检查；包含详情键校验的完整 UI 延迟 p95 为 922.6 ms。两者均不是纯 Rust IPC 或收益对比。关闭后 UI 清空，旧 workspace 的寄存器查询返回 `workspace.stale`；真正的 Arc 释放由 Rust 生命周期测试单独证明。
- UI-02：实际 `CallTreePane` 浏览 512 层链和 10,000 个根节点。深树发出 511 次单子节点请求，DOM 最多 15 行，展开 p95 33.5 ms；宽树浏览全部 99 次后续分页，DOM 最多 13 行，末项跳转为 9999。长标题保留完整文字，错误 identity 与已卸载树的旧响应被拒绝。这是前端合成诊断，不能证明真实 Rust 首次全树构建成本或 IPC 字节数。
- UI-03：真实 Flight 的 instruction、memory、semantic_call、discontinuity 摘要与可访问行名称和 typed detail 对齐，摘要不超过 160 字节，gap 显示明确。新有效 AArch64 ELF 经真实 Attach 和 Resolve 返回 `native_work`；无需新建 projection，时间线自动变为 `native_work+0x5`，稳定键、位置和捕获摘要不变。错误 module digest 被拒绝，已经验证的符号仍可使用。
- UI-04：真实报告的 context 与保留报告完全相等，缺失 profile 继续显示 unavailable。同一 Flight 的独立副本通过固定单文件 picker 打开，context 为 null，界面明确降级且仍可查询；复制没有改变原始产物。已有普通 E2E 另覆盖损坏 artifact 隔离和健康时间线可用。
- UI-05：真实 Flight 超过 2000 个 instruction 命中。双向页面导航和跨页 Previous/Next hit 均匹配真实源行及稳定键；空结果禁用命中导航。故意延迟一个已经从 Rust 读取的真实旧页响应，再关闭、重开工作区，旧响应不能改变新工作区页码、busy 状态或错误。没有替换响应内容。

UI-03 的 E2E bridge 现连接固定白名单 ELF 路由。生产模式继续使用 Tauri bridge。生产门禁原先在本机无监听端口的 IPv4 探测上停滞；改为等待 Vite 的 stdout 就绪信号并启用 `strictPort` 后，生产桥接隔离测试通过。

## 最终服务与保留产物

静默 50 次点击、六个布局场景、Flight 交互、ELF 与 14 项普通 E2E 使用固定 release 副本 `artifacts/complete-optimization-2026-10-19/e2e-server-final`，SHA256 为 `c32d879cafa8a9321471c7c7d7552d339764f220f5d6e1c8908eae24ef4ab8ca`。主代理随后重新编译的当前服务 SHA256 为 `3cce8666d64aed47c6d4ee0025e9d263d39a6a887a8dc5ab216926f470d96c78`；主代理说明后续变更为检查过的 u32 元数据测试入口、单元测试移动及格式，产品执行路径保持一致。本报告仍将延迟数值明确归属于 c32 样本。

将历史 `verify-browser.cjs` 和 `capture-scenarios.json` 原样复制到 `artifacts/complete-optimization-2026-10-19/browser/` 后，使用当前服务顺序复验 offset-v2、symbol、monitor-exit、flight-crash。四份真实产物均通过报告 context、事件总数、instruction 详情、34+34 寄存器、调用树展开/折叠/重展开/跳转、线程过滤、内存与历史、空结果、关闭、服务重启及标注持久化。Flight 另通过双向结果分页和远处最后页。原始历史产物及证据未被覆盖；新结果在该目录的 `browser-captures-result.json`，服务身份在 `service-identity.json`。

## 范围与平台限制

测量平台为当前 Linux/Chromium。没有实测 Tauri WebKit、浏览器原生 200% 缩放、操作系统缩放或屏幕阅读器。前端调用树数字不能替代真实服务的首次构建与 IPC 上限证据；浏览器工作区关闭证明也不能替代 Rust 的 replay Arc 释放证明。

本轮前端实现和验收没有待完成条件。主代理将本报告与独立的服务生命周期、深宽树 IPC 和首次构建证明合并。
