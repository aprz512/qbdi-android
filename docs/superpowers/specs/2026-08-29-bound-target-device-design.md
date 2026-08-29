# BoundTargetDevice 设计

**日期：** 2026-08-29

**范围：** qtrace 主机端设备选择、目标身份预检、部署、注入与制品收集

## 目标

将“已选择的 ADB 设备”和“已经预检、可以以目标应用身份操作的设备”表示为两个不同的 Module。调用方获得 `BoundTargetDevice` 后，不再需要了解绑定顺序、可空字段或重复验证规则。

保持现有 CLI 参数、输出、错误码和 ADB 命令行为。不保持外部 Python 调用方直接使用 `AdbDevice.bind_package()` 的兼容性。

## 现有问题

`AdbDevice` 当前在构造后处于未绑定状态，`bind_package()` 再将七个可空字段一次性写入实例。这个 Interface 要求调用方了解：

- 哪些方法只能在绑定后调用；
- 绑定字段之间的 UID、Android user、数据目录和策略约束；
- 同一实例允许幂等重复绑定，但拒绝不同身份的再绑定；
- 下游必须处理 `None`，或用 `getattr()` 兼容不完整的测试替身。

`build.py` 因此重新实现了一次完整绑定验证，`session.py` 也重新验证 package data directory。这些重复降低了 Locality，并使状态约束扩散到多个调用方。

## 选定方案

采用独立状态类：

```python
@dataclass(frozen=True)
class TargetBinding:
    package: str
    access_mode: str
    root_strategy: str
    package_uid: int
    target_strategy: str
    android_user: int
    package_data_dir: str


class AdbDevice:
    def bind_target(self, binding: TargetBinding) -> BoundTargetDevice: ...


class BoundTargetDevice(AdbDevice):
    @property
    def binding(self) -> TargetBinding: ...

    @property
    def trace_directory(self) -> str: ...

    def root_shell(self, *args: str, ...) -> bytes: ...
    def target_shell(self, *args: str, ...) -> bytes: ...
    def stream_target_file(self, path: str, output: object, ...) -> None: ...
```

`TargetBinding` 在创建时验证全部不变量。`AdbDevice.bind_target()` 返回一个使用同一 serial 和 runner 的新 `BoundTargetDevice`，不修改原 `AdbDevice`。`BoundTargetDevice` 的身份信息由冻结的 `TargetBinding` 持有，只通过非可空属性暴露。

`BoundTargetDevice` 复用 `AdbDevice` 中已验证、有界的通用 ADB 操作。仅有依赖目标身份的方法移入它的 Interface。这个 Module 隐藏身份路由和命令组合，为 deploy、inject、session 和 artifact 调用方提供更高的 Depth 和 Leverage。

## 不采用的方案

### 返回新的 AdbDevice 副本

这个方案可以避免就地修改，但一个类仍然同时表示已绑定和未绑定状态。目标方法仍需要运行时未绑定检查，Interface 没有实质变小。

### 泛型类型状态

`AdbDevice[Unbound]` 和 `AdbDevice[Bound]` 能够提供静态提示，但运行时仍是同一类和同一组可空字段。当前项目也没有强制静态类型门禁，因此这会增加类型复杂度，但不会相应改善运行时 Interface。

## 数据流

```text
DeviceSelector.select()
  -> AdbDevice
  -> Preflight 完成 package、root、run-as/su-uid、UID 与 user 验证
  -> TargetBinding
  -> AdbDevice.bind_target()
  -> BoundTargetDevice
  -> resolver / deploy / inject / session / artifact
```

`Preflight.run()` 改为返回 `tuple[BoundTargetDevice, DeviceIdentity]`。手动 pull 使用的 `bind_package_access()` 改为返回 `BoundTargetDevice`，CLI 使用返回值继续收集，不再依赖参数被隐式修改。

`DeviceIdentity` 仍作为报告数据值，不承担命令行为。它的 `access_mode`、`android_user` 和 `package_data_dir` 来自同一 `TargetBinding`，避免预检产生两套独立数据。

## 调用方调整

- `build.py` 的 deploy Interface 接收 `BoundTargetDevice`，直接使用非可空属性，删除 `valid_binding` 重复验证。
- `session.py` 直接使用 `BoundTargetDevice.trace_directory`，删除 package data directory 的 `getattr()` 和正则重验证。
- injector、artifact 和状态读取路径使用非可空身份属性。
- 测试替身必须满足实际调用方使用的 BoundTargetDevice Interface，不再依赖下游 `getattr()` 默认值。

## 验证与错误处理

`TargetBinding` 保留当前 `bind_package()` 的所有规则：

- package 名称必须合法；
- access mode、root strategy 和 target strategy 组合必须有效；
- package UID 必须为正整数并属于指定 Android user；
- package data directory 必须精确为 `/data/user/<user>/<package>` 且通过远程路径验证。

验证失败保留现有 `QtraceError` code、stage 和 detail。绑定成功后，目标方法不再有 `device.unbound` 错误分支，因为该状态无法通过 Interface 表达。

本次不改变 ADB 进程失败的分类方式，也不更改 CLI 的错误码或报告内容。将 missing remote path、transport unavailable 和 process exited 转换为类型化结果属于后续独立改造，不与状态模型变更混合。

## 测试设计

按红—绿—重构实施，Interface 是测试面：

1. 先添加失败测试，要求 `bind_target()` 返回新 `BoundTargetDevice`，原 `AdbDevice` 不获得目标状态。
2. 覆盖每类合法 root/run-as/su-uid 组合，并通过 `root_shell()`、`target_shell()` 和 `stream_target_file()` 观察实际命令。
3. 覆盖 UID/user、数据目录和策略组合验证，断言现有错误码不变。
4. 预检测试断言返回已绑定对象，且报告身份与 `TargetBinding` 一致。
5. 替换而不叠加旧的“幂等重复绑定/冲突再绑定”测试；新建对象模型不存在这两种运行时状态。
6. 保留现有 CLI、session、deploy、inject 和 artifact 回归测试，确认用户可观察行为未变。

runner Seam 已经有生产 Adapter 和测试 Adapter，用它观察生成的 ADB 命令即可。绑定本身只有一个实现，不为它新增假设性 Seam 或 Adapter。

## 实施范围外

本规格不包含：

- `ArtifactResult` 和 publication claim 的类型化；
- ADB stderr/cause 的类型化错误翻译；
- `TracerRuntime` 或 Native QBDI Interface 改造；
- 新的静态类型、lint 或 CI 门禁。

`ArtifactResult` 将作为下一份独立规格和实施计划，以便两个 Module 可以分别审查、验证和回滚。

## 验收标准

- `AdbDevice` 不再存储 package、access mode、root strategy、package UID、target strategy、Android user 或 package data directory。
- `AdbDevice.bind_package()` 被删除，`bind_target()` 不修改原对象。
- 只有 `BoundTargetDevice` 暴露目标身份属性和目标命令方法，这些属性均不可空。
- `build.py` 不再重复验证绑定字段，`session.py` 不再用 `getattr()` 恢复绑定身份。
- qtrace CLI 的参数、成功输出、失败错误码和报告结构保持不变。
- 相关 Python 测试在生产代码修改前按预期失败，修改后通过。
- 完整 Python unittest 通过，`git diff --check` 无错误。
